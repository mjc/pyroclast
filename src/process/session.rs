use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::process::{ChildStderr, ChildStdin, ChildStdout};
use std::time::{Duration, Instant};

use super::{
    CancellationScope, CommandPurpose, CommandSpec, OwnedProcess, drain_pipe, nonblocking,
    poll_child_pipes, spawn_process,
};

/// An owned, noninteractive child with newline-framed request/response I/O.
/// Dropping the session kills and reaps its pinned process group.
pub struct CommandSession {
    purpose: CommandPurpose,
    process: Option<OwnedProcess>,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl CommandSession {
    pub(super) fn start(command: &CommandSpec) -> io::Result<Self> {
        if command.interactive || command.stdin.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sessions require noninteractive commands without initial stdin",
            ));
        }
        let child = spawn_process(&command.clone().stdin(Vec::new()))?;
        let mut process = OwnedProcess {
            group: i32::try_from(child.id()).map_err(io::Error::other)?,
            child,
            reaped: false,
        };
        let stdin = process.child.stdin.take();
        let stdout = process.child.stdout.take();
        let stderr = process.child.stderr.take();
        if let Some(pipe) = &stdin {
            nonblocking(pipe)?;
        }
        if let Some(pipe) = &stdout {
            nonblocking(pipe)?;
        }
        if let Some(pipe) = &stderr {
            nonblocking(pipe)?;
        }
        Ok(Self {
            purpose: command.purpose,
            process: Some(process),
            stdin,
            stdout,
            stderr,
        })
    }

    /// Writes one request and reads exactly `lines` newline-terminated lines.
    /// The deadline covers this response, not the lifetime of the helper or a
    /// whole batch. Failure closes the session; later calls cannot retry a
    /// partially consumed protocol. Successful replies do not imply child exit.
    /// Only observed bytes can be validated: this fixed-count protocol cannot
    /// predict later extra output. Output already queued before a request is
    /// unsolicited and closes the session rather than becoming that reply.
    ///
    /// # Errors
    /// Returns an error on cancellation, timeout, EOF, observed extra bytes,
    /// invalid framing, a closed session, or failed pipe I/O.
    pub fn exchange_lines(
        &mut self,
        request: &[u8],
        lines: usize,
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        let result = self.exchange(request, lines, timeout);
        if result.is_err() {
            self.stdin = None;
            self.stdout = None;
            self.stderr = None;
            self.process = None;
        }
        result
    }

    fn exchange(&mut self, request: &[u8], lines: usize, timeout: Duration) -> io::Result<Vec<u8>> {
        if self.process.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session is closed",
            ));
        }
        if request.is_empty() || lines == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sessions require a request and a nonzero response line count",
            ));
        }
        let scope = CancellationScope::enter()?;
        let finalizing_after_cancellation =
            self.purpose.permits_finalization() && scope.signal().is_some();
        let started = Instant::now();
        let mut written = 0;
        let mut response = Vec::new();
        let mut diagnostics = Vec::new();
        let mut received_lines = 0;
        loop {
            if scope.signal().is_some() && (!finalizing_after_cancellation || scope.repeated()) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "session request cancelled",
                ));
            }
            if started.elapsed() >= timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "session response deadline exceeded",
                ));
            }
            if written == 0 {
                drain_pipe(&mut self.stdout, &mut response)?;
                if !response.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "session stdout was available before the request",
                    ));
                }
            }
            self.write_request(request, &mut written)?;
            // Discard diagnostics after each bounded drain. We do not retain
            // a growing session-wide stderr log or block a noisy child's stdout.
            diagnostics.clear();
            drain_pipe(&mut self.stderr, &mut diagnostics)?;
            let previous = response.len();
            drain_pipe(&mut self.stdout, &mut response)?;
            received_lines += memchr::memchr_iter(b'\n', &response[previous..]).count();
            if received_lines >= lines {
                Self::validate_response_framing(
                    &response,
                    received_lines,
                    lines,
                    written == request.len(),
                )?;
                return Ok(response);
            }
            if self.stdout.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "session closed after {received_lines}/{lines} response lines: {}",
                        String::from_utf8_lossy(&diagnostics)
                    ),
                ));
            }
            poll_child_pipes([
                self.stdout.as_ref().map(AsRawFd::as_raw_fd),
                self.stderr.as_ref().map(AsRawFd::as_raw_fd),
                self.stdin
                    .as_ref()
                    .filter(|_| written < request.len())
                    .map(AsRawFd::as_raw_fd),
            ])?;
        }
    }

    fn validate_response_framing(
        response: &[u8],
        received_lines: usize,
        lines: usize,
        request_complete: bool,
    ) -> io::Result<()> {
        if received_lines != lines || response.last() != Some(&b'\n') || !request_complete {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected session response framing",
            ));
        }
        Ok(())
    }

    fn write_request(&mut self, request: &[u8], written: &mut usize) -> io::Result<()> {
        if *written == request.len() {
            return Ok(());
        }
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "session stdin is closed"))?;
        let end = request.len().min(*written + 65536);
        match stdin.write(&request[*written..end]) {
            Ok(0) => Err(io::Error::new(io::ErrorKind::WriteZero, "session stdin")),
            Ok(count) => {
                *written += count;
                Ok(())
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CommandSession;
    use crate::process::{CommandSpec, poll_child_pipes};
    use std::io::{ErrorKind, Write};
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    #[test]
    fn observed_response_framing_rejects_extra_or_incomplete_bytes() {
        for response in [
            b"a\nb\nc\n".as_slice(),
            b"a\nb\npartial".as_slice(),
            b"a\n".as_slice(),
            b"partial".as_slice(),
        ] {
            assert_eq!(
                CommandSession::validate_response_framing(
                    response,
                    memchr::memchr_iter(b'\n', response).count(),
                    2,
                    true,
                )
                .unwrap_err()
                .kind(),
                ErrorKind::InvalidData,
                "{response:?}"
            );
        }
    }

    #[test]
    fn observed_response_framing_requires_the_whole_request_and_exact_lines() {
        for response in [b"a\nb\n".as_slice(), b"\n\n".as_slice()] {
            CommandSession::validate_response_framing(response, 2, 2, true).unwrap();
            assert_eq!(
                CommandSession::validate_response_framing(response, 2, 2, false)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData
            );
        }
    }

    fn wait_for_queued_stdout(session: &CommandSession, bytes: usize) {
        let stdout = session.stdout.as_ref().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut available: libc::c_int = 0;
            // SAFETY: stdout owns the live descriptor; available is writable.
            assert_eq!(
                unsafe { libc::ioctl(stdout.as_raw_fd(), libc::FIONREAD, &mut available) },
                0
            );
            if usize::try_from(available).unwrap() >= bytes {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "stdout did not queue {bytes} bytes"
            );
            poll_child_pipes([Some(stdout.as_raw_fd()), None, None]).unwrap();
        }
    }

    #[test]
    fn session_rejects_stdout_queued_before_first_request() {
        let mut session = CommandSession::start(&CommandSpec::new("sh").args([
            "-c",
            "printf 'stale\\nreply\\n'; read -r request; read -r later",
        ]))
        .unwrap();
        wait_for_queued_stdout(&session, b"stale\nreply\n".len());
        assert_eq!(
            session
                .exchange_lines(b"request\n", 2, Duration::from_secs(2))
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            session
                .exchange_lines(b"later\n", 2, Duration::from_secs(2))
                .unwrap_err()
                .kind(),
            ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn session_rejects_stdout_queued_between_requests() {
        let mut session = CommandSession::start(&CommandSpec::new("sh").args([
            "-c",
            "read -r first; printf 'first\\nreply\\n'; read -r release; printf 'stale\\nreply\\n'; read -r request; read -r later",
        ]))
        .unwrap();
        assert_eq!(
            session
                .exchange_lines(b"first\n", 2, Duration::from_secs(2))
                .unwrap(),
            b"first\nreply\n"
        );
        // Fixture-only release: the previous exchange is complete before the
        // child publishes unsolicited output for the next boundary check.
        session
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"release\n")
            .unwrap();
        wait_for_queued_stdout(&session, b"stale\nreply\n".len());
        assert_eq!(
            session
                .exchange_lines(b"request\n", 2, Duration::from_secs(2))
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            session
                .exchange_lines(b"later\n", 2, Duration::from_secs(2))
                .unwrap_err()
                .kind(),
            ErrorKind::BrokenPipe
        );
    }
}
