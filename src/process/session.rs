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
    ///
    /// # Errors
    /// Returns an error on cancellation, timeout, EOF, extra response bytes,
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
            self.write_request(request, &mut written)?;
            // Discard diagnostics after each bounded drain. We do not retain
            // a growing session-wide stderr log or block a noisy child's stdout.
            diagnostics.clear();
            drain_pipe(&mut self.stderr, &mut diagnostics)?;
            let previous = response.len();
            drain_pipe(&mut self.stdout, &mut response)?;
            received_lines += memchr::memchr_iter(b'\n', &response[previous..]).count();
            if received_lines >= lines {
                if received_lines != lines
                    || response.last() != Some(&b'\n')
                    || written != request.len()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected session response framing",
                    ));
                }
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
