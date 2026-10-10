use pyroclast::process::{CommandRunner, CommandSpec, RealCommandRunner};

#[cfg(unix)]
fn command_session(script: &str) -> pyroclast::process::CommandSession {
    RealCommandRunner::default()
        .start_session(&CommandSpec::new("sh").args(["-c", script]))
        .unwrap()
        .expect("real runner must support owned sessions")
}

#[cfg(unix)]
#[test]
fn session_keeps_one_child_and_reaps_it_when_dropped() {
    use std::time::Duration;

    let mut session =
        command_session("while IFS= read -r line; do printf '%s\\n%s\\n' \"$$\" \"$line\"; done");
    let first = session
        .exchange_lines(b"first\n", 2, Duration::from_secs(2))
        .unwrap();
    let first = String::from_utf8(first).unwrap();
    let pid = first.lines().next().unwrap();
    for line in ["second", "third"] {
        let response = session
            .exchange_lines(format!("{line}\n").as_bytes(), 2, Duration::from_secs(2))
            .unwrap();
        assert_eq!(response, format!("{pid}\n{line}\n").as_bytes());
    }
    let pid = pid.parse::<libc::pid_t>().unwrap();
    drop(session);
    // The session owns and reaps this child; no second waiter can find it.
    assert_eq!(
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[cfg(unix)]
#[test]
fn session_timeout_closes_the_protocol_without_retrying() {
    use std::time::Duration;

    // Bounded even without the timeout implementation, so the red run cannot
    // leave an unbounded test child behind.
    let mut session = command_session("read -r line; sleep 1; printf 'ready\\nreply\\n'");
    let error = session
        .exchange_lines(b"request\n", 2, Duration::from_millis(50))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    let error = session
        .exchange_lines(b"later\n", 2, Duration::from_secs(2))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
}

#[cfg(unix)]
#[test]
fn session_response_deadline_does_not_expire_an_idle_helper() {
    use std::time::Duration;

    let mut session = command_session("while IFS= read -r line; do printf '%s\\n' \"$line\"; done");
    for line in [b"first\n", b"later\n"] {
        assert_eq!(
            session
                .exchange_lines(line, 1, Duration::from_secs(1))
                .unwrap(),
            line
        );
        std::thread::sleep(Duration::from_millis(1100));
    }
}

#[cfg(unix)]
#[test]
fn session_accepts_split_response_lines() {
    let mut session = command_session(
        "read -r line; printf 'function\\n'; sleep 0.02; printf 'file\\n'; read -r later",
    );
    assert_eq!(
        session
            .exchange_lines(b"address\n", 2, std::time::Duration::from_secs(2))
            .unwrap(),
        b"function\nfile\n"
    );
}

#[cfg(unix)]
#[test]
fn session_rejects_incomplete_response_lines_and_closes_protocol() {
    use std::io::ErrorKind;
    use std::time::Duration;

    let mut session = command_session("read -r line; printf 'partial'");
    assert_eq!(
        session
            .exchange_lines(b"request\n", 2, Duration::from_secs(2))
            .unwrap_err()
            .kind(),
        ErrorKind::UnexpectedEof
    );
    assert_eq!(
        session
            .exchange_lines(b"later\n", 2, Duration::from_secs(2))
            .unwrap_err()
            .kind(),
        ErrorKind::BrokenPipe
    );
}

#[cfg(unix)]
#[test]
fn session_drains_both_pipes_while_writing_large_requests() {
    use std::time::Duration;

    let mut session = command_session("cat");
    let mut request = vec![b'x'; 1024 * 1024];
    request.push(b'\n');
    assert_eq!(
        session
            .exchange_lines(&request, 1, Duration::from_secs(5))
            .unwrap(),
        request
    );
    assert_eq!(
        session
            .exchange_lines(b"next\n", 1, Duration::from_secs(2))
            .unwrap(),
        b"next\n"
    );
    let mut noisy = command_session(
        "read -r line; i=0; while [ \"$i\" -lt 4096 ]; do printf 'bounded diagnostic line\\n' >&2; i=$((i + 1)); done; printf 'ok\\nreply\\n'; read -r later",
    );
    assert_eq!(
        noisy
            .exchange_lines(b"request\n", 2, Duration::from_secs(5))
            .unwrap(),
        b"ok\nreply\n"
    );
}

#[cfg(unix)]
#[test]
fn session_rejects_interactive_and_initial_stdin_commands() {
    for command in [
        CommandSpec::new("cat").interactive(),
        CommandSpec::new("cat").stdin(b"initial input".to_vec()),
    ] {
        let result = RealCommandRunner::default().start_session(&command);
        assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::InvalidInput));
    }
}

#[cfg(unix)]
#[test]
fn session_cancellation_interrupts_response_and_reaps_its_child() {
    use pyroclast::process::CancellationScope;
    use std::time::Duration;

    let scope = CancellationScope::enter().unwrap();
    let mut session = command_session("read -r line; sleep 1");
    let sender = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(100));
        // SAFETY: This test process pins its own PID throughout the send.
        assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGINT) }, 0);
    });
    let error = session
        .exchange_lines(b"request\n", 2, Duration::from_secs(2))
        .unwrap_err();
    sender.join().unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
    assert_eq!(scope.signal(), Some(libc::SIGINT));
}

#[cfg(unix)]
#[test]
fn session_finalization_honors_first_cancellation_but_not_repeated_signals() {
    use pyroclast::process::{CancellationScope, FinalizationScope};
    use std::time::Duration;

    let scope = CancellationScope::enter().unwrap();
    // SAFETY: Both handlers are installed. raise targets this calling thread,
    // so the handler completes before we inspect the cancellation state.
    assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
    assert_eq!(scope.signal(), Some(libc::SIGINT));
    let _finalization = FinalizationScope::enter();
    let mut session = command_session("while IFS= read -r line; do printf '%s\\n' \"$line\"; done");
    assert_eq!(
        session
            .exchange_lines(b"finalize\n", 1, Duration::from_secs(2))
            .unwrap(),
        b"finalize\n"
    );
    // SAFETY: The same thread and handlers remain live.
    assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
    assert_eq!(
        session
            .exchange_lines(b"again\n", 1, Duration::from_secs(2))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Interrupted
    );
}

#[cfg(unix)]
#[test]
fn inherited_file_survives_exec_without_reopening_its_deleted_path() {
    use std::os::fd::AsRawFd;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("selected");
    std::fs::write(&path, b"selected bytes").unwrap();
    let file = std::sync::Arc::new(std::fs::File::open(&path).unwrap());
    std::fs::remove_file(path).unwrap();
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
    let output = RealCommandRunner::default()
        .run(
            &CommandSpec::new("sh")
                .args(["-c", "cat \"/dev/fd/$SELECTED_INPUT\"; cat"])
                .inherit_file("SELECTED_INPUT", file.clone())
                .stdin(b"\naddress protocol".to_vec()),
        )
        .unwrap();
    assert_eq!(output.status_code, Some(0));
    assert_eq!(output.stdout, b"selected bytes\naddress protocol");
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) },
        flags
    );
}

#[cfg(unix)]
#[test]
fn inherited_files_do_not_break_exec_failure_reporting() {
    let file = std::sync::Arc::new(tempfile::tempfile().unwrap());
    let error = RealCommandRunner::default()
        .run(
            &CommandSpec::new("/definitely/missing/pyroclast-test-command")
                .inherit_file("SELECTED_INPUT", file),
        )
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn real_runner_captures_status_stdout_and_stderr() {
    let output = RealCommandRunner::default()
        .run(&CommandSpec::new("sh").args(["-c", "printf out; printf err >&2"]))
        .expect("run command");

    assert_eq!(output.status_code, Some(0));
    assert_eq!(output.stdout, b"out");
    assert_eq!(output.stderr, b"err");
}

#[test]
fn real_runner_writes_configured_stdin() {
    let output = RealCommandRunner::default()
        .run(&CommandSpec::new("cat").stdin(b"folded stacks".to_vec()))
        .expect("run command");

    assert_eq!(output.status_code, Some(0));
    assert_eq!(output.stdout, b"folded stacks");
}

#[test]
fn real_runner_drains_output_while_writing_large_stdin() {
    let bytes = vec![b'x'; 1024 * 1024];
    let expected = bytes.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = RealCommandRunner::default().run(&CommandSpec::new("cat").stdin(bytes));
        let _ = sender.send(result);
    });

    let output = receiver
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("large bidirectional transfers must not deadlock")
        .expect("run cat");
    assert_eq!(output.status_code, Some(0));
    assert_eq!(output.stdout, expected);
}

#[test]
fn real_runner_can_capture_interactive_output() {
    let output = RealCommandRunner::default()
        .run(
            &CommandSpec::new("sh")
                .args(["-c", "printf profile-output; printf profile-error >&2"])
                .interactive()
                .capture_output(),
        )
        .expect("capture interactive command");

    assert_eq!(output.stdout, b"profile-output");
    assert_eq!(output.stderr, b"profile-error");
}

#[cfg(unix)]
#[test]
fn capturing_interactive_output_retains_interrupt_status() {
    let output = RealCommandRunner::default()
        .run(
            &CommandSpec::new("sh")
                .args(["-c", "printf before-interrupt; kill -INT $$"])
                .interactive()
                .capture_output(),
        )
        .unwrap();

    assert_eq!(output.stdout, b"before-interrupt");
    assert_eq!(output.status_code, Some(-libc::SIGINT));
    assert!(output.succeeded_or_interrupted());
}

#[test]
fn real_runner_reports_child_status_when_stdin_pipe_breaks() {
    let output = RealCommandRunner::default()
        .run(
            &CommandSpec::new("sh")
                .args(["-c", "exit 7"])
                .stdin(vec![b'x'; 1024 * 1024]),
        )
        .expect("broken pipe should not hide child status");

    assert_eq!(output.status_code, Some(7));
}

#[test]
fn real_runner_can_run_interactive_commands_without_capturing_output() {
    let output = RealCommandRunner::default()
        .run(
            &CommandSpec::new("sh")
                .args(["-c", "printf terminal-output; printf terminal-error >&2"])
                .interactive(),
        )
        .expect("interactive command");

    assert_eq!(output.status_code, Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn real_runner_can_inherit_stderr_while_capturing_stdout() {
    let output = RealCommandRunner::default()
        .run(
            &CommandSpec::new("sh")
                .args(["-c", "printf out; printf err >&2"])
                .inherit_stderr(),
        )
        .expect("stderr inherited command");

    assert_eq!(output.status_code, Some(0));
    assert_eq!(output.stdout, b"out");
    assert!(output.stderr.is_empty());
}

#[cfg(unix)]
#[test]
fn cli_owned_writer_restores_nonblocking_flags_and_matches_native_write_status() {
    use pyroclast::process::CliWriter;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;

    let mut file = tempfile::tempfile().unwrap();
    // SAFETY: The file descriptor remains owned throughout both queries.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    // XNU bsd/sys/fcntl.h:FWASWRITTEN is kernel-managed, not F_SETFL state.
    // Compare a plain native write so that bit is not mistaken for our flags.
    let mut control = tempfile::tempfile().unwrap();
    control.write_all(b"final output").unwrap();
    // SAFETY: control stays owned throughout the file-status query.
    let native_flags = unsafe { libc::fcntl(control.as_raw_fd(), libc::F_GETFL) };
    assert!(native_flags >= 0);
    let mut writer = CliWriter::new(file.try_clone().unwrap().into());
    writer.write_all(b"final output").unwrap();
    writer.flush().unwrap();
    // SAFETY: file is still live; its duplicate shares the file-status flags.
    let actual = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(actual & libc::O_NONBLOCK, flags & libc::O_NONBLOCK);
    assert_eq!(actual, native_flags);
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"final output");
}

#[cfg(unix)]
#[test]
fn cli_owned_writer_restores_shared_descriptor_flags_after_broken_pipe() {
    use pyroclast::process::CliWriter;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    let (output, reader) = UnixStream::pair().unwrap();
    drop(reader);
    // SAFETY: output retains ownership throughout the queries and write.
    let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    let mut writer = CliWriter::new(output.try_clone().unwrap().into());
    assert_eq!(
        writer.write_all(b"closed").unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
    // SAFETY: output remains live after the failed write through its duplicate.
    assert_eq!(
        unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) },
        flags
    );
}
