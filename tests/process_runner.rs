use pyroclast::process::{CommandRunner, CommandSpec, RealCommandRunner};

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
