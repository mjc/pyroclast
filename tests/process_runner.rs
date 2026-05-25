use pyroclast::process::{CommandRunner, CommandSpec, RealCommandRunner};

#[test]
fn real_runner_captures_status_stdout_and_stderr() {
    let output = RealCommandRunner
        .run(&CommandSpec::new("sh").args(["-c", "printf out; printf err >&2"]))
        .expect("run command");

    assert_eq!(output.status_code, Some(0));
    assert_eq!(output.stdout, b"out");
    assert_eq!(output.stderr, b"err");
}

#[test]
fn real_runner_writes_configured_stdin() {
    let output = RealCommandRunner
        .run(&CommandSpec::new("cat").stdin(b"folded stacks".to_vec()))
        .expect("run command");

    assert_eq!(output.status_code, Some(0));
    assert_eq!(output.stdout, b"folded stacks");
}

#[test]
fn real_runner_reports_child_status_when_stdin_pipe_breaks() {
    let output = RealCommandRunner
        .run(
            &CommandSpec::new("sh")
                .args(["-c", "exit 7"])
                .stdin(vec![b'x'; 1024 * 1024]),
        )
        .expect("broken pipe should not hide child status");

    assert_eq!(output.status_code, Some(7));
}
