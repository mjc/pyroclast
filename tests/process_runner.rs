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
