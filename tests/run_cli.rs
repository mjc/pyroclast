use pyroclast::run_cli;

#[test]
fn top_level_cpu_command_creates_artifacts() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("cpu-run");

    run_cli([
        "pyroclast",
        "cpu",
        "--out",
        out.to_str().expect("utf8 path"),
        "--",
        "cargo",
        "check",
    ])
    .expect("run cli");

    assert!(out.join("run.json").is_file());
    assert!(out.join("command.txt").is_file());
    assert_eq!(
        std::fs::read_to_string(out.join("command.txt")).unwrap(),
        "cargo check"
    );
}
