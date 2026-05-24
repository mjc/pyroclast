use std::path::PathBuf;

use pyroclast::backends::linux_perf::build_perf_record_command;

#[test]
fn builds_linux_perf_record_command() {
    let command = build_perf_record_command(
        997,
        "fp",
        PathBuf::from("run/profile.raw.perf.data"),
        ["cargo".to_string(), "check".to_string()],
    );

    assert_eq!(command.program, "perf");
    assert_eq!(
        command.args,
        vec![
            "record",
            "-F",
            "997",
            "-g",
            "--call-graph",
            "fp",
            "-o",
            "run/profile.raw.perf.data",
            "--",
            "cargo",
            "check",
        ]
    );
}
