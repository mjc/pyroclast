use std::path::PathBuf;

use pyroclast::backends::linux_perf::build_perf_record_command;
use pyroclast::backends::macos_xctrace::build_xctrace_record_command;

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

#[test]
fn builds_macos_xctrace_record_command() {
    let command = build_xctrace_record_command(
        PathBuf::from("run/profile.raw.xctrace.trace"),
        PathBuf::from("run/xctrace-target.pid"),
        ["target/release/app".to_string(), "--serve".to_string()],
    );

    assert_eq!(command.program, "xctrace");
    assert_eq!(&command.args[..8], [
        "record",
        "--quiet",
        "--template",
        "CPU Profiler",
        "--output",
        "run/profile.raw.xctrace.trace",
        "--no-prompt",
        "--launch",
    ]);
    assert!(command.args.contains(&"/bin/sh".to_string()));
    assert!(command.args.iter().any(|arg| arg.contains("PYROCLAST_XCTRACE_TARGET_PID")));
    assert!(command.args.contains(&"target/release/app".to_string()));
    assert_eq!(
        command.env,
        vec![(
            "PYROCLAST_XCTRACE_TARGET_PID".to_string(),
            "run/xctrace-target.pid".to_string()
        )]
    );
}
