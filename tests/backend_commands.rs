use std::path::PathBuf;

use pyroclast::backends::heaptrack::build_heaptrack_command;
use pyroclast::backends::linux_perf::build_perf_record_command;
use pyroclast::backends::macos_xctrace::build_xctrace_record_command;
use pyroclast::flamegraph::build_inferno_flamegraph_command;

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
fn builds_heaptrack_command() {
    let command = build_heaptrack_command(
        PathBuf::from("run/profile.raw.heaptrack"),
        ["target/release/app".to_string(), "--serve".to_string()],
    );

    assert_eq!(command.program, "heaptrack");
    assert_eq!(
        command.args,
        vec![
            "-o",
            "run/profile.raw.heaptrack",
            "target/release/app",
            "--serve"
        ]
    );
}

#[test]
fn builds_inferno_flamegraph_command() {
    let command = build_inferno_flamegraph_command(
        "CPU profile",
        PathBuf::from("run/stacks.folded"),
        PathBuf::from("run/flamegraph.svg"),
    );

    assert_eq!(command.program, "inferno-flamegraph");
    assert_eq!(
        command.args,
        vec![
            "--title",
            "CPU profile",
            "run/stacks.folded",
            "--output",
            "run/flamegraph.svg"
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
    assert_eq!(
        &command.args[..8],
        [
            "record",
            "--quiet",
            "--template",
            "CPU Profiler",
            "--output",
            "run/profile.raw.xctrace.trace",
            "--no-prompt",
            "--launch",
        ]
    );
    assert!(command.args.contains(&"/bin/sh".to_string()));
    assert!(
        command
            .args
            .iter()
            .any(|arg| arg.contains("PYROCLAST_XCTRACE_TARGET_PID"))
    );
    assert!(command.args.contains(&"target/release/app".to_string()));
    assert_eq!(
        command.env,
        vec![(
            "PYROCLAST_XCTRACE_TARGET_PID".to_string(),
            "run/xctrace-target.pid".to_string()
        )]
    );
}
