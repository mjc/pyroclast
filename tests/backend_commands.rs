use pyroclast::backends::heaptrack::build_heaptrack_command;
use pyroclast::backends::linux_perf::{PerfRecordTarget, build_perf_record_command};
use pyroclast::backends::macos_xctrace::build_xctrace_record_command;
use pyroclast::cli::PerfEvent;
use pyroclast::flamegraph::build_inferno_flamegraph_command;
use pyroclast::symbols::{SymbolRequest, build_addr2line_command};
use std::path::PathBuf;

#[test]
fn builds_linux_perf_record_command() {
    let command = build_perf_record_command(
        PerfEvent::CpuClock,
        997,
        "fp",
        &PathBuf::from("run/profile.raw.perf.data"),
        PerfRecordTarget::Command(vec!["cargo".to_string(), "check".to_string()]),
        3600,
    );

    assert_eq!(command.program, "perf");
    assert_eq!(
        command.args,
        vec![
            "record",
            "-e",
            "cpu-clock",
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
fn builds_linux_perf_thread_record_command() {
    let command = build_perf_record_command(
        PerfEvent::TaskClock,
        199,
        "dwarf",
        &PathBuf::from("run/profile.raw.perf.data"),
        PerfRecordTarget::Threads(vec![101, 102, 103]),
        15,
    );

    assert_eq!(command.program, "perf");
    assert_eq!(
        command.args,
        vec![
            "record",
            "-e",
            "task-clock",
            "-F",
            "199",
            "-g",
            "--call-graph",
            "dwarf",
            "-t",
            "101,102,103",
            "-o",
            "run/profile.raw.perf.data",
            "--",
            "sleep",
            "15",
        ]
    );
}

#[test]
fn builds_linux_perf_process_record_command() {
    let command = build_perf_record_command(
        PerfEvent::Cycles,
        997,
        "fp",
        &PathBuf::from("run/profile.raw.perf.data"),
        PerfRecordTarget::Process(99),
        30,
    );

    assert_eq!(command.program, "perf");
    assert_eq!(
        command.args,
        vec![
            "record",
            "-e",
            "cycles",
            "-F",
            "997",
            "-g",
            "--call-graph",
            "fp",
            "-p",
            "99",
            "-o",
            "run/profile.raw.perf.data",
            "--",
            "sleep",
            "30",
        ]
    );
}

#[test]
fn builds_heaptrack_command() {
    let command = build_heaptrack_command(
        &PathBuf::from("run/profile.raw.heaptrack"),
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
    let command = build_inferno_flamegraph_command("CPU profile");

    assert_eq!(command.program, "inferno-flamegraph");
    assert_eq!(command.args, vec!["--title", "CPU profile", "-"]);
}

#[test]
fn builds_macos_xctrace_record_command() {
    let command = build_xctrace_record_command(
        &PathBuf::from("run/profile.raw.xctrace.trace"),
        &PathBuf::from("run/xctrace-target.pid"),
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

#[test]
fn builds_batched_addr2line_command() {
    let command = build_addr2line_command(
        &PathBuf::from("/bin/app"),
        &[
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x10,
            },
            SymbolRequest {
                path: PathBuf::from("/bin/app"),
                relative_address: 0x20,
            },
        ],
    );

    assert_eq!(command.program, "addr2line");
    assert_eq!(command.args, vec!["-f", "-C", "-e", "/bin/app"]);
    assert_eq!(command.stdin, Some(b"0x10\n0x20\n".to_vec()));
}
