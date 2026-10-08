use std::sync::Mutex;

use pyroclast::backends::macos_xctrace::{MacosXctraceBackend, build_xctrace_export_cpu_command};
use pyroclast::backends::{ProfileRequest, ProfilerBackend};
use pyroclast::cli::{PerfCallGraph, PerfEvent, ProfileKind, SymbolizerKind};
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};

fn default_request(out_dir: std::path::PathBuf) -> ProfileRequest {
    use clap::Parser as _;
    let cli = pyroclast::cli::Cli::try_parse_from(["pyroclast", "cpu", "--", "workload"]).unwrap();
    let invocation = cli.command.profile_invocation().unwrap();
    ProfileRequest {
        kind: invocation.kind,
        command: invocation.command,
        out_dir,
        name: invocation.name,
        json: invocation.json,
        symbols: invocation.symbols,
        symbolizer: invocation.symbolizer,
        frequency: invocation.frequency,
        event: invocation.event,
        call_graph: invocation.call_graph,
        pid: invocation.pid,
        tids: invocation.tids,
        threads_of_pid: invocation.threads_of_pid,
        duration_secs: invocation.duration_secs,
        offcpu_method: None,
    }
}

fn assert_rejected_before_invocation(change: impl FnOnce(&mut ProfileRequest), setting: &str) {
    let root = tempfile::tempdir().unwrap();
    let mut request = default_request(root.path().join("reused-run"));
    let layout = pyroclast::artifacts::ArtifactLayout::new(request.out_dir.clone());
    std::fs::create_dir_all(layout.root()).unwrap();
    let stale = [
        layout.run_json(),
        layout.summary_json(),
        layout.raw_profile("xctrace.xml"),
    ];
    for path in &stale {
        std::fs::write(path, "old success").unwrap();
    }
    change(&mut request);
    let runner = RecordingXctraceRunner::default();
    let error = MacosXctraceBackend::new(&runner)
        .profile(&request)
        .unwrap_err();
    assert!(error.to_string().contains(setting), "{error}");
    assert!(
        runner.programs().is_empty(),
        "invoked tools before validating {setting}"
    );
    assert!(
        stale.iter().all(|path| !path.exists()),
        "stale success after rejecting {setting}"
    );
}

#[test]
fn rejects_custom_frequency_before_invocation() {
    for frequency in [0, 100, 1000] {
        assert_rejected_before_invocation(|request| request.frequency = frequency, "frequency");
    }
}

#[test]
fn rejects_custom_events_before_invocation() {
    for event in [PerfEvent::CpuClock, PerfEvent::TaskClock, PerfEvent::Cycles] {
        assert_rejected_before_invocation(|request| request.event = event, "event");
    }
}

#[test]
fn rejects_custom_call_graph_before_invocation() {
    assert_rejected_before_invocation(
        |request| request.call_graph = PerfCallGraph::Fp,
        "call-graph",
    );
}

#[test]
fn rejects_disabled_symbols_before_invocation() {
    assert_rejected_before_invocation(|request| request.symbols = false, "symbols");
}

#[test]
fn rejects_custom_symbolizer_before_invocation() {
    assert_rejected_before_invocation(
        |request| request.symbolizer = SymbolizerKind::Addr2line,
        "symbolizer",
    );
}

#[test]
fn rejects_custom_duration_before_invocation() {
    assert_rejected_before_invocation(|request| request.duration_secs = 10, "duration");
}

#[test]
fn rejects_offcpu_method_before_invocation() {
    assert_rejected_before_invocation(
        |request| {
            request.offcpu_method = Some(pyroclast::backends::offcpu::OffcpuMethod::PerfSched);
        },
        "offcpu",
    );
}

#[test]
fn rejects_non_cpu_kind_before_invocation() {
    for kind in [
        ProfileKind::Memory,
        ProfileKind::Offcpu,
        ProfileKind::Latency,
        ProfileKind::Async,
    ] {
        assert_rejected_before_invocation(|request| request.kind = kind, "CPU");
    }
}

#[test]
fn xctrace_export_selects_only_cpu_sampling_tables() {
    let command = build_xctrace_export_cpu_command(
        std::path::Path::new("run.trace"),
        std::path::Path::new("cpu.xml"),
    );
    let xpath = command
        .args
        .windows(2)
        .find(|args| args[0] == "--xpath")
        .unwrap();
    assert_eq!(
        xpath[1],
        "//table[@schema=\"cpu-profile\" or @schema=\"time-profile\"]"
    );
}

#[test]
fn macos_xctrace_backend_writes_cpu_summary_artifacts() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("xctrace");
    let runner = RecordingXctraceRunner::default();
    let request = ProfileRequest {
        kind: ProfileKind::Cpu,
        command: vec!["target/release/app".to_string(), "--serve".to_string()],
        out_dir: out,
        name: None,
        json: false,
        symbols: true,
        symbolizer: SymbolizerKind::RustAddr2line,
        frequency: 997,
        event: PerfEvent::Default,
        call_graph: PerfCallGraph::Dwarf,
        pid: None,
        tids: Vec::new(),
        threads_of_pid: None,
        duration_secs: 3600,
        offcpu_method: None,
    };

    let result = MacosXctraceBackend::new(&runner)
        .profile(&request)
        .expect("xctrace profile");

    assert!(result.layout.raw_profile("xctrace.trace").is_dir());
    assert!(result.layout.raw_profile("xctrace.xml").is_file());
    assert_eq!(
        std::fs::read_to_string(result.layout.summary_txt()).expect("summary txt"),
        "xctrace rows: 2\nxctrace weight unit: nanoseconds\nxctrace total weight: 15.500000\napp::main: 12.500000\ntokio::park: 3.000000\n"
    );
    let summary_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(result.layout.summary_json()).unwrap())
            .expect("summary json");
    assert_eq!(summary_json["rows"].as_array().expect("rows").len(), 2);
    assert_eq!(summary_json["total_weight"], 15.5);
    assert_eq!(summary_json["weight_unit"], "nanoseconds");
    assert_eq!(runner.programs(), vec!["xctrace", "xctrace"]);
    assert_eq!(
        result.manifest.actual_backend,
        pyroclast::manifest::BackendName::MacosXctrace
    );
}

#[test]
fn default_cli_request_replays_captured_xcode_cpu_profile() {
    let root = tempfile::tempdir().unwrap();
    let request = default_request(root.path().join("native-replay"));
    let runner = RecordingXctraceRunner {
        native_export: true,
        ..RecordingXctraceRunner::default()
    };
    let result = MacosXctraceBackend::new(&runner).profile(&request).unwrap();
    let summary: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(result.layout.summary_json()).unwrap())
            .unwrap();
    assert_eq!(summary["rows"].as_array().unwrap().len(), 4);
    assert_eq!(summary["weight_unit"], "cycles");
    assert_eq!(summary["total_weight"], 2_024_198.0);
    let commands = runner.commands.lock().unwrap();
    let record = &commands[0];
    assert!(
        record
            .args
            .windows(2)
            .any(|args| args == ["--template", "CPU Profiler"])
    );
    assert_eq!(commands.len(), 2);
}

#[test]
fn manifest_reports_xctrace_measurement_instead_of_perf_defaults() {
    for (native_export, weight_unit) in [(false, "nanoseconds"), (true, "cycles")] {
        let root = tempfile::tempdir().unwrap();
        let request = default_request(root.path().join("measurement"));
        let runner = RecordingXctraceRunner {
            native_export,
            ..RecordingXctraceRunner::default()
        };
        let result = MacosXctraceBackend::new(&runner).profile(&request).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(result.layout.run_json()).unwrap()).unwrap();
        for field in ["sample_frequency", "sample_event", "call_graph", "symbols"] {
            assert!(
                manifest.get(field).is_none(),
                "claimed actual {field}: {manifest}"
            );
        }
        assert_eq!(
            manifest["requested_controls"],
            serde_json::json!({
                "frequency": 997,
                "event": "default",
                "call_graph": "dwarf",
                "symbols": true,
                "symbolizer": "rust-addr2line",
                "duration_secs": 3600
            })
        );
        assert_eq!(
            manifest["measurement"],
            serde_json::json!({
                "source": "xctrace",
                "template": "CPU Profiler",
                "weight_unit": weight_unit
            })
        );
        assert!(manifest["duration_secs"].is_null());
    }
}

#[derive(Default)]
struct RecordingXctraceRunner {
    commands: Mutex<Vec<CommandSpec>>,
    native_export: bool,
}

impl RecordingXctraceRunner {
    fn programs(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .map(|command| command.program.clone())
            .collect()
    }
}

impl CommandRunner for RecordingXctraceRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        if command.args == ["--version"] {
            return Ok(CommandOutput {
                status_code: Some(0),
                stdout: b"xctrace fake version\n".to_vec(),
                stderr: Vec::new(),
            });
        }
        match command.args.first().map(String::as_str) {
            Some("record") => {
                let trace_path = command
                    .args
                    .windows(2)
                    .find(|window| window[0] == "--output")
                    .map(|window| window[1].as_str())
                    .expect("trace output");
                std::fs::create_dir_all(trace_path)?;
                let pid_path = command
                    .env
                    .iter()
                    .find(|(key, _)| key == "PYROCLAST_XCTRACE_TARGET_PID")
                    .unwrap();
                std::fs::write(&pid_path.1, if self.native_export { "7\n" } else { "42\n" })?;
                Ok(CommandOutput {
                    status_code: Some(0),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            }
            Some("export") => {
                let xml_path = command
                    .args
                    .windows(2)
                    .find(|window| window[0] == "--output")
                    .map(|window| window[1].as_str())
                    .expect("xml output");
                std::fs::write(
                    xml_path,
                    if self.native_export {
                        include_str!("fixtures/xctrace/cpu-profile-xcode27.xml")
                    } else {
                        r#"<table><row><process pid="42"/><symbol>app::main</symbol><weight>12.5</weight></row><row><process pid="42"/><symbol>tokio::park</symbol><weight>3</weight></row><row><process pid="99"/><symbol>unrelated</symbol><weight>500</weight></row></table>"#
                    },
                )?;
                Ok(CommandOutput {
                    status_code: Some(0),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            }
            _ => panic!("unexpected command: {command:?}"),
        }
    }
}
