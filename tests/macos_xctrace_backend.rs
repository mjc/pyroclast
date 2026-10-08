use std::sync::Mutex;

use pyroclast::backends::macos_xctrace::{MacosXctraceBackend, build_xctrace_export_cpu_command};
use pyroclast::backends::{ProfileRequest, ProfilerBackend};
use pyroclast::cli::{PerfCallGraph, PerfEvent, ProfileKind, SymbolizerKind};
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};

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
        symbols: false,
        symbolizer: SymbolizerKind::Addr2line,
        frequency: 997,
        event: PerfEvent::CpuClock,
        call_graph: PerfCallGraph::Fp,
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

#[derive(Default)]
struct RecordingXctraceRunner {
    commands: Mutex<Vec<CommandSpec>>,
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
                std::fs::write(&pid_path.1, "42\n")?;
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
                    r#"<table><row><process pid="42"/><symbol>app::main</symbol><weight>12.5</weight></row><row><process pid="42"/><symbol>tokio::park</symbol><weight>3</weight></row><row><process pid="99"/><symbol>unrelated</symbol><weight>500</weight></row></table>"#,
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
