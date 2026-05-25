use std::sync::Mutex;

use pyroclast::backends::offcpu::OffcpuBackend;
use pyroclast::backends::{ProfileRequest, ProfilerBackend};
use pyroclast::cli::{PerfCallGraph, PerfEvent, ProfileKind};
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};

#[test]
fn offcpu_backend_writes_folded_stack_artifacts() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("offcpu");
    let runner = RecordingBpftraceRunner::default();
    let request = ProfileRequest {
        kind: ProfileKind::Offcpu,
        command: vec!["target/release/app".to_string(), "--serve".to_string()],
        out_dir: out,
        name: None,
        json: false,
        symbols: false,
        frequency: 997,
        event: PerfEvent::CpuClock,
        call_graph: PerfCallGraph::Fp,
        pid: None,
        tids: Vec::new(),
        threads_of_pid: None,
        duration_secs: 30,
    };

    let result = OffcpuBackend::new(&runner)
        .profile(&request)
        .expect("offcpu profile");

    assert!(result.layout.raw_profile("bpftrace").is_file());
    assert_eq!(
        std::fs::read_to_string(result.layout.command_txt()).expect("command txt"),
        "target/release/app --serve\n"
    );
    assert_eq!(
        std::fs::read_to_string(result.layout.stacks_folded()).expect("folded"),
        "app::serve;tokio::runtime::park 1500\n"
    );
    let summary_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(result.layout.summary_json()).unwrap())
            .expect("summary json");
    assert_eq!(summary_json["folded_lines"], 1);
    assert_eq!(summary_json["total_count"], 1500);
    assert_eq!(runner.programs(), vec!["bpftrace", "bpftrace"]);
    assert_eq!(
        result.manifest.actual_backend,
        pyroclast::manifest::BackendName::Offcpu
    );
}

#[derive(Default)]
struct RecordingBpftraceRunner {
    commands: Mutex<Vec<CommandSpec>>,
}

impl RecordingBpftraceRunner {
    fn programs(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .map(|command| command.program.clone())
            .collect()
    }
}

impl CommandRunner for RecordingBpftraceRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        if command.args == ["--version"] {
            return Ok(CommandOutput {
                status_code: Some(0),
                stdout: b"bpftrace fake version\n".to_vec(),
                stderr: Vec::new(),
            });
        }
        Ok(CommandOutput {
            status_code: Some(0),
            stdout: b"@offcpu[\n    55 tokio::runtime::park+12 (/bin/app)\n    44 app::serve+7 (/bin/app)\n]: 1500\n".to_vec(),
            stderr: Vec::new(),
        })
    }
}
