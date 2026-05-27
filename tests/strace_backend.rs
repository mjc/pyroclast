use std::sync::Mutex;

use pyroclast::backends::strace::StraceBackend;
use pyroclast::backends::{ProfileRequest, ProfilerBackend};
use pyroclast::cli::{PerfCallGraph, PerfEvent, ProfileKind, SymbolizerKind};
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};

#[test]
fn strace_backend_writes_syscall_summary_artifacts() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("latency");
    let runner = RecordingStraceRunner::default();
    let request = ProfileRequest {
        kind: ProfileKind::Latency,
        command: vec!["target/release/app".to_string(), "--serve".to_string()],
        out_dir: out.clone(),
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

    let result = StraceBackend::new(&runner)
        .profile(&request)
        .expect("strace profile");

    assert!(result.layout.raw_profile("strace").is_file());
    assert_eq!(
        std::fs::read_to_string(result.layout.command_txt()).expect("command txt"),
        "target/release/app --serve\n"
    );
    assert_eq!(
        std::fs::read_to_string(result.layout.summary_txt()).expect("summary txt"),
        "syscall calls: 2\nsyscall seconds: 0.003500\nread: calls=1 seconds=0.001000\nwrite: calls=1 seconds=0.002500\n"
    );
    let summary_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(result.layout.summary_json()).unwrap())
            .expect("summary json");
    assert_eq!(summary_json["total_calls"], 2);
    assert_eq!(summary_json["by_syscall"]["read"]["calls"], 1);
    assert_eq!(runner.programs(), vec!["strace", "strace"]);
    assert_eq!(
        result.manifest.actual_backend,
        pyroclast::manifest::BackendName::Strace
    );
}

#[derive(Default)]
struct RecordingStraceRunner {
    commands: Mutex<Vec<CommandSpec>>,
}

impl RecordingStraceRunner {
    fn programs(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .map(|command| command.program.clone())
            .collect()
    }
}

impl CommandRunner for RecordingStraceRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        if command.args == ["--version"] {
            return Ok(CommandOutput {
                status_code: Some(0),
                stdout: b"strace fake version\n".to_vec(),
                stderr: Vec::new(),
            });
        }
        if command.program == "strace" {
            let output_path = command
                .args
                .windows(2)
                .find(|window| window[0] == "-o")
                .map(|window| window[1].as_str())
                .expect("strace output");
            std::fs::write(
                output_path,
                "123 12:00:00.000000 read(3, \"abc\", 3) = 3 <0.001000>\n123 12:00:00.002000 write(1, \"x\", 1) = 1 <0.002500>\n",
            )?;
        }
        Ok(CommandOutput {
            status_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }
}
