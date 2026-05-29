use std::sync::Mutex;

use pyroclast::backends::heaptrack::HeaptrackBackend;
use pyroclast::backends::{ProfileRequest, ProfilerBackend};
use pyroclast::cli::{PerfCallGraph, PerfEvent, ProfileKind, SymbolizerKind};
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};
use pyroclast::tools::{ResolvedTool, ToolSource, ToolSpec};

#[test]
fn heaptrack_backend_writes_heap_summary_artifacts() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("heap");
    let runner = RecordingHeaptrackRunner::default();
    let request = ProfileRequest {
        kind: ProfileKind::Memory,
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

    let result = HeaptrackBackend::new(&runner)
        .profile(&request)
        .expect("heaptrack profile");

    assert!(result.layout.raw_profile("heaptrack").is_file());
    assert_eq!(
        std::fs::read_to_string(result.layout.command_txt()).expect("command txt"),
        "target/release/app --serve\n"
    );
    assert_eq!(
        std::fs::read_to_string(result.layout.summary_txt()).expect("summary txt"),
        "total allocations: 42\npeak heap memory consumption: 1024 bytes\n"
    );
    let summary_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(result.layout.summary_json()).unwrap())
            .expect("summary json");
    assert_eq!(summary_json["total_allocations"], 42);
    assert_eq!(summary_json["peak_heap_bytes"], 1024);
    assert_eq!(runner.programs(), vec!["heaptrack", "heaptrack_print"]);
    assert_eq!(
        runner
            .commands
            .lock()
            .unwrap()
            .iter()
            .find(|command| command.program == "heaptrack" && command.args != ["--version"])
            .map(|command| command.args.clone()),
        Some(vec![
            "--record-only".to_string(),
            "-o".to_string(),
            result.layout.raw_profile("heaptrack").display().to_string(),
            "target/release/app".to_string(),
            "--serve".to_string(),
        ])
    );
    assert_eq!(
        result.manifest.actual_backend,
        pyroclast::manifest::BackendName::Heaptrack
    );
}

#[test]
fn heaptrack_backend_uses_suffixed_raw_output_when_heaptrack_creates_one() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("heap");
    let runner = SuffixedHeaptrackRunner::default();
    let request = ProfileRequest {
        kind: ProfileKind::Memory,
        command: vec!["target/release/app".to_string()],
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

    let result = HeaptrackBackend::new(&runner)
        .profile(&request)
        .expect("heaptrack profile");

    let raw_output = result.layout.raw_profile("heaptrack.1234.zst");
    assert!(raw_output.is_file());
    assert_eq!(runner.heaptrack_print_inputs(), vec![raw_output]);
    assert!(
        result
            .manifest
            .artifacts
            .contains(&result.layout.raw_profile("heaptrack.1234.zst"))
    );
}

#[test]
fn heaptrack_backend_preflights_heaptrack_print_before_launch() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("heap");
    let runner = MissingHeaptrackPrintRunner::default();
    let request = ProfileRequest {
        kind: ProfileKind::Memory,
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

    let error = HeaptrackBackend::new(&runner)
        .profile(&request)
        .expect_err("missing heaptrack_print");

    assert!(error.to_string().contains("heaptrack_print"));
    assert!(runner.programs().is_empty());
    assert!(!root.path().join("heap/profile.raw.heaptrack").exists());
}

#[derive(Default)]
struct RecordingHeaptrackRunner {
    commands: Mutex<Vec<CommandSpec>>,
}

impl RecordingHeaptrackRunner {
    fn programs(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .map(|command| command.program.clone())
            .collect()
    }
}

impl CommandRunner for RecordingHeaptrackRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        match command.program.as_str() {
            "heaptrack" if command.args == ["--version"] => Ok(CommandOutput {
                status_code: Some(0),
                stdout: b"heaptrack fake version\n".to_vec(),
                stderr: Vec::new(),
            }),
            "heaptrack" => {
                let output_prefix = command
                    .args
                    .windows(2)
                    .find(|window| window[0] == "-o")
                    .map(|window| window[1].as_str())
                    .expect("heaptrack output prefix");
                std::fs::write(output_prefix, b"raw heaptrack bytes")?;
                Ok(CommandOutput {
                    status_code: Some(0),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            }
            "heaptrack_print" => Ok(CommandOutput {
                status_code: Some(0),
                stdout: b"total allocations: 42\npeak heap memory consumption: 1024 bytes\n"
                    .to_vec(),
                stderr: Vec::new(),
            }),
            program => panic!("unexpected command: {program}"),
        }
    }
}

#[derive(Default)]
struct SuffixedHeaptrackRunner {
    commands: Mutex<Vec<CommandSpec>>,
}

impl SuffixedHeaptrackRunner {
    fn heaptrack_print_inputs(&self) -> Vec<std::path::PathBuf> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .filter(|command| command.program == "heaptrack_print")
            .filter_map(|command| command.args.first())
            .map(std::path::PathBuf::from)
            .collect()
    }
}

impl CommandRunner for SuffixedHeaptrackRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        match command.program.as_str() {
            "heaptrack" if command.args == ["--version"] => Ok(CommandOutput {
                status_code: Some(0),
                stdout: b"heaptrack fake version\n".to_vec(),
                stderr: Vec::new(),
            }),
            "heaptrack" => {
                let output_prefix = command
                    .args
                    .windows(2)
                    .find(|window| window[0] == "-o")
                    .map(|window| window[1].as_str())
                    .expect("heaptrack output prefix");
                std::fs::write(
                    format!("{output_prefix}.1234.zst"),
                    b"compressed heaptrack bytes",
                )?;
                Ok(CommandOutput {
                    status_code: Some(0),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            }
            "heaptrack_print" => Ok(CommandOutput {
                status_code: Some(0),
                stdout: b"total allocations: 9\npeak heap memory consumption: 128 bytes\n".to_vec(),
                stderr: Vec::new(),
            }),
            program => panic!("unexpected command: {program}"),
        }
    }
}

#[derive(Default)]
struct MissingHeaptrackPrintRunner {
    commands: Mutex<Vec<CommandSpec>>,
}

impl MissingHeaptrackPrintRunner {
    fn programs(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .map(|command| command.program.clone())
            .collect()
    }
}

impl CommandRunner for MissingHeaptrackPrintRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        panic!("preflight should fail before running commands: {command:?}");
    }

    fn resolve_tool(&self, tool: &ToolSpec) -> std::io::Result<ResolvedTool> {
        if tool.name == "heaptrack_print" {
            return Err(std::io::Error::other(
                "heaptrack_print is required but was not found on PATH or in the project flake; install it or enter the project dev shell",
            ));
        }

        Ok(ResolvedTool {
            name: tool.name.to_string(),
            path: tool.name.to_string(),
            source: ToolSource::Path,
            version: Some(format!("{} fake version", tool.name)),
            launch_program: tool.name.to_string(),
            launch_args: Vec::new(),
        })
    }
}
