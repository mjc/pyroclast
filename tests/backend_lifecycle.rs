use pyroclast::artifacts::ArtifactLayout;
use pyroclast::backends::heaptrack::HeaptrackBackend;
use pyroclast::backends::linux_perf::LinuxPerfBackend;
use pyroclast::backends::macos_xctrace::MacosXctraceBackend;
use pyroclast::backends::offcpu::OffcpuBackend;
use pyroclast::backends::strace::StraceBackend;
use pyroclast::backends::{ProfileRequest, ProfilerBackend};
use pyroclast::cli::{PerfCallGraph, PerfEvent, ProfileKind, SymbolizerKind};
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};
use pyroclast::tools::{ResolvedTool, ToolSpec};

fn request(out_dir: std::path::PathBuf) -> ProfileRequest {
    ProfileRequest {
        kind: ProfileKind::Latency,
        command: vec!["workload".into()],
        out_dir,
        name: Some("named-run".into()),
        json: true,
        symbols: false,
        symbolizer: SymbolizerKind::RustAddr2line,
        frequency: 997,
        event: PerfEvent::Default,
        call_graph: PerfCallGraph::Dwarf,
        pid: None,
        tids: Vec::new(),
        threads_of_pid: None,
        duration_secs: 30,
        offcpu_method: None,
    }
}

struct MissingTools;

impl CommandRunner for MissingTools {
    fn run(&self, _: &CommandSpec) -> std::io::Result<CommandOutput> {
        panic!("a failed preflight must not launch the workload");
    }

    fn resolve_tool(&self, _: &ToolSpec) -> std::io::Result<ResolvedTool> {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing tool",
        ))
    }
}

#[test]
fn every_recording_backend_invalidates_previous_success_before_preflight() {
    let runner = MissingTools;
    let backends: Vec<Box<dyn ProfilerBackend + '_>> = vec![
        Box::new(LinuxPerfBackend::new(&runner)),
        Box::new(HeaptrackBackend::new(&runner)),
        Box::new(StraceBackend::new(&runner)),
        Box::new(MacosXctraceBackend::new(&runner)),
        Box::new(OffcpuBackend::new(&runner)),
    ];
    for backend in backends {
        let root = tempfile::tempdir().unwrap();
        let layout = ArtifactLayout::new(root.path().to_path_buf());
        for path in [
            layout.run_json(),
            layout.summary_json(),
            layout.stacks_folded(),
            layout.raw_profile("perf.data"),
        ] {
            std::fs::write(path, "old success").unwrap();
        }

        let error = backend
            .profile(&request(root.path().to_path_buf()))
            .unwrap_err();
        assert!(error.to_string().contains("missing tool"));
        assert!(!layout.run_json().exists());
        assert!(!layout.summary_json().exists());
        assert!(!layout.stacks_folded().exists());
        assert!(!layout.raw_profile("perf.data").exists());
    }
}

struct DelayedStrace;

impl CommandRunner for DelayedStrace {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        assert!(command.interactive);
        assert!(
            command.capture_output,
            "JSON output must capture workload stdout"
        );
        let path = command
            .args
            .windows(2)
            .find(|pair| pair[0] == "-o")
            .unwrap()[1]
            .as_str();
        std::thread::sleep(std::time::Duration::from_millis(25));
        std::fs::write(path, "42 100.0 read(3, \"x\", 1) = 1 <0.001000>\n")?;
        Ok(CommandOutput {
            status_code: Some(0),
            stdout: b"workload output".to_vec(),
            stderr: Vec::new(),
        })
    }
}

#[test]
fn recording_manifest_covers_execution_time_and_retains_name() {
    let root = tempfile::tempdir().unwrap();
    let result = StraceBackend::new(&DelayedStrace)
        .profile(&request(root.path().to_path_buf()))
        .unwrap();
    let manifest = serde_json::to_value(&result.manifest).unwrap();
    assert_eq!(manifest["name"], "named-run");
    assert!(result.manifest.ended_at_unix_ms.unwrap() - result.manifest.started_at_unix_ms >= 20);
    assert_eq!(
        std::fs::read(result.layout.stdout_log()).unwrap(),
        b"workload output"
    );
}
