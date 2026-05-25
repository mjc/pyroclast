use std::sync::Mutex;

use pyroclast::backends::linux_perf::LinuxPerfBackend;
use pyroclast::backends::{BackendResult, ProfileRequest, ProfilerBackend};
use pyroclast::cli::{PerfCallGraph, PerfEvent, ProfileKind};
use pyroclast::flamegraph::{FlamegraphRenderResult, FlamegraphRenderer, FlamegraphRequest};
use pyroclast::manifest::BackendName;
use pyroclast::perfdata::samples::{PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_TID};
use pyroclast::platform::ThreadLister;
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};

#[test]
fn linux_perf_backend_records_with_perf_and_writes_artifacts() {
    let root = tempfile::tempdir().expect("tempdir");
    let runner = RecordingRunner::default();
    let backend = LinuxPerfBackend::new(&runner);
    let request = ProfileRequest {
        kind: ProfileKind::Cpu,
        command: vec!["true".to_string()],
        out_dir: root.path().join("cpu"),
        name: None,
        json: false,
        symbols: false,
        frequency: 199,
        event: PerfEvent::CpuClock,
        call_graph: PerfCallGraph::Dwarf,
        pid: None,
        tids: Vec::new(),
        threads_of_pid: None,
        duration_secs: 3600,
    };

    let result = backend.profile(&request).expect("profile");

    assert_eq!(result.manifest.actual_backend, BackendName::LinuxPerf);
    assert_eq!(result.manifest.sample_frequency, 199);
    assert_eq!(result.manifest.call_graph, PerfCallGraph::Dwarf);
    assert!(!result.manifest.symbols);
    assert_eq!(
        result
            .manifest
            .tool_versions
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        vec!["perf", "inferno-flamegraph"]
    );
    assert_eq!(
        runner.programs(),
        vec!["perf", "inferno-flamegraph", "perf", "inferno-flamegraph"]
    );
    assert_eq!(runner.perf_frequency(), Some("199".to_string()));
    assert_eq!(runner.perf_call_graph(), Some("dwarf".to_string()));
    assert!(result.layout.raw_profile("perf.data").is_file());
    assert_eq!(
        std::fs::read(result.layout.raw_profile("perf.data")).expect("perf data"),
        tiny_perfdata()
    );
    assert_eq!(
        std::fs::read_to_string(result.layout.stacks_folded()).expect("stacks folded"),
        "app;/bin/app+0x1000 1\n"
    );
    assert_eq!(
        std::fs::read_to_string(result.layout.flamegraph_svg()).expect("flamegraph svg"),
        "<svg></svg>\n"
    );
    let summary_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(result.layout.summary_json()).expect("summary json"),
    )
    .expect("parse summary json");
    assert_eq!(summary_json["folded_lines"], 1);
    assert_eq!(summary_json["folded_bytes"], 22);
    assert_eq!(summary_json["total_count"], 1);
    assert_eq!(
        std::fs::read_to_string(result.layout.summary_txt()).expect("summary txt"),
        "folded lines: 1\nfolded bytes: 22\ntotal count: 1\n"
    );
    assert!(result.layout.run_json().is_file());
    assert!(result.layout.stderr_log().is_file());
}

#[test]
fn linux_perf_backend_can_symbolize_folded_stacks() {
    let root = tempfile::tempdir().expect("tempdir");
    let runner = RecordingRunner::default();
    let backend = LinuxPerfBackend::new(&runner);
    let request = ProfileRequest {
        kind: ProfileKind::Cpu,
        command: vec!["true".to_string()],
        out_dir: root.path().join("cpu"),
        name: None,
        json: false,
        symbols: true,
        frequency: 997,
        event: PerfEvent::CpuClock,
        call_graph: PerfCallGraph::Fp,
        pid: None,
        tids: Vec::new(),
        threads_of_pid: None,
        duration_secs: 3600,
    };

    let result = backend.profile(&request).expect("profile");

    assert_eq!(
        runner.programs(),
        vec![
            "perf",
            "addr2line",
            "inferno-flamegraph",
            "perf",
            "inferno-flamegraph",
            "addr2line"
        ]
    );
    assert_eq!(
        std::fs::read_to_string(result.layout.stacks_folded()).expect("stacks folded"),
        "app;app::work 1\n"
    );
}

#[test]
fn linux_perf_backend_accepts_pluggable_flamegraph_renderer() {
    let root = tempfile::tempdir().expect("tempdir");
    let runner = RecordingRunner::default();
    let renderer = RecordingRenderer::default();
    let backend = LinuxPerfBackend::with_renderer(&runner, &renderer);
    let request = ProfileRequest {
        kind: ProfileKind::Cpu,
        command: vec!["true".to_string()],
        out_dir: root.path().join("cpu"),
        name: None,
        json: false,
        symbols: false,
        frequency: 997,
        event: PerfEvent::CpuClock,
        call_graph: PerfCallGraph::Fp,
        pid: None,
        tids: Vec::new(),
        threads_of_pid: None,
        duration_secs: 3600,
    };

    let result = backend.profile(&request).expect("profile");

    assert_eq!(renderer.folded_stacks(), "app;/bin/app+0x1000 1\n");
    assert_eq!(
        std::fs::read_to_string(result.layout.flamegraph_svg()).expect("flamegraph svg"),
        "<svg>plugin</svg>\n"
    );
    assert_eq!(runner.programs(), vec!["perf", "perf"]);
    assert_eq!(
        result
            .manifest
            .tool_versions
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        vec!["perf"]
    );
}

#[test]
fn linux_perf_backend_records_attached_process() {
    let root = tempfile::tempdir().expect("tempdir");
    let runner = RecordingRunner::default();
    let backend = LinuxPerfBackend::new(&runner);
    let request = ProfileRequest {
        kind: ProfileKind::Cpu,
        command: Vec::new(),
        out_dir: root.path().join("cpu"),
        name: None,
        json: false,
        symbols: false,
        frequency: 199,
        event: PerfEvent::CpuClock,
        call_graph: PerfCallGraph::Fp,
        pid: Some(99),
        tids: Vec::new(),
        threads_of_pid: None,
        duration_secs: 5,
    };

    backend.profile(&request).expect("profile");

    assert_eq!(
        std::fs::read_to_string(root.path().join("cpu/command.txt")).expect("command txt"),
        "pid:99\n"
    );
    assert_eq!(
        runner.first_perf_args(),
        vec![
            "record",
            "-e",
            "cpu-clock",
            "-F",
            "199",
            "-g",
            "--call-graph",
            "fp",
            "-p",
            "99",
            "-o",
            root.path()
                .join("cpu/profile.raw.perf.data")
                .display()
                .to_string()
                .as_str(),
            "--",
            "sleep",
            "5",
        ]
    );
}

#[test]
fn linux_perf_backend_records_attached_threads() {
    let root = tempfile::tempdir().expect("tempdir");
    let runner = RecordingRunner::default();
    let backend = LinuxPerfBackend::new(&runner);
    let request = ProfileRequest {
        kind: ProfileKind::Cpu,
        command: Vec::new(),
        out_dir: root.path().join("cpu"),
        name: None,
        json: false,
        symbols: false,
        frequency: 997,
        event: PerfEvent::CpuClock,
        call_graph: PerfCallGraph::Fp,
        pid: None,
        tids: vec![101, 102],
        threads_of_pid: None,
        duration_secs: 7,
    };

    backend.profile(&request).expect("profile");

    assert_eq!(
        std::fs::read_to_string(root.path().join("cpu/command.txt")).expect("command txt"),
        "tids:101,102\n"
    );
    assert!(runner.first_perf_args().contains(&"-t".to_string()));
    assert!(runner.first_perf_args().contains(&"101,102".to_string()));
    assert!(runner.first_perf_args().ends_with(&[
        "--".to_string(),
        "sleep".to_string(),
        "7".to_string()
    ]));
}

#[test]
fn linux_perf_backend_records_threads_discovered_from_pid() {
    let root = tempfile::tempdir().expect("tempdir");
    let runner = RecordingRunner::default();
    let backend = LinuxPerfBackend::with_thread_lister(&runner, FakeThreadLister::new([101, 102]));
    let request = ProfileRequest {
        kind: ProfileKind::Cpu,
        command: Vec::new(),
        out_dir: root.path().join("cpu"),
        name: None,
        json: false,
        symbols: false,
        frequency: 997,
        event: PerfEvent::CpuClock,
        call_graph: PerfCallGraph::Fp,
        pid: None,
        tids: Vec::new(),
        threads_of_pid: Some(99),
        duration_secs: 7,
    };

    let result = backend.profile(&request).expect("profile");

    assert_eq!(result.manifest.record_target, "threads_of_pid");
    assert_eq!(
        std::fs::read_to_string(root.path().join("cpu/command.txt")).expect("command txt"),
        "threads-of-pid:99 tids:101,102\n"
    );
    assert!(runner.first_perf_args().contains(&"-t".to_string()));
    assert!(runner.first_perf_args().contains(&"101,102".to_string()));
}

#[test]
fn linux_perf_backend_reports_missing_threads_of_pid() {
    let root = tempfile::tempdir().expect("tempdir");
    let runner = RecordingRunner::default();
    let backend = LinuxPerfBackend::with_thread_lister(&runner, FakeThreadLister::empty());
    let request = ProfileRequest {
        kind: ProfileKind::Cpu,
        command: Vec::new(),
        out_dir: root.path().join("cpu"),
        name: None,
        json: false,
        symbols: false,
        frequency: 997,
        event: PerfEvent::CpuClock,
        call_graph: PerfCallGraph::Fp,
        pid: None,
        tids: Vec::new(),
        threads_of_pid: Some(99),
        duration_secs: 7,
    };

    let error = backend.profile(&request).expect_err("missing threads");

    assert!(error.to_string().contains("no thread ids found"));
    assert!(runner.programs().is_empty());
}

struct FakeThreadLister {
    tids: std::io::Result<Vec<u32>>,
}

impl FakeThreadLister {
    fn new<const N: usize>(tids: [u32; N]) -> Self {
        Self {
            tids: Ok(tids.to_vec()),
        }
    }

    fn empty() -> Self {
        Self {
            tids: Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no thread ids found",
            )),
        }
    }
}

impl ThreadLister for FakeThreadLister {
    fn thread_ids(&self, _pid: u32) -> std::io::Result<Vec<u32>> {
        self.tids
            .as_ref()
            .map(std::clone::Clone::clone)
            .map_err(|error| std::io::Error::new(error.kind(), error.to_string()))
    }
}

#[derive(Default)]
struct RecordingRenderer {
    folded_stacks: Mutex<String>,
}

impl RecordingRenderer {
    fn folded_stacks(&self) -> String {
        self.folded_stacks.lock().unwrap().clone()
    }
}

impl FlamegraphRenderer for &RecordingRenderer {
    fn render(&self, request: &FlamegraphRequest) -> BackendResult<FlamegraphRenderResult> {
        self.folded_stacks
            .lock()
            .unwrap()
            .clone_from(&request.folded_stacks);
        std::fs::write(&request.output, "<svg>plugin</svg>\n")?;
        Ok(FlamegraphRenderResult { stderr: Vec::new() })
    }
}

#[derive(Default)]
struct RecordingRunner {
    commands: Mutex<Vec<CommandSpec>>,
}

impl RecordingRunner {
    fn programs(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .map(|command| command.program.clone())
            .collect()
    }

    fn perf_frequency(&self) -> Option<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .find(|command| command.program == "perf")
            .and_then(|command| {
                command
                    .args
                    .windows(2)
                    .find(|window| window[0] == "-F")
                    .map(|window| window[1].clone())
            })
    }

    fn perf_call_graph(&self) -> Option<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .find(|command| command.program == "perf")
            .and_then(|command| {
                command
                    .args
                    .windows(2)
                    .find(|window| window[0] == "--call-graph")
                    .map(|window| window[1].clone())
            })
    }

    fn first_perf_args(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .find(|command| command.program == "perf")
            .map(|command| command.args.clone())
            .unwrap_or_default()
    }
}

impl CommandRunner for RecordingRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        if command.args == ["--version"] {
            return Ok(CommandOutput {
                status_code: Some(0),
                stdout: format!("{} fake version\n", command.program).into_bytes(),
                stderr: Vec::new(),
            });
        }
        if let Some(output_path) = perf_output_path(command) {
            std::fs::write(output_path, tiny_perfdata())?;
        }
        let stdout = match command.program.as_str() {
            "addr2line" => b"app::work\n/bin/app.rs:10\n".to_vec(),
            "inferno-flamegraph" => b"<svg></svg>\n".to_vec(),
            _ => b"perf stdout".to_vec(),
        };
        Ok(CommandOutput {
            status_code: Some(0),
            stdout,
            stderr: b"perf stderr".to_vec(),
        })
    }
}

fn perf_output_path(command: &CommandSpec) -> Option<&str> {
    command
        .args
        .windows(2)
        .find(|window| window[0] == "-o")
        .map(|window| window[1].as_str())
}

fn tiny_perfdata() -> Vec<u8> {
    perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(1, 2, "app")),
            record_bytes(1, &mmap_payload(1, 2, 0x1000, 0x2000, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 1, 2, [0x2000])),
        ],
    )
}

fn perfdata_with_records_and_attrs<const A: usize, const R: usize>(
    attrs: [[u8; 144]; A],
    records: [Vec<u8>; R],
) -> Vec<u8> {
    let attr_size = attrs.len() * 144;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size;
    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    for attr in attrs {
        bytes.extend(attr);
    }
    for record in records {
        bytes.extend(record);
    }
    bytes
}

fn file_attr_bytes(sample_type: u64, ids_offset: u64, ids_size: u64) -> [u8; 144] {
    let mut bytes = [0; 144];
    put_u32(&mut bytes, 4, 128);
    put_u64(&mut bytes, 24, sample_type);
    put_u64(&mut bytes, 128, ids_offset);
    put_u64(&mut bytes, 136, ids_size);
    bytes
}

fn record_bytes(record_type: u32, payload: &[u8]) -> Vec<u8> {
    let size = 8 + payload.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.extend(record_type.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend(
        u16::try_from(size)
            .expect("record fits in u16")
            .to_le_bytes(),
    );
    bytes.extend(payload);
    bytes
}

fn sample_payload<const N: usize>(ip: u64, pid: u32, tid: u32, callchain: [u64; N]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn comm_payload(pid: u32, tid: u32, comm: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(comm.as_bytes());
    payload.push(0);
    payload
}

fn mmap_payload(pid: u32, tid: u32, start: u64, len: u64, pgoff: u64, path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(start.to_le_bytes());
    payload.extend(len.to_le_bytes());
    payload.extend(pgoff.to_le_bytes());
    payload.extend(path.as_bytes());
    payload.push(0);
    payload
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
