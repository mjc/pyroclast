use std::sync::Mutex;

use pyroclast::backends::offcpu::{OffcpuBackend, OffcpuMethod};
use pyroclast::backends::{ProfileRequest, ProfilerBackend};
use pyroclast::cli::{PerfCallGraph, PerfEvent, ProfileKind, SymbolizerKind};
use pyroclast::perfdata::samples::{PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_TID};
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};

#[test]
fn offcpu_backend_defaults_to_perf_sched_summary_artifacts() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("offcpu");
    let runner = RecordingOffcpuRunner::default();
    let request = ProfileRequest {
        kind: ProfileKind::Offcpu,
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
        duration_secs: 30,
        offcpu_method: None,
    };

    let result = OffcpuBackend::new(&runner)
        .profile(&request)
        .expect("offcpu profile");

    assert!(result.layout.raw_profile("perf.data").is_file());
    assert_eq!(
        std::fs::read_to_string(result.layout.command_txt()).expect("command txt"),
        "target/release/app --serve\n"
    );
    assert!(!result.layout.stacks_folded().exists());
    let summary_text = std::fs::read_to_string(result.layout.summary_txt()).unwrap();
    assert!(summary_text.contains("offcpu wait milliseconds: 14.000"));
    let summary_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(result.layout.summary_json()).unwrap())
            .expect("summary json");
    assert_eq!(summary_json["method"], "perf_sched");
    assert_eq!(summary_json["target_pid"], 42);
    assert_eq!(summary_json["total_wait_ms"], 14.0);
    assert_eq!(summary_json["total_sched_delay_ms"], 3.0);
    assert_eq!(summary_json["total_run_ms"], 3.0);
    assert_eq!(summary_json["threads"].as_array().unwrap().len(), 2);
    assert_eq!(summary_json["threads"][0]["name"], "app");
    assert_eq!(
        summary_json["timehist_raw"],
        "99.000000 [0000] sh[42] 0.000 0.000 0.000\n100.000000 [0000] app[42] 10.000 2.000 1.000\n100.001000 [0001] worker[43/42] 4.000 1.000 2.000\n100.002000 [0000] unrelated[99] 500.000 0.000 1.000\n"
    );
    assert_eq!(result.manifest.duration_secs, None);
    assert_eq!(result.manifest.sample_event, PerfEvent::Default);
    assert_eq!(
        result
            .manifest
            .tool_versions
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        vec!["perf"]
    );
    assert!(
        !result
            .manifest
            .artifacts
            .contains(&result.layout.stacks_folded())
    );
    assert_eq!(
        result.manifest.diagnostics,
        vec!["offcpu method: perf_sched".to_string()]
    );
    assert_eq!(runner.programs(), vec!["perf", "perf"]);
}

#[test]
fn offcpu_backend_bpftrace_method_writes_folded_stack_artifacts() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("offcpu");
    let runner = RecordingOffcpuRunner::default();
    let request = ProfileRequest {
        kind: ProfileKind::Offcpu,
        command: vec![
            "sh".into(),
            "-c".into(),
            "printf 'workload stdout\\n'; printf 'workload stderr\\n' >&2; exit 7".into(),
        ],
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
        duration_secs: 30,
        offcpu_method: Some(OffcpuMethod::Bpftrace),
    };

    let result = OffcpuBackend::new(&runner)
        .profile(&request)
        .expect("offcpu profile");

    assert!(result.layout.raw_profile("bpftrace").is_file());
    assert_eq!(
        std::fs::read_to_string(result.layout.raw_profile("bpftrace")).unwrap(),
        "@offcpu[\n    55 tokio::runtime::park+12 (/bin/app)\n    44 app::serve+7 (/bin/app)\n]: 1500\n"
    );
    assert_eq!(
        std::fs::read_to_string(result.layout.stdout_log()).unwrap(),
        "workload stdout\n"
    );
    assert_eq!(
        std::fs::read_to_string(result.layout.stderr_log()).unwrap(),
        "workload stderr\n"
    );
    assert_eq!(result.manifest.exit_status, Some(7));
    assert_eq!(
        std::fs::read_to_string(result.layout.stacks_folded()).expect("folded"),
        "app::serve;tokio::runtime::park 1500\n"
    );
    assert!(result.layout.flamegraph_svg().is_file());
    assert!(
        result
            .manifest
            .artifacts
            .contains(&result.layout.flamegraph_svg())
    );
    let summary_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(result.layout.summary_json()).unwrap())
            .expect("summary json");
    assert_eq!(summary_json["method"], "bpftrace");
    assert_eq!(summary_json["folded_lines"], 1);
    assert_eq!(summary_json["total_offcpu_ns"], 1500);
    assert_eq!(summary_json["workload_outcome"], "completed");
    assert_eq!(result.manifest.duration_secs, Some(30));
    assert_eq!(
        result
            .manifest
            .tool_versions
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        vec!["bpftrace"]
    );
    assert!(
        result
            .manifest
            .artifacts
            .contains(&result.layout.stacks_folded())
    );
    assert_eq!(
        result.manifest.diagnostics,
        vec![
            "offcpu method: bpftrace".to_string(),
            "workload outcome: completed".to_string()
        ]
    );
    assert_eq!(runner.programs(), vec!["bpftrace"]);
}

#[cfg(unix)]
#[test]
fn bpftrace_backend_captures_real_child_output_and_preserves_workload_arguments() {
    struct FixtureBpftrace;
    impl CommandRunner for FixtureBpftrace {
        fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
            run_fixture_bpftrace(command,
                b"@offcpu[\n    55 kernel_wait+12 ([kernel.kallsyms])\n    44 workload+7 ([kernel.kallsyms])\n]: 1500\n")
        }
    }

    let root = tempfile::tempdir().unwrap();
    let request = ProfileRequest {
        kind: ProfileKind::Offcpu,
        command: vec![
            "sh".into(),
            "-c".into(),
            "printf '%s\\n' \"$@\"".into(),
            "workload".into(),
            "argument with spaces".into(),
            "embedded'quote".into(),
            "$(printf must-stay-literal)".into(),
        ],
        out_dir: root.path().to_path_buf(),
        name: None,
        json: false,
        symbols: false,
        symbolizer: SymbolizerKind::RustAddr2line,
        frequency: 997,
        event: PerfEvent::Default,
        call_graph: PerfCallGraph::Dwarf,
        pid: None,
        tids: Vec::new(),
        threads_of_pid: None,
        duration_secs: 30,
        offcpu_method: Some(OffcpuMethod::Bpftrace),
    };
    let result = OffcpuBackend::new(&FixtureBpftrace)
        .profile(&request)
        .unwrap();
    let raw = std::fs::read_to_string(result.layout.raw_profile("bpftrace")).unwrap();
    assert_eq!(
        raw,
        "@offcpu[\n    55 kernel_wait+12 ([kernel.kallsyms])\n    44 workload+7 ([kernel.kallsyms])\n]: 1500\n"
    );
    assert_eq!(
        std::fs::read_to_string(result.layout.stdout_log()).unwrap(),
        "argument with spaces\nembedded'quote\n$(printf must-stay-literal)\n"
    );
    assert_eq!(std::fs::read(result.layout.stderr_log()).unwrap(), b"");
    assert_eq!(result.manifest.exit_status, Some(0));
    assert_eq!(
        std::fs::read_to_string(result.layout.stacks_folded()).unwrap(),
        "workload;kernel_wait 1500\n"
    );
    let summary: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(result.layout.summary_json()).unwrap())
            .unwrap();
    assert_eq!(summary["weight_unit"], "nanoseconds");
    assert_eq!(summary["total_offcpu_ns"], 1500);
    assert_eq!(summary["workload_outcome"], "completed");
}

// bpftrace splits -c on spaces, captures child status internally, and writes
// only recorder data to -o. Run the actual launcher, not a fabricated status.
fn run_fixture_bpftrace(command: &CommandSpec, data: &[u8]) -> std::io::Result<CommandOutput> {
    let child = command
        .args
        .windows(2)
        .find(|args| args[0] == "-c")
        .expect("-c workload");
    let output_path = command
        .args
        .windows(2)
        .find(|args| args[0] == "-o")
        .expect("-o recorder channel");
    let argv: Vec<_> = child[1].split_whitespace().collect();
    let mut launcher = command.clone();
    launcher.program = argv[0].into();
    launcher.args = argv[1..].iter().map(|arg| (*arg).into()).collect();
    let mut output = pyroclast::process::RealCommandRunner::default().run(&launcher)?;
    assert_eq!(
        output.status_code,
        Some(0),
        "supervisor must finish successfully independently of workload status"
    );
    std::fs::write(&output_path[1], data)?;
    output.status_code = Some(0); // Recorder success, not workload success.
    Ok(output)
}

#[test]
fn offcpu_backend_rejects_cpu_clock_as_an_offcpu_measurement() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("offcpu");
    let runner = RecordingOffcpuRunner::default();
    let request = ProfileRequest {
        kind: ProfileKind::Offcpu,
        command: vec!["target/release/app".to_string()],
        out_dir: out,
        name: None,
        json: false,
        symbols: false,
        symbolizer: SymbolizerKind::Addr2line,
        frequency: 997,
        event: PerfEvent::Cycles,
        call_graph: PerfCallGraph::Fp,
        pid: None,
        tids: Vec::new(),
        threads_of_pid: None,
        duration_secs: 30,
        offcpu_method: Some(OffcpuMethod::PerfCpuClock),
    };

    let error = OffcpuBackend::new(&runner)
        .profile(&request)
        .expect_err("CPU-clock cannot measure off-CPU waits");
    assert!(error.to_string().contains("on-CPU"));
    assert!(runner.programs().is_empty());
}

#[test]
fn offcpu_backend_rejects_attach_workflows() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("offcpu");
    let runner = RecordingOffcpuRunner::default();
    let request = ProfileRequest {
        kind: ProfileKind::Offcpu,
        command: Vec::new(),
        out_dir: out,
        name: None,
        json: false,
        symbols: false,
        symbolizer: SymbolizerKind::Addr2line,
        frequency: 997,
        event: PerfEvent::CpuClock,
        call_graph: PerfCallGraph::Fp,
        pid: Some(99),
        tids: Vec::new(),
        threads_of_pid: None,
        duration_secs: 30,
        offcpu_method: None,
    };

    let error = OffcpuBackend::new(&runner)
        .profile(&request)
        .expect_err("attach workflow should fail");

    assert_eq!(
        error.to_string(),
        "offcpu currently supports command-driven workflows only"
    );
    assert!(runner.programs().is_empty());
    assert!(!root.path().join("offcpu").exists());
}

#[test]
fn offcpu_backend_writes_tool_errors_when_perf_sched_timehist_fails() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("offcpu");
    let runner = RecordingOffcpuRunner::failing_timehist();
    let request = ProfileRequest {
        kind: ProfileKind::Offcpu,
        command: vec!["target/release/app".to_string()],
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
        duration_secs: 30,
        offcpu_method: None,
    };

    let error = OffcpuBackend::new(&runner)
        .profile(&request)
        .expect_err("timehist failure");

    assert!(
        error
            .to_string()
            .contains("perf sched timehist exited with Some(2)")
    );
    assert_eq!(
        std::fs::read_to_string(out.join("tool-errors.log")).expect("tool errors"),
        "perf sched timehist exited with Some(2): timehist failed\n"
    );
    assert!(!out.join("summary.txt").exists());
}

#[derive(Default)]
struct RecordingOffcpuRunner {
    commands: Mutex<Vec<CommandSpec>>,
    fail_timehist: bool,
}

impl RecordingOffcpuRunner {
    fn failing_timehist() -> Self {
        Self {
            commands: Mutex::default(),
            fail_timehist: true,
        }
    }

    fn programs(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .map(|command| command.program.clone())
            .collect()
    }
}

impl CommandRunner for RecordingOffcpuRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        if command.args == ["--version"] {
            return Ok(CommandOutput {
                status_code: Some(0),
                stdout: format!("{} fake version\n", command.program).into_bytes(),
                stderr: Vec::new(),
            });
        }
        if command.program == "bpftrace" {
            return run_fixture_bpftrace(command,
                b"@offcpu[\n    55 tokio::runtime::park+12 (/bin/app)\n    44 app::serve+7 (/bin/app)\n]: 1500\n");
        }
        for (key, value) in &command.env {
            if key == "PYROCLAST_OFFCPU_TARGET_PID" {
                std::fs::write(value, "42\n")?;
            }
        }
        if let Some(output_path) = perf_output_path(command) {
            std::fs::write(output_path, tiny_perfdata())?;
        }
        let stdout = match command.program.as_str() {
            "perf"
                if command.args.first().map(String::as_str) == Some("sched")
                    && command.args.get(1).map(String::as_str) == Some("timehist") =>
            {
                if self.fail_timehist {
                    Vec::new()
                } else {
                    b"99.000000 [0000] sh[42] 0.000 0.000 0.000\n100.000000 [0000] app[42] 10.000 2.000 1.000\n100.001000 [0001] worker[43/42] 4.000 1.000 2.000\n100.002000 [0000] unrelated[99] 500.000 0.000 1.000\n".to_vec()
                }
            }
            _ => Vec::new(),
        };
        Ok(CommandOutput {
            status_code: if self.fail_timehist
                && command.program == "perf"
                && command.args.first().map(String::as_str) == Some("sched")
                && command.args.get(1).map(String::as_str) == Some("timehist")
            {
                Some(2)
            } else {
                Some(0)
            },
            stdout,
            stderr: if self.fail_timehist
                && command.program == "perf"
                && command.args.first().map(String::as_str) == Some("sched")
                && command.args.get(1).map(String::as_str) == Some("timehist")
            {
                b"timehist failed".to_vec()
            } else {
                Vec::new()
            },
        })
    }
}

fn perf_output_path(command: &CommandSpec) -> Option<&str> {
    (command.program == "perf")
        .then(|| {
            command
                .args
                .windows(2)
                .find(|window| window[0] == "-o")
                .map(|window| window[1].as_str())
        })
        .flatten()
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

fn file_attr_bytes(sample_type: u64, sample_id_all: u8, freq: u64) -> [u8; 144] {
    let mut bytes = [0; 144];
    put_u32(&mut bytes, 4, 128);
    put_u64(&mut bytes, 24, sample_type);
    put_u64(&mut bytes, 128, sample_id_all.into());
    put_u64(&mut bytes, 136, freq);
    bytes
}

fn record_bytes(record_type: u32, payload: &[u8]) -> Vec<u8> {
    let size = u16::try_from(8 + payload.len()).expect("record fits in u16");
    let mut bytes = Vec::with_capacity(size as usize);
    bytes.extend_from_slice(&record_type.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn sample_payload<const N: usize>(ip: u64, pid: u32, tid: u32, callchain: [u64; N]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&ip.to_le_bytes());
    bytes.extend_from_slice(&pid.to_le_bytes());
    bytes.extend_from_slice(&tid.to_le_bytes());
    bytes.extend_from_slice(&(N as u64).to_le_bytes());
    for frame in callchain {
        bytes.extend_from_slice(&frame.to_le_bytes());
    }
    bytes
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
