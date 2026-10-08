#![cfg(unix)]

use pyroclast::backends::offcpu::{OffcpuBackend, OffcpuMethod};
use pyroclast::backends::{ProfileRequest, ProfilerBackend};
use pyroclast::cli::{PerfCallGraph, PerfEvent, ProfileKind, SymbolizerKind};
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};

// Model bpftrace's native -c/-o contract, but execute the real generated launcher.
struct Recorder {
    stop: Option<bool>, // true: duration, false: interruption
}

impl CommandRunner for Recorder {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        let child = command.args.windows(2).find(|a| a[0] == "-c").unwrap();
        let argv: Vec<_> = child[1].split_whitespace().collect();
        let mut process = if self.stop.is_some() {
            let mut process = std::process::Command::new("timeout");
            process.args(["--signal=TERM", "0.1"]);
            process.args(&argv);
            process
        } else {
            let mut process = std::process::Command::new(argv[0]);
            process.args(&argv[1..]);
            process
        };
        let child_output = process.output()?;
        let mut data = b"@offcpu[\n    1 real_wait+0 ([kernel.kallsyms])\n]: 200\n".to_vec();
        if self.stop == Some(true) {
            data.extend_from_slice(b"@duration_limited: 1\n");
        }
        let mut stdout = child_output.stdout;
        if let Some([_, output]) = command.args.windows(2).find(|a| a[0] == "-o") {
            std::fs::write(output, data)?;
        } else {
            stdout.extend(data);
        }
        Ok(CommandOutput {
            status_code: Some(0),
            stdout,
            stderr: child_output.stderr,
        })
    }
}

fn request(root: &std::path::Path, command: Vec<String>) -> ProfileRequest {
    ProfileRequest {
        kind: ProfileKind::Offcpu,
        command,
        out_dir: root.to_path_buf(),
        name: None,
        json: true,
        symbols: false,
        symbolizer: SymbolizerKind::Addr2line,
        frequency: 997,
        event: PerfEvent::Default,
        call_graph: PerfCallGraph::Fp,
        pid: None,
        tids: Vec::new(),
        threads_of_pid: None,
        duration_secs: 1,
        offcpu_method: Some(OffcpuMethod::Bpftrace),
    }
}

#[test]
fn offcpu_workload_nonzero_is_not_recorder_success() {
    let root = tempfile::tempdir().unwrap();
    let request = request(root.path(), vec!["sh".into(), "-c".into(), "exit 7".into()]);
    let result = OffcpuBackend::new(&Recorder { stop: None })
        .profile(&request)
        .unwrap();
    assert_eq!(result.manifest.exit_status, Some(7));
}

#[test]
fn offcpu_workload_exit_130_is_completed_not_interrupted() {
    let root = tempfile::tempdir().unwrap();
    let request = request(
        root.path(),
        vec!["sh".into(), "-c".into(), "exit 130".into()],
    );
    let result = OffcpuBackend::new(&Recorder { stop: None })
        .profile(&request)
        .unwrap();
    assert_eq!(result.manifest.exit_status, Some(130));
    assert!(
        result
            .manifest
            .diagnostics
            .contains(&"workload outcome: completed".into())
    );
}

#[test]
fn offcpu_workload_arguments_remain_literal_in_logs() {
    let root = tempfile::tempdir().unwrap();
    let request = request(
        root.path(),
        vec![
            "sh".into(),
            "-c".into(),
            "printf '%s\\n' \"$@\"".into(),
            "workload".into(),
            "argument with spaces".into(),
            "embedded'quote".into(),
            "$(printf literal)".into(),
        ],
    );
    let result = OffcpuBackend::new(&Recorder { stop: None })
        .profile(&request)
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(result.layout.stdout_log()).unwrap(),
        "argument with spaces\nembedded'quote\n$(printf literal)\n"
    );
}

#[test]
fn offcpu_workload_missing_executable_is_not_success() {
    let root = tempfile::tempdir().unwrap();
    let request = request(
        root.path(),
        vec!["/pyroclast-nonexistent-executable".into()],
    );
    let result = OffcpuBackend::new(&Recorder { stop: None })
        .profile(&request)
        .unwrap();
    assert_eq!(result.manifest.exit_status, Some(127));
    assert!(
        !std::fs::read(result.layout.stderr_log())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn offcpu_workload_stdout_is_logs_not_stack_data_and_runs_once() {
    let root = tempfile::tempdir().unwrap();
    let count = root.path().join("count");
    let script = "printf x >> \"$1\"; printf '@offcpu[\\n    9 forged+0 ([kernel.kallsyms])\\n]: 999999999999\\n'; printf 'workload stderr\\n' >&2";
    let request = request(
        root.path(),
        vec![
            "sh".into(),
            "-c".into(),
            script.into(),
            "workload".into(),
            count.display().to_string(),
        ],
    );
    let result = OffcpuBackend::new(&Recorder { stop: None })
        .profile(&request)
        .unwrap();
    assert_eq!(std::fs::read(&count).unwrap(), b"x");
    assert_eq!(result.manifest.exit_status, Some(0));
    assert_eq!(
        std::fs::read_to_string(result.layout.stacks_folded()).unwrap(),
        "real_wait 200\n"
    );
    assert!(
        std::fs::read_to_string(result.layout.stdout_log())
            .unwrap()
            .contains("forged")
    );
    assert!(
        !std::fs::read_to_string(result.layout.raw_profile("bpftrace"))
            .unwrap()
            .contains("forged")
    );
    assert!(
        std::fs::read_to_string(result.layout.stderr_log())
            .unwrap()
            .contains("workload stderr")
    );
}

#[test]
fn offcpu_workload_duration_limit_is_not_successful_completion() {
    stopped_workload(true);
}

#[test]
fn offcpu_workload_interruption_is_not_workload_exit_130() {
    stopped_workload(false);
}

fn stopped_workload(duration: bool) {
    let root = tempfile::tempdir().unwrap();
    let request = request(root.path(), vec!["sleep".into(), "5".into()]);
    let result = OffcpuBackend::new(&Recorder {
        stop: Some(duration),
    })
    .profile(&request)
    .unwrap();
    assert_eq!(result.manifest.exit_status, None);
    let outcome = if duration {
        "duration_limited"
    } else {
        "interrupted"
    };
    assert!(
        result
            .manifest
            .diagnostics
            .contains(&format!("workload outcome: {outcome}"))
    );
}
