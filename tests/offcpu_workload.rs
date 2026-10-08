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

#[cfg(target_os = "linux")]
fn cli_recorder_fixture(tools: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir(tools).unwrap();
    let recorder = tools.join("bpftrace");
    // Execute the real product supervisor. The recorder deliberately exits
    // successfully regardless of the supervised workload's exit status.
    std::fs::write(
        &recorder,
        r#"#!/bin/sh
if [ "$1" = --version ]; then echo 'bpftrace v0.24.0'; exit 0; fi
while [ $# -gt 0 ]; do
    case "$1" in
        -c) shift; workload=$1 ;;
        -o) shift; data=$1 ;;
    esac
    shift
done
/bin/sh -c "$workload"
printf '@offcpu[\n    1 real_wait+0 ([kernel.kallsyms])\n]: 200\n' > "$data"
exit 0
"#,
    )
    .unwrap();
    std::fs::set_permissions(&recorder, std::fs::Permissions::from_mode(0o755)).unwrap();
    let cargo = tools.join("cargo");
    std::fs::write(
        &cargo,
        "#!/bin/sh\ncat \"$PYROCLAST_TEST_CARGO_ARTIFACT\"\n",
    )
    .unwrap();
    std::fs::set_permissions(cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(target_os = "linux")]
fn cli_cargo_artifact(root: &std::path::Path, executable: &str) -> std::path::PathBuf {
    let path = root.join("cargo-artifact.json");
    let artifact = serde_json::json!({
        "reason": "compiler-artifact", "package_id": "path+file:///fixture#fixture@0.1.0",
        "manifest_path": "/fixture/Cargo.toml",
        "target": {
            "name": "fixture", "kind": ["bin"], "crate_types": ["bin"],
            "src_path": "/fixture/src/main.rs", "edition": "2024",
            "doc": true, "doctest": false, "test": true,
        },
        "profile": {
            "opt_level": "0", "debuginfo": 2, "debug_assertions": false,
            "overflow_checks": true, "test": false,
        },
        "features": [], "filenames": [], "executable": executable, "fresh": true,
    });
    std::fs::write(&path, format!("{artifact}\n")).unwrap();
    path
}

#[cfg(target_os = "linux")]
fn assert_cli_workload_status(workload: &[&str], status: i32) {
    for (json, cargo, closed_pipe) in [
        (false, false, false),
        (true, false, false),
        (true, false, true),
        (false, true, false),
        (true, true, false),
    ] {
        let root = tempfile::tempdir().unwrap();
        let tools = root.path().join("bin");
        cli_recorder_fixture(&tools);
        let out = root.path().join("run");
        let mut command = std::process::Command::new(if cargo {
            env!("CARGO_BIN_EXE_cargo-pyroclast")
        } else {
            env!("CARGO_BIN_EXE_pyroclast")
        });
        if cargo {
            command.args(["pyroclast", "offcpu", "--bin", "fixture"]);
            command.env(
                "PYROCLAST_TEST_CARGO_ARTIFACT",
                cli_cargo_artifact(root.path(), workload[0]),
            );
        } else {
            command.arg("offcpu");
        }
        command
            .args(["--offcpu-method", "bpftrace", "--out"])
            .arg(&out)
            .env(
                "PATH",
                format!("{}:{}", tools.display(), std::env::var("PATH").unwrap()),
            );
        if json {
            command.arg("--json");
        }
        command
            .arg("--")
            .args(if cargo { &workload[1..] } else { workload });
        let output = if closed_pipe {
            let mut child = command
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            drop(child.stdout.take());
            child.wait_with_output().unwrap()
        } else {
            command.output().unwrap()
        };
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("run.json")).unwrap()).unwrap();
        assert_eq!(manifest["exit_status"], status);
        if json && !closed_pipe {
            let emitted: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(emitted, manifest);
        } else {
            assert!(output.stdout.is_empty(), "{output:?}");
        }
        assert_eq!(
            output.status.code(),
            Some(status),
            "workload={workload:?}, json={json}, cargo={cargo}, closed_pipe={closed_pipe}, stderr={}",
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn cli_offcpu_returns_actual_workload_failure_in_both_output_modes() {
    assert_cli_workload_status(&["sh", "-c", "exit 7"], 7);
}

#[cfg(target_os = "linux")]
#[test]
fn cli_offcpu_returns_launch_failure_in_both_output_modes() {
    assert_cli_workload_status(&["/pyroclast-nonexistent-executable"], 127);
}

#[cfg(target_os = "linux")]
#[test]
fn cli_offcpu_returns_completed_exit_130_in_both_output_modes() {
    assert_cli_workload_status(&["sh", "-c", "exit 130"], 130);
}

#[cfg(target_os = "linux")]
#[test]
fn cli_offcpu_returns_success_in_both_output_modes() {
    assert_cli_workload_status(&["sh", "-c", "exit 0"], 0);
}
