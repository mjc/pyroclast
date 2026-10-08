#![cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn executable(path: &Path, script: &str) {
    std::fs::write(path, script).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn oracle_perf_wrapper_fallback_survives_record_compare_and_child_parity() {
    let root = tempfile::tempdir().unwrap();
    let tools = root.path().join("bin");
    let repo = root.path().join("repo");
    std::fs::create_dir_all(repo.join("scripts")).unwrap();
    std::fs::create_dir(&tools).unwrap();
    std::fs::copy(
        "scripts/check-perf-parity",
        repo.join("scripts/check-perf-parity"),
    )
    .unwrap();
    executable(&tools.join("perf"), "#!/bin/sh\nexit 99\n");
    executable(
        &tools.join("real-perf"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$AUDIT_LOG\"\ncase \"$1\" in version) echo real-perf;; record) shift; while [ $# -gt 0 ]; do if [ \"$1\" = -o ]; then shift; : > \"$1\"; break; fi; shift; done;; script) echo 'stack 1';; *) exit 24;; esac\n",
    );
    executable(&tools.join("find"), "#!/bin/sh\necho \"$REAL_PERF\"\n");
    executable(&tools.join("rustc"), "#!/bin/sh\nexit 0\n");
    executable(&tools.join("readelf"), "#!/bin/sh\nexit 0\n");
    executable(&tools.join("sysctl"), "#!/bin/sh\necho 0\n");
    executable(
        &tools.join("inferno-collapse-perf"),
        "#!/bin/sh\ncat \"$1\"\n",
    );
    executable(&tools.join("inferno-flamegraph"), "#!/bin/sh\ncat\n");
    executable(&tools.join("fake-pyroclast"), "#!/bin/sh\necho 'stack 1'\n");
    executable(&tools.join("fake-bench"), "#!/bin/sh\nexit 0\n");
    executable(
        &tools.join("cargo"),
        "#!/bin/sh\nmkdir -p \"$CARGO_TARGET_DIR/release/examples\"\ncp \"$FAKE_PYROCLAST\" \"$CARGO_TARGET_DIR/release/pyroclast\"\ncp \"$FAKE_BENCH\" \"$CARGO_TARGET_DIR/release/examples/pyroclast-bench\"\n",
    );
    let log = root.path().join("perf.log");
    let output = std::process::Command::new("bash")
        .arg("scripts/oracle/run-in-container.sh")
        .env(
            "PATH",
            format!("{}:{}", tools.display(), std::env::var("PATH").unwrap()),
        )
        .env_remove("PERF_BIN")
        .env("REAL_PERF", tools.join("real-perf"))
        .env("FAKE_PYROCLAST", tools.join("fake-pyroclast"))
        .env("FAKE_BENCH", tools.join("fake-bench"))
        .env("AUDIT_LOG", &log)
        .env("REPO", repo)
        .env("ORACLE_OUT", root.path().join("out"))
        .env("PERF_PARITY_OUT", root.path().join("parity"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "status={:?}\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = std::fs::read_to_string(log).unwrap();
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.starts_with("record "))
            .count(),
        2
    );
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.starts_with("script "))
            .count(),
        10
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout)
            .matches("native-perf-parity ")
            .count(),
        8
    );
}

#[test]
fn oracle_recorder_restores_host_settings_when_recording_fails() {
    assert_restored_settings("exit 23", 23);
}

#[test]
fn oracle_recorder_restores_host_settings_on_success() {
    assert_restored_settings("exit 0", 0);
}

#[test]
fn oracle_recorder_restores_host_settings_after_termination() {
    assert_restored_settings("kill -TERM \"$PPID\"; exit 0", 143);
}

fn assert_restored_settings(record_action: &str, expected_status: i32) {
    let root = tempfile::tempdir().unwrap();
    let tools = root.path().join("bin");
    std::fs::create_dir(&tools).unwrap();
    executable(
        &tools.join("perf"),
        &format!(
            "#!/bin/sh\nif [ \"$1\" = version ]; then echo test-perf; exit 0; fi\n{record_action}\n"
        ),
    );
    executable(&tools.join("rustc"), "#!/bin/sh\nexit 0\n");
    executable(&tools.join("inferno-collapse-perf"), "#!/bin/sh\nexit 0\n");
    executable(
        &tools.join("sysctl"),
        "#!/bin/sh\nif [ \"$1\" = -n ]; then case \"$2\" in kernel.perf_event_paranoid) echo 3;; kernel.kptr_restrict) echo 2;; esac; else printf '%s\\n' \"$*\" >> \"$AUDIT_LOG\"; fi\n",
    );
    let path = format!("{}:{}", tools.display(), std::env::var("PATH").unwrap());
    let log = root.path().join("settings.log");
    let output = std::process::Command::new("bash")
        .arg("scripts/oracle/record-in-container.sh")
        .env("PATH", path)
        .env("AUDIT_LOG", &log)
        .env("ORACLE_OUT", root.path().join("out"))
        .env("REPO", root.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(expected_status));
    let settings = std::fs::read_to_string(log).unwrap();
    assert!(
        settings.contains("kernel.perf_event_paranoid=3"),
        "{settings}"
    );
    assert!(settings.contains("kernel.kptr_restrict=2"), "{settings}");
}

#[test]
fn native_parity_gate_checks_both_inline_modes_and_symbolizers_and_fails_mismatches() {
    let root = tempfile::tempdir().unwrap();
    let tools = root.path().join("bin");
    std::fs::create_dir(&tools).unwrap();
    let data = root.path().join("perf.data");
    std::fs::write(&data, "fixture").unwrap();
    executable(
        &tools.join("perf"),
        "#!/bin/sh\n[ \"${PARITY_EMPTY:-}\" = yes ] && exit 0\n[ \"${PARITY_TOOL_FAIL:-}\" = yes ] && exit 23\nprintf '%s\\n' \"$*\" >> \"$AUDIT_LOG\"\ncase \" $* \" in *' --no-inline '*) echo 'plain 1';; *) echo 'inline 1';; esac\n",
    );
    executable(
        &tools.join("pyroclast"),
        "#!/bin/sh\nif [ \"${PARITY_MISMATCH:-}\" = yes ]; then echo 'wrong 1'; exit 0; fi\ncase \" $* \" in *' --no-inline '*) echo 'plain 1';; *) echo 'inline 1';; esac\n",
    );
    executable(
        &tools.join("inferno-collapse-perf"),
        "#!/bin/sh\ncat \"$1\"\n",
    );
    executable(&tools.join("inferno-flamegraph"), "#!/bin/sh\ncat\n");
    let log = root.path().join("native.log");
    let mut command = std::process::Command::new("bash");
    command
        .arg("scripts/check-perf-parity")
        .arg(&data)
        .env(
            "PATH",
            format!("{}:{}", tools.display(), std::env::var("PATH").unwrap()),
        )
        .env("PYROCLAST_BIN", tools.join("pyroclast"))
        .env_remove("PERF_BIN")
        .env("PERF_PARITY_OUT", root.path().join("parity"))
        .env("AUDIT_LOG", &log);
    let matching = command.output().unwrap();
    assert!(
        matching.status.success(),
        "{}",
        String::from_utf8_lossy(&matching.stderr)
    );
    let calls = std::fs::read_to_string(&log).unwrap();
    assert!(calls.contains("--inline"), "{calls}");
    assert!(calls.contains("--no-inline"), "{calls}");
    let report = String::from_utf8_lossy(&matching.stdout);
    for backend in ["rust-addr2line", "addr2line"] {
        for mode in ["inline", "no-inline"] {
            assert!(
                report.contains(&format!("symbolizer={backend} mode={mode}")),
                "{report}"
            );
        }
    }
    let mismatch = command.env("PARITY_MISMATCH", "yes").output().unwrap();
    assert!(!mismatch.status.success(), "a real diff must fail the gate");
    command.env_remove("PARITY_MISMATCH");
    let empty = command.env("PARITY_EMPTY", "yes").output().unwrap();
    assert!(
        !empty.status.success(),
        "an empty oracle must fail the gate"
    );
    command.env_remove("PARITY_EMPTY");
    let tool_failure = command.env("PARITY_TOOL_FAIL", "yes").output().unwrap();
    assert_eq!(tool_failure.status.code(), Some(23));
    command.env_remove("PARITY_TOOL_FAIL");
    std::fs::remove_file(data).unwrap();
    let missing = command.output().unwrap();
    assert!(
        !missing.status.success(),
        "missing required fixture must fail the gate"
    );
}

#[test]
fn oracle_comparison_rejects_a_missing_required_recording() {
    let root = tempfile::tempdir().unwrap();
    let tools = root.path().join("bin");
    std::fs::create_dir(&tools).unwrap();
    executable(&tools.join("cargo"), "#!/bin/sh\nexit 0\n");
    executable(&tools.join("readelf"), "#!/bin/sh\nexit 0\n");
    let output = std::process::Command::new("bash")
        .arg("scripts/oracle/compare-in-container.sh")
        .env(
            "PATH",
            format!("{}:{}", tools.display(), std::env::var("PATH").unwrap()),
        )
        .env("REPO", root.path())
        .env("ORACLE_OUT", root.path().join("missing"))
        .env("ORACLE_NAMES", "required")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing required oracle recording"));
}
