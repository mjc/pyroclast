#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn heap_workflow_matrix_times_matching_targets_and_keeps_native_analysis_separate() {
    let matrix: serde_json::Value =
        serde_json::from_str(include_str!("../scripts/benchmarks/shipping-heap.json")).unwrap();
    assert_eq!(matrix["repetitions"], 10);
    assert_eq!(matrix["inputs"], serde_json::json!(["WORKLOAD"]));
    // Independent captures have different timing and leaks; compare each summary
    // with a fresh native report of its own raw recording outside timed stages.
    assert_eq!(matrix["comparisons"], serde_json::json!([]));
    let rows = matrix["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["name"], "baseline");
    assert_eq!(
        rows[0]["stages"][0]["argv"],
        serde_json::json!(["WORKLOAD", "alloc", "1000000"])
    );
    assert_eq!(rows[1]["name"], "shipping");
    assert_eq!(rows[1]["stages"].as_array().unwrap().len(), 1);
    assert_eq!(
        rows[1]["stages"][0]["argv"],
        serde_json::json!([
            "{pyroclast}",
            "profile",
            "--kind",
            "memory",
            "--json",
            "--out",
            "{run_dir}/shipping",
            "--",
            "WORKLOAD",
            "alloc",
            "1000000"
        ])
    );
    assert_eq!(rows[2]["name"], "native");
    assert_eq!(rows[2]["stages"].as_array().unwrap().len(), 2);
    assert_eq!(
        rows[2]["stages"][0]["argv"],
        serde_json::json!([
            "heaptrack",
            "--record-only",
            "-o",
            "{run_dir}/native.heaptrack",
            "WORKLOAD",
            "alloc",
            "1000000"
        ])
    );
    assert_eq!(
        rows[2]["stages"][1]["argv"],
        serde_json::json!(["heaptrack_print", "{run_dir}/native.heaptrack.zst"])
    );
    assert_eq!(rows[2]["stages"][1]["stdout"], "native.report");
    for (row, artifact) in [
        (1, "shipping/profile.raw.heaptrack.zst"),
        (1, "shipping/run.json"),
        (1, "shipping/summary.json"),
        (1, "shipping/summary.txt"),
        (1, "shipping/stdout.log"),
        (2, "native.heaptrack.zst"),
        (2, "native.report"),
    ] {
        assert!(
            rows[row]["required_artifacts"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(artifact))
        );
    }
}

fn build(root: &Path) -> [PathBuf; 2] {
    let c = root.join("c-workload");
    let rust = root.join("rust-workload");
    for (program, args, output) in [
        (
            "cc",
            vec![
                "-O2",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-g",
                "-fno-omit-frame-pointer",
                "-pthread",
                "scripts/benchmarks/workload.c",
                "-o",
            ],
            &c,
        ),
        (
            "rustc",
            vec![
                "--edition=2024",
                "-C",
                "opt-level=2",
                "-C",
                "debuginfo=2",
                "-C",
                "force-frame-pointers=yes",
                "scripts/benchmarks/workload.rs",
                "-o",
            ],
            &rust,
        ),
    ] {
        let status = Command::new(program)
            .args(args)
            .arg(output)
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
    }
    [c, rust]
}

fn checksum(mut value: u64, rounds: usize) -> u64 {
    for _ in 0..rounds {
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        value = value.wrapping_mul(0x2545_f491_4f6c_dd1d);
    }
    value
}

#[test]
fn native_c_and_rust_workloads_do_checked_cpu_thread_and_allocation_work() {
    let root = tempfile::tempdir().unwrap();
    let binaries = build(root.path());
    let rounds = 521;
    for (mode, expected) in [
        ("cpu", checksum(1, rounds)),
        (
            "threads",
            (1..=4)
                .map(|seed| checksum(seed, rounds))
                .fold(0_u64, u64::wrapping_add),
        ),
        (
            "alloc",
            (0..rounds)
                .map(|round| 2 * u64::try_from(round % 256).unwrap())
                .sum(),
        ),
    ] {
        for binary in &binaries {
            let output = Command::new(binary)
                .args([mode, &rounds.to_string()])
                .output()
                .unwrap();
            assert!(output.status.success());
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                format!("{expected}\n"),
                "{} {mode}",
                binary.display()
            );
        }
    }
}

#[test]
fn workload_usage_errors_cannot_be_mistaken_for_completed_measurements() {
    let root = tempfile::tempdir().unwrap();
    for binary in build(root.path()) {
        for args in [
            vec![],
            vec!["cpu"],
            vec!["cpu", "0"],
            vec!["alloc", "-1"],
            vec!["cpu", "oops"],
            vec!["cpu", " 1"],
            vec!["unknown", "1"],
            vec!["cpu", "1", "extra"],
        ] {
            let output = Command::new(&binary).args(args).output().unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert!(!output.stderr.is_empty());
        }
    }
}
