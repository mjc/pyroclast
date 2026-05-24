mod common;

use common::{file_attr_bytes, perfdata_with_records_and_attrs, record_bytes, sample_payload};
use pyroclast::perfdata::samples::{PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_TID};
use std::sync::Mutex;

#[test]
fn top_level_memory_command_creates_fake_artifacts() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("memory-run");

    pyroclast::run_cli([
        "pyroclast",
        "memory",
        "--out",
        out.to_str().expect("utf8 path"),
        "--",
        "cargo",
        "check",
    ])
    .expect("run cli");

    assert!(out.join("run.json").is_file());
    assert!(out.join("command.txt").is_file());
    assert_eq!(
        std::fs::read_to_string(out.join("command.txt")).unwrap(),
        "cargo check"
    );
}

#[test]
fn fold_command_reads_perfdata_directly() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(
        &perfdata,
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
        ),
    )
    .expect("write perfdata");

    let output = pyroclast::run_cli(["pyroclast", "fold", perfdata.to_str().unwrap()])
        .expect("fold command");

    assert_eq!(output.stdout, "0x2000 1\n");
}

#[test]
fn top_level_cpu_command_uses_injected_perf_runner() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("cpu-run");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "cpu",
        "--out",
        out.to_str().expect("utf8 path"),
        "--",
        "true",
    ]);

    pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("run cli");

    assert_eq!(runner.programs(), vec!["perf"]);
    let run_json = std::fs::read_to_string(out.join("run.json")).expect("run json");
    assert!(run_json.contains("\"actual_backend\": \"linux_perf\""));
}

#[derive(Default)]
struct RecordingRunner {
    commands: Mutex<Vec<pyroclast::process::CommandSpec>>,
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
}

impl pyroclast::process::CommandRunner for RecordingRunner {
    fn run(
        &self,
        command: &pyroclast::process::CommandSpec,
    ) -> std::io::Result<pyroclast::process::CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        if let Some(output_path) = perf_output_path(command) {
            std::fs::write(output_path, tiny_perfdata())?;
        }
        Ok(pyroclast::process::CommandOutput {
            status_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }
}

fn perf_output_path(command: &pyroclast::process::CommandSpec) -> Option<&str> {
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
        [record_bytes(9, &sample_payload(0x1000, 1, 2, [0x2000]))],
    )
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
