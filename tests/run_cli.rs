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

    assert_eq!(output.stdout, "app;0x2000 1\n");
}

#[test]
fn flamegraph_command_folds_perfdata_without_perf_script() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let output_svg = root.path().join("flamegraph.svg");
    std::fs::write(&perfdata, tiny_perfdata()).expect("write perfdata");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "flamegraph",
        perfdata.to_str().expect("perfdata path"),
        "-o",
        output_svg.to_str().expect("svg path"),
        "--title",
        "sftp-s3 CPU",
    ]);

    pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("flamegraph command");

    assert_eq!(runner.programs(), vec!["inferno-flamegraph"]);
    assert_eq!(
        runner.first_args(),
        Some(vec![
            "--title".to_string(),
            "sftp-s3 CPU".to_string(),
            "-".to_string()
        ])
    );
    assert_eq!(runner.stdins(), vec![Some(b"0x2000 1\n".to_vec())]);
    assert_eq!(
        std::fs::read_to_string(output_svg).expect("svg"),
        "<svg></svg>\n"
    );
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

    assert_eq!(runner.programs(), vec!["perf", "inferno-flamegraph"]);
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

    fn stdins(&self) -> Vec<Option<Vec<u8>>> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .map(|command| command.stdin.clone())
            .collect()
    }

    fn first_args(&self) -> Option<Vec<String>> {
        self.commands
            .lock()
            .unwrap()
            .first()
            .map(|command| command.args.clone())
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
        let stdout = if command.program == "inferno-flamegraph" {
            b"<svg></svg>\n".to_vec()
        } else {
            Vec::new()
        };
        Ok(pyroclast::process::CommandOutput {
            status_code: Some(0),
            stdout,
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

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
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
