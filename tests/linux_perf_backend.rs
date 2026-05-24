mod common;

use std::sync::Mutex;

use common::{file_attr_bytes, perfdata_with_records_and_attrs, record_bytes, sample_payload};
use pyroclast::backends::linux_perf::LinuxPerfBackend;
use pyroclast::backends::{ProfileRequest, ProfilerBackend};
use pyroclast::cli::ProfileKind;
use pyroclast::manifest::BackendName;
use pyroclast::perfdata::samples::{PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_TID};
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
    };

    let result = backend.profile(&request).expect("profile");

    assert_eq!(result.manifest.actual_backend, BackendName::LinuxPerf);
    assert_eq!(runner.programs(), vec!["perf"]);
    assert!(result.layout.raw_profile("perf.data").is_file());
    assert_eq!(
        std::fs::read(result.layout.raw_profile("perf.data")).expect("perf data"),
        tiny_perfdata()
    );
    assert_eq!(
        std::fs::read_to_string(result.layout.stacks_folded()).expect("stacks folded"),
        "0x2000 1\n"
    );
    assert!(result.layout.run_json().is_file());
    assert!(result.layout.stderr_log().is_file());
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
}

impl CommandRunner for RecordingRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        if let Some(output_path) = perf_output_path(command) {
            std::fs::write(output_path, tiny_perfdata())?;
        }
        Ok(CommandOutput {
            status_code: Some(0),
            stdout: b"perf stdout".to_vec(),
            stderr: b"perf stderr".to_vec(),
        })
    }
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

fn perf_output_path(command: &CommandSpec) -> Option<&str> {
    command
        .args
        .windows(2)
        .find(|window| window[0] == "-o")
        .map(|window| window[1].as_str())
}
