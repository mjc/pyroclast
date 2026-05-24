use std::sync::Mutex;

use pyroclast::backends::linux_perf::LinuxPerfBackend;
use pyroclast::backends::{ProfileRequest, ProfilerBackend};
use pyroclast::cli::ProfileKind;
use pyroclast::manifest::BackendName;
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
        Ok(CommandOutput {
            status_code: Some(0),
            stdout: b"perf stdout".to_vec(),
            stderr: b"perf stderr".to_vec(),
        })
    }
}
