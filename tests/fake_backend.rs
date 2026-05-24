use pyroclast::backends::fake::FakeBackend;
use pyroclast::backends::{ProfileRequest, ProfilerBackend};
use pyroclast::cli::ProfileKind;

#[test]
fn fake_backend_writes_required_artifacts() {
    let root = tempfile::tempdir().expect("tempdir");
    let request = ProfileRequest {
        kind: ProfileKind::Cpu,
        command: vec!["true".to_string()],
        out_dir: root.path().join("fake-run"),
        name: Some("fake".to_string()),
        json: false,
    };

    let result = FakeBackend::default()
        .profile(&request)
        .expect("fake profile");

    assert_eq!(
        result.manifest.actual_backend,
        pyroclast::manifest::BackendName::Fake
    );
    assert!(result.layout.run_json().is_file());
    assert!(result.layout.stdout_log().is_file());
    assert!(result.layout.stderr_log().is_file());
    assert!(result.layout.command_txt().is_file());
    assert!(result.layout.summary_txt().is_file());
    assert!(result.layout.summary_json().is_file());
    assert!(result.layout.tool_errors_log().is_file());
}
