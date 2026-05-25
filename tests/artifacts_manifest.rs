use pyroclast::artifacts::ArtifactLayout;
use pyroclast::cli::{PerfCallGraph, ProfileKind};
use pyroclast::manifest::{BackendName, RunManifest};
use pyroclast::tools::ToolVersion;

#[test]
fn artifact_layout_uses_required_file_names() {
    let root = tempfile::tempdir().expect("tempdir");
    let layout = ArtifactLayout::new(root.path().join("run-1"));

    assert_eq!(layout.run_json(), root.path().join("run-1/run.json"));
    assert_eq!(layout.stdout_log(), root.path().join("run-1/stdout.log"));
    assert_eq!(layout.stderr_log(), root.path().join("run-1/stderr.log"));
    assert_eq!(layout.command_txt(), root.path().join("run-1/command.txt"));
    assert_eq!(
        layout.stacks_folded(),
        root.path().join("run-1/stacks.folded")
    );
    assert_eq!(
        layout.flamegraph_svg(),
        root.path().join("run-1/flamegraph.svg")
    );
    assert_eq!(layout.summary_txt(), root.path().join("run-1/summary.txt"));
    assert_eq!(
        layout.summary_json(),
        root.path().join("run-1/summary.json")
    );
    assert_eq!(
        layout.tool_errors_log(),
        root.path().join("run-1/tool-errors.log")
    );
    assert_eq!(
        layout.raw_profile("perf.data"),
        root.path().join("run-1/profile.raw.perf.data")
    );
}

#[test]
fn manifest_serializes_core_run_fields() {
    let manifest = RunManifest {
        command: vec!["cargo".to_string(), "check".to_string()],
        cwd: "/work/pyroclast".into(),
        profile_kind: ProfileKind::Cpu,
        requested_backend: BackendName::LinuxPerf,
        actual_backend: BackendName::LinuxPerf,
        fallback_reason: None,
        platform: "linux".to_string(),
        started_at_unix_ms: 10,
        ended_at_unix_ms: Some(20),
        exit_status: Some(0),
        sample_frequency: 997,
        call_graph: PerfCallGraph::Dwarf,
        symbols: true,
        tool_versions: vec![ToolVersion {
            name: "perf".to_string(),
            version: Some("perf version 6.9".to_string()),
            error: None,
        }],
        artifacts: vec!["run.json".into(), "summary.json".into()],
        diagnostics: vec!["direct perf parser used".to_string()],
    };

    let json = serde_json::to_value(&manifest).expect("serialize manifest");

    assert_eq!(json["command"][0], "cargo");
    assert_eq!(json["profile_kind"], "cpu");
    assert_eq!(json["requested_backend"], "linux_perf");
    assert_eq!(json["actual_backend"], "linux_perf");
    assert_eq!(json["fallback_reason"], serde_json::Value::Null);
    assert_eq!(json["exit_status"], 0);
    assert_eq!(json["sample_frequency"], 997);
    assert_eq!(json["call_graph"], "dwarf");
    assert_eq!(json["symbols"], true);
    assert_eq!(json["tool_versions"][0]["name"], "perf");
    assert_eq!(json["tool_versions"][0]["version"], "perf version 6.9");
}
