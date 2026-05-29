use std::path::PathBuf;

use proptest::prelude::*;
use proptest::string::string_regex;
use pyroclast::artifacts::ArtifactLayout;
use pyroclast::cli::{PerfCallGraph, PerfEvent, ProfileKind};
use pyroclast::manifest::{BackendName, RunManifest};
use pyroclast::tools::{ToolSource, ToolVersion};

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
        sample_event: PerfEvent::CpuClock,
        call_graph: PerfCallGraph::Dwarf,
        record_target: "command".to_string(),
        duration_secs: None,
        symbols: true,
        tool_versions: vec![ToolVersion {
            name: "perf".to_string(),
            path: Some("/usr/bin/perf".to_string()),
            source: Some(ToolSource::Path),
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
    assert_eq!(json["sample_event"], "cpu-clock");
    assert_eq!(json["call_graph"], "dwarf");
    assert_eq!(json["record_target"], "command");
    assert_eq!(json["duration_secs"], serde_json::Value::Null);
    assert_eq!(json["symbols"], true);
    assert_eq!(json["tool_versions"][0]["name"], "perf");
    assert_eq!(json["tool_versions"][0]["path"], "/usr/bin/perf");
    assert_eq!(json["tool_versions"][0]["source"], "path");
    assert_eq!(json["tool_versions"][0]["version"], "perf version 6.9");
}

fn relative_path_from_segments(segments: &[String]) -> PathBuf {
    segments
        .iter()
        .fold(PathBuf::new(), |path, segment| path.join(segment))
}

fn backend_name_from_case(case: u8) -> BackendName {
    match case % 6 {
        0 => BackendName::Fake,
        1 => BackendName::LinuxPerf,
        2 => BackendName::MacosXctrace,
        3 => BackendName::Heaptrack,
        4 => BackendName::Strace,
        _ => BackendName::Offcpu,
    }
}

fn backend_name_json(name: BackendName) -> &'static str {
    match name {
        BackendName::Fake => "fake",
        BackendName::LinuxPerf => "linux_perf",
        BackendName::MacosXctrace => "macos_xctrace",
        BackendName::Heaptrack => "heaptrack",
        BackendName::Strace => "strace",
        BackendName::Offcpu => "offcpu",
    }
}

fn profile_kind_from_case(case: u8) -> ProfileKind {
    match case % 5 {
        0 => ProfileKind::Cpu,
        1 => ProfileKind::Memory,
        2 => ProfileKind::Offcpu,
        3 => ProfileKind::Latency,
        _ => ProfileKind::Async,
    }
}

fn profile_kind_json(kind: ProfileKind) -> &'static str {
    match kind {
        ProfileKind::Cpu => "cpu",
        ProfileKind::Memory => "memory",
        ProfileKind::Offcpu => "offcpu",
        ProfileKind::Latency => "latency",
        ProfileKind::Async => "async",
    }
}

fn perf_event_from_case(case: u8) -> PerfEvent {
    match case % 4 {
        0 => PerfEvent::Default,
        1 => PerfEvent::CpuClock,
        2 => PerfEvent::TaskClock,
        _ => PerfEvent::Cycles,
    }
}

fn perf_event_json(event: PerfEvent) -> &'static str {
    match event {
        PerfEvent::Default => "default",
        PerfEvent::CpuClock => "cpu-clock",
        PerfEvent::TaskClock => "task-clock",
        PerfEvent::Cycles => "cycles",
    }
}

fn perf_call_graph_from_case(case: u8) -> PerfCallGraph {
    match case % 2 {
        0 => PerfCallGraph::Fp,
        _ => PerfCallGraph::Dwarf,
    }
}

fn perf_call_graph_json(call_graph: PerfCallGraph) -> &'static str {
    match call_graph {
        PerfCallGraph::Fp => "fp",
        PerfCallGraph::Dwarf => "dwarf",
    }
}

proptest! {
    #[test]
    fn property_artifact_layout_joins_generated_roots_and_extensions(
        root_segments in prop::collection::vec(
            string_regex("[A-Za-z0-9][A-Za-z0-9._-]{0,15}").expect("valid path-segment regex"),
            1..5,
        ),
        extension in string_regex("[A-Za-z0-9][A-Za-z0-9._-]{0,15}").expect("valid extension regex"),
    ) {
        let root = relative_path_from_segments(&root_segments);
        let layout = ArtifactLayout::new(root.clone());
        let expected_standard = vec![
            root.join("run.json"),
            root.join("stdout.log"),
            root.join("stderr.log"),
            root.join("command.txt"),
            root.join("summary.txt"),
            root.join("summary.json"),
            root.join("tool-errors.log"),
        ];

        prop_assert_eq!(layout.root(), root.as_path());
        prop_assert_eq!(layout.run_json(), root.join("run.json"));
        prop_assert_eq!(layout.stdout_log(), root.join("stdout.log"));
        prop_assert_eq!(layout.stderr_log(), root.join("stderr.log"));
        prop_assert_eq!(layout.command_txt(), root.join("command.txt"));
        prop_assert_eq!(layout.stacks_folded(), root.join("stacks.folded"));
        prop_assert_eq!(layout.flamegraph_svg(), root.join("flamegraph.svg"));
        prop_assert_eq!(layout.summary_txt(), root.join("summary.txt"));
        prop_assert_eq!(layout.summary_json(), root.join("summary.json"));
        prop_assert_eq!(layout.tool_errors_log(), root.join("tool-errors.log"));
        prop_assert_eq!(layout.raw_profile(&extension), root.join(format!("profile.raw.{extension}")));
        prop_assert_eq!(layout.standard_manifest_artifacts(), expected_standard);
    }

    #[test]
    fn property_manifest_serializes_generated_enum_variants_and_optionals(
        requested_backend_case in any::<u8>(),
        actual_backend_case in any::<u8>(),
        profile_kind_case in any::<u8>(),
        perf_event_case in any::<u8>(),
        call_graph_case in any::<u8>(),
        fallback_reason in prop::option::of(
            string_regex("[A-Za-z0-9][A-Za-z0-9 ._-]{0,15}").expect("valid fallback-reason regex"),
        ),
        exit_status in prop::option::of(-128_i32..=255),
        duration_secs in prop::option::of(0_u32..10_000),
        symbols in any::<bool>(),
    ) {
        let requested_backend = backend_name_from_case(requested_backend_case);
        let actual_backend = backend_name_from_case(actual_backend_case);
        let profile_kind = profile_kind_from_case(profile_kind_case);
        let sample_event = perf_event_from_case(perf_event_case);
        let call_graph = perf_call_graph_from_case(call_graph_case);
        let manifest = RunManifest {
            command: vec!["cargo".to_string(), "check".to_string()],
            cwd: PathBuf::from("runs/work"),
            profile_kind,
            requested_backend,
            actual_backend,
            fallback_reason: fallback_reason.clone(),
            platform: "linux".to_string(),
            started_at_unix_ms: 10,
            ended_at_unix_ms: Some(20),
            exit_status,
            sample_frequency: 997,
            sample_event,
            call_graph,
            record_target: "command".to_string(),
            duration_secs,
            symbols,
            tool_versions: vec![ToolVersion {
                name: "perf".to_string(),
                path: Some("/usr/bin/perf".to_string()),
                source: Some(ToolSource::Path),
                version: Some("perf version 6.9".to_string()),
                error: None,
            }],
            artifacts: vec![PathBuf::from("run.json"), PathBuf::from("summary.json")],
            diagnostics: vec!["direct perf parser used".to_string()],
        };

        let json = serde_json::to_value(&manifest).expect("serialize manifest");

        prop_assert_eq!(json["profile_kind"].as_str(), Some(profile_kind_json(profile_kind)));
        prop_assert_eq!(
            json["requested_backend"].as_str(),
            Some(backend_name_json(requested_backend))
        );
        prop_assert_eq!(
            json["actual_backend"].as_str(),
            Some(backend_name_json(actual_backend))
        );
        prop_assert_eq!(json["sample_event"].as_str(), Some(perf_event_json(sample_event)));
        prop_assert_eq!(
            json["call_graph"].as_str(),
            Some(perf_call_graph_json(call_graph))
        );
        prop_assert_eq!(json["symbols"].as_bool(), Some(symbols));
        prop_assert_eq!(
            json["fallback_reason"].as_str(),
            fallback_reason.as_deref()
        );
        prop_assert_eq!(
            json["exit_status"].as_i64(),
            exit_status.map(i64::from)
        );
        prop_assert_eq!(
            json["duration_secs"].as_u64(),
            duration_secs.map(u64::from)
        );
    }
}
