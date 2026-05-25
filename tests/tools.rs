use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};
use pyroclast::tools::{ToolKind, ToolSpec, collect_tool_versions, required_tools};

#[test]
fn linux_required_tools_include_nix_managed_profilers() {
    let tools = required_tools("linux");
    let names: Vec<_> = tools.iter().map(|tool| tool.name).collect();

    assert!(names.contains(&"perf"));
    assert!(names.contains(&"inferno-flamegraph"));
    assert!(names.contains(&"heaptrack"));
    assert!(names.contains(&"heaptrack_print"));
    assert!(names.contains(&"strace"));
    assert!(names.contains(&"bpftrace"));
    assert!(names.contains(&"valgrind"));
    assert!(names.contains(&"tokio-console"));
    assert!(tools.iter().all(|tool| tool.kind == ToolKind::NixManaged));
}

#[test]
fn macos_required_tools_mark_xctrace_as_apple_provided() {
    let tools = required_tools("macos");
    let xctrace = tools
        .iter()
        .find(|tool| tool.name == "xctrace")
        .expect("xctrace tool");

    assert_eq!(xctrace.kind, ToolKind::AppleProvided);
    assert!(tools.iter().any(|tool| tool.name == "inferno-flamegraph"));
    assert!(tools.iter().any(|tool| tool.name == "tokio-console"));
}

#[test]
fn collects_tool_versions_with_version_flag() {
    let runner = VersionRunner;
    let versions = collect_tool_versions(
        &runner,
        &[ToolSpec {
            name: "perf",
            kind: ToolKind::NixManaged,
        }],
    );

    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].name, "perf");
    assert_eq!(versions[0].version.as_deref(), Some("perf version 6.9"));
    assert_eq!(versions[0].error, None);
}

struct VersionRunner;

impl CommandRunner for VersionRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        assert_eq!(command.program, "perf");
        assert_eq!(command.args, ["--version"]);
        Ok(CommandOutput {
            status_code: Some(0),
            stdout: b"perf version 6.9\nextra\n".to_vec(),
            stderr: Vec::new(),
        })
    }
}
