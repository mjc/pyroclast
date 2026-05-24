use pyroclast::tools::{ToolKind, required_tools};

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
