#[test]
fn readme_documents_primary_commands() {
    let readme = std::fs::read_to_string("README.md").expect("README.md");

    for command in [
        "pyroclast profile -- <command...>",
        "pyroclast profile --kind cpu -- <command...>",
        "pyroclast profile --kind heap -- <command...>",
        "pyroclast profile --kind memory -- <command...>",
        "pyroclast profile --kind offcpu -- <command...>",
        "pyroclast profile --kind syscalls -- <command...>",
        "pyroclast profile --kind latency -- <command...>",
        "pyroclast heap -- <command...>",
        "pyroclast syscalls -- <command...>",
        "pyroclast fold <perf.data>",
        "pyroclast flamegraph <perf.data>",
        "pyroclast summarize <artifact-dir>",
    ] {
        assert!(readme.contains(command), "README missing {command}");
    }
}
