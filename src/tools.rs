#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolKind {
    NixManaged,
    AppleProvided,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolSpec {
    pub name: &'static str,
    pub kind: ToolKind,
}

pub fn required_tools(platform: &str) -> Vec<ToolSpec> {
    let mut tools = vec![ToolSpec {
        name: "inferno-flamegraph",
        kind: ToolKind::NixManaged,
    }];

    match platform {
        "linux" => tools.extend([
            nix_tool("perf"),
            nix_tool("heaptrack"),
            nix_tool("heaptrack_print"),
            nix_tool("strace"),
            nix_tool("bpftrace"),
            nix_tool("valgrind"),
        ]),
        "macos" => tools.push(ToolSpec {
            name: "xctrace",
            kind: ToolKind::AppleProvided,
        }),
        _ => {}
    }

    tools
}

const fn nix_tool(name: &'static str) -> ToolSpec {
    ToolSpec {
        name,
        kind: ToolKind::NixManaged,
    }
}
