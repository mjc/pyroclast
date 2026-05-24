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
    match platform {
        "linux" => LINUX_TOOLS.to_vec(),
        "macos" => MACOS_TOOLS.to_vec(),
        _ => COMMON_TOOLS.to_vec(),
    }
}

const fn nix_tool(name: &'static str) -> ToolSpec {
    ToolSpec {
        name,
        kind: ToolKind::NixManaged,
    }
}

const COMMON_TOOLS: &[ToolSpec] = &[nix_tool("inferno-flamegraph")];

const LINUX_TOOLS: &[ToolSpec] = &[
    nix_tool("inferno-flamegraph"),
    nix_tool("perf"),
    nix_tool("heaptrack"),
    nix_tool("heaptrack_print"),
    nix_tool("strace"),
    nix_tool("bpftrace"),
    nix_tool("valgrind"),
];

const MACOS_TOOLS: &[ToolSpec] = &[
    nix_tool("inferno-flamegraph"),
    ToolSpec {
        name: "xctrace",
        kind: ToolKind::AppleProvided,
    },
];
