use crate::process::{CommandRunner, CommandSpec};

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

impl ToolSpec {
    #[must_use]
    pub const fn nix_managed(name: &'static str) -> Self {
        Self {
            name,
            kind: ToolKind::NixManaged,
        }
    }

    #[must_use]
    pub const fn apple_provided(name: &'static str) -> Self {
        Self {
            name,
            kind: ToolKind::AppleProvided,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ToolVersion {
    pub name: String,
    pub version: Option<String>,
    pub error: Option<String>,
}

#[must_use]
pub fn required_tools(platform: &str) -> Vec<ToolSpec> {
    match platform {
        "linux" => LINUX_TOOLS.to_vec(),
        "macos" => MACOS_TOOLS.to_vec(),
        _ => COMMON_TOOLS.to_vec(),
    }
}

pub fn collect_tool_versions<R>(runner: &R, tools: &[ToolSpec]) -> Vec<ToolVersion>
where
    R: CommandRunner,
{
    tools
        .iter()
        .map(|tool| collect_tool_version(runner, tool))
        .collect()
}

fn collect_tool_version<R>(runner: &R, tool: &ToolSpec) -> ToolVersion
where
    R: CommandRunner,
{
    let output = runner.run(&CommandSpec::new(tool.name).arg("--version"));
    match output {
        Ok(output) if output.status_code == Some(0) => ToolVersion {
            name: tool.name.to_string(),
            version: first_output_line(&output.stdout, &output.stderr),
            error: None,
        },
        Ok(output) => ToolVersion {
            name: tool.name.to_string(),
            version: None,
            error: Some(format!("--version exited with {:?}", output.status_code)),
        },
        Err(error) => ToolVersion {
            name: tool.name.to_string(),
            version: None,
            error: Some(error.to_string()),
        },
    }
}

fn first_output_line(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .chain(String::from_utf8_lossy(stderr).lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToOwned::to_owned)
}

const fn nix_tool(name: &'static str) -> ToolSpec {
    ToolSpec::nix_managed(name)
}

const COMMON_TOOLS: &[ToolSpec] = &[nix_tool("inferno-flamegraph"), nix_tool("tokio-console")];

const LINUX_TOOLS: &[ToolSpec] = &[
    nix_tool("inferno-flamegraph"),
    nix_tool("tokio-console"),
    nix_tool("perf"),
    nix_tool("heaptrack"),
    nix_tool("heaptrack_print"),
    nix_tool("strace"),
    nix_tool("bpftrace"),
    nix_tool("valgrind"),
];

const MACOS_TOOLS: &[ToolSpec] = &[
    nix_tool("inferno-flamegraph"),
    nix_tool("tokio-console"),
    ToolSpec::apple_provided("xctrace"),
];
