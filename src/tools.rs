use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::process::{CommandRunner, CommandSpec};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolKind {
    NixManaged,
    AppleProvided,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSource {
    Path,
    InNixShell,
    ProjectFlake,
    EphemeralNix,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolSpec {
    pub name: &'static str,
    pub kind: ToolKind,
    nix_package: Option<&'static str>,
    allow_ephemeral_nix: bool,
}

impl ToolSpec {
    #[must_use]
    pub const fn nix_managed(name: &'static str) -> Self {
        Self {
            name,
            kind: ToolKind::NixManaged,
            nix_package: None,
            allow_ephemeral_nix: false,
        }
    }

    #[must_use]
    pub const fn nix_utility(name: &'static str, nix_package: &'static str) -> Self {
        Self {
            name,
            kind: ToolKind::NixManaged,
            nix_package: Some(nix_package),
            allow_ephemeral_nix: true,
        }
    }

    #[must_use]
    pub const fn apple_provided(name: &'static str) -> Self {
        Self {
            name,
            kind: ToolKind::AppleProvided,
            nix_package: None,
            allow_ephemeral_nix: false,
        }
    }

    fn version_command(program: &str) -> CommandSpec {
        CommandSpec::new(program).arg("--version")
    }

    fn accepts_version_output(self, version: Option<&str>) -> bool {
        match self.name {
            "xctrace" => version.is_none_or(|line| {
                let lowered = line.to_ascii_lowercase();
                !lowered.contains("xcode")
                    && !lowered.contains("developer directory")
                    && !lowered.contains("unable to find utility")
            }),
            _ => true,
        }
    }

    fn missing_tool_error(self) -> String {
        match self.kind {
            ToolKind::AppleProvided => format!(
                "{name} is required on macOS; install Xcode or Command Line Tools so the real profiler is available",
                name = self.name
            ),
            ToolKind::NixManaged => format!(
                "{name} is required but was not found on PATH or in the project flake; install it or enter the project dev shell",
                name = self.name
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ToolVersion {
    pub name: String,
    pub path: Option<String>,
    pub source: Option<ToolSource>,
    pub version: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTool {
    pub name: String,
    pub path: String,
    pub source: ToolSource,
    pub version: Option<String>,
}

impl ResolvedTool {
    #[must_use]
    pub fn bare(tool: &ToolSpec) -> Self {
        Self {
            name: tool.name.to_string(),
            path: tool.name.to_string(),
            source: ToolSource::Path,
            version: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverContext {
    platform: String,
    cwd: PathBuf,
    path: Option<OsString>,
    in_nix_shell: bool,
}

impl ResolverContext {
    #[must_use]
    pub fn from_env(platform: &str) -> Self {
        Self {
            platform: platform.to_string(),
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            path: std::env::var_os("PATH"),
            in_nix_shell: std::env::var_os("IN_NIX_SHELL").is_some(),
        }
    }

    #[must_use]
    pub fn for_tests(
        platform: &str,
        cwd: impl Into<PathBuf>,
        path: Option<OsString>,
        in_nix_shell: bool,
    ) -> Self {
        Self {
            platform: platform.to_string(),
            cwd: cwd.into(),
            path,
            in_nix_shell,
        }
    }
}

pub struct SystemToolResolver<R> {
    runner: R,
    context: ResolverContext,
    cache: BTreeMap<&'static str, ResolvedTool>,
}

impl<R> SystemToolResolver<R> {
    #[must_use]
    pub fn new(runner: R, context: ResolverContext) -> Self {
        Self {
            runner,
            context,
            cache: BTreeMap::new(),
        }
    }
}

impl<R> SystemToolResolver<R>
where
    R: CommandRunner,
{
    /// Resolves an external tool to a concrete executable path.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when probing the environment fails or when no
    /// supported tool path can be found.
    pub fn resolve(&mut self, tool: &ToolSpec) -> std::io::Result<ResolvedTool> {
        if let Some(resolved) = self.cache.get(tool.name) {
            return Ok(resolved.clone());
        }

        let mut resolved = if self.context.in_nix_shell {
            self.resolve_from_path(tool, true)?
        } else {
            None
        };
        if resolved.is_none() && !self.context.in_nix_shell {
            resolved = self.resolve_from_path(tool, false)?;
        }
        if resolved.is_none() {
            resolved = self.resolve_from_project_flake(tool).transpose()?;
        }
        if resolved.is_none() {
            resolved = self.resolve_from_ephemeral_nix(tool).transpose()?;
        }
        let resolved = resolved.ok_or_else(|| std::io::Error::other(tool.missing_tool_error()))?;
        self.cache.insert(tool.name, resolved.clone());
        Ok(resolved)
    }

    fn resolve_from_path(
        &self,
        tool: &ToolSpec,
        in_nix_shell: bool,
    ) -> std::io::Result<Option<ResolvedTool>> {
        let Some(path) = find_executable_on_path(tool.name, self.context.path.as_deref()) else {
            return Ok(None);
        };
        match self.probe_tool_version(tool, &path.to_string_lossy()) {
            Ok(version) => Ok(Some(ResolvedTool {
                name: tool.name.to_string(),
                path: path.to_string_lossy().into_owned(),
                source: if in_nix_shell {
                    ToolSource::InNixShell
                } else {
                    ToolSource::Path
                },
                version,
            })),
            Err(error) if tool.kind == ToolKind::AppleProvided => Err(error),
            Err(_) => Ok(None),
        }
    }

    fn resolve_from_project_flake(&self, tool: &ToolSpec) -> Option<std::io::Result<ResolvedTool>> {
        if tool.kind == ToolKind::AppleProvided {
            return None;
        }
        let nix = find_executable_on_path("nix", self.context.path.as_deref())?;
        let flake_dir = find_nearest_flake_dir(&self.context.cwd)?;
        Some(self.probe_nix_shell_tool(&nix, tool, &flake_dir, false))
    }

    fn resolve_from_ephemeral_nix(&self, tool: &ToolSpec) -> Option<std::io::Result<ResolvedTool>> {
        if !tool.allow_ephemeral_nix {
            return None;
        }
        let nix = find_executable_on_path("nix", self.context.path.as_deref())?;
        Some(self.probe_nix_shell_tool(&nix, tool, &self.context.cwd, true))
    }

    fn probe_nix_shell_tool(
        &self,
        nix: &Path,
        tool: &ToolSpec,
        working_dir: &Path,
        ephemeral: bool,
    ) -> std::io::Result<ResolvedTool> {
        let probe = if ephemeral {
            let Some(package) = tool.nix_package else {
                return Err(std::io::Error::other(tool.missing_tool_error()));
            };
            CommandSpec::new(nix.to_string_lossy().into_owned()).args([
                "--extra-experimental-features".to_string(),
                "nix-command flakes".to_string(),
                "shell".to_string(),
                format!("nixpkgs#{package}"),
                "-c".to_string(),
                "sh".to_string(),
                "-lc".to_string(),
                format!("command -v {}", tool.name),
            ])
        } else {
            CommandSpec::new(nix.to_string_lossy().into_owned()).args([
                "--extra-experimental-features".to_string(),
                "nix-command flakes".to_string(),
                "develop".to_string(),
                working_dir.display().to_string(),
                "-c".to_string(),
                "sh".to_string(),
                "-lc".to_string(),
                format!("command -v {}", tool.name),
            ])
        };
        let output = self.runner.run(&probe)?;
        if output.status_code != Some(0) {
            return Err(std::io::Error::other(tool.missing_tool_error()));
        }
        let path = first_output_line(&output.stdout, &output.stderr)
            .ok_or_else(|| std::io::Error::other(tool.missing_tool_error()))?;
        let version = self.probe_tool_version(tool, &path)?;
        Ok(ResolvedTool {
            name: tool.name.to_string(),
            path,
            source: if ephemeral {
                ToolSource::EphemeralNix
            } else {
                ToolSource::ProjectFlake
            },
            version,
        })
    }

    fn probe_tool_version(
        &self,
        tool: &ToolSpec,
        program: &str,
    ) -> std::io::Result<Option<String>> {
        let output = self.runner.run(&ToolSpec::version_command(program))?;
        if output.status_code != Some(0) {
            return Err(std::io::Error::other(tool.missing_tool_error()));
        }
        let version = first_output_line(&output.stdout, &output.stderr);
        if !tool.accepts_version_output(version.as_deref()) {
            return Err(std::io::Error::other(tool.missing_tool_error()));
        }
        Ok(version)
    }
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
    let resolved = match runner.resolve_tool(tool) {
        Ok(resolved) => resolved,
        Err(error) => {
            return ToolVersion {
                name: tool.name.to_string(),
                path: None,
                source: None,
                version: None,
                error: Some(error.to_string()),
            };
        }
    };
    if let Some(version) = resolved.version.clone() {
        return ToolVersion {
            name: resolved.name,
            path: Some(resolved.path),
            source: Some(resolved.source),
            version: Some(version),
            error: None,
        };
    }
    let output = runner.run(&ToolSpec::version_command(&resolved.path));
    match output {
        Ok(output) if output.status_code == Some(0) => ToolVersion {
            name: tool.name.to_string(),
            path: Some(resolved.path),
            source: Some(resolved.source),
            version: first_output_line(&output.stdout, &output.stderr),
            error: None,
        },
        Ok(output) => ToolVersion {
            name: tool.name.to_string(),
            path: Some(resolved.path),
            source: Some(resolved.source),
            version: None,
            error: Some(format!("--version exited with {:?}", output.status_code)),
        },
        Err(error) => ToolVersion {
            name: tool.name.to_string(),
            path: Some(resolved.path),
            source: Some(resolved.source),
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

const fn nix_utility(name: &'static str, package: &'static str) -> ToolSpec {
    ToolSpec::nix_utility(name, package)
}

pub const INFERNO_FLAMEGRAPH: ToolSpec = nix_utility("inferno-flamegraph", "inferno");
pub const INFERNO_COLLAPSE_PERF: ToolSpec = nix_utility("inferno-collapse-perf", "inferno");
pub const TOKIO_CONSOLE: ToolSpec = nix_utility("tokio-console", "tokio-console");
pub const ADDR2LINE: ToolSpec = nix_utility("addr2line", "binutils");
pub const PERF: ToolSpec = nix_tool("perf");
pub const HEAPTRACK: ToolSpec = nix_tool("heaptrack");
pub const HEAPTRACK_PRINT: ToolSpec = nix_tool("heaptrack_print");
pub const STRACE: ToolSpec = nix_tool("strace");
pub const BPFTRACE: ToolSpec = nix_tool("bpftrace");
pub const VALGRIND: ToolSpec = nix_tool("valgrind");
pub const XCTRACE: ToolSpec = ToolSpec::apple_provided("xctrace");

const COMMON_TOOLS: &[ToolSpec] = &[
    INFERNO_FLAMEGRAPH,
    INFERNO_COLLAPSE_PERF,
    TOKIO_CONSOLE,
    ADDR2LINE,
];

const LINUX_TOOLS: &[ToolSpec] = &[
    INFERNO_FLAMEGRAPH,
    INFERNO_COLLAPSE_PERF,
    TOKIO_CONSOLE,
    ADDR2LINE,
    PERF,
    HEAPTRACK,
    HEAPTRACK_PRINT,
    STRACE,
    BPFTRACE,
    VALGRIND,
];

const MACOS_TOOLS: &[ToolSpec] = &[
    INFERNO_FLAMEGRAPH,
    INFERNO_COLLAPSE_PERF,
    TOKIO_CONSOLE,
    ADDR2LINE,
    XCTRACE,
];

#[must_use]
pub fn tool_spec_named(name: &str) -> Option<ToolSpec> {
    match name {
        "inferno-flamegraph" => Some(INFERNO_FLAMEGRAPH),
        "inferno-collapse-perf" => Some(INFERNO_COLLAPSE_PERF),
        "tokio-console" => Some(TOKIO_CONSOLE),
        "addr2line" => Some(ADDR2LINE),
        "perf" => Some(PERF),
        "heaptrack" => Some(HEAPTRACK),
        "heaptrack_print" => Some(HEAPTRACK_PRINT),
        "strace" => Some(STRACE),
        "bpftrace" => Some(BPFTRACE),
        "valgrind" => Some(VALGRIND),
        "xctrace" => Some(XCTRACE),
        _ => None,
    }
}

#[must_use]
pub fn find_nearest_flake_dir(cwd: &Path) -> Option<PathBuf> {
    let mut current = Some(cwd);
    while let Some(path) = current {
        if path.join("flake.nix").is_file() {
            return Some(path.to_path_buf());
        }
        current = path.parent();
    }
    None
}

#[must_use]
pub fn find_executable_on_path(name: &str, path_var: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let path_var = path_var?;
    std::env::split_paths(path_var)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}
