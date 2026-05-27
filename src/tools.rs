use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write;
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

    fn probe_command(self, program: &str) -> CommandSpec {
        match self.name {
            "inferno-flamegraph" | "inferno-collapse-perf" => {
                CommandSpec::new(program).arg("--help")
            }
            _ => CommandSpec::new(program).arg("--version"),
        }
    }

    fn accepts_probe_output(self, probe_output: Option<&str>) -> bool {
        match self.name {
            "xctrace" => probe_output.is_none_or(|line| {
                let lowered = line.to_ascii_lowercase();
                !lowered.contains("xcode")
                    && !lowered.contains("developer directory")
                    && !lowered.contains("unable to find utility")
            }),
            _ => true,
        }
    }

    fn reported_version(self, stdout: &[u8], stderr: &[u8]) -> Option<String> {
        match self.name {
            "inferno-flamegraph" | "inferno-collapse-perf" => None,
            _ => first_output_line(stdout, stderr),
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
    pub launch_program: String,
    pub launch_args: Vec<String>,
}

impl ResolvedTool {
    #[must_use]
    pub fn bare(tool: &ToolSpec) -> Self {
        Self {
            name: tool.name.to_string(),
            path: tool.name.to_string(),
            source: ToolSource::Path,
            version: None,
            launch_program: tool.name.to_string(),
            launch_args: Vec::new(),
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

        let mut attempts = Vec::new();
        let resolved = if self.context.in_nix_shell {
            self.resolve_from_path(tool, true, &mut attempts)
        } else {
            self.resolve_from_path(tool, false, &mut attempts)
        }
        .or_else(|| self.resolve_from_project_flake(tool, &mut attempts))
        .or_else(|| self.resolve_from_ephemeral_nix(tool, &mut attempts));
        let resolved =
            resolved.ok_or_else(|| resolution_error(tool, &attempts, &self.context.cwd))?;
        self.cache.insert(tool.name, resolved.clone());
        Ok(resolved)
    }

    fn resolve_from_path(
        &self,
        tool: &ToolSpec,
        in_nix_shell: bool,
        attempts: &mut Vec<String>,
    ) -> Option<ResolvedTool> {
        let Some(path) = find_executable_on_path(tool.name, self.context.path.as_deref()) else {
            attempts.push(format!(
                "{}: not found",
                if in_nix_shell {
                    "PATH (inside current nix shell)"
                } else {
                    "PATH"
                }
            ));
            return None;
        };
        match self.probe_tool_version(tool, &path.to_string_lossy()) {
            Ok(version) => {
                let path = path.to_string_lossy().into_owned();
                attempts.push(format!(
                    "{}: found {}",
                    if in_nix_shell {
                        "PATH (inside current nix shell)"
                    } else {
                        "PATH"
                    },
                    path
                ));
                Some(ResolvedTool {
                    name: tool.name.to_string(),
                    path: path.clone(),
                    source: if in_nix_shell {
                        ToolSource::InNixShell
                    } else {
                        ToolSource::Path
                    },
                    version,
                    launch_program: path,
                    launch_args: Vec::new(),
                })
            }
            Err(error) => {
                attempts.push(format!(
                    "{}: found {} but probe failed: {}",
                    if in_nix_shell {
                        "PATH (inside current nix shell)"
                    } else {
                        "PATH"
                    },
                    path.display(),
                    error
                ));
                None
            }
        }
    }

    fn resolve_from_project_flake(
        &self,
        tool: &ToolSpec,
        attempts: &mut Vec<String>,
    ) -> Option<ResolvedTool> {
        if tool.kind == ToolKind::AppleProvided {
            return None;
        }
        let Some(nix) = find_executable_on_path("nix", self.context.path.as_deref()) else {
            attempts.push("project flake: skipped because `nix` was not found on PATH".to_string());
            return None;
        };
        let Some(flake_dir) = find_nearest_flake_dir(&self.context.cwd) else {
            attempts.push(format!(
                "project flake: skipped because no flake.nix was found from {} upward",
                self.context.cwd.display()
            ));
            return None;
        };
        match self.probe_nix_shell_tool(&nix, tool, &flake_dir) {
            Ok(resolved) => {
                attempts.push(format!(
                    "project flake via `nix develop {}`: found {}",
                    flake_dir.display(),
                    resolved.path
                ));
                Some(resolved)
            }
            Err(error) => {
                attempts.push(format!(
                    "project flake via `nix develop {}`: failed: {}",
                    flake_dir.display(),
                    error
                ));
                None
            }
        }
    }

    fn resolve_from_ephemeral_nix(
        &self,
        tool: &ToolSpec,
        attempts: &mut Vec<String>,
    ) -> Option<ResolvedTool> {
        if !tool.allow_ephemeral_nix {
            attempts.push("ephemeral nix shell: skipped because this tool is not allowed to come from nixpkgs on demand".to_string());
            return None;
        }
        let Some(nix) = find_executable_on_path("nix", self.context.path.as_deref()) else {
            attempts.push(
                "ephemeral nix shell: skipped because `nix` was not found on PATH".to_string(),
            );
            return None;
        };
        let package = tool
            .nix_package
            .expect("ephemeral nix tools must declare a nix package");
        match self.probe_ephemeral_nix_tool(&nix, tool) {
            Ok(resolved) => {
                attempts.push(format!(
                    "ephemeral nix shell via `nix shell nixpkgs#{} --command {}`: found {}",
                    package, tool.name, resolved.path
                ));
                Some(resolved)
            }
            Err(error) => {
                attempts.push(format!(
                    "ephemeral nix shell via `nix shell nixpkgs#{} --command {}`: failed: {}",
                    package, tool.name, error
                ));
                None
            }
        }
    }

    fn probe_nix_shell_tool(
        &self,
        nix: &Path,
        tool: &ToolSpec,
        working_dir: &Path,
    ) -> std::io::Result<ResolvedTool> {
        let probe = CommandSpec::new(nix.to_string_lossy().into_owned()).args([
            "--extra-experimental-features".to_string(),
            "nix-command flakes".to_string(),
            "develop".to_string(),
            working_dir.display().to_string(),
            "-c".to_string(),
            "sh".to_string(),
            "-c".to_string(),
            format!("command -v {}", tool.name),
        ]);
        let output = self.runner.run(&probe)?;
        if output.status_code != Some(0) {
            return Err(command_probe_error("nix develop probe failed", &output));
        }
        let path = last_output_line(&output.stdout).ok_or_else(|| {
            probe_output_error("nix develop probe did not report a tool path on stdout")
        })?;
        let version = self.probe_tool_version(tool, &path)?;
        Ok(ResolvedTool {
            name: tool.name.to_string(),
            path: path.clone(),
            source: ToolSource::ProjectFlake,
            version,
            launch_program: path.clone(),
            launch_args: Vec::new(),
        })
    }

    fn probe_ephemeral_nix_tool(
        &self,
        nix: &Path,
        tool: &ToolSpec,
    ) -> std::io::Result<ResolvedTool> {
        let Some(package) = tool.nix_package else {
            return Err(std::io::Error::other(tool.missing_tool_error()));
        };
        let launch_program = nix.to_string_lossy().into_owned();
        let package_ref = format!("nixpkgs#{package}");
        let launch_args = vec![
            "--extra-experimental-features".to_string(),
            "nix-command flakes".to_string(),
            "shell".to_string(),
            package_ref.clone(),
            "--command".to_string(),
            tool.name.to_string(),
        ];
        let probe = CommandSpec::new(launch_program.clone()).args([
            "--extra-experimental-features".to_string(),
            "nix-command flakes".to_string(),
            "shell".to_string(),
            package_ref,
            "--command".to_string(),
            "sh".to_string(),
            "-c".to_string(),
            format!("command -v {}", tool.name),
        ]);
        let output = self.runner.run(&probe)?;
        if output.status_code != Some(0) {
            return Err(command_probe_error("nix shell probe failed", &output));
        }
        let path = last_output_line(&output.stdout).ok_or_else(|| {
            probe_output_error("nix shell probe did not report a tool path on stdout")
        })?;
        let version = self.probe_tool_version(tool, &path)?;
        Ok(ResolvedTool {
            name: tool.name.to_string(),
            path,
            source: ToolSource::EphemeralNix,
            version,
            launch_program,
            launch_args,
        })
    }

    fn probe_tool_version(
        &self,
        tool: &ToolSpec,
        program: &str,
    ) -> std::io::Result<Option<String>> {
        let output = self.runner.run(&tool.probe_command(program))?;
        if output.status_code != Some(0) {
            return Err(command_probe_error(
                &format!("{program} probe failed"),
                &output,
            ));
        }
        let probe_output = first_output_line(&output.stdout, &output.stderr);
        if !tool.accepts_probe_output(probe_output.as_deref()) {
            return Err(probe_output_error(&format!(
                "{program} probe returned unusable output"
            )));
        }
        Ok(tool.reported_version(&output.stdout, &output.stderr))
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

/// Resolves all required tools up front and returns version metadata.
///
/// # Errors
///
/// Returns an I/O error as soon as any required tool cannot be resolved.
pub fn resolve_required_tools<R>(
    runner: &R,
    tools: &[ToolSpec],
) -> std::io::Result<Vec<ToolVersion>>
where
    R: CommandRunner,
{
    tools
        .iter()
        .map(|tool| {
            let resolved = runner.resolve_tool(tool)?;
            Ok(ToolVersion {
                name: resolved.name,
                path: Some(resolved.path),
                source: Some(resolved.source),
                version: resolved.version,
                error: None,
            })
        })
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
    let output = runner.run(&tool.probe_command(&resolved.path));
    match output {
        Ok(output) if output.status_code == Some(0) => ToolVersion {
            name: tool.name.to_string(),
            path: Some(resolved.path),
            source: Some(resolved.source),
            version: tool.reported_version(&output.stdout, &output.stderr),
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

fn last_output_line(output: &[u8]) -> Option<String> {
    String::from_utf8_lossy(output)
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .map(ToOwned::to_owned)
}

fn probe_detail(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    let stderr_lines = String::from_utf8_lossy(stderr);
    stderr_lines
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("error:"))
        .map(ToOwned::to_owned)
        .or_else(|| last_output_line(stderr))
        .or_else(|| last_output_line(stdout))
}

fn command_probe_error(context: &str, output: &crate::process::CommandOutput) -> std::io::Error {
    let detail = probe_detail(&output.stdout, &output.stderr)
        .unwrap_or_else(|| format!("exit status {:?}", output.status_code));
    std::io::Error::other(format!("{context}: {detail}"))
}

fn probe_output_error(context: &str) -> std::io::Error {
    std::io::Error::other(context.to_string())
}

fn resolution_error(tool: &ToolSpec, attempts: &[String], cwd: &Path) -> std::io::Error {
    let mut message = tool.missing_tool_error();
    message.push_str("\nResolution attempts:");
    for attempt in attempts {
        message.push_str("\n- ");
        message.push_str(attempt);
    }
    if attempts.is_empty() {
        message.push_str("\n- no supported resolution sources were available");
    }
    if tool.kind == ToolKind::NixManaged {
        let _ = write!(
            message,
            "\nNext step: install `{}` directly, add it to the project flake, or run from a dev shell for {}.",
            tool.name,
            cwd.display()
        );
    }
    std::io::Error::other(message)
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
pub const HEAPTRACK: ToolSpec = nix_utility("heaptrack", "heaptrack");
pub const HEAPTRACK_PRINT: ToolSpec = nix_utility("heaptrack_print", "heaptrack");
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
