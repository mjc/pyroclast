use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use cargo_metadata::{Artifact, ArtifactDebuginfo, Message, MetadataCommand, Package, TargetKind};
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::backends::BackendResult;
use crate::cli::{
    PerfCallGraph, PerfEvent, ProfileInvocation, ProfileKind, SymbolizerKind,
    profile_symbols_enabled,
};
use crate::process::{CommandRunner, CommandSpec};

#[derive(Debug, Clone, Parser)]
#[command(bin_name = "cargo")]
pub struct CargoCli {
    #[command(subcommand)]
    pub command: CargoCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum CargoCommand {
    #[command(about = "Build a Rust target and profile it with Pyroclast")]
    Pyroclast {
        #[command(subcommand)]
        command: CargoPyroclastCommand,
    },
}

impl CargoCommand {
    #[must_use]
    pub fn pyroclast_command(self) -> CargoPyroclastCommand {
        match self {
            Self::Pyroclast { command } => command,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum UnitTestTargetKind {
    Bin,
    Lib,
}

#[derive(Debug, Clone, Subcommand)]
pub enum CargoPyroclastCommand {
    #[command(alias = "heap")]
    Memory(CargoRunArgs),
    Cpu(CargoRunArgs),
    Offcpu(CargoRunArgs),
    #[command(alias = "syscalls")]
    Latency(CargoRunArgs),
    Async(CargoRunArgs),
}

impl CargoPyroclastCommand {
    /// Resolves the selected Cargo target, builds it, and converts the result
    /// into a Pyroclast profile invocation.
    ///
    /// # Errors
    ///
    /// Returns an error when target selection, cargo build output parsing, or
    /// executable resolution fails.
    pub fn into_profile_invocation<R>(self, runner: &R) -> BackendResult<ProfileInvocation>
    where
        R: CommandRunner,
    {
        let (kind, mut args) = match self {
            Self::Memory(args) => (ProfileKind::Memory, args),
            Self::Cpu(args) => (ProfileKind::Cpu, args),
            Self::Offcpu(args) => (ProfileKind::Offcpu, args),
            Self::Latency(args) => (ProfileKind::Latency, args),
            Self::Async(args) => (ProfileKind::Async, args),
        };

        let target_kind = auto_select_target(&mut args)?;
        let artifacts = build(&args, &target_kind, runner)?;
        let command = workload(&args, &artifacts)?;

        Ok(ProfileInvocation {
            kind,
            out: args.out,
            name: args.name,
            json: args.json,
            symbols: profile_symbols_enabled(kind, args.no_symbols),
            symbolizer: args.symbolizer,
            frequency: args.frequency,
            event: args.event,
            call_graph: args.call_graph,
            pid: None,
            tids: Vec::new(),
            threads_of_pid: None,
            duration_secs: 3600,
            command,
        })
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Args)]
pub struct CargoRunArgs {
    #[arg(long)]
    pub dev: bool,

    #[arg(long)]
    pub profile: Option<String>,

    #[arg(short, long)]
    pub package: Option<String>,

    #[arg(short, long, group = "exec-target")]
    pub bin: Option<String>,

    #[arg(long, group = "exec-target")]
    pub example: Option<String>,

    #[arg(long, group = "exec-target")]
    pub test: Option<String>,

    #[arg(long, group = "exec-target")]
    pub unit_test: Option<Option<String>>,

    #[arg(long)]
    pub unit_test_kind: Option<UnitTestTargetKind>,

    #[arg(long, group = "exec-target")]
    pub unit_bench: Option<Option<String>>,

    #[arg(long, group = "exec-target")]
    pub bench: Option<String>,

    #[arg(long)]
    pub manifest_path: Option<PathBuf>,

    #[arg(short, long)]
    pub features: Option<String>,

    #[arg(long)]
    pub no_default_features: bool,

    #[arg(short, long)]
    pub release: bool,

    #[arg(long)]
    pub target: Option<String>,

    #[arg(long)]
    pub out: Option<PathBuf>,

    #[arg(long)]
    pub name: Option<String>,

    #[arg(long)]
    pub json: bool,

    #[arg(long = "no-symbols")]
    pub no_symbols: bool,

    #[arg(long, value_enum, default_value_t = SymbolizerKind::RustAddr2line)]
    pub symbolizer: SymbolizerKind,

    #[arg(long, default_value_t = 997)]
    pub frequency: u32,

    #[arg(long, value_enum, default_value_t = PerfEvent::Default)]
    pub event: PerfEvent,

    #[arg(long, value_enum, default_value_t = PerfCallGraph::Dwarf)]
    pub call_graph: PerfCallGraph,

    #[arg(last = true)]
    pub trailing_arguments: Vec<String>,
}

#[derive(Clone, Debug)]
struct BinaryTarget {
    package: String,
    target: String,
    kind: Vec<TargetKind>,
}

impl std::fmt::Display for BinaryTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "target {} in package {}",
            self.target, self.package
        )
    }
}

#[must_use]
pub fn normalize_cargo_args<I, T>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let mut normalized: Vec<OsString> = args.into_iter().map(Into::into).collect();
    if normalized.is_empty() {
        normalized.push(OsString::from("cargo"));
    }
    if normalized
        .get(1)
        .is_none_or(|arg| arg.as_os_str() != OsStr::new("pyroclast"))
    {
        normalized.insert(1, OsString::from("pyroclast"));
    }
    reorder_leading_cargo_build_args(normalized)
}

fn reorder_leading_cargo_build_args(args: Vec<OsString>) -> Vec<OsString> {
    if args.len() < 4 {
        return args;
    }

    let mut index = 2usize;
    while index < args.len() {
        let token = args[index].to_string_lossy();
        if is_profile_kind(&token) {
            if index == 2 {
                return args;
            }
            let mut reordered = Vec::with_capacity(args.len());
            reordered.extend(args[..2].iter().cloned());
            reordered.push(args[index].clone());
            reordered.extend(args[2..index].iter().cloned());
            reordered.extend(args[index + 1..].iter().cloned());
            return reordered;
        }
        if token == "--" {
            return args;
        }
        let Some(consumed) = leading_cargo_build_arg_len(&args, index) else {
            return args;
        };
        index += consumed;
    }

    args
}

fn is_profile_kind(token: &str) -> bool {
    matches!(
        token,
        "memory" | "heap" | "cpu" | "offcpu" | "latency" | "syscalls" | "async"
    )
}

fn leading_cargo_build_arg_len(args: &[OsString], index: usize) -> Option<usize> {
    let token = args[index].to_string_lossy();

    if has_inline_value(
        &token,
        &[
            "--profile",
            "--package",
            "--bin",
            "--example",
            "--test",
            "--bench",
            "--manifest-path",
            "--features",
            "--target",
            "--unit-test-kind",
        ],
    ) {
        return Some(1);
    }

    if matches!(
        token.as_ref(),
        "--dev" | "--no-default-features" | "--release" | "-r"
    ) {
        return Some(1);
    }

    if matches!(
        token.as_ref(),
        "--profile"
            | "--package"
            | "-p"
            | "--bin"
            | "--example"
            | "--test"
            | "--bench"
            | "--manifest-path"
            | "--features"
            | "-f"
            | "--target"
            | "--unit-test-kind"
    ) {
        return Some(if index + 1 < args.len() { 2 } else { 1 });
    }

    if matches!(token.as_ref(), "--unit-test" | "--unit-bench") {
        let next = args.get(index + 1).map(|value| value.to_string_lossy());
        let consumes_value = next
            .as_ref()
            .is_some_and(|next| !next.starts_with('-') && !is_profile_kind(next));
        return Some(if consumes_value { 2 } else { 1 });
    }

    None
}

fn has_inline_value(token: &str, flags: &[&str]) -> bool {
    flags.iter().any(|flag| {
        token.len() > flag.len()
            && token.starts_with(flag)
            && token.as_bytes().get(flag.len()) == Some(&b'=')
    })
}

fn auto_select_target(args: &mut CargoRunArgs) -> BackendResult<Vec<TargetKind>> {
    if args.bin.is_none()
        && args.bench.is_none()
        && args.example.is_none()
        && args.test.is_none()
        && args.unit_test.is_none()
        && args.unit_bench.is_none()
    {
        let target = find_unique_target(
            &[TargetKind::Bin],
            args.package.as_deref(),
            args.manifest_path.as_deref(),
            None,
        )?;
        args.bin = Some(target.target);
        args.package = Some(target.package);
        Ok(target.kind)
    } else if let Some(unit_test) = args.unit_test.clone() {
        let kinds = match args.unit_test_kind {
            Some(UnitTestTargetKind::Bin) => &[TargetKind::Bin][..],
            Some(UnitTestTargetKind::Lib) => &[TargetKind::Lib, TargetKind::RLib],
            None => &[TargetKind::Bin, TargetKind::Lib, TargetKind::RLib],
        };
        let target = find_unique_target(
            kinds,
            args.package.as_deref(),
            args.manifest_path.as_deref(),
            unit_test.as_deref(),
        )?;
        args.unit_test = Some(Some(target.target));
        args.package = Some(target.package);
        Ok(target.kind)
    } else if let Some(unit_bench) = args.unit_bench.clone() {
        let kinds = match args.unit_test_kind {
            Some(UnitTestTargetKind::Bin) => &[TargetKind::Bin][..],
            Some(UnitTestTargetKind::Lib) => &[TargetKind::Lib, TargetKind::RLib],
            None => &[TargetKind::Bin, TargetKind::Lib, TargetKind::RLib],
        };
        let target = find_unique_target(
            kinds,
            args.package.as_deref(),
            args.manifest_path.as_deref(),
            unit_bench.as_deref(),
        )?;
        args.unit_bench = Some(Some(target.target));
        args.package = Some(target.package);
        Ok(target.kind)
    } else {
        Ok(Vec::new())
    }
}

fn build<R>(args: &CargoRunArgs, kind: &[TargetKind], runner: &R) -> BackendResult<Vec<Artifact>>
where
    R: CommandRunner,
{
    let mut command = CommandSpec::new("cargo");

    if !args.dev && (args.bench.is_some() || args.unit_bench.is_some()) {
        command = command.args(["bench", "--no-run"]);
    } else if args.unit_test.is_some() {
        command = command.args(["test", "--no-run"]);
    } else {
        command = command.arg("build");
    }

    if let Some(profile) = &args.profile {
        command = command.args(["--profile".to_string(), profile.clone()]);
    } else if !args.dev && args.bench.is_none() && args.unit_bench.is_none() {
        command = command.arg("--release");
    }

    if let Some(package) = &args.package {
        command = command.args(["--package".to_string(), package.clone()]);
    }

    if let Some(bin) = &args.bin {
        command = command.args(["--bin".to_string(), bin.clone()]);
    }

    if let Some(target) = &args.target {
        command = command.args(["--target".to_string(), target.clone()]);
    }

    if let Some(example) = &args.example {
        command = command.args(["--example".to_string(), example.clone()]);
    }

    if let Some(test) = &args.test {
        command = command.args(["--test".to_string(), test.clone()]);
    }

    if let Some(bench) = &args.bench {
        command = command.args(["--bench".to_string(), bench.clone()]);
    }

    if let Some(Some(unit_test)) = &args.unit_test {
        if kind
            .iter()
            .any(|kind| matches!(kind, TargetKind::Lib | TargetKind::RLib))
        {
            command = command.arg("--lib");
        } else {
            command = command.args(["--bin".to_string(), unit_test.clone()]);
        }
    }

    if let Some(Some(unit_bench)) = &args.unit_bench {
        if kind
            .iter()
            .any(|kind| matches!(kind, TargetKind::Lib | TargetKind::RLib))
        {
            command = command.arg("--lib");
        } else {
            command = command.args(["--bin".to_string(), unit_bench.clone()]);
        }
    }

    if let Some(manifest_path) = &args.manifest_path {
        command = command.args([
            "--manifest-path".to_string(),
            manifest_path.display().to_string(),
        ]);
    }

    if let Some(features) = &args.features {
        command = command.args(["--features".to_string(), features.clone()]);
    }

    if args.no_default_features {
        command = command.arg("--no-default-features");
    }

    command = command
        .arg("--message-format=json-render-diagnostics")
        .inherit_stderr();

    let output = runner.run(&command)?;
    if output.status_code != Some(0) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = if stderr.trim().is_empty() {
            "cargo build failed".to_string()
        } else {
            format!("cargo build failed: {stderr}")
        };
        return Err(message.into());
    }

    Message::parse_stream(&*output.stdout)
        .filter_map(|message| match message {
            Ok(Message::CompilerArtifact(artifact)) => Some(Ok(artifact)),
            Ok(_) => None,
            Err(error) => Some(Err(format!("failed to parse cargo build output: {error}"))),
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn workload(args: &CargoRunArgs, artifacts: &[Artifact]) -> BackendResult<Vec<String>> {
    let mut trailing_arguments = args.trailing_arguments.clone();

    if artifacts
        .iter()
        .all(|artifact| artifact.executable.is_none())
    {
        return Err("build artifacts do not contain any executable to profile".into());
    }

    let (kind, target): (&[TargetKind], &str) = match args {
        CargoRunArgs {
            bin: Some(target), ..
        } => (&[TargetKind::Bin], target),
        CargoRunArgs {
            example: Some(target),
            ..
        } => (&[TargetKind::Example], target),
        CargoRunArgs {
            test: Some(target), ..
        } => (&[TargetKind::Test], target),
        CargoRunArgs {
            bench: Some(target),
            ..
        } => (&[TargetKind::Bench], target),
        CargoRunArgs {
            unit_test: Some(Some(target)),
            ..
        } => (
            &[TargetKind::Lib, TargetKind::RLib, TargetKind::Bin],
            target,
        ),
        CargoRunArgs {
            unit_bench: Some(Some(target)),
            ..
        } => {
            trailing_arguments.push("--bench".to_string());
            (
                &[TargetKind::Lib, TargetKind::RLib, TargetKind::Bin],
                target,
            )
        }
        _ => return Err("no target for profiling".into()),
    };

    let (debug_level, binary_path) = artifacts
        .iter()
        .find_map(|artifact| {
            artifact
                .executable
                .as_deref()
                .filter(|_| {
                    artifact.target.name == *target
                        && artifact
                            .target
                            .kind
                            .iter()
                            .any(|artifact_kind| kind.contains(artifact_kind))
                })
                .map(|path| (&artifact.profile.debuginfo, path))
        })
        .ok_or_else(|| {
            let targets: Vec<_> = artifacts
                .iter()
                .map(|artifact| (&artifact.target.kind, &artifact.target.name))
                .collect();
            format!(
                "could not find desired target {:?} in the targets for this crate: {:?}",
                (kind, target),
                targets
            )
        })?;

    if !args.dev && debug_level == &ArtifactDebuginfo::None {
        let profile = match args
            .example
            .as_ref()
            .or(args.bin.as_ref())
            .or_else(|| args.unit_test.as_ref().unwrap_or(&None).as_ref())
        {
            Some(_) => "release",
            None => "bench",
        };

        eprintln!(
            "\nWARNING: profiling without debuginfo. Enable symbol information by adding the following lines to Cargo.toml:\n"
        );
        eprintln!("[profile.{profile}]");
        eprintln!("debug = true\n");
        eprintln!("Or set this environment variable:\n");
        eprintln!("CARGO_PROFILE_{}_DEBUG=true\n", profile.to_uppercase());
    }

    let mut command = Vec::with_capacity(1 + trailing_arguments.len());
    command.push(binary_path.to_string());
    command.extend(trailing_arguments);
    Ok(command)
}

/// Finds the crate root used for cargo target discovery.
///
/// # Errors
///
/// Returns an error when the manifest path is invalid or no Cargo manifest can
/// be found from the current working directory upward.
pub fn find_crate_root(manifest_path: Option<&Path>) -> BackendResult<PathBuf> {
    if let Some(path) = manifest_path {
        let parent = path.parent().ok_or_else(|| {
            format!(
                "the manifest path '{}' must point to a Cargo.toml file",
                path.display()
            )
        })?;
        Ok(parent.canonicalize().map_err(|error| {
            format!(
                "failed to canonicalize manifest parent directory '{}': {error}",
                parent.display()
            )
        })?)
    } else {
        let current_dir = std::env::current_dir()?;
        for parent in current_dir.ancestors() {
            if parent.join("Cargo.toml").exists() {
                return Ok(parent.to_path_buf());
            }
        }
        Err(format!(
            "could not find 'Cargo.toml' in '{}' or any parent directory",
            current_dir.display()
        )
        .into())
    }
}

fn find_unique_target(
    kind: &[TargetKind],
    package: Option<&str>,
    manifest_path: Option<&Path>,
    target_name: Option<&str>,
) -> BackendResult<BinaryTarget> {
    let mut metadata_command = MetadataCommand::new();
    metadata_command.no_deps();
    if let Some(manifest_path) = manifest_path {
        metadata_command.manifest_path(manifest_path);
    }

    let crate_root = find_crate_root(manifest_path)?;

    let mut packages = metadata_command
        .exec()?
        .packages
        .into_iter()
        .filter(|package_metadata| {
            if let Some(package) = package {
                package == package_metadata.name.as_str()
            } else {
                // cargo metadata reports manifest paths as given, which can
                // disagree with the canonicalized crate root through symlinks
                // (macOS /var -> /private/var).
                let manifest_path = package_metadata.manifest_path.as_std_path();
                manifest_path
                    .canonicalize()
                    .as_deref()
                    .unwrap_or(manifest_path)
                    .starts_with(&crate_root)
            }
        })
        .peekable();

    if packages.peek().is_none() {
        return Err(match package {
            Some(package) => format!("workspace has no package named {package}"),
            None => format!(
                "failed to find any package in '{}' or below",
                crate_root.display()
            ),
        }
        .into());
    }

    let mut package_count = 0usize;
    let mut selected_default_run = false;

    let mut targets: Vec<_> = packages
        .flat_map(|package_metadata| {
            let Package {
                targets,
                name,
                default_run,
                ..
            } = package_metadata;
            package_count += 1;
            if default_run.is_some() {
                selected_default_run = true;
            }
            targets.into_iter().filter_map(move |target| {
                if !target.kind.iter().any(|candidate| kind.contains(candidate)) {
                    return None;
                }

                match &default_run {
                    Some(default_run) if default_run != &target.name => return None,
                    _ => {}
                }

                match target_name {
                    Some(target_name) if target_name != target.name => return None,
                    _ => {}
                }

                Some(BinaryTarget {
                    package: name.to_string(),
                    target: target.name,
                    kind: target.kind,
                })
            })
        })
        .collect();

    match targets.as_slice() {
        [_] => {
            let target = targets.remove(0);
            if package_count != 1 || !selected_default_run {
                eprintln!("automatically selected {target} as it is the only valid target");
            }
            Ok(target)
        }
        [] => Err(
            "crate has no automatically selectable target:\nHint: try passing `--example <example>` or similar to choose a binary".into(),
        ),
        _ => Err(format!(
            "several possible targets found: {targets:#?}, please pass an explicit target."
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use serde_json::json;
    use tempfile::tempdir;

    use crate::process::{CommandOutput, CommandRunner};

    #[test]
    fn normalizes_direct_binary_invocation_to_cargo_shape() {
        let cli = CargoCli::parse_from(normalize_cargo_args([
            "cargo-pyroclast",
            "cpu",
            "--",
            "--tui",
        ]));

        let CargoCommand::Pyroclast { command } = cli.command;
        let CargoPyroclastCommand::Cpu(args) = command else {
            panic!("expected cpu command");
        };
        assert_eq!(args.trailing_arguments, vec!["--tui"]);
    }

    #[test]
    fn parses_cargo_style_cpu_invocation_with_profile_options() {
        let cli = CargoCli::parse_from(normalize_cargo_args([
            "cargo",
            "pyroclast",
            "--profile",
            "profiling",
            "cpu",
            "--frequency",
            "199",
            "--event",
            "task-clock",
            "--call-graph",
            "fp",
            "--",
            "--tui",
        ]));

        let CargoCommand::Pyroclast { command } = cli.command;
        let CargoPyroclastCommand::Cpu(args) = command else {
            panic!("expected cpu command");
        };
        assert_eq!(args.profile.as_deref(), Some("profiling"));
        assert_eq!(args.frequency, 199);
        assert_eq!(args.event, PerfEvent::TaskClock);
        assert_eq!(args.call_graph, PerfCallGraph::Fp);
        assert_eq!(args.trailing_arguments, vec!["--tui"]);
    }

    #[test]
    fn parses_leading_manifest_path_before_profile_kind() {
        let cli = CargoCli::parse_from(normalize_cargo_args([
            "cargo",
            "pyroclast",
            "--manifest-path",
            "demo/Cargo.toml",
            "memory",
            "--",
            "--tui",
        ]));

        let CargoCommand::Pyroclast { command } = cli.command;
        let CargoPyroclastCommand::Memory(args) = command else {
            panic!("expected memory command");
        };
        assert_eq!(args.manifest_path, Some(PathBuf::from("demo/Cargo.toml")));
        assert_eq!(args.trailing_arguments, vec!["--tui"]);
    }

    #[test]
    fn resolves_unique_bin_and_forwards_trailing_arguments() {
        let root = tempdir().expect("tempdir");
        write_basic_package(root.path(), "demo");
        let manifest_path = root.path().join("Cargo.toml");
        let executable = root.path().join("target/release/demo");
        let runner = CargoBuildRunner::successful(cargo_artifact_messages(
            &manifest_path,
            "demo",
            "bin",
            &executable,
            2,
        ));

        let cli = CargoCli::parse_from(normalize_cargo_args([
            "cargo-pyroclast",
            "pyroclast",
            "cpu",
            "--manifest-path",
            manifest_path.to_str().expect("utf8 path"),
            "--",
            "--tui",
        ]));

        let invocation = cli
            .command
            .pyroclast_command()
            .into_profile_invocation(&runner)
            .expect("profile invocation");

        assert_eq!(invocation.kind, ProfileKind::Cpu);
        assert_eq!(
            invocation.command,
            vec![executable.display().to_string(), "--tui".to_string()]
        );
        assert_eq!(
            runner.commands()[0].args,
            vec![
                "build".to_string(),
                "--release".to_string(),
                "--package".to_string(),
                "demo".to_string(),
                "--bin".to_string(),
                "demo".to_string(),
                "--manifest-path".to_string(),
                manifest_path.display().to_string(),
                "--message-format=json-render-diagnostics".to_string(),
            ]
        );
        assert!(runner.commands()[0].inherit_stderr);
    }

    #[test]
    fn resolves_manifest_path_through_symlinked_crate_root() {
        let root = tempdir().expect("tempdir");
        let real_root = root.path().join("real");
        write_basic_package(&real_root, "demo");
        let linked_root = root.path().join("linked");
        std::os::unix::fs::symlink(&real_root, &linked_root).expect("symlink crate root");
        let manifest_path = linked_root.join("Cargo.toml");
        let executable = real_root.join("target/release/demo");
        let runner = CargoBuildRunner::successful(cargo_artifact_messages(
            &manifest_path,
            "demo",
            "bin",
            &executable,
            2,
        ));

        let cli = CargoCli::parse_from(normalize_cargo_args([
            "cargo-pyroclast",
            "pyroclast",
            "cpu",
            "--manifest-path",
            manifest_path.to_str().expect("utf8 path"),
        ]));

        let invocation = cli
            .command
            .pyroclast_command()
            .into_profile_invocation(&runner)
            .expect("profile invocation");

        assert_eq!(invocation.command, vec![executable.display().to_string()]);
    }

    #[test]
    fn auto_selects_default_run_target() {
        let root = tempdir().expect("tempdir");
        write_default_run_package(root.path(), "demo", "viewer", &["worker"]);
        let manifest_path = root.path().join("Cargo.toml");
        let executable = root.path().join("target/release/viewer");
        let runner = CargoBuildRunner::successful(cargo_artifact_messages(
            &manifest_path,
            "viewer",
            "bin",
            &executable,
            2,
        ));

        let cli = CargoCli::parse_from(normalize_cargo_args([
            "cargo-pyroclast",
            "cpu",
            "--manifest-path",
            manifest_path.to_str().expect("utf8 path"),
        ]));

        let invocation = cli
            .command
            .pyroclast_command()
            .into_profile_invocation(&runner)
            .expect("profile invocation");

        assert_eq!(invocation.command, vec![executable.display().to_string()]);
        assert_eq!(
            runner.commands()[0].args,
            vec![
                "build".to_string(),
                "--release".to_string(),
                "--package".to_string(),
                "demo".to_string(),
                "--bin".to_string(),
                "viewer".to_string(),
                "--manifest-path".to_string(),
                manifest_path.display().to_string(),
                "--message-format=json-render-diagnostics".to_string(),
            ]
        );
        assert!(runner.commands()[0].inherit_stderr);
    }

    #[test]
    fn uses_explicit_profile_instead_of_release() {
        let root = tempdir().expect("tempdir");
        write_basic_package(root.path(), "demo");
        let manifest_path = root.path().join("Cargo.toml");
        let executable = root.path().join("target/profiling/demo");
        let runner = CargoBuildRunner::successful(cargo_artifact_messages(
            &manifest_path,
            "demo",
            "bin",
            &executable,
            2,
        ));

        let cli = CargoCli::parse_from(normalize_cargo_args([
            "cargo-pyroclast",
            "cpu",
            "--manifest-path",
            manifest_path.to_str().expect("utf8 path"),
            "--profile",
            "profiling",
        ]));

        cli.command
            .pyroclast_command()
            .into_profile_invocation(&runner)
            .expect("profile invocation");

        assert!(runner.commands()[0].args.contains(&"--profile".to_string()));
        assert!(runner.commands()[0].args.contains(&"profiling".to_string()));
        assert!(!runner.commands()[0].args.contains(&"--release".to_string()));
        assert!(runner.commands()[0].inherit_stderr);
    }

    #[test]
    fn forwards_example_and_feature_flags_to_cargo_build() {
        let root = tempdir().expect("tempdir");
        write_basic_package(root.path(), "demo");
        std::fs::create_dir_all(root.path().join("examples")).expect("examples dir");
        std::fs::write(
            root.path().join("examples").join("sample.rs"),
            "fn main() {}\n",
        )
        .expect("example source");
        let manifest_path = root.path().join("Cargo.toml");
        let executable = root.path().join("target/release/examples/sample");
        let runner = CargoBuildRunner::successful(cargo_artifact_messages(
            &manifest_path,
            "sample",
            "example",
            &executable,
            2,
        ));

        let cli = CargoCli::parse_from(normalize_cargo_args([
            "cargo-pyroclast",
            "cpu",
            "--manifest-path",
            manifest_path.to_str().expect("utf8 path"),
            "--example",
            "sample",
            "--features",
            "tui,profiling",
            "--no-default-features",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--",
            "--tui",
        ]));

        let invocation = cli
            .command
            .pyroclast_command()
            .into_profile_invocation(&runner)
            .expect("profile invocation");

        assert_eq!(
            invocation.command,
            vec![executable.display().to_string(), "--tui".to_string()]
        );
        assert_eq!(
            runner.commands()[0].args,
            vec![
                "build".to_string(),
                "--release".to_string(),
                "--target".to_string(),
                "x86_64-unknown-linux-gnu".to_string(),
                "--example".to_string(),
                "sample".to_string(),
                "--manifest-path".to_string(),
                manifest_path.display().to_string(),
                "--features".to_string(),
                "tui,profiling".to_string(),
                "--no-default-features".to_string(),
                "--message-format=json-render-diagnostics".to_string(),
            ]
        );
        assert!(runner.commands()[0].inherit_stderr);
    }

    #[test]
    fn rejects_ambiguous_automatic_target_selection() {
        let root = tempdir().expect("tempdir");
        write_multi_bin_package(root.path(), "demo", &["alpha", "beta"]);
        let manifest_path = root.path().join("Cargo.toml");
        let runner = CargoBuildRunner::successful(Vec::new());

        let cli = CargoCli::parse_from(normalize_cargo_args([
            "cargo-pyroclast",
            "cpu",
            "--manifest-path",
            manifest_path.to_str().expect("utf8 path"),
        ]));

        let error = cli
            .command
            .pyroclast_command()
            .into_profile_invocation(&runner)
            .expect_err("ambiguous target should fail");

        assert!(error.to_string().contains("several possible targets found"));
        assert!(runner.commands().is_empty());
    }

    #[test]
    fn reports_cargo_build_failure_with_stderr() {
        let root = tempdir().expect("tempdir");
        write_basic_package(root.path(), "demo");
        let manifest_path = root.path().join("Cargo.toml");
        let runner = CargoBuildRunner::failing(b"compile failed\n".to_vec());

        let cli = CargoCli::parse_from(normalize_cargo_args([
            "cargo-pyroclast",
            "cpu",
            "--manifest-path",
            manifest_path.to_str().expect("utf8 path"),
        ]));

        let error = cli
            .command
            .pyroclast_command()
            .into_profile_invocation(&runner)
            .expect_err("cargo build should fail");

        assert_eq!(error.to_string(), "cargo build failed: compile failed\n");
        assert_eq!(runner.commands().len(), 1);
    }

    #[test]
    fn reports_missing_executable_artifact() {
        let root = tempdir().expect("tempdir");
        write_basic_package(root.path(), "demo");
        let manifest_path = root.path().join("Cargo.toml");
        let runner = CargoBuildRunner::successful(cargo_artifact_messages_without_executable(
            &manifest_path,
            "demo",
            "bin",
        ));

        let cli = CargoCli::parse_from(normalize_cargo_args([
            "cargo-pyroclast",
            "cpu",
            "--manifest-path",
            manifest_path.to_str().expect("utf8 path"),
        ]));

        let error = cli
            .command
            .pyroclast_command()
            .into_profile_invocation(&runner)
            .expect_err("missing executable should fail");

        assert_eq!(
            error.to_string(),
            "build artifacts do not contain any executable to profile"
        );
    }

    #[test]
    fn cargo_memory_command_runs_end_to_end() {
        let root = tempdir().expect("tempdir");
        let workspace = root.path().join("workspace");
        write_basic_package(&workspace, "demo");
        let manifest_path = workspace.join("Cargo.toml");
        let executable = workspace.join("target/release/demo");
        let out_dir = root.path().join("memory-run");
        let runner = CargoMemoryRunner::new(cargo_artifact_messages(
            &manifest_path,
            "demo",
            "bin",
            &executable,
            2,
        ));

        let cli = CargoCli::parse_from(normalize_cargo_args([
            "cargo-pyroclast",
            "memory",
            "--manifest-path",
            manifest_path.to_str().expect("utf8 path"),
            "--out",
            out_dir.to_str().expect("utf8 path"),
            "--",
            "--serve",
        ]));

        crate::run_parsed_cargo_cli_with_runner(cli, &runner).expect("run cargo memory command");

        assert_eq!(
            std::fs::read_to_string(out_dir.join("command.txt")).expect("command.txt"),
            format!("{} --serve\n", executable.display())
        );
        let run_json = std::fs::read_to_string(out_dir.join("run.json")).expect("run.json");
        assert!(run_json.contains("\"actual_backend\": \"heaptrack\""));
        let summary_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(out_dir.join("summary.json")).unwrap())
                .expect("summary json");
        assert_eq!(summary_json["total_allocations"], 42);
        assert_eq!(summary_json["peak_heap_bytes"], 1024);
        assert_eq!(
            runner.programs(),
            vec![
                "cargo".to_string(),
                "heaptrack".to_string(),
                "heaptrack_print".to_string(),
            ]
        );
        assert!(runner.commands().iter().any(|command| {
            command.program == "heaptrack"
                && command.args
                    == vec![
                        "--record-only".to_string(),
                        "-o".to_string(),
                        out_dir.join("profile.raw.heaptrack").display().to_string(),
                        executable.display().to_string(),
                        "--serve".to_string(),
                    ]
        }));
    }

    struct CargoBuildRunner {
        commands: Mutex<Vec<CommandSpec>>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        status_code: i32,
    }

    impl CargoBuildRunner {
        fn successful(stdout: Vec<u8>) -> Self {
            Self {
                commands: Mutex::new(Vec::new()),
                stdout,
                stderr: Vec::new(),
                status_code: 0,
            }
        }

        fn failing(stderr: Vec<u8>) -> Self {
            Self {
                commands: Mutex::new(Vec::new()),
                stdout: Vec::new(),
                stderr,
                status_code: 101,
            }
        }

        fn commands(&self) -> Vec<CommandSpec> {
            self.commands.lock().expect("commands lock").clone()
        }
    }

    impl CommandRunner for CargoBuildRunner {
        fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
            self.commands
                .lock()
                .expect("commands lock")
                .push(command.clone());
            Ok(CommandOutput {
                status_code: Some(self.status_code),
                stdout: self.stdout.clone(),
                stderr: self.stderr.clone(),
            })
        }
    }

    struct CargoMemoryRunner {
        commands: Mutex<Vec<CommandSpec>>,
        stdout: Vec<u8>,
    }

    impl CargoMemoryRunner {
        fn new(stdout: Vec<u8>) -> Self {
            Self {
                commands: Mutex::new(Vec::new()),
                stdout,
            }
        }

        fn commands(&self) -> Vec<CommandSpec> {
            self.commands.lock().expect("commands lock").clone()
        }

        fn programs(&self) -> Vec<String> {
            self.commands()
                .into_iter()
                .map(|command| command.program)
                .collect()
        }
    }

    impl CommandRunner for CargoMemoryRunner {
        fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
            self.commands
                .lock()
                .expect("commands lock")
                .push(command.clone());
            match command.program.as_str() {
                "cargo" => Ok(CommandOutput {
                    status_code: Some(0),
                    stdout: self.stdout.clone(),
                    stderr: Vec::new(),
                }),
                "heaptrack" => {
                    let output_prefix = command
                        .args
                        .windows(2)
                        .find(|window| window[0] == "-o")
                        .map(|window| window[1].as_str())
                        .expect("heaptrack output prefix");
                    std::fs::write(output_prefix, b"raw heaptrack bytes")?;
                    Ok(CommandOutput {
                        status_code: Some(0),
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                    })
                }
                "heaptrack_print" => Ok(CommandOutput {
                    status_code: Some(0),
                    stdout: b"total allocations: 42\npeak heap memory consumption: 1024 bytes\n"
                        .to_vec(),
                    stderr: Vec::new(),
                }),
                program => panic!("unexpected command: {program}"),
            }
        }
    }

    fn write_basic_package(root: &Path, name: &str) {
        std::fs::create_dir_all(root.join("src")).expect("src dir");
        std::fs::write(
            root.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"),
        )
        .expect("Cargo.toml");
        std::fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("main.rs");
    }

    fn write_default_run_package(root: &Path, name: &str, default_run: &str, bins: &[&str]) {
        std::fs::create_dir_all(root.join("src/bin")).expect("src/bin dir");
        std::fs::write(
            root.join("Cargo.toml"),
            format!(
                "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\ndefault-run = \"{default_run}\"\n"
            ),
        )
        .expect("Cargo.toml");
        std::fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("main.rs");
        std::fs::write(
            root.join("src/bin").join(format!("{default_run}.rs")),
            "fn main() {}\n",
        )
        .expect("default-run source");
        for bin in bins {
            std::fs::write(
                root.join("src/bin").join(format!("{bin}.rs")),
                "fn main() {}\n",
            )
            .expect("bin source");
        }
    }

    fn write_multi_bin_package(root: &Path, name: &str, bins: &[&str]) {
        std::fs::create_dir_all(root.join("src/bin")).expect("src/bin dir");
        std::fs::write(
            root.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"),
        )
        .expect("Cargo.toml");
        std::fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("main.rs");
        for bin in bins {
            std::fs::write(
                root.join("src/bin").join(format!("{bin}.rs")),
                "fn main() {}\n",
            )
            .expect("bin source");
        }
    }

    fn cargo_artifact_messages(
        manifest_path: &Path,
        target_name: &str,
        kind: &str,
        executable: &Path,
        debuginfo: u32,
    ) -> Vec<u8> {
        let manifest_parent = manifest_path.parent().expect("manifest parent");
        let artifact = json!({
            "reason": "compiler-artifact",
            "package_id": format!("path+file://{}#{}@0.1.0", manifest_parent.display(), target_name),
            "manifest_path": manifest_path,
            "target": {
                "kind": [kind],
                "crate_types": ["bin"],
                "name": target_name,
                "src_path": manifest_parent.join("src/main.rs"),
                "edition": "2024",
                "doc": true,
                "doctest": false,
                "test": true
            },
            "profile": {
                "opt_level": "3",
                "debuginfo": debuginfo,
                "debug_assertions": false,
                "overflow_checks": false,
                "test": false
            },
            "features": [],
            "filenames": [executable],
            "executable": executable,
            "fresh": false
        });
        let build_finished = json!({
            "reason": "build-finished",
            "success": true
        });
        format!("{artifact}\n{build_finished}\n").into_bytes()
    }

    fn cargo_artifact_messages_without_executable(
        manifest_path: &Path,
        target_name: &str,
        kind: &str,
    ) -> Vec<u8> {
        let manifest_parent = manifest_path.parent().expect("manifest parent");
        let artifact = json!({
            "reason": "compiler-artifact",
            "package_id": format!("path+file://{}#{}@0.1.0", manifest_parent.display(), target_name),
            "manifest_path": manifest_path,
            "target": {
                "kind": [kind],
                "crate_types": ["bin"],
                "name": target_name,
                "src_path": manifest_parent.join("src/main.rs"),
                "edition": "2024",
                "doc": true,
                "doctest": false,
                "test": true
            },
            "profile": {
                "opt_level": "3",
                "debuginfo": 2,
                "debug_assertions": false,
                "overflow_checks": false,
                "test": false
            },
            "features": [],
            "filenames": [],
            "executable": serde_json::Value::Null,
            "fresh": false
        });
        let build_finished = json!({
            "reason": "build-finished",
            "success": true
        });
        format!("{artifact}\n{build_finished}\n").into_bytes()
    }
}
