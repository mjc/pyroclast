pub mod artifacts;
pub mod backends;
pub mod benchmarks;
pub mod cli;
pub mod config;
pub mod errors;
pub mod flamegraph;
pub mod folded;
pub mod manifest;
pub mod output;
pub mod parsers;
pub mod perfdata;
pub mod platform;
pub mod process;
pub mod summary;
pub mod symbols;
pub mod tools;

use artifacts::ArtifactLayout;
use backends::fake::FakeBackend;
use backends::linux_perf::LinuxPerfBackend;
use backends::{ProfileRequest, ProfilerBackend};
use cli::ProfileKind;
use cli::{Cli, CliCommand};
use flamegraph::{FlamegraphRenderer, FlamegraphRequest, InfernoFlamegraphRenderer};
pub use output::{CliOutput, write_cli_output};
use perfdata::fold::{
    FoldOptions, fold_perfdata_file, fold_perfdata_file_with_options,
    fold_perfdata_file_with_symbols,
};
use process::{CommandRunner, RealCommandRunner};
use symbols::Addr2lineResolver;

/// Parses command-line arguments and runs the requested Pyroclast command.
///
/// # Errors
///
/// Returns an error when command execution, artifact I/O, or input parsing
/// fails.
pub fn run_cli<I, T>(args: I) -> backends::BackendResult<CliOutput>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);
    run_parsed_cli(cli)
}

/// Runs a parsed CLI command with the real process runner.
///
/// # Errors
///
/// Returns an error when command execution, artifact I/O, or input parsing
/// fails.
pub fn run_parsed_cli(cli: Cli) -> backends::BackendResult<CliOutput> {
    run_parsed_cli_with_runner(cli, &RealCommandRunner)
}

/// Runs a parsed CLI command with an injected process runner.
///
/// # Errors
///
/// Returns an error when command execution, artifact I/O, or input parsing
/// fails.
pub fn run_parsed_cli_with_runner<R>(cli: Cli, runner: &R) -> backends::BackendResult<CliOutput>
where
    R: CommandRunner,
{
    run_parsed_cli_with_runner_and_renderer(cli, runner, InfernoFlamegraphRenderer::new(runner))
}

/// Runs a parsed CLI command with injected process and flamegraph renderers.
///
/// # Errors
///
/// Returns an error when command execution, artifact I/O, rendering, or input
/// parsing fails.
pub fn run_parsed_cli_with_runner_and_renderer<R, F>(
    cli: Cli,
    runner: &R,
    flamegraph_renderer: F,
) -> backends::BackendResult<CliOutput>
where
    R: CommandRunner,
    F: FlamegraphRenderer,
{
    if let Some(invocation) = cli.command.profile_invocation() {
        let out_dir = invocation
            .out
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("pyroclast-runs/latest"));
        let request = ProfileRequest {
            kind: invocation.kind,
            command: invocation.command,
            out_dir,
            name: invocation.name,
            json: invocation.json,
            symbols: invocation.symbols,
            frequency: invocation.frequency,
            event: invocation.event,
            call_graph: invocation.call_graph,
            pid: invocation.pid,
            tids: invocation.tids,
            threads_of_pid: invocation.threads_of_pid,
            duration_secs: invocation.duration_secs,
        };
        match request.kind {
            ProfileKind::Cpu if std::env::consts::OS == "linux" => {
                LinuxPerfBackend::with_renderer(runner, flamegraph_renderer).profile(&request)?;
            }
            _ => {
                FakeBackend.profile(&request)?;
            }
        }
        return Ok(CliOutput::default());
    }

    match cli.command {
        CliCommand::Fold(command) => {
            let options = FoldOptions {
                count_periods: command.count_periods,
            };
            let stdout = fold_perfdata_for_cli(&command.input, options, command.symbols, runner)?;
            Ok(CliOutput {
                stdout,
                stderr: String::new(),
            })
        }
        CliCommand::Flamegraph(command) => {
            let output = command
                .output
                .unwrap_or_else(|| std::path::PathBuf::from("flamegraph.svg"));
            let folded_stacks = fold_perfdata_for_cli(
                &command.input,
                FoldOptions::default(),
                command.symbols,
                runner,
            )?;
            let render = flamegraph_renderer.render(&FlamegraphRequest {
                title: command.title,
                folded_stacks,
                output,
            })?;
            Ok(CliOutput {
                stdout: String::new(),
                stderr: String::from_utf8_lossy(&render.stderr).into_owned(),
            })
        }
        CliCommand::Summarize(command) => {
            let stdout = summarize_artifact_dir(&command.artifact_dir, command.json)?;
            Ok(CliOutput {
                stdout,
                stderr: String::new(),
            })
        }
        CliCommand::Memory(_)
        | CliCommand::Cpu(_)
        | CliCommand::Offpcu(_)
        | CliCommand::Latency(_)
        | CliCommand::Async(_)
        | CliCommand::Profile(_) => unreachable!("profile invocations returned earlier"),
    }
}

fn summarize_artifact_dir(path: &std::path::Path, json: bool) -> backends::BackendResult<String> {
    let layout = ArtifactLayout::new(path.to_path_buf());
    let summary_path = if json {
        layout.summary_json()
    } else {
        layout.summary_txt()
    };
    Ok(std::fs::read_to_string(summary_path)?)
}

fn fold_perfdata_for_cli<R>(
    path: &std::path::Path,
    options: FoldOptions,
    symbols: bool,
    runner: &R,
) -> backends::BackendResult<String>
where
    R: CommandRunner,
{
    if symbols {
        let symbol_resolver = Addr2lineResolver::new(runner);
        Ok(fold_perfdata_file_with_symbols(
            path,
            options,
            &symbol_resolver,
        )?)
    } else if options == FoldOptions::default() {
        Ok(fold_perfdata_file(path)?)
    } else {
        Ok(fold_perfdata_file_with_options(path, options)?)
    }
}
