pub mod artifacts;
pub mod backends;
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

use backends::fake::FakeBackend;
use backends::linux_perf::LinuxPerfBackend;
use backends::{ProfileRequest, ProfilerBackend};
use cli::ProfileKind;
use cli::{Cli, CliCommand};
use flamegraph::{FlamegraphRenderer, FlamegraphRequest, InfernoFlamegraphRenderer};
pub use output::{CliOutput, write_cli_output};
use perfdata::fold::{
    FoldOptions, fold_perfdata_callchains, fold_perfdata_callchains_with_options,
    fold_perfdata_callchains_with_symbols,
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
        };
        match request.kind {
            ProfileKind::Cpu if std::env::consts::OS == "linux" => {
                LinuxPerfBackend::new(runner).profile(&request)?;
            }
            _ => {
                FakeBackend.profile(&request)?;
            }
        }
        return Ok(CliOutput::default());
    }

    match cli.command {
        CliCommand::Fold(command) => {
            let bytes = std::fs::read(command.input)?;
            let options = FoldOptions {
                count_periods: command.count_periods,
            };
            let stdout = fold_perfdata_for_cli(&bytes, options, command.symbols, runner)?;
            Ok(CliOutput {
                stdout,
                stderr: String::new(),
            })
        }
        CliCommand::Flamegraph(command) => {
            let bytes = std::fs::read(command.input)?;
            let output = command
                .output
                .unwrap_or_else(|| std::path::PathBuf::from("flamegraph.svg"));
            let folded_stacks =
                fold_perfdata_for_cli(&bytes, FoldOptions::default(), command.symbols, runner)?;
            let render = InfernoFlamegraphRenderer::new(runner).render(&FlamegraphRequest {
                title: command.title,
                folded_stacks,
                output,
            })?;
            Ok(CliOutput {
                stdout: String::new(),
                stderr: String::from_utf8_lossy(&render.stderr).into_owned(),
            })
        }
        CliCommand::Summarize(_) => Ok(CliOutput::default()),
        CliCommand::Memory(_)
        | CliCommand::Cpu(_)
        | CliCommand::Offpcu(_)
        | CliCommand::Latency(_)
        | CliCommand::Async(_)
        | CliCommand::Profile(_) => unreachable!("profile invocations returned earlier"),
    }
}

fn fold_perfdata_for_cli<R>(
    bytes: &[u8],
    options: FoldOptions,
    symbols: bool,
    runner: &R,
) -> backends::BackendResult<String>
where
    R: CommandRunner,
{
    if symbols {
        let symbol_resolver = Addr2lineResolver::new(runner);
        Ok(fold_perfdata_callchains_with_symbols(
            bytes,
            options,
            &symbol_resolver,
        )?)
    } else if options == FoldOptions::default() {
        Ok(fold_perfdata_callchains(bytes)?)
    } else {
        Ok(fold_perfdata_callchains_with_options(bytes, options)?)
    }
}
