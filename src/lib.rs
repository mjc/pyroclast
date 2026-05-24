pub mod artifacts;
pub mod backends;
pub mod cli;
pub mod config;
pub mod errors;
pub mod flamegraph;
pub mod folded;
pub mod manifest;
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
use perfdata::fold::{PerfSummary, summarize_perfdata};
use process::{CommandRunner, RealCommandRunner};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CliOutput {
    pub stdout: String,
    pub stderr: String,
}

pub fn run_cli<I, T>(args: I) -> backends::BackendResult<CliOutput>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);
    run_parsed_cli(cli)
}

pub fn run_parsed_cli(cli: Cli) -> backends::BackendResult<CliOutput> {
    run_parsed_cli_with_runner(cli, &RealCommandRunner)
}

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
            let summary = summarize_perfdata(&bytes)?;
            Ok(CliOutput {
                stdout: format_perf_summary(summary),
                stderr: String::new(),
            })
        }
        CliCommand::Summarize(_) | CliCommand::Flamegraph(_) => Ok(CliOutput::default()),
        CliCommand::Memory(_)
        | CliCommand::Cpu(_)
        | CliCommand::Offpcu(_)
        | CliCommand::Latency(_)
        | CliCommand::Async(_)
        | CliCommand::Profile(_) => unreachable!("profile invocations returned earlier"),
    }
}

fn format_perf_summary(summary: PerfSummary) -> String {
    let mut stdout = format!("total_records={}\n", summary.total_records);
    for (record_type, count) in summary.record_counts {
        stdout.push_str(&format!("record_type_{record_type}={count}\n"));
    }
    for comm in summary.comms {
        stdout.push_str(&format!("comm={comm}\n"));
    }
    for mmap in summary.mmaps {
        stdout.push_str(&format!("mmap={mmap}\n"));
    }
    stdout
}
