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
use backends::{ProfileRequest, ProfilerBackend};
use cli::{Cli, CliCommand};

pub fn run_cli<I, T>(args: I) -> backends::BackendResult<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);
    run_parsed_cli(cli)
}

pub fn run_parsed_cli(cli: Cli) -> backends::BackendResult<()> {
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
        FakeBackend.profile(&request)?;
        return Ok(());
    }

    match cli.command {
        CliCommand::Fold(_) | CliCommand::Summarize(_) | CliCommand::Flamegraph(_) => Ok(()),
        CliCommand::Memory(_)
        | CliCommand::Cpu(_)
        | CliCommand::Offpcu(_)
        | CliCommand::Latency(_)
        | CliCommand::Async(_)
        | CliCommand::Profile(_) => unreachable!("profile invocations returned earlier"),
    }
}
