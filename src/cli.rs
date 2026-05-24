use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "pyroclast")]
#[command(about = "Rust-only profiling orchestration and analysis")]
pub struct Cli {
    #[command(subcommand)]
    pub command: CliCommand,
}

impl Cli {
    pub fn parse_from<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        <Self as Parser>::parse_from(args)
    }
}

#[derive(Debug, Subcommand)]
pub enum CliCommand {
    Memory(RunArgs),
    Cpu(RunArgs),
    Offpcu(RunArgs),
    Latency(RunArgs),
    Async(RunArgs),
    Profile(ProfileArgs),
    Fold(FoldArgs),
    Summarize(SummarizeArgs),
    Flamegraph(FlamegraphArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    Cpu,
    Memory,
    Offcpu,
    Latency,
    Async,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(long)]
    pub out: Option<PathBuf>,

    #[arg(long)]
    pub name: Option<String>,

    #[arg(long)]
    pub json: bool,

    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProfileInvocation {
    pub kind: ProfileKind,
    pub out: Option<PathBuf>,
    pub name: Option<String>,
    pub json: bool,
    pub command: Vec<String>,
}

impl CliCommand {
    #[must_use]
    pub fn profile_invocation(&self) -> Option<ProfileInvocation> {
        match self {
            Self::Memory(args) => Some(ProfileInvocation::from_run(ProfileKind::Memory, args)),
            Self::Cpu(args) => Some(ProfileInvocation::from_run(ProfileKind::Cpu, args)),
            Self::Offpcu(args) => Some(ProfileInvocation::from_run(ProfileKind::Offcpu, args)),
            Self::Latency(args) => Some(ProfileInvocation::from_run(ProfileKind::Latency, args)),
            Self::Async(args) => Some(ProfileInvocation::from_run(ProfileKind::Async, args)),
            Self::Profile(args) => Some(ProfileInvocation {
                kind: args.kind,
                out: args.out.clone(),
                name: args.name.clone(),
                json: args.json,
                command: args.command.clone(),
            }),
            Self::Fold(_) | Self::Summarize(_) | Self::Flamegraph(_) => None,
        }
    }
}

impl ProfileInvocation {
    fn from_run(kind: ProfileKind, args: &RunArgs) -> Self {
        Self {
            kind,
            out: args.out.clone(),
            name: args.name.clone(),
            json: args.json,
            command: args.command.clone(),
        }
    }
}

#[derive(Debug, Args)]
pub struct ProfileArgs {
    #[arg(long, value_enum, default_value_t = ProfileKind::Cpu)]
    pub kind: ProfileKind,

    #[arg(long)]
    pub out: Option<PathBuf>,

    #[arg(long)]
    pub name: Option<String>,

    #[arg(long)]
    pub json: bool,

    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct FoldArgs {
    #[arg(long)]
    pub count_periods: bool,

    pub input: PathBuf,
}

#[derive(Debug, Args)]
pub struct SummarizeArgs {
    #[arg(long)]
    pub json: bool,

    pub artifact_dir: PathBuf,
}

#[derive(Debug, Args)]
pub struct FlamegraphArgs {
    pub input: PathBuf,

    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    #[arg(long, default_value = "CPU profile")]
    pub title: String,
}
