use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

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
    Profile(ProfileArgs),
    Fold(FoldArgs),
    Summarize(SummarizeArgs),
    Flamegraph(FlamegraphArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ProfileKind {
    Cpu,
    Heap,
    Offcpu,
    Syscalls,
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
}
