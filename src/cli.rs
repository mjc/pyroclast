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
    #[command(alias = "heap")]
    Memory(RunArgs),
    Cpu(RunArgs),
    #[command(alias = "offcpu")]
    Offpcu(RunArgs),
    #[command(alias = "syscalls")]
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
    #[value(alias = "heap")]
    Memory,
    Offcpu,
    #[value(alias = "syscalls")]
    Latency,
    Async,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum PerfCallGraph {
    Fp,
    Dwarf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum PerfEvent {
    CpuClock,
    TaskClock,
    Cycles,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolizerKind {
    Addr2line,
    RustAddr2line,
}

impl std::fmt::Display for PerfEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CpuClock => formatter.write_str("cpu-clock"),
            Self::TaskClock => formatter.write_str("task-clock"),
            Self::Cycles => formatter.write_str("cycles"),
        }
    }
}

impl std::fmt::Display for PerfCallGraph {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fp => formatter.write_str("fp"),
            Self::Dwarf => formatter.write_str("dwarf"),
        }
    }
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(long)]
    pub out: Option<PathBuf>,

    #[arg(long)]
    pub name: Option<String>,

    #[arg(long)]
    pub json: bool,

    #[arg(long)]
    pub symbols: bool,

    #[arg(long, value_enum, default_value_t = SymbolizerKind::Addr2line)]
    pub symbolizer: SymbolizerKind,

    #[arg(long, default_value_t = 997)]
    pub frequency: u32,

    #[arg(long, value_enum, default_value_t = PerfEvent::CpuClock)]
    pub event: PerfEvent,

    #[arg(long, value_enum, default_value_t = PerfCallGraph::Fp)]
    pub call_graph: PerfCallGraph,

    #[arg(long, conflicts_with_all = ["tids", "threads_of_pid"])]
    pub pid: Option<u32>,

    #[arg(long = "tid", value_delimiter = ',', conflicts_with_all = ["pid", "threads_of_pid"])]
    pub tids: Vec<u32>,

    #[arg(long, conflicts_with_all = ["pid", "tids"])]
    pub threads_of_pid: Option<u32>,

    #[arg(long, default_value_t = 3600)]
    pub duration_secs: u32,

    #[arg(last = true, required_unless_present_any = ["pid", "tids", "threads_of_pid"])]
    pub command: Vec<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProfileInvocation {
    pub kind: ProfileKind,
    pub out: Option<PathBuf>,
    pub name: Option<String>,
    pub json: bool,
    pub symbols: bool,
    pub symbolizer: SymbolizerKind,
    pub frequency: u32,
    pub event: PerfEvent,
    pub call_graph: PerfCallGraph,
    pub pid: Option<u32>,
    pub tids: Vec<u32>,
    pub threads_of_pid: Option<u32>,
    pub duration_secs: u32,
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
                symbols: args.symbols,
                symbolizer: args.symbolizer,
                frequency: args.frequency,
                event: args.event,
                call_graph: args.call_graph,
                pid: args.pid,
                tids: args.tids.clone(),
                threads_of_pid: args.threads_of_pid,
                duration_secs: args.duration_secs,
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
            symbols: args.symbols,
            symbolizer: args.symbolizer,
            frequency: args.frequency,
            event: args.event,
            call_graph: args.call_graph,
            pid: args.pid,
            tids: args.tids.clone(),
            threads_of_pid: args.threads_of_pid,
            duration_secs: args.duration_secs,
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

    #[arg(long)]
    pub symbols: bool,

    #[arg(long, value_enum, default_value_t = SymbolizerKind::Addr2line)]
    pub symbolizer: SymbolizerKind,

    #[arg(long, default_value_t = 997)]
    pub frequency: u32,

    #[arg(long, value_enum, default_value_t = PerfEvent::CpuClock)]
    pub event: PerfEvent,

    #[arg(long, value_enum, default_value_t = PerfCallGraph::Fp)]
    pub call_graph: PerfCallGraph,

    #[arg(long, conflicts_with_all = ["tids", "threads_of_pid"])]
    pub pid: Option<u32>,

    #[arg(long = "tid", value_delimiter = ',', conflicts_with_all = ["pid", "threads_of_pid"])]
    pub tids: Vec<u32>,

    #[arg(long, conflicts_with_all = ["pid", "tids"])]
    pub threads_of_pid: Option<u32>,

    #[arg(long, default_value_t = 3600)]
    pub duration_secs: u32,

    #[arg(last = true, required_unless_present_any = ["pid", "tids", "threads_of_pid"])]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct FoldArgs {
    #[arg(long)]
    pub count_periods: bool,

    #[arg(long)]
    pub symbols: bool,

    #[arg(long, value_enum, default_value_t = SymbolizerKind::Addr2line)]
    pub symbolizer: SymbolizerKind,

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

    #[arg(long)]
    pub symbols: bool,

    #[arg(long, value_enum, default_value_t = SymbolizerKind::Addr2line)]
    pub symbolizer: SymbolizerKind,

    #[arg(long, default_value = "CPU profile")]
    pub title: String,
}
