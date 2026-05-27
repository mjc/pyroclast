use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;

pub use crate::symbols::SymbolizerKind;

#[derive(Debug, Parser)]
#[command(name = "pyroclast")]
#[command(
    about = "Rust-first profiling orchestration with separate porcelain and plumbing surfaces"
)]
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
    Offcpu(RunArgs),
    #[command(alias = "syscalls")]
    Latency(RunArgs),
    Async(RunArgs),
    Profile(ProfileArgs),
    Plumbing {
        #[command(subcommand)]
        command: PlumbingCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum PlumbingCommand {
    Fold(FoldArgs),
    Flamegraph(FlamegraphArgs),
    Summarize(SummarizeArgs),
    Parse {
        #[command(subcommand)]
        command: ParseCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum ParseCommand {
    Perf {
        #[command(subcommand)]
        command: ParsePerfCommand,
    },
    Flamegraph {
        #[command(subcommand)]
        command: ParseFlamegraphCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum ParsePerfCommand {
    Summary(ParsePerfSummaryArgs),
}

#[derive(Debug, Subcommand)]
pub enum ParseFlamegraphCommand {
    Top(ParseFlamegraphTopArgs),
    Search(ParseFlamegraphSearchArgs),
    Syscalls(ParseFlamegraphSyscallsArgs),
    Summary(ParseFlamegraphSummaryArgs),
    Diff(ParseFlamegraphDiffArgs),
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
    Default,
    CpuClock,
    TaskClock,
    Cycles,
}

impl std::fmt::Display for PerfEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => formatter.write_str("default"),
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
            Self::Dwarf => formatter.write_str("dwarf,64000"),
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

    #[arg(long, value_enum, default_value_t = SymbolizerKind::RustAddr2line)]
    pub symbolizer: SymbolizerKind,

    #[arg(long, default_value_t = 997)]
    pub frequency: u32,

    #[arg(long, value_enum, default_value_t = PerfEvent::Default)]
    pub event: PerfEvent,

    #[arg(long, value_enum, default_value_t = PerfCallGraph::Dwarf)]
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
            Self::Offcpu(args) => Some(ProfileInvocation::from_run(ProfileKind::Offcpu, args)),
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
            Self::Plumbing { .. } => None,
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

    #[arg(long, value_enum, default_value_t = SymbolizerKind::RustAddr2line)]
    pub symbolizer: SymbolizerKind,

    #[arg(long, default_value_t = 997)]
    pub frequency: u32,

    #[arg(long, value_enum, default_value_t = PerfEvent::Default)]
    pub event: PerfEvent,

    #[arg(long, value_enum, default_value_t = PerfCallGraph::Dwarf)]
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

    #[arg(long, value_enum, default_value_t = SymbolizerKind::RustAddr2line)]
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

    #[arg(long, value_enum, default_value_t = SymbolizerKind::RustAddr2line)]
    pub symbolizer: SymbolizerKind,

    #[arg(long, default_value = "CPU profile")]
    pub title: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlamegraphAnalysisMode {
    Top,
    Search,
    Syscalls,
    Summary,
    Diff,
}

#[derive(Debug)]
pub struct AnalyzeFlamegraphArgs {
    pub json: bool,
    pub mode: FlamegraphAnalysisMode,
    pub limit: usize,
    pub min_percent: f64,
    pub search: Option<String>,
    pub other: Option<PathBuf>,
    pub input: PathBuf,
}

#[derive(Debug)]
pub struct AnalyzePerfdataArgs {
    pub json: bool,
    pub limit: usize,
    pub input: PathBuf,
}

#[derive(Debug, Args)]
pub struct ParsePerfSummaryArgs {
    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value_t = 30)]
    pub limit: usize,

    pub input: PathBuf,
}

impl ParsePerfSummaryArgs {
    #[must_use]
    pub fn analyze_args(&self) -> AnalyzePerfdataArgs {
        AnalyzePerfdataArgs {
            json: self.json,
            limit: self.limit,
            input: self.input.clone(),
        }
    }
}

#[derive(Debug, Args)]
pub struct ParseFlamegraphTopArgs {
    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value_t = 30)]
    pub limit: usize,

    #[arg(long, default_value_t = 1.0)]
    pub min_percent: f64,

    pub input: PathBuf,
}

impl ParseFlamegraphTopArgs {
    #[must_use]
    pub fn analyze_args(&self) -> AnalyzeFlamegraphArgs {
        AnalyzeFlamegraphArgs {
            json: self.json,
            mode: FlamegraphAnalysisMode::Top,
            limit: self.limit,
            min_percent: self.min_percent,
            search: None,
            other: None,
            input: self.input.clone(),
        }
    }
}

#[derive(Debug, Args)]
pub struct ParseFlamegraphSearchArgs {
    #[arg(long)]
    pub json: bool,

    pub input: PathBuf,
    pub pattern: String,
}

impl ParseFlamegraphSearchArgs {
    #[must_use]
    pub fn analyze_args(&self) -> AnalyzeFlamegraphArgs {
        AnalyzeFlamegraphArgs {
            json: self.json,
            mode: FlamegraphAnalysisMode::Search,
            limit: 30,
            min_percent: 1.0,
            search: Some(self.pattern.clone()),
            other: None,
            input: self.input.clone(),
        }
    }
}

#[derive(Debug, Args)]
pub struct ParseFlamegraphSyscallsArgs {
    #[arg(long)]
    pub json: bool,

    pub input: PathBuf,
}

impl ParseFlamegraphSyscallsArgs {
    #[must_use]
    pub fn analyze_args(&self) -> AnalyzeFlamegraphArgs {
        AnalyzeFlamegraphArgs {
            json: self.json,
            mode: FlamegraphAnalysisMode::Syscalls,
            limit: 30,
            min_percent: 1.0,
            search: None,
            other: None,
            input: self.input.clone(),
        }
    }
}

#[derive(Debug, Args)]
pub struct ParseFlamegraphSummaryArgs {
    #[arg(long)]
    pub json: bool,

    pub input: PathBuf,
}

impl ParseFlamegraphSummaryArgs {
    #[must_use]
    pub fn analyze_args(&self) -> AnalyzeFlamegraphArgs {
        AnalyzeFlamegraphArgs {
            json: self.json,
            mode: FlamegraphAnalysisMode::Summary,
            limit: 30,
            min_percent: 1.0,
            search: None,
            other: None,
            input: self.input.clone(),
        }
    }
}

#[derive(Debug, Args)]
pub struct ParseFlamegraphDiffArgs {
    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value_t = 1.0)]
    pub min_percent: f64,

    pub before: PathBuf,
    pub after: PathBuf,
}

impl ParseFlamegraphDiffArgs {
    #[must_use]
    pub fn analyze_args(&self) -> AnalyzeFlamegraphArgs {
        AnalyzeFlamegraphArgs {
            json: self.json,
            mode: FlamegraphAnalysisMode::Diff,
            limit: 30,
            min_percent: self.min_percent,
            search: None,
            other: Some(self.after.clone()),
            input: self.before.clone(),
        }
    }
}
