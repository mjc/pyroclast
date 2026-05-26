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
use backends::heaptrack::HeaptrackBackend;
use backends::linux_perf::LinuxPerfBackend;
use backends::macos_xctrace::MacosXctraceBackend;
use backends::offcpu::OffcpuBackend;
use backends::strace::StraceBackend;
use backends::{ProfileRequest, ProfilerBackend};
use cli::{AnalyzeFlamegraphArgs, AnalyzePerfdataArgs, FlamegraphAnalysisMode};
use cli::{Cli, CliCommand};
use flamegraph::analysis::{
    FlamegraphCategory, FlamegraphDelta, FlamegraphEntry, category_summary, diff_flamegraphs,
    parse_flamegraph_entries, search_entries, syscall_breakdown, top_entries,
};
use flamegraph::{FlamegraphRenderer, FlamegraphRequest, InfernoFlamegraphRenderer};
pub use output::{CliOutput, write_cli_output};
use perfdata::analysis::{PerfdataAnalysis, analyze_perfdata};
use perfdata::fold::{
    FoldOptions, fold_perfdata_file, fold_perfdata_file_with_options,
    fold_perfdata_file_with_symbols,
};
use process::{CommandRunner, RealCommandRunner};
use summary::threads::{render_folded_stack_summary_text, summarize_folded_stacks};
use symbols::{SymbolizerKind, perf_symbol_resolver_for_current_home_with_symbolizer};

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
    run_parsed_cli_with_runner_and_renderer_on_platform(
        cli,
        runner,
        flamegraph_renderer,
        std::env::consts::OS,
    )
}

/// Runs a parsed CLI command with injected dependencies and platform routing.
///
/// # Errors
///
/// Returns an error when command execution, artifact I/O, rendering, or input
/// parsing fails.
pub fn run_parsed_cli_with_runner_and_renderer_on_platform<R, F>(
    cli: Cli,
    runner: &R,
    flamegraph_renderer: F,
    platform: &str,
) -> backends::BackendResult<CliOutput>
where
    R: CommandRunner,
    F: FlamegraphRenderer,
{
    if let Some(invocation) = cli.command.profile_invocation() {
        run_profile_invocation(invocation, runner, flamegraph_renderer, platform)?;
        return Ok(CliOutput::default());
    }

    run_analysis_command(cli.command, runner, &flamegraph_renderer)
}

fn run_profile_invocation<R, F>(
    invocation: cli::ProfileInvocation,
    runner: &R,
    flamegraph_renderer: F,
    platform: &str,
) -> backends::BackendResult<()>
where
    R: CommandRunner,
    F: FlamegraphRenderer,
{
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
        symbolizer: invocation.symbolizer,
        frequency: invocation.frequency,
        event: invocation.event,
        call_graph: invocation.call_graph,
        pid: invocation.pid,
        tids: invocation.tids,
        threads_of_pid: invocation.threads_of_pid,
        duration_secs: invocation.duration_secs,
    };
    match request.kind {
        cli::ProfileKind::Cpu if platform == "linux" => {
            LinuxPerfBackend::with_renderer(runner, flamegraph_renderer).profile(&request)?;
        }
        cli::ProfileKind::Cpu if platform == "macos" => {
            MacosXctraceBackend::new(runner).profile(&request)?;
        }
        cli::ProfileKind::Latency if platform == "linux" => {
            StraceBackend::new(runner).profile(&request)?;
        }
        cli::ProfileKind::Memory if platform == "linux" => {
            HeaptrackBackend::new(runner).profile(&request)?;
        }
        cli::ProfileKind::Offcpu if platform == "linux" => {
            OffcpuBackend::new(runner).profile(&request)?;
        }
        _ => {
            FakeBackend.profile(&request)?;
        }
    }
    Ok(())
}

fn run_analysis_command<R, F>(
    command: CliCommand,
    runner: &R,
    flamegraph_renderer: &F,
) -> backends::BackendResult<CliOutput>
where
    R: CommandRunner,
    F: FlamegraphRenderer,
{
    match command {
        CliCommand::Fold(command) => {
            let options = FoldOptions {
                count_periods: command.count_periods,
            };
            let stdout = fold_perfdata_for_cli(
                &command.input,
                options,
                command.symbols,
                command.symbolizer,
                runner,
            )?;
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
                FoldOptions {
                    count_periods: true,
                },
                command.symbols,
                command.symbolizer,
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
        CliCommand::AnalyzeFlamegraph(command) => {
            let stdout = analyze_flamegraph_for_cli(&command)?;
            Ok(CliOutput {
                stdout,
                stderr: String::new(),
            })
        }
        CliCommand::AnalyzePerfdata(command) => {
            let stdout = analyze_perfdata_for_cli(&command)?;
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

fn analyze_perfdata_for_cli(command: &AnalyzePerfdataArgs) -> backends::BackendResult<String> {
    let bytes = std::fs::read(&command.input)?;
    let analysis = analyze_perfdata(&bytes, command.limit)?;
    render_perfdata_analysis(&analysis, command.json)
}

fn render_perfdata_analysis(
    analysis: &PerfdataAnalysis,
    json: bool,
) -> backends::BackendResult<String> {
    use std::fmt::Write as _;

    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(analysis)?));
    }

    let mut output = String::new();
    writeln!(output, "records: {}", analysis.total_records)?;
    writeln!(output, "samples: {}", analysis.total_samples)?;
    writeln!(output, "weighted samples: {}", analysis.weighted_samples)?;
    writeln!(output, "lost records: {}", analysis.lost_records)?;
    writeln!(output)?;
    writeln!(output, "threads")?;
    for thread in &analysis.threads {
        writeln!(
            output,
            "{:>10} {:>10} {:>7}  {}",
            thread.weighted_samples, thread.samples, thread.tid, thread.comm
        )?;
    }
    writeln!(output)?;
    writeln!(output, "top leaf ips")?;
    for ip in &analysis.top_leaf_ips {
        writeln!(
            output,
            "{:>10} {:>10}  {}",
            ip.weighted_samples, ip.samples, ip.ip
        )?;
    }
    writeln!(output)?;
    writeln!(output, "top edges")?;
    for edge in &analysis.top_edges {
        writeln!(
            output,
            "{:>10} {:>10}  {} -> {}",
            edge.weighted_samples, edge.samples, edge.caller, edge.callee
        )?;
    }
    Ok(output)
}

fn analyze_flamegraph_for_cli(command: &AnalyzeFlamegraphArgs) -> backends::BackendResult<String> {
    let svg = std::fs::read_to_string(&command.input)?;
    let entries = parse_flamegraph_entries(&svg);

    match command.mode {
        FlamegraphAnalysisMode::Top => {
            let entries = top_entries(&entries, command.limit, command.min_percent);
            render_flamegraph_entries(&entries, command.json)
        }
        FlamegraphAnalysisMode::Search => {
            let pattern = command.search.as_deref().unwrap_or_default();
            let entries = search_entries(&entries, pattern);
            render_flamegraph_entries(&entries, command.json)
        }
        FlamegraphAnalysisMode::Syscalls => {
            let entries = syscall_breakdown(&entries);
            render_flamegraph_entries(&entries, command.json)
        }
        FlamegraphAnalysisMode::Summary => {
            let categories = category_summary(&entries);
            render_flamegraph_categories(&categories, command.json)
        }
        FlamegraphAnalysisMode::Diff => {
            let other = command
                .other
                .as_ref()
                .ok_or("--other is required for flamegraph diff mode")?;
            let other_svg = std::fs::read_to_string(other)?;
            let other_entries = parse_flamegraph_entries(&other_svg);
            let deltas = diff_flamegraphs(&entries, &other_entries, command.min_percent);
            render_flamegraph_deltas(&deltas, command.json)
        }
    }
}

fn render_flamegraph_entries(
    entries: &[FlamegraphEntry],
    json: bool,
) -> backends::BackendResult<String> {
    if json {
        Ok(format!("{}\n", serde_json::to_string_pretty(entries)?))
    } else {
        let mut output = String::new();
        for entry in entries {
            use std::fmt::Write as _;
            writeln!(
                output,
                "{:>6.2}% {:>10}  {}",
                entry.percent, entry.samples, entry.name
            )?;
        }
        Ok(output)
    }
}

fn render_flamegraph_categories(
    categories: &[FlamegraphCategory],
    json: bool,
) -> backends::BackendResult<String> {
    if json {
        Ok(format!("{}\n", serde_json::to_string_pretty(categories)?))
    } else {
        let mut output = String::new();
        for category in categories {
            use std::fmt::Write as _;
            writeln!(output, "{:>6.2}%  {}", category.percent, category.name)?;
        }
        Ok(output)
    }
}

fn render_flamegraph_deltas(
    deltas: &[FlamegraphDelta],
    json: bool,
) -> backends::BackendResult<String> {
    if json {
        Ok(format!("{}\n", serde_json::to_string_pretty(deltas)?))
    } else {
        let mut output = String::new();
        for delta in deltas {
            use std::fmt::Write as _;
            writeln!(
                output,
                "{:>7.2}% {:>7.2}% {:+7.2}% {:>10} {:>10}  {}",
                delta.before_percent,
                delta.after_percent,
                delta.delta_percent,
                delta.before_samples,
                delta.after_samples,
                delta.name
            )?;
        }
        Ok(output)
    }
}

fn summarize_artifact_dir(path: &std::path::Path, json: bool) -> backends::BackendResult<String> {
    let layout = ArtifactLayout::new(path.to_path_buf());
    let summary_path = if json {
        layout.summary_json()
    } else {
        layout.summary_txt()
    };
    match std::fs::read_to_string(&summary_path) {
        Ok(summary) => Ok(summary),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            summarize_folded_artifact(&layout, json)
        }
        Err(error) => Err(error.into()),
    }
}

fn summarize_folded_artifact(
    layout: &ArtifactLayout,
    json: bool,
) -> backends::BackendResult<String> {
    let folded_stacks = match std::fs::read_to_string(layout.stacks_folded()) {
        Ok(folded_stacks) => folded_stacks,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fold_perfdata_file(&layout.raw_profile("perf.data"))?
        }
        Err(error) => return Err(error.into()),
    };
    let summary = summarize_folded_stacks(&folded_stacks);
    if json {
        Ok(format!("{}\n", serde_json::to_string_pretty(&summary)?))
    } else {
        Ok(render_folded_stack_summary_text(&summary))
    }
}

fn fold_perfdata_for_cli<R>(
    path: &std::path::Path,
    options: FoldOptions,
    symbols: bool,
    symbolizer: SymbolizerKind,
    runner: &R,
) -> backends::BackendResult<String>
where
    R: CommandRunner,
{
    if symbols {
        let symbol_resolver =
            perf_symbol_resolver_for_current_home_with_symbolizer(runner, path, symbolizer);
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
