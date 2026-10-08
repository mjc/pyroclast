pub mod artifacts;
pub mod backends;
pub mod benchmarks;
pub mod cargo_cli;
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
use backends::heaptrack::HeaptrackBackend;
use backends::linux_perf::LinuxPerfBackend;
use backends::macos_xctrace::MacosXctraceBackend;
use backends::offcpu::{OffcpuBackend, OffcpuMethod};
use backends::strace::StraceBackend;
use backends::{ProfileRequest, ProfilerBackend};
use clap::Parser;
use cli::{
    AnalyzeFlamegraphArgs, AnalyzePerfdataArgs, Cli, CliCommand, FlamegraphAnalysisMode,
    FlamegraphReportArgs, FlamegraphReportCommand, ParseCommand, ParseFlamegraphCommand,
    ParsePerfCommand, PlumbingCommand,
};
use flamegraph::analysis::{
    FlamegraphCategory, FlamegraphDelta, FlamegraphEntry, FlamegraphProfile, categorize_profile,
    diff_flamegraphs, parse_category_rules, parse_flamegraph, search_entries, top_entries,
};
use flamegraph::{BuiltinFlamegraphRenderer, FlamegraphRenderer, FlamegraphRequest};
pub use output::{CliOutput, write_cli_output};
use perfdata::analysis::{PerfdataAnalysis, analyze_perfdata_file};
use perfdata::fold::{
    FoldOptions, fold_perfdata_file, write_folded_perfdata_file_with_options,
    write_folded_perfdata_file_with_symbols, write_inferno_perf_script_file_with_options,
    write_inferno_perf_script_file_with_symbols,
};
use process::{CancellationScope, CommandRunner, RealCommandRunner};
use summary::threads::{render_folded_stack_summary_text, summarize_folded_stacks};
use symbols::{SymbolizerKind, perf_symbol_resolver_for_current_home_with_symbolizer};

/// Converts Clap help, version, or usage errors into normal CLI output.
#[must_use]
pub fn cli_parse_output(error: &clap::Error) -> CliOutput {
    let text = error.to_string();
    if error.use_stderr() {
        // Clap's documented usage-error status is 2; help and version use 0.
        CliOutput {
            stderr: text,
            exit_code: 2,
            ..CliOutput::default()
        }
    } else {
        CliOutput {
            stdout: text,
            ..CliOutput::default()
        }
    }
}

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
    let _cancellation = CancellationScope::enter()?;
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => return Ok(cli_parse_output(&error)),
    };
    run_parsed_cli(cli)
}

/// Runs the CLI with streaming perf text and folded output.
/// Returns the command's exit code after writing and flushing its output.
///
/// # Errors
///
/// Returns an error when parsing, resolution, or writing fails.
pub fn run_cli_to_writers<I, T>(
    args: I,
    mut stdout: impl std::io::Write,
    mut stderr: impl std::io::Write,
) -> backends::BackendResult<u8>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cancellation = CancellationScope::enter()?;
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let output = cli_parse_output(&error);
            let mut stream = output::PipeWriter::new(&mut stdout);
            let written = write_cli_output(&output, &mut stream, &mut stderr)
                .and_then(|()| std::io::Write::flush(&mut stream))
                .and_then(|()| std::io::Write::flush(&mut stderr));
            if let Some(exit_code) = cancellation.exit_code() {
                return Ok(exit_code);
            }
            if !stream.broken_pipe() {
                written?;
            }
            return Ok(output.exit_code);
        }
    };
    let runner = RealCommandRunner::default();
    let json_profile = cli
        .command
        .profile_invocation()
        .is_some_and(|invocation| invocation.json);
    let mut stream = output::PipeWriter::new(&mut stdout);
    let result = match cli.command {
        CliCommand::Plumbing {
            command: PlumbingCommand::Fold(command),
        } => write_perfdata_for_cli(
            &command.input,
            FoldOptions {
                count_periods: command.count_periods,
                inline: command.inline_frames.enabled(),
            },
            command.symbols,
            command.symbolizer,
            &runner,
            PerfdataOutput::Folded,
            &mut stream,
        )
        .map(|()| 0),
        CliCommand::Plumbing {
            command: PlumbingCommand::PerfScript(command),
        } => write_perfdata_for_cli(
            &command.input,
            FoldOptions {
                count_periods: true,
                inline: command.inline_frames.enabled(),
            },
            command.symbols,
            command.symbolizer,
            &runner,
            PerfdataOutput::PerfScript,
            &mut stream,
        )
        .map(|()| 0),
        command => match run_parsed_cli(Cli { command }) {
            Ok(output) => write_cli_output(&output, &mut stream, &mut stderr)
                .map(|()| output.exit_code)
                .map_err(Into::into),
            Err(error) => {
                if json_profile {
                    serde_json::to_writer(
                        &mut stream,
                        &serde_json::json!({
                            "status": "failed", "error": error.to_string(),
                        }),
                    )?;
                    std::io::Write::write_all(&mut stream, b"\n")?;
                }
                Err(error)
            }
        },
    };
    if stream.broken_pipe() {
        return Ok(cancellation.exit_code().unwrap_or(result.unwrap_or(0)));
    }
    // Flush even on a parse error: samples already delivered are valid text.
    let flushed = std::io::Write::flush(&mut stream);
    if stream.broken_pipe() {
        return Ok(cancellation.exit_code().unwrap_or(result.unwrap_or(0)));
    }
    flushed?;
    if let Some(exit_code) = cancellation.exit_code() {
        return Ok(exit_code);
    }
    result
}

/// Parses cargo-subcommand arguments and runs the requested Pyroclast profile.
///
/// # Errors
///
/// Returns an error when cargo target resolution, command execution, artifact
/// I/O, or input parsing fails.
pub fn run_cargo_cli<I, T>(args: I) -> backends::BackendResult<CliOutput>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let _cancellation = CancellationScope::enter()?;
    let cli = match cargo_cli::CargoCli::try_parse_from(cargo_cli::normalize_cargo_args(args)) {
        Ok(cli) => cli,
        Err(error) => return Ok(cli_parse_output(&error)),
    };
    run_parsed_cargo_cli(cli)
}

/// Runs a parsed CLI command with the real process runner.
///
/// # Errors
///
/// Returns an error when command execution, artifact I/O, or input parsing
/// fails.
pub fn run_parsed_cli(cli: Cli) -> backends::BackendResult<CliOutput> {
    let cancellation = CancellationScope::enter()?;
    let runner = RealCommandRunner::default();
    let mut output = run_parsed_cli_with_runner(cli, &runner)?;
    output.exit_code = cancellation.exit_code().unwrap_or(output.exit_code);
    Ok(output)
}

/// Runs a parsed cargo-subcommand command with the real process runner.
///
/// # Errors
///
/// Returns an error when cargo target resolution, command execution, artifact
/// I/O, or input parsing fails.
pub fn run_parsed_cargo_cli(cli: cargo_cli::CargoCli) -> backends::BackendResult<CliOutput> {
    let cancellation = CancellationScope::enter()?;
    let runner = RealCommandRunner::default();
    let mut output = run_parsed_cargo_cli_with_runner(cli, &runner)?;
    output.exit_code = cancellation.exit_code().unwrap_or(output.exit_code);
    Ok(output)
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
    run_parsed_cli_with_runner_and_renderer(cli, runner, BuiltinFlamegraphRenderer)
}

/// Runs a parsed CLI command with an injected process runner and explicit
/// platform routing.
///
/// # Errors
///
/// Returns an error when command execution, artifact I/O, or input parsing
/// fails.
pub fn run_parsed_cli_with_runner_on_platform<R>(
    cli: Cli,
    runner: &R,
    platform: &str,
) -> backends::BackendResult<CliOutput>
where
    R: CommandRunner,
{
    run_parsed_cli_with_runner_and_renderer_on_platform(
        cli,
        runner,
        BuiltinFlamegraphRenderer,
        platform,
    )
}

/// Runs a parsed cargo-subcommand command with an injected process runner and
/// explicit platform routing.
///
/// # Errors
///
/// Returns an error when cargo target resolution, command execution, artifact
/// I/O, or input parsing fails.
pub fn run_parsed_cargo_cli_with_runner_on_platform<R>(
    cli: cargo_cli::CargoCli,
    runner: &R,
    platform: &str,
) -> backends::BackendResult<CliOutput>
where
    R: CommandRunner,
{
    run_parsed_cargo_cli_with_runner_and_renderer_on_platform(
        cli,
        runner,
        BuiltinFlamegraphRenderer,
        platform,
    )
}

/// Runs a parsed cargo-subcommand command with an injected process runner.
///
/// # Errors
///
/// Returns an error when cargo target resolution, command execution, artifact
/// I/O, or input parsing fails.
pub fn run_parsed_cargo_cli_with_runner<R>(
    cli: cargo_cli::CargoCli,
    runner: &R,
) -> backends::BackendResult<CliOutput>
where
    R: CommandRunner,
{
    run_parsed_cargo_cli_with_runner_and_renderer(cli, runner, BuiltinFlamegraphRenderer)
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

/// Runs a parsed cargo-subcommand command with injected process and flamegraph
/// renderers.
///
/// # Errors
///
/// Returns an error when cargo target resolution, command execution, artifact
/// I/O, rendering, or input parsing fails.
pub fn run_parsed_cargo_cli_with_runner_and_renderer<R, F>(
    cli: cargo_cli::CargoCli,
    runner: &R,
    flamegraph_renderer: F,
) -> backends::BackendResult<CliOutput>
where
    R: CommandRunner,
    F: FlamegraphRenderer,
{
    run_parsed_cargo_cli_with_runner_and_renderer_on_platform(
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
        return run_profile_invocation(invocation, runner, flamegraph_renderer, platform);
    }

    run_non_profile_command(cli.command, runner, &flamegraph_renderer)
}

/// Runs a parsed cargo-subcommand command with injected dependencies and
/// platform routing.
///
/// # Errors
///
/// Returns an error when cargo target resolution, command execution, artifact
/// I/O, rendering, or input parsing fails.
pub fn run_parsed_cargo_cli_with_runner_and_renderer_on_platform<R, F>(
    cli: cargo_cli::CargoCli,
    runner: &R,
    flamegraph_renderer: F,
    platform: &str,
) -> backends::BackendResult<CliOutput>
where
    R: CommandRunner,
    F: FlamegraphRenderer,
{
    let invocation = cli
        .command
        .pyroclast_command()
        .into_profile_invocation(runner)?;
    run_profile_invocation(invocation, runner, flamegraph_renderer, platform)
}

pub(crate) fn run_profile_invocation<R, F>(
    invocation: cli::ProfileInvocation,
    runner: &R,
    flamegraph_renderer: F,
    platform: &str,
) -> backends::BackendResult<CliOutput>
where
    R: CommandRunner,
    F: FlamegraphRenderer,
{
    let out_dir = invocation
        .out
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("pyroclast-runs/latest"));
    ArtifactLayout::new(out_dir.clone()).prepare()?;
    let attaching = invocation.pid.is_some()
        || !invocation.tids.is_empty()
        || invocation.threads_of_pid.is_some();
    if attaching && !(invocation.kind == cli::ProfileKind::Cpu && platform == "linux") {
        return Err(format!(
            "{} profiling does not support attach targets on {platform}",
            profile_kind_name(invocation.kind)
        )
        .into());
    }
    if invocation.offcpu_method.is_some()
        && !matches!(
            invocation.kind,
            cli::ProfileKind::Offcpu | cli::ProfileKind::Async
        )
    {
        return Err("--offcpu-method is only available for offcpu and async profiles".into());
    }
    let offcpu_method = if matches!(
        invocation.kind,
        cli::ProfileKind::Offcpu | cli::ProfileKind::Async
    ) && platform == "linux"
    {
        Some(match invocation.offcpu_method {
            Some(cli::OffcpuChoice::PerfSched) => OffcpuMethod::PerfSched,
            Some(cli::OffcpuChoice::Bpftrace) => OffcpuMethod::Bpftrace,
            None => match probe_perf_sched(runner) {
                Ok(()) => OffcpuMethod::PerfSched,
                Err(perf_error) => {
                    probe_bpftrace_offcpu(runner).map_err(|bpf_error| format!("blocked-time profiling needs a usable native recorder: perf: {perf_error}; bpftrace: {bpf_error}"))?;
                    OffcpuMethod::Bpftrace
                }
            },
        })
    } else {
        None
    };
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
        offcpu_method,
    };
    let result = match request.kind {
        cli::ProfileKind::Cpu if platform == "linux" => {
            LinuxPerfBackend::with_renderer(runner, flamegraph_renderer).profile(&request)?
        }
        cli::ProfileKind::Cpu if platform == "macos" => {
            MacosXctraceBackend::new(runner).profile(&request)?
        }
        cli::ProfileKind::Latency if platform == "linux" => {
            StraceBackend::new(runner).profile(&request)?
        }
        cli::ProfileKind::Memory if platform == "linux" => {
            HeaptrackBackend::new(runner).profile(&request)?
        }
        cli::ProfileKind::Offcpu | cli::ProfileKind::Async if platform == "linux" => {
            OffcpuBackend::new(runner).profile(&request)?
        }
        kind => {
            return Err(format!(
                "{} profiling is not supported on {platform}",
                profile_kind_name(kind)
            )
            .into());
        }
    };
    let exit_code = result.completion.exit_code()?;
    Ok(CliOutput {
        stdout: if request.json {
            format!("{}\n", serde_json::to_string_pretty(&result.manifest)?)
        } else {
            String::new()
        },
        stderr: String::new(),
        exit_code,
    })
}

fn probe_perf_sched(runner: &impl CommandRunner) -> Result<(), String> {
    runner
        .resolve_tool(&tools::PERF)
        .map_err(|error| error.to_string())?;
    let temporary = tempfile::tempdir().map_err(|error| error.to_string())?;
    let command = process::CommandSpec::new("perf").args([
        "sched".to_string(),
        "record".to_string(),
        "-o".to_string(),
        temporary
            .path()
            .join("probe.perf.data")
            .display()
            .to_string(),
        "--".to_string(),
        "sh".to_string(),
        "-c".to_string(),
        ":".to_string(),
    ]);
    check_recorder_probe(runner, &command)
}

fn probe_bpftrace_offcpu(runner: &impl CommandRunner) -> Result<(), String> {
    runner
        .resolve_tool(&tools::BPFTRACE)
        .map_err(|error| error.to_string())?;
    // Attach the actual required tracepoint and compile the stack helper before
    // starting the requested workload. A BEGIN-only probe misses these checks.
    let command = process::CommandSpec::new("bpftrace").args([
        "-e",
        "tracepoint:sched:sched_switch { @probe[kstack(perf)] = count(); } interval:ms:1 { exit(); } END { clear(@probe); }",
    ]);
    check_recorder_probe(runner, &command)
}

fn check_recorder_probe(
    runner: &impl CommandRunner,
    command: &process::CommandSpec,
) -> Result<(), String> {
    let output = runner.run(command).map_err(|error| error.to_string())?;
    if output.status_code == Some(0) {
        Ok(())
    } else {
        Err(format!(
            "capability probe exited with {:?}: {}",
            output.status_code,
            String::from_utf8_lossy(&output.stderr).trim(),
        ))
    }
}

fn profile_kind_name(kind: cli::ProfileKind) -> &'static str {
    match kind {
        cli::ProfileKind::Cpu => "cpu",
        cli::ProfileKind::Memory => "memory",
        cli::ProfileKind::Offcpu => "off-cpu",
        cli::ProfileKind::Latency => "latency",
        cli::ProfileKind::Async => "async",
    }
}

fn run_non_profile_command<R, F>(
    command: CliCommand,
    runner: &R,
    flamegraph_renderer: &F,
) -> backends::BackendResult<CliOutput>
where
    R: CommandRunner,
    F: FlamegraphRenderer,
{
    match command {
        CliCommand::Plumbing { command } => {
            run_plumbing_command(command, runner, flamegraph_renderer)
        }
        CliCommand::Analyze(command) => Ok(CliOutput {
            stdout: analyze_svg_report_for_cli(&command)?,
            stderr: String::new(),
            exit_code: 0,
        }),
        CliCommand::Memory(_)
        | CliCommand::Cpu(_)
        | CliCommand::Offcpu(_)
        | CliCommand::Latency(_)
        | CliCommand::Async(_)
        | CliCommand::Profile(_) => unreachable!("profile invocations returned earlier"),
    }
}

fn run_plumbing_command<R, F>(
    command: PlumbingCommand,
    runner: &R,
    flamegraph_renderer: &F,
) -> backends::BackendResult<CliOutput>
where
    R: CommandRunner,
    F: FlamegraphRenderer,
{
    match command {
        PlumbingCommand::Fold(command) => {
            let options = FoldOptions {
                count_periods: command.count_periods,
                inline: command.inline_frames.enabled(),
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
                exit_code: 0,
            })
        }
        PlumbingCommand::PerfScript(command) => {
            let stdout = perf_script_for_cli(
                &command.input,
                command.symbols,
                command.inline_frames.enabled(),
                command.symbolizer,
                runner,
            )?;
            Ok(CliOutput {
                stdout,
                stderr: String::new(),
                exit_code: 0,
            })
        }
        PlumbingCommand::Flamegraph(command) => {
            let inline = command.inline_frames.enabled();
            let output = command
                .output
                .unwrap_or_else(|| std::path::PathBuf::from("flamegraph.svg"));
            let folded_stacks = fold_perfdata_for_cli(
                &command.input,
                FoldOptions {
                    count_periods: true,
                    inline,
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
                exit_code: 0,
            })
        }
        PlumbingCommand::Summarize(command) => {
            let stdout = summarize_artifact_dir(&command.artifact_dir, command.json)?;
            Ok(CliOutput {
                stdout,
                stderr: String::new(),
                exit_code: 0,
            })
        }
        PlumbingCommand::Parse { command } => run_parse_command(command),
    }
}

fn run_parse_command(command: ParseCommand) -> backends::BackendResult<CliOutput> {
    match command {
        ParseCommand::Perf { command } => run_parse_perf_command(command),
        ParseCommand::Flamegraph { command } => run_parse_flamegraph_command(command),
    }
}

fn run_parse_perf_command(command: ParsePerfCommand) -> backends::BackendResult<CliOutput> {
    match command {
        ParsePerfCommand::Summary(command) => {
            let stdout = analyze_perfdata_for_cli(&command.analyze_args())?;
            Ok(CliOutput {
                stdout,
                stderr: String::new(),
                exit_code: 0,
            })
        }
    }
}

fn run_parse_flamegraph_command(
    command: ParseFlamegraphCommand,
) -> backends::BackendResult<CliOutput> {
    let stdout = match command {
        ParseFlamegraphCommand::Top(command) => {
            analyze_flamegraph_for_cli(&command.analyze_args())?
        }
        ParseFlamegraphCommand::Search(command) => {
            analyze_flamegraph_for_cli(&command.analyze_args())?
        }
        ParseFlamegraphCommand::Syscalls(command) => {
            analyze_flamegraph_for_cli(&command.analyze_args())?
        }
        ParseFlamegraphCommand::Summary(command) => {
            analyze_flamegraph_for_cli(&command.analyze_args())?
        }
        ParseFlamegraphCommand::Diff(command) => {
            analyze_flamegraph_for_cli(&command.analyze_args())?
        }
    };
    Ok(CliOutput {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    })
}

fn analyze_perfdata_for_cli(command: &AnalyzePerfdataArgs) -> backends::BackendResult<String> {
    let analysis = analyze_perfdata_file(&command.input, command.limit)?;
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
    if let Some(duration) = analysis.profile.timeline.duration_ns {
        writeln!(output, "sample span (ns): {duration}")?;
    }
    writeln!(
        output,
        "untimed samples: {}",
        analysis.profile.timeline.untimed_samples
    )?;
    writeln!(output, "timeline (1 second buckets)")?;
    for bucket in &analysis.profile.timeline.buckets {
        writeln!(
            output,
            "{} ns: {} samples, {} weight",
            bucket.start_offset_ns, bucket.samples, bucket.weighted_samples
        )?;
    }
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

fn analyze_svg_report_for_cli(command: &FlamegraphReportArgs) -> backends::BackendResult<String> {
    let svg = std::fs::read_to_string(&command.input)?;
    let mut profile = parse_flamegraph(&svg)?;
    let min_percent = command.min_percent.unwrap_or(match command.mode {
        Some(FlamegraphReportCommand::Search { .. }) => 0.0,
        Some(FlamegraphReportCommand::Diff { .. }) => 0.01,
        _ => 1.0,
    });
    let rules = command
        .categories
        .as_ref()
        .map(|path| {
            let json = std::fs::read_to_string(path)?;
            parse_category_rules(&json)
        })
        .transpose()?
        .unwrap_or_default();
    if matches!(command.mode, None | Some(FlamegraphReportCommand::Summary)) {
        categorize_profile(&mut profile, &rules, command.limit, min_percent);
    }
    if let Some(mode) = &command.mode {
        let entries = if mode.uses_self_samples() {
            &profile.self_samples
        } else {
            &profile.inclusive
        };
        return match mode {
            FlamegraphReportCommand::Top { .. } => render_flamegraph_entries(
                &top_entries(entries, command.limit, min_percent),
                command.json,
            ),
            FlamegraphReportCommand::Search { pattern, .. } => {
                let found = search_entries(entries, pattern);
                render_flamegraph_entries(
                    &top_entries(&found, command.limit, min_percent),
                    command.json,
                )
            }
            FlamegraphReportCommand::Syscalls => render_flamegraph_entries(
                &top_entries(&profile.syscalls, command.limit, min_percent),
                command.json,
            ),
            FlamegraphReportCommand::Summary => {
                render_flamegraph_categories(&profile.categories, command.json)
            }
            FlamegraphReportCommand::Diff { other, .. } => {
                let other_svg = std::fs::read_to_string(other)?;
                let other_profile = parse_flamegraph(&other_svg)?;
                let other_entries = if mode.uses_self_samples() {
                    &other_profile.self_samples
                } else {
                    &other_profile.inclusive
                };
                let mut deltas = diff_flamegraphs(entries, other_entries, min_percent);
                deltas.truncate(command.limit);
                render_flamegraph_deltas(&deltas, command.json)
            }
        };
    }
    profile.inclusive = top_entries(&profile.inclusive, command.limit, min_percent);
    profile.self_samples = top_entries(&profile.self_samples, command.limit, min_percent);
    profile.syscalls = top_entries(&profile.syscalls, command.limit, min_percent);
    render_svg_report(&profile, command.json)
}

fn render_svg_report(profile: &FlamegraphProfile, json: bool) -> backends::BackendResult<String> {
    use std::fmt::Write as _;
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(&profile)?));
    }
    let mut output = format!("{} sample units\n", profile.total_samples);
    for (heading, entries) in [
        ("Inclusive coverage (rows overlap)", &profile.inclusive),
        (
            "Self coverage (deepest visible frame)",
            &profile.self_samples,
        ),
    ] {
        writeln!(output, "\n{heading}")?;
        output.push_str(&render_flamegraph_entries(entries, false)?);
    }
    writeln!(output, "\nExclusive categories (all samples)")?;
    output.push_str(&render_flamegraph_categories(&profile.categories, false)?);
    if profile.any_syscall_samples > 0 {
        writeln!(output, "\nSyscall coverage (rows may overlap)")?;
        output.push_str(&render_flamegraph_entries(&profile.syscalls, false)?);
        writeln!(
            output,
            "Any syscall: {} sample units",
            profile.any_syscall_samples
        )?;
    }
    Ok(output)
}

fn analyze_flamegraph_for_cli(command: &AnalyzeFlamegraphArgs) -> backends::BackendResult<String> {
    let mode = match command.mode {
        FlamegraphAnalysisMode::Top => FlamegraphReportCommand::Top {
            self_samples: false,
        },
        FlamegraphAnalysisMode::Search => FlamegraphReportCommand::Search {
            pattern: command.search.clone().unwrap_or_default(),
            self_samples: false,
        },
        FlamegraphAnalysisMode::Syscalls => FlamegraphReportCommand::Syscalls,
        FlamegraphAnalysisMode::Summary => FlamegraphReportCommand::Summary,
        FlamegraphAnalysisMode::Diff => FlamegraphReportCommand::Diff {
            other: command
                .other
                .clone()
                .ok_or("other SVG is required for flamegraph diff")?,
            self_samples: false,
        },
    };
    let unbounded = matches!(
        command.mode,
        FlamegraphAnalysisMode::Search
            | FlamegraphAnalysisMode::Syscalls
            | FlamegraphAnalysisMode::Diff
    );
    analyze_svg_report_for_cli(&FlamegraphReportArgs {
        input: command.input.clone(),
        json: command.json,
        limit: if unbounded { usize::MAX } else { command.limit },
        min_percent: Some(
            if matches!(
                command.mode,
                FlamegraphAnalysisMode::Search | FlamegraphAnalysisMode::Syscalls
            ) {
                0.0
            } else {
                command.min_percent
            },
        ),
        mode: Some(mode),
        categories: None,
    })
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
            for entry in &category.inclusive_functions {
                writeln!(
                    output,
                    "    {:>6.2}% inclusive {:>10}  {}",
                    entry.percent, entry.samples, entry.name
                )?;
            }
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
    let mut output = Vec::new();
    write_perfdata_for_cli(
        path,
        options,
        symbols,
        symbolizer,
        runner,
        PerfdataOutput::Folded,
        &mut output,
    )?;
    Ok(String::from_utf8(output)?)
}

fn perf_script_for_cli<R>(
    path: &std::path::Path,
    symbols: bool,
    inline: bool,
    symbolizer: SymbolizerKind,
    runner: &R,
) -> backends::BackendResult<String>
where
    R: CommandRunner,
{
    let options = FoldOptions {
        count_periods: true,
        inline,
    };
    let mut output = Vec::new();
    write_perfdata_for_cli(
        path,
        options,
        symbols,
        symbolizer,
        runner,
        PerfdataOutput::PerfScript,
        &mut output,
    )?;
    Ok(String::from_utf8(output)?)
}

#[derive(Clone, Copy)]
enum PerfdataOutput {
    Folded,
    PerfScript,
}

fn write_perfdata_for_cli<R: CommandRunner>(
    path: &std::path::Path,
    options: FoldOptions,
    symbols: bool,
    symbolizer: SymbolizerKind,
    runner: &R,
    format: PerfdataOutput,
    writer: &mut impl std::io::Write,
) -> backends::BackendResult<()> {
    if symbols {
        let resolver =
            perf_symbol_resolver_for_current_home_with_symbolizer(runner, path, symbolizer);
        match format {
            PerfdataOutput::Folded => {
                write_folded_perfdata_file_with_symbols(path, options, &resolver, writer)?;
            }
            PerfdataOutput::PerfScript => {
                write_inferno_perf_script_file_with_symbols(path, options, &resolver, writer)?;
            }
        }
    } else {
        match format {
            PerfdataOutput::Folded => {
                write_folded_perfdata_file_with_options(path, options, writer)?;
            }
            PerfdataOutput::PerfScript => {
                write_inferno_perf_script_file_with_options(path, options, writer)?;
            }
        }
    }
    Ok(())
}
