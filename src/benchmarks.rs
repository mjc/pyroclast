use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::flamegraph::build_inferno_flamegraph_command;
use crate::perfdata::fold::{FoldOptions, fold_perfdata_file, fold_perfdata_file_with_symbols};
use crate::process::{CommandRunner, CommandSpec};
use crate::symbols::Addr2lineResolver;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BenchArgs {
    pub perf_data: Option<PathBuf>,
    pub perf_script: Option<PathBuf>,
    pub export_perf_script: Option<PathBuf>,
    pub symbols: bool,
}

impl BenchArgs {
    #[must_use]
    pub fn parse(args: Vec<PathBuf>) -> Self {
        let mut parsed = Self::default();
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            if arg.as_os_str() == "--perf-script" {
                parsed.perf_script = iter.next();
            } else if arg.as_os_str() == "--export-perf-script" {
                parsed.export_perf_script = iter.next();
            } else if arg.as_os_str() == "--symbols" {
                parsed.symbols = true;
            } else {
                parsed.perf_data = Some(arg);
            }
        }
        parsed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FoldBenchmarkReport {
    pub input: PathBuf,
    pub elapsed: Duration,
    pub folded_bytes: usize,
    pub folded_lines: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FoldComparisonReport {
    pub pyroclast_folded_lines: usize,
    pub inferno_folded_lines: usize,
    pub matches: bool,
    pub svg_matches: bool,
    pub pyroclast_svg_bytes: usize,
    pub inferno_svg_bytes: usize,
    pub only_pyroclast: Vec<String>,
    pub only_inferno: Vec<String>,
}

/// Folds a `perf.data` file and returns timing and output-size metadata.
///
/// # Errors
///
/// Returns an error when the input file cannot be mapped or parsed.
pub fn run_fold_benchmark(input: &Path) -> Result<FoldBenchmarkReport, String> {
    run_fold_benchmark_with_folded(input, || fold_perfdata_file(input))
}

/// Folds a `perf.data` file with an optional symbolizing runner and returns
/// timing and output-size metadata.
///
/// # Errors
///
/// Returns an error when the input file cannot be mapped, parsed, or
/// symbolized.
pub fn run_fold_benchmark_with_runner<R>(
    input: &Path,
    runner: &R,
    symbols: bool,
) -> Result<FoldBenchmarkReport, String>
where
    R: CommandRunner,
{
    if symbols {
        let resolver = Addr2lineResolver::new(runner);
        run_fold_benchmark_with_folded(input, || {
            fold_perfdata_file_with_symbols(input, FoldOptions::default(), &resolver)
        })
    } else {
        run_fold_benchmark(input)
    }
}

fn run_fold_benchmark_with_folded<F>(input: &Path, fold: F) -> Result<FoldBenchmarkReport, String>
where
    F: FnOnce() -> Result<String, String>,
{
    let started = Instant::now();
    let folded = fold()?;
    let elapsed = started.elapsed();
    Ok(FoldBenchmarkReport {
        input: input.to_path_buf(),
        elapsed,
        folded_bytes: folded.len(),
        folded_lines: folded.lines().count(),
    })
}

/// Runs `inferno-collapse-perf` over a saved `perf script` text file and
/// returns timing and output-size metadata.
///
/// # Errors
///
/// Returns an error when the collapse command cannot run or exits nonzero.
pub fn run_inferno_collapse_benchmark<R>(
    input: &Path,
    runner: &R,
) -> Result<FoldBenchmarkReport, String>
where
    R: CommandRunner,
{
    let started = Instant::now();
    let output = runner
        .run(&CommandSpec::new("inferno-collapse-perf").arg(input.display().to_string()))
        .map_err(|error| format!("failed to run inferno-collapse-perf: {error}"))?;
    if output.status_code != Some(0) {
        return Err(format!(
            "inferno-collapse-perf exited with {:?}",
            output.status_code
        ));
    }
    let elapsed = started.elapsed();
    let folded = String::from_utf8_lossy(&output.stdout);
    Ok(FoldBenchmarkReport {
        input: input.to_path_buf(),
        elapsed,
        folded_bytes: output.stdout.len(),
        folded_lines: folded.lines().count(),
    })
}

#[must_use]
pub fn format_comparison_report(name: &str, report: &FoldComparisonReport) -> String {
    format!(
        concat!(
            "{name}.matches={matches}\n",
            "{name}.svg_matches={svg_matches}\n",
            "{name}.pyroclast_folded_lines={pyroclast_folded_lines}\n",
            "{name}.inferno_folded_lines={inferno_folded_lines}\n",
            "{name}.pyroclast_svg_bytes={pyroclast_svg_bytes}\n",
            "{name}.inferno_svg_bytes={inferno_svg_bytes}\n",
            "{name}.only_pyroclast={only_pyroclast}\n",
            "{name}.only_inferno={only_inferno}\n",
        ),
        name = name,
        matches = report.matches,
        svg_matches = report.svg_matches,
        pyroclast_folded_lines = report.pyroclast_folded_lines,
        inferno_folded_lines = report.inferno_folded_lines,
        pyroclast_svg_bytes = report.pyroclast_svg_bytes,
        inferno_svg_bytes = report.inferno_svg_bytes,
        only_pyroclast = report.only_pyroclast.len(),
        only_inferno = report.only_inferno.len(),
    )
}

/// Compares Pyroclast's direct folded stacks with the old
/// `perf script | inferno-collapse-perf` folded-stack output.
///
/// # Errors
///
/// Returns an error when Pyroclast cannot fold the `perf.data`, Inferno cannot
/// collapse the saved script, or either folded output is malformed.
pub fn compare_with_inferno_collapse<R>(
    perf_data: &Path,
    perf_script: &Path,
    runner: &R,
) -> Result<FoldComparisonReport, String>
where
    R: CommandRunner,
{
    let pyroclast_folded = fold_perfdata_file(perf_data)?;
    let inferno_output = runner
        .run(&CommandSpec::new("inferno-collapse-perf").arg(perf_script.display().to_string()))
        .map_err(|error| format!("failed to run inferno-collapse-perf: {error}"))?;
    if inferno_output.status_code != Some(0) {
        return Err(format!(
            "inferno-collapse-perf exited with {:?}",
            inferno_output.status_code
        ));
    }
    let inferno_folded = String::from_utf8_lossy(&inferno_output.stdout);
    let pyroclast = parse_folded_counts(&pyroclast_folded)?;
    let inferno = parse_folded_counts(&inferno_folded)?;
    let only_pyroclast = folded_difference(&pyroclast, &inferno);
    let only_inferno = folded_difference(&inferno, &pyroclast);
    let pyroclast_svg = render_inferno_svg("Pyroclast comparison", &pyroclast_folded, runner)?;
    let inferno_svg = render_inferno_svg("Pyroclast comparison", &inferno_folded, runner)?;
    let svg_matches = pyroclast_svg == inferno_svg;

    Ok(FoldComparisonReport {
        pyroclast_folded_lines: pyroclast.len(),
        inferno_folded_lines: inferno.len(),
        matches: only_pyroclast.is_empty() && only_inferno.is_empty() && svg_matches,
        svg_matches,
        pyroclast_svg_bytes: pyroclast_svg.len(),
        inferno_svg_bytes: inferno_svg.len(),
        only_pyroclast,
        only_inferno,
    })
}

/// Exports `perf script` text for old-pipeline benchmarking.
///
/// This is intentionally benchmark-only; Pyroclast's normal fold path parses
/// `perf.data` directly.
///
/// # Errors
///
/// Returns an error when `perf script` cannot run, exits nonzero, or the output
/// file cannot be written.
pub fn export_perf_script<R>(perf_data: &Path, output: &Path, runner: &R) -> Result<(), String>
where
    R: CommandRunner,
{
    let command = CommandSpec::new("perf")
        .args(["script", "-i"])
        .arg(perf_data.display().to_string());
    let command_output = runner
        .run(&command)
        .map_err(|error| format!("failed to run perf script: {error}"))?;
    if command_output.status_code != Some(0) {
        return Err(format!(
            "perf script exited with {:?}",
            command_output.status_code
        ));
    }
    std::fs::write(output, command_output.stdout)
        .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn parse_folded_counts(folded: &str) -> Result<BTreeMap<String, u64>, String> {
    let mut counts = BTreeMap::new();
    for line in folded.lines().filter(|line| !line.trim().is_empty()) {
        let (stack, count) = line
            .rsplit_once(' ')
            .ok_or_else(|| format!("folded stack line is missing count: {line}"))?;
        let count = count
            .parse::<u64>()
            .map_err(|error| format!("folded stack count is invalid: {error}"))?;
        *counts.entry(stack.to_string()).or_insert(0) += count;
    }
    Ok(counts)
}

fn folded_difference(left: &BTreeMap<String, u64>, right: &BTreeMap<String, u64>) -> Vec<String> {
    left.iter()
        .filter(|(stack, count)| right.get(*stack).copied().unwrap_or(0) != **count)
        .map(|(stack, count)| format!("{stack} {count}"))
        .collect()
}

fn render_inferno_svg<R>(title: &str, folded: &str, runner: &R) -> Result<Vec<u8>, String>
where
    R: CommandRunner,
{
    let command = build_inferno_flamegraph_command(title).stdin(folded.as_bytes().to_vec());
    let output = runner
        .run(&command)
        .map_err(|error| format!("failed to run inferno-flamegraph: {error}"))?;
    if output.status_code != Some(0) {
        return Err(format!(
            "inferno-flamegraph exited with {:?}",
            output.status_code
        ));
    }
    Ok(output.stdout)
}
