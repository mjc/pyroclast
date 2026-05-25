use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::perfdata::fold::fold_perfdata_file;
use crate::process::{CommandRunner, CommandSpec};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BenchArgs {
    pub perf_data: Option<PathBuf>,
    pub perf_script: Option<PathBuf>,
}

impl BenchArgs {
    #[must_use]
    pub fn parse(args: Vec<PathBuf>) -> Self {
        let mut parsed = Self::default();
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            if arg.as_os_str() == "--perf-script" {
                parsed.perf_script = iter.next();
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

/// Folds a `perf.data` file and returns timing and output-size metadata.
///
/// # Errors
///
/// Returns an error when the input file cannot be mapped or parsed.
pub fn run_fold_benchmark(input: &Path) -> Result<FoldBenchmarkReport, String> {
    let started = Instant::now();
    let folded = fold_perfdata_file(input)?;
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
