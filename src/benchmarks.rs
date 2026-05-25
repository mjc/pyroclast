use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::perfdata::fold::fold_perfdata_file;

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
