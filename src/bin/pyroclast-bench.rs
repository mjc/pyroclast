use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_INPUT: &str = "target/benchmarks/biggest.perf.data";

fn main() -> ExitCode {
    let input = std::env::args_os()
        .nth(1)
        .map_or_else(|| PathBuf::from(DEFAULT_INPUT), PathBuf::from);

    if !input.is_file() {
        eprintln!(
            "benchmark input not found: {}\nlink or copy a perf.data file there, or pass a path",
            input.display()
        );
        return ExitCode::FAILURE;
    }

    match pyroclast::benchmarks::run_fold_benchmark(&input) {
        Ok(report) => {
            println!("input={}", report.input.display());
            println!("elapsed_ms={}", report.elapsed.as_millis());
            println!("folded_bytes={}", report.folded_bytes);
            println!("folded_lines={}", report.folded_lines);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("benchmark failed: {error}");
            ExitCode::FAILURE
        }
    }
}
