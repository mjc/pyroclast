use std::path::PathBuf;
use std::process::ExitCode;

use pyroclast::process::RealCommandRunner;

const DEFAULT_INPUT: &str = "target/benchmarks/biggest.perf.data";

fn main() -> ExitCode {
    let args = BenchArgs::parse(std::env::args_os().skip(1).map(PathBuf::from).collect());
    let input = args
        .perf_data
        .unwrap_or_else(|| PathBuf::from(DEFAULT_INPUT));

    if !input.is_file() {
        eprintln!(
            "benchmark input not found: {}\nlink or copy a perf.data file there, or pass a path",
            input.display()
        );
        return ExitCode::FAILURE;
    }

    match pyroclast::benchmarks::run_fold_benchmark(&input) {
        Ok(report) => {
            print_report("pyroclast_fold", &report);
            if let Some(perf_script) = args.perf_script {
                if !perf_script.is_file() {
                    eprintln!("perf script input not found: {}", perf_script.display());
                    return ExitCode::FAILURE;
                }
                match pyroclast::benchmarks::run_inferno_collapse_benchmark(
                    &perf_script,
                    &RealCommandRunner,
                ) {
                    Ok(report) => print_report("inferno_collapse_perf", &report),
                    Err(error) => {
                        eprintln!("inferno benchmark failed: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("benchmark failed: {error}");
            ExitCode::FAILURE
        }
    }
}

struct BenchArgs {
    perf_data: Option<PathBuf>,
    perf_script: Option<PathBuf>,
}

impl BenchArgs {
    fn parse(args: Vec<PathBuf>) -> Self {
        let mut perf_data = None;
        let mut perf_script = None;
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            if arg.as_os_str() == "--perf-script" {
                perf_script = iter.next();
            } else {
                perf_data = Some(arg);
            }
        }
        Self {
            perf_data,
            perf_script,
        }
    }
}

fn print_report(name: &str, report: &pyroclast::benchmarks::FoldBenchmarkReport) {
    println!("{name}.input={}", report.input.display());
    println!("{name}.elapsed_ms={}", report.elapsed.as_millis());
    println!("{name}.folded_bytes={}", report.folded_bytes);
    println!("{name}.folded_lines={}", report.folded_lines);
}
