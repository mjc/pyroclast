use std::path::PathBuf;
use std::process::ExitCode;

use pyroclast::benchmarks::BenchArgs;
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

    match pyroclast::benchmarks::run_fold_benchmark_with_runner(
        &input,
        &RealCommandRunner,
        args.symbols,
    ) {
        Ok(report) => {
            print_report("pyroclast_fold", &report);
            let perf_script = match args.export_perf_script {
                Some(path) => {
                    if let Err(error) =
                        pyroclast::benchmarks::export_perf_script(&input, &path, &RealCommandRunner)
                    {
                        eprintln!("perf script export failed: {error}");
                        return ExitCode::FAILURE;
                    }
                    Some(path)
                }
                None => args.perf_script,
            };
            if let Some(perf_script) = perf_script {
                if !perf_script.is_file() {
                    eprintln!("perf script input not found: {}", perf_script.display());
                    return ExitCode::FAILURE;
                }
                match pyroclast::benchmarks::run_inferno_collapse_benchmark(
                    &perf_script,
                    &RealCommandRunner,
                ) {
                    Ok(report) => {
                        print_report("inferno_collapse_perf", &report);
                        match pyroclast::benchmarks::compare_with_inferno_collapse_with_symbols(
                            &input,
                            &perf_script,
                            &RealCommandRunner,
                            args.symbols,
                        ) {
                            Ok(report) => print!(
                                "{}",
                                pyroclast::benchmarks::format_comparison_report(
                                    "inferno_compare",
                                    &report
                                )
                            ),
                            Err(error) => {
                                eprintln!("inferno comparison failed: {error}");
                                return ExitCode::FAILURE;
                            }
                        }
                    }
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

fn print_report(name: &str, report: &pyroclast::benchmarks::FoldBenchmarkReport) {
    println!("{name}.input={}", report.input.display());
    println!("{name}.elapsed_ms={}", report.elapsed.as_millis());
    println!("{name}.folded_bytes={}", report.folded_bytes);
    println!("{name}.folded_lines={}", report.folded_lines);
}
