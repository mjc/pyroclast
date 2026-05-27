use std::path::PathBuf;
use std::process::ExitCode;

use pyroclast::benchmarks::{BenchArgs, run_bench_command};
use pyroclast::process::RealCommandRunner;

fn main() -> ExitCode {
    let args = BenchArgs::parse(std::env::args_os().skip(1).map(PathBuf::from).collect());
    let runner = RealCommandRunner::default();

    match run_bench_command(&args, &runner) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
