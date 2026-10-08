use std::io::Write;

use pyroclast::process::{CancellationScope, CliWriter};

fn main() {
    let cancellation = match CancellationScope::enter() {
        Ok(scope) => scope,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    };
    let exit_code = match run() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            if let Ok(mut stderr) = CliWriter::stderr() {
                let _ = writeln!(stderr, "error: {error}");
            }
            1
        }
    };
    std::process::exit(i32::from(cancellation.exit_code().unwrap_or(exit_code)));
}

fn run() -> pyroclast::backends::BackendResult<u8> {
    pyroclast::run_cli_to_writers(
        std::env::args_os(),
        std::io::BufWriter::new(CliWriter::stdout()?),
        CliWriter::stderr()?,
    )
}
