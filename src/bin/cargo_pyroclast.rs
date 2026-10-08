use clap::Parser;
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
    let mut stdout = CliWriter::stdout()?;
    let mut stderr = CliWriter::stderr()?;
    let cli = match pyroclast::cargo_cli::CargoCli::try_parse_from(
        pyroclast::cargo_cli::normalize_cargo_args(std::env::args_os()),
    ) {
        Ok(cli) => cli,
        Err(error) => {
            let output = pyroclast::cli_parse_output(&error);
            pyroclast::write_cli_output(&output, &mut stdout, &mut stderr)?;
            stdout.flush()?;
            stderr.flush()?;
            return Ok(output.exit_code);
        }
    };
    let json = cli.command.json();
    match pyroclast::run_parsed_cargo_cli(cli) {
        Ok(output) => {
            pyroclast::write_cli_output(&output, &mut stdout, &mut stderr)?;
            stdout.flush()?;
            stderr.flush()?;
            Ok(output.exit_code)
        }
        Err(error) => {
            if json {
                let _ = serde_json::to_writer(
                    &mut stdout,
                    &serde_json::json!({"status": "failed", "error": error.to_string()}),
                );
                let _ = stdout.write_all(b"\n");
            }
            Err(error)
        }
    }
}
