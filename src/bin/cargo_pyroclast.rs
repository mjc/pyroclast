use clap::Parser;

fn main() {
    let cli = pyroclast::cargo_cli::CargoCli::parse_from(
        pyroclast::cargo_cli::normalize_cargo_args(std::env::args_os()),
    );
    let json = cli.command.json();
    match pyroclast::run_parsed_cargo_cli(cli) {
        Ok(output) => {
            if let Err(error) =
                pyroclast::write_cli_output(&output, std::io::stdout(), std::io::stderr())
            {
                eprintln!("error: {error}");
                std::process::exit(1);
            }
            std::process::exit(i32::from(output.exit_code));
        }
        Err(error) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"status": "failed", "error": error.to_string()})
                );
            }
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}
