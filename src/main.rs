fn main() {
    match pyroclast::run_cli(std::env::args_os()) {
        Ok(output) => {
            if let Err(error) =
                pyroclast::write_cli_output(output, std::io::stdout(), std::io::stderr())
            {
                eprintln!("error: {error}");
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}
