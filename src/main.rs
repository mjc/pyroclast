fn main() {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let exit_code = match pyroclast::run_cli_to_writers(
        std::env::args_os(),
        std::io::BufWriter::new(stdout.lock()),
        stderr.lock(),
    ) {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("error: {error}");
            1
        }
    };
    std::process::exit(i32::from(exit_code));
}
