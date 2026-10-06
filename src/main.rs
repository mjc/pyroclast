fn main() {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    if let Err(error) = pyroclast::run_cli_to_writers(
        std::env::args_os(),
        std::io::BufWriter::new(stdout.lock()),
        stderr.lock(),
    ) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
