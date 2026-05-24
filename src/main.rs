fn main() {
    if let Err(error) = pyroclast::run_cli(std::env::args_os()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
