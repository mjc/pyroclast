fn main() {
    match pyroclast::run_cli(std::env::args_os()) {
        Ok(output) => {
            print!("{}", output.stdout);
            eprint!("{}", output.stderr);
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}
