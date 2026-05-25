use std::path::Path;

use crate::process::CommandSpec;

pub fn build_strace_command(
    output: &Path,
    profiled_command: impl IntoIterator<Item = String>,
) -> CommandSpec {
    CommandSpec::new("strace")
        .args(["-f", "-ttt", "-T", "-o"])
        .arg(output.display().to_string())
        .arg("--")
        .args(profiled_command)
}
