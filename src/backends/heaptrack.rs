use std::path::Path;

use crate::process::CommandSpec;

pub fn build_heaptrack_command(
    output_prefix: &Path,
    profiled_command: impl IntoIterator<Item = String>,
) -> CommandSpec {
    CommandSpec::new("heaptrack")
        .arg("-o")
        .arg(output_prefix.display().to_string())
        .args(profiled_command)
}
