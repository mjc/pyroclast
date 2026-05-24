use std::path::PathBuf;

use crate::process::CommandSpec;

pub fn build_inferno_flamegraph_command(
    title: &str,
    folded_input: PathBuf,
    svg_output: PathBuf,
) -> CommandSpec {
    CommandSpec::new("inferno-flamegraph").args([
        "--title".to_string(),
        title.to_string(),
        folded_input.display().to_string(),
        "--output".to_string(),
        svg_output.display().to_string(),
    ])
}
