use std::path::Path;

use crate::process::CommandSpec;

#[must_use]
pub fn build_inferno_flamegraph_command(title: &str, folded_input: &Path) -> CommandSpec {
    CommandSpec::new("inferno-flamegraph").args([
        "--title".to_string(),
        title.to_string(),
        folded_input.display().to_string(),
    ])
}
