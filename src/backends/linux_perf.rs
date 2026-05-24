use std::path::PathBuf;

use crate::process::CommandSpec;

pub fn build_perf_record_command(
    frequency: u32,
    callgraph: &str,
    output: PathBuf,
    profiled_command: impl IntoIterator<Item = String>,
) -> CommandSpec {
    CommandSpec::new("perf")
        .args([
            "record".to_string(),
            "-F".to_string(),
            frequency.to_string(),
            "-g".to_string(),
            "--call-graph".to_string(),
            callgraph.to_string(),
            "-o".to_string(),
            output.display().to_string(),
            "--".to_string(),
        ])
        .args(profiled_command)
}
