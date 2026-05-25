use std::path::Path;

use crate::process::CommandSpec;

pub const XCTRACE_PID_ENV: &str = "PYROCLAST_XCTRACE_TARGET_PID";

pub fn build_xctrace_record_command(
    trace_path: &Path,
    target_pid_path: &Path,
    profiled_command: impl IntoIterator<Item = String>,
) -> CommandSpec {
    CommandSpec::new("xctrace")
        .args([
            "record".to_string(),
            "--quiet".to_string(),
            "--template".to_string(),
            "CPU Profiler".to_string(),
            "--output".to_string(),
            trace_path.display().to_string(),
            "--no-prompt".to_string(),
            "--launch".to_string(),
            "--".to_string(),
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("printf '%s\\n' \"$$\" > \"${XCTRACE_PID_ENV}\"; exec \"$@\""),
            "pyroclast-xctrace-launch".to_string(),
        ])
        .env(XCTRACE_PID_ENV, target_pid_path.display().to_string())
        .args(profiled_command)
}

#[must_use]
pub fn build_xctrace_export_cpu_command(trace_path: &Path, output_xml: &Path) -> CommandSpec {
    CommandSpec::new("xctrace").args([
        "export".to_string(),
        "--input".to_string(),
        trace_path.display().to_string(),
        "--output".to_string(),
        output_xml.display().to_string(),
        "--xpath".to_string(),
        "//table".to_string(),
    ])
}
