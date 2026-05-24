use std::path::PathBuf;

use crate::process::CommandSpec;

pub const XCTRACE_PID_ENV: &str = "PYROCLAST_XCTRACE_TARGET_PID";

pub fn build_xctrace_record_command(
    trace_path: PathBuf,
    target_pid_path: PathBuf,
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
