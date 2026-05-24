use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::artifacts::ArtifactLayout;
use crate::backends::{BackendResult, ProfileRequest, ProfileResult, ProfilerBackend};
use crate::flamegraph::build_inferno_flamegraph_command;
use crate::manifest::{BackendName, RunManifest};
use crate::perfdata::fold::fold_perfdata_callchains;
use crate::process::{CommandRunner, CommandSpec};

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

pub struct LinuxPerfBackend<'a, R> {
    runner: &'a R,
}

impl<'a, R> LinuxPerfBackend<'a, R> {
    pub fn new(runner: &'a R) -> Self {
        Self { runner }
    }
}

impl<R> ProfilerBackend for LinuxPerfBackend<'_, R>
where
    R: CommandRunner,
{
    fn profile(&self, request: &ProfileRequest) -> BackendResult<ProfileResult> {
        let layout = ArtifactLayout::new(request.out_dir.clone());
        std::fs::create_dir_all(layout.root())?;

        let perf_data = layout.raw_profile("perf.data");
        let command =
            build_perf_record_command(997, "fp", perf_data.clone(), request.command.clone());
        let output = self.runner.run(&command)?;
        let perf_bytes = std::fs::read(&perf_data)?;
        std::fs::write(
            layout.stacks_folded(),
            fold_perfdata_callchains(&perf_bytes)?,
        )?;
        let flamegraph_command = build_inferno_flamegraph_command(
            "CPU profile",
            layout.stacks_folded(),
            layout.flamegraph_svg(),
        );
        let flamegraph_output = self.runner.run(&flamegraph_command)?;

        std::fs::write(layout.stdout_log(), &output.stdout)?;
        let mut stderr = output.stderr;
        stderr.extend(flamegraph_output.stderr);
        std::fs::write(layout.stderr_log(), &stderr)?;
        std::fs::write(layout.command_txt(), request.command.join(" "))?;
        std::fs::write(layout.summary_txt(), "linux perf profile recorded\n")?;
        std::fs::write(layout.summary_json(), "{}\n")?;
        std::fs::write(layout.tool_errors_log(), "")?;

        let manifest = RunManifest {
            command: request.command.clone(),
            cwd: std::env::current_dir()?,
            profile_kind: request.kind,
            requested_backend: BackendName::LinuxPerf,
            actual_backend: BackendName::LinuxPerf,
            fallback_reason: None,
            platform: std::env::consts::OS.to_string(),
            started_at_unix_ms: unix_ms_now(),
            ended_at_unix_ms: Some(unix_ms_now()),
            exit_status: output.status_code,
            artifacts: {
                let mut artifacts = layout.standard_manifest_artifacts();
                artifacts.push(perf_data);
                artifacts.push(layout.stacks_folded());
                artifacts.push(layout.flamegraph_svg());
                artifacts
            },
            diagnostics: vec!["perf record executed".to_string()],
        };
        std::fs::write(layout.run_json(), serde_json::to_string_pretty(&manifest)?)?;

        Ok(ProfileResult { layout, manifest })
    }
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
