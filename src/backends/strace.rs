use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::artifacts::ArtifactLayout;
use crate::backends::{BackendResult, ProfileRequest, ProfileResult, ProfilerBackend};
use crate::manifest::{BackendName, RunManifest};
use crate::parsers::strace::{parse_strace_summary, render_strace_summary_text};
use crate::process::CommandRunner;
use crate::process::CommandSpec;
use crate::tools::{ToolSpec, collect_tool_versions};

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

pub struct StraceBackend<'a, R> {
    runner: &'a R,
}

impl<'a, R> StraceBackend<'a, R> {
    pub fn new(runner: &'a R) -> Self {
        Self { runner }
    }
}

impl<R> ProfilerBackend for StraceBackend<'_, R>
where
    R: CommandRunner,
{
    fn profile(&self, request: &ProfileRequest) -> BackendResult<ProfileResult> {
        let layout = ArtifactLayout::new(request.out_dir.clone());
        std::fs::create_dir_all(layout.root())?;

        let raw_strace = layout.raw_profile("strace");
        let command = build_strace_command(&raw_strace, request.command.clone());
        let output = self.runner.run(&command)?;
        std::fs::write(layout.stdout_log(), &output.stdout)?;
        std::fs::write(layout.stderr_log(), &output.stderr)?;
        std::fs::write(
            layout.command_txt(),
            format!("{}\n", request.command.join(" ")),
        )?;

        if output.status_code != Some(0) {
            let error = format!(
                "strace exited with {:?}: {}",
                output.status_code,
                String::from_utf8_lossy(&output.stderr)
            );
            std::fs::write(layout.tool_errors_log(), format!("{error}\n"))?;
            return Err(error.into());
        }

        let raw_output = std::fs::read_to_string(&raw_strace)?;
        let summary = parse_strace_summary(&raw_output);
        std::fs::write(layout.summary_txt(), render_strace_summary_text(&summary))?;
        std::fs::write(
            layout.summary_json(),
            format!("{}\n", serde_json::to_string_pretty(&summary)?),
        )?;
        std::fs::write(layout.tool_errors_log(), "")?;

        let manifest = RunManifest {
            command: request.command.clone(),
            cwd: std::env::current_dir()?,
            profile_kind: request.kind,
            requested_backend: BackendName::Strace,
            actual_backend: BackendName::Strace,
            fallback_reason: None,
            platform: std::env::consts::OS.to_string(),
            started_at_unix_ms: unix_ms_now(),
            ended_at_unix_ms: Some(unix_ms_now()),
            exit_status: output.status_code,
            sample_frequency: request.frequency,
            sample_event: request.event,
            call_graph: request.call_graph,
            record_target: "command".to_string(),
            duration_secs: None,
            symbols: request.symbols,
            tool_versions: collect_tool_versions(self.runner, &[ToolSpec::nix_managed("strace")]),
            artifacts: {
                let mut artifacts = layout.standard_manifest_artifacts();
                artifacts.push(raw_strace);
                artifacts
            },
            diagnostics: vec!["strace executed".to_string()],
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
