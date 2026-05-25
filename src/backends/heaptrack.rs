use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::artifacts::ArtifactLayout;
use crate::backends::{BackendResult, ProfileRequest, ProfileResult, ProfilerBackend};
use crate::manifest::{BackendName, RunManifest};
use crate::parsers::heaptrack::{parse_heaptrack_summary, render_heaptrack_summary_text};
use crate::process::CommandRunner;
use crate::process::CommandSpec;
use crate::tools::{ToolSpec, collect_tool_versions};

pub fn build_heaptrack_command(
    output_prefix: &Path,
    profiled_command: impl IntoIterator<Item = String>,
) -> CommandSpec {
    CommandSpec::new("heaptrack")
        .arg("-o")
        .arg(output_prefix.display().to_string())
        .args(profiled_command)
}

#[must_use]
pub fn build_heaptrack_print_command(raw_output: &Path) -> CommandSpec {
    CommandSpec::new("heaptrack_print").arg(raw_output.display().to_string())
}

pub struct HeaptrackBackend<'a, R> {
    runner: &'a R,
}

impl<'a, R> HeaptrackBackend<'a, R> {
    #[must_use]
    pub fn new(runner: &'a R) -> Self {
        Self { runner }
    }
}

impl<R> ProfilerBackend for HeaptrackBackend<'_, R>
where
    R: CommandRunner,
{
    fn profile(&self, request: &ProfileRequest) -> BackendResult<ProfileResult> {
        let layout = ArtifactLayout::new(request.out_dir.clone());
        std::fs::create_dir_all(layout.root())?;

        let raw_heaptrack = layout.raw_profile("heaptrack");
        let command = build_heaptrack_command(&raw_heaptrack, request.command.clone());
        let output = self.runner.run(&command)?;
        std::fs::write(layout.stdout_log(), &output.stdout)?;
        std::fs::write(layout.stderr_log(), &output.stderr)?;
        std::fs::write(
            layout.command_txt(),
            format!("{}\n", request.command.join(" ")),
        )?;

        if output.status_code != Some(0) {
            let error = format!(
                "heaptrack exited with {:?}: {}",
                output.status_code,
                String::from_utf8_lossy(&output.stderr)
            );
            std::fs::write(layout.tool_errors_log(), format!("{error}\n"))?;
            return Err(error.into());
        }

        let print_output = self
            .runner
            .run(&build_heaptrack_print_command(&raw_heaptrack))?;
        if print_output.status_code != Some(0) {
            let error = format!(
                "heaptrack_print exited with {:?}: {}",
                print_output.status_code,
                String::from_utf8_lossy(&print_output.stderr)
            );
            std::fs::write(layout.tool_errors_log(), format!("{error}\n"))?;
            return Err(error.into());
        }

        let summary_text = String::from_utf8_lossy(&print_output.stdout);
        let summary = parse_heaptrack_summary(&summary_text);
        std::fs::write(
            layout.summary_txt(),
            render_heaptrack_summary_text(&summary),
        )?;
        std::fs::write(
            layout.summary_json(),
            format!("{}\n", serde_json::to_string_pretty(&summary)?),
        )?;
        std::fs::write(layout.tool_errors_log(), "")?;

        let manifest = RunManifest {
            command: request.command.clone(),
            cwd: std::env::current_dir()?,
            profile_kind: request.kind,
            requested_backend: BackendName::Heaptrack,
            actual_backend: BackendName::Heaptrack,
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
            tool_versions: collect_tool_versions(
                self.runner,
                &[ToolSpec::nix_managed("heaptrack")],
            ),
            artifacts: {
                let mut artifacts = layout.standard_manifest_artifacts();
                artifacts.push(raw_heaptrack);
                artifacts
            },
            diagnostics: vec!["heaptrack executed".to_string()],
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
