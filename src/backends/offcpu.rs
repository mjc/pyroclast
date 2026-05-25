use std::time::{SystemTime, UNIX_EPOCH};

use crate::artifacts::ArtifactLayout;
use crate::backends::{BackendResult, ProfileRequest, ProfileResult, ProfilerBackend};
use crate::manifest::{BackendName, RunManifest};
use crate::parsers::bpftrace::collapse_offcpu;
use crate::process::CommandRunner;
use crate::process::CommandSpec;
use crate::summary::threads::{render_folded_stack_summary_text, summarize_folded_stacks};
use crate::tools::{ToolSpec, collect_tool_versions};

#[must_use]
pub fn build_bpftrace_offcpu_command(profiled_command: String, duration_secs: u32) -> CommandSpec {
    CommandSpec::new("bpftrace")
        .arg("-e")
        .arg(offcpu_bpftrace_program(duration_secs))
        .arg("-c")
        .arg(profiled_command)
        .arg("--unsafe")
}

fn offcpu_bpftrace_program(duration_secs: u32) -> String {
    format!(
        r"
tracepoint:sched:sched_switch
{{
  if (args->prev_state != 0) {{
    @start[args->prev_pid] = nsecs;
  }}
  if (@start[args->next_pid]) {{
    @offcpu[kstack] = sum(nsecs - @start[args->next_pid]);
    delete(@start[args->next_pid]);
  }}
}}

interval:s:{duration_secs}
{{
  exit();
}}
"
    )
}

pub struct OffcpuBackend<'a, R> {
    runner: &'a R,
}

impl<'a, R> OffcpuBackend<'a, R> {
    #[must_use]
    pub fn new(runner: &'a R) -> Self {
        Self { runner }
    }
}

impl<R> ProfilerBackend for OffcpuBackend<'_, R>
where
    R: CommandRunner,
{
    fn profile(&self, request: &ProfileRequest) -> BackendResult<ProfileResult> {
        let layout = ArtifactLayout::new(request.out_dir.clone());
        std::fs::create_dir_all(layout.root())?;

        let profiled_command = request.command.join(" ");
        let command = build_bpftrace_offcpu_command(profiled_command, request.duration_secs);
        let output = self.runner.run(&command)?;
        std::fs::write(layout.stdout_log(), &output.stdout)?;
        std::fs::write(layout.stderr_log(), &output.stderr)?;
        std::fs::write(
            layout.command_txt(),
            format!("{}\n", request.command.join(" ")),
        )?;

        if output.status_code != Some(0) {
            let error = format!(
                "bpftrace exited with {:?}: {}",
                output.status_code,
                String::from_utf8_lossy(&output.stderr)
            );
            std::fs::write(layout.tool_errors_log(), format!("{error}\n"))?;
            return Err(error.into());
        }

        let raw_bpftrace = layout.raw_profile("bpftrace");
        std::fs::write(&raw_bpftrace, &output.stdout)?;
        let folded_stacks = collapse_offcpu(&String::from_utf8_lossy(&output.stdout)).join("\n");
        let folded_stacks = if folded_stacks.is_empty() {
            String::new()
        } else {
            format!("{folded_stacks}\n")
        };
        std::fs::write(layout.stacks_folded(), &folded_stacks)?;
        let summary = summarize_folded_stacks(&folded_stacks);
        std::fs::write(
            layout.summary_txt(),
            render_folded_stack_summary_text(summary),
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
            requested_backend: BackendName::Offcpu,
            actual_backend: BackendName::Offcpu,
            fallback_reason: None,
            platform: std::env::consts::OS.to_string(),
            started_at_unix_ms: unix_ms_now(),
            ended_at_unix_ms: Some(unix_ms_now()),
            exit_status: output.status_code,
            sample_frequency: request.frequency,
            sample_event: request.event,
            call_graph: request.call_graph,
            record_target: "command".to_string(),
            duration_secs: Some(request.duration_secs),
            symbols: request.symbols,
            tool_versions: collect_tool_versions(self.runner, &[ToolSpec::nix_managed("bpftrace")]),
            artifacts: {
                let mut artifacts = layout.standard_manifest_artifacts();
                artifacts.push(raw_bpftrace);
                artifacts.push(layout.stacks_folded());
                artifacts
            },
            diagnostics: vec!["bpftrace offcpu executed".to_string()],
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
