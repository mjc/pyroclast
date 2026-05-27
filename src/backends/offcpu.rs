use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::artifacts::ArtifactLayout;
use crate::backends::linux_perf::{
    PerfRecordTarget, build_perf_record_command, fold_linux_perfdata, linux_perf_fold_tools,
};
use crate::backends::{BackendResult, ProfileRequest, ProfileResult, ProfilerBackend};
use crate::cli::PerfEvent;
use crate::manifest::{BackendName, RunManifest};
use crate::parsers::bpftrace::collapse_offcpu;
use crate::process::{CommandRunner, CommandSpec};
use crate::summary::threads::{
    FoldedStackSummary, render_folded_stack_summary_text, summarize_folded_stacks,
};
use crate::tools::{ToolSpec, collect_tool_versions};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OffcpuMethod {
    PerfSched,
    PerfCpuClock,
    Bpftrace,
}

impl OffcpuMethod {
    fn summary_label(self) -> &'static str {
        match self {
            Self::PerfSched => "perf_sched",
            Self::PerfCpuClock => "perf_cpu_clock",
            Self::Bpftrace => "bpftrace",
        }
    }
}

#[derive(Serialize)]
struct FoldedOffcpuSummary {
    method: OffcpuMethod,
    #[serde(flatten)]
    folded: FoldedStackSummary,
}

#[derive(Serialize)]
struct PerfSchedSummary {
    method: OffcpuMethod,
    timehist_raw: String,
}

#[must_use]
pub fn build_bpftrace_offcpu_command(profiled_command: String, duration_secs: u32) -> CommandSpec {
    CommandSpec::new("bpftrace")
        .arg("-e")
        .arg(offcpu_bpftrace_program(duration_secs))
        .arg("-c")
        .arg(profiled_command)
        .arg("--unsafe")
        .interactive()
}

#[must_use]
pub fn build_perf_sched_record_command(
    output: &Path,
    profiled_command: Vec<String>,
) -> CommandSpec {
    CommandSpec::new("perf")
        .arg("sched")
        .arg("record")
        .arg("-o")
        .arg(output.display().to_string())
        .arg("--")
        .args(profiled_command)
        .interactive()
}

#[must_use]
pub fn build_perf_sched_timehist_command(input: &Path) -> CommandSpec {
    CommandSpec::new("perf")
        .arg("sched")
        .arg("timehist")
        .arg("-i")
        .arg(input.display().to_string())
}

#[must_use]
pub fn build_perf_cpu_clock_command(
    frequency: u32,
    callgraph: &str,
    output: &Path,
    profiled_command: Vec<String>,
) -> CommandSpec {
    build_perf_record_command(
        PerfEvent::CpuClock,
        frequency,
        callgraph,
        output,
        PerfRecordTarget::Command(profiled_command),
        0,
    )
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
        ensure_command_workflow(request)?;

        let layout = ArtifactLayout::new(request.out_dir.clone());
        std::fs::create_dir_all(layout.root())?;
        std::fs::write(
            layout.command_txt(),
            format!("{}\n", request.command.join(" ")),
        )?;

        let method = request.offcpu_method.unwrap_or(OffcpuMethod::PerfSched);
        let run = match method {
            OffcpuMethod::PerfSched => self.profile_with_perf_sched(request, &layout)?,
            OffcpuMethod::PerfCpuClock => self.profile_with_perf_cpu_clock(request, &layout)?,
            OffcpuMethod::Bpftrace => self.profile_with_bpftrace(request, &layout)?,
        };

        std::fs::write(layout.stdout_log(), &run.stdout)?;
        std::fs::write(layout.stderr_log(), &run.stderr)?;
        std::fs::write(layout.summary_txt(), &run.summary_text)?;
        std::fs::write(
            layout.summary_json(),
            format!("{}\n", serde_json::to_string_pretty(&run.summary_json)?),
        )?;
        if let Some(folded_stacks) = &run.folded_stacks {
            std::fs::write(layout.stacks_folded(), folded_stacks)?;
        }
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
            exit_status: run.exit_status,
            sample_frequency: request.frequency,
            sample_event: run.sample_event,
            call_graph: request.call_graph,
            record_target: "command".to_string(),
            duration_secs: run.duration_secs,
            symbols: request.symbols,
            tool_versions: collect_tool_versions(self.runner, &run.tool_specs),
            artifacts: {
                let mut artifacts = layout.standard_manifest_artifacts();
                artifacts.push(run.raw_profile);
                if run.folded_stacks.is_some() {
                    artifacts.push(layout.stacks_folded());
                }
                artifacts
            },
            diagnostics: vec![format!("offcpu method: {}", method.summary_label())],
        };
        std::fs::write(layout.run_json(), serde_json::to_string_pretty(&manifest)?)?;

        Ok(ProfileResult { layout, manifest })
    }
}

impl<R> OffcpuBackend<'_, R>
where
    R: CommandRunner,
{
    fn profile_with_perf_sched(
        &self,
        request: &ProfileRequest,
        layout: &ArtifactLayout,
    ) -> BackendResult<OffcpuRun> {
        let perf_data = layout.raw_profile("perf.data");
        let record = build_perf_sched_record_command(&perf_data, request.command.clone());
        let record_output = self.runner.run(&record)?;
        if record_output.status_code != Some(0) {
            return offcpu_command_error("perf sched record", &record_output, layout);
        }

        let timehist = build_perf_sched_timehist_command(&perf_data);
        let timehist_output = self.runner.run(&timehist)?;
        if timehist_output.status_code != Some(0) {
            return offcpu_command_error("perf sched timehist", &timehist_output, layout);
        }

        let timehist_raw = String::from_utf8_lossy(&timehist_output.stdout).into_owned();
        Ok(OffcpuRun {
            exit_status: timehist_output.status_code,
            sample_event: PerfEvent::Default,
            duration_secs: None,
            stdout: [record_output.stdout, timehist_output.stdout].concat(),
            stderr: [record_output.stderr, timehist_output.stderr].concat(),
            raw_profile: perf_data,
            folded_stacks: None,
            summary_text: timehist_raw.clone(),
            summary_json: serde_json::to_value(PerfSchedSummary {
                method: OffcpuMethod::PerfSched,
                timehist_raw,
            })?,
            tool_specs: vec![ToolSpec::nix_managed("perf")],
        })
    }

    fn profile_with_perf_cpu_clock(
        &self,
        request: &ProfileRequest,
        layout: &ArtifactLayout,
    ) -> BackendResult<OffcpuRun> {
        let perf_data = layout.raw_profile("perf.data");
        let command = build_perf_cpu_clock_command(
            request.frequency,
            &request.call_graph.to_string(),
            &perf_data,
            request.command.clone(),
        );
        let output = self.runner.run(&command)?;
        if output.status_code != Some(0) {
            return offcpu_command_error("perf record", &output, layout);
        }

        let folded_stacks =
            fold_linux_perfdata(&perf_data, request.symbols, request.symbolizer, self.runner)?;
        folded_offcpu_run(
            OffcpuMethod::PerfCpuClock,
            output,
            perf_data,
            folded_stacks,
            PerfEvent::CpuClock,
            None,
            linux_perf_fold_tools(request.symbols, request.symbolizer),
        )
    }

    fn profile_with_bpftrace(
        &self,
        request: &ProfileRequest,
        layout: &ArtifactLayout,
    ) -> BackendResult<OffcpuRun> {
        let profiled_command = request.command.join(" ");
        let command = build_bpftrace_offcpu_command(profiled_command, request.duration_secs);
        let output = self.runner.run(&command)?;
        if output.status_code != Some(0) {
            return offcpu_command_error("bpftrace", &output, layout);
        }

        let raw_bpftrace = layout.raw_profile("bpftrace");
        std::fs::write(&raw_bpftrace, &output.stdout)?;
        let folded_stacks = collapse_offcpu(&String::from_utf8_lossy(&output.stdout)).join("\n");
        let folded_stacks = if folded_stacks.is_empty() {
            String::new()
        } else {
            format!("{folded_stacks}\n")
        };
        folded_offcpu_run(
            OffcpuMethod::Bpftrace,
            output,
            raw_bpftrace,
            folded_stacks,
            request.event,
            Some(request.duration_secs),
            vec![ToolSpec::nix_managed("bpftrace")],
        )
    }
}

struct OffcpuRun {
    exit_status: Option<i32>,
    sample_event: PerfEvent,
    duration_secs: Option<u32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    raw_profile: PathBuf,
    folded_stacks: Option<String>,
    summary_text: String,
    summary_json: serde_json::Value,
    tool_specs: Vec<ToolSpec>,
}

fn folded_offcpu_run(
    method: OffcpuMethod,
    output: crate::process::CommandOutput,
    raw_profile: PathBuf,
    folded_stacks: String,
    sample_event: PerfEvent,
    duration_secs: Option<u32>,
    tool_specs: Vec<ToolSpec>,
) -> BackendResult<OffcpuRun> {
    let folded_summary = summarize_folded_stacks(&folded_stacks);
    Ok(OffcpuRun {
        exit_status: output.status_code,
        sample_event,
        duration_secs,
        stdout: output.stdout,
        stderr: output.stderr,
        raw_profile,
        summary_text: render_folded_stack_summary_text(&folded_summary),
        summary_json: serde_json::to_value(FoldedOffcpuSummary {
            method,
            folded: folded_summary,
        })?,
        folded_stacks: Some(folded_stacks),
        tool_specs,
    })
}

fn ensure_command_workflow(request: &ProfileRequest) -> BackendResult<()> {
    if request.pid.is_some() || request.threads_of_pid.is_some() || !request.tids.is_empty() {
        return Err("offcpu currently supports command-driven workflows only".into());
    }
    Ok(())
}

fn offcpu_command_error<T>(
    label: &str,
    output: &crate::process::CommandOutput,
    layout: &ArtifactLayout,
) -> BackendResult<T> {
    let error = format!(
        "{label} exited with {:?}: {}",
        output.status_code,
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::write(layout.stdout_log(), &output.stdout)?;
    std::fs::write(layout.stderr_log(), &output.stderr)?;
    std::fs::write(layout.tool_errors_log(), format!("{error}\n"))?;
    Err(error.into())
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
