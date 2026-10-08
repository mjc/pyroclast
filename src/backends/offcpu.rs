use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::artifacts::ArtifactLayout;
use crate::backends::linux_perf::{PerfRecordTarget, build_perf_record_command};
use crate::backends::{BackendResult, ProfileRequest, ProfileResult, ProfilerBackend};
use crate::cli::PerfEvent;
use crate::flamegraph::{BuiltinFlamegraphRenderer, FlamegraphRenderer, FlamegraphRequest};
use crate::manifest::{BackendName, RunManifest};
use crate::parsers::bpftrace::collapse_offcpu;
use crate::process::{CommandRunner, CommandSpec};
use crate::summary::threads::{
    FoldedStackSummary, render_folded_stack_summary_text, summarize_folded_stacks,
};
use crate::tools::{BPFTRACE, PERF, ToolSpec, resolve_required_tools};

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
    weight_unit: &'static str,
    scope: &'static str,
    total_offcpu_ns: u64,
    #[serde(flatten)]
    folded: FoldedStackSummary,
}

#[derive(Serialize)]
struct PerfSchedSummary {
    method: OffcpuMethod,
    target_pid: u32,
    scope: &'static str,
    total_wait_ms: f64,
    total_sched_delay_ms: f64,
    total_run_ms: f64,
    threads: Vec<PerfSchedThread>,
    timehist_raw: String,
}

#[derive(Default, Serialize)]
struct PerfSchedThread {
    tid: u32,
    name: String,
    intervals: u64,
    wait_ms: f64,
    sched_delay_ms: f64,
    run_ms: f64,
}

pub const OFFCPU_PID_ENV: &str = "PYROCLAST_OFFCPU_TARGET_PID";

#[must_use]
pub fn build_bpftrace_offcpu_command(profiled_command: String, duration_secs: u32) -> CommandSpec {
    bpftrace_command(
        profiled_command,
        offcpu_bpftrace_program(duration_secs, false),
    )
}

fn bpftrace_command(profiled_command: String, program: String) -> CommandSpec {
    CommandSpec::new("bpftrace")
        .arg("-e")
        .arg(program)
        .arg("-c")
        .arg(profiled_command)
        .arg("--unsafe")
        .interactive()
        .capture_output()
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

fn offcpu_bpftrace_program(duration_secs: u32, supervised: bool) -> String {
    let (setup, target, cleanup) = if supervised {
        (
            "tracepoint:sched:sched_process_fork /args->parent_pid == cpid/ { @workload_pid = args->child_pid; }",
            "@workload_pid",
            "clear(@workload_pid);",
        )
    } else {
        ("", "cpid", "")
    };
    format!(
        r"
{setup}
tracepoint:sched:sched_switch
{{
  if (pid == {target} && args->prev_state != 0) {{
    @start[args->prev_pid] = nsecs;
    @stack[args->prev_pid] = kstack(perf);
  }}
  if (@start[args->next_pid]) {{
    @offcpu[@stack[args->next_pid]] = sum((int64)(nsecs - @start[args->next_pid]));
    delete(@start[args->next_pid]);
    delete(@stack[args->next_pid]);
  }}
}}

interval:s:{duration_secs}
{{
  @duration_limited = 1;
  exit();
}}

END
{{
  clear(@start);
  clear(@stack);
  {cleanup}
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
        if request.offcpu_method == Some(OffcpuMethod::PerfCpuClock) {
            return Err(
                "cpu-clock measures on-CPU execution; use perf-sched or bpftrace for off-CPU waits"
                    .into(),
            );
        }
        let started_at_unix_ms = unix_ms_now();
        let layout = ArtifactLayout::new(request.out_dir.clone());
        layout.prepare()?;
        let tool_versions = resolve_required_tools(
            self.runner,
            &offcpu_tool_specs(request.offcpu_method.unwrap_or(OffcpuMethod::PerfSched)),
        )?;

        std::fs::write(
            layout.command_txt(),
            format!("{}\n", request.command.join(" ")),
        )?;

        let method = request.offcpu_method.unwrap_or(OffcpuMethod::PerfSched);
        let run = match method {
            OffcpuMethod::PerfSched => self.profile_with_perf_sched(request, &layout)?,
            OffcpuMethod::PerfCpuClock => unreachable!("CPU-clock rejected before recording"),
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
            if !folded_stacks.is_empty() {
                BuiltinFlamegraphRenderer.render(&FlamegraphRequest {
                    title: "Off-CPU time (nanoseconds)".to_string(),
                    folded_stacks: folded_stacks.clone(),
                    output: layout.flamegraph_svg(),
                })?;
            }
        }
        std::fs::write(layout.tool_errors_log(), "")?;

        let manifest = RunManifest {
            name: request.name.clone(),
            command: request.command.clone(),
            cwd: std::env::current_dir()?,
            profile_kind: request.kind,
            requested_backend: BackendName::Offcpu,
            actual_backend: BackendName::Offcpu,
            fallback_reason: None,
            platform: std::env::consts::OS.to_string(),
            started_at_unix_ms,
            ended_at_unix_ms: Some(unix_ms_now()),
            exit_status: run.exit_status,
            sample_frequency: request.frequency,
            sample_event: run.sample_event,
            call_graph: request.call_graph,
            record_target: "command".to_string(),
            duration_secs: run.duration_secs,
            symbols: request.symbols,
            tool_versions,
            artifacts: {
                let mut artifacts = layout.standard_manifest_artifacts();
                artifacts.push(run.raw_profile);
                if run.folded_stacks.is_some() {
                    artifacts.push(layout.stacks_folded());
                }
                if layout.flamegraph_svg().is_file() {
                    artifacts.push(layout.flamegraph_svg());
                }
                artifacts
            },
            diagnostics: {
                let mut diagnostics = vec![format!("offcpu method: {}", method.summary_label())];
                if let Some(outcome) = run
                    .summary_json
                    .get("workload_outcome")
                    .and_then(serde_json::Value::as_str)
                {
                    diagnostics.push(format!("workload outcome: {outcome}"));
                }
                diagnostics
            },
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
        let pid_path = layout.root().join("offcpu-target.pid");
        let workload = [
            "sh".to_string(),
            "-c".to_string(),
            format!("printf '%s\\n' \"$$\" > \"${OFFCPU_PID_ENV}\"; exec \"$@\""),
            "pyroclast-offcpu-launch".to_string(),
        ]
        .into_iter()
        .chain(request.command.clone())
        .collect();
        let record = build_perf_sched_record_command(&perf_data, workload)
            .env(OFFCPU_PID_ENV, pid_path.to_string_lossy());
        let record = if request.json {
            record.capture_output()
        } else {
            record
        };
        let record_output = self.runner.run(&record)?;
        if !record_output.succeeded_or_interrupted() {
            return offcpu_command_error("perf sched record", &record_output, layout);
        }

        let target_pid: u32 = std::fs::read_to_string(&pid_path)
            .map_err(|error| format!("could not read recorded workload PID: {error}"))?
            .trim()
            .parse()
            .map_err(|error| format!("invalid recorded workload PID: {error}"))?;
        let timehist = build_perf_sched_timehist_command(&perf_data)
            .args(["-p".to_string(), target_pid.to_string()]);
        let timehist_output = self.runner.run(&timehist)?;
        if timehist_output.status_code != Some(0) {
            return offcpu_command_error("perf sched timehist", &timehist_output, layout);
        }

        let timehist_raw = String::from_utf8_lossy(&timehist_output.stdout).into_owned();
        let summary = summarize_perf_sched_timehist(timehist_raw, target_pid)?;
        let summary_text = format!(
            "offcpu wait milliseconds: {:.3}\nscheduling delay milliseconds: {:.3}\noncpu run milliseconds: {:.3}\n{}",
            summary.total_wait_ms,
            summary.total_sched_delay_ms,
            summary.total_run_ms,
            summary.timehist_raw,
        );
        Ok(OffcpuRun {
            exit_status: record_output.status_code,
            sample_event: PerfEvent::Default,
            duration_secs: None,
            stdout: [record_output.stdout, timehist_output.stdout].concat(),
            stderr: [record_output.stderr, timehist_output.stderr].concat(),
            raw_profile: perf_data,
            folded_stacks: None,
            summary_text,
            summary_json: serde_json::to_value(summary)?,
        })
    }

    #[cfg(unix)]
    fn profile_with_bpftrace(
        &self,
        request: &ProfileRequest,
        layout: &ArtifactLayout,
    ) -> BackendResult<OffcpuRun> {
        use std::io::Write;

        // bpftrace's status describes the recorder, not its -c child. A private
        // supervisor waits once for the workload, independently of recorder I/O.
        let private = tempfile::Builder::new()
            .prefix("pyroclast-offcpu-")
            .tempdir_in("/tmp")?;
        let status_path = private.path().join("status");
        let data_path = private.path().join("recorder");
        let launcher_path = private.path().join("launch");
        let mut launcher = std::fs::File::create(&launcher_path)?;
        writeln!(
            launcher,
            "{}",
            bpftrace_workload_launcher(&request.command, &status_path)
        )?;
        launcher.flush()?;
        // -c does not recognize quoting, so its path must be whitespace-free.
        let profiled_command = format!("/bin/sh {}", launcher_path.display());
        let command = bpftrace_command(
            profiled_command,
            offcpu_bpftrace_program(request.duration_secs, true),
        )
        .arg("-o")
        .arg(data_path.to_string_lossy());
        let mut output = self.runner.run(&command)?;
        if !output.succeeded_or_interrupted() {
            return offcpu_command_error("bpftrace", &output, layout);
        }
        std::fs::write(layout.stdout_log(), &output.stdout)?;
        std::fs::write(layout.stderr_log(), &output.stderr)?;

        // -o redirects bpftrace's Output stream, not the child's file descriptors.
        // Never collapse stdout: it belongs to the workload, even if it looks
        // exactly like a recorder map.
        let data = std::fs::read(&data_path)?;
        let raw_bpftrace = layout.raw_profile("bpftrace");
        std::fs::write(&raw_bpftrace, &data)?;
        let data = String::from_utf8_lossy(&data);
        let duration_limited = data.lines().any(|line| line == "@duration_limited: 1");
        let status = std::fs::read_to_string(&status_path);
        let (exit_status, outcome) = match status.as_deref().map(str::trim) {
            Ok("stopped") if duration_limited => (None, "duration_limited"),
            Ok("stopped") => (None, "interrupted"),
            Ok(status) => match status.parse::<i32>() {
                Ok(status @ 0..=255) => (Some(status), "completed"),
                _ => {
                    return offcpu_command_error(
                        "invalid workload completion status",
                        &output,
                        layout,
                    );
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && duration_limited => {
                (None, "duration_limited")
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && output.status_code != Some(0) =>
            {
                (None, "interrupted")
            }
            Err(_) => {
                return offcpu_command_error("missing workload completion status", &output, layout);
            }
        };
        output.status_code = exit_status;
        let folded_stacks = collapse_offcpu(&data).join("\n");
        let folded_stacks = if folded_stacks.is_empty() {
            String::new()
        } else {
            format!("{folded_stacks}\n")
        };
        let mut run = folded_offcpu_run(
            OffcpuMethod::Bpftrace,
            output,
            raw_bpftrace,
            folded_stacks,
            request.event,
            Some(request.duration_secs),
        )?;
        run.summary_json["workload_outcome"] = outcome.into();
        Ok(run)
    }

    #[cfg(not(unix))]
    fn profile_with_bpftrace(
        &self,
        _request: &ProfileRequest,
        _layout: &ArtifactLayout,
    ) -> BackendResult<OffcpuRun> {
        Err("bpftrace profiling requires Unix".into())
    }
}

fn offcpu_tool_specs(method: OffcpuMethod) -> Vec<ToolSpec> {
    match method {
        OffcpuMethod::PerfSched => vec![PERF],
        OffcpuMethod::PerfCpuClock => Vec::new(),
        OffcpuMethod::Bpftrace => vec![BPFTRACE],
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
}

fn folded_offcpu_run(
    method: OffcpuMethod,
    output: crate::process::CommandOutput,
    raw_profile: PathBuf,
    folded_stacks: String,
    sample_event: PerfEvent,
    duration_secs: Option<u32>,
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
            weight_unit: "nanoseconds",
            scope: "workload_process_and_threads",
            total_offcpu_ns: folded_summary.total_count,
            folded: folded_summary,
        })?,
        folded_stacks: Some(folded_stacks),
    })
}

fn ensure_command_workflow(request: &ProfileRequest) -> BackendResult<()> {
    request.ensure_command_target("offcpu")
}

#[cfg(unix)]
fn shell_command(command: &[String]) -> String {
    command
        .iter()
        .map(|argument| format!("'{}'", argument.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(unix)]
fn bpftrace_workload_launcher(command: &[String], status_path: &Path) -> String {
    let status = shell_command(&[status_path.to_string_lossy().into_owned()]);
    let workload = shell_command(command);
    format!(
        r#"workload=
stop() {{
  trap '' INT TERM
  printf 'stopped\n' > {status}
  workload=${{workload:-$!}}
  if [ -n "$workload" ]; then
    kill -TERM "$workload" 2>/dev/null
    wait "$workload"
  fi
  exit 0
}}
trap stop INT TERM
exec 3<&0
(exec 0<&3 3<&-; exec {workload}) &
workload=$!
exec 3<&-
wait "$workload"
status=$?
trap '' INT TERM
printf '%s\n' "$status" > {status}
"#
    )
}

fn summarize_perf_sched_timehist(
    input: String,
    target_pid: u32,
) -> BackendResult<PerfSchedSummary> {
    let mut threads = std::collections::BTreeMap::<u32, PerfSchedThread>::new();
    let mut recognized = false;
    for line in input.lines() {
        let line = line.trim();
        let Some((time, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if !time.parse::<f64>().is_ok_and(f64::is_finite) {
            continue;
        }
        let Some((cpu, task)) = rest.trim_start().split_once(']') else {
            continue;
        };
        if cpu
            .strip_prefix('[')
            .is_none_or(|cpu| cpu.parse::<u32>().is_err())
        {
            continue;
        }
        let Some((task, values)) = task.trim_start().split_once(']') else {
            continue;
        };
        let Some((name, ids)) = task.rsplit_once('[') else {
            continue;
        };
        let (tid, pid) = ids.split_once('/').unwrap_or((ids, ids));
        let (Ok(tid), Ok(pid)) = (tid.parse::<u32>(), pid.parse::<u32>()) else {
            continue;
        };
        let mut values = values.split_whitespace().take(3).map(str::parse::<f64>);
        let (Some(Ok(wait_ms)), Some(Ok(sched_delay_ms)), Some(Ok(run_ms))) =
            (values.next(), values.next(), values.next())
        else {
            continue;
        };
        if ![wait_ms, sched_delay_ms, run_ms]
            .iter()
            .all(|value| value.is_finite() && *value >= 0.0)
        {
            continue;
        }
        recognized = true;
        if pid != target_pid {
            continue;
        }
        let thread = threads.entry(tid).or_insert_with(|| PerfSchedThread {
            tid,
            ..PerfSchedThread::default()
        });
        name.clone_into(&mut thread.name);
        thread.intervals += 1;
        thread.wait_ms += wait_ms;
        thread.sched_delay_ms += sched_delay_ms;
        thread.run_ms += run_ms;
    }
    if !(recognized
        || (input.contains("wait time")
            && input.contains("sch delay")
            && input.contains("run time")))
    {
        return Err("perf sched timehist did not contain a recognized scheduler report".into());
    }
    let threads: Vec<_> = threads.into_values().collect();
    Ok(PerfSchedSummary {
        method: OffcpuMethod::PerfSched,
        target_pid,
        scope: "workload_process_and_threads",
        total_wait_ms: threads.iter().map(|thread| thread.wait_ms).sum(),
        total_sched_delay_ms: threads.iter().map(|thread| thread.sched_delay_ms).sum(),
        total_run_ms: threads.iter().map(|thread| thread.run_ms).sum(),
        threads,
        timehist_raw: input,
    })
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
