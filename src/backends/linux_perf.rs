use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::artifacts::ArtifactLayout;
use crate::backends::{BackendResult, ProfileRequest, ProfileResult, ProfilerBackend};
use crate::cli::PerfEvent;
use crate::flamegraph::{FlamegraphRenderer, FlamegraphRequest, InfernoFlamegraphRenderer};
use crate::manifest::{BackendName, RunManifest};
use crate::perfdata::fold::{
    FoldOptions, fold_perfdata_file_with_options, fold_perfdata_file_with_symbols,
};
use crate::platform::{NativeThreadLister, ThreadLister};
use crate::process::{CommandRunner, CommandSpec};
use crate::summary::threads::{render_folded_stack_summary_text, summarize_folded_stacks};
use crate::symbols::PerfSymbolResolver;
use crate::tools::{ToolSpec, collect_tool_versions};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PerfRecordTarget {
    Command(Vec<String>),
    Process(u32),
    Threads(Vec<u32>),
}

pub fn build_perf_record_command(
    event: PerfEvent,
    frequency: u32,
    callgraph: &str,
    output: &Path,
    target: PerfRecordTarget,
    duration_secs: u32,
) -> CommandSpec {
    let mut command = CommandSpec::new("perf").args([
        "record".to_string(),
        "-e".to_string(),
        event.to_string(),
        "-F".to_string(),
        frequency.to_string(),
        "-g".to_string(),
        "--call-graph".to_string(),
        callgraph.to_string(),
    ]);

    command = match &target {
        PerfRecordTarget::Command(_) => command,
        PerfRecordTarget::Process(pid) => command.args(["-p".to_string(), pid.to_string()]),
        PerfRecordTarget::Threads(tids) => command.args([
            "-t".to_string(),
            tids.iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ]),
    };

    command = command.args([
        "-o".to_string(),
        output.display().to_string(),
        "--".to_string(),
    ]);

    match target {
        PerfRecordTarget::Command(profiled_command) => command.args(profiled_command),
        PerfRecordTarget::Process(_) | PerfRecordTarget::Threads(_) => {
            command.args(["sleep".to_string(), duration_secs.to_string()])
        }
    }
}

pub struct LinuxPerfBackend<'a, R, T = NativeThreadLister, F = InfernoFlamegraphRenderer<'a, R>> {
    runner: &'a R,
    thread_lister: T,
    flamegraph_renderer: F,
}

impl<'a, R> LinuxPerfBackend<'a, R, NativeThreadLister, InfernoFlamegraphRenderer<'a, R>> {
    pub fn new(runner: &'a R) -> Self {
        Self {
            runner,
            thread_lister: NativeThreadLister::default(),
            flamegraph_renderer: InfernoFlamegraphRenderer::new(runner),
        }
    }

    pub fn with_renderer<F>(
        runner: &'a R,
        flamegraph_renderer: F,
    ) -> LinuxPerfBackend<'a, R, NativeThreadLister, F> {
        LinuxPerfBackend {
            runner,
            thread_lister: NativeThreadLister::default(),
            flamegraph_renderer,
        }
    }
}

impl<'a, R, T> LinuxPerfBackend<'a, R, T, InfernoFlamegraphRenderer<'a, R>> {
    pub fn with_thread_lister(runner: &'a R, thread_lister: T) -> Self {
        Self {
            runner,
            thread_lister,
            flamegraph_renderer: InfernoFlamegraphRenderer::new(runner),
        }
    }
}

impl<R, T, F> ProfilerBackend for LinuxPerfBackend<'_, R, T, F>
where
    R: CommandRunner,
    T: ThreadLister,
    F: FlamegraphRenderer,
{
    fn profile(&self, request: &ProfileRequest) -> BackendResult<ProfileResult> {
        let layout = ArtifactLayout::new(request.out_dir.clone());
        std::fs::create_dir_all(layout.root())?;

        let perf_data = layout.raw_profile("perf.data");
        let call_graph = request.call_graph.to_string();
        let target = self.perf_record_target(request)?;
        let command = build_perf_record_command(
            request.event,
            request.frequency,
            &call_graph,
            &perf_data,
            target.clone(),
            request.duration_secs,
        );
        let output = self.runner.run(&command)?;
        if output.status_code != Some(0) {
            std::fs::write(layout.stdout_log(), &output.stdout)?;
            std::fs::write(layout.stderr_log(), &output.stderr)?;
            let error = format!(
                "perf record exited with {:?}: {}",
                output.status_code,
                String::from_utf8_lossy(&output.stderr)
            );
            std::fs::write(layout.tool_errors_log(), format!("{error}\n"))?;
            return Err(error.into());
        }
        let folded_stacks = fold_linux_perfdata(&perf_data, request.symbols, self.runner)?;
        let folded_summary = summarize_folded_stacks(&folded_stacks);
        std::fs::write(layout.stacks_folded(), &folded_stacks)?;
        let flamegraph_output = match self.flamegraph_renderer.render(&FlamegraphRequest {
            title: "CPU profile".to_string(),
            folded_stacks,
            output: layout.flamegraph_svg(),
        }) {
            Ok(output) => output,
            Err(error) => {
                std::fs::write(layout.tool_errors_log(), format!("{error}\n"))?;
                return Err(error);
            }
        };

        std::fs::write(layout.stdout_log(), &output.stdout)?;
        let mut stderr = output.stderr;
        stderr.extend(flamegraph_output.stderr);
        std::fs::write(layout.stderr_log(), &stderr)?;
        std::fs::write(layout.command_txt(), command_text(request, &target))?;
        std::fs::write(
            layout.summary_txt(),
            render_folded_stack_summary_text(&folded_summary),
        )?;
        std::fs::write(
            layout.summary_json(),
            format!("{}\n", serde_json::to_string_pretty(&folded_summary)?),
        )?;
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
            sample_frequency: request.frequency,
            sample_event: request.event,
            call_graph: request.call_graph,
            record_target: record_target_label(request).to_string(),
            duration_secs: attach_duration(request),
            symbols: request.symbols,
            tool_versions: collect_tool_versions(
                self.runner,
                &linux_perf_tools(request.symbols, &self.flamegraph_renderer),
            ),
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

impl<R, T, F> LinuxPerfBackend<'_, R, T, F>
where
    T: ThreadLister,
{
    fn perf_record_target(&self, request: &ProfileRequest) -> BackendResult<PerfRecordTarget> {
        if let Some(pid) = request.pid {
            Ok(PerfRecordTarget::Process(pid))
        } else if let Some(pid) = request.threads_of_pid {
            Ok(PerfRecordTarget::Threads(
                self.thread_lister.thread_ids(pid)?,
            ))
        } else if request.tids.is_empty() {
            Ok(PerfRecordTarget::Command(request.command.clone()))
        } else {
            Ok(PerfRecordTarget::Threads(request.tids.clone()))
        }
    }
}

fn record_target_label(request: &ProfileRequest) -> &'static str {
    if request.pid.is_some() {
        "process"
    } else if request.threads_of_pid.is_some() {
        "threads_of_pid"
    } else if request.tids.is_empty() {
        "command"
    } else {
        "threads"
    }
}

fn attach_duration(request: &ProfileRequest) -> Option<u32> {
    if request.pid.is_some() || request.threads_of_pid.is_some() || !request.tids.is_empty() {
        Some(request.duration_secs)
    } else {
        None
    }
}

fn command_text(request: &ProfileRequest, target: &PerfRecordTarget) -> String {
    if let Some(pid) = request.pid {
        format!("pid:{pid}\n")
    } else if let Some(pid) = request.threads_of_pid {
        format!(
            "threads-of-pid:{pid} tids:{}\n",
            target
                .thread_ids()
                .map(|tid| tid.to_string())
                .collect::<Vec<_>>()
                .join(",")
        )
    } else if request.tids.is_empty() {
        format!("{}\n", request.command.join(" "))
    } else {
        format!(
            "tids:{}\n",
            request
                .tids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

impl PerfRecordTarget {
    fn thread_ids(&self) -> impl Iterator<Item = u32> + '_ {
        match self {
            Self::Threads(tids) => tids.iter().copied(),
            Self::Command(_) | Self::Process(_) => [].iter().copied(),
        }
    }
}

fn linux_perf_tools(symbols: bool, renderer: &impl FlamegraphRenderer) -> Vec<ToolSpec> {
    let mut tools = vec![ToolSpec::nix_managed("perf")];
    tools.extend(renderer.tool_specs());
    if symbols {
        tools.push(ToolSpec::nix_managed("addr2line"));
    }
    tools
}

fn fold_linux_perfdata<R>(perf_data: &Path, symbols: bool, runner: &R) -> BackendResult<String>
where
    R: CommandRunner,
{
    let options = FoldOptions {
        count_periods: true,
    };
    if symbols {
        let symbol_resolver = PerfSymbolResolver::new(runner).with_system_kallsyms();
        Ok(fold_perfdata_file_with_symbols(
            perf_data,
            options,
            &symbol_resolver,
        )?)
    } else {
        Ok(fold_perfdata_file_with_options(perf_data, options)?)
    }
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
