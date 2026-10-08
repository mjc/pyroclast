use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::artifacts::ArtifactLayout;
use crate::backends::{BackendResult, ProfileRequest, ProfileResult, ProfilerBackend};
use crate::cli::{
    DEFAULT_PROFILE_DURATION_SECS, DEFAULT_SAMPLE_FREQUENCY, PerfCallGraph, PerfEvent, ProfileKind,
    SymbolizerKind,
};
use crate::manifest::{BackendName, RunManifest};
use crate::parsers::xctrace::{parse_cpu_profile_for_pid, render_cpu_profile_summary_text};
use crate::process::CommandRunner;
use crate::process::CommandSpec;
use crate::tools::{XCTRACE, resolve_required_tools};

pub const XCTRACE_PID_ENV: &str = "PYROCLAST_XCTRACE_TARGET_PID";

pub fn build_xctrace_record_command(
    trace_path: &Path,
    target_pid_path: &Path,
    profiled_command: impl IntoIterator<Item = String>,
) -> CommandSpec {
    CommandSpec::new("xctrace")
        .recording()
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
        .interactive()
}

#[must_use]
pub fn build_xctrace_export_cpu_command(trace_path: &Path, output_xml: &Path) -> CommandSpec {
    CommandSpec::new("xctrace").finalization().args([
        "export".to_string(),
        "--input".to_string(),
        trace_path.display().to_string(),
        "--output".to_string(),
        output_xml.display().to_string(),
        "--xpath".to_string(),
        "//table[@schema=\"cpu-profile\" or @schema=\"time-profile\"]".to_string(),
    ])
}

pub struct MacosXctraceBackend<'a, R> {
    runner: &'a R,
}

impl<'a, R> MacosXctraceBackend<'a, R> {
    #[must_use]
    pub fn new(runner: &'a R) -> Self {
        Self { runner }
    }
}

impl<R> ProfilerBackend for MacosXctraceBackend<'_, R>
where
    R: CommandRunner,
{
    fn profile(&self, request: &ProfileRequest) -> BackendResult<ProfileResult> {
        let started_at_unix_ms = unix_ms_now();
        let layout = ArtifactLayout::new(request.out_dir.clone());
        layout.prepare()?;
        request.ensure_command_target("macos_xctrace")?;
        validate_controls(request)?;
        let tool_versions = resolve_required_tools(self.runner, &[XCTRACE])?;

        let trace_path = layout.raw_profile("xctrace.trace");
        let target_pid_path = layout.root().join("xctrace-target.pid");
        let record_command =
            build_xctrace_record_command(&trace_path, &target_pid_path, request.command.clone());
        let record_command = if request.json {
            record_command.capture_output()
        } else {
            record_command
        };
        let record_output = self.runner.run(&record_command)?;
        std::fs::write(layout.stdout_log(), &record_output.stdout)?;
        std::fs::write(layout.stderr_log(), &record_output.stderr)?;
        std::fs::write(
            layout.command_txt(),
            format!("{}\n", request.command.join(" ")),
        )?;

        if record_output.status_code != Some(0) {
            let error = format!(
                "xctrace record exited with {:?}: {}",
                record_output.status_code,
                String::from_utf8_lossy(&record_output.stderr)
            );
            std::fs::write(layout.tool_errors_log(), format!("{error}\n"))?;
            return Err(error.into());
        }

        let xml_path = layout.raw_profile("xctrace.xml");
        let export_output = self
            .runner
            .run(&build_xctrace_export_cpu_command(&trace_path, &xml_path))?;
        if export_output.status_code != Some(0) {
            let error = format!(
                "xctrace export exited with {:?}: {}",
                export_output.status_code,
                String::from_utf8_lossy(&export_output.stderr)
            );
            std::fs::write(layout.tool_errors_log(), format!("{error}\n"))?;
            return Err(error.into());
        }

        let target_pid: u32 = std::fs::read_to_string(&target_pid_path)
            .map_err(|error| format!("could not read xctrace workload PID: {error}"))?
            .trim()
            .parse()
            .map_err(|error| format!("invalid xctrace workload PID: {error}"))?;
        let profile =
            parse_cpu_profile_for_pid(&std::fs::read_to_string(&xml_path)?, Some(target_pid))?;
        std::fs::write(
            layout.summary_txt(),
            render_cpu_profile_summary_text(&profile),
        )?;
        std::fs::write(
            layout.summary_json(),
            format!("{}\n", serde_json::to_string_pretty(&profile)?),
        )?;
        std::fs::write(layout.tool_errors_log(), "")?;

        let manifest = RunManifest {
            name: request.name.clone(),
            command: request.command.clone(),
            cwd: std::env::current_dir()?,
            profile_kind: request.kind,
            requested_backend: BackendName::MacosXctrace,
            actual_backend: BackendName::MacosXctrace,
            fallback_reason: None,
            platform: "macos".to_string(),
            started_at_unix_ms,
            ended_at_unix_ms: Some(unix_ms_now()),
            exit_status: record_output.status_code,
            requested_controls: request.requested_controls(),
            measurement: Some(crate::manifest::NativeMeasurement::Xctrace {
                template: "CPU Profiler".into(),
                weight_unit: profile.weight_unit,
            }),
            record_target: "command".to_string(),
            duration_secs: None,
            tool_versions,
            artifacts: {
                let mut artifacts = layout.standard_manifest_artifacts();
                artifacts.push(trace_path);
                artifacts.push(xml_path);
                artifacts
            },
            diagnostics: vec!["xctrace record/export executed".to_string()],
        };
        std::fs::write(layout.run_json(), serde_json::to_string_pretty(&manifest)?)?;

        Ok(ProfileResult {
            completion: super::ProfileCompletion::from_recorder(
                record_output.status_code,
                self.runner.cancellation_signal(),
            ),
            layout,
            manifest,
        })
    }
}

fn validate_controls(request: &ProfileRequest) -> BackendResult<()> {
    if request.kind != ProfileKind::Cpu {
        return Err("macos_xctrace supports CPU profiling only".into());
    }
    // Shared CLI defaults select the native template, not equivalent perf settings.
    let unsupported = if request.frequency != DEFAULT_SAMPLE_FREQUENCY {
        Some("--frequency")
    } else if request.event != PerfEvent::Default {
        Some("--event")
    } else if request.call_graph != PerfCallGraph::Dwarf {
        Some("--call-graph")
    } else if !request.symbols {
        Some("--no-symbols")
    } else if request.symbolizer != SymbolizerKind::RustAddr2line {
        Some("--symbolizer")
    } else if request.duration_secs != DEFAULT_PROFILE_DURATION_SECS {
        Some("--duration-secs")
    } else if request.offcpu_method.is_some() {
        Some("--offcpu-method")
    } else {
        None
    };
    if let Some(control) = unsupported {
        return Err(format!("macos_xctrace does not support overriding {control}; CPU Profiler controls sampling, unwinding, and symbolication").into());
    }
    Ok(())
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
