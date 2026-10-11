use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::artifacts::ArtifactLayout;
use crate::backends::{BackendResult, ProfileRequest, ProfileResult, ProfilerBackend};
use crate::cli::PerfEvent;
use crate::flamegraph::{
    BuiltinFlamegraphRenderer, FlamegraphRenderer, FlamegraphRequest, INFERNO_DEFAULT_TITLE,
};
use crate::manifest::{BackendName, RunManifest};
use crate::perfdata::fold::{
    FoldOptions, fold_perfdata_file_with_options_and_origin,
    fold_perfdata_file_with_symbols_and_origin,
};
use crate::platform::{NativeThreadLister, ThreadLister};
use crate::process::{CommandOutput, CommandRunner, CommandSpec, FinalizationScope};
use crate::summary::threads::{
    FoldedStackSummary, render_folded_stack_summary_text, summarize_folded_stacks,
};
use crate::summary::{PerfProfileSummary, summarize_perfdata_profile_file_with_origin};
use crate::symbols::{SymbolizerKind, perf_symbol_resolver_for_current_home_with_symbolizer};
use crate::tools::{ADDR2LINE, PERF, ToolSpec, resolve_required_tools};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PerfRecordTarget {
    Command(Vec<String>),
    Process(u32),
    Threads(Vec<u32>),
}

#[derive(serde::Serialize)]
struct CpuProfileSummary<'a> {
    #[serde(flatten)]
    folded: &'a FoldedStackSummary,
    profile: &'a PerfProfileSummary,
}

impl<'a> CpuProfileSummary<'a> {
    fn new(folded: &'a FoldedStackSummary, profile: &'a PerfProfileSummary) -> Self {
        Self { folded, profile }
    }
}

pub fn build_perf_record_command(
    event: PerfEvent,
    frequency: u32,
    callgraph: &str,
    output: &Path,
    target: PerfRecordTarget,
    duration_secs: u32,
) -> CommandSpec {
    let mut command = CommandSpec::new("perf")
        .recording()
        .arg("record".to_string());
    if event != PerfEvent::Default {
        command = command.args(["-e".to_string(), event.to_string()]);
    }
    command = command.args([
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
        PerfRecordTarget::Command(profiled_command) => command.args(profiled_command).interactive(),
        PerfRecordTarget::Process(_) | PerfRecordTarget::Threads(_) => {
            command.args(["sleep".to_string(), duration_secs.to_string()])
        }
    }
}

pub struct LinuxPerfBackend<'a, R, T = NativeThreadLister, F = BuiltinFlamegraphRenderer> {
    runner: &'a R,
    thread_lister: T,
    flamegraph_renderer: F,
}

impl<'a, R> LinuxPerfBackend<'a, R, NativeThreadLister, BuiltinFlamegraphRenderer> {
    pub fn new(runner: &'a R) -> Self {
        Self {
            runner,
            thread_lister: NativeThreadLister::default(),
            flamegraph_renderer: BuiltinFlamegraphRenderer,
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

impl<'a, R, T> LinuxPerfBackend<'a, R, T, BuiltinFlamegraphRenderer> {
    pub fn with_thread_lister(runner: &'a R, thread_lister: T) -> Self {
        Self {
            runner,
            thread_lister,
            flamegraph_renderer: BuiltinFlamegraphRenderer,
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
        let started_at_unix_ms = unix_ms_now();
        let layout = ArtifactLayout::new(request.out_dir.clone());
        layout.prepare()?;
        let tool_versions = resolve_required_tools(
            self.runner,
            &linux_perf_tools(
                request.symbols,
                request.symbolizer,
                &self.flamegraph_renderer,
            ),
        )?;

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
        let command = if request.json {
            command.capture_output()
        } else {
            command
        };
        let output = self.runner.run(&command)?;
        check_perf_record_output(&output, &layout)?;
        let _finalization = FinalizationScope::enter();
        let (folded_stacks, profile_summary) = fold_and_summarize_perfdata(
            &perf_data,
            request.symbols,
            request.symbolizer,
            self.runner,
            1_000_000_000,
            20,
        )?;
        let folded_summary = summarize_folded_stacks(&folded_stacks);
        std::fs::write(layout.stacks_folded(), &folded_stacks)?;
        let flamegraph_output = match self.flamegraph_renderer.render(&FlamegraphRequest {
            title: INFERNO_DEFAULT_TITLE.to_string(),
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
        write_profile_summary(&layout, &profile_summary, &folded_summary)?;
        std::fs::write(layout.tool_errors_log(), "")?;

        let manifest = RunManifest {
            name: request.name.clone(),
            command: request.command.clone(),
            cwd: std::env::current_dir()?,
            profile_kind: request.kind,
            requested_backend: BackendName::LinuxPerf,
            actual_backend: BackendName::LinuxPerf,
            fallback_reason: None,
            platform: std::env::consts::OS.to_string(),
            started_at_unix_ms,
            ended_at_unix_ms: Some(unix_ms_now()),
            exit_status: output.status_code,
            requested_controls: request.requested_controls(),
            measurement: Some(crate::manifest::NativeMeasurement::Perf {
                frequency: request.frequency,
                event: request.event,
                call_graph: request.call_graph,
            }),
            record_target: record_target_label(request).to_string(),
            duration_secs: attach_duration(request),
            tool_versions,
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

        Ok(ProfileResult {
            completion: super::ProfileCompletion::from_recorder(
                output.status_code,
                self.runner.cancellation_signal(),
            ),
            layout,
            manifest,
        })
    }
}

fn check_perf_record_output(output: &CommandOutput, layout: &ArtifactLayout) -> BackendResult<()> {
    if !output.succeeded_or_interrupted() {
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
    Ok(())
}

fn write_profile_summary(
    layout: &ArtifactLayout,
    profile: &PerfProfileSummary,
    folded: &FoldedStackSummary,
) -> BackendResult<()> {
    use std::fmt::Write as _;

    let summary = CpuProfileSummary::new(folded, profile);
    let mut text = render_folded_stack_summary_text(folded);
    if let Some(span) = summary.profile.timeline.duration_ns {
        writeln!(text, "recorded sample span: {span} ns")?;
    } else {
        text.push_str("recorded sample span: unavailable\n");
    }
    for thread in &summary.profile.threads {
        writeln!(
            text,
            "thread {} ({}): {} samples, {} weighted samples",
            thread.tid, thread.comm, thread.samples, thread.weighted_samples
        )?;
    }
    std::fs::write(layout.summary_txt(), text)?;
    std::fs::write(
        layout.summary_json(),
        format!("{}\n", serde_json::to_string_pretty(&summary)?),
    )?;
    Ok(())
}

fn fold_and_summarize_perfdata<R: CommandRunner>(
    perf_data: &Path,
    symbols: bool,
    symbolizer: SymbolizerKind,
    runner: &R,
    bucket_width_ns: u64,
    limit: usize,
) -> BackendResult<(String, PerfProfileSummary)> {
    let options = FoldOptions {
        count_periods: true,
        inline: true,
    };
    let (folded, first_sample_ns) = if symbols {
        let resolver =
            perf_symbol_resolver_for_current_home_with_symbolizer(runner, perf_data, symbolizer);
        fold_perfdata_file_with_symbols_and_origin(perf_data, options, &resolver)?
    } else {
        fold_perfdata_file_with_options_and_origin(perf_data, options)?
    };
    let summary = summarize_perfdata_profile_file_with_origin(
        perf_data,
        bucket_width_ns,
        limit,
        first_sample_ns,
    )?;
    Ok((folded, summary))
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

fn linux_perf_tools(
    symbols: bool,
    symbolizer: SymbolizerKind,
    renderer: &impl FlamegraphRenderer,
) -> Vec<ToolSpec> {
    let mut tools = linux_perf_fold_tools(symbols, symbolizer);
    tools.extend(renderer.tool_specs());
    tools
}

pub(crate) fn linux_perf_fold_tools(symbols: bool, symbolizer: SymbolizerKind) -> Vec<ToolSpec> {
    let mut tools = vec![PERF];
    if symbols && symbolizer == SymbolizerKind::Addr2line {
        tools.push(ADDR2LINE);
    }
    tools
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perfdata::count_file_record_at_calls;
    use crate::perfdata::fold::fold_perfdata_file_with_options;
    use crate::process::CommandOutput;
    use crate::summary::summarize_perfdata_profile_file;

    struct TestRunner;

    impl CommandRunner for TestRunner {
        fn run(&self, _: &CommandSpec) -> std::io::Result<CommandOutput> {
            Ok(CommandOutput {
                status_code: Some(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }

    struct FixtureRunner(Vec<u8>);

    impl CommandRunner for FixtureRunner {
        fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
            if let Some([_, output]) = command.args.windows(2).find(|args| args[0] == "-o") {
                std::fs::write(output, &self.0)?;
            }
            TestRunner.run(command)
        }
    }

    #[test]
    fn public_backend_profile_preserves_outputs_and_traversal_counts() {
        use crate::cli::{PerfCallGraph, ProfileKind};

        for (bytes, records, fold_passes, first_sample_ns) in [
            (mixed_sample_perfdata(), 4, 1, 32),
            (dynamic_stream_fallback_perfdata(), 3, 2, 9),
        ] {
            let input = tempfile::NamedTempFile::new().expect("fixture file");
            std::fs::write(input.path(), &bytes).expect("write fixture");
            let expected_folded = fold_perfdata_file_with_options(
                input.path(),
                FoldOptions {
                    count_periods: true,
                    inline: true,
                },
            )
            .expect("standalone fold");
            let (expected_profile, standalone_visits) = count_file_record_at_calls(|| {
                summarize_perfdata_profile_file(input.path(), 1_000_000_000, 20)
                    .expect("standalone two-pass summary")
            });
            let out = tempfile::tempdir().expect("artifact directory");
            let request = ProfileRequest {
                kind: ProfileKind::Cpu,
                command: vec!["true".into()],
                out_dir: out.path().join("cpu"),
                name: None,
                json: false,
                symbols: false,
                symbolizer: SymbolizerKind::Addr2line,
                frequency: 99,
                event: PerfEvent::CpuClock,
                call_graph: PerfCallGraph::Fp,
                pid: None,
                tids: Vec::new(),
                threads_of_pid: None,
                duration_secs: 1,
                offcpu_method: None,
            };
            let runner = FixtureRunner(bytes);
            let backend = LinuxPerfBackend::new(&runner);
            let (result, visits) = count_file_record_at_calls(|| {
                backend.profile(&request).expect("public backend profile")
            });
            let folded =
                std::fs::read_to_string(result.layout.stacks_folded()).expect("read folded output");
            let summary: serde_json::Value = serde_json::from_slice(
                &std::fs::read(result.layout.summary_json()).expect("read summary JSON"),
            )
            .expect("parse summary JSON");

            assert_eq!(folded, expected_folded);
            assert_eq!(
                summary["profile"],
                serde_json::to_value(&expected_profile).unwrap()
            );
            assert_eq!(
                expected_profile.timeline.first_sample_ns,
                Some(first_sample_ns)
            );
            assert_eq!(standalone_visits, 2 * records);
            assert_eq!(visits, (fold_passes + 1) * records);
        }
    }

    #[test]
    fn profile_serialization_wrapper_reuses_owned_profile_storage() {
        let file = tempfile::NamedTempFile::new().expect("fixture file");
        std::fs::write(file.path(), mixed_sample_perfdata()).expect("write fixture");
        let mut profile = summarize_perfdata_profile_file(file.path(), 3, 20)
            .expect("standalone profile summary");
        profile.threads[0].cpus = vec![0, 2];
        let folded = summarize_folded_stacks("sample;frame 11\n");
        assert!(!profile.threads.is_empty());
        assert!(!profile.threads[0].comm.is_empty());
        assert!(!profile.threads[0].cpus.is_empty());
        assert!(!profile.timeline.buckets.is_empty());

        let summary = CpuProfileSummary::new(&folded, &profile);
        let mut expected = serde_json::to_value(&folded).expect("folded JSON");
        expected.as_object_mut().unwrap().insert(
            "profile".into(),
            serde_json::to_value(&profile).expect("profile JSON"),
        );
        assert_eq!(serde_json::to_value(&summary).unwrap(), expected);
        let out = tempfile::tempdir().expect("artifact directory");
        let layout = ArtifactLayout::new(out.path().to_path_buf());
        write_profile_summary(&layout, &profile, &folded).expect("write profile summary");
        let actual: serde_json::Value = serde_json::from_slice(
            &std::fs::read(layout.summary_json()).expect("read summary JSON"),
        )
        .expect("parse summary JSON");
        assert_eq!(actual, expected);

        assert!(
            std::ptr::eq(summary.profile.threads.as_ptr(), profile.threads.as_ptr()),
            "serialization wrapper must reuse the thread allocation"
        );
        assert!(std::ptr::eq(
            summary.profile.threads[0].comm.as_ptr(),
            profile.threads[0].comm.as_ptr()
        ));
        assert!(std::ptr::eq(
            summary.profile.threads[0].cpus.as_ptr(),
            profile.threads[0].cpus.as_ptr()
        ));
        assert!(std::ptr::eq(
            summary.profile.timeline.buckets.as_ptr(),
            profile.timeline.buckets.as_ptr()
        ));
    }

    #[test]
    fn combined_backend_summary_reuses_the_fold_record_traversal() {
        let file = tempfile::NamedTempFile::new().expect("fixture file");
        let fixture = tiny_timed_perfdata();
        std::fs::write(file.path(), &fixture).expect("write fixture");
        if let Some(path) = std::env::var_os("PYROC31_RED_FIXTURE") {
            std::fs::write(path, &fixture).expect("save RED fixture");
        }

        let runner = TestRunner;
        let expected_folded = fold_perfdata_file_with_options(
            file.path(),
            FoldOptions {
                count_periods: true,
                inline: true,
            },
        )
        .expect("legacy fold");
        let expected_profile = summarize_perfdata_profile_file(file.path(), 1_000_000_000, 20)
            .expect("legacy two-pass summary");

        let (actual, record_traversals) = count_file_record_at_calls(|| {
            fold_and_summarize_perfdata(
                file.path(),
                false,
                SymbolizerKind::Addr2line,
                &runner,
                1_000_000_000,
                20,
            )
            .expect("combined backend output")
        });

        assert_eq!(actual.0, expected_folded);
        assert_eq!(actual.1, expected_profile);
        assert_eq!(record_traversals, 2, "one fold plus one summary traversal");
    }

    #[test]
    fn combined_backend_traverses_each_mixed_sample_record_twice() {
        let bytes = mixed_sample_perfdata();
        let file = tempfile::NamedTempFile::new().expect("fixture file");
        std::fs::write(file.path(), &bytes).expect("write fixture");
        let runner = TestRunner;

        let expected_folded = fold_perfdata_file_with_options(
            file.path(),
            FoldOptions {
                count_periods: true,
                inline: true,
            },
        )
        .expect("legacy fold");
        let expected_profile =
            summarize_perfdata_profile_file(file.path(), 3, 20).expect("legacy two-pass summary");
        let (actual, record_traversals) = count_file_record_at_calls(|| {
            fold_and_summarize_perfdata(
                file.path(),
                false,
                SymbolizerKind::Addr2line,
                &runner,
                3,
                20,
            )
            .expect("combined backend output")
        });

        assert_eq!(actual.0, expected_folded);
        assert_eq!(actual.1, expected_profile);
        assert_eq!(actual.1.timeline.first_sample_ns, Some(32));
        assert_eq!(actual.1.timeline.bucket_width_ns, 3);
        assert_eq!(
            actual
                .1
                .timeline
                .buckets
                .iter()
                .map(|bucket| (bucket.start_offset_ns, bucket.samples))
                .collect::<Vec<_>>(),
            [(0, 3), (3, 1)]
        );
        assert_eq!(record_traversals, 2 * 4);
    }

    #[test]
    fn origin_fold_does_not_reparse_samples_for_metadata() {
        let bytes = mixed_sample_perfdata();
        let file = tempfile::NamedTempFile::new().expect("fixture file");
        std::fs::write(file.path(), &bytes).expect("write fixture");
        if let Some(path) = std::env::var_os("PYROC31_PARSER_RED_FIXTURE") {
            std::fs::write(path, &bytes).expect("save parser RED fixture");
        }

        let options = FoldOptions {
            count_periods: true,
            inline: true,
        };
        let expected_folded =
            fold_perfdata_file_with_options(file.path(), options).expect("standalone fold");
        let expected_profile =
            summarize_perfdata_profile_file(file.path(), 3, 20).expect("legacy summary");

        let ((folded, origin), metadata_parser_calls) =
            crate::perfdata::samples::count_sample_metadata_parser_calls(|| {
                fold_perfdata_file_with_options_and_origin(file.path(), options)
                    .expect("fold and collect origin")
            });
        let actual_profile =
            summarize_perfdata_profile_file_with_origin(file.path(), 3, 20, origin)
                .expect("summary seeded from fold");

        assert_eq!(folded, expected_folded);
        assert_eq!(actual_profile, expected_profile);
        assert_eq!(
            metadata_parser_calls, 0,
            "fold origin must not parse samples again"
        );
    }

    #[test]
    fn combined_backend_collects_origin_before_deferred_sample_delivery() {
        use crate::perfdata::samples::{
            PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_TID, PERF_SAMPLE_TIME,
        };

        let mut attr = [0_u8; 144];
        attr[4..8].copy_from_slice(&128_u32.to_le_bytes());
        attr[16..24].copy_from_slice(&1_u64.to_le_bytes());
        attr[24..32].copy_from_slice(
            &(PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN)
                .to_le_bytes(),
        );
        // perf evsel.c:3391 marks deferred callchains before queueing delivery.
        attr[40..48].copy_from_slice(&(1_u64 << 38).to_le_bytes());

        let mut payload = Vec::new();
        payload.extend(0x1000_u64.to_le_bytes());
        payload.extend(1_u32.to_le_bytes());
        payload.extend(2_u32.to_le_bytes());
        payload.extend(12_u64.to_le_bytes());
        payload.extend(3_u64.to_le_bytes());
        payload.extend(0x1000_u64.to_le_bytes());
        payload.extend(0xffff_ffff_ffff_fd80_u64.to_le_bytes());
        payload.extend(0x1040_u64.to_le_bytes());
        let bytes = perfdata(attr, vec![record(9, &payload)]);
        let file = tempfile::NamedTempFile::new().expect("fixture file");
        std::fs::write(file.path(), &bytes).expect("write fixture");
        let runner = TestRunner;

        let expected_folded = fold_perfdata_file_with_options(
            file.path(),
            FoldOptions {
                count_periods: true,
                inline: true,
            },
        )
        .expect("standalone fold");
        let expected_profile = summarize_perfdata_profile_file(file.path(), 3, 20)
            .expect("standalone two-pass summary");
        let (actual, record_traversals) = count_file_record_at_calls(|| {
            fold_and_summarize_perfdata(
                file.path(),
                false,
                SymbolizerKind::Addr2line,
                &runner,
                3,
                20,
            )
            .expect("combined backend output")
        });

        assert_eq!(actual.0, expected_folded);
        assert_eq!(actual.1, expected_profile);
        assert_eq!(actual.1.timeline.first_sample_ns, Some(12));
        assert_eq!(record_traversals, 2);
    }

    #[test]
    fn combined_backend_stream_parser_preserves_fold_origin() {
        use crate::perfdata::samples::{PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_TIME};

        let mut attr = [0_u8; 144];
        attr[4..8].copy_from_slice(&128_u32.to_le_bytes());
        attr[16..24].copy_from_slice(&3_u64.to_le_bytes());
        // Without TID, folding uses the whole-stream Inferno parser.
        attr[24..32].copy_from_slice(
            &(PERF_SAMPLE_IP | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN).to_le_bytes(),
        );
        let mut payload = Vec::new();
        payload.extend(0x1000_u64.to_le_bytes());
        payload.extend(21_u64.to_le_bytes());
        payload.extend(1_u64.to_le_bytes());
        payload.extend(0x1000_u64.to_le_bytes());
        let bytes = perfdata(attr, vec![record(9, &payload)]);
        let file = tempfile::NamedTempFile::new().expect("fixture file");
        std::fs::write(file.path(), &bytes).expect("write fixture");
        let runner = TestRunner;

        let expected_folded = fold_perfdata_file_with_options(
            file.path(),
            FoldOptions {
                count_periods: true,
                inline: true,
            },
        )
        .expect("standalone fold");
        let expected_profile = summarize_perfdata_profile_file(file.path(), 3, 20)
            .expect("standalone two-pass summary");
        let (actual, record_traversals) = count_file_record_at_calls(|| {
            fold_and_summarize_perfdata(
                file.path(),
                false,
                SymbolizerKind::Addr2line,
                &runner,
                3,
                20,
            )
            .expect("combined backend output")
        });

        assert_eq!(actual.0, expected_folded);
        assert_eq!(actual.1, expected_profile);
        assert_eq!(actual.1.timeline.first_sample_ns, Some(21));
        assert_eq!(record_traversals, 2);
    }

    #[test]
    fn folded_origin_matches_metadata_only_samples_and_native_time_sentinels() {
        use crate::perfdata::samples::{PERF_SAMPLE_TID, PERF_SAMPLE_TIME};

        // The earlier timestamp is physically later; zero and ~0ULL bypass
        // ordered-events queuing per ordered-events.c:199-200 but remain metadata.
        for times in [[20, 10], [u64::MAX, 0]] {
            let bytes = metadata_only_perfdata(PERF_SAMPLE_TID | PERF_SAMPLE_TIME, 7, true, &times);
            let file = tempfile::NamedTempFile::new().expect("fixture file");
            std::fs::write(file.path(), &bytes).expect("write fixture");

            let (folded, origin) = fold_perfdata_file_with_options_and_origin(
                file.path(),
                FoldOptions {
                    count_periods: true,
                    inline: true,
                },
            )
            .expect("fold plus origin");
            let expected_folded = fold_perfdata_file_with_options(
                file.path(),
                FoldOptions {
                    count_periods: true,
                    inline: true,
                },
            )
            .expect("standalone fold");
            let expected_profile = summarize_perfdata_profile_file(file.path(), 3, 20)
                .expect("standalone two-pass summary");
            let actual_profile =
                summarize_perfdata_profile_file_with_origin(file.path(), 3, 20, origin)
                    .expect("one-pass summary with fold origin");

            assert_eq!(folded, expected_folded);
            assert_eq!(actual_profile, expected_profile);
            assert_eq!(actual_profile.weighted_samples, 14);
            assert_eq!(
                actual_profile.timeline.first_sample_ns,
                Some(times.into_iter().min().unwrap())
            );
            assert_eq!(
                actual_profile
                    .timeline
                    .buckets
                    .iter()
                    .map(|bucket| bucket.start_offset_ns)
                    .collect::<Vec<_>>(),
                if times == [20, 10] {
                    vec![0, 9]
                } else {
                    vec![0, u64::MAX / 3 * 3]
                }
            );
        }
    }

    #[test]
    fn folded_origin_stays_absent_for_untimed_samples_and_preserves_lost_counts() {
        use crate::perfdata::samples::PERF_SAMPLE_TID;

        let bytes = metadata_only_perfdata(PERF_SAMPLE_TID, 9, false, &[0]);
        let mut bytes = bytes;
        let lost = record(2, &[4_u64.to_le_bytes(), 5_u64.to_le_bytes()].concat());
        let data_size = u64::from_le_bytes(bytes[48..56].try_into().unwrap()) + lost.len() as u64;
        bytes.extend(lost);
        bytes[48..56].copy_from_slice(&data_size.to_le_bytes());
        let file = tempfile::NamedTempFile::new().expect("fixture file");
        std::fs::write(file.path(), &bytes).expect("write fixture");

        let (_, origin) = fold_perfdata_file_with_options_and_origin(
            file.path(),
            FoldOptions {
                count_periods: true,
                inline: true,
            },
        )
        .expect("fold plus origin");
        let expected = summarize_perfdata_profile_file(file.path(), 3, 20)
            .expect("standalone two-pass summary");
        let actual = summarize_perfdata_profile_file_with_origin(file.path(), 3, 20, origin)
            .expect("one-pass summary with fold origin");

        assert_eq!(origin, None);
        assert_eq!(actual, expected);
        assert_eq!(actual.weighted_samples, 9);
        assert_eq!(actual.lost_records, 5);
        assert_eq!(actual.timeline.untimed_samples, 1);
    }

    fn tiny_timed_perfdata() -> Vec<u8> {
        use crate::perfdata::samples::{
            PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_TID, PERF_SAMPLE_TIME,
        };

        let mut attr = [0_u8; 144];
        attr[4..8].copy_from_slice(&128_u32.to_le_bytes());
        attr[16..24].copy_from_slice(&1_u64.to_le_bytes());
        attr[24..32].copy_from_slice(
            &(PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN)
                .to_le_bytes(),
        );
        let mut payload = Vec::new();
        payload.extend(0x1000_u64.to_le_bytes());
        payload.extend(1_u32.to_le_bytes());
        payload.extend(2_u32.to_le_bytes());
        payload.extend(12_u64.to_le_bytes());
        payload.extend(1_u64.to_le_bytes());
        payload.extend(0x1000_u64.to_le_bytes());
        let mut record = Vec::new();
        record.extend(9_u32.to_le_bytes());
        record.extend(0_u16.to_le_bytes());
        record.extend(u16::try_from(payload.len() + 8).unwrap().to_le_bytes());
        record.extend(payload);

        let mut bytes = vec![0; 104];
        bytes[..8].copy_from_slice(b"PERFILE2");
        bytes[8..16].copy_from_slice(&104_u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&104_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&144_u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&248_u64.to_le_bytes());
        bytes[48..56].copy_from_slice(&(record.len() as u64).to_le_bytes());
        bytes.extend(attr);
        bytes.extend(record);
        bytes
    }

    fn dynamic_stream_fallback_perfdata() -> Vec<u8> {
        let mut bytes = tiny_timed_perfdata();
        let mut late_sample = bytes[248..].to_vec();
        late_sample[24..32].copy_from_slice(&9_u64.to_le_bytes());
        let mut comm = Vec::new();
        comm.extend(1_u32.to_le_bytes());
        comm.extend(2_u32.to_le_bytes());
        // Inferno perf.rs:process_single_stack skips # headers; this COMM
        // requests stream replay only after the first normal sample was folded.
        comm.extend(b"#comment\0");
        bytes.extend(record(3, &comm));
        bytes.extend(late_sample);
        let data_size = bytes.len() as u64 - 248;
        bytes[48..56].copy_from_slice(&data_size.to_le_bytes());
        bytes
    }

    fn metadata_only_perfdata(
        sample_type: u64,
        default_period: u64,
        sample_id_all: bool,
        times: &[u64],
    ) -> Vec<u8> {
        let mut attr = [0_u8; 144];
        attr[4..8].copy_from_slice(&128_u32.to_le_bytes());
        // evsel.c:evsel__parse_sample initializes omitted PERIOD from attr.sample_period.
        attr[16..24].copy_from_slice(&default_period.to_le_bytes());
        attr[24..32].copy_from_slice(&sample_type.to_le_bytes());
        if sample_id_all {
            attr[40..48].copy_from_slice(&(1_u64 << 18).to_le_bytes());
        }
        let records = times
            .iter()
            .map(|time| {
                let mut payload = Vec::new();
                if sample_type & crate::perfdata::samples::PERF_SAMPLE_TID != 0 {
                    payload.extend(1_u32.to_le_bytes());
                    payload.extend(2_u32.to_le_bytes());
                }
                if sample_type & crate::perfdata::samples::PERF_SAMPLE_TIME != 0 {
                    payload.extend(time.to_le_bytes());
                }
                record(9, &payload)
            })
            .collect::<Vec<_>>();
        perfdata(attr, records)
    }

    fn mixed_sample_perfdata() -> Vec<u8> {
        use crate::perfdata::samples::{
            PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IDENTIFIER, PERF_SAMPLE_IP, PERF_SAMPLE_TID,
            PERF_SAMPLE_TIME,
        };

        let metadata_type = PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
        let rendered_type = metadata_type | PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
        let ids_offset: u64 = 104 + 2 * 144;
        let attrs = [
            mixed_attr(metadata_type, 5, ids_offset),
            mixed_attr(rendered_type, 2, ids_offset + 8),
        ];
        let records = [
            mixed_sample(22, Some(0x1000), 37),
            mixed_sample(11, None, 32),
            mixed_sample(22, Some(0x1000), 34),
            mixed_sample(22, Some(0x1000), 34),
        ];
        let data_offset = ids_offset + 16;
        let data_size = records.iter().map(Vec::len).sum::<usize>();
        let mut bytes = vec![0; 104];
        bytes[..8].copy_from_slice(b"PERFILE2");
        bytes[8..16].copy_from_slice(&104_u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&104_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&288_u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&data_offset.to_le_bytes());
        bytes[48..56].copy_from_slice(&(data_size as u64).to_le_bytes());
        bytes.extend(attrs.into_iter().flatten());
        bytes.extend(11_u64.to_le_bytes());
        bytes.extend(22_u64.to_le_bytes());
        for record in records {
            bytes.extend(record);
        }
        bytes
    }

    fn mixed_attr(sample_type: u64, default_period: u64, ids_offset: u64) -> Vec<u8> {
        let mut attr = vec![0; 144];
        attr[4..8].copy_from_slice(&128_u32.to_le_bytes());
        attr[16..24].copy_from_slice(&default_period.to_le_bytes());
        attr[24..32].copy_from_slice(&sample_type.to_le_bytes());
        attr[40..48].copy_from_slice(&(1_u64 << 18).to_le_bytes());
        attr[128..136].copy_from_slice(&ids_offset.to_le_bytes());
        attr[136..144].copy_from_slice(&8_u64.to_le_bytes());
        attr
    }

    fn mixed_sample(id: u64, ip: Option<u64>, time: u64) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend(id.to_le_bytes());
        if let Some(ip) = ip {
            payload.extend(ip.to_le_bytes());
        }
        payload.extend(1_u32.to_le_bytes());
        payload.extend(2_u32.to_le_bytes());
        payload.extend(time.to_le_bytes());
        if let Some(ip) = ip {
            payload.extend(1_u64.to_le_bytes());
            payload.extend(ip.to_le_bytes());
        }
        record(9, &payload)
    }

    fn perfdata(attr: [u8; 144], records: Vec<Vec<u8>>) -> Vec<u8> {
        let data_offset = 248_u64;
        let data_size = records.iter().map(Vec::len).sum::<usize>();
        let mut bytes = vec![0; 104];
        bytes[..8].copy_from_slice(b"PERFILE2");
        bytes[8..16].copy_from_slice(&104_u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&104_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&144_u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&data_offset.to_le_bytes());
        bytes[48..56].copy_from_slice(&(data_size as u64).to_le_bytes());
        bytes.extend(attr);
        for record in records {
            bytes.extend(record);
        }
        bytes
    }

    fn record(record_type: u32, payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(payload.len() + 8);
        record.extend(record_type.to_le_bytes());
        record.extend(0_u16.to_le_bytes());
        record.extend(u16::try_from(payload.len() + 8).unwrap().to_le_bytes());
        record.extend(payload);
        record
    }
}
