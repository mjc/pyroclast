use object::{Object, ObjectSegment, ObjectSymbol};
use pyroclast::perfdata::records::PERF_RECORD_FORK;
use pyroclast::perfdata::samples::{
    PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_CPU, PERF_SAMPLE_IDENTIFIER, PERF_SAMPLE_IP,
    PERF_SAMPLE_PERIOD, PERF_SAMPLE_TID, PERF_SAMPLE_TIME,
};
use std::sync::Mutex;

#[test]
fn top_level_memory_command_uses_injected_heaptrack_runner() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("memory-run");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "memory",
        "--out",
        out.to_str().expect("utf8 path"),
        "--",
        "cargo",
        "check",
    ]);

    pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, "linux").expect("run cli");

    assert!(out.join("run.json").is_file());
    assert!(out.join("command.txt").is_file());
    assert_eq!(
        std::fs::read_to_string(out.join("command.txt")).unwrap(),
        "cargo check\n"
    );
    assert_eq!(runner.programs(), vec!["heaptrack", "heaptrack_print"]);
    assert!(runner.commands().iter().any(|command| {
        command.program == "heaptrack"
            && command.args.first().map(String::as_str) == Some("--record-only")
    }));
    let run_json = std::fs::read_to_string(out.join("run.json")).expect("run json");
    assert!(run_json.contains("\"actual_backend\": \"heaptrack\""));
    assert!(out.join("profile.raw.heaptrack").is_file());
    let summary_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("summary.json")).unwrap())
            .expect("summary json");
    assert_eq!(summary_json["total_allocations"], 42);
    assert_eq!(summary_json["peak_heap_bytes"], 1024);
}

#[test]
fn fold_command_reads_perfdata_directly() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [
                record_bytes(3, &comm_payload(1, 2, "app")),
                record_bytes(1, &mmap_payload(1, 2, 0x1000, 0x2000, 0, "/bin/app")),
                record_bytes(9, &sample_payload(0x1000, 1, 2, [0x2000])),
            ],
        ),
    )
    .expect("write perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "fold",
        "--no-symbols",
        perfdata.to_str().unwrap(),
    ])
    .expect("fold command");

    assert_eq!(output.stdout, "app;[app] 1\n");
}

#[test]
fn profiling_json_returns_named_run_and_artifact_paths() {
    let root = tempfile::tempdir().unwrap();
    let out = root.path().join("named");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "latency",
        "--json",
        "--name",
        "native-service",
        "--out",
        out.to_str().unwrap(),
        "--",
        "service",
        "--foreground",
    ]);
    let output = pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, "linux").unwrap();
    let result: serde_json::Value = serde_json::from_str(&output.stdout).expect("JSON result");
    assert_eq!(result["name"], "native-service");
    assert_eq!(result["actual_backend"], "strace");
    assert_eq!(
        result["command"],
        serde_json::json!(["service", "--foreground"])
    );
    assert!(
        result["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| path.as_str().unwrap().ends_with("summary.json"))
    );
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("run.json")).unwrap()).unwrap();
    assert_eq!(saved["name"], "native-service");
}

#[test]
fn unsupported_attach_is_rejected_before_launching_a_command() {
    for (kind, platform) in [
        ("memory", "linux"),
        ("latency", "linux"),
        ("cpu", "macos"),
        ("offcpu", "linux"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let runner = RecordingRunner::default();
        let cli = pyroclast::cli::Cli::parse_from([
            "pyroclast",
            kind,
            "--pid",
            "4294967295",
            "--out",
            root.path().to_str().unwrap(),
            "--",
            "must-not-run",
        ]);
        let error = pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, platform)
            .expect_err("unsupported target");
        assert!(error.to_string().contains("attach"), "{error}");
        assert!(runner.programs().is_empty());
    }
}

struct WithoutPerf(RecordingRunner);

#[test]
fn failed_automatic_selection_invalidates_previous_success() {
    struct MissingRecorders;
    impl pyroclast::process::CommandRunner for MissingRecorders {
        fn run(
            &self,
            _: &pyroclast::process::CommandSpec,
        ) -> std::io::Result<pyroclast::process::CommandOutput> {
            panic!("missing recorders must not launch a workload")
        }
        fn resolve_tool(
            &self,
            _: &pyroclast::tools::ToolSpec,
        ) -> std::io::Result<pyroclast::tools::ResolvedTool> {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "missing recorder",
            ))
        }
    }
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("run.json"), "old success").unwrap();
    std::fs::write(root.path().join("summary.json"), "old summary").unwrap();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "offcpu",
        "--out",
        root.path().to_str().unwrap(),
        "--",
        "must-not-run",
    ]);
    let error = pyroclast::run_parsed_cli_with_runner_on_platform(cli, &MissingRecorders, "linux")
        .unwrap_err();
    assert!(error.to_string().contains("missing recorder"));
    assert!(!root.path().join("run.json").exists());
    assert!(!root.path().join("summary.json").exists());
}

#[test]
fn failed_json_profile_returns_machine_readable_error_and_nonzero_status() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pyroclast"))
        .args([
            "cpu",
            "--json",
            "--offcpu-method",
            "bpftrace",
            "--",
            "must-not-run",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON failure");
    assert_eq!(error["status"], "failed");
    assert!(error["error"].as_str().unwrap().contains("offcpu-method"));
}

#[test]
fn cargo_json_build_failure_returns_machine_readable_error() {
    let root = tempfile::tempdir().unwrap();
    let out = root.path().join("run");
    std::fs::create_dir(&out).unwrap();
    std::fs::write(out.join("run.json"), "old success").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cargo-pyroclast"))
        .args(["pyroclast", "cpu", "--json", "--manifest-path"])
        .arg(root.path().join("missing.toml"))
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON failure");
    assert_eq!(error["status"], "failed");
    assert!(!error["error"].as_str().unwrap().is_empty());
    assert!(!out.join("run.json").exists());
}

impl pyroclast::process::CommandRunner for WithoutPerf {
    fn run(
        &self,
        command: &pyroclast::process::CommandSpec,
    ) -> std::io::Result<pyroclast::process::CommandOutput> {
        pyroclast::process::CommandRunner::run(&self.0, command)
    }

    fn resolve_tool(
        &self,
        tool: &pyroclast::tools::ToolSpec,
    ) -> std::io::Result<pyroclast::tools::ResolvedTool> {
        if tool.name == "perf" {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "perf unavailable",
            ))
        } else {
            Ok(pyroclast::tools::ResolvedTool::bare(tool))
        }
    }
}

#[test]
fn blocked_and_async_profiles_choose_available_native_tracing_automatically() {
    for kind in ["offcpu", "async"] {
        let root = tempfile::tempdir().unwrap();
        let runner = WithoutPerf(RecordingRunner::default());
        let cli = pyroclast::cli::Cli::parse_from([
            "pyroclast",
            kind,
            "--out",
            root.path().to_str().unwrap(),
            "--",
            "native-service",
        ]);
        pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, "linux").unwrap();
        assert_eq!(runner.0.programs(), vec!["bpftrace", "bpftrace"]);
        let summary: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.path().join("summary.json")).unwrap())
                .unwrap();
        assert_eq!(summary["method"], "bpftrace");
        assert!(
            !std::fs::read_to_string(root.path().join("stacks.folded"))
                .unwrap()
                .is_empty()
        );
    }
}

struct DeniedPerf {
    recording: RecordingRunner,
    bpftrace_available: bool,
    bpftrace_permitted: bool,
}

impl pyroclast::process::CommandRunner for DeniedPerf {
    fn run(
        &self,
        command: &pyroclast::process::CommandSpec,
    ) -> std::io::Result<pyroclast::process::CommandOutput> {
        if command.program == "perf" {
            self.recording
                .commands
                .lock()
                .unwrap()
                .push(command.clone());
            return Ok(pyroclast::process::CommandOutput {
                status_code: Some(255),
                stdout: Vec::new(),
                stderr: b"sched tracepoints are not permitted".to_vec(),
            });
        }
        if command.program == "bpftrace" && !self.bpftrace_permitted {
            self.recording
                .commands
                .lock()
                .unwrap()
                .push(command.clone());
            return Ok(pyroclast::process::CommandOutput {
                status_code: Some(1),
                stdout: Vec::new(),
                stderr: b"kernel stack helper is not permitted".to_vec(),
            });
        }
        pyroclast::process::CommandRunner::run(&self.recording, command)
    }

    fn resolve_tool(
        &self,
        tool: &pyroclast::tools::ToolSpec,
    ) -> std::io::Result<pyroclast::tools::ResolvedTool> {
        if tool.name == "bpftrace" && !self.bpftrace_available {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "bpftrace unavailable",
            ));
        }
        Ok(pyroclast::tools::ResolvedTool::bare(tool))
    }
}

#[test]
fn automatic_blocked_time_selection_checks_permissions_before_launching_workload() {
    let root = tempfile::tempdir().unwrap();
    let runner = DeniedPerf {
        recording: RecordingRunner::default(),
        bpftrace_available: true,
        bpftrace_permitted: true,
    };
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "offcpu",
        "--json",
        "--out",
        root.path().to_str().unwrap(),
        "--",
        "native-service",
    ]);
    let output = pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, "linux")
        .expect("use bpftrace when installed perf lacks scheduler permissions");
    let commands = runner.recording.commands();
    assert_eq!(commands[0].program, "perf");
    assert!(
        commands[0]
            .args
            .ends_with(&["--".into(), "sh".into(), "-c".into(), ":".into()])
    );
    assert!(!commands[0].interactive);
    assert!(!commands[0].args.iter().any(|arg| arg == "native-service"));
    assert_eq!(
        commands
            .iter()
            .filter(|command| command.program == "bpftrace")
            .count(),
        2
    );
    let bpftrace_probe = &commands[1];
    assert!(!bpftrace_probe.interactive);
    assert!(!bpftrace_probe.args.iter().any(|arg| arg == "-c"));
    assert!(commands[2].args.iter().any(|arg| arg == "-c"));
    let manifest: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(manifest["command"], serde_json::json!(["native-service"]));
    let summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.path().join("summary.json")).unwrap()).unwrap();
    assert_eq!(summary["method"], "bpftrace");
}

#[test]
fn unusable_blocked_time_recorders_report_both_causes_without_launching_workload() {
    let root = tempfile::tempdir().unwrap();
    let runner = DeniedPerf {
        recording: RecordingRunner::default(),
        bpftrace_available: false,
        bpftrace_permitted: false,
    };
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "offcpu",
        "--out",
        root.path().to_str().unwrap(),
        "--",
        "must-not-run",
    ]);
    let error =
        pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, "linux").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("sched tracepoints are not permitted"),
        "{error}"
    );
    assert!(
        error.to_string().contains("bpftrace unavailable"),
        "{error}"
    );
    assert_eq!(runner.recording.programs(), vec!["perf"]);
    assert!(!root.path().join("run.json").exists());
}

#[test]
fn failed_blocked_time_capability_probes_do_not_launch_requested_workload() {
    let root = tempfile::tempdir().unwrap();
    let runner = DeniedPerf {
        recording: RecordingRunner::default(),
        bpftrace_available: true,
        bpftrace_permitted: false,
    };
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "offcpu",
        "--out",
        root.path().to_str().unwrap(),
        "--",
        "must-not-run",
    ]);
    let error =
        pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, "linux").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("sched tracepoints are not permitted"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("kernel stack helper is not permitted"),
        "{error}"
    );
    let commands = runner.recording.commands();
    assert_eq!(runner.recording.programs(), vec!["perf", "bpftrace"]);
    assert!(commands.iter().all(|command| !command.interactive));
    assert!(
        commands
            .iter()
            .all(|command| !command.args.iter().any(|arg| arg == "must-not-run"))
    );
    assert!(!root.path().join("run.json").exists());
}

#[test]
fn explicit_blocked_time_recorder_skips_automatic_capability_probe() {
    let root = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "offcpu",
        "--offcpu-method",
        "perf-sched",
        "--out",
        root.path().to_str().unwrap(),
        "--",
        "native-service",
    ]);
    pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, "linux").unwrap();
    assert_eq!(runner.programs(), vec!["perf", "perf"]);
    assert!(
        runner.commands()[0]
            .env
            .iter()
            .any(|(name, _)| name == "PYROCLAST_OFFCPU_TARGET_PID")
    );
}

#[test]
fn streaming_perf_commands_match_explicit_owned_output_adapters() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), tiny_perfdata()).unwrap();
    for command in ["fold", "perf-script"] {
        let args = [
            "pyroclast",
            "plumbing",
            command,
            "--no-symbols",
            file.path().to_str().unwrap(),
        ];
        let expected = pyroclast::run_cli(args).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        pyroclast::run_cli_to_writers(args, &mut stdout, &mut stderr).unwrap();
        assert_eq!(stdout, expected.stdout.as_bytes());
        assert_eq!(stderr, expected.stderr.as_bytes());
    }
}

struct FailingStream(std::io::ErrorKind);

impl std::io::Write for FailingStream {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(self.0))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::from(self.0))
    }
}

#[test]
fn streaming_perf_text_accepts_broken_pipe_but_reports_other_write_errors() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), tiny_perfdata()).unwrap();
    let args = [
        "pyroclast",
        "plumbing",
        "perf-script",
        "--no-symbols",
        file.path().to_str().unwrap(),
    ];
    assert!(
        pyroclast::run_cli_to_writers(
            args,
            FailingStream(std::io::ErrorKind::BrokenPipe),
            Vec::new()
        )
        .is_ok()
    );
    assert!(
        pyroclast::run_cli_to_writers(
            args,
            FailingStream(std::io::ErrorKind::PermissionDenied),
            Vec::new()
        )
        .is_err()
    );
}

#[test]
fn perf_script_binary_streams_delivered_samples_before_a_later_parse_error() {
    // perf session.c delivers an untimed sample immediately. A malformed
    // later record must not make the CLI buffer and discard earlier text.
    let mut bytes = tiny_perfdata();
    let mut invalid = record_bytes(68, &[]);
    invalid[6..8].copy_from_slice(&4_u16.to_le_bytes());
    bytes.extend(invalid);
    let data_offset = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
    let data_size = bytes.len() as u64 - data_offset;
    put_u64(&mut bytes, 48, data_size);
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pyroclast"))
        .args(["plumbing", "perf-script", "--no-symbols"])
        .arg(file.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid perf record size"));
    assert!(
        !output.stdout.is_empty(),
        "delivered text must not be retained in CliOutput"
    );
}

#[test]
fn perf_script_command_exports_inferno_compatible_perf_script() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_TIME
                    | PERF_SAMPLE_CPU
                    | PERF_SAMPLE_PERIOD
                    | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [
                record_bytes(3, &comm_payload(1, 2, "app")),
                record_bytes(1, &mmap_payload(1, 2, 0x1000, 0x2000, 0, "/bin/app")),
                record_bytes(
                    9,
                    &sample_payload_with_time_cpu_period(
                        0x1000,
                        1,
                        2,
                        123_456_000,
                        3,
                        144,
                        [0x2000],
                    ),
                ),
            ],
        ),
    )
    .expect("write perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "perf-script",
        "--no-symbols",
        perfdata.to_str().unwrap(),
    ])
    .expect("perf script command");

    assert_eq!(
        output.stdout,
        "app       2 [003]     0.123456:        144 cycles: \n\t            2000 [unknown] (/bin/app)\n\n"
    );
}

#[test]
fn perf_script_command_returns_empty_failure_for_zero_data_size_like_perf_script() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let mut bytes = tiny_perfdata();
    put_u64(&mut bytes, 16, 144);
    put_u64(&mut bytes, 48, 0);
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    #[cfg(target_os = "linux")]
    {
        let perf = std::process::Command::new("perf")
            .args(["script", "--force", "-i", perfdata.to_str().unwrap()])
            .output()
            .expect("run reference perf script");
        assert!(
            !perf.status.success(),
            "perf unexpectedly accepted a zero-sized data section"
        );
        assert!(
            perf.stdout.is_empty(),
            "{}",
            String::from_utf8_lossy(&perf.stdout)
        );
    }

    let error = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "perf-script",
        "--no-symbols",
        perfdata.to_str().unwrap(),
    ])
    .expect_err("perf script cannot process a zero-sized event section");

    assert!(!error.to_string().is_empty());
}

#[test]
fn fold_command_processes_zero_data_size_like_perf_script_and_inferno() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let mut bytes = tiny_perfdata();
    put_u64(&mut bytes, 16, 144);
    put_u64(&mut bytes, 48, 0);
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "fold",
        "--no-symbols",
        perfdata.to_str().unwrap(),
    ])
    .expect("empty perf script stream folds to empty output");

    assert_eq!(output.stdout, "");
}

#[test]
fn perf_script_command_keeps_unreadable_objects_unknown_and_zero_default_period_like_perf() {
    // perf machine.c:append_inlines does not ask addr2line for names without
    // a base symbol. This fixture has no ELF or DWARF inline chain.
    // evsel.c:evsel__parse_sample uses attr.sample_period (zero here) without
    // PERF_SAMPLE_PERIOD. Script output prints that value even without TIME.
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let missing_object = root.path().join("app");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [
                record_bytes(3, &comm_payload(1, 2, "app")),
                record_bytes(
                    1,
                    &mmap_payload(1, 2, 0x1000, 0x2000, 0, missing_object.to_str().unwrap()),
                ),
                record_bytes(9, &sample_payload(0x1000, 1, 2, [0x2000])),
            ],
        ),
    )
    .expect("write perfdata");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "plumbing",
        "perf-script",
        "--symbolizer",
        "addr2line",
        perfdata.to_str().unwrap(),
    ]);

    let output = pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("perf script command");

    assert_eq!(
        output.stdout,
        format!(
            "app       2          0 cycles: \n\t            2000 [unknown] ({})\n\n",
            missing_object.display()
        )
    );
    assert!(runner.programs().is_empty());
    assert!(runner.stdins().is_empty());
}

#[test]
fn perf_script_command_inline_option_defaults_on_like_perf_script() {
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "plumbing",
        "perf-script",
        "profile.perf.data",
    ]);

    let pyroclast::cli::CliCommand::Plumbing {
        command: pyroclast::cli::PlumbingCommand::PerfScript(args),
    } = cli.command
    else {
        panic!("expected plumbing perf-script command");
    };

    assert!(args.symbols);
    assert!(args.inline_frames.enabled());

    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "plumbing",
        "perf-script",
        "--inline",
        "profile.perf.data",
    ]);
    let pyroclast::cli::CliCommand::Plumbing {
        command: pyroclast::cli::PlumbingCommand::PerfScript(args),
    } = cli.command
    else {
        panic!("expected plumbing perf-script command");
    };
    assert!(args.inline_frames.enabled());

    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "plumbing",
        "perf-script",
        "--no-inline",
        "profile.perf.data",
    ]);
    let pyroclast::cli::CliCommand::Plumbing {
        command: pyroclast::cli::PlumbingCommand::PerfScript(args),
    } = cli.command
    else {
        panic!("expected plumbing perf-script command");
    };
    assert!(!args.inline_frames.enabled());
}

#[test]
fn perf_script_command_uses_perf_default_thread_comm_when_comm_is_missing() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_TIME
                    | PERF_SAMPLE_CPU
                    | PERF_SAMPLE_PERIOD
                    | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [
                record_bytes(1, &mmap_payload(1, 2, 0x1000, 0x2000, 0, "/bin/app")),
                record_bytes(
                    9,
                    &sample_payload_with_time_cpu_period(
                        0x1000,
                        1,
                        2,
                        123_456_000,
                        3,
                        144,
                        [0x2000],
                    ),
                ),
            ],
        ),
    )
    .expect("write perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "perf-script",
        "--no-symbols",
        perfdata.to_str().unwrap(),
    ])
    .expect("perf script command");

    assert_eq!(
        output.stdout,
        ":2       2 [003]     0.123456:        144 cycles: \n\t            2000 [unknown] (/bin/app)\n\n"
    );
}

#[test]
fn perf_script_command_preserves_sample_event_records_like_perf_script() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_TIME
                    | PERF_SAMPLE_CPU
                    | PERF_SAMPLE_PERIOD
                    | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [
                record_bytes(3, &comm_payload(1, 2, "app")),
                record_bytes(1, &mmap_payload(1, 2, 0x1000, 0x2000, 0, "/bin/app")),
                record_bytes(
                    9,
                    &sample_payload_with_time_cpu_period(0x1000, 1, 2, 10_000, 4, 7, [0x2000]),
                ),
                record_bytes(
                    9,
                    &sample_payload_with_time_cpu_period(0x1000, 1, 2, 20_000, 5, 11, [0x2000]),
                ),
            ],
        ),
    )
    .expect("write perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "perf-script",
        "--no-symbols",
        perfdata.to_str().unwrap(),
    ])
    .expect("perf script command");

    assert_eq!(
        output.stdout,
        concat!(
            "app       2 [004]     0.000010:          7 cycles: \n",
            "\t            2000 [unknown] (/bin/app)\n\n",
            "app       2 [005]     0.000020:         11 cycles: \n",
            "\t            2000 [unknown] (/bin/app)\n\n",
        )
    );
}

#[test]
fn perf_script_command_writes_sample_ip_on_event_line_when_callchain_is_absent_like_perf_script() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD,
                0,
                0,
            )],
            [
                record_bytes(1, &mmap_payload(1, 2, 0x1000, 0x2000, 0, "/bin/app")),
                record_bytes(
                    9,
                    &sample_payload_with_period_no_callchain(0x1000, 1, 2, 144),
                ),
            ],
        ),
    )
    .expect("write perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "perf-script",
        "--no-symbols",
        perfdata.to_str().unwrap(),
    ])
    .expect("perf script command");

    assert_eq!(
        output.stdout,
        "              :2       2        144 cycles:              1000 [unknown] (/bin/app)\n"
    );
}

#[test]
fn perf_script_command_uses_perf_event_name_from_software_attr_like_perf_script() {
    const PERF_TYPE_SOFTWARE: u32 = 1;
    const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;

    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes_with_type_config(
                PERF_TYPE_SOFTWARE,
                PERF_COUNT_SW_CPU_CLOCK,
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [
                record_bytes(3, &comm_payload(1, 2, "app")),
                record_bytes(1, &mmap_payload(1, 2, 0x1000, 0x2000, 0, "/bin/app")),
                record_bytes(9, &sample_payload_with_period(0x1000, 1, 2, 144, [0x2000])),
            ],
        ),
    )
    .expect("write perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "perf-script",
        "--no-symbols",
        perfdata.to_str().unwrap(),
    ])
    .expect("perf script command");

    assert_eq!(
        output.stdout,
        "app       2        144 cpu-clock: \n\t            2000 [unknown] (/bin/app)\n\n"
    );
}

#[test]
fn perf_script_command_pads_event_names_to_evlist_max_width_like_perf_script() {
    const PERF_TYPE_HARDWARE: u32 = 0;
    const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
    const PERF_TYPE_SOFTWARE: u32 = 1;
    const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;

    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(
        &perfdata,
        perfdata_with_attrs_ids_and_records(
            [
                file_attr_bytes_with_type_config(
                    PERF_TYPE_HARDWARE,
                    PERF_COUNT_HW_CPU_CYCLES,
                    PERF_SAMPLE_IDENTIFIER
                        | PERF_SAMPLE_IP
                        | PERF_SAMPLE_TID
                        | PERF_SAMPLE_PERIOD
                        | PERF_SAMPLE_CALLCHAIN,
                    392,
                    8,
                ),
                file_attr_bytes_with_type_config(
                    PERF_TYPE_SOFTWARE,
                    PERF_COUNT_SW_CPU_CLOCK,
                    PERF_SAMPLE_IDENTIFIER
                        | PERF_SAMPLE_IP
                        | PERF_SAMPLE_TID
                        | PERF_SAMPLE_PERIOD
                        | PERF_SAMPLE_CALLCHAIN,
                    400,
                    8,
                ),
            ],
            [111, 222],
            [
                record_bytes(3, &comm_payload(1, 2, "app")),
                record_bytes(
                    9,
                    &sample_payload_with_identifier_and_period(111, 0x1000, 1, 2, 5, [0x2000]),
                ),
                record_bytes(
                    9,
                    &sample_payload_with_identifier_and_period(222, 0x1000, 1, 2, 7, [0x2000]),
                ),
            ],
        ),
    )
    .expect("write perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "perf-script",
        "--no-symbols",
        perfdata.to_str().unwrap(),
    ])
    .expect("perf script command");

    assert_eq!(
        output.stdout,
        concat!(
            "app       2          5    cycles: \n",
            "\t            2000 [unknown] ([unknown])\n\n",
            "app       2          7 cpu-clock: \n",
            "\t            2000 [unknown] ([unknown])\n\n",
        )
    );
}

#[test]
fn perf_script_command_omits_tid_column_when_sample_type_lacks_tid_like_perf_script() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [record_bytes(
                9,
                &sample_payload_with_period_without_tid(0x1000, 5, [0x2000]),
            )],
        ),
    )
    .expect("write perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "perf-script",
        "--no-symbols",
        perfdata.to_str().unwrap(),
    ])
    .expect("perf script command");

    assert_eq!(
        output.stdout,
        ":-1          5 cycles: \n\t            2000 [unknown] ([unknown])\n\n"
    );
}

#[test]
fn perf_script_command_inherits_parent_comm_on_fork_like_perf_script() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_TIME
                    | PERF_SAMPLE_CPU
                    | PERF_SAMPLE_PERIOD
                    | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [
                record_bytes(3, &comm_payload(11, 11, "sh")),
                record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x2000, 0, "/bin/sh")),
                record_bytes(PERF_RECORD_FORK, &fork_payload([22, 11, 22, 11], 99)),
                record_bytes(
                    9,
                    &sample_payload_with_time_cpu_period(0x1000, 22, 22, 30_000, 6, 5, [0x2000]),
                ),
            ],
        ),
    )
    .expect("write perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "perf-script",
        "--no-symbols",
        perfdata.to_str().unwrap(),
    ])
    .expect("perf script command");

    assert_eq!(
        output.stdout,
        "sh      22 [006]     0.000030:          5 cycles: \n\t            2000 [unknown] (/bin/sh)\n\n"
    );
}

#[test]
fn perf_script_command_keeps_perf_stack_order_and_skips_context_markers() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_TIME
                    | PERF_SAMPLE_CPU
                    | PERF_SAMPLE_PERIOD
                    | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [
                record_bytes(3, &comm_payload(1, 2, "app")),
                record_bytes(1, &mmap_payload(1, 2, 0x1000, 0x3000, 0, "/bin/app")),
                record_bytes(
                    9,
                    &sample_payload_with_time_cpu_period(
                        0x1000,
                        1,
                        2,
                        0,
                        0,
                        13,
                        [0x2000, 0x2100, 0xffff_ffff_ffff_ff80],
                    ),
                ),
            ],
        ),
    )
    .expect("write perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "perf-script",
        "--no-symbols",
        perfdata.to_str().unwrap(),
    ])
    .expect("perf script command");

    assert_eq!(
        output.stdout,
        concat!(
            "app       2 [000]     0.000000:         13 cycles: \n",
            "\t            2000 [unknown] (/bin/app)\n",
            "\t            2100 [unknown] (/bin/app)\n\n",
        )
    );
}

#[test]
fn fold_command_uses_module_fallback_without_a_perf_base_symbol() {
    // Inferno perf.rs:with_module_fallback uses the module basename when
    // perf's ELF loader cannot provide a symbol for append_inlines.
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let missing_object = root.path().join("app");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [
                record_bytes(3, &comm_payload(1, 2, "app")),
                record_bytes(
                    1,
                    &mmap_payload(1, 2, 0x1000, 0x2000, 0, missing_object.to_str().unwrap()),
                ),
                record_bytes(9, &sample_payload(0x1000, 1, 2, [0x2000])),
            ],
        ),
    )
    .expect("write perfdata");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "plumbing",
        "fold",
        "--symbolizer",
        "addr2line",
        perfdata.to_str().unwrap(),
    ]);

    let output = pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("fold command");

    assert_eq!(output.stdout, "app;[app] 1\n");
    assert!(runner.programs().is_empty());
    assert!(runner.stdins().is_empty());
}

#[test]
fn fold_command_can_use_rust_symbolizer_without_addr2line() {
    let root = tempfile::tempdir().expect("tempdir");
    let current_exe = std::env::current_exe().expect("current exe");
    let object_bytes = std::fs::read(&current_exe).expect("current exe bytes");
    let object = object::File::parse(object_bytes.as_slice()).expect("current exe object");
    let symbol = object
        .symbols()
        .filter(|symbol| symbol.address() != 0)
        .find(|symbol| {
            symbol.name().is_ok_and(|name| {
                name.contains("fold_command_can_use_rust_symbolizer")
                    && !name.contains("{{closure}}")
            })
        })
        .expect("test symbol");
    let sample_file_offset = object
        .segments()
        .find_map(|segment| {
            let start = segment.address();
            let end = start.checked_add(segment.size())?;
            let (file_offset, _) = segment.file_range();
            (symbol.address() >= start && symbol.address() < end)
                .then(|| file_offset + (symbol.address() - start))
        })
        .expect("test symbol is in a load segment");
    let perfdata = root.path().join("perf.data");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [
                record_bytes(3, &comm_payload(1, 2, "pyroclast-test")),
                record_bytes(
                    1,
                    &mmap_payload(
                        1,
                        2,
                        0,
                        sample_file_offset.saturating_add(1),
                        0,
                        &current_exe.display().to_string(),
                    ),
                ),
                record_bytes(
                    9,
                    &sample_payload(sample_file_offset, 1, 2, [sample_file_offset]),
                ),
            ],
        ),
    )
    .expect("write perfdata");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "plumbing",
        "fold",
        "--symbolizer",
        "rust-addr2line",
        perfdata.to_str().unwrap(),
    ]);

    let output = pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("fold command");

    assert!(
        output.stdout.starts_with("pyroclast-test;") && !output.stdout.contains("[unknown]"),
        "{}",
        output.stdout
    );
    assert!(runner.programs().is_empty());
}

#[test]
fn flamegraph_command_folds_perfdata_without_perf_script() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let output_svg = root.path().join("flamegraph.svg");
    std::fs::write(&perfdata, tiny_perfdata()).expect("write perfdata");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "plumbing",
        "flamegraph",
        "--no-symbols",
        perfdata.to_str().expect("perfdata path"),
        "-o",
        output_svg.to_str().expect("svg path"),
        "--title",
        "sftp-s3 CPU",
    ]);

    pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("flamegraph command");

    assert!(runner.programs().is_empty());
    let svg = std::fs::read_to_string(output_svg).expect("svg");
    assert!(svg.contains("sftp-s3 CPU"));
    let entries = pyroclast::flamegraph::analysis::parse_flamegraph(&svg)
        .expect("profile")
        .inclusive;
    assert!(
        entries
            .iter()
            .any(|entry| entry.name == "[unknown]" && entry.samples == 1)
    );
}

#[test]
fn flamegraph_command_uses_infernos_unit_weight_for_untimed_period_samples() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let output_svg = root.path().join("flamegraph.svg");
    std::fs::write(&perfdata, tiny_period_perfdata()).expect("write perfdata");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "plumbing",
        "flamegraph",
        "--no-symbols",
        perfdata.to_str().expect("perfdata path"),
        "-o",
        output_svg.to_str().expect("svg path"),
    ]);

    pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("flamegraph command");

    assert!(runner.programs().is_empty());
    let entries = pyroclast::flamegraph::analysis::parse_flamegraph(
        &std::fs::read_to_string(output_svg).unwrap(),
    )
    .expect("profile")
    .inclusive;
    assert!(
        entries
            .iter()
            .any(|entry| entry.name == "[unknown]" && entry.samples == 1)
    );
}

#[test]
fn flamegraph_command_accepts_injected_renderer() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let output_svg = root.path().join("flamegraph.svg");
    std::fs::write(&perfdata, tiny_perfdata()).expect("write perfdata");
    let runner = RecordingRunner::default();
    let renderer = RecordingRenderer::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "plumbing",
        "flamegraph",
        "--no-symbols",
        perfdata.to_str().expect("perfdata path"),
        "-o",
        output_svg.to_str().expect("svg path"),
    ]);

    pyroclast::run_parsed_cli_with_runner_and_renderer(cli, &runner, &renderer)
        .expect("flamegraph command");

    assert_eq!(runner.programs(), Vec::<String>::new());
    assert_eq!(renderer.folded_stacks(), ":2;[unknown] 1\n");
    assert_eq!(
        std::fs::read_to_string(output_svg).expect("svg"),
        "<svg>cli plugin</svg>\n"
    );
}

#[test]
fn flamegraph_command_keeps_module_fallback_without_a_perf_base_symbol() {
    // perf machine.c:append_inlines cannot revive a symbol from addr2line
    // when the mapped ELF is unreadable; Inferno keeps the module fallback.
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let output_svg = root.path().join("flamegraph.svg");
    let missing_object = root.path().join("app");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [
                record_bytes(3, &comm_payload(1, 2, "app")),
                record_bytes(
                    1,
                    &mmap_payload(1, 2, 0x1000, 0x2000, 0, missing_object.to_str().unwrap()),
                ),
                record_bytes(9, &sample_payload(0x1000, 1, 2, [0x2000])),
            ],
        ),
    )
    .expect("write perfdata");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "plumbing",
        "flamegraph",
        "--symbolizer",
        "addr2line",
        perfdata.to_str().expect("perfdata path"),
        "-o",
        output_svg.to_str().expect("svg path"),
    ]);

    pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("flamegraph command");

    assert!(runner.programs().is_empty());
    let entries = pyroclast::flamegraph::analysis::parse_flamegraph(
        &std::fs::read_to_string(output_svg).unwrap(),
    )
    .expect("profile")
    .inclusive;
    assert!(
        entries
            .iter()
            .any(|entry| entry.name == "[app]" && entry.samples == 1)
    );
}

#[test]
fn analyze_flamegraph_command_emits_json_summary() {
    let root = tempfile::tempdir().expect("tempdir");
    let svg = root.path().join("flamegraph.svg");
    std::fs::write(
        &svg,
        r#"
<svg total_samples="100">
  <g><title>all (100 samples, 100%)</title><rect fg:x="0" fg:w="100" y="96"/></g>
  <g><title>tokio::runtime::park (40 samples, 40.00%)</title><rect fg:x="0" fg:w="40" y="80"/></g>
  <g><title>zfs_read (30 samples, 30.00%)</title><rect fg:x="40" fg:w="30" y="80"/></g>
</svg>
"#,
    )
    .expect("svg");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "parse",
        "flamegraph",
        "summary",
        "--json",
        svg.to_str().expect("svg path"),
    ])
    .expect("analyze flamegraph");

    let json: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert_eq!(json[0]["name"], "Tokio Runtime");
    assert_eq!(json[0]["percent"], 40.0);
    assert_eq!(json[1]["name"], "Disk I/O");
    assert_eq!(json[1]["percent"], 30.0);
    assert_eq!(json[2]["name"], "Other");
    assert_eq!(json[2]["percent"], 30.0);
}

#[test]
fn analyze_flamegraph_command_emits_text_diff() {
    let render_test_flamegraph = |lines: &[&str]| {
        let mut svg = Vec::new();
        inferno::flamegraph::from_lines(
            &mut inferno::flamegraph::Options::default(),
            lines.iter().copied(),
            &mut svg,
        )
        .unwrap();
        svg
    };
    let root = tempfile::tempdir().expect("tempdir");
    let before = root.path().join("before.svg");
    let after = root.path().join("after.svg");
    std::fs::write(&before, render_test_flamegraph(&["parse 80", "read 20"])).expect("before");
    std::fs::write(&after, render_test_flamegraph(&["parse 50", "write 50"])).expect("after");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "parse",
        "flamegraph",
        "diff",
        before.to_str().expect("before path"),
        after.to_str().expect("after path"),
    ])
    .expect("analyze flamegraph");

    assert!(output.stdout.contains("+50.00%"));
    assert!(output.stdout.contains("write"));
    assert!(output.stdout.contains("-30.00%"));
    assert!(output.stdout.contains("parse"));
}

#[test]
fn analyze_perfdata_command_emits_json_report() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(&perfdata, tiny_period_perfdata()).expect("perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "parse",
        "perf",
        "summary",
        "--json",
        perfdata.to_str().expect("perfdata path"),
    ])
    .expect("analyze perfdata");

    let json: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert_eq!(json["total_samples"], 1);
    assert_eq!(json["weighted_samples"], 144);
    assert_eq!(json["threads"][0]["tid"], 2);
    assert_eq!(json["profile"]["threads"][0]["pid"], 1);
    assert_eq!(json["profile"]["timeline"]["untimed_samples"], 1);
    assert_eq!(json["top_leaf_ips"][0]["ip"], "0x0000000000002000");
}

#[test]
fn analyze_perfdata_command_emits_text_report() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(&perfdata, tiny_period_perfdata()).expect("perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "parse",
        "perf",
        "summary",
        perfdata.to_str().expect("perfdata path"),
    ])
    .expect("analyze perfdata");

    assert!(output.stdout.contains("samples: 1"));
    assert!(output.stdout.contains("weighted samples: 144"));
    assert!(output.stdout.contains("0x0000000000002000"));
}

#[test]
fn summarize_command_prints_summary_text() {
    let root = tempfile::tempdir().expect("tempdir");
    let run_dir = root.path().join("run");
    std::fs::create_dir(&run_dir).expect("run dir");
    std::fs::write(run_dir.join("summary.txt"), "folded lines: 3\n").expect("summary txt");
    std::fs::write(run_dir.join("summary.json"), "{\"folded_lines\":3}\n").expect("summary json");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "summarize",
        run_dir.to_str().unwrap(),
    ])
    .expect("summarize command");

    assert_eq!(output.stdout, "folded lines: 3\n");
}

#[test]
fn summarize_command_prints_summary_json() {
    let root = tempfile::tempdir().expect("tempdir");
    let run_dir = root.path().join("run");
    std::fs::create_dir(&run_dir).expect("run dir");
    std::fs::write(run_dir.join("summary.txt"), "folded lines: 3\n").expect("summary txt");
    std::fs::write(run_dir.join("summary.json"), "{\"folded_lines\":3}\n").expect("summary json");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "summarize",
        "--json",
        run_dir.to_str().unwrap(),
    ])
    .expect("summarize command");

    assert_eq!(output.stdout, "{\"folded_lines\":3}\n");
}

#[test]
fn summarize_command_computes_text_from_folded_stacks_when_summary_is_missing() {
    let root = tempfile::tempdir().expect("tempdir");
    let run_dir = root.path().join("run");
    std::fs::create_dir(&run_dir).expect("run dir");
    std::fs::write(run_dir.join("stacks.folded"), "a;b 2\nc 3\n").expect("folded stacks");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "summarize",
        run_dir.to_str().unwrap(),
    ])
    .expect("summarize command");

    assert_eq!(
        output.stdout,
        "folded lines: 2\nfolded bytes: 10\ntotal count: 5\n"
    );
}

#[test]
fn summarize_command_computes_text_from_raw_perfdata_when_summaries_are_missing() {
    let root = tempfile::tempdir().expect("tempdir");
    let run_dir = root.path().join("run");
    std::fs::create_dir(&run_dir).expect("run dir");
    std::fs::write(run_dir.join("profile.raw.perf.data"), tiny_perfdata()).expect("perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "summarize",
        run_dir.to_str().unwrap(),
    ])
    .expect("summarize command");

    assert_eq!(
        output.stdout,
        "folded lines: 1\nfolded bytes: 15\ntotal count: 1\n"
    );
}

#[test]
fn summarize_command_computes_json_from_raw_perfdata_when_summaries_are_missing() {
    let root = tempfile::tempdir().expect("tempdir");
    let run_dir = root.path().join("run");
    std::fs::create_dir(&run_dir).expect("run dir");
    std::fs::write(run_dir.join("profile.raw.perf.data"), tiny_perfdata()).expect("perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "summarize",
        "--json",
        run_dir.to_str().unwrap(),
    ])
    .expect("summarize command");
    let summary: serde_json::Value = serde_json::from_str(&output.stdout).expect("summary json");

    assert_eq!(summary["folded_lines"], 1);
    assert_eq!(summary["folded_bytes"], 15);
    assert_eq!(summary["total_count"], 1);
}

#[test]
fn top_level_cpu_command_uses_injected_perf_runner() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("cpu-run");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "cpu",
        "--out",
        out.to_str().expect("utf8 path"),
        "--",
        "true",
    ]);

    pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, "linux").expect("run cli");

    assert_eq!(runner.programs(), vec!["perf"]);
    let run_json = std::fs::read_to_string(out.join("run.json")).expect("run json");
    assert!(run_json.contains("\"actual_backend\": \"linux_perf\""));
    assert!(run_json.contains("\"sample_frequency\": 997"));
    assert!(run_json.contains("\"sample_event\": \"default\""));
    assert!(run_json.contains("\"call_graph\": \"dwarf\""));
    assert!(run_json.contains("\"record_target\": \"command\""));
    assert!(run_json.contains("\"duration_secs\": null"));
    assert!(run_json.contains("\"symbols\": true"));
    assert!(run_json.contains("\"tool_versions\""));
    let summary_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("summary.json")).unwrap())
            .expect("summary json");
    assert_eq!(summary_json["folded_lines"], 1);
    assert_eq!(summary_json["total_count"], 1);
}

#[test]
fn profile_cpu_command_uses_injected_perf_runner() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("profile-cpu-run");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "profile",
        "--kind",
        "cpu",
        "--out",
        out.to_str().expect("utf8 path"),
        "--",
        "true",
    ]);

    pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, "linux").expect("run cli");

    assert_eq!(runner.programs(), vec!["perf"]);
    let run_json = std::fs::read_to_string(out.join("run.json")).expect("run json");
    assert!(run_json.contains("\"actual_backend\": \"linux_perf\""));
    assert!(run_json.contains("\"symbols\": true"));
}

#[test]
fn top_level_cpu_command_uses_xctrace_on_macos() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("macos-cpu-run");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "cpu",
        "--out",
        out.to_str().expect("utf8 path"),
        "--",
        "true",
    ]);

    pyroclast::run_parsed_cli_with_runner_and_renderer_on_platform(
        cli,
        &runner,
        pyroclast::flamegraph::InfernoFlamegraphRenderer::new(&runner),
        "macos",
    )
    .expect("run cli");

    assert_eq!(runner.programs(), vec!["xctrace", "xctrace"]);
    let run_json = std::fs::read_to_string(out.join("run.json")).expect("run json");
    assert!(run_json.contains("\"actual_backend\": \"macos_xctrace\""));
    assert!(out.join("profile.raw.xctrace.trace").is_dir());
    assert!(out.join("profile.raw.xctrace.xml").is_file());
}

#[test]
fn profile_memory_command_keeps_symbols_off_by_default() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("profile-memory-run");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "profile",
        "--kind",
        "memory",
        "--out",
        out.to_str().expect("utf8 path"),
        "--",
        "true",
    ]);

    pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, "linux").expect("run cli");

    assert_eq!(runner.programs(), vec!["heaptrack", "heaptrack_print"]);
    let run_json = std::fs::read_to_string(out.join("run.json")).expect("run json");
    assert!(run_json.contains("\"actual_backend\": \"heaptrack\""));
    assert!(run_json.contains("\"symbols\": false"));
}

#[test]
fn top_level_latency_command_uses_injected_strace_runner() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("latency-run");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "latency",
        "--out",
        out.to_str().expect("utf8 path"),
        "--",
        "true",
    ]);

    pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, "linux").expect("run cli");

    assert_eq!(runner.programs(), vec!["strace"]);
    let run_json = std::fs::read_to_string(out.join("run.json")).expect("run json");
    assert!(run_json.contains("\"actual_backend\": \"strace\""));
    assert!(out.join("profile.raw.strace").is_file());
    let summary_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("summary.json")).unwrap())
            .expect("summary json");
    assert_eq!(summary_json["total_calls"], 2);
}

#[test]
fn top_level_offcpu_command_uses_injected_perf_sched_runner() {
    let root = tempfile::tempdir().expect("tempdir");
    let out = root.path().join("offcpu-run");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "offcpu",
        "--out",
        out.to_str().expect("utf8 path"),
        "--",
        "true",
    ]);

    pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, "linux").expect("run cli");

    assert_eq!(runner.programs(), vec!["perf", "perf", "perf"]);
    let run_json = std::fs::read_to_string(out.join("run.json")).expect("run json");
    assert!(run_json.contains("\"actual_backend\": \"offcpu\""));
    assert!(run_json.contains("\"symbols\": true"));
    assert!(out.join("profile.raw.perf.data").is_file());
    assert!(!out.join("stacks.folded").exists());
    let summary_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("summary.json")).unwrap())
            .expect("summary json");
    assert_eq!(summary_json["method"], "perf_sched");
}

#[test]
fn top_level_offcpu_command_rejects_attach_workflows() {
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "offcpu",
        "--pid",
        "99",
        "--duration-secs",
        "5",
    ]);

    let error = pyroclast::run_parsed_cli_with_runner_on_platform(cli, &runner, "linux")
        .expect_err("attach should fail");

    assert_eq!(
        error.to_string(),
        "off-cpu profiling does not support attach targets on linux"
    );
    assert!(runner.programs().is_empty());
}

#[derive(Default)]
struct RecordingRunner {
    commands: Mutex<Vec<pyroclast::process::CommandSpec>>,
}

impl RecordingRunner {
    fn commands(&self) -> Vec<pyroclast::process::CommandSpec> {
        self.commands.lock().unwrap().clone()
    }

    fn programs(&self) -> Vec<String> {
        self.commands()
            .iter()
            .map(|command| command.program.clone())
            .collect()
    }

    fn stdins(&self) -> Vec<Option<Vec<u8>>> {
        self.commands()
            .iter()
            .map(|command| command.stdin.clone())
            .collect()
    }
}

impl pyroclast::process::CommandRunner for RecordingRunner {
    fn run(
        &self,
        command: &pyroclast::process::CommandSpec,
    ) -> std::io::Result<pyroclast::process::CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        if command.args == ["--version"] {
            return Ok(pyroclast::process::CommandOutput {
                status_code: Some(0),
                stdout: format!("{} fake version\n", command.program).into_bytes(),
                stderr: Vec::new(),
            });
        }
        for (name, path) in &command.env {
            if matches!(
                name.as_str(),
                "PYROCLAST_OFFCPU_TARGET_PID" | "PYROCLAST_XCTRACE_TARGET_PID"
            ) {
                std::fs::write(path, "42\n")?;
            }
        }
        if let Some(output_path) = perf_output_path(command) {
            std::fs::write(output_path, tiny_perfdata())?;
        }
        if let Some(output_path) = strace_output_path(command) {
            std::fs::write(
                output_path,
                "123 12:00:00.000000 read(3, \"abc\", 3) = 3 <0.001000>\n123 12:00:00.002000 write(1, \"x\", 1) = 1 <0.002500>\n",
            )?;
        }
        if let Some(output_path) = heaptrack_output_path(command) {
            std::fs::write(output_path, b"raw heaptrack bytes")?;
        }
        if let Some(trace_path) = xctrace_record_output_path(command) {
            std::fs::create_dir_all(trace_path)?;
        }
        if let Some(xml_path) = xctrace_export_output_path(command) {
            std::fs::write(
                xml_path,
                "<table><row><process pid=\"42\"/><symbol>app::main</symbol><weight>12.5</weight></row></table>",
            )?;
        }
        let stdout = match command.program.as_str() {
            "addr2line" => b"app::work\n/bin/app.rs:10\n".to_vec(),
            "perf"
                if command.args.first().map(String::as_str) == Some("sched")
                    && command.args.get(1).map(String::as_str) == Some("timehist") =>
            {
                b"100.000000 [0000] app[42] 10.000 2.000 1.000\n".to_vec()
            }
            "bpftrace" => {
                b"@offcpu[\n    55 tokio::runtime::park+12 (/bin/app)\n    44 app::serve+7 (/bin/app)\n]: 1500\n".to_vec()
            }
            "heaptrack_print" => {
                b"total allocations: 42\npeak heap memory consumption: 1024 bytes\n".to_vec()
            }
            "inferno-flamegraph" => b"<svg></svg>\n".to_vec(),
            _ => Vec::new(),
        };
        Ok(pyroclast::process::CommandOutput {
            status_code: Some(0),
            stdout,
            stderr: Vec::new(),
        })
    }
}

#[derive(Default)]
struct RecordingRenderer {
    folded_stacks: Mutex<String>,
}

impl RecordingRenderer {
    fn folded_stacks(&self) -> String {
        self.folded_stacks.lock().unwrap().clone()
    }
}

impl pyroclast::flamegraph::FlamegraphRenderer for &RecordingRenderer {
    fn render(
        &self,
        request: &pyroclast::flamegraph::FlamegraphRequest,
    ) -> pyroclast::backends::BackendResult<pyroclast::flamegraph::FlamegraphRenderResult> {
        self.folded_stacks
            .lock()
            .unwrap()
            .clone_from(&request.folded_stacks);
        std::fs::write(&request.output, "<svg>cli plugin</svg>\n")?;
        Ok(pyroclast::flamegraph::FlamegraphRenderResult { stderr: Vec::new() })
    }
}

fn perf_output_path(command: &pyroclast::process::CommandSpec) -> Option<&str> {
    command
        .args
        .windows(2)
        .find(|window| window[0] == "-o")
        .map(|window| window[1].as_str())
}

fn strace_output_path(command: &pyroclast::process::CommandSpec) -> Option<&str> {
    (command.program == "strace")
        .then(|| {
            command
                .args
                .windows(2)
                .find(|window| window[0] == "-o")
                .map(|window| window[1].as_str())
        })
        .flatten()
}

fn heaptrack_output_path(command: &pyroclast::process::CommandSpec) -> Option<&str> {
    (command.program == "heaptrack")
        .then(|| {
            command
                .args
                .windows(2)
                .find(|window| window[0] == "-o")
                .map(|window| window[1].as_str())
        })
        .flatten()
}

fn xctrace_record_output_path(command: &pyroclast::process::CommandSpec) -> Option<&str> {
    (command.program == "xctrace" && command.args.first().map(String::as_str) == Some("record"))
        .then(|| {
            command
                .args
                .windows(2)
                .find(|window| window[0] == "--output")
                .map(|window| window[1].as_str())
        })
        .flatten()
}

fn xctrace_export_output_path(command: &pyroclast::process::CommandSpec) -> Option<&str> {
    (command.program == "xctrace" && command.args.first().map(String::as_str) == Some("export"))
        .then(|| {
            command
                .args
                .windows(2)
                .find(|window| window[0] == "--output")
                .map(|window| window[1].as_str())
        })
        .flatten()
}

fn tiny_perfdata() -> Vec<u8> {
    perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(9, &sample_payload(0x1000, 1, 2, [0x2000]))],
    )
}

fn tiny_period_perfdata() -> Vec<u8> {
    perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload_with_period(0x1000, 1, 2, 144, [0x2000]),
        )],
    )
}

fn perfdata_with_records_and_attrs<const A: usize, const R: usize>(
    attrs: [[u8; 144]; A],
    records: [Vec<u8>; R],
) -> Vec<u8> {
    let attr_size = attrs.len() * 144;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size;
    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    for attr in attrs {
        bytes.extend(attr);
    }
    for record in records {
        bytes.extend(record);
    }
    bytes
}

fn perfdata_with_attrs_ids_and_records<const A: usize, const I: usize, const R: usize>(
    attrs: [[u8; 144]; A],
    ids: [u64; I],
    records: [Vec<u8>; R],
) -> Vec<u8> {
    let attr_size = attrs.len() * 144;
    let ids_size = ids.len() * 8;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size + ids_size;
    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    for attr in attrs {
        bytes.extend(attr);
    }
    for id in ids {
        bytes.extend(id.to_le_bytes());
    }
    for record in records {
        bytes.extend(record);
    }
    bytes
}

fn file_attr_bytes(sample_type: u64, ids_offset: u64, ids_size: u64) -> [u8; 144] {
    let mut bytes = [0; 144];
    put_u32(&mut bytes, 4, 128);
    put_u64(&mut bytes, 24, sample_type);
    put_u64(&mut bytes, 128, ids_offset);
    put_u64(&mut bytes, 136, ids_size);
    bytes
}

fn file_attr_bytes_with_type_config(
    event_type: u32,
    config: u64,
    sample_type: u64,
    ids_offset: u64,
    ids_size: u64,
) -> [u8; 144] {
    let mut bytes = file_attr_bytes(sample_type, ids_offset, ids_size);
    put_u32(&mut bytes, 0, event_type);
    put_u64(&mut bytes, 8, config);
    bytes
}

fn record_bytes(record_type: u32, payload: &[u8]) -> Vec<u8> {
    let size = 8 + payload.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.extend(record_type.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend(
        u16::try_from(size)
            .expect("record fits in u16")
            .to_le_bytes(),
    );
    bytes.extend(payload);
    bytes
}

fn sample_payload<const N: usize>(ip: u64, pid: u32, tid: u32, callchain: [u64; N]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_period<const N: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_identifier_and_period<const N: usize>(
    identifier: u64,
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(identifier.to_le_bytes());
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_period_without_tid<const N: usize>(
    ip: u64,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_period_no_callchain(ip: u64, pid: u32, tid: u32, period: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload
}

fn sample_payload_with_time_cpu_period<const N: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    time: u64,
    cpu: u32,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(time.to_le_bytes());
    payload.extend(cpu.to_le_bytes());
    payload.extend(0u32.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn comm_payload(pid: u32, tid: u32, comm: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(comm.as_bytes());
    payload.push(0);
    payload
}

fn fork_payload(ids: [u32; 4], time: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    for id in ids {
        payload.extend(id.to_le_bytes());
    }
    payload.extend(time.to_le_bytes());
    payload
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn mmap_payload(pid: u32, tid: u32, start: u64, len: u64, pgoff: u64, path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(start.to_le_bytes());
    payload.extend(len.to_le_bytes());
    payload.extend(pgoff.to_le_bytes());
    payload.extend(path.as_bytes());
    payload.push(0);
    payload
}
