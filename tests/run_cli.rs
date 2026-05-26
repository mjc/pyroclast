use object::{Object, ObjectSegment, ObjectSymbol};
use pyroclast::perfdata::samples::{
    PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_PERIOD, PERF_SAMPLE_TID,
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

    pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("run cli");

    assert!(out.join("run.json").is_file());
    assert!(out.join("command.txt").is_file());
    assert_eq!(
        std::fs::read_to_string(out.join("command.txt")).unwrap(),
        "cargo check\n"
    );
    assert_eq!(
        runner.programs(),
        vec!["heaptrack", "heaptrack_print", "heaptrack"]
    );
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

    let output = pyroclast::run_cli(["pyroclast", "fold", perfdata.to_str().unwrap()])
        .expect("fold command");

    assert_eq!(output.stdout, "app;/bin/app+0x1000 1\n");
}

#[test]
fn fold_command_can_symbolize_mapped_frames() {
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
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "fold",
        "--symbols",
        perfdata.to_str().unwrap(),
    ]);

    let output = pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("fold command");

    assert_eq!(output.stdout, "app;app::work 1\n");
    assert_eq!(runner.programs(), vec!["addr2line"]);
    assert_eq!(runner.stdins(), vec![Some(b"0x1000\n".to_vec())]);
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
            symbol
                .name()
                .is_ok_and(|name| name.contains("fold_command_can_use_rust_symbolizer"))
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
        "fold",
        "--symbols",
        "--symbolizer",
        "rust-addr2line",
        perfdata.to_str().unwrap(),
    ]);

    let output = pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("fold command");

    assert!(
        output.stdout.starts_with("pyroclast-test;")
            && output
                .stdout
                .contains("fold_command_can_use_rust_symbolizer"),
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
        "flamegraph",
        perfdata.to_str().expect("perfdata path"),
        "-o",
        output_svg.to_str().expect("svg path"),
        "--title",
        "sftp-s3 CPU",
    ]);

    pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("flamegraph command");

    assert_eq!(runner.programs(), vec!["inferno-flamegraph"]);
    assert_eq!(
        runner.first_args(),
        Some(vec![
            "--title".to_string(),
            "sftp-s3 CPU".to_string(),
            "-".to_string()
        ])
    );
    assert_eq!(runner.stdins(), vec![Some(b"0x2000 1\n".to_vec())]);
    assert_eq!(
        std::fs::read_to_string(output_svg).expect("svg"),
        "<svg></svg>\n"
    );
}

#[test]
fn flamegraph_command_weights_perf_sample_periods() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let output_svg = root.path().join("flamegraph.svg");
    std::fs::write(&perfdata, tiny_period_perfdata()).expect("write perfdata");
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "flamegraph",
        perfdata.to_str().expect("perfdata path"),
        "-o",
        output_svg.to_str().expect("svg path"),
    ]);

    pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("flamegraph command");

    assert_eq!(runner.stdins(), vec![Some(b"0x2000 144\n".to_vec())]);
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
        "flamegraph",
        perfdata.to_str().expect("perfdata path"),
        "-o",
        output_svg.to_str().expect("svg path"),
    ]);

    pyroclast::run_parsed_cli_with_runner_and_renderer(cli, &runner, &renderer)
        .expect("flamegraph command");

    assert_eq!(runner.programs(), Vec::<String>::new());
    assert_eq!(renderer.folded_stacks(), "0x2000 1\n");
    assert_eq!(
        std::fs::read_to_string(output_svg).expect("svg"),
        "<svg>cli plugin</svg>\n"
    );
}

#[test]
fn flamegraph_command_can_symbolize_mapped_frames() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let output_svg = root.path().join("flamegraph.svg");
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
    let runner = RecordingRunner::default();
    let cli = pyroclast::cli::Cli::parse_from([
        "pyroclast",
        "flamegraph",
        "--symbols",
        perfdata.to_str().expect("perfdata path"),
        "-o",
        output_svg.to_str().expect("svg path"),
    ]);

    pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("flamegraph command");

    assert_eq!(runner.programs(), vec!["addr2line", "inferno-flamegraph"]);
    assert_eq!(
        runner.stdins(),
        vec![
            Some(b"0x1000\n".to_vec()),
            Some(b"app;app::work 1\n".to_vec()),
        ]
    );
}

#[test]
fn analyze_flamegraph_command_emits_json_summary() {
    let root = tempfile::tempdir().expect("tempdir");
    let svg = root.path().join("flamegraph.svg");
    std::fs::write(
        &svg,
        r"
<svg>
  <title>all (100 samples, 100%)</title>
  <title>tokio::runtime::park (40 samples, 40.00%)</title>
  <title>zfs_read (30 samples, 30.00%)</title>
</svg>
",
    )
    .expect("svg");

    let output = pyroclast::run_cli([
        "pyroclast",
        "analyze-flamegraph",
        "--json",
        "--mode",
        "summary",
        svg.to_str().expect("svg path"),
    ])
    .expect("analyze flamegraph");

    let json: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert_eq!(json[0]["name"], "Tokio Runtime");
    assert_eq!(json[0]["percent"], 40.0);
    assert_eq!(json[1]["name"], "Disk I/O");
    assert_eq!(json[1]["percent"], 30.0);
}

#[test]
fn analyze_flamegraph_command_emits_text_diff() {
    let root = tempfile::tempdir().expect("tempdir");
    let before = root.path().join("before.svg");
    let after = root.path().join("after.svg");
    std::fs::write(
        &before,
        r"<title>parse (80 samples, 80.00%)</title><title>read (20 samples, 20.00%)</title>",
    )
    .expect("before");
    std::fs::write(
        &after,
        r"<title>parse (50 samples, 50.00%)</title><title>write (50 samples, 50.00%)</title>",
    )
    .expect("after");

    let output = pyroclast::run_cli([
        "pyroclast",
        "analyze-flamegraph",
        "--mode",
        "diff",
        "--other",
        after.to_str().expect("after path"),
        before.to_str().expect("before path"),
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
        "analyze-perfdata",
        "--json",
        perfdata.to_str().expect("perfdata path"),
    ])
    .expect("analyze perfdata");

    let json: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert_eq!(json["total_samples"], 1);
    assert_eq!(json["weighted_samples"], 144);
    assert_eq!(json["threads"][0]["tid"], 2);
    assert_eq!(json["top_leaf_ips"][0]["ip"], "0x0000000000002000");
}

#[test]
fn analyze_perfdata_command_emits_text_report() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(&perfdata, tiny_period_perfdata()).expect("perfdata");

    let output = pyroclast::run_cli([
        "pyroclast",
        "analyze-perfdata",
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

    let output = pyroclast::run_cli(["pyroclast", "summarize", run_dir.to_str().unwrap()])
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

    let output = pyroclast::run_cli(["pyroclast", "summarize", run_dir.to_str().unwrap()])
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

    let output = pyroclast::run_cli(["pyroclast", "summarize", run_dir.to_str().unwrap()])
        .expect("summarize command");

    assert_eq!(
        output.stdout,
        "folded lines: 1\nfolded bytes: 9\ntotal count: 1\n"
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
        "summarize",
        "--json",
        run_dir.to_str().unwrap(),
    ])
    .expect("summarize command");
    let summary: serde_json::Value = serde_json::from_str(&output.stdout).expect("summary json");

    assert_eq!(summary["folded_lines"], 1);
    assert_eq!(summary["folded_bytes"], 9);
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

    pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("run cli");

    assert_eq!(
        runner.programs(),
        vec!["perf", "inferno-flamegraph", "perf", "inferno-flamegraph"]
    );
    let run_json = std::fs::read_to_string(out.join("run.json")).expect("run json");
    assert!(run_json.contains("\"actual_backend\": \"linux_perf\""));
    assert!(run_json.contains("\"sample_frequency\": 997"));
    assert!(run_json.contains("\"sample_event\": \"cpu-clock\""));
    assert!(run_json.contains("\"call_graph\": \"fp\""));
    assert!(run_json.contains("\"record_target\": \"command\""));
    assert!(run_json.contains("\"duration_secs\": null"));
    assert!(run_json.contains("\"symbols\": false"));
    assert!(run_json.contains("\"tool_versions\""));
    let summary_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("summary.json")).unwrap())
            .expect("summary json");
    assert_eq!(summary_json["folded_lines"], 1);
    assert_eq!(summary_json["total_count"], 1);
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

    assert_eq!(runner.programs(), vec!["xctrace", "xctrace", "xctrace"]);
    let run_json = std::fs::read_to_string(out.join("run.json")).expect("run json");
    assert!(run_json.contains("\"actual_backend\": \"macos_xctrace\""));
    assert!(out.join("profile.raw.xctrace.trace").is_dir());
    assert!(out.join("profile.raw.xctrace.xml").is_file());
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

    pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("run cli");

    assert_eq!(runner.programs(), vec!["strace", "strace"]);
    let run_json = std::fs::read_to_string(out.join("run.json")).expect("run json");
    assert!(run_json.contains("\"actual_backend\": \"strace\""));
    assert!(out.join("profile.raw.strace").is_file());
    let summary_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("summary.json")).unwrap())
            .expect("summary json");
    assert_eq!(summary_json["total_calls"], 2);
}

#[test]
fn top_level_offcpu_command_uses_injected_bpftrace_runner() {
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

    pyroclast::run_parsed_cli_with_runner(cli, &runner).expect("run cli");

    assert_eq!(runner.programs(), vec!["bpftrace", "bpftrace"]);
    let run_json = std::fs::read_to_string(out.join("run.json")).expect("run json");
    assert!(run_json.contains("\"actual_backend\": \"offcpu\""));
    assert!(out.join("profile.raw.bpftrace").is_file());
    assert_eq!(
        std::fs::read_to_string(out.join("stacks.folded")).expect("folded"),
        "app::serve;tokio::runtime::park 1500\n"
    );
}

#[derive(Default)]
struct RecordingRunner {
    commands: Mutex<Vec<pyroclast::process::CommandSpec>>,
}

impl RecordingRunner {
    fn programs(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .map(|command| command.program.clone())
            .collect()
    }

    fn stdins(&self) -> Vec<Option<Vec<u8>>> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .map(|command| command.stdin.clone())
            .collect()
    }

    fn first_args(&self) -> Option<Vec<String>> {
        self.commands
            .lock()
            .unwrap()
            .first()
            .map(|command| command.args.clone())
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
                "<table><row><symbol>app::main</symbol><weight>12.5</weight></row></table>",
            )?;
        }
        let stdout = match command.program.as_str() {
            "addr2line" => b"app::work\n/bin/app.rs:10\n".to_vec(),
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

fn file_attr_bytes(sample_type: u64, ids_offset: u64, ids_size: u64) -> [u8; 144] {
    let mut bytes = [0; 144];
    put_u32(&mut bytes, 4, 128);
    put_u64(&mut bytes, 24, sample_type);
    put_u64(&mut bytes, 128, ids_offset);
    put_u64(&mut bytes, 136, ids_size);
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

fn comm_payload(pid: u32, tid: u32, comm: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(comm.as_bytes());
    payload.push(0);
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
