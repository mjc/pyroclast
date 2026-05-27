use std::sync::Mutex;

use pyroclast::benchmarks::{
    BenchArgs, DEFAULT_BENCHMARK_INPUT, compare_with_inferno_collapse,
    compare_with_inferno_collapse_with_symbols, export_perf_script, format_bench_output,
    format_comparison_report, run_bench_command, run_fold_benchmark,
    run_fold_benchmark_with_runner, run_inferno_collapse_benchmark,
};
use pyroclast::perfdata::samples::{
    PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_PERIOD, PERF_SAMPLE_TID,
};
use pyroclast::process::{CommandOutput, CommandRunner, CommandSpec};

#[test]
fn fold_benchmark_reports_folded_output_size() {
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
                record_bytes(9, &sample_payload(0x1000, 1, 2, [0x2000])),
                record_bytes(9, &sample_payload(0x1000, 1, 2, [0x2000])),
            ],
        ),
    )
    .expect("write perfdata");

    let report = run_fold_benchmark(&perfdata).expect("benchmark");

    assert_eq!(report.input, perfdata);
    assert_eq!(report.folded_bytes, "[unknown];0x2000 2\n".len());
    assert_eq!(report.folded_lines, 1);
    assert!(report.elapsed.as_nanos() > 0);
}

#[test]
fn fold_benchmark_weights_perf_sample_periods() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(
        &perfdata,
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
        ),
    )
    .expect("write perfdata");

    let report = run_fold_benchmark(&perfdata).expect("benchmark");

    assert_eq!(report.folded_bytes, "[unknown];0x2000 144\n".len());
}

#[test]
fn inferno_collapse_benchmark_reports_folded_output_size() {
    let root = tempfile::tempdir().expect("tempdir");
    let perf_script = root.path().join("perf-script.txt");
    std::fs::write(&perf_script, "sample script\n").expect("write perf script");
    let runner = CollapseRunner::default();

    let report = run_inferno_collapse_benchmark(&perf_script, &runner).expect("benchmark");

    assert_eq!(report.input, perf_script);
    assert_eq!(report.folded_bytes, 20);
    assert_eq!(report.folded_lines, 2);
    assert!(report.elapsed.as_nanos() > 0);
    assert_eq!(
        runner.commands(),
        vec![
            CommandSpec::new("inferno-collapse-perf").arg(
                report
                    .input
                    .to_str()
                    .expect("perf script path should be utf8")
            )
        ]
    );
}

#[test]
fn symbolized_fold_benchmark_uses_runner_addr2line() {
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
                record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
                record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010])),
            ],
        ),
    )
    .expect("write perfdata");
    let runner = Addr2lineRunner::default();

    let report = run_fold_benchmark_with_runner(&perfdata, &runner, true).expect("benchmark");

    assert_eq!(report.folded_bytes, "[unknown];app::main 1\n".len());
    assert_eq!(runner.programs(), vec!["addr2line"]);
}

#[test]
fn compares_pyroclast_folded_stacks_with_inferno_collapse() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let perf_script = root.path().join("perf-script.txt");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [
                record_bytes(9, &sample_payload(0x1000, 1, 2, [0x2000])),
                record_bytes(9, &sample_payload(0x1000, 1, 2, [0x2000])),
            ],
        ),
    )
    .expect("write perfdata");
    std::fs::write(&perf_script, "sample script\n").expect("write perf script");
    let runner = MatchingCollapseRunner::default();

    let report =
        compare_with_inferno_collapse(&perfdata, &perf_script, &runner).expect("comparison");

    assert_eq!(report.pyroclast_folded_lines, 1);
    assert_eq!(report.inferno_folded_lines, 1);
    assert!(report.matches);
    assert!(report.svg_matches);
    assert_eq!(report.pyroclast_svg_bytes, 21);
    assert_eq!(report.inferno_svg_bytes, 21);
    assert_eq!(report.only_pyroclast, Vec::<String>::new());
    assert_eq!(report.only_inferno, Vec::<String>::new());
}

#[test]
fn compares_symbolized_pyroclast_folded_stacks_with_inferno_collapse() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let perf_script = root.path().join("perf-script.txt");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [
                record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
                record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010])),
            ],
        ),
    )
    .expect("write perfdata");
    std::fs::write(&perf_script, "sample script\n").expect("write perf script");
    let runner = SymbolizedCompareRunner::default();

    let report = compare_with_inferno_collapse_with_symbols(&perfdata, &perf_script, &runner, true)
        .expect("comparison");

    assert!(report.matches);
    assert!(report.svg_matches);
    assert_eq!(
        runner.programs(),
        vec![
            "addr2line",
            "inferno-collapse-perf",
            "inferno-flamegraph",
            "inferno-flamegraph"
        ]
    );
}

#[test]
fn exports_perf_script_for_old_pipeline_benchmarks() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let perf_script = root.path().join("perf-script.txt");
    std::fs::write(
        &perfdata,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [record_bytes(9, &sample_payload(0x1000, 1, 2, [0x2000]))],
        ),
    )
    .expect("write perfdata");
    let runner = PerfScriptRunner::default();

    export_perf_script(&perfdata, &perf_script, &runner, false).expect("export perf script");

    assert_eq!(
        std::fs::read_to_string(&perf_script).unwrap(),
        "[unknown] 1/1 0: 1 cycles:\n\t2000 0x2000 ([unknown])\n\n"
    );
    assert!(runner.commands().is_empty());
}

#[test]
fn formats_fold_and_svg_comparison_report() {
    let report = pyroclast::benchmarks::FoldComparisonReport {
        pyroclast_folded_lines: 3,
        inferno_folded_lines: 3,
        matches: true,
        svg_matches: true,
        pyroclast_svg_bytes: 123,
        inferno_svg_bytes: 123,
        only_pyroclast: Vec::new(),
        only_inferno: Vec::new(),
    };

    assert_eq!(
        format_comparison_report("inferno_compare", &report),
        concat!(
            "inferno_compare.matches=true\n",
            "inferno_compare.svg_matches=true\n",
            "inferno_compare.pyroclast_folded_lines=3\n",
            "inferno_compare.inferno_folded_lines=3\n",
            "inferno_compare.pyroclast_svg_bytes=123\n",
            "inferno_compare.inferno_svg_bytes=123\n",
            "inferno_compare.only_pyroclast=0\n",
            "inferno_compare.only_inferno=0\n",
        )
    );
}

#[test]
fn parses_benchmark_inputs() {
    let args = BenchArgs::parse(vec![
        "profile.perf.data".into(),
        "--symbols".into(),
        "--export-perf-script".into(),
        "exported-script.txt".into(),
        "--perf-script".into(),
        "perf-script.txt".into(),
    ]);

    assert_eq!(args.perf_data, Some("profile.perf.data".into()));
    assert!(args.symbols);
    assert_eq!(args.export_perf_script, Some("exported-script.txt".into()));
    assert_eq!(args.perf_script, Some("perf-script.txt".into()));
}

#[test]
fn benchmark_args_default_to_standard_input_path() {
    let args = BenchArgs::default();

    assert_eq!(
        args.input_path(),
        std::path::PathBuf::from(DEFAULT_BENCHMARK_INPUT)
    );
}

#[test]
fn bench_command_reports_missing_input() {
    let runner = CollapseRunner::default();
    let args = BenchArgs {
        perf_data: Some("missing.perf.data".into()),
        perf_script: None,
        export_perf_script: None,
        symbols: false,
    };

    let error = run_bench_command(&args, &runner).expect_err("missing input should fail");

    assert!(error.contains("benchmark input not found"));
}

#[test]
fn bench_command_reports_missing_perf_script_input() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    std::fs::write(&perfdata, tiny_perfdata()).expect("write perfdata");
    let runner = CollapseRunner::default();
    let args = BenchArgs {
        perf_data: Some(perfdata),
        perf_script: Some(root.path().join("missing.perf-script")),
        export_perf_script: None,
        symbols: false,
    };

    let error = run_bench_command(&args, &runner).expect_err("missing perf script should fail");

    assert!(error.contains("perf script input not found"));
}

#[test]
fn bench_command_exports_perf_script_and_compares_without_perf_runner() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let exported_perf_script = root.path().join("exported.perf-script");
    std::fs::write(&perfdata, tiny_perfdata()).expect("write perfdata");
    let runner = BenchCommandRunner::default();
    let args = BenchArgs {
        perf_data: Some(perfdata),
        perf_script: None,
        export_perf_script: Some(exported_perf_script.clone()),
        symbols: false,
    };

    let output = run_bench_command(&args, &runner).expect("bench command");

    assert_eq!(
        std::fs::read_to_string(&exported_perf_script).expect("exported perf script"),
        "[unknown] 1/1 0: 1 cycles:\n\t2000 0x2000 ([unknown])\n\n"
    );
    assert!(output.contains("inferno_compare.matches=true"));
    assert!(output.contains("pyroclast_fold.input="));
    assert!(output.contains("inferno_collapse_perf.input="));
}

#[test]
fn formats_streaming_benchmark_output() {
    let report = pyroclast::benchmarks::StreamingComparisonReport {
        pyroclast_fold: pyroclast::benchmarks::FoldBenchmarkReport {
            input: "profile.perf.data".into(),
            elapsed: std::time::Duration::from_millis(10),
            folded_bytes: 100,
            folded_lines: 4,
        },
        inferno_fold: pyroclast::benchmarks::FoldBenchmarkReport {
            input: "profile.perf.script".into(),
            elapsed: std::time::Duration::from_millis(20),
            folded_bytes: 120,
            folded_lines: 5,
        },
        comparison: pyroclast::benchmarks::FoldComparisonReport {
            pyroclast_folded_lines: 4,
            inferno_folded_lines: 5,
            matches: false,
            svg_matches: false,
            pyroclast_svg_bytes: 40,
            inferno_svg_bytes: 41,
            only_pyroclast: vec!["a".to_string()],
            only_inferno: vec!["b".to_string()],
        },
    };

    let output = format_bench_output(&report);

    assert!(output.contains("pyroclast_fold.input=profile.perf.data"));
    assert!(output.contains("inferno_collapse_perf.input=profile.perf.script"));
    assert!(output.contains("inferno_compare.matches=false"));
}

#[derive(Default)]
struct PerfScriptRunner {
    commands: Mutex<Vec<CommandSpec>>,
}

impl PerfScriptRunner {
    fn commands(&self) -> Vec<CommandSpec> {
        self.commands.lock().unwrap().clone()
    }
}

impl CommandRunner for PerfScriptRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        Ok(CommandOutput {
            status_code: Some(0),
            stdout: b"perf script\n".to_vec(),
            stderr: Vec::new(),
        })
    }
}

#[derive(Default)]
struct CollapseRunner {
    commands: Mutex<Vec<CommandSpec>>,
}

impl CollapseRunner {
    fn commands(&self) -> Vec<CommandSpec> {
        self.commands.lock().unwrap().clone()
    }
}

impl CommandRunner for CollapseRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        Ok(CommandOutput {
            status_code: Some(0),
            stdout: b"app;work 2\napp;io 1\n".to_vec(),
            stderr: Vec::new(),
        })
    }
}

#[derive(Default)]
struct BenchCommandRunner {
    commands: Mutex<Vec<CommandSpec>>,
}

impl CommandRunner for BenchCommandRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        let stdout = match command.program.as_str() {
            "inferno-collapse-perf" => b"[unknown];0x2000 1\n".to_vec(),
            "inferno-flamegraph" => {
                let mut svg = b"<svg>".to_vec();
                svg.extend(command.stdin.as_deref().unwrap_or_default());
                svg.extend(b"</svg>\n");
                svg
            }
            program => panic!("unexpected command: {program}"),
        };
        Ok(CommandOutput {
            status_code: Some(0),
            stdout,
            stderr: Vec::new(),
        })
    }
}

#[derive(Default)]
struct MatchingCollapseRunner {
    commands: Mutex<Vec<CommandSpec>>,
}

impl CommandRunner for MatchingCollapseRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        if command.program == "inferno-flamegraph" {
            return Ok(CommandOutput {
                status_code: Some(0),
                stdout: b"<svg>0x2000 2\n</svg>\n".to_vec(),
                stderr: Vec::new(),
            });
        }
        Ok(CommandOutput {
            status_code: Some(0),
            stdout: b"[unknown];0x2000 2\n".to_vec(),
            stderr: Vec::new(),
        })
    }
}

#[derive(Default)]
struct Addr2lineRunner {
    commands: Mutex<Vec<CommandSpec>>,
}

impl Addr2lineRunner {
    fn programs(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .map(|command| command.program.clone())
            .collect()
    }
}

impl CommandRunner for Addr2lineRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        Ok(CommandOutput {
            status_code: Some(0),
            stdout: b"app::main\n/bin/app.rs:10\n".to_vec(),
            stderr: Vec::new(),
        })
    }
}

#[derive(Default)]
struct SymbolizedCompareRunner {
    commands: Mutex<Vec<CommandSpec>>,
}

impl SymbolizedCompareRunner {
    fn programs(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .map(|command| command.program.clone())
            .collect()
    }
}

impl CommandRunner for SymbolizedCompareRunner {
    fn run(&self, command: &CommandSpec) -> std::io::Result<CommandOutput> {
        self.commands.lock().unwrap().push(command.clone());
        let stdout = match command.program.as_str() {
            "addr2line" => b"app::main\n/bin/app.rs:10\n".to_vec(),
            "inferno-collapse-perf" => b"[unknown];app::main 1\n".to_vec(),
            "inferno-flamegraph" => {
                let mut svg = b"<svg>".to_vec();
                svg.extend(command.stdin.as_deref().unwrap_or_default());
                svg.extend(b"</svg>\n");
                svg
            }
            _ => Vec::new(),
        };
        Ok(CommandOutput {
            status_code: Some(0),
            stdout,
            stderr: Vec::new(),
        })
    }
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

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
