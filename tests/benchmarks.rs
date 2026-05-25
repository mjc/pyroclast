use std::sync::Mutex;

use pyroclast::benchmarks::{
    BenchArgs, compare_with_inferno_collapse, export_perf_script, format_comparison_report,
    run_fold_benchmark, run_inferno_collapse_benchmark,
};
use pyroclast::perfdata::samples::{PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_TID};
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
    assert_eq!(report.folded_bytes, 9);
    assert_eq!(report.folded_lines, 1);
    assert!(report.elapsed.as_nanos() > 0);
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
fn exports_perf_script_for_old_pipeline_benchmarks() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let perf_script = root.path().join("perf-script.txt");
    std::fs::write(&perfdata, b"PERFILE2 placeholder").expect("write perfdata");
    let runner = PerfScriptRunner::default();

    export_perf_script(&perfdata, &perf_script, &runner).expect("export perf script");

    assert_eq!(
        std::fs::read_to_string(&perf_script).unwrap(),
        "perf script\n"
    );
    assert_eq!(
        runner.commands(),
        vec![
            CommandSpec::new("perf")
                .args(["script", "-i"])
                .arg(perfdata.to_str().expect("perfdata path should be utf8"))
        ]
    );
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
        "--export-perf-script".into(),
        "exported-script.txt".into(),
        "--perf-script".into(),
        "perf-script.txt".into(),
    ]);

    assert_eq!(args.perf_data, Some("profile.perf.data".into()));
    assert_eq!(args.export_perf_script, Some("exported-script.txt".into()));
    assert_eq!(args.perf_script, Some("perf-script.txt".into()));
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
            stdout: b"0x2000 2\n".to_vec(),
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

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
