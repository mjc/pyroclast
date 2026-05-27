use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use crate::flamegraph::build_inferno_flamegraph_command;
use crate::perfdata::fold::{
    FoldOptions, fold_perfdata_file_with_options, fold_perfdata_file_with_symbols,
    write_folded_perfdata_file_with_options, write_folded_perfdata_file_with_symbols,
    write_inferno_perf_script_file_with_options, write_inferno_perf_script_file_with_symbols,
};
use crate::process::{CommandRunner, CommandSpec};
use crate::symbols::perf_symbol_resolver_for_current_home;
use blake3::Hash;

const PIPE_BUFFER_CAPACITY: usize = 1024 * 1024;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BenchArgs {
    pub perf_data: Option<PathBuf>,
    pub perf_script: Option<PathBuf>,
    pub export_perf_script: Option<PathBuf>,
    pub symbols: bool,
}

impl BenchArgs {
    #[must_use]
    pub fn parse(args: Vec<PathBuf>) -> Self {
        let mut parsed = Self::default();
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            if arg.as_os_str() == "--perf-script" {
                parsed.perf_script = iter.next();
            } else if arg.as_os_str() == "--export-perf-script" {
                parsed.export_perf_script = iter.next();
            } else if arg.as_os_str() == "--symbols" {
                parsed.symbols = true;
            } else {
                parsed.perf_data = Some(arg);
            }
        }
        parsed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FoldBenchmarkReport {
    pub input: PathBuf,
    pub elapsed: Duration,
    pub folded_bytes: usize,
    pub folded_lines: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FoldComparisonReport {
    pub pyroclast_folded_lines: usize,
    pub inferno_folded_lines: usize,
    pub matches: bool,
    pub svg_matches: bool,
    pub pyroclast_svg_bytes: usize,
    pub inferno_svg_bytes: usize,
    pub only_pyroclast: Vec<String>,
    pub only_inferno: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamingComparisonReport {
    pub pyroclast_fold: FoldBenchmarkReport,
    pub inferno_fold: FoldBenchmarkReport,
    pub comparison: FoldComparisonReport,
}

/// Folds a `perf.data` file and returns timing and output-size metadata.
///
/// # Errors
///
/// Returns an error when the input file cannot be mapped or parsed.
pub fn run_fold_benchmark(input: &Path) -> Result<FoldBenchmarkReport, String> {
    run_fold_benchmark_with_writer(input, |writer| {
        write_folded_perfdata_file_with_options(input, benchmark_fold_options(), writer)
    })
}

/// Folds a `perf.data` file with an optional symbolizing runner and returns
/// timing and output-size metadata.
///
/// # Errors
///
/// Returns an error when the input file cannot be mapped, parsed, or
/// symbolized.
pub fn run_fold_benchmark_with_runner<R>(
    input: &Path,
    runner: &R,
    symbols: bool,
) -> Result<FoldBenchmarkReport, String>
where
    R: CommandRunner,
{
    if symbols {
        let resolver = perf_symbol_resolver_for_current_home(runner, input);
        run_fold_benchmark_with_writer(input, |writer| {
            write_folded_perfdata_file_with_symbols(
                input,
                benchmark_fold_options(),
                &resolver,
                writer,
            )
        })
    } else {
        run_fold_benchmark(input)
    }
}

fn run_fold_benchmark_with_writer<F>(
    input: &Path,
    write_folded: F,
) -> Result<FoldBenchmarkReport, String>
where
    F: FnOnce(&mut dyn Write) -> Result<(), String>,
{
    let started = Instant::now();
    let mut writer = CountingWriter::new(std::io::sink());
    write_folded(&mut writer)?;
    let elapsed = started.elapsed();
    let (folded_bytes, folded_lines) = writer.counts();
    Ok(FoldBenchmarkReport {
        input: input.to_path_buf(),
        elapsed,
        folded_bytes,
        folded_lines,
    })
}

/// Runs `inferno-collapse-perf` over a saved `perf script` text file and
/// returns timing and output-size metadata.
///
/// # Errors
///
/// Returns an error when the collapse command cannot run or exits nonzero.
pub fn run_inferno_collapse_benchmark<R>(
    input: &Path,
    runner: &R,
) -> Result<FoldBenchmarkReport, String>
where
    R: CommandRunner,
{
    let started = Instant::now();
    let output = runner
        .run(&CommandSpec::new("inferno-collapse-perf").arg(input.display().to_string()))
        .map_err(|error| format!("failed to run inferno-collapse-perf: {error}"))?;
    if output.status_code != Some(0) {
        return Err(format!(
            "inferno-collapse-perf exited with {:?}",
            output.status_code
        ));
    }
    let elapsed = started.elapsed();
    let folded = String::from_utf8_lossy(&output.stdout);
    Ok(FoldBenchmarkReport {
        input: input.to_path_buf(),
        elapsed,
        folded_bytes: output.stdout.len(),
        folded_lines: folded.lines().count(),
    })
}

#[must_use]
pub fn format_comparison_report(name: &str, report: &FoldComparisonReport) -> String {
    format!(
        concat!(
            "{name}.matches={matches}\n",
            "{name}.svg_matches={svg_matches}\n",
            "{name}.pyroclast_folded_lines={pyroclast_folded_lines}\n",
            "{name}.inferno_folded_lines={inferno_folded_lines}\n",
            "{name}.pyroclast_svg_bytes={pyroclast_svg_bytes}\n",
            "{name}.inferno_svg_bytes={inferno_svg_bytes}\n",
            "{name}.only_pyroclast={only_pyroclast}\n",
            "{name}.only_inferno={only_inferno}\n",
        ),
        name = name,
        matches = report.matches,
        svg_matches = report.svg_matches,
        pyroclast_folded_lines = report.pyroclast_folded_lines,
        inferno_folded_lines = report.inferno_folded_lines,
        pyroclast_svg_bytes = report.pyroclast_svg_bytes,
        inferno_svg_bytes = report.inferno_svg_bytes,
        only_pyroclast = report.only_pyroclast.len(),
        only_inferno = report.only_inferno.len(),
    )
}

/// Compares Pyroclast's direct folded stacks with the old
/// `perf script | inferno-collapse-perf` folded-stack output.
///
/// # Errors
///
/// Returns an error when Pyroclast cannot fold the `perf.data`, Inferno cannot
/// collapse the saved script, or either folded output is malformed.
pub fn compare_with_inferno_collapse<R>(
    perf_data: &Path,
    perf_script: &Path,
    runner: &R,
) -> Result<FoldComparisonReport, String>
where
    R: CommandRunner,
{
    compare_with_inferno_collapse_with_symbols(perf_data, perf_script, runner, false)
}

/// Compares Pyroclast's direct folded stacks with the old
/// `perf script | inferno-collapse-perf` folded-stack output, optionally using
/// Pyroclast's symbolizing fold path.
///
/// # Errors
///
/// Returns an error when Pyroclast cannot fold the `perf.data`, Inferno cannot
/// collapse the saved script, either SVG render fails, or either folded output
/// is malformed.
pub fn compare_with_inferno_collapse_with_symbols<R>(
    perf_data: &Path,
    perf_script: &Path,
    runner: &R,
    symbols: bool,
) -> Result<FoldComparisonReport, String>
where
    R: CommandRunner,
{
    let pyroclast_folded = if symbols {
        let resolver = perf_symbol_resolver_for_current_home(runner, perf_data);
        fold_perfdata_file_with_symbols(perf_data, benchmark_fold_options(), &resolver)?
    } else {
        fold_perfdata_file_with_options(perf_data, benchmark_fold_options())?
    };
    let inferno_output = runner
        .run(&CommandSpec::new("inferno-collapse-perf").arg(perf_script.display().to_string()))
        .map_err(|error| format!("failed to run inferno-collapse-perf: {error}"))?;
    if inferno_output.status_code != Some(0) {
        return Err(format!(
            "inferno-collapse-perf exited with {:?}",
            inferno_output.status_code
        ));
    }
    let inferno_folded = String::from_utf8_lossy(&inferno_output.stdout);
    let pyroclast = parse_folded_counts(&pyroclast_folded)?;
    let inferno = parse_folded_counts(&inferno_folded)?;
    let only_pyroclast = folded_difference(&pyroclast, &inferno);
    let only_inferno = folded_difference(&inferno, &pyroclast);
    let pyroclast_svg = render_inferno_svg("Pyroclast comparison", &pyroclast_folded, runner)?;
    let inferno_svg = render_inferno_svg("Pyroclast comparison", &inferno_folded, runner)?;
    let svg_matches = pyroclast_svg == inferno_svg;

    Ok(FoldComparisonReport {
        pyroclast_folded_lines: pyroclast.len(),
        inferno_folded_lines: inferno.len(),
        matches: only_pyroclast.is_empty() && only_inferno.is_empty() && svg_matches,
        svg_matches,
        pyroclast_svg_bytes: pyroclast_svg.len(),
        inferno_svg_bytes: inferno_svg.len(),
        only_pyroclast,
        only_inferno,
    })
}

/// Streams Pyroclast and Inferno folded outputs through pipes so benchmarking
/// and comparison do not retain multi-gigabyte intermediates in memory.
///
/// # Errors
///
/// Returns an error when folding, collapsing, SVG rendering, or folded-output
/// comparison fails.
pub fn run_streaming_comparison_with_symbols<R>(
    perf_data: &Path,
    perf_script: Option<&Path>,
    runner: &R,
    symbols: bool,
) -> Result<StreamingComparisonReport, String>
where
    R: CommandRunner + Sync,
{
    thread::scope(|scope| {
        let (pyro_tx, pyro_rx) = sync_channel(64);
        let (inferno_tx, inferno_rx) = sync_channel(64);
        let pyro_thread =
            scope.spawn(move || run_pyroclast_stream(perf_data, runner, symbols, pyro_tx));
        let inferno_thread = scope
            .spawn(move || run_inferno_stream(perf_data, perf_script, runner, symbols, inferno_tx));
        let diff = compare_folded_line_receivers(&pyro_rx, &inferno_rx)?;
        let pyro = match pyro_thread.join() {
            Ok(result) => result?,
            Err(_) => return Err("pyroclast fold thread panicked".to_string()),
        };
        let inferno = match inferno_thread.join() {
            Ok(result) => result?,
            Err(_) => return Err("inferno collapse thread panicked".to_string()),
        };
        let svg_matches = pyro.svg.hash == inferno.svg.hash;

        Ok(StreamingComparisonReport {
            pyroclast_fold: pyro.report.clone(),
            inferno_fold: inferno.report.clone(),
            comparison: FoldComparisonReport {
                pyroclast_folded_lines: pyro.report.folded_lines,
                inferno_folded_lines: inferno.report.folded_lines,
                matches: diff.matches && svg_matches,
                svg_matches,
                pyroclast_svg_bytes: pyro.svg.bytes,
                inferno_svg_bytes: inferno.svg.bytes,
                only_pyroclast: diff.only_pyroclast,
                only_inferno: diff.only_inferno,
            },
        })
    })
}

/// Exports `perf script` text for old-pipeline benchmarking.
///
/// This is intentionally benchmark-only; Pyroclast's normal fold path parses
/// `perf.data` directly.
///
/// # Errors
///
/// Returns an error when the `perf.data` input cannot be parsed, symbolized, or
/// the output file cannot be written.
pub fn export_perf_script<R>(
    perf_data: &Path,
    output: &Path,
    runner: &R,
    symbols: bool,
) -> Result<(), String>
where
    R: CommandRunner,
{
    let file = std::fs::File::create(output)
        .map_err(|error| format!("failed to create perf script output: {error}"))?;
    let mut writer = std::io::BufWriter::new(file);
    if symbols {
        let resolver = perf_symbol_resolver_for_current_home(runner, perf_data);
        write_inferno_perf_script_file_with_symbols(
            perf_data,
            benchmark_fold_options(),
            &resolver,
            &mut writer,
        )?;
    } else {
        write_inferno_perf_script_file_with_options(
            perf_data,
            benchmark_fold_options(),
            &mut writer,
        )?;
    }
    writer
        .flush()
        .map_err(|error| format!("failed to flush perf script output: {error}"))
}

fn parse_folded_counts(folded: &str) -> Result<BTreeMap<String, u64>, String> {
    let mut counts = BTreeMap::new();
    for line in folded.lines().filter(|line| !line.trim().is_empty()) {
        let (stack, count) = line
            .rsplit_once(' ')
            .ok_or_else(|| format!("folded stack line is missing count: {line}"))?;
        let count = count
            .parse::<u64>()
            .map_err(|error| format!("folded stack count is invalid: {error}"))?;
        *counts.entry(stack.to_string()).or_insert(0) += count;
    }
    Ok(counts)
}

fn folded_difference(left: &BTreeMap<String, u64>, right: &BTreeMap<String, u64>) -> Vec<String> {
    left.iter()
        .filter(|(stack, count)| right.get(*stack).copied().unwrap_or(0) != **count)
        .map(|(stack, count)| format!("{stack} {count}"))
        .collect()
}

fn render_inferno_svg<R>(title: &str, folded: &str, runner: &R) -> Result<Vec<u8>, String>
where
    R: CommandRunner,
{
    let command = build_inferno_flamegraph_command(title).stdin(folded.as_bytes().to_vec());
    let output = runner
        .run(&command)
        .map_err(|error| format!("failed to run inferno-flamegraph: {error}"))?;
    if output.status_code != Some(0) {
        return Err(format!(
            "inferno-flamegraph exited with {:?}",
            output.status_code
        ));
    }
    Ok(output.stdout)
}

const MAX_REPORTED_DIFFERENCES: usize = 1_000;

#[derive(Debug)]
struct CountingWriter<W> {
    inner: W,
    bytes: usize,
    lines: usize,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            bytes: 0,
            lines: 0,
        }
    }

    fn counts(&self) -> (usize, usize) {
        (self.bytes, self.lines)
    }

    fn into_inner_and_counts(self) -> (W, (usize, usize)) {
        (self.inner, (self.bytes, self.lines))
    }
}

#[allow(clippy::naive_bytecount)]
impl<W> Write for CountingWriter<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.bytes += written;
        self.lines += buf[..written].iter().filter(|byte| **byte == b'\n').count();
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Debug)]
struct TeeWriter<A, B> {
    left: A,
    right: B,
}

impl<A, B> TeeWriter<A, B> {
    fn new(left: A, right: B) -> Self {
        Self { left, right }
    }
}

impl<A, B> Write for TeeWriter<A, B>
where
    A: Write,
    B: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.left.write_all(buf)?;
        self.right.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.left.flush()?;
        self.right.flush()
    }
}

#[derive(Debug)]
struct LineChannelWriter {
    sender: SyncSender<String>,
    buffer: Vec<u8>,
}

impl LineChannelWriter {
    fn new(sender: SyncSender<String>) -> Self {
        Self {
            sender,
            buffer: Vec::new(),
        }
    }

    fn emit_complete_lines(&mut self) -> std::io::Result<()> {
        let mut consumed = 0;
        while let Some(newline) = self.buffer[consumed..]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            let end = consumed + newline;
            let line = self.buffer[consumed..end].to_vec();
            let line = String::from_utf8(line)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            self.sender.send(line).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "receiver closed")
            })?;
            consumed = end + 1;
        }
        if consumed > 0 {
            self.buffer.drain(..consumed);
        }
        Ok(())
    }
}

impl Write for LineChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        self.emit_complete_lines()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SvgDigest {
    bytes: usize,
    hash: Hash,
}

#[derive(Debug)]
struct ProducerResult {
    report: FoldBenchmarkReport,
    svg: SvgDigest,
}

#[derive(Debug)]
struct DiffSummary {
    matches: bool,
    only_pyroclast: Vec<String>,
    only_inferno: Vec<String>,
}

#[derive(Debug)]
struct FoldedEntry {
    raw: String,
    stack: String,
    count: u64,
}

type SpawnedFlamegraph = (
    std::process::Child,
    std::process::ChildStdin,
    thread::JoinHandle<Result<SvgDigest, String>>,
    thread::JoinHandle<Result<Vec<u8>, String>>,
);

fn run_pyroclast_stream<R>(
    perf_data: &Path,
    runner: &R,
    symbols: bool,
    line_sender: SyncSender<String>,
) -> Result<ProducerResult, String>
where
    R: CommandRunner + Sync,
{
    let perf_data = perf_data.to_path_buf();
    let started = Instant::now();
    let (mut flamegraph, flamegraph_stdin, svg_thread, stderr_thread) =
        spawn_inferno_flamegraph_process("Pyroclast comparison")?;
    let line_writer = LineChannelWriter::new(line_sender);
    let tee = TeeWriter::new(
        line_writer,
        BufWriter::with_capacity(PIPE_BUFFER_CAPACITY, flamegraph_stdin),
    );
    let mut writer = CountingWriter::new(tee);
    if symbols {
        let resolver = perf_symbol_resolver_for_current_home(runner, &perf_data);
        write_folded_perfdata_file_with_symbols(
            &perf_data,
            benchmark_fold_options(),
            &resolver,
            &mut writer,
        )?;
    } else {
        write_folded_perfdata_file_with_options(&perf_data, benchmark_fold_options(), &mut writer)?;
    }
    writer
        .flush()
        .map_err(|error| format!("failed to flush pyroclast comparison output: {error}"))?;
    let elapsed = started.elapsed();
    let (tee, (folded_bytes, folded_lines)) = writer.into_inner_and_counts();
    drop(tee);
    let svg = finish_hashed_child(
        &mut flamegraph,
        svg_thread,
        stderr_thread,
        "inferno-flamegraph",
    )?;
    Ok(ProducerResult {
        report: FoldBenchmarkReport {
            input: perf_data,
            elapsed,
            folded_bytes,
            folded_lines,
        },
        svg,
    })
}

#[allow(clippy::too_many_lines)]
fn run_inferno_stream<R>(
    perf_data: &Path,
    perf_script: Option<&Path>,
    runner: &R,
    symbols: bool,
    line_sender: SyncSender<String>,
) -> Result<ProducerResult, String>
where
    R: CommandRunner + Sync,
{
    let perf_data = perf_data.to_path_buf();
    let perf_script = perf_script.map(Path::to_path_buf);
    let started = Instant::now();
    let mut collapse_command = Command::new("inferno-collapse-perf");
    if let Some(path) = &perf_script {
        collapse_command.arg(path);
    }
    collapse_command.stdin(if perf_script.is_some() {
        Stdio::null()
    } else {
        Stdio::piped()
    });
    let mut collapse = collapse_command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to run inferno-collapse-perf: {error}"))?;
    let mut collapse_stdout = collapse
        .stdout
        .take()
        .ok_or_else(|| "failed to capture inferno-collapse-perf stdout".to_string())?;
    let collapse_stderr = collapse
        .stderr
        .take()
        .ok_or_else(|| "failed to capture inferno-collapse-perf stderr".to_string())?;
    let collapse_stderr_thread = thread::spawn(move || read_all(collapse_stderr));
    let mut collapse_stdin = collapse.stdin.take();

    let (mut flamegraph, flamegraph_stdin, svg_thread, stderr_thread) =
        spawn_inferno_flamegraph_process("Pyroclast comparison")?;
    let line_writer = LineChannelWriter::new(line_sender);
    let tee = TeeWriter::new(
        line_writer,
        BufWriter::with_capacity(PIPE_BUFFER_CAPACITY, flamegraph_stdin),
    );
    let mut writer = CountingWriter::new(tee);
    thread::scope(|scope| -> Result<(), String> {
        let export_thread = match collapse_stdin.take() {
            Some(stdin) => {
                let export_perf_data = perf_data.clone();
                Some(scope.spawn(move || -> Result<(), String> {
                    let mut stdin = BufWriter::with_capacity(PIPE_BUFFER_CAPACITY, stdin);
                    if symbols {
                        let resolver =
                            perf_symbol_resolver_for_current_home(runner, &export_perf_data);
                        write_inferno_perf_script_file_with_symbols(
                            &export_perf_data,
                            benchmark_fold_options(),
                            &resolver,
                            &mut stdin,
                        )
                    } else {
                        write_inferno_perf_script_file_with_options(
                            &export_perf_data,
                            benchmark_fold_options(),
                            &mut stdin,
                        )
                    }?;
                    stdin.flush().map_err(|error| {
                        format!("failed to flush inferno-collapse-perf stdin: {error}")
                    })
                }))
            }
            None => None,
        };
        std::io::copy(&mut collapse_stdout, &mut writer)
            .map_err(|error| format!("failed to stream inferno-collapse-perf output: {error}"))?;
        writer
            .flush()
            .map_err(|error| format!("failed to flush inferno comparison output: {error}"))?;
        if let Some(thread) = export_thread {
            match thread.join() {
                Ok(result) => result?,
                Err(_) => return Err("perf script export thread panicked".to_string()),
            }
        }
        Ok(())
    })?;
    let status = collapse
        .wait()
        .map_err(|error| format!("failed to wait for inferno-collapse-perf: {error}"))?;
    let stderr = join_io_thread(collapse_stderr_thread, "inferno-collapse-perf stderr")?;
    if !status.success() {
        return Err(format!(
            "inferno-collapse-perf exited with {status}: {}",
            String::from_utf8_lossy(&stderr)
        ));
    }
    let elapsed = started.elapsed();
    let (tee, (folded_bytes, folded_lines)) = writer.into_inner_and_counts();
    drop(tee);
    let svg = finish_hashed_child(
        &mut flamegraph,
        svg_thread,
        stderr_thread,
        "inferno-flamegraph",
    )?;
    Ok(ProducerResult {
        report: FoldBenchmarkReport {
            input: perf_script.unwrap_or(perf_data),
            elapsed,
            folded_bytes,
            folded_lines,
        },
        svg,
    })
}

fn spawn_inferno_flamegraph_process(title: &str) -> Result<SpawnedFlamegraph, String> {
    let spec = build_inferno_flamegraph_command(title);
    let mut command = Command::new(&spec.program);
    command.args(&spec.args);
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to run inferno-flamegraph: {error}"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| "failed to open inferno-flamegraph stdin".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture inferno-flamegraph stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture inferno-flamegraph stderr".to_string())?;
    let svg_thread = thread::spawn(move || hash_reader(stdout));
    let stderr_thread = thread::spawn(move || read_all(stderr));
    Ok((child, stdin, svg_thread, stderr_thread))
}

fn finish_hashed_child(
    child: &mut std::process::Child,
    svg_thread: thread::JoinHandle<Result<SvgDigest, String>>,
    stderr_thread: thread::JoinHandle<Result<Vec<u8>, String>>,
    program: &str,
) -> Result<SvgDigest, String> {
    let status = child
        .wait()
        .map_err(|error| format!("failed to wait for {program}: {error}"))?;
    let svg = join_result_thread(svg_thread, &format!("{program} stdout"))?;
    let stderr = join_result_thread(stderr_thread, &format!("{program} stderr"))?;
    if !status.success() {
        return Err(format!(
            "{program} exited with {status}: {}",
            String::from_utf8_lossy(&stderr)
        ));
    }
    Ok(svg)
}

fn compare_folded_line_receivers(
    pyroclast: &Receiver<String>,
    inferno: &Receiver<String>,
) -> Result<DiffSummary, String> {
    let mut left = next_folded_entry(pyroclast)?;
    let mut right = next_folded_entry(inferno)?;
    let mut matches = true;
    let mut only_pyroclast = Vec::new();
    let mut only_inferno = Vec::new();
    while left.is_some() || right.is_some() {
        match (&left, &right) {
            (Some(left_entry), Some(right_entry)) => match left_entry.stack.cmp(&right_entry.stack)
            {
                Ordering::Less => {
                    matches = false;
                    record_difference(&mut only_pyroclast, &left_entry.raw);
                    left = next_folded_entry(pyroclast)?;
                }
                Ordering::Greater => {
                    matches = false;
                    record_difference(&mut only_inferno, &right_entry.raw);
                    right = next_folded_entry(inferno)?;
                }
                Ordering::Equal => {
                    if left_entry.count != right_entry.count {
                        matches = false;
                        record_difference(&mut only_pyroclast, &left_entry.raw);
                        record_difference(&mut only_inferno, &right_entry.raw);
                    }
                    left = next_folded_entry(pyroclast)?;
                    right = next_folded_entry(inferno)?;
                }
            },
            (Some(left_entry), None) => {
                matches = false;
                record_difference(&mut only_pyroclast, &left_entry.raw);
                left = next_folded_entry(pyroclast)?;
            }
            (None, Some(right_entry)) => {
                matches = false;
                record_difference(&mut only_inferno, &right_entry.raw);
                right = next_folded_entry(inferno)?;
            }
            (None, None) => break,
        }
    }
    Ok(DiffSummary {
        matches,
        only_pyroclast,
        only_inferno,
    })
}

fn next_folded_entry(receiver: &Receiver<String>) -> Result<Option<FoldedEntry>, String> {
    match receiver.recv() {
        Ok(raw) => {
            let (stack, count) = raw
                .rsplit_once(' ')
                .ok_or_else(|| format!("folded stack line is missing count: {raw}"))?;
            let count = count
                .parse::<u64>()
                .map_err(|error| format!("folded stack count is invalid: {error}"))?;
            let stack = stack.to_string();
            Ok(Some(FoldedEntry { raw, stack, count }))
        }
        Err(_) => Ok(None),
    }
}

fn record_difference(differences: &mut Vec<String>, line: &str) {
    if differences.len() < MAX_REPORTED_DIFFERENCES {
        differences.push(line.to_string());
    }
}

fn hash_reader<R>(mut reader: R) -> Result<SvgDigest, String>
where
    R: Read,
{
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0usize;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("failed to read child output: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes += read;
    }
    Ok(SvgDigest {
        bytes,
        hash: hasher.finalize(),
    })
}

fn read_all<R>(mut reader: R) -> Result<Vec<u8>, String>
where
    R: Read,
{
    let mut output = Vec::new();
    reader
        .read_to_end(&mut output)
        .map_err(|error| format!("failed to read child stderr: {error}"))?;
    Ok(output)
}

fn join_io_thread(
    handle: thread::JoinHandle<Result<Vec<u8>, String>>,
    name: &str,
) -> Result<Vec<u8>, String> {
    join_result_thread(handle, name)
}

fn join_result_thread<T>(
    handle: thread::JoinHandle<Result<T, String>>,
    name: &str,
) -> Result<T, String> {
    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(format!("{name} thread panicked")),
    }
}

fn benchmark_fold_options() -> FoldOptions {
    FoldOptions {
        count_periods: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counting_writer_tracks_bytes_and_lines() {
        let mut writer = CountingWriter::new(Vec::new());
        writer.write_all(b"one\ntwo\nthree").unwrap();

        assert_eq!(writer.counts(), (13, 2));
    }

    #[test]
    fn compares_sorted_folded_receivers_without_buffering_all_lines() {
        let (left_tx, left_rx) = sync_channel(4);
        let (right_tx, right_rx) = sync_channel(4);
        left_tx.send("a 1".to_string()).unwrap();
        left_tx.send("c 2".to_string()).unwrap();
        drop(left_tx);
        right_tx.send("a 1".to_string()).unwrap();
        right_tx.send("b 3".to_string()).unwrap();
        drop(right_tx);

        let diff = compare_folded_line_receivers(&left_rx, &right_rx).unwrap();

        assert!(!diff.matches);
        assert_eq!(diff.only_pyroclast, vec!["c 2"]);
        assert_eq!(diff.only_inferno, vec!["b 3"]);
    }
}
