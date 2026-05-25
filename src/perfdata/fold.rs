use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::folded::render_folded_stack;
use crate::perfdata::attrs::parse_file_attrs;
use crate::perfdata::header::parse_header;
use crate::perfdata::mappings::{MmapTable, ResolvedMapping};
use crate::perfdata::records::{
    iter_records, parse_comm_record, parse_mmap_record, parse_mmap2_record,
};
use crate::perfdata::samples::{SampleLayout, is_perf_context_marker, parse_sample_record};
use crate::symbols::{SymbolCache, SymbolRequest, SymbolResolver};

const PERF_RECORD_MMAP: u32 = 1;
const PERF_RECORD_COMM: u32 = 3;
const PERF_RECORD_SAMPLE: u32 = 9;
const PERF_RECORD_MMAP2: u32 = 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfSummary {
    pub total_records: usize,
    pub record_counts: BTreeMap<u32, usize>,
    pub comms: Vec<String>,
    pub comms_by_pid: BTreeMap<u32, String>,
    pub mmaps: Vec<String>,
    pub mmap_table: MmapTable,
    pub sample_callchains: Vec<Vec<u64>>,
    pub sample_stacks: Vec<PerfSampleStack>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfSampleStack {
    pub pid: Option<u32>,
    pub period: Option<u64>,
    pub callchain: Vec<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FoldOptions {
    pub count_periods: bool,
}

impl PerfSummary {
    #[must_use]
    pub fn record_count(&self, record_type: u32) -> usize {
        self.record_counts.get(&record_type).copied().unwrap_or(0)
    }
}

impl PerfSampleStack {
    fn count(&self, options: FoldOptions) -> u64 {
        if options.count_periods {
            self.period.unwrap_or(1)
        } else {
            1
        }
    }
}

/// Summarizes record counts and parsed sample callchains from `perf.data`.
///
/// # Errors
///
/// Returns an error when the file header, attr section, record stream, or a
/// supported record payload is malformed.
pub fn summarize_perfdata(bytes: &[u8]) -> Result<PerfSummary, String> {
    let header = parse_header(bytes)?;
    let sample_layout = first_sample_layout(bytes, header)?;
    let records = iter_records(bytes, header)?;
    let mut summary = PerfSummary {
        total_records: 0,
        record_counts: BTreeMap::new(),
        comms: Vec::new(),
        comms_by_pid: BTreeMap::new(),
        mmaps: Vec::new(),
        mmap_table: MmapTable::default(),
        sample_callchains: Vec::new(),
        sample_stacks: Vec::new(),
    };

    for record in records {
        summary.total_records += 1;
        *summary
            .record_counts
            .entry(record.header.record_type)
            .or_insert(0) += 1;
        let record_result: Result<(), String> = match record.header.record_type {
            PERF_RECORD_COMM => parse_comm_record(record.payload).map(|record| {
                summary.comms_by_pid.insert(record.pid, record.comm.clone());
                summary.comms.push(record.comm);
            }),
            PERF_RECORD_MMAP => parse_mmap_record(record.payload).map(|record| {
                summary.mmaps.push(record.path.clone());
                summary.mmap_table.insert_mmap(record);
            }),
            PERF_RECORD_SAMPLE => {
                parse_sample_for_summary(record.payload, sample_layout).map(|sample| {
                    if let Some(sample) = sample {
                        summary.sample_callchains.push(sample.callchain.clone());
                        summary.sample_stacks.push(sample);
                    }
                })
            }
            PERF_RECORD_MMAP2 => parse_mmap2_record(record.payload).map(|record| {
                summary.mmaps.push(record.path.clone());
                summary.mmap_table.insert_mmap2(record);
            }),
            _ => Ok(()),
        };
        record_result.map_err(|error| {
            format!(
                "failed to parse record type {} at offset {}: {error}",
                record.header.record_type, record.offset
            )
        })?;
    }

    Ok(summary)
}

/// Collapses parsed perf sample callchains into folded stack lines.
///
/// # Errors
///
/// Returns an error when the `perf.data` input cannot be parsed.
pub fn fold_perfdata_callchains(bytes: &[u8]) -> Result<String, String> {
    fold_perfdata_callchains_with_options(bytes, FoldOptions::default())
}

/// Collapses parsed perf sample callchains into folded stack lines.
///
/// # Errors
///
/// Returns an error when the `perf.data` input cannot be parsed.
pub fn fold_perfdata_callchains_with_options(
    bytes: &[u8],
    options: FoldOptions,
) -> Result<String, String> {
    let summary = summarize_perfdata(bytes)?;
    fold_summary::<NoopSymbolResolver>(&summary, options, None)
}

/// Collapses perf sample callchains from a `perf.data` file path.
///
/// # Errors
///
/// Returns an error when the file cannot be opened, mapped, or parsed.
pub fn fold_perfdata_file(path: &Path) -> Result<String, String> {
    fold_perfdata_file_with_options(path, FoldOptions::default())
}

/// Collapses perf sample callchains from a `perf.data` file path.
///
/// # Errors
///
/// Returns an error when the file cannot be opened, mapped, or parsed.
pub fn fold_perfdata_file_with_options(
    path: &Path,
    options: FoldOptions,
) -> Result<String, String> {
    let file =
        std::fs::File::open(path).map_err(|error| format!("failed to open perf.data: {error}"))?;
    let mapping = map_perfdata_file(&file)?;
    fold_perfdata_callchains_with_options(&mapping, options)
}

/// Collapses parsed perf sample callchains, symbolizing mapped frames through
/// the provided resolver.
///
/// # Errors
///
/// Returns an error when `perf.data` parsing or symbol resolution fails.
pub fn fold_perfdata_callchains_with_symbols<R>(
    bytes: &[u8],
    options: FoldOptions,
    symbol_resolver: &R,
) -> Result<String, String>
where
    R: SymbolResolver,
{
    let summary = summarize_perfdata(bytes)?;
    let mut symbol_cache = SymbolCache::new(symbol_resolver);
    fold_summary(&summary, options, Some(&mut symbol_cache))
}

/// Collapses symbolized perf sample callchains from a `perf.data` file path.
///
/// # Errors
///
/// Returns an error when file mapping, `perf.data` parsing, or symbol
/// resolution fails.
pub fn fold_perfdata_file_with_symbols<R>(
    path: &Path,
    options: FoldOptions,
    symbol_resolver: &R,
) -> Result<String, String>
where
    R: SymbolResolver,
{
    let file =
        std::fs::File::open(path).map_err(|error| format!("failed to open perf.data: {error}"))?;
    let mapping = map_perfdata_file(&file)?;
    fold_perfdata_callchains_with_symbols(&mapping, options, symbol_resolver)
}

fn map_perfdata_file(file: &std::fs::File) -> Result<memmap2::Mmap, String> {
    // SAFETY: The returned mapping is read-only and is only exposed as an
    // immutable byte slice while the file handle and mapping are alive in this
    // function's callers.
    unsafe { memmap2::MmapOptions::new().map(file) }
        .map_err(|error| format!("failed to map perf.data: {error}"))
}

fn fold_summary<R>(
    summary: &PerfSummary,
    options: FoldOptions,
    mut symbol_cache: Option<&mut SymbolCache<'_, R>>,
) -> Result<String, String>
where
    R: SymbolResolver,
{
    if let Some(cache) = symbol_cache.as_deref_mut() {
        prefetch_symbols(summary, cache)?;
    }
    let mut counts = BTreeMap::<Vec<String>, u64>::new();
    let frame_resolver = FoldFrameResolver::new(summary);
    for sample in &summary.sample_stacks {
        let frames = frame_resolver.frames_for_sample(sample, symbol_cache.as_deref_mut())?;
        *counts.entry(frames).or_insert(0) += sample.count(options);
    }

    let mut folded = String::new();
    for (callchain, count) in counts {
        folded.push_str(&render_folded_stack(
            callchain.iter().map(String::as_str),
            count,
        ));
        folded.push('\n');
    }
    Ok(folded)
}

fn prefetch_symbols<R>(
    summary: &PerfSummary,
    symbol_cache: &mut SymbolCache<'_, R>,
) -> Result<(), String>
where
    R: SymbolResolver,
{
    let requests = summary
        .sample_stacks
        .iter()
        .flat_map(|sample| symbol_requests_for_sample(sample, &summary.mmap_table))
        .collect::<Vec<_>>();
    symbol_cache.resolve_many(&requests).map(|_| ())
}

fn symbol_requests_for_sample(
    sample: &PerfSampleStack,
    mmap_table: &MmapTable,
) -> Vec<SymbolRequest> {
    sample
        .callchain
        .iter()
        .copied()
        .filter(|frame| !is_perf_context_marker(*frame))
        .filter_map(|frame| {
            sample
                .pid
                .and_then(|pid| mmap_table.resolve(pid, frame))
                .map(|mapping| symbol_request(&mapping))
        })
        .collect()
}

struct FoldFrameResolver<'a> {
    comms_by_pid: &'a BTreeMap<u32, String>,
    mmap_table: &'a MmapTable,
}

struct NoopSymbolResolver;

impl SymbolResolver for NoopSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(vec![None; requests.len()])
    }
}

impl<'a> FoldFrameResolver<'a> {
    fn new(summary: &'a PerfSummary) -> Self {
        Self {
            comms_by_pid: &summary.comms_by_pid,
            mmap_table: &summary.mmap_table,
        }
    }

    fn frames_for_sample<R>(
        &self,
        sample: &PerfSampleStack,
        mut symbol_cache: Option<&mut SymbolCache<'_, R>>,
    ) -> Result<Vec<String>, String>
    where
        R: SymbolResolver,
    {
        let mut frames = if let Some(comm) = sample.pid.and_then(|pid| self.comms_by_pid.get(&pid))
        {
            vec![comm.clone()]
        } else {
            Vec::new()
        };
        for frame in sample
            .callchain
            .iter()
            .copied()
            .filter(|frame| !is_perf_context_marker(*frame))
        {
            frames.push(self.format_frame(sample.pid, frame, symbol_cache.as_deref_mut())?);
        }
        Ok(frames)
    }

    fn format_frame<R>(
        &self,
        pid: Option<u32>,
        frame: u64,
        symbol_cache: Option<&mut SymbolCache<'_, R>>,
    ) -> Result<String, String>
    where
        R: SymbolResolver,
    {
        if let Some(mapping) = pid.and_then(|pid| self.mmap_table.resolve(pid, frame)) {
            if let Some(cache) = symbol_cache {
                return Ok(cache
                    .resolve(&symbol_request(&mapping))?
                    .unwrap_or_else(|| mapped_frame_label(&mapping)));
            }
            Ok(mapped_frame_label(&mapping))
        } else {
            Ok(format!("0x{frame:x}"))
        }
    }
}

fn symbol_request(mapping: &ResolvedMapping) -> SymbolRequest {
    SymbolRequest {
        path: PathBuf::from(&mapping.path),
        relative_address: mapping.relative_address,
    }
}

fn mapped_frame_label(mapping: &ResolvedMapping) -> String {
    format!("{}+0x{:x}", mapping.path, mapping.relative_address)
}

fn parse_sample_for_summary(
    payload: &[u8],
    sample_layout: Option<SampleLayout>,
) -> Result<Option<PerfSampleStack>, String> {
    if let Some(layout) = sample_layout {
        parse_sample_record(payload, layout).map(|record| {
            Some(PerfSampleStack {
                pid: record.pid,
                period: record.period,
                callchain: record.callchain,
            })
        })
    } else {
        Ok(None)
    }
}

fn first_sample_layout(
    bytes: &[u8],
    header: crate::perfdata::header::PerfHeader,
) -> Result<Option<SampleLayout>, String> {
    Ok(parse_file_attrs(bytes, header)?
        .first()
        .map(|attr| SampleLayout {
            sample_type: attr.sample_type,
        }))
}
