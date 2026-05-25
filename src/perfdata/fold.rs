use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::folded::render_folded_stack;
use crate::perfdata::attrs::{PerfFileAttr, parse_file_attr_ids, parse_file_attrs};
use crate::perfdata::header::parse_header;
use crate::perfdata::mappings::{MmapTable, ResolvedMapping};
use crate::perfdata::raw_stack::{CollapsedRawStack, RawStackAccumulator};
use crate::perfdata::records::{ParsedRecord, PerfRecord, iter_records, parse_record};
use crate::perfdata::samples::{
    PERF_SAMPLE_IDENTIFIER, SampleCallchainFrames, SampleLayout, is_kernel_space_frame,
    is_perf_context_marker, parse_sample_record, parse_sample_record_callchain,
};
use crate::symbols::{SymbolCache, SymbolRequest, SymbolResolver};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfSummary {
    pub total_records: usize,
    pub record_counts: BTreeMap<u32, usize>,
    pub comms: Vec<String>,
    pub comms_by_pid: BTreeMap<u32, String>,
    pub mmaps: Vec<String>,
    pub lost_records: u64,
    pub mmap_table: MmapTable,
    pub sample_stacks: Vec<PerfSampleStack>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfSampleStack {
    pub pid: Option<u32>,
    pub period: Option<u64>,
    pub callchain: Vec<u64>,
}

struct PerfFoldData {
    comms_by_pid: BTreeMap<u32, String>,
    mmap_table: MmapTable,
    raw_stacks: Vec<CollapsedRawStack>,
}

#[derive(Clone, Debug, Default)]
struct SampleLayouts {
    fallback: Option<SampleLayout>,
    by_identifier: BTreeMap<u64, SampleLayout>,
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

/// Summarizes record counts and parsed sample callchains from `perf.data`.
///
/// # Errors
///
/// Returns an error when the file header, attr section, record stream, or a
/// supported record payload is malformed.
pub fn summarize_perfdata(bytes: &[u8]) -> Result<PerfSummary, String> {
    let header = parse_header(bytes)?;
    let sample_layouts = sample_layouts(bytes, header)?;
    let records = iter_records(bytes, header)?;
    let mut summary = PerfSummary {
        total_records: 0,
        record_counts: BTreeMap::new(),
        comms: Vec::new(),
        comms_by_pid: BTreeMap::new(),
        mmaps: Vec::new(),
        lost_records: 0,
        mmap_table: MmapTable::default(),
        sample_stacks: Vec::new(),
    };

    for record in records {
        summary.total_records += 1;
        *summary
            .record_counts
            .entry(record.header.record_type)
            .or_insert(0) += 1;
        let parsed_record = parse_record_with_context(record)?;
        let record_result: Result<(), String> = match parsed_record {
            ParsedRecord::Comm(record) => {
                summary.comms_by_pid.insert(record.pid, record.comm.clone());
                summary.comms.push(record.comm);
                Ok(())
            }
            ParsedRecord::Lost(record) => {
                summary.lost_records = summary.lost_records.saturating_add(record.lost);
                Ok(())
            }
            ParsedRecord::LostSamples(record) => {
                summary.lost_records = summary.lost_records.saturating_add(record.lost);
                Ok(())
            }
            ParsedRecord::Mmap(record) => {
                summary.mmaps.push(record.path.clone());
                summary.mmap_table.insert_mmap(record);
                Ok(())
            }
            ParsedRecord::Sample(record) => {
                parse_sample_for_summary(&record.payload, &sample_layouts).map(|sample| {
                    if let Some(sample) = sample {
                        summary.sample_stacks.push(sample);
                    }
                })
            }
            ParsedRecord::Mmap2(record) => {
                summary.mmaps.push(record.path.clone());
                summary.mmap_table.insert_mmap2(record);
                Ok(())
            }
            ParsedRecord::Mmap2BuildId(record) => {
                summary.mmaps.push(record.path.clone());
                summary.mmap_table.insert_mmap2_build_id(record);
                Ok(())
            }
            ParsedRecord::Unsupported { .. }
            | ParsedRecord::Fork(_)
            | ParsedRecord::Exit(_)
            | ParsedRecord::Throttle(_)
            | ParsedRecord::Unthrottle(_)
            | ParsedRecord::Read(_)
            | ParsedRecord::Aux(_)
            | ParsedRecord::ItraceStart(_)
            | ParsedRecord::Switch(_)
            | ParsedRecord::SwitchCpuWide(_)
            | ParsedRecord::Namespaces(_)
            | ParsedRecord::Ksymbol(_)
            | ParsedRecord::BpfEvent(_)
            | ParsedRecord::Cgroup(_)
            | ParsedRecord::TextPoke(_)
            | ParsedRecord::AuxOutputHwId(_)
            | ParsedRecord::CallchainDeferred(_) => Ok(()),
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
    let fold_data = collect_fold_data(bytes, options)?;
    render_fold_data::<NoopSymbolResolver>(&fold_data, None)
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
    let fold_data = collect_fold_data(bytes, options)?;
    let mut symbol_cache = SymbolCache::new(symbol_resolver);
    render_fold_data(&fold_data, Some(&mut symbol_cache))
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

fn parse_record_with_context(record: PerfRecord<'_>) -> Result<ParsedRecord, String> {
    parse_record(record).map_err(|error| {
        format!(
            "failed to parse record type {} at offset {}: {error}",
            record.header.record_type, record.offset
        )
    })
}

fn collect_fold_data(bytes: &[u8], options: FoldOptions) -> Result<PerfFoldData, String> {
    let header = parse_header(bytes)?;
    let sample_layouts = sample_layouts(bytes, header)?;
    let records = iter_records(bytes, header)?;
    let mut comms_by_pid = BTreeMap::new();
    let mut mmap_table = MmapTable::default();
    let mut raw_stacks = RawStackAccumulator::new();
    let mut callchain = Vec::new();

    for record in records {
        let parsed_record = parse_record_with_context(record)?;
        let record_result: Result<(), String> = match parsed_record {
            ParsedRecord::Comm(record) => {
                comms_by_pid.insert(record.pid, record.comm);
                Ok(())
            }
            ParsedRecord::Mmap(record) => {
                mmap_table.insert_mmap(record);
                Ok(())
            }
            ParsedRecord::Sample(record) => {
                parse_sample_for_fold(&record.payload, &sample_layouts, options).map(|sample| {
                    if let Some((pid, count, frames)) = sample {
                        callchain.clear();
                        callchain.reserve(frames.len());
                        callchain.extend(frames.filter(|frame| !is_perf_context_marker(*frame)));
                        raw_stacks.add_slice(pid, &callchain, count);
                    }
                })
            }
            ParsedRecord::Mmap2(record) => {
                mmap_table.insert_mmap2(record);
                Ok(())
            }
            ParsedRecord::Mmap2BuildId(record) => {
                mmap_table.insert_mmap2_build_id(record);
                Ok(())
            }
            ParsedRecord::Unsupported { .. }
            | ParsedRecord::Lost(_)
            | ParsedRecord::LostSamples(_)
            | ParsedRecord::Fork(_)
            | ParsedRecord::Exit(_)
            | ParsedRecord::Throttle(_)
            | ParsedRecord::Unthrottle(_)
            | ParsedRecord::Read(_)
            | ParsedRecord::Aux(_)
            | ParsedRecord::ItraceStart(_)
            | ParsedRecord::Switch(_)
            | ParsedRecord::SwitchCpuWide(_)
            | ParsedRecord::Namespaces(_)
            | ParsedRecord::Ksymbol(_)
            | ParsedRecord::BpfEvent(_)
            | ParsedRecord::Cgroup(_)
            | ParsedRecord::TextPoke(_)
            | ParsedRecord::AuxOutputHwId(_)
            | ParsedRecord::CallchainDeferred(_) => Ok(()),
        };
        record_result.map_err(|error| {
            format!(
                "failed to parse record type {} at offset {}: {error}",
                record.header.record_type, record.offset
            )
        })?;
    }

    Ok(PerfFoldData {
        comms_by_pid,
        mmap_table,
        raw_stacks: raw_stacks.into_collapsed(),
    })
}

fn render_fold_data<R>(
    fold_data: &PerfFoldData,
    mut symbol_cache: Option<&mut SymbolCache<'_, R>>,
) -> Result<String, String>
where
    R: SymbolResolver,
{
    if let Some(cache) = symbol_cache.as_deref_mut() {
        prefetch_symbols(&fold_data.raw_stacks, &fold_data.mmap_table, cache)?;
    }
    let mut counts = BTreeMap::<Vec<String>, u64>::new();
    let frame_resolver = FoldFrameResolver::new(&fold_data.comms_by_pid, &fold_data.mmap_table);
    for stack in &fold_data.raw_stacks {
        let frames = frame_resolver.frames_for_stack(
            stack.pid,
            &stack.callchain,
            symbol_cache.as_deref_mut(),
        )?;
        *counts.entry(frames).or_insert(0) += stack.count;
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
    raw_stacks: &[CollapsedRawStack],
    mmap_table: &MmapTable,
    symbol_cache: &mut SymbolCache<'_, R>,
) -> Result<(), String>
where
    R: SymbolResolver,
{
    let requests = raw_stacks
        .iter()
        .flat_map(|stack| symbol_requests_for_stack(stack.pid, &stack.callchain, mmap_table))
        .collect::<Vec<_>>();
    symbol_cache.resolve_many(&requests).map(|_| ())
}

fn symbol_requests_for_stack(
    pid: Option<u32>,
    callchain: &[u64],
    mmap_table: &MmapTable,
) -> Vec<SymbolRequest> {
    callchain
        .iter()
        .copied()
        .filter(|frame| !is_kernel_space_frame(*frame))
        .filter_map(|frame| {
            pid.and_then(|pid| mmap_table.resolve(pid, frame))
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
    fn new(comms_by_pid: &'a BTreeMap<u32, String>, mmap_table: &'a MmapTable) -> Self {
        Self {
            comms_by_pid,
            mmap_table,
        }
    }

    fn frames_for_stack<R>(
        &self,
        pid: Option<u32>,
        callchain: &[u64],
        mut symbol_cache: Option<&mut SymbolCache<'_, R>>,
    ) -> Result<Vec<String>, String>
    where
        R: SymbolResolver,
    {
        let mut frames = if let Some(comm) = pid.and_then(|pid| self.comms_by_pid.get(&pid)) {
            vec![comm.clone()]
        } else {
            Vec::new()
        };
        for frame in callchain.iter().copied() {
            frames.push(self.format_frame(pid, frame, symbol_cache.as_deref_mut())?);
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
        if is_kernel_space_frame(frame) {
            return Ok(format!("0x{frame:x}"));
        }
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
    sample_layouts: &SampleLayouts,
) -> Result<Option<PerfSampleStack>, String> {
    if let Some(layout) = sample_layouts.layout_for_payload(payload)? {
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

fn parse_sample_for_fold<'a>(
    payload: &'a [u8],
    sample_layouts: &SampleLayouts,
    options: FoldOptions,
) -> Result<Option<(Option<u32>, u64, SampleCallchainFrames<'a>)>, String> {
    if let Some(layout) = sample_layouts.layout_for_payload(payload)? {
        parse_sample_record_callchain(payload, layout).map(|sample| {
            sample.map(|sample| {
                let count = if options.count_periods {
                    sample.period.unwrap_or(1)
                } else {
                    1
                };
                (sample.pid, count, sample.frames)
            })
        })
    } else {
        Ok(None)
    }
}

fn sample_layouts(
    bytes: &[u8],
    header: crate::perfdata::header::PerfHeader,
) -> Result<SampleLayouts, String> {
    let attrs = parse_file_attrs(bytes, header)?;
    let mut layouts = SampleLayouts {
        fallback: attrs.first().map(layout_from_attr),
        by_identifier: BTreeMap::new(),
    };
    for attr in &attrs {
        let layout = layout_from_attr(attr);
        for id in parse_file_attr_ids(bytes, attr)? {
            layouts.by_identifier.insert(id, layout);
        }
    }
    Ok(layouts)
}

fn layout_from_attr(attr: &PerfFileAttr) -> SampleLayout {
    SampleLayout {
        sample_type: attr.sample_type,
        read_format: attr.read_format,
        branch_sample_type: attr.branch_sample_type,
        sample_regs_user: attr.sample_regs_user,
        sample_regs_intr: attr.sample_regs_intr,
    }
}

impl SampleLayouts {
    fn layout_for_payload(&self, payload: &[u8]) -> Result<Option<SampleLayout>, String> {
        if self.by_identifier.is_empty() {
            return Ok(self.fallback);
        }
        let Some(fallback) = self.fallback else {
            return Ok(None);
        };
        if fallback.sample_type & PERF_SAMPLE_IDENTIFIER == 0 {
            return Ok(Some(fallback));
        }
        let identifier = payload
            .get(..8)
            .ok_or_else(|| "perf sample payload is truncated".to_string())
            .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("slice has 8 bytes")))?;
        Ok(self
            .by_identifier
            .get(&identifier)
            .copied()
            .or(Some(fallback)))
    }
}
