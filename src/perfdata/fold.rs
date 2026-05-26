use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};

use crate::folded::render_folded_stack;
use crate::perfdata::attrs::{PerfFileAttr, parse_file_attr_ids, parse_file_attrs};
use crate::perfdata::endian::read_u64;
use crate::perfdata::header::parse_header;
use crate::perfdata::mappings::{
    FileIdentity, MmapTable, ResolvedMapping, file_matches_recorded_identity,
};
use crate::perfdata::raw_stack::{CollapsedRawStack, RawStackAccumulator};
use crate::perfdata::records::{Mmap2Record, ParsedRecord, PerfRecord, iter_records, parse_record};
use crate::perfdata::samples::{
    PERF_SAMPLE_ADDR, PERF_SAMPLE_CPU, PERF_SAMPLE_ID, PERF_SAMPLE_IDENTIFIER, PERF_SAMPLE_IP,
    PERF_SAMPLE_STREAM_ID, PERF_SAMPLE_TID, PERF_SAMPLE_TIME, SampleLayout, is_kernel_space_frame,
    is_perf_context_marker, is_perf_user_deferred_context_marker, parse_sample_record_callchain,
};
use crate::perfdata::unwind::{FramehopUnwinder, PerfX86_64Regs, unwind_x86_64_stack};
use crate::symbols::{SymbolFrameCache, SymbolRequest, SymbolResolver};

const UNKNOWN_FRAME: &str = "[unknown]";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfSummary {
    pub total_records: usize,
    pub record_counts: BTreeMap<u32, usize>,
    pub comms: Vec<String>,
    pub comms_by_pid: BTreeMap<u32, String>,
    pub comms_by_tid: BTreeMap<u32, String>,
    pub mmaps: Vec<String>,
    pub lost_records: u64,
    pub mmap_table: MmapTable,
    pub sample_stacks: Vec<PerfSampleStack>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfSampleStack {
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub period: Option<u64>,
    pub callchain: Vec<u64>,
    pub has_user_stack: bool,
    pub user_register_count: usize,
    pub user_stack_size: usize,
}

struct PerfFoldData {
    mmap_table: MmapTable,
    raw_stacks: Vec<CollapsedRawStack<FoldFrame>>,
}

struct FoldAccumulator {
    process_comms: BTreeMap<u32, String>,
    exec_process_comms: BTreeMap<u32, String>,
    thread_comms: BTreeMap<u32, String>,
    mmap_table: MmapTable,
    object_unwinder: FramehopUnwinder,
    loaded_unwind_mappings: BTreeSet<(String, u64, u64, u64)>,
    raw_stacks: RawStackAccumulator<FoldFrame>,
    deferred_samples: BTreeMap<u64, Vec<DeferredFoldSample>>,
    callchain: Vec<FoldFrame>,
}

struct TimedRecord<'a> {
    index: usize,
    time: Option<u64>,
    record: PerfRecord<'a>,
}

struct FoldSample {
    pid: Option<u32>,
    tid: Option<u32>,
    count: u64,
    frames: Vec<FoldFrame>,
    deferred_cookie: Option<u64>,
}

struct DeferredFoldSample {
    pid: Option<u32>,
    comm: Option<String>,
    count: u64,
    frames: Vec<FoldFrame>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum FoldFrame {
    Callchain(u64),
    UserUnwind(u64),
}

impl FoldFrame {
    fn address(self) -> u64 {
        match self {
            Self::Callchain(address) | Self::UserUnwind(address) => address,
        }
    }
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
        comms_by_tid: BTreeMap::new(),
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
                summary.comms_by_tid.insert(record.tid, record.comm.clone());
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
    let mut symbol_cache = SymbolFrameCache::new(symbol_resolver);
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
    let mut records = timed_records(bytes, header, &sample_layouts)?;
    let mut accumulator = FoldAccumulator::new();

    records.sort_by_key(|record| (record.time.unwrap_or(0), record.index));
    for timed_record in records {
        let record = timed_record.record;
        let parsed_record = parse_record_with_context(record)?;
        let record_result = accumulator.apply_record(parsed_record, &sample_layouts, options);
        record_result.map_err(|error| {
            format!(
                "failed to parse record type {} at offset {}: {error}",
                record.header.record_type, record.offset
            )
        })?;
    }

    Ok(accumulator.into_fold_data())
}

impl FoldAccumulator {
    fn new() -> Self {
        Self {
            process_comms: BTreeMap::new(),
            exec_process_comms: BTreeMap::new(),
            thread_comms: BTreeMap::new(),
            mmap_table: MmapTable::default(),
            object_unwinder: FramehopUnwinder::new(),
            loaded_unwind_mappings: BTreeSet::new(),
            raw_stacks: RawStackAccumulator::<FoldFrame>::new(),
            deferred_samples: BTreeMap::new(),
            callchain: Vec::new(),
        }
    }

    fn apply_record(
        &mut self,
        record: ParsedRecord,
        sample_layouts: &SampleLayouts,
        options: FoldOptions,
    ) -> Result<(), String> {
        match record {
            ParsedRecord::Comm(record) => {
                update_comm_tables(
                    &mut self.process_comms,
                    &mut self.exec_process_comms,
                    &mut self.thread_comms,
                    record,
                );
                Ok(())
            }
            ParsedRecord::Mmap(record) => {
                load_unwind_mapping(
                    &mut self.object_unwinder,
                    &mut self.loaded_unwind_mappings,
                    record.start,
                    record.len,
                    record.pgoff,
                    &record.path,
                    None,
                );
                self.mmap_table.insert_mmap(record);
                Ok(())
            }
            ParsedRecord::Sample(record) => parse_sample_for_fold(
                &record.payload,
                sample_layouts,
                options,
                &mut self.object_unwinder,
            )
            .map(|sample| self.add_fold_sample(sample)),
            ParsedRecord::CallchainDeferred(record) => {
                self.add_deferred_callchain(record.cookie, record.ips);
                Ok(())
            }
            ParsedRecord::Mmap2(record) => {
                load_mmap2_unwind_mapping(
                    &mut self.object_unwinder,
                    &mut self.loaded_unwind_mappings,
                    &record,
                );
                self.mmap_table.insert_mmap2(record);
                Ok(())
            }
            ParsedRecord::Mmap2BuildId(record) => {
                load_unwind_mapping(
                    &mut self.object_unwinder,
                    &mut self.loaded_unwind_mappings,
                    record.start,
                    record.len,
                    record.pgoff,
                    &record.path,
                    None,
                );
                self.mmap_table.insert_mmap2_build_id(record);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn into_fold_data(self) -> PerfFoldData {
        PerfFoldData {
            mmap_table: self.mmap_table,
            raw_stacks: self.raw_stacks.into_collapsed(),
        }
    }
}

fn timed_records<'a>(
    bytes: &'a [u8],
    header: crate::perfdata::header::PerfHeader,
    sample_layouts: &SampleLayouts,
) -> Result<Vec<TimedRecord<'a>>, String> {
    iter_records(bytes, header)?
        .into_iter()
        .enumerate()
        .map(|(index, record)| {
            let time = record_time(record, sample_layouts)?;
            Ok(TimedRecord {
                index,
                time,
                record,
            })
        })
        .collect()
}

fn record_time(
    record: PerfRecord<'_>,
    sample_layouts: &SampleLayouts,
) -> Result<Option<u64>, String> {
    if record.header.record_type == crate::perfdata::records::PERF_RECORD_SAMPLE {
        return sample_layouts
            .layout_for_payload(record.payload)?
            .map_or(Ok(None), |layout| {
                sample_payload_time(record.payload, layout)
            });
    }

    sample_layouts
        .fallback
        .filter(|layout| layout.sample_id_all)
        .map_or(Ok(None), |layout| {
            sample_id_payload_time(record.payload, layout)
        })
}

fn sample_payload_time(payload: &[u8], layout: SampleLayout) -> Result<Option<u64>, String> {
    if layout.sample_type & PERF_SAMPLE_TIME == 0 {
        return Ok(None);
    }
    let mut offset = 0usize;
    if layout.sample_type & PERF_SAMPLE_IDENTIFIER != 0 {
        offset += 8;
    }
    if layout.sample_type & PERF_SAMPLE_IP != 0 {
        offset += 8;
    }
    if layout.sample_type & PERF_SAMPLE_TID != 0 {
        offset += 8;
    }
    read_u64(payload, offset).map(Some)
}

fn sample_id_payload_time(payload: &[u8], layout: SampleLayout) -> Result<Option<u64>, String> {
    if layout.sample_type & PERF_SAMPLE_TIME == 0 {
        return Ok(None);
    }
    let sample_id_size = sample_id_size(layout);
    if payload.len() < sample_id_size {
        return Ok(None);
    }
    let mut offset = payload.len() - sample_id_size;
    if layout.sample_type & PERF_SAMPLE_TID != 0 {
        offset += 8;
    }
    read_u64(payload, offset).map(Some)
}

fn sample_id_size(layout: SampleLayout) -> usize {
    [
        PERF_SAMPLE_TID,
        PERF_SAMPLE_TIME,
        PERF_SAMPLE_ID,
        PERF_SAMPLE_STREAM_ID,
        PERF_SAMPLE_CPU,
        PERF_SAMPLE_IDENTIFIER,
    ]
    .into_iter()
    .filter(|flag| layout.sample_type & flag != 0)
    .count()
        * 8
}

fn update_comm_tables(
    process_comms: &mut BTreeMap<u32, String>,
    exec_process_comms: &mut BTreeMap<u32, String>,
    thread_comms: &mut BTreeMap<u32, String>,
    record: crate::perfdata::records::CommRecord,
) {
    if record.is_exec {
        exec_process_comms.insert(record.pid, record.comm.clone());
    }
    process_comms.insert(record.pid, record.comm.clone());
    thread_comms.insert(record.tid, record.comm);
}

fn add_fold_stack(
    pid: Option<u32>,
    comm: Option<String>,
    count: u64,
    frames: Vec<FoldFrame>,
    mmap_table: &MmapTable,
    raw_stacks: &mut RawStackAccumulator<FoldFrame>,
    callchain: &mut Vec<FoldFrame>,
) {
    callchain.clear();
    callchain.reserve(frames.len());
    callchain.extend(frames.into_iter().rev().filter(|frame| {
        let address = frame.address();
        if is_perf_context_marker(address) {
            return false;
        }
        if should_drop_known_non_executable_user_frame(pid, address, mmap_table) {
            return false;
        }
        true
    }));
    if !callchain.is_empty() {
        raw_stacks.add_slice_with_comm(pid, comm, callchain, count);
    }
}

impl FoldAccumulator {
    fn add_fold_sample(&mut self, sample: Option<FoldSample>) {
        if let Some(sample) = sample {
            let comm = self.comm_for_sample(&sample);
            if let Some(cookie) = sample.deferred_cookie {
                self.deferred_samples
                    .entry(cookie)
                    .or_default()
                    .push(DeferredFoldSample {
                        pid: sample.pid,
                        comm,
                        count: sample.count,
                        frames: sample.frames,
                    });
            } else {
                add_fold_stack(
                    sample.pid,
                    comm,
                    sample.count,
                    sample.frames,
                    &self.mmap_table,
                    &mut self.raw_stacks,
                    &mut self.callchain,
                );
            }
        }
    }

    fn add_deferred_callchain(&mut self, cookie: u64, ips: Vec<u64>) {
        let Some(samples) = self.deferred_samples.remove(&cookie) else {
            return;
        };
        let deferred_frames = ips
            .into_iter()
            .map(FoldFrame::Callchain)
            .collect::<Vec<_>>();
        for mut sample in samples {
            sample.frames.extend(deferred_frames.iter().copied());
            add_fold_stack(
                sample.pid,
                sample.comm,
                sample.count,
                sample.frames,
                &self.mmap_table,
                &mut self.raw_stacks,
                &mut self.callchain,
            );
        }
    }

    fn comm_for_sample(&self, sample: &FoldSample) -> Option<String> {
        sample
            .pid
            .and_then(|pid| self.exec_process_comms.get(&pid))
            .or_else(|| sample.tid.and_then(|tid| self.thread_comms.get(&tid)))
            .or_else(|| sample.pid.and_then(|pid| self.process_comms.get(&pid)))
            .cloned()
    }
}

fn is_valid_unwound_user_frame(pid: Option<u32>, frame: FoldFrame, mmap_table: &MmapTable) -> bool {
    let FoldFrame::UserUnwind(address) = frame else {
        return true;
    };
    pid.is_none_or(|pid| {
        !mmap_table.has_executable_mappings_for_pid(pid)
            || mmap_table.resolve(pid, address).is_some()
            || is_kernel_space_frame(address)
    })
}

fn render_fold_data<R>(
    fold_data: &PerfFoldData,
    mut symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
) -> Result<String, String>
where
    R: SymbolResolver,
{
    if let Some(cache) = symbol_cache.as_deref_mut() {
        prefetch_symbols(&fold_data.raw_stacks, &fold_data.mmap_table, cache)?;
    }
    let mut counts = BTreeMap::<Vec<String>, u64>::new();
    let frame_resolver = FoldFrameResolver::new(&fold_data.mmap_table);
    for stack in &fold_data.raw_stacks {
        let frames = frame_resolver.frames_for_stack(
            stack.pid,
            stack.comm.as_deref(),
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
    raw_stacks: &[CollapsedRawStack<FoldFrame>],
    mmap_table: &MmapTable,
    symbol_cache: &mut SymbolFrameCache<'_, R>,
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
    callchain: &[FoldFrame],
    mmap_table: &MmapTable,
) -> Vec<SymbolRequest> {
    callchain
        .iter()
        .copied()
        .filter(|frame| is_valid_unwound_user_frame(pid, *frame, mmap_table))
        .map(FoldFrame::address)
        .filter_map(|frame| {
            pid.and_then(|pid| mmap_table.resolve(pid, frame))
                .filter(|mapping| !is_kernel_space_frame(frame) || is_kernel_mapping(mapping))
                .map(|mapping| symbol_request(&mapping))
        })
        .collect()
}

struct FoldFrameResolver<'a> {
    mmap_table: &'a MmapTable,
}

struct NoopSymbolResolver;

impl SymbolResolver for NoopSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(vec![None; requests.len()])
    }
}

impl<'a> FoldFrameResolver<'a> {
    fn new(mmap_table: &'a MmapTable) -> Self {
        Self { mmap_table }
    }

    fn frames_for_stack<R>(
        &self,
        pid: Option<u32>,
        comm: Option<&str>,
        callchain: &[FoldFrame],
        mut symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
    ) -> Result<Vec<String>, String>
    where
        R: SymbolResolver,
    {
        let mut frames = if let Some(comm) = comm {
            vec![comm.replace(' ', "_")]
        } else {
            Vec::new()
        };
        for frame in callchain.iter().copied() {
            if !is_valid_unwound_user_frame(pid, frame, self.mmap_table) {
                continue;
            }
            let frame = frame.address();
            if should_drop_known_non_executable_user_frame(pid, frame, self.mmap_table) {
                continue;
            }
            frames.extend(self.format_frames(pid, frame, symbol_cache.as_deref_mut())?);
        }
        Ok(frames)
    }

    fn format_frames<R>(
        &self,
        pid: Option<u32>,
        frame: u64,
        symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
    ) -> Result<Vec<String>, String>
    where
        R: SymbolResolver,
    {
        if let Some(mapping) = pid.and_then(|pid| self.mmap_table.resolve(pid, frame)) {
            if is_kernel_space_frame(frame) && !is_kernel_mapping(&mapping) {
                return Ok(vec![format!("0x{frame:x}")]);
            }
            if let Some(cache) = symbol_cache {
                let frames = cache.resolve(&symbol_request(&mapping))?;
                if frames.is_empty() {
                    return Ok(vec![symbol_fallback_frame(&mapping)]);
                }
                return Ok(frames);
            }
            if is_kernel_space_frame(frame) {
                return Ok(vec![UNKNOWN_FRAME.to_string()]);
            }
            Ok(vec![mapped_frame_label(&mapping)])
        } else if is_kernel_space_frame(frame) {
            Ok(vec![UNKNOWN_FRAME.to_string()])
        } else {
            Ok(vec![format!("0x{frame:x}")])
        }
    }
}

fn should_drop_known_non_executable_user_frame(
    pid: Option<u32>,
    address: u64,
    mmap_table: &MmapTable,
) -> bool {
    !is_kernel_space_frame(address)
        && pid.is_some_and(|pid| mmap_table.is_known_non_executable(pid, address))
}

fn symbol_fallback_frame(mapping: &ResolvedMapping) -> String {
    if is_kernel_mapping(mapping) {
        UNKNOWN_FRAME.to_string()
    } else if mapping.path.starts_with('[') {
        mapped_frame_label(mapping)
    } else {
        module_fallback_frame(&mapping.path)
    }
}

fn symbol_request(mapping: &ResolvedMapping) -> SymbolRequest {
    SymbolRequest {
        path: symbol_request_path(mapping),
        relative_address: mapping.relative_address,
        build_id: mapping.build_id.as_deref().map(build_id_hex),
        file_identity: mapping.file_identity,
        kernel_relocation: mapping.kernel_relocation.clone(),
    }
}

fn symbol_request_path(mapping: &ResolvedMapping) -> PathBuf {
    if is_kernel_mapping(mapping) && mapping.path.starts_with("[kernel") {
        PathBuf::from("[kernel.kallsyms]")
    } else {
        PathBuf::from(&mapping.path)
    }
}

fn build_id_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex, "{byte:02x}").expect("writing to a string cannot fail");
    }
    hex
}

fn mapped_frame_label(mapping: &ResolvedMapping) -> String {
    format!("{}+0x{:x}", mapping.path, mapping.relative_address)
}

fn module_fallback_frame(path: &str) -> String {
    let name = Path::new(path)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or(path);
    format!("[{name}]")
}

fn is_kernel_mapping(mapping: &ResolvedMapping) -> bool {
    is_kernel_space_frame(mapping.relative_address) && mapping.path.starts_with('[')
}

fn parse_sample_for_summary(
    payload: &[u8],
    sample_layouts: &SampleLayouts,
) -> Result<Option<PerfSampleStack>, String> {
    if let Some(layout) = sample_layouts.layout_for_payload(payload)? {
        parse_sample_record_callchain(payload, layout).map(|sample| {
            sample.map(|sample| PerfSampleStack {
                pid: sample.pid,
                tid: sample.tid,
                period: sample.period,
                callchain: sample.frames.collect(),
                has_user_stack: sample.user_stack.is_some(),
                user_register_count: sample
                    .user_regs
                    .as_ref()
                    .map_or(0, |regs| regs.values.len()),
                user_stack_size: sample
                    .user_stack
                    .as_ref()
                    .map_or(0, |stack| stack.bytes.len()),
            })
        })
    } else {
        Ok(None)
    }
}

fn parse_sample_for_fold(
    payload: &[u8],
    sample_layouts: &SampleLayouts,
    options: FoldOptions,
    object_unwinder: &mut FramehopUnwinder,
) -> Result<Option<FoldSample>, String> {
    if let Some(layout) = sample_layouts.layout_for_payload(payload)? {
        parse_sample_record_callchain(payload, layout).map(|sample| {
            sample.map(|sample| {
                let count = if options.count_periods {
                    sample.period.unwrap_or(1)
                } else {
                    1
                };
                let mut frames = sample.frames.map(FoldFrame::Callchain).collect::<Vec<_>>();
                let deferred_cookie = take_deferred_cookie(&mut frames);
                if let (Some(regs), Some(stack)) = (&sample.user_regs, &sample.user_stack)
                    && !stack.bytes.is_empty()
                    && let Ok(regs) = PerfX86_64Regs::from_perf_masked_values(
                        layout.sample_regs_user,
                        &regs.values,
                    )
                {
                    let unwound_frames = if object_unwinder.module_count() == 0 {
                        unwind_x86_64_stack(regs, stack.bytes, 256)
                    } else {
                        object_unwinder.unwind_stack(regs, stack.bytes, 256)
                    };
                    let unwound_frames = unwound_frames
                        .into_iter()
                        .map(FoldFrame::UserUnwind)
                        .collect::<Vec<_>>();
                    if frames.is_empty() {
                        frames = unwound_frames;
                    } else {
                        frames.extend(unwound_frames);
                    }
                }
                FoldSample {
                    pid: sample.pid,
                    tid: sample.tid,
                    count,
                    frames,
                    deferred_cookie,
                }
            })
        })
    } else {
        Ok(None)
    }
}

fn take_deferred_cookie(frames: &mut Vec<FoldFrame>) -> Option<u64> {
    match frames.as_slice() {
        [
            ..,
            FoldFrame::Callchain(marker),
            FoldFrame::Callchain(cookie),
        ] if is_perf_user_deferred_context_marker(*marker) => {
            let cookie = *cookie;
            frames.pop();
            Some(cookie)
        }
        _ => None,
    }
}

fn load_unwind_mapping(
    object_unwinder: &mut FramehopUnwinder,
    loaded_unwind_mappings: &mut BTreeSet<(String, u64, u64, u64)>,
    start: u64,
    len: u64,
    pgoff: u64,
    path: &str,
    file_identity: Option<FileIdentity>,
) {
    if !should_load_unwind_object(path, file_identity) {
        return;
    }
    let key = (path.to_string(), start, len, pgoff);
    if !loaded_unwind_mappings.insert(key) {
        return;
    }
    let _ = object_unwinder.add_object_mapping(Path::new(path), start, len, pgoff);
}

fn load_mmap2_unwind_mapping(
    object_unwinder: &mut FramehopUnwinder,
    loaded_unwind_mappings: &mut BTreeSet<(String, u64, u64, u64)>,
    record: &Mmap2Record,
) {
    load_unwind_mapping(
        object_unwinder,
        loaded_unwind_mappings,
        record.start,
        record.len,
        record.pgoff,
        &record.path,
        Some(mmap2_file_identity(record)),
    );
}

fn mmap2_file_identity(record: &Mmap2Record) -> FileIdentity {
    FileIdentity {
        major: record.major,
        minor: record.minor,
        inode: record.inode,
        inode_generation: record.inode_generation,
    }
}

fn should_load_unwind_object(path: &str, file_identity: Option<FileIdentity>) -> bool {
    if path.starts_with('[') {
        return false;
    }
    file_identity.is_none_or(|identity| file_matches_recorded_identity(Path::new(path), identity))
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
        sample_id_all: attr.sample_id_all,
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
        if let Some(identifier) = sample_event_id(payload, fallback)? {
            return Ok(self
                .by_identifier
                .get(&identifier)
                .copied()
                .or(Some(fallback)));
        }
        Ok(Some(fallback))
    }
}

fn sample_event_id(payload: &[u8], layout: SampleLayout) -> Result<Option<u64>, String> {
    if layout.sample_type & PERF_SAMPLE_IDENTIFIER != 0 {
        return read_sample_u64(payload, 0).map(Some);
    }
    if layout.sample_type & PERF_SAMPLE_ID == 0 {
        return Ok(None);
    }

    let mut offset = 0usize;
    if layout.sample_type & PERF_SAMPLE_IP != 0 {
        offset += 8;
    }
    if layout.sample_type & PERF_SAMPLE_TID != 0 {
        offset += 8;
    }
    if layout.sample_type & PERF_SAMPLE_TIME != 0 {
        offset += 8;
    }
    if layout.sample_type & PERF_SAMPLE_ADDR != 0 {
        offset += 8;
    }
    read_sample_u64(payload, offset).map(Some)
}

fn read_sample_u64(payload: &[u8], offset: usize) -> Result<u64, String> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| "perf sample field offset overflows usize".to_string())?;
    let bytes = payload
        .get(offset..end)
        .ok_or_else(|| "perf sample payload is truncated".to_string())?;
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| "perf sample payload is truncated".to_string())?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use crate::perfdata::mappings::FileIdentity;

    #[test]
    fn skips_unwind_object_when_recorded_file_identity_mismatches_path() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("app");
        std::fs::write(&path, b"binary").expect("write app");
        let inode = std::fs::metadata(&path).expect("metadata").ino();

        assert!(!super::should_load_unwind_object(
            path.to_str().expect("utf-8 path"),
            Some(FileIdentity {
                major: 0,
                minor: 0,
                inode: inode + 1,
                inode_generation: 0,
            }),
        ));
    }
}
