use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::fs::File;
use std::hash::Hasher;
use std::io::{BufReader, Read, Seek, SeekFrom, Write as IoWrite};
use std::path::{Path, PathBuf};

use hashbrown::{HashMap, HashSet};
use rustc_hash::{FxBuildHasher, FxHasher};

use crate::folded::append_inferno_perf_frame;
use crate::perfdata::attrs::{PerfFileAttr, parse_file_attr_ids, parse_file_attrs};
use crate::perfdata::build_id::{
    BuildIdEvent, build_id_events_from_perfdata, parse_build_id_events,
};
use crate::perfdata::endian::read_u64;
use crate::perfdata::header::{PerfFeatureSection, PerfHeader, parse_header};
use crate::perfdata::mappings::{FileIdentity, MappingResolveCache, MmapTable, ResolvedMappingRef};
use crate::perfdata::raw_stack::{RawStackAccumulator, RawStackEntryRef};
use crate::perfdata::records::{
    Mmap2Record, PERF_RECORD_FINISHED_ROUND, PERF_RECORD_MISC_CPUMODE_KERNEL,
    PERF_RECORD_MISC_CPUMODE_MASK, ParsedRecord, PerfRecord, PerfRecordHeader, iter_records,
    parse_record, parse_record_header,
};
use crate::perfdata::samples::{
    PERF_SAMPLE_ADDR, PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_CPU, PERF_SAMPLE_ID,
    PERF_SAMPLE_IDENTIFIER, PERF_SAMPLE_IP, PERF_SAMPLE_STREAM_ID, PERF_SAMPLE_TID,
    PERF_SAMPLE_TIME, SampleLayout, is_kernel_space_frame, is_perf_context_marker,
    is_perf_user_deferred_context_marker, parse_sample_record_callchain,
};
use crate::perfdata::unwind::{FramehopUnwinder, PerfX86_64Regs, unwind_x86_64_stack};
use crate::symbols::{SymbolFrameCache, SymbolRequest, SymbolResolver, perf_build_id_elf_path};

const UNKNOWN_FRAME: &str = "[unknown]";
const PREFETCH_SYMBOL_REQUEST_BATCH_SIZE: usize = 4096;
const RECORD_READER_BUFFER_CAPACITY: usize = 4 * 1024 * 1024;
const FOLD_COUNT_STORAGE_LINEAR_GROWTH_THRESHOLD: usize = 64 * 1024 * 1024;
const FOLD_COUNT_STORAGE_LINEAR_GROWTH_CHUNK: usize = 8 * 1024 * 1024;
const PROT_EXEC: u32 = 4;
type FoldFrameRenderCache = HashMap<String, String, FxBuildHasher>;

#[derive(Default)]
struct FoldCounts {
    storage: Vec<u8>,
    entries: Vec<FoldCountEntry>,
    by_hash: HashMap<u64, FoldHashBucket, FxBuildHasher>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FoldCountEntry {
    offset: usize,
    len: usize,
    count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FoldHashBucket {
    One(usize),
    Many(Vec<usize>),
}

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
    pub misc: u16,
    pub cpumode: u16,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub period: Option<u64>,
    pub callchain: Vec<u64>,
    pub has_user_stack: bool,
    pub user_register_count: usize,
    pub user_register_ip: Option<u64>,
    pub user_stack_size: usize,
    pub user_stack_dynamic_size: u64,
}

struct PerfFoldData {
    mmap_table: MmapTable,
    raw_stacks: RawStackAccumulator<FoldFrame>,
}

struct FoldAccumulator {
    process_comms: BTreeMap<u32, String>,
    exec_process_comms: BTreeMap<u32, String>,
    thread_comms: BTreeMap<u32, String>,
    mmap_table: MmapTable,
    unwind_states: HashMap<u32, PidUnwindState, FxBuildHasher>,
    header_build_ids: BTreeMap<String, Vec<u8>>,
    raw_stacks: RawStackAccumulator<FoldFrame>,
    deferred_samples: BTreeMap<u64, Vec<DeferredFoldSample>>,
    sample_frames: Vec<FoldFrame>,
    callchain: Vec<FoldFrame>,
    unwind_debug_dir: Option<PathBuf>,
}

#[derive(Default)]
struct PidUnwindState {
    object_unwinder: FramehopUnwinder,
    attempted_unwind_mappings: BTreeSet<UnwindMappingKey>,
    loaded_unwind_mappings: BTreeSet<UnwindMappingKey>,
}

type UnwindMappingKey = (String, u64, u64, u64);

struct TimedRecord {
    index: usize,
    time: Option<u64>,
    offset: usize,
    header: PerfRecordHeader,
}

struct PendingParsedRecord {
    index: usize,
    time: u64,
    record: ParsedRecord,
}

#[derive(Default)]
struct OrderedRecordQueue {
    pending_records: Vec<PendingParsedRecord>,
    next_flush_time: Option<u64>,
    max_timestamp: Option<u64>,
}

struct DeferredFoldSample {
    pid: Option<u32>,
    comm: Option<String>,
    count: u64,
    frames: Vec<FoldFrame>,
}

struct PreparedFoldSample {
    pid: Option<u32>,
    comm: Option<String>,
    count: u64,
    frames: Vec<FoldFrame>,
    deferred_cookie: Option<u64>,
}

#[derive(Clone, Copy)]
struct UnwindMappingRequest<'a> {
    start: u64,
    len: u64,
    pgoff: u64,
    prot: Option<u32>,
    path: &'a str,
    file_identity: Option<FileIdentity>,
    build_id: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum FoldFrame {
    Callchain(u64),
    UserUnwind(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserUnwindSource {
    None,
    FramePointer,
    Object,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SampleCallchainState {
    KernelWithoutCallchain,
    Other {
        has_callchain: bool,
        has_frames: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitialIpMappingState {
    NoRecordedMapping,
    RecordedMappingLoaded,
    RecordedMappingMissing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UserUnwindContext {
    callchain: SampleCallchainState,
    initial_ip_mapping: InitialIpMappingState,
    module_count: usize,
}

impl FoldFrame {
    fn address(self) -> u64 {
        match self {
            Self::Callchain(address) | Self::UserUnwind(address) => address,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PrefetchMappingKey {
    symbol_source_id: usize,
    relative_address: u64,
}

#[derive(Clone, Debug, Default)]
struct SampleLayouts {
    fallback: Option<SampleEventLayout>,
    by_identifier: BTreeMap<u64, SampleEventLayout>,
}

#[derive(Clone, Copy, Debug)]
struct SampleEventLayout {
    layout: SampleLayout,
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

impl FoldCounts {
    fn reserve_first_drain(&mut self, additional_entries: usize) {
        if self.entries.is_empty() {
            self.entries.reserve(additional_entries);
            self.by_hash.reserve(additional_entries);
        }
    }

    fn add_rendered(&mut self, rendered: &str, count: u64) {
        let rendered = rendered.as_bytes();
        let hash = fold_count_hash(rendered);
        self.add_rendered_with_hash(rendered, count, hash);
    }

    fn add_rendered_with_hash(&mut self, rendered: &[u8], count: u64, hash: u64) {
        if let Some(entry_id) = self.find_entry_id(hash, rendered) {
            self.entries[entry_id].count += count;
            return;
        }

        self.reserve_storage_for(rendered.len());
        let offset = self.storage.len();
        self.storage.extend_from_slice(rendered);
        let entry_id = self.entries.len();
        self.entries.push(FoldCountEntry {
            offset,
            len: rendered.len(),
            count,
        });
        match self.by_hash.entry(hash) {
            hashbrown::hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(entry_id),
            hashbrown::hash_map::Entry::Vacant(entry) => {
                entry.insert(FoldHashBucket::One(entry_id));
            }
        }
    }

    fn find_entry_id(&self, hash: u64, rendered: &[u8]) -> Option<usize> {
        self.by_hash
            .get(&hash)
            .and_then(|bucket| bucket.find_entry_id(self, rendered))
    }

    fn entry_bytes<'a>(&'a self, entry: &FoldCountEntry) -> &'a [u8] {
        &self.storage[entry.offset..entry.offset + entry.len]
    }

    fn reserve_storage_for(&mut self, additional: usize) {
        let available = self.storage.capacity().saturating_sub(self.storage.len());
        if available >= additional {
            return;
        }
        let missing = additional - available;
        if self.storage.capacity() >= FOLD_COUNT_STORAGE_LINEAR_GROWTH_THRESHOLD {
            self.storage
                .reserve_exact(missing.max(FOLD_COUNT_STORAGE_LINEAR_GROWTH_CHUNK));
        } else {
            self.storage.reserve(missing);
        }
    }
}

impl FoldHashBucket {
    fn push(&mut self, entry_id: usize) {
        match self {
            Self::One(existing) => *self = Self::Many(vec![*existing, entry_id]),
            Self::Many(entries) => entries.push(entry_id),
        }
    }

    fn find_entry_id(&self, counts: &FoldCounts, rendered: &[u8]) -> Option<usize> {
        match self {
            Self::One(entry_id) => {
                (counts.entry_bytes(&counts.entries[*entry_id]) == rendered).then_some(*entry_id)
            }
            Self::Many(entry_ids) => entry_ids
                .iter()
                .copied()
                .find(|&entry_id| counts.entry_bytes(&counts.entries[entry_id]) == rendered),
        }
    }
}

fn fold_count_hash(rendered: &[u8]) -> u64 {
    let mut hasher = FxHasher::default();
    hasher.write(rendered);
    hasher.finish()
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
                parse_sample_for_summary(record.misc, &record.payload, &sample_layouts).map(
                    |sample| {
                        if let Some(sample) = sample {
                            summary.sample_stacks.push(sample);
                        }
                    },
                )
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
            ParsedRecord::Fork(record) => {
                if record.clone_maps {
                    summary
                        .mmap_table
                        .clone_pid_mappings(record.ppid, record.pid);
                }
                Ok(())
            }
            ParsedRecord::Unsupported { .. }
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
    render_fold_data::<NoopSymbolResolver>(fold_data, None)
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
    let file = File::open(path).map_err(|error| format!("failed to open perf.data: {error}"))?;
    let mut folded = Vec::new();
    write_folded_perfdata_from_file::<NoopSymbolResolver, _>(&file, options, None, &mut folded)?;
    String::from_utf8(folded).map_err(|error| format!("folded output is not utf-8: {error}"))
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
    render_fold_data(fold_data, Some(&mut symbol_cache))
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
    let file = File::open(path).map_err(|error| format!("failed to open perf.data: {error}"))?;
    let mut symbol_cache = SymbolFrameCache::new(symbol_resolver);
    let mut folded = Vec::new();
    write_folded_perfdata_from_file(&file, options, Some(&mut symbol_cache), &mut folded)?;
    String::from_utf8(folded).map_err(|error| format!("folded output is not utf-8: {error}"))
}

pub(crate) fn write_folded_perfdata_file_with_options<W>(
    path: &Path,
    options: FoldOptions,
    writer: &mut W,
) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    let file = File::open(path).map_err(|error| format!("failed to open perf.data: {error}"))?;
    write_folded_perfdata_from_file::<NoopSymbolResolver, _>(&file, options, None, writer)
}

pub(crate) fn write_folded_perfdata_file_with_symbols<R, W>(
    path: &Path,
    options: FoldOptions,
    symbol_resolver: &R,
    writer: &mut W,
) -> Result<(), String>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    let file = File::open(path).map_err(|error| format!("failed to open perf.data: {error}"))?;
    let mut symbol_cache = SymbolFrameCache::new(symbol_resolver);
    write_folded_perfdata_from_file(&file, options, Some(&mut symbol_cache), writer)
}

pub(crate) fn write_inferno_perf_script_file_with_options<W>(
    path: &Path,
    options: FoldOptions,
    writer: &mut W,
) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    let file = File::open(path).map_err(|error| format!("failed to open perf.data: {error}"))?;
    write_inferno_perf_script_from_file::<NoopSymbolResolver, _>(&file, options, None, writer)
}

pub(crate) fn write_inferno_perf_script_file_with_symbols<R, W>(
    path: &Path,
    options: FoldOptions,
    symbol_resolver: &R,
    writer: &mut W,
) -> Result<(), String>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    let file = File::open(path).map_err(|error| format!("failed to open perf.data: {error}"))?;
    let mut symbol_cache = SymbolFrameCache::new(symbol_resolver);
    write_inferno_perf_script_from_file(&file, options, Some(&mut symbol_cache), writer)
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
    let header_build_ids = header_build_ids_by_filename(bytes)?;
    let mut accumulator = FoldAccumulator::new(header_build_ids);
    let records = timed_records(bytes, header, &sample_layouts)?;
    let mut ordered_records = OrderedRecordQueue::default();

    for timed_record in records {
        let record = timed_record.record(bytes)?;
        if record.header.record_type == PERF_RECORD_FINISHED_ROUND {
            ordered_records.flush_round(&mut accumulator, &sample_layouts, options)?;
            continue;
        }
        let parsed_record = parse_record_with_context(record)?;
        let record_result = ordered_records.apply_or_queue(
            timed_record.index,
            timed_record.time,
            parsed_record,
            &mut accumulator,
            &sample_layouts,
            options,
        );
        record_result.map_err(|error| {
            format!(
                "failed to parse record type {} at offset {}: {error}",
                record.header.record_type, record.offset
            )
        })?;
    }
    ordered_records.flush_final(&mut accumulator, &sample_layouts, options)?;

    Ok(accumulator.into_fold_data())
}

fn header_build_ids_by_filename(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    build_id_events_from_perfdata(bytes)?
        .into_iter()
        .map(|event| hex_build_id_bytes(&event.build_id).map(|build_id| (event.filename, build_id)))
        .collect()
}

fn write_folded_perfdata_from_file<R, W>(
    file: &File,
    options: FoldOptions,
    mut symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
    writer: &mut W,
) -> Result<(), String>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    let (header, header_bytes) = perfdata_header_from_file(file)?;
    let sample_layouts = sample_layouts_from_file(file, header)?;
    let header_build_ids = header_build_ids_by_filename_from_file(file, header, &header_bytes)?;
    let mut accumulator = FoldAccumulator::new(header_build_ids);
    let data_end = header
        .data_offset
        .checked_add(header.data_size)
        .ok_or_else(|| "perf data section size overflows u64".to_string())?;
    if file
        .metadata()
        .map_err(|error| format!("failed to stat perf.data: {error}"))?
        .len()
        < data_end
    {
        return Err("perf data section extends past end of file".to_string());
    }

    let mut reader = BufReader::with_capacity(
        RECORD_READER_BUFFER_CAPACITY,
        file.try_clone()
            .map_err(|error| format!("failed to clone perf.data handle: {error}"))?,
    );
    reader
        .seek(SeekFrom::Start(header.data_offset))
        .map_err(|error| format!("failed to seek perf data section: {error}"))?;

    let mut counts = FoldCounts::default();
    let mut ordered_records = OrderedRecordQueue::default();
    let mut header_bytes = [0_u8; 8];
    let mut payload = Vec::new();
    let mut offset = usize::try_from(header.data_offset)
        .map_err(|_| "perf data section offset exceeds usize".to_string())?;
    let end =
        usize::try_from(data_end).map_err(|_| "perf data section end exceeds usize".to_string())?;
    let mut index = 0usize;

    while offset < end {
        reader.read_exact(&mut header_bytes).map_err(|error| {
            format!("failed to read perf record header at offset {offset}: {error}")
        })?;
        let record_header = parse_record_header(&header_bytes)?;
        let size = usize::from(record_header.size);
        if size < 8 {
            return Err(format!(
                "invalid perf record size {size} at offset {offset}"
            ));
        }
        let next = offset
            .checked_add(size)
            .ok_or_else(|| format!("perf record size overflows at offset {offset}"))?;
        if next > end {
            return Err(format!(
                "perf record overruns data section at offset {offset}"
            ));
        }

        payload.resize(size - 8, 0);
        reader.read_exact(&mut payload).map_err(|error| {
            format!("failed to read perf record payload at offset {offset}: {error}")
        })?;

        if record_header.record_type == PERF_RECORD_FINISHED_ROUND {
            ordered_records.flush_round(&mut accumulator, &sample_layouts, options)?;
            accumulator.drain_fold_counts(&mut counts, symbol_cache.as_deref_mut())?;
            offset = next;
            continue;
        }

        let record = PerfRecord {
            offset,
            header: record_header,
            payload: &payload,
        };
        let time = record_time(record, &sample_layouts)?;
        let parsed_record = parse_record_with_context(record)?;
        ordered_records.apply_or_queue(
            index,
            time,
            parsed_record,
            &mut accumulator,
            &sample_layouts,
            options,
        )?;
        index += 1;

        offset = next;
    }

    ordered_records.flush_final(&mut accumulator, &sample_layouts, options)?;
    accumulator.drain_fold_counts(&mut counts, symbol_cache)?;
    write_fold_counts(counts, writer)
}

fn write_inferno_perf_script_from_file<R, W>(
    file: &File,
    options: FoldOptions,
    symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
    writer: &mut W,
) -> Result<(), String>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    let (header, header_bytes) = perfdata_header_from_file(file)?;
    let sample_layouts = sample_layouts_from_file(file, header)?;
    let header_build_ids = header_build_ids_by_filename_from_file(file, header, &header_bytes)?;
    let data_end = header
        .data_offset
        .checked_add(header.data_size)
        .ok_or_else(|| "perf data section size overflows u64".to_string())?;
    if file
        .metadata()
        .map_err(|error| format!("failed to stat perf.data: {error}"))?
        .len()
        < data_end
    {
        return Err("perf data section extends past end of file".to_string());
    }

    let mut reader = BufReader::with_capacity(
        RECORD_READER_BUFFER_CAPACITY,
        file.try_clone()
            .map_err(|error| format!("failed to clone perf.data handle: {error}"))?,
    );
    reader
        .seek(SeekFrom::Start(header.data_offset))
        .map_err(|error| format!("failed to seek perf data section: {error}"))?;

    let mut sink = PerfScriptSink::new(header_build_ids, symbol_cache, writer);
    let mut ordered_records = OrderedRecordQueue::default();
    let mut header_bytes = [0_u8; 8];
    let mut payload = Vec::new();
    let mut offset = usize::try_from(header.data_offset)
        .map_err(|_| "perf data section offset exceeds usize".to_string())?;
    let end =
        usize::try_from(data_end).map_err(|_| "perf data section end exceeds usize".to_string())?;
    let mut index = 0usize;

    while offset < end {
        reader.read_exact(&mut header_bytes).map_err(|error| {
            format!("failed to read perf record header at offset {offset}: {error}")
        })?;
        let record_header = parse_record_header(&header_bytes)?;
        let size = usize::from(record_header.size);
        if size < 8 {
            return Err(format!(
                "invalid perf record size {size} at offset {offset}"
            ));
        }
        let next = offset
            .checked_add(size)
            .ok_or_else(|| format!("perf record size overflows at offset {offset}"))?;
        if next > end {
            return Err(format!(
                "perf record overruns data section at offset {offset}"
            ));
        }

        payload.resize(size - 8, 0);
        reader.read_exact(&mut payload).map_err(|error| {
            format!("failed to read perf record payload at offset {offset}: {error}")
        })?;

        if record_header.record_type == PERF_RECORD_FINISHED_ROUND {
            ordered_records
                .flush_round_with(|record| sink.apply_record(record, &sample_layouts, options))?;
            offset = next;
            continue;
        }

        let record = PerfRecord {
            offset,
            header: record_header,
            payload: &payload,
        };
        let time = record_time(record, &sample_layouts)?;
        let parsed_record = parse_record_with_context(record)?;
        ordered_records.apply_or_queue_with(index, time, parsed_record, |record| {
            sink.apply_record(record, &sample_layouts, options)
        })?;
        index += 1;
        offset = next;
    }

    ordered_records.flush_final_with(|record| sink.apply_record(record, &sample_layouts, options))
}

struct PerfScriptSink<'io, 'cache, R, W: ?Sized> {
    accumulator: FoldAccumulator,
    symbol_cache: Option<&'io mut SymbolFrameCache<'cache, R>>,
    writer: &'io mut W,
}

impl<'io, 'cache, R, W> PerfScriptSink<'io, 'cache, R, W>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    fn new(
        header_build_ids: BTreeMap<String, Vec<u8>>,
        symbol_cache: Option<&'io mut SymbolFrameCache<'cache, R>>,
        writer: &'io mut W,
    ) -> Self {
        Self {
            accumulator: FoldAccumulator::new(header_build_ids),
            symbol_cache,
            writer,
        }
    }

    fn apply_record(
        &mut self,
        record: ParsedRecord,
        sample_layouts: &SampleLayouts,
        options: FoldOptions,
    ) -> Result<(), String> {
        match record {
            ParsedRecord::Sample(record) => {
                self.write_sample(record.misc, &record.payload, sample_layouts, options)
            }
            ParsedRecord::CallchainDeferred(record) => {
                self.write_deferred_callchain(record.cookie, &record.ips)
            }
            record => self
                .accumulator
                .apply_record(record, sample_layouts, options),
        }
    }

    fn write_sample(
        &mut self,
        misc: u16,
        payload: &[u8],
        sample_layouts: &SampleLayouts,
        options: FoldOptions,
    ) -> Result<(), String> {
        let Some(sample) = prepare_sample_for_fold(
            &mut self.accumulator,
            misc,
            payload,
            sample_layouts,
            options,
        )?
        else {
            return Ok(());
        };
        if let Some(cookie) = sample.deferred_cookie {
            self.accumulator
                .deferred_samples
                .entry(cookie)
                .or_default()
                .push(DeferredFoldSample {
                    pid: sample.pid,
                    comm: sample.comm,
                    count: sample.count,
                    frames: sample.frames,
                });
            return Ok(());
        }
        self.write_sample_event(&sample)
    }

    fn write_deferred_callchain(&mut self, cookie: u64, ips: &[u64]) -> Result<(), String> {
        let Some(samples) = self.accumulator.deferred_samples.remove(&cookie) else {
            return Ok(());
        };
        for mut sample in samples {
            sample
                .frames
                .extend(ips.iter().copied().map(FoldFrame::Callchain));
            let sample = PreparedFoldSample {
                pid: sample.pid,
                comm: sample.comm,
                count: sample.count,
                frames: sample.frames,
                deferred_cookie: None,
            };
            self.write_sample_event(&sample)?;
        }
        Ok(())
    }

    fn write_sample_event(&mut self, sample: &PreparedFoldSample) -> Result<(), String> {
        let comm = sample.comm.as_deref().unwrap_or("[unknown]");
        let pid = sample.pid.unwrap_or(0);
        writeln!(
            self.writer,
            "{comm} {pid} 0: {} cpu/cycles/P:",
            sample.count
        )
        .map_err(|error| format!("failed to write perf script output: {error}"))?;
        FoldFrameResolver::new(&self.accumulator.mmap_table).write_script_frames_for_stack(
            sample.pid,
            &sample.frames,
            self.symbol_cache.as_deref_mut(),
            self.writer,
        )?;
        self.writer
            .write_all(b"\n")
            .map_err(|error| format!("failed to write perf script output: {error}"))
    }
}

impl OrderedRecordQueue {
    fn apply_or_queue_with<F>(
        &mut self,
        index: usize,
        time: Option<u64>,
        record: ParsedRecord,
        mut apply: F,
    ) -> Result<(), String>
    where
        F: FnMut(ParsedRecord) -> Result<(), String>,
    {
        if let Some(time) = time {
            self.queue(index, time, record);
            Ok(())
        } else {
            apply(record)
        }
    }

    fn apply_or_queue(
        &mut self,
        index: usize,
        time: Option<u64>,
        record: ParsedRecord,
        accumulator: &mut FoldAccumulator,
        sample_layouts: &SampleLayouts,
        options: FoldOptions,
    ) -> Result<(), String> {
        self.apply_or_queue_with(index, time, record, |record| {
            accumulator.apply_record(record, sample_layouts, options)
        })
    }

    fn queue(&mut self, index: usize, time: u64, record: ParsedRecord) {
        self.max_timestamp = Some(self.max_timestamp.map_or(time, |max| max.max(time)));
        self.pending_records.push(PendingParsedRecord {
            index,
            time,
            record,
        });
    }

    fn flush_round(
        &mut self,
        accumulator: &mut FoldAccumulator,
        sample_layouts: &SampleLayouts,
        options: FoldOptions,
    ) -> Result<(), String> {
        self.flush_round_with(|record| accumulator.apply_record(record, sample_layouts, options))
    }

    fn flush_round_with<F>(&mut self, apply: F) -> Result<(), String>
    where
        F: FnMut(ParsedRecord) -> Result<(), String>,
    {
        if let Some(limit) = self.next_flush_time {
            self.flush_through_with(Some(limit), apply)?;
        }
        self.next_flush_time = self.max_timestamp;
        Ok(())
    }

    fn flush_final(
        &mut self,
        accumulator: &mut FoldAccumulator,
        sample_layouts: &SampleLayouts,
        options: FoldOptions,
    ) -> Result<(), String> {
        self.flush_final_with(|record| accumulator.apply_record(record, sample_layouts, options))
    }

    fn flush_final_with<F>(&mut self, apply: F) -> Result<(), String>
    where
        F: FnMut(ParsedRecord) -> Result<(), String>,
    {
        self.flush_through_with(None, apply)
    }

    fn flush_through_with<F>(&mut self, limit: Option<u64>, mut apply: F) -> Result<(), String>
    where
        F: FnMut(ParsedRecord) -> Result<(), String>,
    {
        self.pending_records
            .sort_by_key(|record| (record.time, record.index));
        let split = limit.map_or(self.pending_records.len(), |limit| {
            self.pending_records
                .partition_point(|record| record.time <= limit)
        });
        for pending_record in self.pending_records.drain(..split) {
            apply(pending_record.record)?;
        }
        Ok(())
    }
}

fn perfdata_header_from_file(file: &File) -> Result<(PerfHeader, [u8; 104]), String> {
    let mut bytes = [0_u8; 104];
    let mut reader = file
        .try_clone()
        .map_err(|error| format!("failed to clone perf.data handle: {error}"))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("failed to seek perf.data header: {error}"))?;
    reader
        .read_exact(&mut bytes)
        .map_err(|error| format!("failed to read perf.data header: {error}"))?;
    let header = parse_header(&bytes)?;
    Ok((header, bytes))
}

fn sample_layouts_from_file(file: &File, header: PerfHeader) -> Result<SampleLayouts, String> {
    let attr_size = usize::try_from(header.attr_size)
        .map_err(|_| "perf attr section size exceeds usize".to_string())?;
    let attr_bytes = read_file_range(file, header.attr_offset, attr_size, "perf attr section")?;
    let attrs = parse_file_attrs(
        &attr_bytes,
        PerfHeader {
            header_size: header.header_size,
            attr_offset: 0,
            attr_size: header.attr_size,
            data_offset: 0,
            data_size: 0,
        },
    )?;

    let mut layouts = SampleLayouts {
        fallback: attrs.first().map(|attr| SampleEventLayout {
            layout: layout_from_attr(attr),
        }),
        by_identifier: BTreeMap::new(),
    };
    for attr in &attrs {
        let event = SampleEventLayout {
            layout: layout_from_attr(attr),
        };
        for id in file_attr_ids_from_file(file, attr)? {
            layouts.by_identifier.insert(id, event);
        }
    }
    Ok(layouts)
}

fn file_attr_ids_from_file(file: &File, attr: &PerfFileAttr) -> Result<Vec<u64>, String> {
    let ids_size = usize::try_from(attr.ids_size)
        .map_err(|_| "perf attr id section size exceeds usize".to_string())?;
    let ids_bytes = read_file_range(file, attr.ids_offset, ids_size, "perf attr id section")?;
    parse_file_attr_ids(
        &ids_bytes,
        &PerfFileAttr {
            ids_offset: 0,
            ..attr.clone()
        },
    )
}

fn header_build_ids_by_filename_from_file(
    file: &File,
    header: PerfHeader,
    header_bytes: &[u8; 104],
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    build_id_events_from_file(file, header, header_bytes)?
        .into_iter()
        .map(|event| hex_build_id_bytes(&event.build_id).map(|build_id| (event.filename, build_id)))
        .collect()
}

fn build_id_events_from_file(
    file: &File,
    header: PerfHeader,
    header_bytes: &[u8; 104],
) -> Result<Vec<BuildIdEvent>, String> {
    let Some(section) = feature_sections_from_file(file, header, header_bytes)?
        .into_iter()
        .find(|section| section.feature == 2)
    else {
        return Ok(Vec::new());
    };
    let size = usize::try_from(section.size)
        .map_err(|_| "build-id feature size exceeds usize".to_string())?;
    let payload = read_file_range(file, section.offset, size, "build-id feature payload")?;
    parse_build_id_events(&payload)
}

fn feature_sections_from_file(
    file: &File,
    header: PerfHeader,
    header_bytes: &[u8; 104],
) -> Result<Vec<PerfFeatureSection>, String> {
    let features = perf_feature_bits(header_bytes)?;
    if features.is_empty() {
        return Ok(Vec::new());
    }
    let table_offset = header
        .data_offset
        .checked_add(header.data_size)
        .ok_or_else(|| "perf.data feature table offset overflows u64".to_string())?;
    let table_size = features
        .len()
        .checked_mul(16)
        .ok_or_else(|| "perf.data feature table size overflows usize".to_string())?;
    let table = read_file_range(file, table_offset, table_size, "perf feature table")?;

    let mut sections = Vec::with_capacity(features.len());
    for (index, feature) in features.into_iter().enumerate() {
        let entry_offset = index * 16;
        sections.push(PerfFeatureSection {
            feature,
            offset: read_u64(&table, entry_offset)?,
            size: read_u64(&table, entry_offset + 8)?,
        });
    }
    Ok(sections)
}

fn perf_feature_bits(header_bytes: &[u8; 104]) -> Result<Vec<u16>, String> {
    let mut features = Vec::new();
    for word_index in 0..4 {
        let word = read_u64(header_bytes, 56 + word_index * 8)?;
        for bit_index in 0..64 {
            if word & (1_u64 << bit_index) != 0 {
                let feature = u16::try_from(word_index * 64 + bit_index)
                    .map_err(|_| "perf.data feature bit exceeds u16".to_string())?;
                features.push(feature);
            }
        }
    }
    Ok(features)
}

fn read_file_range(
    file: &File,
    offset: u64,
    len: usize,
    range_name: &str,
) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0; len];
    let mut reader = file
        .try_clone()
        .map_err(|error| format!("failed to clone perf.data handle: {error}"))?;
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|error| format!("failed to seek {range_name}: {error}"))?;
    reader
        .read_exact(&mut bytes)
        .map_err(|error| format!("failed to read {range_name}: {error}"))?;
    Ok(bytes)
}

fn hex_build_id_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("build-id hex has odd length: {}", hex.len()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .map_err(|error| format!("build-id hex is invalid at offset {index}: {error}"))
        })
        .collect()
}

impl FoldAccumulator {
    fn new(header_build_ids: BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            process_comms: BTreeMap::new(),
            exec_process_comms: BTreeMap::new(),
            thread_comms: BTreeMap::new(),
            mmap_table: MmapTable::default(),
            unwind_states: HashMap::with_hasher(FxBuildHasher),
            header_build_ids,
            raw_stacks: RawStackAccumulator::<FoldFrame>::new(),
            deferred_samples: BTreeMap::new(),
            sample_frames: Vec::new(),
            callchain: Vec::new(),
            unwind_debug_dir: current_perf_debug_dir(),
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
                let unwind_state = self.unwind_state_mut(record.pid);
                load_unwind_mapping(
                    &mut unwind_state.object_unwinder,
                    &mut unwind_state.attempted_unwind_mappings,
                    &mut unwind_state.loaded_unwind_mappings,
                    UnwindMappingRequest {
                        start: record.start,
                        len: record.len,
                        pgoff: record.pgoff,
                        prot: None,
                        path: &record.path,
                        file_identity: None,
                        build_id: None,
                    },
                );
                self.mmap_table.insert_mmap(record);
                Ok(())
            }
            ParsedRecord::Sample(record) => {
                parse_sample_for_fold(self, record.misc, &record.payload, sample_layouts, options)
            }
            ParsedRecord::CallchainDeferred(record) => {
                self.add_deferred_callchain(record.cookie, &record.ips);
                Ok(())
            }
            ParsedRecord::Mmap2(record) => {
                let build_id = self.header_build_ids.get(&record.path).cloned();
                if let Some(build_id) = build_id {
                    let unwind_debug_dir = self.unwind_debug_dir.clone();
                    let unwind_state = self.unwind_state_mut(record.pid);
                    load_build_id_unwind_mapping(
                        &mut unwind_state.object_unwinder,
                        &mut unwind_state.attempted_unwind_mappings,
                        &mut unwind_state.loaded_unwind_mappings,
                        UnwindMappingRequest {
                            start: record.start,
                            len: record.len,
                            pgoff: record.pgoff,
                            prot: Some(record.prot),
                            path: &record.path,
                            file_identity: Some(mmap2_file_identity(&record)),
                            build_id: Some(&build_id),
                        },
                        unwind_debug_dir.as_deref(),
                    );
                    self.mmap_table
                        .insert_mmap2_with_build_id(record, Some(build_id));
                } else {
                    let unwind_state = self.unwind_state_mut(record.pid);
                    load_mmap2_unwind_mapping(
                        &mut unwind_state.object_unwinder,
                        &mut unwind_state.attempted_unwind_mappings,
                        &mut unwind_state.loaded_unwind_mappings,
                        &record,
                    );
                    self.mmap_table.insert_mmap2(record);
                }
                Ok(())
            }
            ParsedRecord::Mmap2BuildId(record) => {
                let unwind_debug_dir = self.unwind_debug_dir.clone();
                let unwind_state = self.unwind_state_mut(record.pid);
                load_build_id_unwind_mapping(
                    &mut unwind_state.object_unwinder,
                    &mut unwind_state.attempted_unwind_mappings,
                    &mut unwind_state.loaded_unwind_mappings,
                    UnwindMappingRequest {
                        start: record.start,
                        len: record.len,
                        pgoff: record.pgoff,
                        prot: Some(record.prot),
                        path: &record.path,
                        file_identity: None,
                        build_id: Some(&record.build_id),
                    },
                    unwind_debug_dir.as_deref(),
                );
                self.mmap_table.insert_mmap2_build_id(record);
                Ok(())
            }
            ParsedRecord::Fork(record) => {
                if record.clone_maps {
                    self.mmap_table.clone_pid_mappings(record.ppid, record.pid);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn into_fold_data(self) -> PerfFoldData {
        PerfFoldData {
            mmap_table: self.mmap_table,
            raw_stacks: self.raw_stacks,
        }
    }

    fn unwind_state_mut(&mut self, pid: u32) -> &mut PidUnwindState {
        self.unwind_states.entry(pid).or_default()
    }
}

fn timed_records(
    bytes: &[u8],
    header: PerfHeader,
    sample_layouts: &SampleLayouts,
) -> Result<Vec<TimedRecord>, String> {
    let mut timed = Vec::new();
    let mut offset = usize::try_from(header.data_offset)
        .map_err(|_| "perf data section offset exceeds usize".to_string())?;
    let data_size = usize::try_from(header.data_size)
        .map_err(|_| "perf data section size exceeds usize".to_string())?;
    let end = offset
        .checked_add(data_size)
        .ok_or_else(|| "perf data section size overflows usize".to_string())?;
    if end > bytes.len() {
        return Err("perf data section extends past end of file".to_string());
    }

    let mut index = 0usize;
    while offset < end {
        let header = parse_record_header(
            bytes
                .get(offset..offset + 8)
                .ok_or_else(|| format!("truncated perf record header at offset {offset}"))?,
        )?;
        let size = usize::from(header.size);
        if size < 8 {
            return Err(format!(
                "invalid perf record size {size} at offset {offset}"
            ));
        }
        let next = offset
            .checked_add(size)
            .ok_or_else(|| format!("perf record size overflows at offset {offset}"))?;
        if next > end {
            return Err(format!(
                "perf record overruns data section at offset {offset}"
            ));
        }
        let record = PerfRecord {
            offset,
            header,
            payload: &bytes[offset + 8..next],
        };
        let time = record_time(record, sample_layouts)?;
        timed.push(TimedRecord {
            index,
            time,
            offset,
            header,
        });
        index += 1;
        offset = next;
    }
    Ok(timed)
}

impl TimedRecord {
    fn record<'a>(&self, bytes: &'a [u8]) -> Result<PerfRecord<'a>, String> {
        let next = self
            .offset
            .checked_add(usize::from(self.header.size))
            .ok_or_else(|| format!("perf record size overflows at offset {}", self.offset))?;
        let payload = bytes
            .get(self.offset + 8..next)
            .ok_or_else(|| format!("perf record payload is truncated at offset {}", self.offset))?;
        Ok(PerfRecord {
            offset: self.offset,
            header: self.header,
            payload,
        })
    }
}

fn record_time(
    record: PerfRecord<'_>,
    sample_layouts: &SampleLayouts,
) -> Result<Option<u64>, String> {
    if record.header.record_type == crate::perfdata::records::PERF_RECORD_SAMPLE {
        return sample_layouts
            .layout_for_payload(record.payload)?
            .map_or(Ok(None), |event| {
                sample_payload_time(record.payload, event.layout)
            });
    }

    sample_layouts
        .fallback
        .filter(|event| event.layout.sample_id_all)
        .map_or(Ok(None), |event| {
            sample_id_payload_time(record.payload, event.layout)
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
    comm: Option<&str>,
    count: u64,
    frames: &[FoldFrame],
    mmap_table: &MmapTable,
    raw_stacks: &mut RawStackAccumulator<FoldFrame>,
    callchain: &mut Vec<FoldFrame>,
) {
    callchain.clear();
    callchain.reserve(frames.len());
    let mut mapping_cache = MappingResolveCache::default();
    for frame in frames.iter().rev().copied() {
        let address = frame.address();
        if is_perf_context_marker(address) {
            continue;
        }
        if should_drop_perf_data_user_unwind_frame(pid, frame, mmap_table, &mut mapping_cache) {
            continue;
        }
        callchain.push(frame);
    }
    if !callchain.is_empty() {
        raw_stacks.add_slice_with_borrowed_comm(pid, comm, callchain, count);
    }
}

impl FoldAccumulator {
    fn add_deferred_callchain(&mut self, cookie: u64, ips: &[u64]) {
        let Some(samples) = self.deferred_samples.remove(&cookie) else {
            return;
        };
        for mut sample in samples {
            sample
                .frames
                .extend(ips.iter().copied().map(FoldFrame::Callchain));
            add_fold_stack(
                sample.pid,
                sample.comm.as_deref(),
                sample.count,
                &sample.frames,
                &self.mmap_table,
                &mut self.raw_stacks,
                &mut self.callchain,
            );
        }
    }

    fn has_loaded_unwind_mapping_for_ip(&self, pid: Option<u32>, ip: u64) -> bool {
        let Some(pid) = pid else {
            return false;
        };
        let Some(mapping) = self.mmap_table.user_mapping_for_pid_ip(pid, ip) else {
            return false;
        };
        let Some(unwind_state) = self.unwind_states.get(&pid) else {
            return false;
        };
        let object_path = mapping.build_id.map_or_else(
            || PathBuf::from(mapping.path),
            |build_id| {
                unwind_object_path_for_build_id(
                    mapping.path,
                    build_id,
                    self.unwind_debug_dir.as_deref(),
                )
            },
        );
        unwind_state.loaded_unwind_mappings.contains(&(
            object_path.to_string_lossy().into_owned(),
            mapping.start,
            mapping.len,
            mapping.pgoff,
        ))
    }

    fn drain_fold_counts<R>(
        &mut self,
        counts: &mut FoldCounts,
        symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
    ) -> Result<(), String>
    where
        R: SymbolResolver,
    {
        let raw_stacks = std::mem::take(&mut self.raw_stacks);
        accumulate_fold_counts(&raw_stacks, &self.mmap_table, counts, symbol_cache)
    }
}

fn is_valid_unwound_user_frame(
    pid: Option<u32>,
    frame: FoldFrame,
    mmap_table: &MmapTable,
    mapping_cache: &mut MappingResolveCache,
) -> bool {
    let FoldFrame::UserUnwind(address) = frame else {
        return true;
    };
    pid.is_none_or(|pid| {
        !mmap_table.has_executable_mappings_for_pid(pid)
            || mmap_table.has_mapping_for_pid_cached(pid, address, mapping_cache)
            || is_kernel_space_frame(address)
    })
}

fn comm_for_ids<'a>(
    process_comms: &'a BTreeMap<u32, String>,
    exec_process_comms: &'a BTreeMap<u32, String>,
    thread_comms: &'a BTreeMap<u32, String>,
    pid: Option<u32>,
    tid: Option<u32>,
) -> Option<&'a str> {
    tid.and_then(|tid| thread_comms.get(&tid))
        .or_else(|| pid.and_then(|pid| exec_process_comms.get(&pid)))
        .or_else(|| pid.and_then(|pid| process_comms.get(&pid)))
        .map(String::as_str)
}

fn render_fold_data<R>(
    fold_data: PerfFoldData,
    symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
) -> Result<String, String>
where
    R: SymbolResolver,
{
    let mut folded = Vec::new();
    write_fold_data(fold_data, symbol_cache, &mut folded)?;
    String::from_utf8(folded).map_err(|error| format!("folded output is not utf-8: {error}"))
}

fn write_fold_data<R, W>(
    fold_data: PerfFoldData,
    symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
    writer: &mut W,
) -> Result<(), String>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    let PerfFoldData {
        mmap_table,
        raw_stacks,
    } = fold_data;
    let mut counts = FoldCounts::default();
    accumulate_fold_counts(&raw_stacks, &mmap_table, &mut counts, symbol_cache)?;
    write_fold_counts(counts, writer)
}

fn prefetch_symbols<R>(
    raw_stacks: &[RawStackEntryRef<'_, FoldFrame>],
    mmap_table: &MmapTable,
    symbol_cache: &mut SymbolFrameCache<'_, R>,
) -> Result<(), String>
where
    R: SymbolResolver,
{
    let mut mappings = Vec::new();
    let mut seen = HashSet::with_hasher(FxBuildHasher);
    let mut callchain = Vec::new();
    let mut mapping_cache = MappingResolveCache::default();
    for stack in raw_stacks {
        extend_symbol_mappings_for_stack(
            stack.pid(),
            stack.callchain(&mut callchain),
            mmap_table,
            &mut mapping_cache,
            &mut mappings,
            &mut seen,
        );
        if mappings.len() >= PREFETCH_SYMBOL_REQUEST_BATCH_SIZE {
            symbol_cache.prefetch_mapping_refs(&mappings)?;
            mappings.clear();
            seen.clear();
        }
    }
    if !mappings.is_empty() {
        symbol_cache.prefetch_mapping_refs(&mappings)?;
    }
    Ok(())
}

fn accumulate_fold_counts<R>(
    raw_stacks: &RawStackAccumulator<FoldFrame>,
    mmap_table: &MmapTable,
    counts: &mut FoldCounts,
    mut symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
) -> Result<(), String>
where
    R: SymbolResolver,
{
    let raw_stacks = raw_stacks.sorted_entries();
    counts.reserve_first_drain(raw_stacks.len());
    if let Some(cache) = symbol_cache.as_deref_mut() {
        prefetch_symbols(&raw_stacks, mmap_table, cache)?;
    }
    let frame_resolver = FoldFrameResolver::new(mmap_table);
    let mut callchain = Vec::new();
    let mut buffers = FoldedRenderBuffers::default();
    for stack in raw_stacks {
        frame_resolver.render_folded_stack_for_stack(
            stack.pid(),
            stack.comm(),
            stack.callchain(&mut callchain),
            symbol_cache.as_deref_mut(),
            &mut buffers,
        )?;
        counts.add_rendered(buffers.rendered.as_str(), stack.count());
    }
    Ok(())
}

fn write_fold_counts<W>(counts: FoldCounts, writer: &mut W) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    let FoldCounts {
        storage,
        mut entries,
        by_hash: _,
    } = counts;
    entries.sort_unstable_by(|left, right| {
        storage[left.offset..left.offset + left.len]
            .cmp(&storage[right.offset..right.offset + right.len])
    });
    for entry in entries {
        let callchain = std::str::from_utf8(&storage[entry.offset..entry.offset + entry.len])
            .map_err(|error| format!("stored folded output is not utf-8: {error}"))?;
        write_folded_line(writer, callchain, entry.count)?;
    }
    Ok(())
}

fn write_folded_line<W>(writer: &mut W, callchain: &str, count: u64) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    writer
        .write_all(callchain.as_bytes())
        .map_err(|error| format!("failed to write folded output: {error}"))?;
    writer
        .write_all(b" ")
        .map_err(|error| format!("failed to write folded output: {error}"))?;
    writer
        .write_all(count.to_string().as_bytes())
        .map_err(|error| format!("failed to write folded output: {error}"))?;
    writer
        .write_all(b"\n")
        .map_err(|error| format!("failed to write folded output: {error}"))
}

fn extend_symbol_mappings_for_stack<'a>(
    pid: Option<u32>,
    callchain: &[FoldFrame],
    mmap_table: &'a MmapTable,
    mapping_cache: &mut MappingResolveCache,
    mappings: &mut Vec<ResolvedMappingRef<'a>>,
    seen: &mut HashSet<PrefetchMappingKey, FxBuildHasher>,
) {
    for frame in callchain {
        let frame = frame.address();
        if let Some(mapping) = pid
            .and_then(|pid| mmap_table.resolve_ref_cached(pid, frame, mapping_cache))
            .filter(|mapping| !is_kernel_space_frame(frame) || is_kernel_mapping_ref(mapping))
        {
            let key = PrefetchMappingKey {
                symbol_source_id: mapping.symbol_source_id,
                relative_address: mapping.relative_address,
            };
            if seen.insert(key) {
                mappings.push(mapping);
            }
        }
    }
}

struct FoldFrameResolver<'a> {
    mmap_table: &'a MmapTable,
}

#[derive(Default)]
struct FoldedRenderBuffers {
    rendered: String,
    render_scratch: String,
    label_scratch: String,
    frame_rendered: String,
    frame_cache: FoldFrameRenderCache,
    mapping_cache: MappingResolveCache,
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

    fn render_folded_stack_for_stack<R>(
        &self,
        pid: Option<u32>,
        comm: Option<&str>,
        callchain: &[FoldFrame],
        mut symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
        buffers: &mut FoldedRenderBuffers,
    ) -> Result<(), String>
    where
        R: SymbolResolver,
    {
        buffers.rendered.clear();
        if let Some(comm) = comm {
            let FoldedRenderBuffers {
                rendered,
                render_scratch,
                label_scratch,
                frame_rendered,
                frame_cache,
                mapping_cache: _,
            } = buffers;
            label_scratch.clear();
            for character in comm.chars() {
                label_scratch.push(if character == ' ' { '_' } else { character });
            }
            append_cached_inferno_perf_frame(
                rendered,
                render_scratch,
                frame_rendered,
                frame_cache,
                label_scratch.as_str(),
            );
        } else {
            append_cached_inferno_perf_frame_to_buffers(buffers, UNKNOWN_FRAME);
        }

        for frame in callchain.iter().copied() {
            if symbol_cache.is_none()
                && !is_valid_unwound_user_frame(
                    pid,
                    frame,
                    self.mmap_table,
                    &mut buffers.mapping_cache,
                )
            {
                continue;
            }
            if should_drop_perf_data_user_unwind_frame(
                pid,
                frame,
                self.mmap_table,
                &mut buffers.mapping_cache,
            ) {
                continue;
            }
            self.append_folded_frame_labels(
                pid,
                frame.address(),
                symbol_cache.as_deref_mut(),
                buffers,
            )?;
        }
        Ok(())
    }

    fn write_script_frames_for_stack<R, W>(
        &self,
        pid: Option<u32>,
        callchain: &[FoldFrame],
        mut symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
        writer: &mut W,
    ) -> Result<(), String>
    where
        R: SymbolResolver,
        W: IoWrite + ?Sized,
    {
        let mut mapping_cache = MappingResolveCache::default();
        for frame in callchain.iter().copied() {
            if is_perf_context_marker(frame.address()) {
                continue;
            }
            if symbol_cache.is_none()
                && !is_valid_unwound_user_frame(pid, frame, self.mmap_table, &mut mapping_cache)
            {
                continue;
            }
            if should_drop_perf_data_user_unwind_frame(
                pid,
                frame,
                self.mmap_table,
                &mut mapping_cache,
            ) {
                continue;
            }
            let address = frame.address();
            let symbolizing = symbol_cache.is_some();
            if let Some(mapping) = pid.and_then(|pid| {
                self.mmap_table
                    .resolve_ref_cached(pid, address, &mut mapping_cache)
            }) {
                if is_kernel_space_frame(address) && !is_kernel_mapping_ref(&mapping) {
                    write_perf_script_address_frame(writer, address)?;
                    continue;
                }
                if let Some(cache) = symbol_cache.as_deref_mut() {
                    let frames = cache.resolve_mapping_ref(&mapping)?;
                    if frames.is_empty() {
                        write_perf_script_frame_for_label(
                            writer,
                            address,
                            &symbol_fallback_frame_ref(&mapping),
                        )?;
                    } else {
                        for label in frames.iter().rev() {
                            write_perf_script_frame_for_label(writer, address, label)?;
                        }
                    }
                    continue;
                }
                if is_kernel_space_frame(address) {
                    write_perf_script_unknown_frame(writer, address)?;
                } else {
                    write_perf_script_mapped_frame(
                        writer,
                        address,
                        mapping.path,
                        mapping.relative_address,
                    )?;
                }
            } else if is_kernel_space_frame(address) || symbolizing {
                write_perf_script_unknown_frame(writer, address)?;
            } else {
                write_perf_script_address_frame(writer, address)?;
            }
        }
        Ok(())
    }

    fn append_folded_frame_labels<R>(
        &self,
        pid: Option<u32>,
        frame: u64,
        symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
        buffers: &mut FoldedRenderBuffers,
    ) -> Result<(), String>
    where
        R: SymbolResolver,
    {
        let symbolizing = symbol_cache.is_some();
        if let Some(mapping) = pid.and_then(|pid| {
            self.mmap_table
                .resolve_ref_cached(pid, frame, &mut buffers.mapping_cache)
        }) {
            if is_kernel_space_frame(frame) && !is_kernel_mapping_ref(&mapping) {
                buffers.label_scratch.clear();
                write!(buffers.label_scratch, "0x{frame:x}")
                    .expect("writing to a string cannot fail");
                append_inferno_perf_frame(
                    &mut buffers.rendered,
                    &buffers.label_scratch,
                    &mut buffers.render_scratch,
                );
                return Ok(());
            }
            if let Some(cache) = symbol_cache {
                if let Some(rendered) = cache.resolve_folded_mapping_ref(&mapping)? {
                    append_cached_rendered_frame(&mut buffers.rendered, rendered);
                } else {
                    let fallback = symbol_fallback_frame_ref(&mapping);
                    append_cached_inferno_perf_frame_to_buffers(buffers, &fallback);
                }
                return Ok(());
            }
            if is_kernel_space_frame(frame) {
                append_cached_inferno_perf_frame_to_buffers(buffers, UNKNOWN_FRAME);
            } else {
                buffers.label_scratch.clear();
                write!(
                    buffers.label_scratch,
                    "{}+0x{:x}",
                    mapping.path, mapping.relative_address
                )
                .expect("writing to a string cannot fail");
                append_inferno_perf_frame(
                    &mut buffers.rendered,
                    &buffers.label_scratch,
                    &mut buffers.render_scratch,
                );
            }
        } else if is_kernel_space_frame(frame) || symbolizing {
            append_cached_inferno_perf_frame_to_buffers(buffers, UNKNOWN_FRAME);
        } else {
            buffers.label_scratch.clear();
            write!(buffers.label_scratch, "0x{frame:x}").expect("writing to a string cannot fail");
            append_inferno_perf_frame(
                &mut buffers.rendered,
                &buffers.label_scratch,
                &mut buffers.render_scratch,
            );
        }
        Ok(())
    }
}

fn append_cached_inferno_perf_frame(
    rendered: &mut String,
    render_scratch: &mut String,
    frame_rendered: &mut String,
    frame_cache: &mut FoldFrameRenderCache,
    frame: &str,
) {
    if let Some(cached) = frame_cache.get(frame) {
        append_cached_rendered_frame(rendered, cached);
        return;
    }
    frame_rendered.clear();
    append_inferno_perf_frame(frame_rendered, frame, render_scratch);
    append_cached_rendered_frame(rendered, frame_rendered.as_str());
    frame_cache.insert(frame.to_string(), std::mem::take(frame_rendered));
}

fn append_cached_inferno_perf_frame_to_buffers(buffers: &mut FoldedRenderBuffers, frame: &str) {
    append_cached_inferno_perf_frame(
        &mut buffers.rendered,
        &mut buffers.render_scratch,
        &mut buffers.frame_rendered,
        &mut buffers.frame_cache,
        frame,
    );
}

fn append_cached_rendered_frame(rendered: &mut String, cached: &str) {
    if cached.is_empty() {
        return;
    }
    if !rendered.is_empty() {
        rendered.push(';');
    }
    rendered.push_str(cached);
}

fn write_perf_script_frame_for_label<W>(
    writer: &mut W,
    address: u64,
    label: &str,
) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    if label == UNKNOWN_FRAME {
        return write_perf_script_unknown_frame(writer, address);
    }
    if label.starts_with("0x") {
        return write_perf_script_label_frame(writer, address, label);
    }
    if let Some(module) = module_fallback_label_module(label) {
        return writeln!(writer, "\t{address:x} {UNKNOWN_FRAME} ({module})")
            .map_err(|error| format!("failed to write perf script output: {error}"));
    }
    if looks_like_mapped_frame_label(label) {
        return writeln!(writer, "\t{address:x} {label}+0x0 ({UNKNOWN_FRAME})")
            .map_err(|error| format!("failed to write perf script output: {error}"));
    }
    write_perf_script_label_frame(writer, address, label)
}

fn write_perf_script_unknown_frame<W>(writer: &mut W, address: u64) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    writeln!(writer, "\t{address:x} {UNKNOWN_FRAME} ({UNKNOWN_FRAME})")
        .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn write_perf_script_address_frame<W>(writer: &mut W, address: u64) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    writeln!(writer, "\t{address:x} 0x{address:x} ({UNKNOWN_FRAME})")
        .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn write_perf_script_label_frame<W>(writer: &mut W, address: u64, label: &str) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    writeln!(writer, "\t{address:x} {label} ({UNKNOWN_FRAME})")
        .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn write_perf_script_mapped_frame<W>(
    writer: &mut W,
    address: u64,
    path: &str,
    relative_address: u64,
) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    writeln!(
        writer,
        "\t{address:x} {path}+0x{relative_address:x}+0x0 ({UNKNOWN_FRAME})"
    )
    .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn module_fallback_label_module(label: &str) -> Option<&str> {
    let inner = label.strip_prefix('[')?.strip_suffix(']')?;
    (inner != "unknown" && !inner.is_empty()).then_some(inner)
}

fn looks_like_mapped_frame_label(label: &str) -> bool {
    label.rsplit_once("+0x").is_some_and(|(_, suffix)| {
        !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_hexdigit())
    })
}

fn should_drop_perf_data_user_unwind_frame(
    pid: Option<u32>,
    frame: FoldFrame,
    mmap_table: &MmapTable,
    mapping_cache: &mut MappingResolveCache,
) -> bool {
    let FoldFrame::UserUnwind(address) = frame else {
        return false;
    };
    is_kernel_space_frame(address)
        || pid.is_some_and(|pid| {
            mmap_table
                .mapping_path_cached(pid, address, mapping_cache)
                .is_some_and(should_drop_user_unwind_mapping_path)
        })
}

fn should_drop_user_unwind_mapping_path(path: &str) -> bool {
    is_perf_data_mapping_path(path) || matches!(path, "//anon" | "[anon]" | "[stack]" | "[heap]")
}

fn is_perf_data_mapping_path(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|file_name| file_name == "perf.data" || file_name.starts_with("perf.data."))
}

fn symbol_fallback_frame_ref(mapping: &ResolvedMappingRef<'_>) -> String {
    if is_kernel_mapping_ref(mapping) {
        kernel_module_fallback_frame(mapping.path)
    } else if mapping.path == UNKNOWN_FRAME {
        mapping.path.to_string()
    } else if mapping.path.starts_with('[') {
        mapped_frame_label_ref(mapping)
    } else {
        module_fallback_frame(mapping.path)
    }
}

fn build_id_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex, "{byte:02x}").expect("writing to a string cannot fail");
    }
    hex
}

fn mapped_frame_label_ref(mapping: &ResolvedMappingRef<'_>) -> String {
    format!("{}+0x{:x}", mapping.path, mapping.relative_address)
}

fn module_fallback_frame(path: &str) -> String {
    let name = Path::new(path)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or(path);
    format!("[{name}]")
}

fn kernel_module_fallback_frame(path: &str) -> String {
    if path.starts_with("[kernel.kallsyms]") {
        "[[kernel.kallsyms]]".to_string()
    } else {
        module_fallback_frame(path)
    }
}

fn is_kernel_mapping_ref(mapping: &ResolvedMappingRef<'_>) -> bool {
    is_kernel_space_frame(mapping.relative_address) && mapping.path.starts_with('[')
}

fn parse_sample_for_summary(
    sample_misc: u16,
    payload: &[u8],
    sample_layouts: &SampleLayouts,
) -> Result<Option<PerfSampleStack>, String> {
    if let Some(event) = sample_layouts.layout_for_payload(payload)? {
        parse_sample_record_callchain(payload, event.layout).map(|sample| {
            sample.map(|sample| PerfSampleStack {
                misc: sample_misc,
                cpumode: sample_misc & PERF_RECORD_MISC_CPUMODE_MASK,
                pid: sample.pid,
                tid: sample.tid,
                period: sample.period,
                callchain: sample.frames.collect(),
                has_user_stack: sample.user_stack.is_some(),
                user_register_count: sample
                    .user_regs
                    .as_ref()
                    .map_or(0, |regs| regs.values.len()),
                user_register_ip: sample.user_regs.as_ref().and_then(|regs| {
                    perf_user_reg_value(event.layout.sample_regs_user, &regs.values, 8)
                }),
                user_stack_size: sample
                    .user_stack
                    .as_ref()
                    .map_or(0, |stack| stack.bytes.len()),
                user_stack_dynamic_size: sample
                    .user_stack
                    .as_ref()
                    .map_or(0, |stack| stack.dynamic_size),
            })
        })
    } else {
        Ok(None)
    }
}

fn perf_user_reg_value(mask: u64, values: &[u64], register: u32) -> Option<u64> {
    if mask & (1_u64 << register) == 0 {
        return None;
    }
    let index = (mask & ((1_u64 << register) - 1)).count_ones() as usize;
    values.get(index).copied()
}

fn parse_sample_for_fold(
    accumulator: &mut FoldAccumulator,
    misc: u16,
    payload: &[u8],
    sample_layouts: &SampleLayouts,
    options: FoldOptions,
) -> Result<(), String> {
    let Some(sample) =
        prepare_sample_for_fold(accumulator, misc, payload, sample_layouts, options)?
    else {
        return Ok(());
    };
    if let Some(cookie) = sample.deferred_cookie {
        accumulator
            .deferred_samples
            .entry(cookie)
            .or_default()
            .push(DeferredFoldSample {
                pid: sample.pid,
                comm: sample.comm,
                count: sample.count,
                frames: sample.frames,
            });
    } else {
        add_fold_stack(
            sample.pid,
            sample.comm.as_deref(),
            sample.count,
            &sample.frames,
            &accumulator.mmap_table,
            &mut accumulator.raw_stacks,
            &mut accumulator.callchain,
        );
    }
    Ok(())
}

fn prepare_sample_for_fold(
    accumulator: &mut FoldAccumulator,
    misc: u16,
    payload: &[u8],
    sample_layouts: &SampleLayouts,
    options: FoldOptions,
) -> Result<Option<PreparedFoldSample>, String> {
    let Some(event) = sample_layouts.layout_for_payload(payload)? else {
        return Ok(None);
    };
    let Some(sample) = parse_sample_record_callchain(payload, event.layout)? else {
        return Ok(None);
    };
    let count = sample_fold_count(sample.period, options);
    accumulator.sample_frames.clear();
    accumulator.sample_frames.reserve(sample.frames.len());
    accumulator
        .sample_frames
        .extend(sample.frames.clone().map(FoldFrame::Callchain));
    let deferred_cookie = take_deferred_cookie(&mut accumulator.sample_frames);
    append_perf_user_unwind_frames(accumulator, misc, event, &sample);
    let comm = comm_for_ids(
        &accumulator.process_comms,
        &accumulator.exec_process_comms,
        &accumulator.thread_comms,
        sample.pid,
        sample.tid,
    );
    Ok(Some(PreparedFoldSample {
        pid: sample.pid,
        comm: comm.map(str::to_owned),
        count,
        frames: std::mem::take(&mut accumulator.sample_frames),
        deferred_cookie,
    }))
}

fn append_perf_user_unwind_frames(
    accumulator: &mut FoldAccumulator,
    misc: u16,
    event: SampleEventLayout,
    sample: &crate::perfdata::samples::SampleCallchain<'_>,
) {
    let (Some(regs), Some(stack)) = (&sample.user_regs, &sample.user_stack) else {
        return;
    };
    if !has_perf_captured_user_stack(stack) {
        return;
    }
    let Ok(regs) =
        PerfX86_64Regs::from_perf_masked_values(event.layout.sample_regs_user, &regs.values)
    else {
        return;
    };
    let initial_ip_mapping = if sample
        .pid
        .is_some_and(|pid| accumulator.mmap_table.has_mapping_for_pid(pid, regs.ip))
    {
        if accumulator.has_loaded_unwind_mapping_for_ip(sample.pid, regs.ip) {
            InitialIpMappingState::RecordedMappingLoaded
        } else {
            InitialIpMappingState::RecordedMappingMissing
        }
    } else {
        InitialIpMappingState::NoRecordedMapping
    };
    let module_count = sample
        .pid
        .and_then(|pid| accumulator.unwind_states.get(&pid))
        .map_or(0, |state| state.object_unwinder.module_count());
    // perf script on kernel samples with an empty FP chain prints no stack,
    // even when PERF_SAMPLE_REGS_USER/PERF_SAMPLE_STACK_USER are present.
    let callchain = if (misc & PERF_RECORD_MISC_CPUMODE_MASK) == PERF_RECORD_MISC_CPUMODE_KERNEL
        && sample.frames.is_empty()
    {
        SampleCallchainState::KernelWithoutCallchain
    } else {
        SampleCallchainState::Other {
            has_callchain: event.layout.sample_type & PERF_SAMPLE_CALLCHAIN != 0,
            has_frames: !accumulator.sample_frames.is_empty(),
        }
    };
    let unwound_frames = unwind_user_stack_like_perf(
        accumulator,
        sample,
        &regs,
        UserUnwindContext {
            callchain,
            initial_ip_mapping,
            module_count,
        },
    );
    let mut unwound_frames = perf_accepted_unwind_frames(unwound_frames)
        .into_iter()
        .map(FoldFrame::UserUnwind)
        .collect::<Vec<_>>();
    let mut mapping_cache = MappingResolveCache::default();
    truncate_user_unwind_at_first_unmapped_frame(
        sample.pid,
        &mut unwound_frames,
        &accumulator.mmap_table,
        &mut mapping_cache,
    );
    accumulator.sample_frames.extend(unwound_frames);
}

fn unwind_user_stack_like_perf(
    accumulator: &mut FoldAccumulator,
    sample: &crate::perfdata::samples::SampleCallchain<'_>,
    regs: &PerfX86_64Regs,
    context: UserUnwindContext,
) -> Vec<u64> {
    let Some(stack) = &sample.user_stack else {
        return Vec::new();
    };
    let Some(stack_bytes) = perf_effective_user_stack_bytes(stack) else {
        return Vec::new();
    };
    match choose_user_unwind_source(context) {
        UserUnwindSource::None => Vec::new(),
        UserUnwindSource::FramePointer => unwind_x86_64_stack(*regs, stack_bytes, 256),
        UserUnwindSource::Object => sample
            .pid
            .and_then(|pid| accumulator.unwind_states.get_mut(&pid))
            .map_or_else(Vec::new, |state| {
                perf_accepted_object_unwind_frames(
                    regs,
                    context.callchain,
                    state.object_unwinder.unwind_stack(*regs, stack_bytes, 256),
                )
            }),
    }
}

fn choose_user_unwind_source(context: UserUnwindContext) -> UserUnwindSource {
    if context.callchain == SampleCallchainState::KernelWithoutCallchain
        || context.initial_ip_mapping == InitialIpMappingState::RecordedMappingMissing
    {
        UserUnwindSource::None
    } else if context.module_count == 0 {
        if context.callchain
            == (SampleCallchainState::Other {
                has_callchain: true,
                has_frames: true,
            })
            && context.initial_ip_mapping == InitialIpMappingState::NoRecordedMapping
        {
            UserUnwindSource::FramePointer
        } else {
            UserUnwindSource::None
        }
    } else if matches!(
        context.callchain,
        SampleCallchainState::Other {
            has_callchain: true,
            ..
        }
    ) {
        UserUnwindSource::Object
    } else {
        UserUnwindSource::None
    }
}

fn sample_fold_count(period: Option<u64>, options: FoldOptions) -> u64 {
    if options.count_periods {
        period.unwrap_or(1)
    } else {
        1
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

fn has_perf_captured_user_stack(stack: &crate::perfdata::samples::SampleUserStack<'_>) -> bool {
    !stack.bytes.is_empty() && stack.dynamic_size != 0
}

fn perf_effective_user_stack_bytes<'a>(
    stack: &'a crate::perfdata::samples::SampleUserStack<'a>,
) -> Option<&'a [u8]> {
    let dynamic_size = usize::try_from(stack.dynamic_size).ok()?;
    stack.bytes.get(..dynamic_size)
}

fn truncate_user_unwind_at_first_unmapped_frame(
    pid: Option<u32>,
    frames: &mut Vec<FoldFrame>,
    mmap_table: &MmapTable,
    mapping_cache: &mut MappingResolveCache,
) {
    let Some(index) = frames
        .iter()
        .position(|frame| !is_valid_unwound_user_frame(pid, *frame, mmap_table, mapping_cache))
    else {
        return;
    };
    if index + 1 != frames.len() {
        frames.truncate(index);
    }
}

fn perf_accepted_unwind_frames(unwound_frames: Vec<u64>) -> Vec<u64> {
    unwound_frames
}

fn perf_accepted_object_unwind_frames(
    regs: &PerfX86_64Regs,
    callchain: SampleCallchainState,
    unwound_frames: Vec<u64>,
) -> Vec<u64> {
    // framehop yields the sampled instruction pointer before trying to advance.
    // perf's libdw path reports the IP to DWFL as initial state, then only
    // prints entries accepted via frame_callback/entry.
    match unwound_frames.as_slice() {
        [ip] if *ip == regs.ip => Vec::new(),
        [ip, _]
            if *ip == regs.ip
                && callchain
                    == (SampleCallchainState::Other {
                        has_callchain: false,
                        has_frames: false,
                    }) =>
        {
            Vec::new()
        }
        _ => unwound_frames,
    }
}

fn load_unwind_mapping(
    object_unwinder: &mut FramehopUnwinder,
    attempted_unwind_mappings: &mut BTreeSet<(String, u64, u64, u64)>,
    loaded_unwind_mappings: &mut BTreeSet<(String, u64, u64, u64)>,
    request: UnwindMappingRequest<'_>,
) {
    if !should_load_unwind_object(request.path, request.file_identity) {
        return;
    }
    if request.prot.is_some_and(|prot| prot & PROT_EXEC == 0) {
        return;
    }
    let key = (
        request.path.to_string(),
        request.start,
        request.len,
        request.pgoff,
    );
    if !attempted_unwind_mappings.insert(key.clone()) {
        return;
    }
    if object_unwinder
        .add_object_mapping(
            Path::new(request.path),
            request.start,
            request.len,
            request.pgoff,
        )
        .is_ok_and(|loaded| loaded || object_unwinder.has_reported_module_for_ip(request.start))
    {
        loaded_unwind_mappings.insert(key);
    }
}

fn load_mmap2_unwind_mapping(
    object_unwinder: &mut FramehopUnwinder,
    attempted_unwind_mappings: &mut BTreeSet<(String, u64, u64, u64)>,
    loaded_unwind_mappings: &mut BTreeSet<(String, u64, u64, u64)>,
    record: &Mmap2Record,
) {
    load_unwind_mapping(
        object_unwinder,
        attempted_unwind_mappings,
        loaded_unwind_mappings,
        UnwindMappingRequest {
            start: record.start,
            len: record.len,
            pgoff: record.pgoff,
            prot: Some(record.prot),
            path: &record.path,
            file_identity: Some(mmap2_file_identity(record)),
            build_id: None,
        },
    );
}

fn load_build_id_unwind_mapping(
    object_unwinder: &mut FramehopUnwinder,
    attempted_unwind_mappings: &mut BTreeSet<(String, u64, u64, u64)>,
    loaded_unwind_mappings: &mut BTreeSet<(String, u64, u64, u64)>,
    request: UnwindMappingRequest<'_>,
    debug_dir: Option<&Path>,
) {
    let Some(build_id) = request.build_id else {
        return;
    };
    let object_path = unwind_object_path_for_build_id(request.path, build_id, debug_dir);
    if object_path.to_string_lossy().starts_with('[') {
        return;
    }
    let key = (
        object_path.to_string_lossy().into_owned(),
        request.start,
        request.len,
        request.pgoff,
    );
    if !attempted_unwind_mappings.insert(key.clone()) {
        return;
    }
    if object_unwinder
        .add_object_mapping(&object_path, request.start, request.len, request.pgoff)
        .is_ok_and(|loaded| loaded || object_unwinder.has_reported_module_for_ip(request.start))
    {
        loaded_unwind_mappings.insert(key);
    }
}

fn unwind_object_path_for_build_id(
    path: &str,
    build_id: &[u8],
    debug_dir: Option<&Path>,
) -> PathBuf {
    debug_dir
        .map(|debug_dir| perf_build_id_elf_path(debug_dir, &build_id_hex(build_id)))
        .filter(|cached| cached.exists())
        .unwrap_or_else(|| PathBuf::from(path))
}

fn mmap2_file_identity(record: &Mmap2Record) -> FileIdentity {
    FileIdentity {
        major: record.major,
        minor: record.minor,
        inode: record.inode,
        inode_generation: record.inode_generation,
    }
}

fn should_load_unwind_object(path: &str, _file_identity: Option<FileIdentity>) -> bool {
    !path.starts_with('[')
}

fn current_perf_debug_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".debug"))
}

fn sample_layouts(
    bytes: &[u8],
    header: crate::perfdata::header::PerfHeader,
) -> Result<SampleLayouts, String> {
    let attrs = parse_file_attrs(bytes, header)?;
    let mut layouts = SampleLayouts {
        fallback: attrs.first().map(|attr| SampleEventLayout {
            layout: layout_from_attr(attr),
        }),
        by_identifier: BTreeMap::new(),
    };
    for attr in &attrs {
        let event = SampleEventLayout {
            layout: layout_from_attr(attr),
        };
        for id in parse_file_attr_ids(bytes, attr)? {
            layouts.by_identifier.insert(id, event);
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
    fn layout_for_payload(&self, payload: &[u8]) -> Result<Option<SampleEventLayout>, String> {
        if self.by_identifier.is_empty() {
            return Ok(self.fallback);
        }
        let Some(fallback) = self.fallback else {
            return Ok(None);
        };
        if let Some(identifier) = sample_event_id(payload, fallback.layout)? {
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
    use crate::perfdata::mappings::FileIdentity;

    fn test_regs(ip: u64) -> super::PerfX86_64Regs {
        super::PerfX86_64Regs {
            ip,
            sp: 0x2000,
            bp: 0x3000,
            registers: [0; 16],
        }
    }

    #[test]
    fn loads_unwind_object_when_recorded_file_identity_mismatches_path_like_perf_libdw() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("app");
        std::fs::write(&path, b"binary").expect("write app");

        assert!(super::should_load_unwind_object(
            path.to_str().expect("utf-8 path"),
            Some(FileIdentity {
                major: 0,
                minor: 0,
                inode: u64::MAX,
                inode_generation: 0,
            }),
        ));
    }

    #[test]
    fn chooses_perf_build_id_cache_for_build_id_unwind_mappings() {
        let root = tempfile::tempdir().expect("tempdir");
        let debug_dir = root.path().join(".debug");
        let cached = debug_dir
            .join(".build-id")
            .join("aa")
            .join("bbcc")
            .join("elf");
        std::fs::create_dir_all(cached.parent().expect("parent")).expect("cache dir");
        std::fs::write(&cached, b"cached elf").expect("cached elf");

        let resolved = super::unwind_object_path_for_build_id(
            "/tmp/stale-app",
            &[0xaa, 0xbb, 0xcc],
            Some(&debug_dir),
        );

        assert_eq!(resolved, cached);
    }

    #[test]
    fn empty_unwind_for_loaded_module_does_not_invent_current_ip_like_perf_libdw() {
        assert_eq!(
            super::perf_accepted_unwind_frames(Vec::new()),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn object_unwind_drops_short_fallback_stack_without_callchain_like_perf_libdw() {
        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &test_regs(0x1000),
                super::SampleCallchainState::Other {
                    has_callchain: false,
                    has_frames: false,
                },
                vec![0x1000, 0x1100],
            ),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn fold_counts_coalesce_duplicate_rendered_lines() {
        let mut counts = super::FoldCounts::default();

        counts.add_rendered("alpha;beta", 2);
        counts.add_rendered("alpha;beta", 3);
        counts.add_rendered("alpha;gamma", 5);

        assert_eq!(counts.entries.len(), 2);

        let alpha_beta = counts
            .find_entry_id(super::fold_count_hash(b"alpha;beta"), b"alpha;beta")
            .expect("alpha beta entry");
        let alpha_gamma = counts
            .find_entry_id(super::fold_count_hash(b"alpha;gamma"), b"alpha;gamma")
            .expect("alpha gamma entry");

        assert_eq!(counts.entries[alpha_beta].count, 5);
        assert_eq!(counts.entries[alpha_gamma].count, 5);
    }

    #[test]
    fn write_fold_counts_matches_string_sort_order() {
        let mut counts = super::FoldCounts::default();
        let mut expected = vec![
            ("zeta;leaf".to_string(), 4_u64),
            ("alpha;leaf".to_string(), 2_u64),
            ("éclair;leaf".to_string(), 3_u64),
            ("beta;leaf".to_string(), 1_u64),
        ];

        for (callchain, count) in &expected {
            counts.add_rendered(callchain, *count);
        }

        let mut written = Vec::new();
        super::write_fold_counts(counts, &mut written).expect("write fold counts");

        expected.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let expected =
            expected
                .into_iter()
                .fold(String::new(), |mut rendered, (callchain, count)| {
                    rendered.push_str(&callchain);
                    rendered.push(' ');
                    rendered.push_str(&count.to_string());
                    rendered.push('\n');
                    rendered
                });

        assert_eq!(String::from_utf8(written).expect("utf-8"), expected);
    }

    #[test]
    fn fold_counts_round_trip_many_large_entries_after_growth() {
        let mut counts = super::FoldCounts::default();
        let mut expected = Vec::new();

        for index in 0..192_u64 {
            let callchain = format!("root;frame-{index:03};{}", "x".repeat(2048));
            counts.add_rendered(&callchain, index + 1);
            expected.push((callchain, index + 1));
        }

        counts.add_rendered(&expected[17].0, 5);
        expected[17].1 += 5;

        let mut written = Vec::new();
        super::write_fold_counts(counts, &mut written).expect("write fold counts");

        expected.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let expected =
            expected
                .into_iter()
                .fold(String::new(), |mut rendered, (callchain, count)| {
                    rendered.push_str(&callchain);
                    rendered.push(' ');
                    rendered.push_str(&count.to_string());
                    rendered.push('\n');
                    rendered
                });

        assert_eq!(String::from_utf8(written).expect("utf-8"), expected);
    }

    #[test]
    fn fold_counts_reserve_for_drain_extends_capacity_after_first_drain() {
        let mut counts = super::FoldCounts::default();

        counts.reserve_first_drain(1);
        counts.add_rendered("alpha;leaf", 1);

        let previous_entry_capacity = counts.entries.capacity();
        let previous_hash_capacity = counts.by_hash.capacity();

        counts.reserve_first_drain(128);

        assert_eq!(counts.entries.capacity(), previous_entry_capacity);
        assert_eq!(counts.by_hash.capacity(), previous_hash_capacity);
    }

    #[test]
    fn extend_symbol_mappings_deduplicates_prefetch_keys_across_stacks() {
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x1000,
            len: 0x1000,
            pgoff: 0,
            path: "/bin/demo".to_string(),
        });

        let mut mapping_cache = super::MappingResolveCache::default();
        let mut mappings = Vec::new();
        let mut seen = hashbrown::HashSet::with_hasher(rustc_hash::FxBuildHasher);
        let callchain = [
            super::FoldFrame::Callchain(0x1010),
            super::FoldFrame::Callchain(0x1020),
        ];

        super::extend_symbol_mappings_for_stack(
            Some(11),
            &callchain,
            &mmap_table,
            &mut mapping_cache,
            &mut mappings,
            &mut seen,
        );
        super::extend_symbol_mappings_for_stack(
            Some(11),
            &callchain,
            &mmap_table,
            &mut mapping_cache,
            &mut mappings,
            &mut seen,
        );

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].relative_address, 0x10);
        assert_eq!(mappings[1].relative_address, 0x20);
    }

    #[test]
    fn truncates_user_unwind_at_first_unmapped_frame_like_perf_libdw_entry() {
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x1000,
            len: 0x100,
            pgoff: 0,
            path: "/bin/demo".to_string(),
        });
        let mut mapping_cache = super::MappingResolveCache::default();
        let mut frames = vec![
            super::FoldFrame::UserUnwind(0x1010),
            super::FoldFrame::UserUnwind(0x6),
            super::FoldFrame::UserUnwind(0x1020),
        ];

        super::truncate_user_unwind_at_first_unmapped_frame(
            Some(11),
            &mut frames,
            &mmap_table,
            &mut mapping_cache,
        );

        assert_eq!(frames, vec![super::FoldFrame::UserUnwind(0x1010)]);
    }

    #[test]
    fn keeps_terminal_unmapped_user_unwind_frame_like_perf_libdw_entry() {
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x1000,
            len: 0x100,
            pgoff: 0,
            path: "/bin/demo".to_string(),
        });
        let mut mapping_cache = super::MappingResolveCache::default();
        let mut frames = vec![
            super::FoldFrame::UserUnwind(0x1010),
            super::FoldFrame::UserUnwind(0x6),
        ];

        super::truncate_user_unwind_at_first_unmapped_frame(
            Some(11),
            &mut frames,
            &mmap_table,
            &mut mapping_cache,
        );

        assert_eq!(
            frames,
            vec![
                super::FoldFrame::UserUnwind(0x1010),
                super::FoldFrame::UserUnwind(0x6),
            ]
        );
    }

    #[test]
    fn user_unwind_source_skips_recorded_ip_without_loaded_unwind_module() {
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                callchain: super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: true,
                },
                initial_ip_mapping: super::InitialIpMappingState::RecordedMappingMissing,
                module_count: 1,
            }),
            super::UserUnwindSource::None
        );
    }

    #[test]
    fn user_unwind_source_uses_frame_pointer_only_for_callchain_without_modules() {
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                callchain: super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: true,
                },
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                module_count: 0,
            }),
            super::UserUnwindSource::FramePointer
        );
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                callchain: super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: false,
                },
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                module_count: 0,
            }),
            super::UserUnwindSource::None
        );
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                callchain: super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: true,
                },
                initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
                module_count: 0,
            }),
            super::UserUnwindSource::None
        );
    }

    #[test]
    fn user_unwind_source_uses_object_unwinder_with_callchain_field_like_perf_script() {
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                callchain: super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: false,
                },
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                module_count: 1,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_uses_object_unwinder_for_nonempty_callchain_after_modules_are_loaded() {
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                callchain: super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: true,
                },
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                module_count: 1,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_skips_kernel_samples_without_kernel_callchain_like_perf_script() {
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                callchain: super::SampleCallchainState::KernelWithoutCallchain,
                initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
                module_count: 1,
            }),
            super::UserUnwindSource::None
        );
    }

    #[test]
    fn sample_fold_count_uses_period_only_when_requested() {
        assert_eq!(
            super::sample_fold_count(
                Some(37),
                super::FoldOptions {
                    count_periods: true
                }
            ),
            37
        );
        assert_eq!(
            super::sample_fold_count(
                Some(37),
                super::FoldOptions {
                    count_periods: false
                }
            ),
            1
        );
    }

    #[test]
    fn sample_fold_count_defaults_missing_period_to_one() {
        assert_eq!(
            super::sample_fold_count(
                None,
                super::FoldOptions {
                    count_periods: true
                }
            ),
            1
        );
    }

    #[test]
    fn fold_counts_handle_hash_collisions_without_losing_entries() {
        let mut counts = super::FoldCounts::default();

        counts.add_rendered_with_hash(b"alpha;leaf", 2, 7);
        counts.add_rendered_with_hash(b"beta;leaf", 3, 7);
        counts.add_rendered_with_hash(b"alpha;leaf", 5, 7);

        let mut written = Vec::new();
        super::write_fold_counts(counts, &mut written).expect("write fold counts");

        assert_eq!(
            String::from_utf8(written).expect("utf-8"),
            "alpha;leaf 7\nbeta;leaf 3\n"
        );
    }
}
