use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::fs::File;
use std::hash::Hasher;
use std::io::{BufReader, Read, Seek, SeekFrom, Write as IoWrite};
use std::path::{Path, PathBuf};

use hashbrown::{HashMap, HashSet};
use rustc_hash::{FxBuildHasher, FxHasher};

use crate::folded::{append_inferno_perf_folded_label, append_inferno_perf_raw_function};
use crate::perfdata::attrs::{PerfFileAttr, parse_file_attr_ids, parse_file_attrs};
use crate::perfdata::build_id::{
    BuildIdEvent, build_id_events_from_perfdata, parse_build_id_events,
};
use crate::perfdata::endian::{read_u32, read_u64};
use crate::perfdata::header::{PerfFeatureSection, PerfHeader, parse_header, parse_header_arch};
use crate::perfdata::mappings::{
    FileIdentity, MappingResolveCache, MmapTable, ResolvedMappingRef, UserMapping,
};
use crate::perfdata::raw_stack::{RawStackAccumulator, RawStackEntryRef};
use crate::perfdata::records::{
    PERF_RECORD_FINISHED_ROUND, PERF_RECORD_MISC_CPUMODE_KERNEL, PERF_RECORD_MISC_CPUMODE_MASK,
    ParsedRecord, PerfRecord, PerfRecordHeader, iter_records, parse_record, parse_record_header,
};
use crate::perfdata::samples::{
    PERF_SAMPLE_ADDR, PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_CPU, PERF_SAMPLE_ID,
    PERF_SAMPLE_IDENTIFIER, PERF_SAMPLE_IP, PERF_SAMPLE_STREAM_ID, PERF_SAMPLE_TID,
    PERF_SAMPLE_TIME, SampleLayout, is_kernel_space_frame, is_perf_context_marker,
    is_perf_user_deferred_context_marker, parse_sample_record_callchain,
};
use crate::perfdata::unwind::{
    FramehopUnwinder, PerfArch, PerfUserRegs, UserStackUnwindResult, UserStackUnwinder,
    unwind_aarch64_frame_pointer_stack_like_elfutils,
    unwind_x86_64_frame_pointer_stack_like_elfutils,
};
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
    /// Architecture of the recording machine (HEADER_ARCH), used to decode
    /// REGS_USER samples and construct per-pid unwinders. Defaults to x86_64
    /// when the feature is absent.
    arch: PerfArch,
}

struct PidUnwindState {
    object_unwinder: FramehopUnwinder,
    attempted_unwind_mappings: BTreeSet<UnwindMappingKey>,
    loaded_unwind_modules: BTreeSet<UnwindModuleKey>,
}

impl PidUnwindState {
    fn with_arch(arch: PerfArch) -> Self {
        Self {
            object_unwinder: FramehopUnwinder::with_arch(arch),
            attempted_unwind_mappings: BTreeSet::new(),
            loaded_unwind_modules: BTreeSet::new(),
        }
    }
}

type UnwindMappingKey = (String, u64, u64, u64);
type UnwindModuleKey = (String, u64);
const MAX_LIBDW_CALLBACK_REPORT_PASSES: usize = 8;

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
    tid: Option<u32>,
    time: Option<u64>,
    cpu: Option<u32>,
    comm: Option<String>,
    event_name: String,
    count: u64,
    frames: Vec<FoldFrame>,
    has_callchain: bool,
}

struct PreparedFoldSample {
    pid: Option<u32>,
    tid: Option<u32>,
    time: Option<u64>,
    cpu: Option<u32>,
    comm: Option<String>,
    event_name: String,
    count: u64,
    frames: Vec<FoldFrame>,
    deferred_cookie: Option<u64>,
    has_callchain: bool,
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
    InlineCurrentIp(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserUnwindSource {
    None,
    Object,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SampleCallchainState {
    KernelWithoutCallchain,
    KernelWithCallchain,
    KernelWithUserFrame,
    Other {
        has_callchain: bool,
        has_frames: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SampleCallchainPresence {
    Present,
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectUnwindInitialFramePolicy {
    DropSyntheticCurrentIp,
    KeepDsoLeaf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitialIpMappingState {
    NoRecordedMapping,
    RecordedMappingLoaded,
    RecordedMappingMissing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReportModuleResult {
    NoDso,
    Reported,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UserUnwindContext {
    sample_callchain: SampleCallchainPresence,
    callchain: SampleCallchainState,
    initial_ip_mapping: InitialIpMappingState,
    initial_ip_is_dso: bool,
    module_count: usize,
    frame_pointer_at_or_above_stack_pointer: bool,
    syscall_return_state: bool,
}

impl FoldFrame {
    fn address(self) -> u64 {
        match self {
            Self::Callchain(address)
            | Self::UserUnwind(address)
            | Self::InlineCurrentIp(address) => address,
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
    event_name_width: usize,
}

#[derive(Clone, Debug)]
struct SampleEventLayout {
    layout: SampleLayout,
    event_name: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FoldOptions {
    pub count_periods: bool,
    /// When set, expand each callchain entry into its DWARF inline frames,
    /// mirroring `perf script --inline`. Off by default: plain `perf script`
    /// prints exactly one line per callchain entry, named from the ELF symtab.
    pub inline: bool,
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
                if let Some(comm) = summary.comms_by_tid.get(&record.ptid).cloned() {
                    summary.comms_by_pid.insert(record.pid, comm.clone());
                    summary.comms_by_tid.insert(record.tid, comm);
                }
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
    render_fold_data::<NoopSymbolResolver>(fold_data, None, options.inline)
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
    render_fold_data(fold_data, Some(&mut symbol_cache), options.inline)
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
    let arch = perf_arch_from_header(parse_header_arch(bytes, &header)?.as_deref());
    let mut accumulator = FoldAccumulator::new(header_build_ids).with_arch(arch);
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
    accumulator.flush_deferred_samples();

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
    let sample_layouts = sample_layouts_from_file(file, header, &header_bytes)?;
    let header_build_ids = header_build_ids_by_filename_from_file(file, header, &header_bytes)?;
    let arch =
        perf_arch_from_header(header_arch_from_file(file, header, &header_bytes)?.as_deref());
    let mut accumulator = FoldAccumulator::new(header_build_ids).with_arch(arch);
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
            accumulator.drain_fold_counts(
                &mut counts,
                symbol_cache.as_deref_mut(),
                options.inline,
            )?;
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
    accumulator.flush_deferred_samples();
    accumulator.drain_fold_counts(&mut counts, symbol_cache, options.inline)?;
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
    let sample_layouts = sample_layouts_from_file(file, header, &header_bytes)?;
    let header_build_ids = header_build_ids_by_filename_from_file(file, header, &header_bytes)?;
    let arch =
        perf_arch_from_header(header_arch_from_file(file, header, &header_bytes)?.as_deref());
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

    let mut sink = PerfScriptSink::new(
        header_build_ids,
        symbol_cache,
        writer,
        sample_layouts.event_name_width,
        options.inline,
        arch,
    );
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

    ordered_records
        .flush_final_with(|record| sink.apply_record(record, &sample_layouts, options))?;
    sink.flush_deferred_samples()
}

struct PerfScriptSink<'io, 'cache, R, W: ?Sized> {
    accumulator: FoldAccumulator,
    symbol_cache: Option<&'io mut SymbolFrameCache<'cache, R>>,
    writer: &'io mut W,
    event_name_width: usize,
    inline: bool,
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
        event_name_width: usize,
        inline: bool,
        arch: PerfArch,
    ) -> Self {
        Self {
            accumulator: FoldAccumulator::new(header_build_ids).with_arch(arch),
            symbol_cache,
            writer,
            event_name_width,
            inline,
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
                let tid = deferred_callchain_tid(&record.sample_id, sample_layouts);
                self.write_deferred_callchain(record.cookie, tid, &record.ips)
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
                    tid: sample.tid,
                    time: sample.time,
                    cpu: sample.cpu,
                    comm: sample.comm,
                    event_name: sample.event_name,
                    count: sample.count,
                    frames: sample.frames,
                    has_callchain: sample.has_callchain,
                });
            return Ok(());
        }
        self.write_sample_event(&sample)
    }

    fn write_deferred_callchain(
        &mut self,
        cookie: u64,
        tid: Option<u32>,
        ips: &[u64],
    ) -> Result<(), String> {
        let Some(samples) = self.accumulator.deferred_samples.remove(&cookie) else {
            return Ok(());
        };
        for mut sample in samples {
            if tid.is_some() && tid != sample.tid {
                continue;
            }
            sample
                .frames
                .extend(ips.iter().copied().map(FoldFrame::Callchain));
            let sample = PreparedFoldSample {
                pid: sample.pid,
                tid: sample.tid,
                time: sample.time,
                cpu: sample.cpu,
                comm: sample.comm,
                event_name: sample.event_name,
                count: sample.count,
                frames: sample.frames,
                deferred_cookie: None,
                has_callchain: sample.has_callchain,
            };
            self.write_sample_event(&sample)?;
        }
        Ok(())
    }

    fn flush_deferred_samples(&mut self) -> Result<(), String> {
        let samples = self.accumulator.take_deferred_samples();
        for sample in samples {
            let sample = PreparedFoldSample {
                pid: sample.pid,
                tid: sample.tid,
                time: sample.time,
                cpu: sample.cpu,
                comm: sample.comm,
                event_name: sample.event_name,
                count: sample.count,
                frames: sample.frames,
                deferred_cookie: None,
                has_callchain: sample.has_callchain,
            };
            self.write_sample_header(&sample)?;
            self.writer
                .write_all(b"\n")
                .map_err(|error| format!("failed to write perf script output: {error}"))?;
        }
        Ok(())
    }

    fn write_sample_event(&mut self, sample: &PreparedFoldSample) -> Result<(), String> {
        if sample.has_callchain {
            self.write_sample_header(sample)?;
            let frame_resolver = FoldFrameResolver::new(&self.accumulator.mmap_table, self.inline);
            frame_resolver.write_script_frames_for_stack(
                sample.pid,
                &sample.frames,
                self.symbol_cache.as_deref_mut(),
                self.writer,
            )?;
        } else {
            self.write_sample_inline_header(sample)?;
            let frame_resolver = FoldFrameResolver::new(&self.accumulator.mmap_table, self.inline);
            frame_resolver.write_inline_sample_frame_for_stack(
                sample.pid,
                &sample.frames,
                self.symbol_cache.as_deref_mut(),
                self.writer,
            )?;
        }
        self.writer
            .write_all(b"\n")
            .map_err(|error| format!("failed to write perf script output: {error}"))
    }

    fn write_sample_header(&mut self, sample: &PreparedFoldSample) -> Result<(), String> {
        let comm = perf_script_comm(sample);
        write!(self.writer, "{comm} ")
            .map_err(|error| format!("failed to write perf script output: {error}"))?;
        if let Some(tid) = sample.tid.or(sample.pid) {
            write!(self.writer, "{tid:>7} ")
                .map_err(|error| format!("failed to write perf script output: {error}"))?;
        }
        if let Some(cpu) = sample.cpu {
            write!(self.writer, "[{cpu:03}] ")
                .map_err(|error| format!("failed to write perf script output: {error}"))?;
        }
        if let Some(time) = sample.time {
            let secs = time / 1_000_000_000;
            let usecs = (time % 1_000_000_000) / 1_000;
            write!(self.writer, "{secs:>5}.{usecs:06}: ")
                .map_err(|error| format!("failed to write perf script output: {error}"))?;
        }
        // builtin-script.c prints `fprintf(fp, "%*s: ", name_width, evname)`
        // (note the trailing space) and then `fputc(cursor ? '\n' : ' ', fp)`.
        // For a resolved callchain (the multi-frame path) cursor is set, so the
        // header line ends with the event-name colon, a space, then a newline.
        writeln!(
            self.writer,
            "{:>10} {:>width$}: ",
            sample.count,
            sample.event_name,
            width = self.event_name_width,
        )
        .map_err(|error| format!("failed to write perf script output: {error}"))
    }

    fn write_sample_inline_header(&mut self, sample: &PreparedFoldSample) -> Result<(), String> {
        let comm = perf_script_comm(sample);
        write!(self.writer, "{comm:>16} ")
            .map_err(|error| format!("failed to write perf script output: {error}"))?;
        if let Some(tid) = sample.tid.or(sample.pid) {
            write!(self.writer, "{tid:>7} ")
                .map_err(|error| format!("failed to write perf script output: {error}"))?;
        }
        if let Some(cpu) = sample.cpu {
            write!(self.writer, "[{cpu:03}] ")
                .map_err(|error| format!("failed to write perf script output: {error}"))?;
        }
        if let Some(time) = sample.time {
            let secs = time / 1_000_000_000;
            let usecs = (time % 1_000_000_000) / 1_000;
            write!(self.writer, "{secs:>5}.{usecs:06}: ")
                .map_err(|error| format!("failed to write perf script output: {error}"))?;
        }
        write!(
            self.writer,
            "{:>10} {:>width$}: ",
            sample.count,
            sample.event_name,
            width = self.event_name_width,
        )
        .map_err(|error| format!("failed to write perf script output: {error}"))
    }
}

fn perf_script_comm(sample: &PreparedFoldSample) -> &str {
    sample.comm.as_deref().unwrap_or_else(|| {
        if sample.tid.or(sample.pid).is_none() {
            ":-1"
        } else {
            "[unknown]"
        }
    })
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

fn sample_layouts_from_file(
    file: &File,
    header: PerfHeader,
    header_bytes: &[u8; 104],
) -> Result<SampleLayouts, String> {
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

    let attr_ids = attrs
        .iter()
        .map(|attr| file_attr_ids_from_file(file, attr))
        .collect::<Result<Vec<_>, _>>()?;
    let event_desc = event_desc_entries_from_file(file, header, header_bytes)?;
    let event_names = build_event_names(&attrs, &attr_ids, &event_desc);
    let event_name_width = event_names
        .iter()
        .map(String::len)
        .max()
        .unwrap_or_default();
    let mut layouts = SampleLayouts {
        fallback: attrs.first().map(|attr| SampleEventLayout {
            layout: layout_from_attr(attr),
            event_name: event_names.first().cloned().unwrap_or_default(),
        }),
        by_identifier: BTreeMap::new(),
        event_name_width,
    };
    for ((attr, event_name), ids) in attrs.iter().zip(event_names).zip(attr_ids) {
        let event = SampleEventLayout {
            layout: layout_from_attr(attr),
            event_name,
        };
        for id in ids {
            layouts.by_identifier.insert(id, event.clone());
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

// HEADER_ARCH feature bit (tools/perf/util/header.h enum HEADER_*).
const HEADER_ARCH_FEATURE: u16 = 6;

/// Maps a HEADER_ARCH string to the unwinder architecture, defaulting to
/// x86_64 when the feature is absent or unrecognized. perf records the
/// recording machine's `uname -m`, so an unknown value (an arch pyroclast does
/// not unwind) falls back to the x86_64 path rather than failing the fold.
fn perf_arch_from_header(arch: Option<&str>) -> PerfArch {
    arch.and_then(PerfArch::from_header_arch)
        .unwrap_or_default()
}

/// Reads the HEADER_ARCH feature string from a perf.data `File`.
///
/// The feature table and payload live after the data section, so this reads
/// them from the file the way `build_id_events_from_file` does, then parses the
/// `perf_header_string` (u32 length + NUL-terminated bytes).
fn header_arch_from_file(
    file: &File,
    header: PerfHeader,
    header_bytes: &[u8; 104],
) -> Result<Option<String>, String> {
    let Some(section) = feature_sections_from_file(file, header, header_bytes)?
        .into_iter()
        .find(|section| section.feature == HEADER_ARCH_FEATURE)
    else {
        return Ok(None);
    };
    let size =
        usize::try_from(section.size).map_err(|_| "arch feature size exceeds usize".to_string())?;
    let payload = read_file_range(file, section.offset, size, "arch feature payload")?;
    let length = usize::try_from(read_u32(&payload, 0)?)
        .map_err(|_| "arch feature string length exceeds usize".to_string())?;
    let string = payload
        .get(4..4 + length)
        .ok_or_else(|| "arch feature string is truncated".to_string())?;
    let end = string
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(string.len());
    std::str::from_utf8(&string[..end])
        .map(|arch| Some(arch.to_string()))
        .map_err(|error| format!("arch feature string is not UTF-8: {error}"))
}

// HEADER_EVENT_DESC feature bit (tools/perf/util/header.h enum HEADER_*).
const HEADER_EVENT_DESC_FEATURE: u16 = 12;

fn event_desc_entries_from_file(
    file: &File,
    header: PerfHeader,
    header_bytes: &[u8; 104],
) -> Result<Vec<EventDescEntry>, String> {
    let Some(section) = feature_sections_from_file(file, header, header_bytes)?
        .into_iter()
        .find(|section| section.feature == HEADER_EVENT_DESC_FEATURE)
    else {
        return Ok(Vec::new());
    };
    let size = usize::try_from(section.size)
        .map_err(|_| "event desc feature size exceeds usize".to_string())?;
    let payload = read_file_range(file, section.offset, size, "event desc feature payload")?;
    Ok(parse_event_desc_entries(&payload))
}

fn event_desc_entries_from_bytes(
    bytes: &[u8],
    header: crate::perfdata::header::PerfHeader,
) -> Vec<EventDescEntry> {
    let Ok(sections) = crate::perfdata::header::parse_feature_sections(bytes, &header) else {
        return Vec::new();
    };
    let Some(section) = sections
        .into_iter()
        .find(|section| section.feature == HEADER_EVENT_DESC_FEATURE)
    else {
        return Vec::new();
    };
    let (Ok(offset), Ok(size)) = (
        usize::try_from(section.offset),
        usize::try_from(section.size),
    ) else {
        return Vec::new();
    };
    bytes
        .get(offset..offset + size)
        .map(parse_event_desc_entries)
        .unwrap_or_default()
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
    // adds_features bitmap begins at byte offset 72 in struct perf_file_header
    // (tools/perf/util/header.h); see set_feature_bits in header.rs.
    let mut features = Vec::new();
    for word_index in 0..4 {
        let word = read_u64(header_bytes, 72 + word_index * 8)?;
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
            arch: PerfArch::default(),
        }
    }

    fn with_arch(mut self, arch: PerfArch) -> Self {
        self.arch = arch;
        self
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
                self.invalidate_pid_unwinder_if_mapping_overlaps_like_perf(
                    record.pid,
                    record.start,
                    record.len,
                );
                self.mmap_table.insert_mmap(record);
                Ok(())
            }
            ParsedRecord::Sample(record) => {
                parse_sample_for_fold(self, record.misc, &record.payload, sample_layouts, options)
            }
            ParsedRecord::CallchainDeferred(record) => {
                let tid = deferred_callchain_tid(&record.sample_id, sample_layouts);
                self.add_deferred_callchain(record.cookie, tid, &record.ips);
                Ok(())
            }
            ParsedRecord::Mmap2(record) => {
                self.invalidate_pid_unwinder_if_mapping_overlaps_like_perf(
                    record.pid,
                    record.start,
                    record.len,
                );
                let build_id = self.header_build_ids.get(&record.path).cloned();
                if let Some(build_id) = build_id {
                    self.mmap_table
                        .insert_mmap2_with_build_id(record, Some(build_id));
                } else {
                    self.mmap_table.insert_mmap2(record);
                }
                Ok(())
            }
            ParsedRecord::Mmap2BuildId(record) => {
                self.invalidate_pid_unwinder_if_mapping_overlaps_like_perf(
                    record.pid,
                    record.start,
                    record.len,
                );
                self.mmap_table.insert_mmap2_build_id(record);
                Ok(())
            }
            ParsedRecord::Fork(record) => {
                self.apply_fork_record(record);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn apply_fork_record(&mut self, record: crate::perfdata::records::ForkRecord) {
        inherit_fork_comm_tables(
            &mut self.process_comms,
            &mut self.exec_process_comms,
            &mut self.thread_comms,
            record,
        );
        self.unwind_states.remove(&record.pid);
        if record.clone_maps {
            self.mmap_table.clone_pid_mappings(record.ppid, record.pid);
        }
    }

    fn into_fold_data(self) -> PerfFoldData {
        PerfFoldData {
            mmap_table: self.mmap_table,
            raw_stacks: self.raw_stacks,
        }
    }

    fn unwind_state_mut(&mut self, pid: u32) -> &mut PidUnwindState {
        let arch = self.arch;
        self.unwind_states
            .entry(pid)
            .or_insert_with(|| PidUnwindState::with_arch(arch))
    }

    fn invalidate_pid_unwinder_if_mapping_overlaps_like_perf(
        &mut self,
        pid: u32,
        start: u64,
        len: u64,
    ) {
        if self
            .mmap_table
            .has_overlapping_user_mapping_for_pid(pid, start, len)
        {
            // perf's map removal path invalidates the per-maps DWFL address
            // space. Its overlap-fix insert path replaces/removes maps inline,
            // so stale modules must not survive into later report_module calls.
            self.unwind_states.remove(&pid);
        }
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
        .clone()
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

fn sample_id_payload_tid(payload: &[u8], layout: SampleLayout) -> Option<u32> {
    if layout.sample_type & PERF_SAMPLE_TID == 0 {
        return None;
    }
    let sample_id_size = sample_id_size(layout);
    if payload.len() < sample_id_size {
        return None;
    }
    read_u32(payload, payload.len() - sample_id_size + 4).ok()
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

fn deferred_callchain_tid(sample_id: &[u8], sample_layouts: &SampleLayouts) -> Option<u32> {
    sample_layouts
        .fallback
        .clone()
        .filter(|event| event.layout.sample_id_all)
        .and_then(|event| sample_id_payload_tid(sample_id, event.layout))
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

fn inherit_fork_comm(
    thread_comms: &mut BTreeMap<u32, String>,
    record: crate::perfdata::records::ForkRecord,
) {
    if let Some(comm) = thread_comms.get(&record.ptid).cloned() {
        thread_comms.insert(record.tid, comm);
    }
}

fn inherit_fork_comm_tables(
    process_comms: &mut BTreeMap<u32, String>,
    exec_process_comms: &mut BTreeMap<u32, String>,
    thread_comms: &mut BTreeMap<u32, String>,
    record: crate::perfdata::records::ForkRecord,
) {
    inherit_fork_comm(thread_comms, record);
    if let Some(comm) = thread_comms.get(&record.tid).cloned() {
        process_comms.insert(record.pid, comm);
    }
    if let Some(comm) = exec_process_comms.get(&record.ppid).cloned() {
        exec_process_comms.insert(record.pid, comm);
    }
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
    fn ensure_unwind_mapping_for_ip(&mut self, pid: Option<u32>, ip: u64) {
        let Some(pid) = pid else {
            return;
        };
        let Some(mapping) = self.mmap_table.user_mapping_for_pid_ip(pid, ip) else {
            return;
        };
        let path = mapping.path.to_string();
        let build_id = mapping.build_id.map(<[u8]>::to_vec);
        let mapping = UserMapping {
            pid: mapping.pid,
            start: mapping.start,
            len: mapping.len,
            pgoff: mapping.pgoff,
            prot: mapping.prot,
            path: &path,
            build_id: build_id.as_deref(),
            file_identity: mapping.file_identity,
        };
        let unwind_debug_dir = self.unwind_debug_dir.clone();
        let unwind_state = self.unwind_state_mut(pid);
        load_unwind_mapping_for_user_mapping_like_perf(
            unwind_state,
            mapping,
            unwind_debug_dir.as_deref(),
        );
    }

    fn add_deferred_callchain(&mut self, cookie: u64, tid: Option<u32>, ips: &[u64]) {
        let Some(samples) = self.deferred_samples.remove(&cookie) else {
            return;
        };
        for mut sample in samples {
            if tid.is_some() && tid != sample.tid {
                continue;
            }
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

    fn flush_deferred_samples(&mut self) {
        self.deferred_samples.clear();
    }

    fn take_deferred_samples(&mut self) -> Vec<DeferredFoldSample> {
        std::mem::take(&mut self.deferred_samples)
            .into_values()
            .flatten()
            .collect()
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
        unwind_state
            .loaded_unwind_modules
            .contains(&unwind_module_key(
                object_path.to_string_lossy().as_ref(),
                mapping.start,
                mapping.pgoff,
            ))
    }

    fn drain_fold_counts<R>(
        &mut self,
        counts: &mut FoldCounts,
        symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
        inline: bool,
    ) -> Result<(), String>
    where
        R: SymbolResolver,
    {
        let raw_stacks = std::mem::take(&mut self.raw_stacks);
        accumulate_fold_counts(&raw_stacks, &self.mmap_table, counts, symbol_cache, inline)
    }
}

fn is_valid_unwound_user_frame(
    _pid: Option<u32>,
    frame: FoldFrame,
    _mmap_table: &MmapTable,
    _mapping_cache: &mut MappingResolveCache,
) -> bool {
    let (FoldFrame::UserUnwind(address) | FoldFrame::InlineCurrentIp(address)) = frame else {
        return true;
    };
    address != 0
}

fn comm_for_ids(thread_comms: &BTreeMap<u32, String>, tid: Option<u32>) -> Option<Cow<'_, str>> {
    let tid = tid?;
    Some(thread_comms.get(&tid).map_or_else(
        || Cow::Owned(format!(":{tid}")),
        |comm| Cow::Borrowed(comm.as_str()),
    ))
}

fn render_fold_data<R>(
    fold_data: PerfFoldData,
    symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
    inline: bool,
) -> Result<String, String>
where
    R: SymbolResolver,
{
    let mut folded = Vec::new();
    write_fold_data(fold_data, symbol_cache, inline, &mut folded)?;
    String::from_utf8(folded).map_err(|error| format!("folded output is not utf-8: {error}"))
}

fn write_fold_data<R, W>(
    fold_data: PerfFoldData,
    symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
    inline: bool,
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
    accumulate_fold_counts(&raw_stacks, &mmap_table, &mut counts, symbol_cache, inline)?;
    write_fold_counts(counts, writer)
}

fn prefetch_symbols<R>(
    raw_stacks: &[RawStackEntryRef<'_, FoldFrame>],
    mmap_table: &MmapTable,
    symbol_cache: &mut SymbolFrameCache<'_, R>,
    inline: bool,
) -> Result<(), String>
where
    R: SymbolResolver,
{
    let mut batches = SymbolPrefetchBatches::new();
    let mut callchain = Vec::new();
    let mut mapping_cache = MappingResolveCache::default();
    for stack in raw_stacks {
        extend_symbol_mappings_for_stack(
            stack.pid(),
            stack.callchain(&mut callchain),
            mmap_table,
            &mut mapping_cache,
            &mut batches,
            inline,
        );
        if batches.full_mappings.len() >= PREFETCH_SYMBOL_REQUEST_BATCH_SIZE {
            symbol_cache.prefetch_mapping_refs(&batches.full_mappings)?;
            batches.full_mappings.clear();
            batches.seen_full.clear();
        }
        if batches.base_mappings.len() >= PREFETCH_SYMBOL_REQUEST_BATCH_SIZE {
            symbol_cache.prefetch_base_mapping_refs(&batches.base_mappings)?;
            batches.base_mappings.clear();
            batches.seen_base.clear();
        }
    }
    if !batches.full_mappings.is_empty() {
        symbol_cache.prefetch_mapping_refs(&batches.full_mappings)?;
    }
    if !batches.base_mappings.is_empty() {
        symbol_cache.prefetch_base_mapping_refs(&batches.base_mappings)?;
    }
    Ok(())
}

fn accumulate_fold_counts<R>(
    raw_stacks: &RawStackAccumulator<FoldFrame>,
    mmap_table: &MmapTable,
    counts: &mut FoldCounts,
    mut symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
    inline: bool,
) -> Result<(), String>
where
    R: SymbolResolver,
{
    let raw_stacks = raw_stacks.sorted_entries();
    counts.reserve_first_drain(raw_stacks.len());
    if let Some(cache) = symbol_cache.as_deref_mut() {
        prefetch_symbols(&raw_stacks, mmap_table, cache, inline)?;
    }
    let frame_resolver = FoldFrameResolver::new(mmap_table, inline);
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
        if !buffers.rendered.is_empty() {
            counts.add_rendered(buffers.rendered.as_str(), stack.count());
        }
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

struct SymbolPrefetchBatches<'a> {
    full_mappings: Vec<ResolvedMappingRef<'a>>,
    base_mappings: Vec<ResolvedMappingRef<'a>>,
    seen_full: HashSet<PrefetchMappingKey, FxBuildHasher>,
    seen_base: HashSet<PrefetchMappingKey, FxBuildHasher>,
}

impl SymbolPrefetchBatches<'_> {
    fn new() -> Self {
        Self {
            full_mappings: Vec::new(),
            base_mappings: Vec::new(),
            seen_full: HashSet::with_hasher(FxBuildHasher),
            seen_base: HashSet::with_hasher(FxBuildHasher),
        }
    }
}

fn extend_symbol_mappings_for_stack<'a>(
    pid: Option<u32>,
    callchain: &[FoldFrame],
    mmap_table: &'a MmapTable,
    mapping_cache: &mut MappingResolveCache,
    batches: &mut SymbolPrefetchBatches<'a>,
    inline: bool,
) {
    for frame in callchain {
        let address = frame.address();
        if let Some(mapping) = pid
            .and_then(|pid| mmap_table.resolve_ref_cached(pid, address, mapping_cache))
            .filter(|mapping| !is_kernel_space_frame(address) || is_kernel_mapping_ref(mapping))
        {
            let key = PrefetchMappingKey {
                symbol_source_id: mapping.symbol_source_id,
                relative_address: mapping.relative_address,
            };
            // Without --inline (the default), every frame is rendered from its
            // single base ELF symtab symbol, so prefetch only the base symbol.
            // With --inline, perf's machine.c unwind_entry() runs
            // append_inlines() on every accepted entry including the leaf, so
            // InlineCurrentIp leaves prefetch the full DWARF inline chain too.
            if !inline {
                if batches.seen_base.insert(key) {
                    batches.base_mappings.push(mapping);
                }
            } else if batches.seen_full.insert(key) {
                batches.full_mappings.push(mapping);
            }
        }
    }
}

struct FoldFrameResolver<'a> {
    mmap_table: &'a MmapTable,
    inline: bool,
}

enum FrameMappingDecision<'a> {
    Mapped(ResolvedMappingRef<'a>),
    KernelAddress,
    Unknown,
    Address,
}

#[derive(Default)]
struct FoldedRenderBuffers {
    rendered: String,
    render_scratch: String,
    label_scratch: String,
    frame_rendered: String,
    raw_function_cache: FoldFrameRenderCache,
    folded_label_cache: FoldFrameRenderCache,
    mapping_cache: MappingResolveCache,
}

struct NoopSymbolResolver;

impl SymbolResolver for NoopSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(vec![None; requests.len()])
    }
}

impl<'a> FoldFrameResolver<'a> {
    fn new(mmap_table: &'a MmapTable, inline: bool) -> Self {
        Self { mmap_table, inline }
    }

    fn mapping_decision(
        &self,
        pid: Option<u32>,
        address: u64,
        mapping_cache: &mut MappingResolveCache,
    ) -> FrameMappingDecision<'a> {
        if let Some(mapping) = pid.and_then(|pid| {
            self.mmap_table
                .resolve_ref_cached(pid, address, mapping_cache)
        }) {
            if is_kernel_space_frame(address) && !is_kernel_mapping_ref(&mapping) {
                FrameMappingDecision::KernelAddress
            } else {
                FrameMappingDecision::Mapped(mapping)
            }
        } else {
            FrameMappingDecision::Unknown
        }
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
                label_scratch,
                frame_rendered,
                folded_label_cache,
                ..
            } = buffers;
            label_scratch.clear();
            for character in comm.chars() {
                label_scratch.push(if character == ' ' { '_' } else { character });
            }
            append_cached_inferno_perf_folded_label(
                rendered,
                frame_rendered,
                folded_label_cache,
                label_scratch.as_str(),
            );
        } else {
            append_cached_inferno_perf_folded_label_to_buffers(buffers, UNKNOWN_FRAME);
        }
        let comm_prefix_len = buffers.rendered.len();

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
            if let FoldFrame::InlineCurrentIp(address) = frame {
                // perf's machine.c unwind_entry() runs append_inlines() on
                // EVERY accepted entry, including the initial sampled IP, so
                // with --inline the leaf expands its inline chain just like a
                // caller frame. Only the no-inline default renders the single
                // base symtab symbol for the leaf.
                if self.inline {
                    self.append_folded_frame_labels(
                        pid,
                        FoldFrame::UserUnwind(address),
                        symbol_cache.as_deref_mut(),
                        buffers,
                    )?;
                } else {
                    self.append_inline_current_ip_folded_frame(
                        pid,
                        address,
                        symbol_cache.as_deref_mut(),
                        buffers,
                    )?;
                }
                continue;
            }
            self.append_folded_frame_labels(pid, frame, symbol_cache.as_deref_mut(), buffers)?;
        }
        if buffers.rendered.len() == comm_prefix_len {
            buffers.rendered.clear();
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
            if let FoldFrame::InlineCurrentIp(address) = frame {
                // perf's machine.c unwind_entry() runs append_inlines() on
                // EVERY accepted entry, including the initial sampled IP, so
                // with --inline the leaf expands its inline chain just like a
                // caller frame. Only the no-inline default renders the single
                // base symtab symbol for the leaf.
                if self.inline {
                    self.write_regular_script_frame(
                        pid,
                        FoldFrame::UserUnwind(address),
                        symbol_cache.as_deref_mut(),
                        &mut mapping_cache,
                        writer,
                    )?;
                } else {
                    self.write_inline_current_ip_script_frames(
                        pid,
                        address,
                        symbol_cache.as_deref_mut(),
                        &mut mapping_cache,
                        writer,
                    )?;
                }
                continue;
            }
            self.write_regular_script_frame(
                pid,
                frame,
                symbol_cache.as_deref_mut(),
                &mut mapping_cache,
                writer,
            )?;
        }
        Ok(())
    }

    fn write_inline_sample_frame_for_stack<R, W>(
        &self,
        pid: Option<u32>,
        callchain: &[FoldFrame],
        symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
        writer: &mut W,
    ) -> Result<(), String>
    where
        R: SymbolResolver,
        W: IoWrite + ?Sized,
    {
        let mut mapping_cache = MappingResolveCache::default();
        let Some(frame) = callchain.first().copied() else {
            return Ok(());
        };
        let address = frame.address();
        match self.mapping_decision(pid, address, &mut mapping_cache) {
            FrameMappingDecision::Mapped(mapping) => {
                write_perf_script_inline_mapped_decision_frame(
                    writer,
                    address,
                    &mapping,
                    symbol_cache,
                )?;
            }
            FrameMappingDecision::KernelAddress | FrameMappingDecision::Address => {
                write_perf_script_address_frame_fragment(writer, "", address)?;
            }
            FrameMappingDecision::Unknown => {
                write_perf_script_unknown_frame_fragment(writer, "", address)?;
            }
        }
        Ok(())
    }

    fn write_regular_script_frame<R, W>(
        &self,
        pid: Option<u32>,
        frame: FoldFrame,
        symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
        mapping_cache: &mut MappingResolveCache,
        writer: &mut W,
    ) -> Result<(), String>
    where
        R: SymbolResolver,
        W: IoWrite + ?Sized,
    {
        let address = frame.address();
        match self.mapping_decision(pid, address, mapping_cache) {
            FrameMappingDecision::Mapped(mapping) => {
                write_perf_script_mapped_decision_frame(
                    writer,
                    address,
                    frame,
                    &mapping,
                    symbol_cache,
                    self.inline,
                )?;
            }
            FrameMappingDecision::KernelAddress | FrameMappingDecision::Address => {
                write_perf_script_address_frame(writer, address)?;
            }
            FrameMappingDecision::Unknown => {
                write_perf_script_unknown_frame(writer, address)?;
            }
        }
        Ok(())
    }

    fn write_inline_current_ip_script_frames<R, W>(
        &self,
        pid: Option<u32>,
        address: u64,
        symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
        mapping_cache: &mut MappingResolveCache,
        writer: &mut W,
    ) -> Result<(), String>
    where
        R: SymbolResolver,
        W: IoWrite + ?Sized,
    {
        if symbol_cache.is_none() {
            self.write_regular_script_frame(
                pid,
                FoldFrame::UserUnwind(address),
                None::<&mut SymbolFrameCache<'_, R>>,
                mapping_cache,
                writer,
            )?;
            return Ok(());
        }
        let Some(cache) = symbol_cache else {
            return Ok(());
        };
        // Resolve the mapping path first so the inline chain can carry the
        // mapped DSO name like every other script frame (map__fprintf_dsoname),
        // rather than the hardcoded "([unknown])".
        let dso_path = pid
            .and_then(|pid| {
                self.mmap_table
                    .resolve_ref_cached(pid, address, mapping_cache)
            })
            .map(|mapping| mapping.path.to_string());
        if let Some(frames) =
            self.resolve_inline_current_ip_frames(pid, address, cache, mapping_cache)?
        {
            for label in frames.iter().rev() {
                match dso_path.as_deref() {
                    Some(path) => {
                        write_perf_script_mapped_symbol_frame(writer, address, label, path)?;
                    }
                    None => write_perf_script_frame_for_label(writer, address, label)?,
                }
            }
        } else {
            self.write_regular_script_frame(
                pid,
                FoldFrame::UserUnwind(address),
                None::<&mut SymbolFrameCache<'_, R>>,
                mapping_cache,
                writer,
            )?;
        }
        Ok(())
    }

    fn append_inline_current_ip_folded_frame<R>(
        &self,
        pid: Option<u32>,
        address: u64,
        symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
        buffers: &mut FoldedRenderBuffers,
    ) -> Result<(), String>
    where
        R: SymbolResolver,
    {
        let Some(cache) = symbol_cache else {
            return self.append_folded_frame_labels(
                pid,
                FoldFrame::UserUnwind(address),
                None::<&mut SymbolFrameCache<'_, R>>,
                buffers,
            );
        };
        if let Some(frames) =
            self.resolve_inline_current_ip_frames(pid, address, cache, &mut buffers.mapping_cache)?
        {
            for label in frames {
                append_cached_inferno_perf_raw_function_to_buffers(buffers, label);
            }
        } else {
            self.append_inline_current_ip_fallback_folded_frame(pid, address, buffers);
        }
        Ok(())
    }

    fn resolve_inline_current_ip_frames<'cache, R>(
        &self,
        pid: Option<u32>,
        address: u64,
        cache: &'cache mut SymbolFrameCache<'_, R>,
        mapping_cache: &mut MappingResolveCache,
    ) -> Result<Option<&'cache [String]>, String>
    where
        R: SymbolResolver,
    {
        let Some(mapping) = pid.and_then(|pid| {
            self.mmap_table
                .resolve_ref_cached(pid, address, mapping_cache)
        }) else {
            return Ok(None);
        };
        let Some(frames) = cache.resolve_mapping_ref_with_base_symbol(&mapping)? else {
            return Ok(None);
        };
        Ok(Some(frames))
    }

    fn append_inline_current_ip_fallback_folded_frame(
        &self,
        pid: Option<u32>,
        address: u64,
        buffers: &mut FoldedRenderBuffers,
    ) {
        match self.mapping_decision(pid, address, &mut buffers.mapping_cache) {
            FrameMappingDecision::Mapped(mapping) => {
                let fallback = symbol_fallback_frame_ref(&mapping);
                append_cached_inferno_perf_folded_label_to_buffers(buffers, &fallback);
            }
            FrameMappingDecision::KernelAddress | FrameMappingDecision::Address => {
                append_folded_address_label(buffers, address);
            }
            FrameMappingDecision::Unknown => {
                append_cached_inferno_perf_folded_label_to_buffers(buffers, UNKNOWN_FRAME);
            }
        }
    }

    fn append_folded_frame_labels<R>(
        &self,
        pid: Option<u32>,
        frame: FoldFrame,
        symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
        buffers: &mut FoldedRenderBuffers,
    ) -> Result<(), String>
    where
        R: SymbolResolver,
    {
        let address = frame.address();
        let symbolizing = symbol_cache.is_some();
        match self.mapping_decision_for_folded_frame(
            pid,
            frame,
            symbolizing,
            &mut buffers.mapping_cache,
        ) {
            FrameMappingDecision::Mapped(mapping) => {
                if let Some(cache) = symbol_cache {
                    let rendered = if self.inline {
                        cache.resolve_folded_mapping_ref(&mapping)?
                    } else {
                        cache.resolve_base_folded_mapping_ref(&mapping)?
                    };
                    if let Some(rendered) = rendered {
                        append_cached_rendered_frame(&mut buffers.rendered, rendered);
                    } else {
                        let fallback = symbol_fallback_frame_ref(&mapping);
                        append_cached_inferno_perf_folded_label_to_buffers(buffers, &fallback);
                    }
                    return Ok(());
                }
                let fallback = symbol_fallback_frame_ref(&mapping);
                append_cached_inferno_perf_folded_label_to_buffers(buffers, &fallback);
            }
            FrameMappingDecision::KernelAddress | FrameMappingDecision::Address => {
                append_folded_address_label(buffers, address);
            }
            FrameMappingDecision::Unknown => {
                append_cached_inferno_perf_folded_label_to_buffers(buffers, UNKNOWN_FRAME);
            }
        }
        Ok(())
    }

    fn mapping_decision_for_folded_frame(
        &self,
        pid: Option<u32>,
        frame: FoldFrame,
        symbolizing: bool,
        mapping_cache: &mut MappingResolveCache,
    ) -> FrameMappingDecision<'a> {
        let address = frame.address();
        let decision = self.mapping_decision(pid, address, mapping_cache);
        if !symbolizing
            && matches!(
                frame,
                FoldFrame::UserUnwind(_) | FoldFrame::InlineCurrentIp(_)
            )
            && matches!(decision, FrameMappingDecision::Unknown)
            && is_kernel_space_frame(address)
        {
            FrameMappingDecision::Address
        } else {
            decision
        }
    }
}

fn append_folded_address_label(buffers: &mut FoldedRenderBuffers, address: u64) {
    buffers.label_scratch.clear();
    write!(buffers.label_scratch, "0x{address:x}").expect("writing to a string cannot fail");
    append_inferno_perf_folded_label(&mut buffers.rendered, &buffers.label_scratch);
}

fn append_cached_inferno_perf_raw_function(
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
    append_inferno_perf_raw_function(frame_rendered, frame, render_scratch);
    append_cached_rendered_frame(rendered, frame_rendered.as_str());
    frame_cache.insert(frame.to_string(), std::mem::take(frame_rendered));
}

fn append_cached_inferno_perf_raw_function_to_buffers(
    buffers: &mut FoldedRenderBuffers,
    frame: &str,
) {
    append_cached_inferno_perf_raw_function(
        &mut buffers.rendered,
        &mut buffers.render_scratch,
        &mut buffers.frame_rendered,
        &mut buffers.raw_function_cache,
        frame,
    );
}

fn append_cached_inferno_perf_folded_label(
    rendered: &mut String,
    frame_rendered: &mut String,
    frame_cache: &mut FoldFrameRenderCache,
    frame: &str,
) {
    if let Some(cached) = frame_cache.get(frame) {
        append_cached_rendered_frame(rendered, cached);
        return;
    }
    frame_rendered.clear();
    append_inferno_perf_folded_label(frame_rendered, frame);
    append_cached_rendered_frame(rendered, frame_rendered.as_str());
    frame_cache.insert(frame.to_string(), std::mem::take(frame_rendered));
}

fn append_cached_inferno_perf_folded_label_to_buffers(
    buffers: &mut FoldedRenderBuffers,
    frame: &str,
) {
    append_cached_inferno_perf_folded_label(
        &mut buffers.rendered,
        &mut buffers.frame_rendered,
        &mut buffers.folded_label_cache,
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
    write_perf_script_frame_for_label_fragment(writer, "\t", address, label)?;
    writer
        .write_all(b"\n")
        .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn write_perf_script_frame_for_label_fragment<W>(
    writer: &mut W,
    prefix: &str,
    address: u64,
    label: &str,
) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    if label == UNKNOWN_FRAME {
        return write_perf_script_unknown_frame_fragment(writer, prefix, address);
    }
    if label.starts_with("0x") {
        return write_perf_script_label_frame_fragment(writer, prefix, address, label);
    }
    if let Some(module) = module_fallback_label_module(label) {
        return write!(writer, "{prefix}{address:16x} {UNKNOWN_FRAME} ({module})")
            .map_err(|error| format!("failed to write perf script output: {error}"));
    }
    if looks_like_mapped_frame_label(label) {
        return write!(
            writer,
            "{prefix}{address:16x} {label}+0x0 ({UNKNOWN_FRAME})"
        )
        .map_err(|error| format!("failed to write perf script output: {error}"));
    }
    write_perf_script_label_frame_fragment(writer, prefix, address, label)
}

fn write_perf_script_mapped_decision_frame<R, W>(
    writer: &mut W,
    address: u64,
    frame: FoldFrame,
    mapping: &ResolvedMappingRef<'_>,
    symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
    inline: bool,
) -> Result<(), String>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    let Some(cache) = symbol_cache else {
        write_perf_script_mapped_unknown_symbol_frame(writer, address, mapping.path)?;
        return Ok(());
    };
    // Default `perf script` prints exactly one line per callchain entry, named
    // from the ELF symtab (builtin-script.c sample__fprintf_sym without
    // --inline). Resolve only the base object symbol and print it with the
    // mapping's full DSO name (map__fprintf_dsoname).
    if !inline {
        return match cache.resolve_mapping_ref_with_base_symbol(mapping)? {
            Some([label, ..]) => {
                write_perf_script_mapped_symbol_frame(writer, address, label, mapping.path)
            }
            _ => write_perf_script_mapped_unknown_symbol_frame(writer, address, mapping.path),
        };
    }
    let frames = cache.resolve_mapping_ref(mapping)?;
    if frames.is_empty() {
        write_perf_script_mapped_unknown_symbol_frame(writer, address, mapping.path)?;
    } else if matches!(frame, FoldFrame::UserUnwind(_))
        && frames.len() == 1
        && !is_kernel_space_frame(address)
    {
        write_perf_script_mapped_symbol_frame(writer, address, &frames[0], mapping.path)?;
    } else {
        for label in frames.iter().rev() {
            write_perf_script_mapped_symbol_frame(writer, address, label, mapping.path)?;
        }
    }
    Ok(())
}

fn write_perf_script_inline_mapped_decision_frame<R, W>(
    writer: &mut W,
    address: u64,
    mapping: &ResolvedMappingRef<'_>,
    symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
) -> Result<(), String>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    if let Some(cache) = symbol_cache {
        let frames = cache.resolve_mapping_ref(mapping)?;
        if let Some(label) = frames.first() {
            return write_perf_script_mapped_symbol_frame_fragment(
                writer,
                "",
                address,
                label,
                mapping.path,
            );
        }
        return write_perf_script_frame_for_label_fragment(
            writer,
            "",
            address,
            &symbol_fallback_frame_ref(mapping),
        );
    }
    write_perf_script_mapped_unknown_symbol_frame_fragment(writer, "", address, mapping.path)
}

fn write_perf_script_unknown_frame<W>(writer: &mut W, address: u64) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    write_perf_script_unknown_frame_fragment(writer, "\t", address)?;
    writer
        .write_all(b"\n")
        .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn write_perf_script_address_frame<W>(writer: &mut W, address: u64) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    write_perf_script_address_frame_fragment(writer, "\t", address)?;
    writer
        .write_all(b"\n")
        .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn write_perf_script_unknown_frame_fragment<W>(
    writer: &mut W,
    prefix: &str,
    address: u64,
) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    write!(
        writer,
        "{prefix}{address:16x} {UNKNOWN_FRAME} ({UNKNOWN_FRAME})"
    )
    .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn write_perf_script_address_frame_fragment<W>(
    writer: &mut W,
    prefix: &str,
    address: u64,
) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    write!(
        writer,
        "{prefix}{address:16x} 0x{address:x} ({UNKNOWN_FRAME})"
    )
    .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn write_perf_script_label_frame_fragment<W>(
    writer: &mut W,
    prefix: &str,
    address: u64,
    label: &str,
) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    write!(writer, "{prefix}{address:16x} {label} ({UNKNOWN_FRAME})")
        .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn write_perf_script_mapped_symbol_frame<W>(
    writer: &mut W,
    address: u64,
    label: &str,
    path: &str,
) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    if label == UNKNOWN_FRAME
        || label.starts_with("0x")
        || module_fallback_label_module(label).is_some()
    {
        return write_perf_script_frame_for_label(writer, address, label);
    }
    write_perf_script_mapped_symbol_frame_fragment(writer, "\t", address, label, path)?;
    writer
        .write_all(b"\n")
        .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn write_perf_script_mapped_symbol_frame_fragment<W>(
    writer: &mut W,
    prefix: &str,
    address: u64,
    label: &str,
    path: &str,
) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    if label == UNKNOWN_FRAME
        || label.starts_with("0x")
        || module_fallback_label_module(label).is_some()
    {
        return write_perf_script_frame_for_label_fragment(writer, prefix, address, label);
    }
    write!(writer, "{prefix}{address:16x} {label} ({path})")
        .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn write_perf_script_mapped_unknown_symbol_frame<W>(
    writer: &mut W,
    address: u64,
    path: &str,
) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    write_perf_script_mapped_unknown_symbol_frame_fragment(writer, "\t", address, path)?;
    writer
        .write_all(b"\n")
        .map_err(|error| format!("failed to write perf script output: {error}"))
}

fn write_perf_script_mapped_unknown_symbol_frame_fragment<W>(
    writer: &mut W,
    prefix: &str,
    address: u64,
    path: &str,
) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    write!(writer, "{prefix}{address:16x} {UNKNOWN_FRAME} ({path})")
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
    let (FoldFrame::UserUnwind(address) | FoldFrame::InlineCurrentIp(address)) = frame else {
        return false;
    };
    pid.is_some_and(|pid| {
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
                tid: sample.tid,
                time: sample.time,
                cpu: sample.cpu,
                comm: sample.comm,
                event_name: sample.event_name,
                count: sample.count,
                frames: sample.frames,
                has_callchain: sample.has_callchain,
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
    append_perf_user_unwind_frames(accumulator, misc, &event, &sample);
    let comm = comm_for_ids(&accumulator.thread_comms, sample.tid);
    Ok(Some(PreparedFoldSample {
        pid: sample.pid,
        tid: sample.tid,
        time: sample.time,
        cpu: sample.cpu,
        comm: comm.map(Cow::into_owned),
        event_name: event.event_name,
        count,
        frames: std::mem::take(&mut accumulator.sample_frames),
        deferred_cookie,
        has_callchain: event.layout.sample_type & PERF_SAMPLE_CALLCHAIN != 0,
    }))
}

fn append_perf_user_unwind_frames(
    accumulator: &mut FoldAccumulator,
    misc: u16,
    event: &SampleEventLayout,
    sample: &crate::perfdata::samples::SampleCallchain<'_>,
) {
    let (Some(regs), Some(stack)) = (&sample.user_regs, &sample.user_stack) else {
        return;
    };
    if !has_perf_captured_user_stack(stack) {
        return;
    }
    let Ok(regs) = PerfUserRegs::from_perf_masked_values(
        accumulator.arch,
        event.layout.sample_regs_user,
        &regs.values,
    ) else {
        return;
    };
    accumulator.ensure_unwind_mapping_for_ip(sample.pid, regs.ip());
    let context = build_user_unwind_context(accumulator, misc, event, sample, &regs);
    let mut unwound_frames = unwind_user_stack_like_perf(accumulator, sample, &regs, context);
    let mut mapping_cache = MappingResolveCache::default();
    truncate_user_unwind_at_first_unmapped_frame(
        sample.pid,
        &mut unwound_frames,
        &accumulator.mmap_table,
        &mut mapping_cache,
    );
    accumulator.sample_frames.extend(unwound_frames);
}

fn build_user_unwind_context(
    accumulator: &FoldAccumulator,
    misc: u16,
    event: &SampleEventLayout,
    sample: &crate::perfdata::samples::SampleCallchain<'_>,
    regs: &PerfUserRegs,
) -> UserUnwindContext {
    let sample_callchain = if event.layout.sample_type & PERF_SAMPLE_CALLCHAIN != 0 {
        SampleCallchainPresence::Present
    } else {
        SampleCallchainPresence::Absent
    };
    UserUnwindContext {
        sample_callchain,
        callchain: sample_callchain_state(
            misc,
            event,
            sample,
            !accumulator.sample_frames.is_empty(),
        ),
        initial_ip_mapping: initial_ip_mapping_state(accumulator, sample.pid, regs.ip()),
        initial_ip_is_dso: object_unwind_initial_frame_policy(
            sample.pid,
            regs.ip(),
            &accumulator.mmap_table,
        ) == ObjectUnwindInitialFramePolicy::KeepDsoLeaf,
        module_count: loaded_unwind_module_count(accumulator, sample.pid),
        // x86_64-specific `ebl_unwind` precondition (false on aarch64, whose
        // backend has its own internal accept condition).
        frame_pointer_at_or_above_stack_pointer: regs.frame_pointer_at_or_above_stack_pointer(),
        syscall_return_state: regs.is_syscall_return_state(),
    }
}

fn initial_ip_mapping_state(
    accumulator: &FoldAccumulator,
    pid: Option<u32>,
    ip: u64,
) -> InitialIpMappingState {
    if !pid.is_some_and(|pid| accumulator.mmap_table.has_mapping_for_pid(pid, ip)) {
        return InitialIpMappingState::NoRecordedMapping;
    }
    if accumulator.has_loaded_unwind_mapping_for_ip(pid, ip) {
        InitialIpMappingState::RecordedMappingLoaded
    } else {
        InitialIpMappingState::RecordedMappingMissing
    }
}

fn loaded_unwind_module_count(accumulator: &FoldAccumulator, pid: Option<u32>) -> usize {
    pid.and_then(|pid| accumulator.unwind_states.get(&pid))
        .map_or(0, |state| state.object_unwinder.module_count())
}

fn sample_callchain_state(
    misc: u16,
    event: &SampleEventLayout,
    sample: &crate::perfdata::samples::SampleCallchain<'_>,
    has_sample_frames: bool,
) -> SampleCallchainState {
    let is_kernel_sample =
        (misc & PERF_RECORD_MISC_CPUMODE_MASK) == PERF_RECORD_MISC_CPUMODE_KERNEL;
    if is_kernel_sample && sample.frames.is_empty() {
        return SampleCallchainState::KernelWithoutCallchain;
    }
    let has_recorded_user_frame = sample.frames.clone().any(is_recorded_user_callchain_frame);
    let has_recorded_kernel_frame = sample
        .frames
        .clone()
        .any(is_recorded_kernel_callchain_frame);
    if has_recorded_kernel_frame && has_recorded_user_frame {
        // perf script keeps a recorded kernel-to-user callchain and does not
        // append extra user DWARF callers after the user-space frame.
        return SampleCallchainState::KernelWithUserFrame;
    }
    if is_kernel_sample {
        SampleCallchainState::KernelWithCallchain
    } else {
        SampleCallchainState::Other {
            has_callchain: event.layout.sample_type & PERF_SAMPLE_CALLCHAIN != 0,
            has_frames: has_sample_frames,
        }
    }
}

fn unwind_user_stack_like_perf(
    accumulator: &mut FoldAccumulator,
    sample: &crate::perfdata::samples::SampleCallchain<'_>,
    regs: &PerfUserRegs,
    context: UserUnwindContext,
) -> Vec<FoldFrame> {
    let Some(stack) = &sample.user_stack else {
        return Vec::new();
    };
    let Some(stack_bytes) = perf_effective_user_stack_bytes(stack) else {
        return Vec::new();
    };
    match choose_user_unwind_source(context) {
        UserUnwindSource::None => Vec::new(),
        UserUnwindSource::Object => {
            unwind_object_stack_like_perf(accumulator, sample.pid, regs, stack_bytes, context)
        }
    }
}

fn unwind_object_stack_like_perf(
    accumulator: &mut FoldAccumulator,
    pid: Option<u32>,
    regs: &PerfUserRegs,
    stack_bytes: &[u8],
    context: UserUnwindContext,
) -> Vec<FoldFrame> {
    let Some(pid_value) = pid else {
        return Vec::new();
    };
    let mut state = accumulator
        .unwind_states
        .remove(&pid_value)
        .unwrap_or_else(|| PidUnwindState::with_arch(accumulator.arch));
    let unwind_debug_dir = accumulator.unwind_debug_dir.clone();
    let frames = unwind_object_frame_addresses_like_perf(
        &mut state,
        pid_value,
        &accumulator.mmap_table,
        unwind_debug_dir.as_deref(),
        regs,
        stack_bytes,
        context,
    );
    accumulator.unwind_states.insert(pid_value, state);
    frames
        .into_iter()
        .enumerate()
        .map(|(index, address)| {
            if index == 0 && address == regs.ip() {
                FoldFrame::InlineCurrentIp(address)
            } else {
                FoldFrame::UserUnwind(address)
            }
        })
        .collect::<Vec<_>>()
}

fn unwind_object_frame_addresses_like_perf(
    state: &mut PidUnwindState,
    pid: u32,
    mmap_table: &MmapTable,
    unwind_debug_dir: Option<&Path>,
    regs: &PerfUserRegs,
    stack_bytes: &[u8],
    context: UserUnwindContext,
) -> Vec<u64> {
    let initial_frame_policy = object_unwind_initial_frame_policy(Some(pid), regs.ip(), mmap_table);
    if report_unwind_module_for_ip_like_perf(state, mmap_table, pid, regs.ip(), unwind_debug_dir)
        == ReportModuleResult::Failed
    {
        return Vec::new();
    }
    let mut object_unwind =
        unwind_user_stack_with_diagnostics(&mut state.object_unwinder, *regs, stack_bytes, 256);
    for _ in 0..MAX_LIBDW_CALLBACK_REPORT_PASSES {
        if !report_unwind_modules_for_frame_callbacks_like_perf(
            state,
            mmap_table,
            pid,
            &object_unwind.accepted_frames,
            unwind_debug_dir,
        ) {
            break;
        }
        let next_unwind =
            unwind_user_stack_with_diagnostics(&mut state.object_unwinder, *regs, stack_bytes, 256);
        if next_unwind == object_unwind {
            break;
        }
        object_unwind = next_unwind;
    }
    let raw_frames = object_unwind.accepted_frames;
    let initial_ip_has_reported_module = initial_ip_mapping_has_reported_unwind_module(
        Some(pid),
        regs.ip(),
        mmap_table,
        &state.object_unwinder,
    );
    let use_libdw_arch_fallback = should_use_libdw_arch_fallback_after_empty_object_unwind(
        context,
        initial_ip_has_reported_module,
    );
    let raw_frames = libdw_arch_fallback_after_empty_object_unwind(
        raw_frames,
        regs,
        stack_bytes,
        use_libdw_arch_fallback,
    );
    let raw_frames = truncate_syscall_return_unwind_after_first_executable_frame(
        raw_frames,
        Some(pid),
        mmap_table,
        context,
    );
    perf_accepted_object_unwind_frames(regs, context.callchain, initial_frame_policy, raw_frames)
}

fn libdw_arch_fallback_after_empty_object_unwind(
    raw_frames: Vec<u64>,
    regs: &PerfUserRegs,
    stack_bytes: &[u8],
    use_libdw_arch_fallback: bool,
) -> Vec<u64> {
    if !use_libdw_arch_fallback {
        return raw_frames;
    }
    match *regs {
        // elfutils' x86_64 backend only walks the rbp chain when the frame
        // pointer is at or above the stack pointer. framehop's own x86_64
        // frame-pointer recovery already advances most stacks, so the elfutils
        // fallback only fills in stacks where framehop produced nothing.
        PerfUserRegs::X86_64(regs) if raw_frames.is_empty() && regs.bp >= regs.sp => {
            unwind_x86_64_frame_pointer_stack_like_elfutils(regs, stack_bytes, 256)
        }
        PerfUserRegs::X86_64(_) => raw_frames,
        // aarch64's backend has no bp/sp precondition: it accepts the lr-based
        // caller unless lr == 0, with its own internal `fp == 0 || fp+16 > sp`
        // accept condition (backends/aarch64_unwind.c). framehop's aarch64
        // unwinder yields only the seed pc when no CFI covers it, which is
        // exactly when libdwfl invokes ebl_unwind on the leaf, so the fallback
        // fires when framehop produced no caller beyond the sampled pc.
        PerfUserRegs::Aarch64(regs) if frames_are_seed_only(&raw_frames, regs.pc) => {
            unwind_aarch64_frame_pointer_stack_like_elfutils(regs, stack_bytes, 256)
        }
        PerfUserRegs::Aarch64(_) => raw_frames,
    }
}

/// Whether framehop produced no caller beyond the sampled pc: either nothing at
/// all, or just the seed instruction pointer.
fn frames_are_seed_only(raw_frames: &[u64], pc: u64) -> bool {
    raw_frames.is_empty() || raw_frames == [pc]
}

fn truncate_syscall_return_unwind_after_first_executable_frame(
    raw_frames: Vec<u64>,
    _pid: Option<u32>,
    _mmap_table: &MmapTable,
    _context: UserUnwindContext,
) -> Vec<u64> {
    raw_frames
}

fn should_use_libdw_arch_fallback_after_empty_object_unwind(
    context: UserUnwindContext,
    _initial_ip_mapping_has_reported_module: bool,
) -> bool {
    context.initial_ip_mapping != InitialIpMappingState::RecordedMappingMissing
}

fn initial_ip_mapping_has_reported_unwind_module(
    pid: Option<u32>,
    ip: u64,
    mmap_table: &MmapTable,
    object_unwinder: &FramehopUnwinder,
) -> bool {
    let mut mapping_cache = MappingResolveCache::default();
    pid.and_then(|pid| mmap_table.resolve_ref_cached(pid, ip, &mut mapping_cache))
        .is_some()
        && object_unwinder.has_reported_module_for_ip(ip)
}

fn report_unwind_modules_for_frame_callbacks_like_perf(
    state: &mut PidUnwindState,
    mmap_table: &MmapTable,
    pid: u32,
    frame_addresses: &[u64],
    unwind_debug_dir: Option<&Path>,
) -> bool {
    let mut loaded = false;
    for address in frame_addresses {
        loaded |= report_unwind_module_for_ip_like_perf(
            state,
            mmap_table,
            pid,
            *address,
            unwind_debug_dir,
        ) == ReportModuleResult::Reported;
    }
    loaded
}

fn report_unwind_module_for_ip_like_perf(
    state: &mut PidUnwindState,
    mmap_table: &MmapTable,
    pid: u32,
    ip: u64,
    unwind_debug_dir: Option<&Path>,
) -> ReportModuleResult {
    let Some(mapping) = mmap_table.user_mapping_for_pid_ip(pid, ip) else {
        return ReportModuleResult::NoDso;
    };
    if state.object_unwinder.has_reported_module_for_ip(ip) {
        return ReportModuleResult::Reported;
    }
    if load_unwind_mapping_for_user_mapping_like_perf(state, mapping, unwind_debug_dir) {
        ReportModuleResult::Reported
    } else {
        ReportModuleResult::Failed
    }
}

fn load_unwind_mapping_for_user_mapping_like_perf(
    state: &mut PidUnwindState,
    mapping: UserMapping<'_>,
    unwind_debug_dir: Option<&Path>,
) -> bool {
    let path = mapping.path.to_string();
    let build_id = mapping.build_id.map(<[u8]>::to_vec);
    let request = UnwindMappingRequest {
        start: mapping.start,
        len: mapping.len,
        pgoff: mapping.pgoff,
        prot: mapping.prot,
        path: &path,
        file_identity: mapping.file_identity,
        build_id: build_id.as_deref(),
    };
    if build_id.is_some() {
        load_build_id_unwind_mapping(
            &mut state.object_unwinder,
            &mut state.attempted_unwind_mappings,
            &mut state.loaded_unwind_modules,
            request,
            unwind_debug_dir,
        )
    } else {
        load_unwind_mapping(
            &mut state.object_unwinder,
            &mut state.attempted_unwind_mappings,
            &mut state.loaded_unwind_modules,
            request,
        )
    }
}

fn unwind_user_stack_with_diagnostics(
    unwinder: &mut impl UserStackUnwinder,
    regs: PerfUserRegs,
    stack_bytes: &[u8],
    max_frames: usize,
) -> UserStackUnwindResult {
    unwinder.unwind_user_stack(regs, stack_bytes, max_frames)
}

fn choose_user_unwind_source(context: UserUnwindContext) -> UserUnwindSource {
    if has_perf_object_unwind(context) {
        UserUnwindSource::Object
    } else {
        UserUnwindSource::None
    }
}

fn has_perf_object_unwind(context: UserUnwindContext) -> bool {
    // tools/perf/builtin-script.c only calls thread__resolve_callchain()
    // behind `symbol_conf.use_callchain && sample->callchain`. libdw's
    // unwind__get_entries() is reached later from that callchain resolver, so
    // captured regs/stack without a PERF_SAMPLE_CALLCHAIN payload must not
    // trigger object unwinding.
    context.sample_callchain == SampleCallchainPresence::Present
}

fn sample_fold_count(period: Option<u64>, options: FoldOptions) -> u64 {
    if options.count_periods {
        period.unwrap_or(1)
    } else {
        1
    }
}

fn is_recorded_user_callchain_frame(frame: u64) -> bool {
    !is_perf_context_marker(frame) && !is_kernel_space_frame(frame)
}

fn is_recorded_kernel_callchain_frame(frame: u64) -> bool {
    !is_perf_context_marker(frame) && is_kernel_space_frame(frame)
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
    _pid: Option<u32>,
    _frames: &mut Vec<FoldFrame>,
    _mmap_table: &MmapTable,
    _mapping_cache: &mut MappingResolveCache,
) {
}

fn perf_accepted_object_unwind_frames(
    regs: &PerfUserRegs,
    callchain: SampleCallchainState,
    initial_frame_policy: ObjectUnwindInitialFramePolicy,
    unwound_frames: Vec<u64>,
) -> Vec<u64> {
    if callchain == SampleCallchainState::KernelWithUserFrame {
        return Vec::new();
    }
    // framehop yields the sampled instruction pointer before trying to advance.
    // perf's libdw path reports the IP to DWFL as initial state, then only
    // prints entries accepted via frame_callback/entry.
    let _ = (regs, callchain, initial_frame_policy);
    unwound_frames
}

fn object_unwind_initial_frame_policy(
    pid: Option<u32>,
    ip: u64,
    mmap_table: &MmapTable,
) -> ObjectUnwindInitialFramePolicy {
    let mut mapping_cache = MappingResolveCache::default();
    if pid
        .and_then(|pid| mmap_table.resolve_ref_cached(pid, ip, &mut mapping_cache))
        .is_some_and(|mapping| is_shared_object_mapping_path(mapping.path))
    {
        ObjectUnwindInitialFramePolicy::KeepDsoLeaf
    } else {
        ObjectUnwindInitialFramePolicy::DropSyntheticCurrentIp
    }
}

fn is_shared_object_mapping_path(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|file_name| file_name.contains(".so") || has_dylib_extension(file_name))
}

fn has_dylib_extension(file_name: &str) -> bool {
    Path::new(file_name)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dylib"))
}

fn load_unwind_mapping(
    object_unwinder: &mut FramehopUnwinder,
    attempted_unwind_mappings: &mut BTreeSet<UnwindMappingKey>,
    loaded_unwind_modules: &mut BTreeSet<UnwindModuleKey>,
    request: UnwindMappingRequest<'_>,
) -> bool {
    if !should_load_unwind_object(request.path, request.file_identity) {
        return false;
    }
    if request.prot.is_some_and(|prot| prot & PROT_EXEC == 0) {
        return false;
    }
    let key = unwind_mapping_key(request.path, request.start, request.len, request.pgoff);
    if !attempted_unwind_mappings.insert(key.clone()) {
        return false;
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
        loaded_unwind_modules.insert(unwind_module_key(
            request.path,
            request.start,
            request.pgoff,
        ))
    } else {
        false
    }
}

fn load_build_id_unwind_mapping(
    object_unwinder: &mut FramehopUnwinder,
    attempted_unwind_mappings: &mut BTreeSet<UnwindMappingKey>,
    loaded_unwind_modules: &mut BTreeSet<UnwindModuleKey>,
    request: UnwindMappingRequest<'_>,
    debug_dir: Option<&Path>,
) -> bool {
    let Some(build_id) = request.build_id else {
        return false;
    };
    let object_path = unwind_object_path_for_build_id(request.path, build_id, debug_dir);
    if object_path.to_string_lossy().starts_with('[') {
        return false;
    }
    let object_path = object_path.to_string_lossy();
    let key = unwind_mapping_key(
        object_path.as_ref(),
        request.start,
        request.len,
        request.pgoff,
    );
    if !attempted_unwind_mappings.insert(key.clone()) {
        return false;
    }
    if object_unwinder
        .add_object_mapping(
            Path::new(object_path.as_ref()),
            request.start,
            request.len,
            request.pgoff,
        )
        .is_ok_and(|loaded| loaded || object_unwinder.has_reported_module_for_ip(request.start))
    {
        loaded_unwind_modules.insert(unwind_module_key(
            object_path.as_ref(),
            request.start,
            request.pgoff,
        ))
    } else {
        false
    }
}

fn unwind_mapping_key(path: &str, start: u64, len: u64, pgoff: u64) -> UnwindMappingKey {
    (path.to_string(), start, len, pgoff)
}

fn unwind_module_key(path: &str, start: u64, pgoff: u64) -> UnwindModuleKey {
    (path.to_string(), start.saturating_sub(pgoff))
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
    let attr_ids = attrs
        .iter()
        .map(|attr| parse_file_attr_ids(bytes, attr))
        .collect::<Result<Vec<_>, _>>()?;
    let event_desc = event_desc_entries_from_bytes(bytes, header);
    let event_names = build_event_names(&attrs, &attr_ids, &event_desc);
    let event_name_width = event_names
        .iter()
        .map(String::len)
        .max()
        .unwrap_or_default();
    let mut layouts = SampleLayouts {
        fallback: attrs.first().map(|attr| SampleEventLayout {
            layout: layout_from_attr(attr),
            event_name: event_names.first().cloned().unwrap_or_default(),
        }),
        by_identifier: BTreeMap::new(),
        event_name_width,
    };
    for ((attr, event_name), ids) in attrs.iter().zip(event_names).zip(attr_ids) {
        let event = SampleEventLayout {
            layout: layout_from_attr(attr),
            event_name,
        };
        for id in ids {
            layouts.by_identifier.insert(id, event.clone());
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

fn perf_event_name(attr: &PerfFileAttr) -> String {
    const PERF_TYPE_HARDWARE: u32 = 0;
    const PERF_TYPE_SOFTWARE: u32 = 1;
    const PERF_TYPE_TRACEPOINT: u32 = 2;
    const PERF_TYPE_HW_CACHE: u32 = 3;
    const PERF_TYPE_RAW: u32 = 4;
    const PERF_TYPE_BREAKPOINT: u32 = 5;

    match attr.event_type {
        PERF_TYPE_HARDWARE => hardware_event_name(attr.config).to_string(),
        PERF_TYPE_SOFTWARE => software_event_name(attr.config).to_string(),
        PERF_TYPE_TRACEPOINT => "unknown tracepoint".to_string(),
        PERF_TYPE_HW_CACHE => "invalid-cache".to_string(),
        PERF_TYPE_RAW => format!("raw 0x{:x}", attr.config),
        PERF_TYPE_BREAKPOINT => "breakpoint".to_string(),
        _ => format!("unknown attr type: {}", attr.event_type),
    }
}

/// A single event description parsed from the `HEADER_EVENT_DESC` feature.
#[derive(Clone, Debug, Eq, PartialEq)]
struct EventDescEntry {
    name: String,
    ids: Vec<u64>,
}

/// Parses the `HEADER_EVENT_DESC` feature payload.
///
/// `perf record` writes evsel names verbatim into this feature (see
/// `write_event_desc`/`read_event_desc` in `tools/perf/util/header.c`), and
/// `perf script` prints those names instead of reconstructing them from the
/// attr type/config. The layout is: `nre` (u32, number of events), `attr_sz`
/// (u32, sizeof perf_event_attr), then for each event: `attr_sz` attr bytes, a
/// `nr` (u32) id count, a length-prefixed name string, and `nr` u64 ids.
///
/// The name string is written by `do_write_string`: a u32 length
/// (`PERF_ALIGN(strlen + 1, NAME_ALIGN)`) followed by that many bytes holding
/// the NUL-terminated name plus zero padding. We read the declared number of
/// bytes and take the text up to the first NUL.
fn parse_event_desc_entries(payload: &[u8]) -> Vec<EventDescEntry> {
    parse_event_desc_entries_checked(payload).unwrap_or_default()
}

fn parse_event_desc_entries_checked(payload: &[u8]) -> Result<Vec<EventDescEntry>, String> {
    let event_count = read_u32(payload, 0)?;
    let attr_size = usize::try_from(read_u32(payload, 4)?)
        .map_err(|_| "event desc attr size exceeds usize".to_string())?;
    let mut offset = 8usize;
    let mut entries = Vec::with_capacity(event_count as usize);
    for _ in 0..event_count {
        offset = offset
            .checked_add(attr_size)
            .ok_or_else(|| "event desc attr offset overflow".to_string())?;
        let id_count = usize::try_from(read_u32(payload, offset)?)
            .map_err(|_| "event desc id count exceeds usize".to_string())?;
        offset += 4;
        let name_len = usize::try_from(read_u32(payload, offset)?)
            .map_err(|_| "event desc name length exceeds usize".to_string())?;
        offset += 4;
        let name_bytes = payload
            .get(offset..offset + name_len)
            .ok_or_else(|| "event desc name truncated".to_string())?;
        let name = event_desc_name_from_bytes(name_bytes);
        offset += name_len;
        let mut ids = Vec::with_capacity(id_count);
        for _ in 0..id_count {
            ids.push(read_u64(payload, offset)?);
            offset += 8;
        }
        entries.push(EventDescEntry { name, ids });
    }
    Ok(entries)
}

fn event_desc_name_from_bytes(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Builds the per-attr event names `perf script` would print.
///
/// Prefers the verbatim evsel names from `HEADER_EVENT_DESC`, matched to each
/// attr by shared sample id (and by event index as a fallback, which is how
/// `process_event_desc` in `tools/perf/util/header.c` pairs descriptions with
/// evsels). Falls back to reconstructing the name from the attr type/config
/// when no description matches.
fn build_event_names(
    attrs: &[PerfFileAttr],
    attr_ids: &[Vec<u64>],
    event_desc: &[EventDescEntry],
) -> Vec<String> {
    attrs
        .iter()
        .enumerate()
        .map(|(index, attr)| {
            event_desc_name_for_attr(index, attr_ids.get(index), event_desc)
                .unwrap_or_else(|| perf_event_name(attr))
        })
        .collect()
}

fn event_desc_name_for_attr(
    index: usize,
    attr_ids: Option<&Vec<u64>>,
    event_desc: &[EventDescEntry],
) -> Option<String> {
    if event_desc.is_empty() {
        return None;
    }
    if let Some(ids) = attr_ids.filter(|ids| !ids.is_empty())
        && let Some(entry) = event_desc
            .iter()
            .find(|entry| entry.ids.iter().any(|id| ids.contains(id)))
    {
        return Some(entry.name.clone());
    }
    event_desc.get(index).map(|entry| entry.name.clone())
}

fn hardware_event_name(config: u64) -> &'static str {
    match config & 0xffff_ffff {
        0 => "cycles",
        1 => "instructions",
        2 => "cache-references",
        3 => "cache-misses",
        4 => "branches",
        5 => "branch-misses",
        6 => "bus-cycles",
        7 => "stalled-cycles-frontend",
        8 => "stalled-cycles-backend",
        9 => "ref-cycles",
        _ => "unknown-hardware",
    }
}

fn software_event_name(config: u64) -> &'static str {
    match config {
        0 => "cpu-clock",
        1 => "task-clock",
        2 => "page-faults",
        3 => "context-switches",
        4 => "cpu-migrations",
        5 => "minor-faults",
        6 => "major-faults",
        7 => "alignment-faults",
        8 => "emulation-faults",
        9 => "dummy",
        _ => "unknown-software",
    }
}

impl SampleLayouts {
    fn layout_for_payload(&self, payload: &[u8]) -> Result<Option<SampleEventLayout>, String> {
        if self.by_identifier.is_empty() {
            return Ok(self.fallback.clone());
        }
        let Some(fallback) = self.fallback.clone() else {
            return Ok(None);
        };
        if let Some(identifier) = sample_event_id(payload, fallback.layout)? {
            return Ok(self
                .by_identifier
                .get(&identifier)
                .cloned()
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
    use std::cell::RefCell;

    use crate::perfdata::mappings::FileIdentity;
    use crate::perfdata::unwind::{
        PerfArch, PerfUserRegs, PerfX86_64Regs, UserStackUnwindResult, UserStackUnwinder,
    };
    use crate::symbols::{ResolvedSymbolFrames, SymbolFrameCache, SymbolRequest, SymbolResolver};

    // tools/perf/util/header.c write_event_desc: nre(u32), attr_sz(u32), then
    // per event attr_sz attr bytes, nr(u32), do_write_string(name), nr u64 ids.
    fn event_desc_payload(events: &[(&str, &[u64])], attr_sz: usize) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend((events.len() as u32).to_le_bytes());
        payload.extend((attr_sz as u32).to_le_bytes());
        for (name, ids) in events {
            payload.extend(std::iter::repeat_n(0_u8, attr_sz));
            payload.extend((ids.len() as u32).to_le_bytes());
            // do_write_string: u32 len = PERF_ALIGN(strlen+1, NAME_ALIGN=64),
            // then len bytes of NUL-terminated name plus zero padding.
            let aligned = (name.len() + 1).div_ceil(64) * 64;
            payload.extend((aligned as u32).to_le_bytes());
            let mut name_bytes = name.as_bytes().to_vec();
            name_bytes.resize(aligned, 0);
            payload.extend(name_bytes);
            for id in *ids {
                payload.extend(id.to_le_bytes());
            }
        }
        payload
    }

    #[test]
    fn parses_event_desc_names_verbatim_like_perf_read_event_desc() {
        // perf script prints the evsel names recorded in HEADER_EVENT_DESC
        // (e.g. "task-clock:ppp") rather than reconstructing them; the trailing
        // colon perf script appends is a separator, not part of the name.
        let payload = event_desc_payload(&[("task-clock:ppp", &[230, 231, 242])], 136);
        let entries = super::parse_event_desc_entries(&payload);
        assert_eq!(
            entries,
            vec![super::EventDescEntry {
                name: "task-clock:ppp".to_string(),
                ids: vec![230, 231, 242],
            }]
        );
    }

    #[test]
    fn event_desc_name_matches_attr_by_shared_id() {
        let entries = vec![
            super::EventDescEntry {
                name: "cycles:ppp".to_string(),
                ids: vec![10, 11],
            },
            super::EventDescEntry {
                name: "task-clock:ppp".to_string(),
                ids: vec![20, 21],
            },
        ];
        assert_eq!(
            super::event_desc_name_for_attr(0, Some(&vec![21]), &entries),
            Some("task-clock:ppp".to_string())
        );
    }

    #[test]
    fn event_desc_name_falls_back_to_event_index_without_ids() {
        let entries = vec![super::EventDescEntry {
            name: "task-clock:ppp".to_string(),
            ids: Vec::new(),
        }];
        assert_eq!(
            super::event_desc_name_for_attr(0, None, &entries),
            Some("task-clock:ppp".to_string())
        );
    }

    #[derive(Default)]
    struct FakeUserStackUnwinder {
        calls: usize,
        result: UserStackUnwindResult,
    }

    impl UserStackUnwinder for FakeUserStackUnwinder {
        fn unwind_user_stack(
            &mut self,
            _regs: PerfUserRegs,
            _stack: &[u8],
            _max_frames: usize,
        ) -> UserStackUnwindResult {
            self.calls += 1;
            self.result.clone()
        }
    }

    struct StaticFrameResolver {
        frames: Vec<String>,
        has_base_symbol: bool,
    }

    impl SymbolResolver for StaticFrameResolver {
        fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
            Ok(vec![None; requests.len()])
        }

        fn resolve_frame_batch(
            &self,
            requests: &[SymbolRequest],
        ) -> Result<Vec<Vec<String>>, String> {
            Ok(vec![self.frames.clone(); requests.len()])
        }

        fn resolve_frame_batch_with_metadata(
            &self,
            requests: &[SymbolRequest],
        ) -> Result<Vec<ResolvedSymbolFrames>, String> {
            Ok(vec![
                ResolvedSymbolFrames {
                    frames: self.frames.clone(),
                    has_base_symbol: self.has_base_symbol,
                };
                requests.len()
            ])
        }
    }

    fn insert_test_mapping(
        mmap_table: &mut super::MmapTable,
        pid: u32,
        start: u64,
        len: u64,
        path: &str,
    ) {
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid,
            tid: pid,
            start,
            len,
            pgoff: 0,
            path: path.to_string(),
        });
    }

    #[derive(Default)]
    struct RecordingFrameResolver {
        full_requests: RefCell<Vec<u64>>,
        base_requests: RefCell<Vec<u64>>,
    }

    impl RecordingFrameResolver {
        fn resolved_for(requests: &[SymbolRequest]) -> Vec<ResolvedSymbolFrames> {
            requests
                .iter()
                .map(|request| ResolvedSymbolFrames {
                    frames: vec![format!("symbol_{:x}", request.relative_address)],
                    has_base_symbol: true,
                })
                .collect()
        }
    }

    impl SymbolResolver for RecordingFrameResolver {
        fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
            Ok(vec![None; requests.len()])
        }

        fn resolve_frame_batch_with_metadata(
            &self,
            requests: &[SymbolRequest],
        ) -> Result<Vec<ResolvedSymbolFrames>, String> {
            self.full_requests
                .borrow_mut()
                .extend(requests.iter().map(|request| request.relative_address));
            Ok(Self::resolved_for(requests))
        }

        fn resolve_base_frame_batch_with_metadata(
            &self,
            requests: &[SymbolRequest],
        ) -> Result<Vec<ResolvedSymbolFrames>, String> {
            self.base_requests
                .borrow_mut()
                .extend(requests.iter().map(|request| request.relative_address));
            Ok(Self::resolved_for(requests))
        }
    }

    fn test_x86_regs(ip: u64) -> PerfX86_64Regs {
        PerfX86_64Regs {
            ip,
            sp: 0x2000,
            bp: 0x3000,
            registers: [0; 16],
        }
    }

    fn test_regs(ip: u64) -> PerfUserRegs {
        PerfUserRegs::X86_64(test_x86_regs(ip))
    }

    #[test]
    fn object_unwind_diagnostics_use_pluggable_user_stack_unwinder() {
        let mut unwinder = FakeUserStackUnwinder {
            result: UserStackUnwindResult {
                accepted_frames: vec![0x1111, 0x2222],
                framehop_frame_count: 2,
            },
            ..FakeUserStackUnwinder::default()
        };

        let result = super::unwind_user_stack_with_diagnostics(
            &mut unwinder,
            test_regs(0x1111),
            &[0; 16],
            8,
        );

        assert_eq!(unwinder.calls, 1);
        assert_eq!(result.accepted_frames, vec![0x1111, 0x2222]);
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
    fn fork_clone_copies_maps_without_preloading_unwind_modules_like_perf() {
        let current_exe = std::env::current_exe().expect("current exe");
        let current_exe = current_exe.to_string_lossy().into_owned();
        let mut accumulator = super::FoldAccumulator::new(std::collections::BTreeMap::default());
        let sample_layouts = super::SampleLayouts::default();
        accumulator
            .apply_record(
                crate::perfdata::records::ParsedRecord::Mmap(
                    crate::perfdata::records::MmapRecord {
                        pid: 11,
                        tid: 11,
                        start: 0,
                        len: 0x1000_0000,
                        pgoff: 0,
                        path: current_exe,
                    },
                ),
                &sample_layouts,
                super::FoldOptions::default(),
            )
            .expect("parent mmap");

        accumulator
            .apply_record(
                crate::perfdata::records::ParsedRecord::Fork(
                    crate::perfdata::records::ForkRecord {
                        pid: 22,
                        ppid: 11,
                        tid: 22,
                        ptid: 11,
                        time: 99,
                        clone_maps: true,
                    },
                ),
                &sample_layouts,
                super::FoldOptions::default(),
            )
            .expect("fork");

        assert!(
            accumulator
                .mmap_table
                .user_mapping_for_pid_ip(22, 0)
                .is_some(),
            "perf copies address maps for forked children"
        );
        assert!(
            accumulator.unwind_states.get(&22).is_none(),
            "perf libdw reports modules lazily from sampled/callback PCs"
        );
    }

    #[test]
    fn object_unwind_keeps_single_current_ip_callback_like_perf_libdw() {
        // dwfl_thread_getframes() calls perf's frame_callback() for the initial
        // frame before attempting to unwind callers. If entry() accepted that
        // current IP, perf keeps it.
        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &test_regs(0x1000),
                super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: false,
                },
                super::ObjectUnwindInitialFramePolicy::DropSyntheticCurrentIp,
                vec![0x1000],
            ),
            vec![0x1000]
        );
    }

    #[test]
    fn object_unwind_keeps_short_fallback_stack_without_callchain_like_perf_libdw() {
        // tools/perf/util/unwind-libdw.c does not filter accepted callbacks
        // based on whether PERF_SAMPLE_CALLCHAIN contributed recorded frames.
        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &test_regs(0x1000),
                super::SampleCallchainState::Other {
                    has_callchain: false,
                    has_frames: false,
                },
                super::ObjectUnwindInitialFramePolicy::DropSyntheticCurrentIp,
                vec![0x1000, 0x1100],
            ),
            vec![0x1000, 0x1100]
        );
    }

    #[test]
    fn object_unwind_acceptance_does_not_invent_sample_ip_for_empty_libdw_callbacks() {
        // tools/perf/util/unwind-libdw.c only appends frames accepted by
        // frame_callback -> entry after dwfl_getthread_frames runs. A captured
        // stack with no accepted callbacks stays empty.
        let mut regs = test_x86_regs(0x5555_556f_bbbb);
        regs.sp = 0x7fff_ffff_7790;
        regs.bp = 0x76c8;
        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &PerfUserRegs::X86_64(regs),
                super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: false,
                },
                super::ObjectUnwindInitialFramePolicy::DropSyntheticCurrentIp,
                Vec::new(),
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
    fn inline_current_ip_without_base_symbol_renders_module_fallback_like_perf_unwind_entry() {
        // tools/perf/util/machine.c append_inlines() returns nonzero when
        // ms.sym is missing. unwind_entry() then appends the unresolved
        // map_symbol, which Inferno collapses through the module fallback.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x5555_5567_0000,
            len: 0x10_0000,
            pgoff: 0,
            path: "/bin/pyroclast".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec!["core::num::flt2dec::strategy::dragon::mul_pow10".to_string()],
            has_base_symbol: false,
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();

        super::FoldFrameResolver::new(&mmap_table, false)
            .render_folded_stack_for_stack(
                Some(11),
                Some("pyroclast"),
                &[super::FoldFrame::InlineCurrentIp(0x5555_5567_6876)],
                Some(&mut symbol_cache),
                &mut buffers,
            )
            .expect("render folded stack");

        assert_eq!(buffers.rendered, "pyroclast;[pyroclast]");
    }

    #[test]
    fn inline_current_ip_with_base_symbol_renders_single_frame_like_perf_unwind_entry() {
        // tools/perf/util/machine.c unwind_entry() calls append_inlines(); when
        // no inline chain is appended it still appends the current map_symbol.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x5555_5567_0000,
            len: 0x10_0000,
            pgoff: 0,
            path: "/bin/pyroclast".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec!["core::num::flt2dec::strategy::dragon::format_shortest".to_string()],
            has_base_symbol: true,
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();

        super::FoldFrameResolver::new(&mmap_table, false)
            .render_folded_stack_for_stack(
                Some(11),
                Some("pyroclast"),
                &[super::FoldFrame::InlineCurrentIp(0x5555_5567_a0be)],
                Some(&mut symbol_cache),
                &mut buffers,
            )
            .expect("render folded stack");

        assert_eq!(
            buffers.rendered,
            "pyroclast;core::num::flt2dec::strategy::dragon::format_shortest"
        );
    }

    #[test]
    fn inline_current_ip_without_base_symbol_skips_inline_chain_but_keeps_module_fallback_like_perf()
     {
        // tools/perf/util/machine.c append_inlines() returns before expanding
        // DWARF inline frames when thread__find_symbol() did not populate
        // ms.sym, but unwind_entry() still appends the unresolved map_symbol.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x5555_5570_0000,
            len: 0x10_0000,
            pgoff: 0,
            path: "/bin/pyroclast".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec![
                "index_mut<u8>".to_string(),
                "default_read_exact<std::fs::File>".to_string(),
                "read_file_range".to_string(),
            ],
            has_base_symbol: false,
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();

        super::FoldFrameResolver::new(&mmap_table, false)
            .render_folded_stack_for_stack(
                Some(11),
                Some("pyroclast"),
                &[super::FoldFrame::InlineCurrentIp(0x5555_557a_e068)],
                Some(&mut symbol_cache),
                &mut buffers,
            )
            .expect("render folded stack");

        assert_eq!(buffers.rendered, "pyroclast;[pyroclast]");
    }

    #[test]
    fn inline_current_ip_with_inline_chain_renders_folded_stack_like_perf_libdw() {
        // Real period 4268704 sample from
        // target/profiling-runs/octo-symbolized-fold-final/profile.raw.perf.data:
        // libdw emits the sampled IP only as an inline chain.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x5555_5560_0000,
            len: 0x20_0000,
            pgoff: 0,
            path: "/bin/pyroclast".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec![
                "add<&str>".to_string(),
                "sort8_stable<&str>".to_string(),
                "quicksort<&str>".to_string(),
            ],
            has_base_symbol: true,
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();

        super::FoldFrameResolver::new(&mmap_table, false)
            .render_folded_stack_for_stack(
                Some(11),
                Some("pyroclast"),
                &[super::FoldFrame::InlineCurrentIp(0x5555_556f_bbbb)],
                Some(&mut symbol_cache),
                &mut buffers,
            )
            .expect("render folded stack");

        assert_eq!(
            buffers.rendered,
            "pyroclast;add<&str>;sort8_stable<&str>;quicksort<&str>"
        );
    }

    #[test]
    fn symbolized_user_unwind_script_frame_keeps_mapped_dso_like_perf_script() {
        // tools/perf/util/machine.c add_callchain_ip() resolves every accepted
        // unwound IP through thread__find_cpumode_addr_location(); builtin-script.c
        // then prints the DSO name for that resolved map_symbol.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x1000,
            len: 0x1000,
            pgoff: 0,
            path: "/nix/store/glibc/lib/libc.so.6".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec!["_Fork+0x48".to_string()],
            has_base_symbol: true,
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut written = Vec::new();

        super::FoldFrameResolver::new(&mmap_table, false)
            .write_script_frames_for_stack(
                Some(11),
                &[super::FoldFrame::UserUnwind(0x1048)],
                Some(&mut symbol_cache),
                &mut written,
            )
            .expect("write perf script frames");

        assert_eq!(
            String::from_utf8(written).expect("utf-8"),
            "\t            1048 _Fork+0x48 (/nix/store/glibc/lib/libc.so.6)\n"
        );
    }

    #[test]
    fn inferno_perf_render_cache_keeps_raw_functions_separate_from_folded_labels() {
        let mut buffers = super::FoldedRenderBuffers::default();

        super::append_cached_inferno_perf_folded_label_to_buffers(&mut buffers, "handler+0x2a");
        assert_eq!(buffers.rendered, "handler+0x2a");

        buffers.rendered.clear();
        super::append_cached_inferno_perf_raw_function_to_buffers(&mut buffers, "handler+0x2a");

        assert_eq!(buffers.rendered, "handler");
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
        let mut batches = super::SymbolPrefetchBatches::new();
        let callchain = [
            super::FoldFrame::Callchain(0x1010),
            super::FoldFrame::Callchain(0x1020),
        ];

        // Inline mode routes regular Callchain frames into the full-mapping
        // batch; this test exercises the cross-stack dedup of those keys.
        super::extend_symbol_mappings_for_stack(
            Some(11),
            &callchain,
            &mmap_table,
            &mut mapping_cache,
            &mut batches,
            true,
        );
        super::extend_symbol_mappings_for_stack(
            Some(11),
            &callchain,
            &mmap_table,
            &mut mapping_cache,
            &mut batches,
            true,
        );

        assert_eq!(batches.full_mappings.len(), 2);
        assert_eq!(batches.full_mappings[0].relative_address, 0x10);
        assert_eq!(batches.full_mappings[1].relative_address, 0x20);
        assert!(batches.base_mappings.is_empty());
    }

    #[test]
    fn prefetch_symbols_batches_inline_current_ip_through_full_dwarf_with_inline() {
        // perf's machine.c unwind_entry() runs append_inlines() on EVERY
        // accepted entry, including the initial sampled IP (the InlineCurrentIp
        // leaf), so with --inline the leaf is symbolized through the full DWARF
        // inline chain exactly like a caller frame. Only the no-inline default
        // resolves it from the single base symtab symbol.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x1000,
            len: 0x1000,
            pgoff: 0,
            path: "/bin/demo".to_string(),
        });
        let mut raw_stacks = crate::perfdata::raw_stack::RawStackAccumulator::new();
        raw_stacks.add_vec_with_comm(
            Some(11),
            Some("demo".to_string()),
            vec![
                super::FoldFrame::UserUnwind(0x1010),
                super::FoldFrame::InlineCurrentIp(0x1020),
            ],
            1,
        );
        let entries = raw_stacks.sorted_entries();
        let resolver = RecordingFrameResolver::default();
        let mut symbol_cache = SymbolFrameCache::new(&resolver);

        // With --inline, both the caller (UserUnwind 0x1010) and the leaf
        // (InlineCurrentIp 0x1020) prefetch the full DWARF inline chain.
        super::prefetch_symbols(&entries, &mmap_table, &mut symbol_cache, true)
            .expect("prefetch folded stack symbols");

        assert_eq!(*resolver.full_requests.borrow(), vec![0x10, 0x20]);
        assert!(resolver.base_requests.borrow().is_empty());
    }

    #[test]
    fn keeps_unmapped_middle_user_unwind_frame_like_perf_libdw_entry() {
        // tools/perf/util/unwind-libdw.c entry() calls __report_module() for
        // each callback IP, but __report_module() returns success when
        // thread__find_symbol() finds no DSO. With hide_unresolved disabled,
        // tools/perf/util/machine.c unwind_entry() appends unresolved entries.
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

        assert_eq!(
            frames,
            vec![
                super::FoldFrame::UserUnwind(0x1010),
                super::FoldFrame::UserUnwind(0x6),
                super::FoldFrame::UserUnwind(0x1020),
            ]
        );
    }

    #[test]
    fn keeps_terminal_unmapped_user_unwind_frame_like_perf_libdw_entry() {
        // tools/perf/util/unwind-libdw.c entry() stores frames even when
        // __report_module() leaves entry->ms.map NULL. Later
        // machine.c unwind_entry() only drops unresolved frames when
        // symbol_conf.hide_unresolved is set.
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
    fn user_unwind_source_attempts_recorded_ip_without_loaded_unwind_module_like_perf_libdw() {
        // tools/perf/util/unwind-libdw.c calls report_module(ip) before
        // dwfl_getthread_frames(). A recorded mapping that is not already
        // loaded is not a reason to skip libdw; report_module is the loading
        // operation.
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: true,
                },
                initial_ip_mapping: super::InitialIpMappingState::RecordedMappingMissing,
                initial_ip_is_dso: false,
                module_count: 1,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_uses_libdw_for_captured_stack_without_modules_like_perf() {
        // tools/perf/util/machine.c thread__resolve_callchain_unwind() gates on
        // captured user regs and stack, not on preloaded modules. elfutils
        // libdwfl/frame_unwind.c falls through to ebl_unwind(), whose x86_64
        // backend performs the frame-pointer fallback inside libdw.
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: true,
                },
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                initial_ip_is_dso: false,
                module_count: 0,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: false,
                },
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                initial_ip_is_dso: false,
                module_count: 0,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: true,
                },
                initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
                initial_ip_is_dso: false,
                module_count: 0,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_uses_object_unwinder_with_callchain_field_like_perf_script() {
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: false,
                },
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                initial_ip_is_dso: false,
                module_count: 1,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_uses_object_unwinder_for_nonempty_callchain_after_modules_are_loaded() {
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: true,
                },
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                initial_ip_is_dso: false,
                module_count: 1,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_skips_object_unwinder_without_sample_callchain_like_perf_script() {
        // tools/perf/builtin-script.c only calls thread__resolve_callchain()
        // behind `symbol_conf.use_callchain && sample->callchain`; captured
        // DWARF regs/stack alone do not enter the libdw unwind path.
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Absent,
                callchain: super::SampleCallchainState::Other {
                    has_callchain: false,
                    has_frames: false,
                },
                initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
                initial_ip_is_dso: true,
                module_count: 1,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::None
        );
    }

    #[test]
    fn user_unwind_source_uses_object_unwind_for_kernel_callchain_like_perf_libdw() {
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::KernelWithCallchain,
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                initial_ip_is_dso: false,
                module_count: 1,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_uses_object_unwind_for_syscall_return_like_perf_libdw() {
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::KernelWithCallchain,
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                initial_ip_is_dso: false,
                module_count: 1,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: true,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_uses_object_unwind_for_valid_kernel_bp_like_perf_script() {
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::KernelWithCallchain,
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                initial_ip_is_dso: false,
                module_count: 1,
                frame_pointer_at_or_above_stack_pointer: true,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_uses_object_unwind_for_kernel_sample_without_callchain_like_perf_libdw() {
        // Real period 4745147 sample from target/profiling-runs/octo-latest-fold/profile.raw.perf.data:
        // perf script records a kernel-mode IP but still calls libdw with the
        // captured user regs/stack and emits the user-space memmove leaf.
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::KernelWithoutCallchain,
                initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
                initial_ip_is_dso: true,
                module_count: 1,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_attempts_kernel_sample_without_callchain_from_executable_like_perf_libdw()
    {
        // tools/perf/util/machine.c thread__resolve_callchain_unwind() only
        // requires PERF_SAMPLE_REGS_USER, PERF_SAMPLE_STACK_USER, user regs,
        // and a non-empty user stack. tools/perf/util/unwind-libdw.c then
        // calls report_module(ip). Perf does not pre-skip object unwinding
        // because the captured user IP belongs to the main executable.
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::KernelWithoutCallchain,
                initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
                initial_ip_is_dso: false,
                module_count: 1,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_uses_object_unwind_for_kernel_samples_with_user_frame_like_perf_script() {
        // tools/perf/util/machine.c __thread__resolve_callchain() calls
        // thread__resolve_callchain_sample() and then
        // thread__resolve_callchain_unwind() for ORDER_CALLEE. The unwind
        // path checks captured regs/stack, not whether the recorded callchain
        // already contains a user frame.
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::KernelWithUserFrame,
                initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
                initial_ip_is_dso: false,
                module_count: 1,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn object_unwind_keeps_syscall_return_callers_like_perf_libdw() {
        let regs = PerfX86_64Regs {
            ip: 0x7fff_f7ea_3f4b,
            sp: 0x7fff_ffff_9928,
            bp: 3,
            registers: {
                let mut registers = [0; 16];
                registers[framehop::x86_64::Reg::RCX as usize] = 0x7fff_f7ea_3f4b;
                registers[framehop::x86_64::Reg::R11 as usize] = 0x206;
                registers
            },
        };

        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &PerfUserRegs::X86_64(regs),
                super::SampleCallchainState::KernelWithCallchain,
                super::ObjectUnwindInitialFramePolicy::DropSyntheticCurrentIp,
                vec![0x7fff_f7ea_3f4b, 0x5555_5578_8ba4, 0x5555_5578_8ba5],
            ),
            vec![0x7fff_f7ea_3f4b, 0x5555_5578_8ba4, 0x5555_5578_8ba5]
        );
    }

    #[test]
    fn syscall_return_kernel_unwind_keeps_all_accepted_frames_like_perf_libdw() {
        // perf stops when libdw stops producing callback frames; it does not
        // apply a path-based "shared object then executable" truncation rule
        // after frames have already been accepted by frame_callback -> entry().
        let mut mmap_table = super::MmapTable::default();
        insert_test_mapping(
            &mut mmap_table,
            11,
            0x7fff_f7d8_2000,
            0x0020_b000,
            "/nix/store/glibc/lib/libc.so.6",
        );
        insert_test_mapping(
            &mut mmap_table,
            11,
            0x5555_5555_4000,
            0x0040_0000,
            "/home/mjc/projects/pyroclast/target/profiling/pyroclast",
        );

        let frames = super::truncate_syscall_return_unwind_after_first_executable_frame(
            vec![
                0x7fff_f7e1_c03e,
                0x7fff_f7e1_c083,
                0x7fff_f7e9_9d7d,
                0x5555_557d_c17e,
                0x5555_557f_587a,
                0x5555_5577_6369,
            ],
            Some(11),
            &mmap_table,
            super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::KernelWithCallchain,
                initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
                initial_ip_is_dso: true,
                module_count: 2,
                frame_pointer_at_or_above_stack_pointer: true,
                syscall_return_state: true,
            },
        );

        assert_eq!(
            frames,
            vec![
                0x7fff_f7e1_c03e,
                0x7fff_f7e1_c083,
                0x7fff_f7e9_9d7d,
                0x5555_557d_c17e,
                0x5555_557f_587a,
                0x5555_5577_6369,
            ]
        );
    }

    #[test]
    fn non_syscall_kernel_unwind_keeps_executable_tail() {
        let mut mmap_table = super::MmapTable::default();
        insert_test_mapping(
            &mut mmap_table,
            11,
            0x7fff_f7d8_2000,
            0x0020_b000,
            "/nix/store/glibc/lib/libc.so.6",
        );
        insert_test_mapping(
            &mut mmap_table,
            11,
            0x5555_5555_4000,
            0x0040_0000,
            "/home/mjc/projects/pyroclast/target/profiling/pyroclast",
        );
        let frames = vec![0x7fff_f7e1_c03e, 0x5555_557d_c17e, 0x5555_557f_587a];

        let actual = super::truncate_syscall_return_unwind_after_first_executable_frame(
            frames.clone(),
            Some(11),
            &mmap_table,
            super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::KernelWithCallchain,
                initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
                initial_ip_is_dso: true,
                module_count: 2,
                frame_pointer_at_or_above_stack_pointer: true,
                syscall_return_state: false,
            },
        );

        assert_eq!(actual, frames);
    }

    #[test]
    fn user_unwind_source_attempts_libdw_for_kernel_callchain_without_modules_like_perf_script() {
        // tools/perf/util/machine.c still calls thread__resolve_callchain_unwind()
        // after resolving the recorded callchain. A missing preloaded module is
        // not a skip condition; elfutils may still use its EBL frame-pointer
        // fallback after report_module(ip).
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::KernelWithCallchain,
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                initial_ip_is_dso: false,
                module_count: 0,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_attempts_libdw_for_syscall_return_without_modules_like_perf_script() {
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::KernelWithCallchain,
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                initial_ip_is_dso: false,
                module_count: 0,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: true,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_uses_libdw_ebl_fallback_for_valid_kernel_bp_like_perf_script() {
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::KernelWithCallchain,
                initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                initial_ip_is_dso: false,
                module_count: 0,
                frame_pointer_at_or_above_stack_pointer: true,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn object_unwind_acceptance_keeps_user_mode_executable_frames_like_libdw_entry() {
        // Real period 4633851 sample from target/profiling-runs/octo-latest-fold/profile.raw.perf.data:
        // perf script prints no frames for add_fold_stack in the Pyroclast
        // executable because the full unwind path rejects that synthesized
        // stack before this acceptance step. tools/perf/util/unwind-libdw.c's
        // entry callback does not drop already-accepted executable frames.
        let regs = PerfX86_64Regs {
            ip: 0x5555_5578_c601,
            sp: 0x7fff_ffff_8cf8,
            bp: 0x4002,
            registers: [0; 16],
        };

        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &PerfUserRegs::X86_64(regs),
                super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: false,
                },
                super::ObjectUnwindInitialFramePolicy::DropSyntheticCurrentIp,
                vec![0x5555_5578_c601, 0x5555_5579_6e23],
            ),
            vec![0x5555_5578_c601, 0x5555_5579_6e23]
        );
    }

    #[test]
    fn object_unwind_keeps_single_dso_leaf_with_empty_callchain_like_perf_libdw() {
        // Real period 4754368 sample from target/profiling-runs/octo-latest-fold/profile.raw.perf.data:
        // perf script prints the _int_free_chunk glibc leaf even though the
        // recorded FP callchain itself is empty.
        let regs = PerfX86_64Regs {
            ip: 0x7fff_f7e2_ecb7,
            sp: 0x7fff_ffff_8cf8,
            bp: 0x4002,
            registers: [0; 16],
        };

        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &PerfUserRegs::X86_64(regs),
                super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: false,
                },
                super::ObjectUnwindInitialFramePolicy::KeepDsoLeaf,
                vec![0x7fff_f7e2_ecb7],
            ),
            vec![0x7fff_f7e2_ecb7]
        );
    }

    #[test]
    fn loaded_unwind_module_applies_across_dso_segments_like_perf_dwfl() {
        // perf's tools/perf/util/unwind-libdw.c reports a DSO to DWFL and then
        // asks dwfl_addrmodule(ui->dwfl, ip). A module loaded from one ELF
        // segment must therefore satisfy a later IP resolved through another
        // segment with the same load base.
        let path = "/nix/store/glibc/lib/libc.so.6";
        let mut accumulator = super::FoldAccumulator::new(std::collections::BTreeMap::new());
        accumulator
            .mmap_table
            .insert_mmap(crate::perfdata::records::MmapRecord {
                pid: 11,
                tid: 11,
                start: 0x7fff_f7d8_2000,
                len: 0x0020_b000,
                pgoff: 0,
                path: path.to_string(),
            });
        accumulator
            .mmap_table
            .insert_mmap(crate::perfdata::records::MmapRecord {
                pid: 11,
                tid: 11,
                start: 0x7fff_f7da_a000,
                len: 0x0018_1000,
                pgoff: 0x28000,
                path: path.to_string(),
            });
        accumulator
            .unwind_state_mut(11)
            .loaded_unwind_modules
            .insert((path.to_string(), 0x7fff_f7d8_2000));

        assert!(accumulator.has_loaded_unwind_mapping_for_ip(11.into(), 0x7fff_f7e3_2455));
    }

    #[test]
    fn sample_unwind_loads_sampled_ip_module_like_perf_report_module() {
        // perf's tools/perf/util/unwind-libdw.c calls report_module(ip, ui)
        // before dwfl_getthread_frames, so the sampled IP can load its DSO even
        // when no earlier mmap path was loaded into the unwinder.
        let current_exe = std::env::current_exe().expect("current exe");
        let current_exe = current_exe.to_string_lossy().into_owned();
        let mut accumulator = super::FoldAccumulator::new(std::collections::BTreeMap::new());
        accumulator
            .mmap_table
            .insert_mmap(crate::perfdata::records::MmapRecord {
                pid: 11,
                tid: 11,
                start: 0x1000,
                len: 0x1000_0000,
                pgoff: 0,
                path: current_exe,
            });

        accumulator.ensure_unwind_mapping_for_ip(Some(11), 0x2000);

        assert!(accumulator.has_loaded_unwind_mapping_for_ip(Some(11), 0x2000));
    }

    #[test]
    fn fork_exec_removes_existing_child_unwinder_like_perf_thread_replacement() {
        // tools/perf/util/machine.c machine__process_fork_event() removes an
        // existing child thread before creating the new one. For synthesized
        // exec fork events, PERF_RECORD_MISC_FORK_EXEC also disables map
        // cloning, so stale pre-exec DWFL state must not survive.
        let current_exe = std::env::current_exe().expect("current exe");
        let current_exe = current_exe.to_string_lossy().into_owned();
        let mut accumulator = super::FoldAccumulator::new(std::collections::BTreeMap::new());
        accumulator
            .mmap_table
            .insert_mmap(crate::perfdata::records::MmapRecord {
                pid: 11,
                tid: 11,
                start: 0x1000,
                len: 0x1000_0000,
                pgoff: 0,
                path: current_exe.clone(),
            });
        accumulator.ensure_unwind_mapping_for_ip(Some(11), 0x2000);
        assert!(accumulator.unwind_states.contains_key(&11));

        accumulator
            .apply_record(
                crate::perfdata::records::ParsedRecord::Fork(
                    crate::perfdata::records::ForkRecord {
                        pid: 11,
                        tid: 11,
                        ppid: 10,
                        ptid: 10,
                        time: 0,
                        clone_maps: false,
                    },
                ),
                &super::SampleLayouts::default(),
                super::FoldOptions::default(),
            )
            .expect("fork exec");

        assert!(accumulator.unwind_states.get(&11).is_none());
    }

    #[test]
    fn overlapping_mmap_insert_invalidates_stale_unwind_modules_like_perf_dwfl() {
        // tools/perf/util/maps.c invalidates libdw's per-maps DWFL state when
        // map removals happen. Its overlap-fix insert path removes/replaces
        // maps inline, so the broad synthesized MMAP must not leave a stale
        // module that rejects the later executable MMAP2 split.
        let current_exe = std::env::current_exe().expect("current exe");
        let current_exe = current_exe.to_string_lossy().into_owned();
        let mut accumulator = super::FoldAccumulator::new(std::collections::BTreeMap::new());
        accumulator
            .apply_record(
                crate::perfdata::records::ParsedRecord::Mmap(
                    crate::perfdata::records::MmapRecord {
                        pid: 11,
                        tid: 11,
                        start: 0x5555_5555_4000,
                        len: 0x002b_e000,
                        pgoff: 0,
                        path: current_exe.clone(),
                    },
                ),
                &super::SampleLayouts::default(),
                super::FoldOptions::default(),
            )
            .expect("broad mmap");
        accumulator.ensure_unwind_mapping_for_ip(Some(11), 0x5555_5555_5000);
        assert!(accumulator.unwind_states.contains_key(&11));

        accumulator
            .apply_record(
                crate::perfdata::records::ParsedRecord::Mmap2(
                    crate::perfdata::records::Mmap2Record {
                        pid: 11,
                        tid: 11,
                        start: 0x5555_555d_6000,
                        len: 0x0022_b000,
                        pgoff: 0x0008_1000,
                        major: 0,
                        minor: 0,
                        inode: 0,
                        inode_generation: 0,
                        prot: super::PROT_EXEC,
                        flags: 2,
                        path: current_exe,
                    },
                ),
                &super::SampleLayouts::default(),
                super::FoldOptions::default(),
            )
            .expect("exec mmap2");

        assert!(
            accumulator.unwind_states.get(&11).is_none(),
            "overlap fix should invalidate stale DWFL-like module state"
        );
        accumulator.ensure_unwind_mapping_for_ip(Some(11), 0x5555_5567_66de);
        let state = accumulator.unwind_states.get(&11).expect("reloaded state");
        assert!(
            state
                .object_unwinder
                .has_reported_module_for_ip(0x5555_5567_66de),
            "later executable split should load after invalidation"
        );
        assert!(
            !state
                .object_unwinder
                .has_rejected_mapping_for_ip(0x5555_5567_66de),
            "later executable split must not inherit the stale broad-module overlap"
        );
    }

    #[test]
    fn object_unwind_reports_callback_frame_modules_like_perf_libdw() {
        // tools/perf/util/unwind-libdw.c frame_callback() calls report_module(pc)
        // before entry(). A direct framehop pass can reveal a caller address
        // before its module is loaded, so the fold path must lazily report
        // callback-frame modules too.
        let current_exe = std::env::current_exe().expect("current exe");
        let current_exe = current_exe.to_string_lossy().into_owned();
        let mut accumulator = super::FoldAccumulator::new(std::collections::BTreeMap::new());
        accumulator
            .mmap_table
            .insert_mmap(crate::perfdata::records::MmapRecord {
                pid: 11,
                tid: 11,
                start: 0x1000,
                len: 0x1000_0000,
                pgoff: 0,
                path: current_exe.clone(),
            });
        accumulator
            .mmap_table
            .insert_mmap(crate::perfdata::records::MmapRecord {
                pid: 11,
                tid: 11,
                start: 0x2000_0000,
                len: 0x1000_0000,
                pgoff: 0,
                path: current_exe,
            });

        let mut state = super::PidUnwindState::with_arch(PerfArch::X86_64);
        let loaded = super::report_unwind_modules_for_frame_callbacks_like_perf(
            &mut state,
            &accumulator.mmap_table,
            11,
            &[0x1000, 0x2000_1000],
            None,
        );

        assert!(loaded);
        assert!(
            state
                .object_unwinder
                .has_reported_module_for_ip(0x2000_1000)
        );
    }

    #[test]
    fn callback_module_reporting_does_not_probe_next_ip_like_perf_libdw_entry() {
        // tools/perf/util/unwind-libdw.c frame_callback() calls
        // report_module(pc), then decrements non-activation PCs before calling
        // entry(pc). entry() calls __report_module() for that decremented IP.
        // There is no perf/libdw path that turns an unmapped callback IP into a
        // mapped one by probing ip + 1.
        let current_exe = std::env::current_exe().expect("current exe");
        let current_exe = current_exe.to_string_lossy().into_owned();
        let mut accumulator = super::FoldAccumulator::new(std::collections::BTreeMap::new());
        accumulator
            .mmap_table
            .insert_mmap(crate::perfdata::records::MmapRecord {
                pid: 11,
                tid: 11,
                start: 0x1000,
                len: 0x1000_0000,
                pgoff: 0,
                path: current_exe,
            });

        let mut state = super::PidUnwindState::with_arch(PerfArch::X86_64);
        let loaded = super::report_unwind_modules_for_frame_callbacks_like_perf(
            &mut state,
            &accumulator.mmap_table,
            11,
            &[0x0fff],
            None,
        );

        assert!(!loaded);
        assert!(
            !state.object_unwinder.has_reported_module_for_ip(0x1000),
            "ip + 1 probing loads a module that perf/libdw entry would reject"
        );
    }

    #[test]
    fn object_unwind_acceptance_keeps_short_dso_tail_like_libdw_entry() {
        // Real sample from target/profiling-runs/octo-latest-fold/profile.raw.perf.data:
        // perf script prints only __memmove_avx_unaligned_erms for this event,
        // but that decision belongs to the full unwind/truncation path. Once
        // libdw entry has accepted frames, there is no user-mode empty-callchain
        // filter here.
        let regs = PerfX86_64Regs {
            ip: 0x7fff_f7f0_277b,
            sp: 0x7fff_ffff_8cf8,
            bp: 0x4002,
            registers: [0; 16],
        };

        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &PerfUserRegs::X86_64(regs),
                super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: false,
                },
                super::ObjectUnwindInitialFramePolicy::KeepDsoLeaf,
                vec![0x7fff_f7f0_277b, 0x5555_5579_6e23, 0x5555_5579_6e23],
            ),
            vec![0x7fff_f7f0_277b, 0x5555_5579_6e23, 0x5555_5579_6e23]
        );
    }

    #[test]
    fn object_unwind_keeps_user_mode_libdw_tail_for_empty_recorded_callchain() {
        // Real sh period 3559 sample from target/profiling-runs/octo-latest-fold/profile.raw.perf.data:
        // perf/libdw emits _int_malloc followed by bash callers even though the
        // recorded FP callchain has nr:0. tools/perf/util/unwind-libdw.c has no
        // blanket filter for user-mode samples with an empty callchain; it emits
        // each frame accepted by frame_callback -> entry.
        let regs = PerfX86_64Regs {
            ip: 0x7fff_f7e5_7982,
            sp: 0x7fff_ffff_a1e0,
            bp: 0x7fff_ffff_a220,
            registers: [0; 16],
        };

        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &PerfUserRegs::X86_64(regs),
                super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: false,
                },
                super::ObjectUnwindInitialFramePolicy::KeepDsoLeaf,
                vec![
                    0x7fff_f7e5_7982,
                    0x5555_555a_019e,
                    0x5555_5559_21a3,
                    0x5555_5559_6488,
                ],
            ),
            vec![
                0x7fff_f7e5_7982,
                0x5555_555a_019e,
                0x5555_5559_21a3,
                0x5555_5559_6488,
            ]
        );
    }

    #[test]
    fn object_unwind_acceptance_keeps_two_frame_dso_tail_like_libdw_entry() {
        // Real period 5288210 sample from target/profiling-runs/octo-latest-fold/profile.raw.perf.data:
        // perf script prints only __memmove_avx_unaligned_erms even though the
        // sampled BP points above SP; the full unwind path is responsible for
        // rejecting framehop-only tails that libdw did not accept.
        let regs = PerfX86_64Regs {
            ip: 0x7fff_f7f0_277b,
            sp: 0x7fff_ffff_8938,
            bp: 0x7fff_ffff_9650,
            registers: [0; 16],
        };

        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &PerfUserRegs::X86_64(regs),
                super::SampleCallchainState::Other {
                    has_callchain: true,
                    has_frames: false,
                },
                super::ObjectUnwindInitialFramePolicy::KeepDsoLeaf,
                vec![0x7fff_f7f0_277b, 0x5555_556b_ab79],
            ),
            vec![0x7fff_f7f0_277b, 0x5555_556b_ab79]
        );
    }

    #[test]
    fn empty_object_unwind_uses_arch_fallback_like_libdw_ebl_unwind() {
        // elfutils libdwfl/frame_unwind.c tries EH CFI, then DWARF CFI, then
        // falls through to ebl_unwind(). The real period 803991 sample in the
        // octo profile takes this path: framehop returns no object frames, while
        // perf script prints the frame-pointer spine after the kernel stack.
        let regs = PerfX86_64Regs {
            ip: 0x7fff_f7e1_c03e,
            sp: 0x7fff_ffff_9250,
            bp: 0x7fff_ffff_9260,
            registers: {
                let mut registers = [0; 16];
                registers[framehop::x86_64::Reg::RSP as usize] = 0x7fff_ffff_9250;
                registers[framehop::x86_64::Reg::RBP as usize] = 0x7fff_ffff_9260;
                registers
            },
        };
        let mut stack = vec![0; 0x40];
        stack[0x10..0x18].copy_from_slice(&0x7fff_ffff_9270_u64.to_le_bytes());
        stack[0x18..0x20].copy_from_slice(&0x7fff_f7e1_c084_u64.to_le_bytes());
        stack[0x20..0x28].copy_from_slice(&0_u64.to_le_bytes());
        stack[0x28..0x30].copy_from_slice(&0x7fff_f7e9_9d7e_u64.to_le_bytes());

        assert_eq!(
            super::libdw_arch_fallback_after_empty_object_unwind(
                Vec::new(),
                &PerfUserRegs::X86_64(regs),
                &stack,
                true,
            ),
            vec![0x7fff_f7e1_c03e, 0x7fff_f7e1_c083, 0x7fff_f7e9_9d7d]
        );
    }

    #[test]
    fn empty_object_unwind_arch_fallback_does_not_require_reported_mapping_like_elfutils() {
        let regs = PerfX86_64Regs {
            ip: 0x4000,
            sp: 0x8000,
            bp: 0x8000,
            registers: [0; 16],
        };
        let stack = 0x5000_u64.to_le_bytes();

        assert_eq!(
            super::libdw_arch_fallback_after_empty_object_unwind(
                Vec::new(),
                &PerfUserRegs::X86_64(regs),
                &stack,
                false,
            ),
            Vec::<u64>::new()
        );

        let matching_context = super::UserUnwindContext {
            sample_callchain: super::SampleCallchainPresence::Present,
            callchain: super::SampleCallchainState::KernelWithCallchain,
            initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
            initial_ip_is_dso: true,
            module_count: 1,
            frame_pointer_at_or_above_stack_pointer: true,
            syscall_return_state: true,
        };
        assert!(
            super::should_use_libdw_arch_fallback_after_empty_object_unwind(matching_context, true)
        );

        assert!(
            super::should_use_libdw_arch_fallback_after_empty_object_unwind(
                super::UserUnwindContext {
                    initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                    ..matching_context
                },
                false
            )
        );
        assert!(
            super::should_use_libdw_arch_fallback_after_empty_object_unwind(
                super::UserUnwindContext {
                    initial_ip_is_dso: false,
                    ..matching_context
                },
                false
            )
        );
        assert!(
            super::should_use_libdw_arch_fallback_after_empty_object_unwind(
                super::UserUnwindContext {
                    syscall_return_state: false,
                    ..matching_context
                },
                false
            )
        );
        assert!(
            super::should_use_libdw_arch_fallback_after_empty_object_unwind(
                matching_context,
                false
            )
        );
    }

    #[test]
    fn aarch64_arch_fallback_fires_on_seed_only_object_unwind_like_libdw_ebl() {
        // framehop's aarch64 unwinder yields only the seed pc when no CFI
        // covers it; that is exactly when libdwfl invokes ebl_unwind on the
        // leaf (backends/aarch64_unwind.c), so the fp-chain fallback must run
        // even though framehop returned one frame.
        let regs = PerfUserRegs::Aarch64(crate::perfdata::unwind::PerfAarch64Regs {
            pc: 0x4000,
            sp: 0x1000,
            fp: 0x1010,
            lr: 0x5000,
        });
        let stack = vec![0_u8; 0x40];

        assert_eq!(
            super::libdw_arch_fallback_after_empty_object_unwind(vec![0x4000], &regs, &stack, true,),
            // pc, then the lr caller (perf pc-1 adjustment), then stop on the
            // zeroed next lr.
            vec![0x4000, 0x4fff]
        );
    }

    #[test]
    fn aarch64_arch_fallback_keeps_multi_frame_object_unwind() {
        // When framehop already produced callers past the seed (CFI worked),
        // the ebl fallback must not clobber them.
        let regs = PerfUserRegs::Aarch64(crate::perfdata::unwind::PerfAarch64Regs {
            pc: 0x4000,
            sp: 0x1000,
            fp: 0x1010,
            lr: 0x5000,
        });

        assert_eq!(
            super::libdw_arch_fallback_after_empty_object_unwind(
                vec![0x4000, 0x9000],
                &regs,
                &[0_u8; 0x40],
                true,
            ),
            vec![0x4000, 0x9000]
        );
    }

    #[test]
    fn object_unwind_keeps_kernel_without_callchain_dso_tail_like_perf_libdw() {
        // Real period 144 __strlen_avx2 sample from
        // target/profiling-runs/octo-latest-fold/profile.raw.perf.data:
        // perf script records a kernel-mode sampled IP with no recorded
        // callchain, then libdw emits the captured user-space leaf and bash
        // callers. In perf util/unwind-libdw.c, frame_callback reports every
        // accepted frame via entry(); there is no kernel-without-callchain
        // post-filter that truncates to the leaf.
        let regs = PerfX86_64Regs {
            ip: 0x7fff_f7f2_d344,
            sp: 0x7fff_ffff_a1d8,
            bp: 0x7fff_ffff_a220,
            registers: [0; 16],
        };

        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &PerfUserRegs::X86_64(regs),
                super::SampleCallchainState::KernelWithoutCallchain,
                super::ObjectUnwindInitialFramePolicy::KeepDsoLeaf,
                vec![
                    0x7fff_f7f2_d344,
                    0x5555_5559_a556,
                    0x5555_555a_019e,
                    0x5555_5559_21a3,
                    0x5555_5559_6488,
                ],
            ),
            vec![
                0x7fff_f7f2_d344,
                0x5555_5559_a556,
                0x5555_555a_019e,
                0x5555_5559_21a3,
                0x5555_5559_6488,
            ]
        );
    }

    #[test]
    fn sample_fold_count_uses_period_only_when_requested() {
        assert_eq!(
            super::sample_fold_count(
                Some(37),
                super::FoldOptions {
                    count_periods: true,
                    ..super::FoldOptions::default()
                }
            ),
            37
        );
        assert_eq!(
            super::sample_fold_count(
                Some(37),
                super::FoldOptions {
                    count_periods: false,
                    ..super::FoldOptions::default()
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
                    count_periods: true,
                    ..super::FoldOptions::default()
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
