use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;
use smallvec::SmallVec;

use crate::folded::{
    append_escaped_spans, append_inferno_perf_folded_label, append_inferno_perf_raw_function,
    append_separator, escape_frame_into, tidy_inferno_perf_generic_into,
};
use crate::perfdata::attrs::{PerfFileAttr, parse_file_attr_ids, parse_file_attrs};
use crate::perfdata::build_id::{
    BuildIdEvent, build_id_events_from_perfdata, parse_build_id_events,
};
use crate::perfdata::endian::{read_u32, read_u64};
use crate::perfdata::header::{
    PerfFeatureSection, PerfHeader, feature_sections_from_reader, parse_header, parse_header_arch,
};
use crate::perfdata::mappings::{
    FileIdentity, FrameMappingContext, MappedFrame, MappingPathLayout, MappingResolveCache,
    MmapTable, ModuleFallbackKind, ResolvedMappingRef, UserMapping,
};
use crate::perfdata::records::{
    PERF_RECORD_FINISHED_ROUND, PERF_RECORD_MISC_COMM_EXEC, PERF_RECORD_MISC_CPUMODE_KERNEL,
    PERF_RECORD_MISC_CPUMODE_MASK, PERF_RECORD_MISC_CPUMODE_USER, PERF_RECORD_MISC_FORK_EXEC,
    PERF_RECORD_MISC_MMAP_BUILD_ID, ParsedRecord, PerfRecord, iter_records,
    parse_aux_output_hw_id_record, parse_aux_record, parse_bpf_event_record,
    parse_callchain_deferred_record, parse_cgroup_record, parse_comm_record, parse_exit_record,
    parse_fork_record, parse_itrace_start_record, parse_ksymbol_record, parse_lost_record,
    parse_lost_samples_record, parse_mmap_record, parse_mmap2_build_id_record, parse_mmap2_record,
    parse_namespaces_record, parse_read_record, parse_record, parse_switch_cpu_wide_record,
    parse_switch_record, parse_text_poke_record, parse_throttle_record, parse_unthrottle_record,
};
use crate::perfdata::samples::{
    PERF_SAMPLE_ADDR, PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_CPU, PERF_SAMPLE_ID,
    PERF_SAMPLE_IDENTIFIER, PERF_SAMPLE_IP, PERF_SAMPLE_STREAM_ID, PERF_SAMPLE_TID,
    PERF_SAMPLE_TIME, SampleLayout, is_kernel_space_frame, is_perf_context_marker,
    is_perf_user_deferred_context_marker, parse_sample_record_callchain,
};
use crate::perfdata::source::{FileSource, RecordSource, SliceSource};
use crate::perfdata::unwind::{
    FramehopUnwinder, PerfArch, PerfUserRegs, UserStackUnwindResult, UserStackUnwinder,
    unwind_aarch64_frame_pointer_stack_like_elfutils,
    unwind_x86_64_frame_pointer_stack_like_elfutils,
};
use crate::symbols::{
    SymbolFrameCache, SymbolRequest, SymbolResolver, perf_build_id_elf_path_for_dso,
};

const UNKNOWN_FRAME: &str = "[unknown]";
const PROT_EXEC: u32 = 4;
const PERF_CONTEXT_KERNEL: u64 = 0xffff_ffff_ffff_ff80;
const PERF_CONTEXT_USER: u64 = 0xffff_ffff_ffff_fe00;
const PERF_CONTEXT_USER_DEFERRED: u64 = 0xffff_ffff_ffff_fd80;
type FoldFrameStack = SmallVec<[FoldFrame; 16]>;
type LabelId = usize;
#[cfg(test)]
type LabelIds = SmallVec<[LabelId; 4]>;

#[derive(Default)]
struct FoldCounts {
    names: Vec<Arc<str>>,
    by_name: HashMap<Arc<str>, LabelId, FxBuildHasher>,
    stacks: HashMap<Box<[LabelId]>, u64, FxBuildHasher>,
    scratch_stack: Vec<LabelId>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
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

struct SessionState {
    process_comms: BTreeMap<u32, String>,
    exec_process_comms: BTreeMap<u32, String>,
    thread_comms: BTreeMap<u32, String>,
    mmap_table: MmapTable,
    mapping_cache: MappingResolveCache,
    unwind_states: HashMap<u32, PidUnwindState, FxBuildHasher>,
    header_build_ids: BTreeMap<String, Vec<u8>>,
    deferred_samples: Vec<DeferredFoldSample>,
    sample_frames: FoldFrameStack,
    unwind_debug_dir: Option<PathBuf>,
    /// Architecture of the recording machine (`HEADER_ARCH`), used to decode
    /// `REGS_USER` samples and construct per-pid unwinders. Defaults to `x86_64`
    /// when the feature is absent.
    arch: PerfArch,
}

struct PidUnwindState {
    object_unwinder: FramehopUnwinder,
    attempted_unwind_mappings: BTreeSet<UnwindMappingKey>,
    loaded_unwind_modules: BTreeSet<UnwindModuleKey>,
    /// Memo of the ip-intrinsic leaf-only eligibility per sampled IP. Only the
    /// `(pid, ip)`-stable facts are cached here: whether the module covering
    /// `ip` is reported and whether any CFI covers `ip`. The per-sample register
    /// condition (`bp < sp` on `x86_64` / `lr == 0` on aarch64) and the sample's
    /// callchain state are combined fresh at query time, since both vary across
    /// samples at the same IP. The whole `PidUnwindState` (and thus this memo) is
    /// dropped when the pid's mappings change or the pid forks (see
    /// `invalidate_pid_unwinder_if_mapping_overlaps_like_perf` /
    /// `apply_fork_record`), which is exactly when reported-module / CFI facts
    /// could change.
    leaf_only_eligibility: HashMap<u64, LeafOnlyEligibility, FxBuildHasher>,
}

impl PidUnwindState {
    fn with_arch(arch: PerfArch) -> Self {
        Self {
            object_unwinder: FramehopUnwinder::with_arch(arch),
            attempted_unwind_mappings: BTreeSet::new(),
            loaded_unwind_modules: BTreeSet::new(),
            leaf_only_eligibility: HashMap::with_hasher(FxBuildHasher),
        }
    }
}

/// The `(pid, ip)`-stable half of the libdw leaf-only decision.
///
/// `Eligible` means: the module covering the sampled IP is reported into the
/// unwinder AND no CFI (`.eh_frame`/`.debug_frame` FDE) covers the IP. In elfutils
/// `libdwfl/dwfl_frame.c`, `dwfl_thread_getframes()` invokes the frame callback
/// once for the seeded IP before `__libdwfl_frame_unwind()` tries to advance.
/// With no FDE row, advancement depends on the arch `ebl_unwind` fallback; if
/// that fallback also cannot advance, libdwfl stops after the seeded leaf.
/// `Ineligible` means CFI covers the IP, so framehop must run to determine
/// whether there is a caller, or the IP's module is not reported, which perf
/// handles before calling `dwfl_getthread_frames()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeafOnlyEligibility {
    Eligible,
    Ineligible,
}

/// Outcome of classifying a sample's object unwind before running framehop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectUnwindClass {
    /// perf/libdw would emit zero unwound frames.
    SkipUnwind,
    /// perf/libdw fires the initial-frame callback exactly once and stops
    /// after the arch fallback cannot advance: emit the sampled-IP leaf.
    LeafOnly,
    /// Could be 1-or-N frames; framehop must run.
    MustUnwind,
}

type UnwindMappingKey = (String, u64, u64, u64);
type UnwindModuleKey = (String, u64);
const MAX_LIBDW_CALLBACK_REPORT_PASSES: usize = 8;

enum FoldRecord<'a> {
    Comm(crate::perfdata::records::CommRecord),
    Mmap {
        misc: u16,
        record: crate::perfdata::records::MmapRecord,
    },
    Mmap2 {
        misc: u16,
        record: crate::perfdata::records::Mmap2Record,
    },
    Mmap2BuildId {
        misc: u16,
        record: crate::perfdata::records::Mmap2BuildIdRecord,
    },
    Fork(crate::perfdata::records::ForkRecord),
    Sample {
        misc: u16,
        payload: &'a [u8],
    },
    CallchainDeferred(crate::perfdata::records::CallchainDeferredRecord),
    Ignored,
}

#[derive(Clone, Copy)]
struct PendingFoldRecord {
    offset: usize,
    time: u64,
}

#[derive(Default)]
struct OrderedRecordQueue {
    pending_records: Vec<PendingFoldRecord>,
    next_flush_time: Option<u64>,
    max_timestamp: Option<u64>,
}

struct DeferredFoldSample {
    cookie: u64,
    pid: Option<u32>,
    tid: Option<u32>,
    time: Option<u64>,
    cpu: Option<u32>,
    event_name: Arc<str>,
    count: u64,
    frames: FoldFrameStack,
    has_callchain: bool,
}

struct PreparedFoldSample<'layout> {
    pid: Option<u32>,
    tid: Option<u32>,
    time: Option<u64>,
    cpu: Option<u32>,
    event_name: &'layout str,
    count: u64,
    frames: FoldFrameStack,
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
    UserCallchain(u64),
    SampleIp { address: u64, cpumode: u16 },
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
enum InitialIpMappingState {
    NoRecordedMapping,
    RecordedMappingLoaded,
    RecordedMappingMissing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReportModuleResult {
    NoDso,
    /// A module covering this IP was loaded into the unwinder by this call.
    NewlyReported,
    /// A module covering this IP was already present (no new work, no new
    /// unwind information for framehop — used to suppress the PERF-4 redundant
    /// re-unwind in the module-report retry loop).
    AlreadyReported,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UserUnwindContext {
    sample_callchain: SampleCallchainPresence,
    callchain: SampleCallchainState,
    initial_ip_mapping: InitialIpMappingState,
    module_count: usize,
    frame_pointer_at_or_above_stack_pointer: bool,
    syscall_return_state: bool,
}

impl FoldFrame {
    fn address(self) -> u64 {
        match self {
            Self::Callchain(address)
            | Self::UserCallchain(address)
            | Self::SampleIp { address, .. }
            | Self::UserUnwind(address)
            | Self::InlineCurrentIp(address) => address,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct SampleLayouts {
    fallback: Option<Arc<SampleEventLayout>>,
    by_identifier: BTreeMap<u64, Arc<SampleEventLayout>>,
    event_name_width: usize,
}

#[derive(Clone, Debug)]
struct SampleEventLayout {
    layout: SampleLayout,
    event_name: Arc<str>,
    offsets: SampleOffsets,
}

#[derive(Clone, Copy, Debug)]
struct SampleOffsets {
    id: Option<usize>,
    time: Option<usize>,
}

impl SampleOffsets {
    fn new(sample_type: u64) -> Self {
        // tools/perf/util/evsel.c:__perf_evsel__calc_id_pos() and
        // evsel__parse_sample_timestamp() compute these fixed u64 positions.
        let id = if sample_type & PERF_SAMPLE_IDENTIFIER != 0 {
            Some(0)
        } else if sample_type & PERF_SAMPLE_ID != 0 {
            Some(
                (sample_type
                    & (PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR))
                    .count_ones() as usize
                    * 8,
            )
        } else {
            None
        };
        let time = (sample_type & PERF_SAMPLE_TIME != 0).then(|| {
            (sample_type & (PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_IP | PERF_SAMPLE_TID)).count_ones()
                as usize
                * 8
        });
        Self { id, time }
    }
}

impl SampleEventLayout {
    fn new(layout: SampleLayout, event_name: impl Into<Arc<str>>) -> Self {
        Self {
            layout,
            event_name: event_name.into(),
            offsets: SampleOffsets::new(layout.sample_type),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FoldOptions {
    pub count_periods: bool,
    /// Internal renderer switch for tests and specialized callers. The CLI
    /// parity paths keep this on: real `perf script` emits DWARF inline frames
    /// when the recorded stack and debuginfo make them printable, while fp data
    /// with no inline DIEs naturally renders as one frame per callchain entry.
    pub inline: bool,
}

impl PerfSummary {
    #[must_use]
    pub fn record_count(&self, record_type: u32) -> usize {
        self.record_counts.get(&record_type).copied().unwrap_or(0)
    }
}

impl FoldCounts {
    fn intern(&mut self, label: &str) -> LabelId {
        if let Some(&id) = self.by_name.get(label) {
            return id;
        }
        let id = self.names.len();
        let label: Arc<str> = label.into();
        self.names.push(Arc::clone(&label));
        self.by_name.insert(label, id);
        id
    }

    #[cfg(test)]
    fn intern_normalized(&mut self, normalized: &str) -> LabelIds {
        if normalized.is_empty() {
            return LabelIds::new();
        }
        normalized
            .split(';')
            .map(|label| self.intern(label))
            .collect()
    }

    fn add_stack(&mut self, stack: &str, count: u64) {
        self.scratch_stack.clear();
        if !stack.is_empty() {
            // Serialized separators round-trip even when ';' was escaped.
            for label in stack.split(';') {
                let id = self.intern(label);
                self.scratch_stack.push(id);
            }
        }
        add_stack_count(&mut self.stacks, self.scratch_stack.as_slice(), count);
    }

    #[cfg(test)]
    fn add_rendered(&mut self, rendered: &str, count: u64) {
        self.add_stack(rendered, count);
    }

    #[cfg(test)]
    fn frame_text_bytes(&self) -> usize {
        self.names.iter().map(|name| name.len()).sum()
    }

    #[cfg(test)]
    fn count_for_rendered(&mut self, stack: &str) -> Option<u64> {
        let ids = self.intern_normalized(stack);
        self.stacks.get(ids.as_slice()).copied()
    }
}

fn add_stack_count<K, Q, S>(stacks: &mut HashMap<K, u64, S>, key: &Q, count: u64)
where
    K: std::hash::Hash + Eq + std::borrow::Borrow<Q> + for<'a> From<&'a Q>,
    Q: std::hash::Hash + Eq + ?Sized,
    S: std::hash::BuildHasher,
{
    let hash = stacks.hasher().hash_one(key);
    match stacks.raw_entry_mut().from_key_hashed_nocheck(hash, key) {
        hashbrown::hash_map::RawEntryMut::Occupied(entry) => *entry.into_mut() += count,
        hashbrown::hash_map::RawEntryMut::Vacant(entry) => {
            // Borrow<Q> requires owned and borrowed keys to hash and compare
            // identically. Keep full equality checks even when hashes collide.
            entry.insert_hashed_nocheck(hash, K::from(key), count);
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
    let sample_layouts = sample_layouts(bytes, header)?;
    let records = iter_records(bytes, header)?;
    let mut summary = PerfSummary::default();

    for record in records {
        summary.total_records += 1;
        *summary
            .record_counts
            .entry(record.header.record_type)
            .or_insert(0) += 1;
        let parsed_record = parse_record_with_context(record)?;
        let record_result: Result<(), String> = match parsed_record {
            ParsedRecord::Comm(record) => {
                summary
                    .comms_by_pid
                    .insert(record.pid, record.comm.to_string());
                summary
                    .comms_by_tid
                    .insert(record.tid, record.comm.to_string());
                summary.comms.push(record.comm.to_string());
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
            ParsedRecord::Mmap2BuildId { misc, record } => {
                summary.mmaps.push(record.path.clone());
                summary
                    .mmap_table
                    .insert_mmap2_build_id_with_misc(record, misc);
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
    let counts = collect_fold_counts::<NoopSymbolResolver>(bytes, options, None)?;
    let mut output = Vec::new();
    write_fold_counts(counts, &mut output)?;
    String::from_utf8(output).map_err(|error| format!("folded output is not utf-8: {error}"))
}

/// Collapses perf sample callchains from a `perf.data` file path.
///
/// The completed recording must remain unmodified and untruncated during this call.
///
/// # Errors
///
/// Returns an error when the file cannot be opened, mapped, or parsed.
pub fn fold_perfdata_file(path: &Path) -> Result<String, String> {
    fold_perfdata_file_with_options(path, FoldOptions::default())
}

/// Collapses perf sample callchains from a `perf.data` file path.
///
/// The completed recording must remain unmodified and untruncated during this call.
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
    let mut symbol_cache = SymbolFrameCache::new(symbol_resolver);
    let counts = collect_fold_counts(bytes, options, Some(&mut symbol_cache))?;
    let mut output = Vec::new();
    write_fold_counts(counts, &mut output)?;
    String::from_utf8(output).map_err(|error| format!("folded output is not utf-8: {error}"))
}

/// Collapses symbolized perf sample callchains from a `perf.data` file path.
///
/// The completed recording must remain unmodified and untruncated during this call.
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

fn parse_fold_record(record: PerfRecord<'_>) -> Result<FoldRecord<'_>, String> {
    let parsed = match record.header.record_type {
        crate::perfdata::records::PERF_RECORD_MMAP => FoldRecord::Mmap {
            misc: record.header.misc,
            record: parse_mmap_record(record.payload)?,
        },
        crate::perfdata::records::PERF_RECORD_LOST => {
            parse_lost_record(record.payload).map(|_| FoldRecord::Ignored)?
        }
        crate::perfdata::records::PERF_RECORD_COMM => {
            let mut comm = parse_comm_record(record.payload)?;
            comm.is_exec = record.header.misc & PERF_RECORD_MISC_COMM_EXEC != 0;
            FoldRecord::Comm(comm)
        }
        crate::perfdata::records::PERF_RECORD_THROTTLE => {
            parse_throttle_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_UNTHROTTLE => {
            parse_unthrottle_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_MMAP2
            if record.header.misc & PERF_RECORD_MISC_MMAP_BUILD_ID != 0 =>
        {
            FoldRecord::Mmap2BuildId {
                misc: record.header.misc,
                record: parse_mmap2_build_id_record(record.payload)?,
            }
        }
        crate::perfdata::records::PERF_RECORD_MMAP2 => FoldRecord::Mmap2 {
            misc: record.header.misc,
            record: parse_mmap2_record(record.payload)?,
        },
        crate::perfdata::records::PERF_RECORD_LOST_SAMPLES => {
            parse_lost_samples_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_EXIT => {
            parse_exit_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_FORK => FoldRecord::Fork({
            let mut fork = parse_fork_record(record.payload)?;
            fork.clone_maps = record.header.misc & PERF_RECORD_MISC_FORK_EXEC == 0;
            fork
        }),
        crate::perfdata::records::PERF_RECORD_READ => {
            parse_read_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_SAMPLE => FoldRecord::Sample {
            misc: record.header.misc,
            payload: record.payload,
        },
        crate::perfdata::records::PERF_RECORD_AUX => {
            parse_aux_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_ITRACE_START => {
            parse_itrace_start_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_SWITCH => {
            parse_switch_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_SWITCH_CPU_WIDE => {
            parse_switch_cpu_wide_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_NAMESPACES => {
            parse_namespaces_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_KSYMBOL => {
            parse_ksymbol_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_BPF_EVENT => {
            parse_bpf_event_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_CGROUP => {
            parse_cgroup_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_TEXT_POKE => {
            parse_text_poke_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_AUX_OUTPUT_HW_ID => {
            parse_aux_output_hw_id_record(record.payload)?;
            FoldRecord::Ignored
        }
        crate::perfdata::records::PERF_RECORD_CALLCHAIN_DEFERRED => {
            FoldRecord::CallchainDeferred(parse_callchain_deferred_record(record.payload)?)
        }
        _ => FoldRecord::Ignored,
    };
    Ok(parsed)
}

fn collect_fold_counts<R>(
    bytes: &[u8],
    options: FoldOptions,
    symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
) -> Result<FoldCounts, String>
where
    R: SymbolResolver,
{
    let header = parse_header(bytes)?;
    let layouts = sample_layouts(bytes, header)?;
    let arch = perf_arch_from_header(parse_header_arch(bytes, &header)?.as_deref());
    let mut sink = SampleSink::new(
        SessionState::new(header_build_ids_by_filename(bytes)?).with_arch(arch),
        FoldedOutput::new(symbol_cache, options.inline),
    );
    replay_records(
        &mut SliceSource(bytes),
        header,
        &layouts,
        options,
        &mut sink,
    )?;
    Ok(sink.output.buffers.counts)
}

fn replay_records<O: SampleOutput>(
    source: &mut impl RecordSource,
    header: PerfHeader,
    layouts: &SampleLayouts,
    options: FoldOptions,
    sink: &mut SampleSink<O>,
) -> Result<(), String> {
    let mut offset = usize::try_from(header.data_offset)
        .map_err(|_| "perf data section offset exceeds usize".to_string())?;
    let size = usize::try_from(header.data_size)
        .map_err(|_| "perf data section size exceeds usize".to_string())?;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| "perf data section size overflows usize".to_string())?;
    if end > source.len() {
        return Err("perf data section extends past end of file".to_string());
    }
    let mut ordered = OrderedRecordQueue::default();
    while offset < end {
        let record = source.record_at(offset, end)?;
        let next = offset + usize::from(record.header.size);
        if record.header.record_type == PERF_RECORD_FINISHED_ROUND {
            ordered.flush_round_with(|offset| {
                deliver_record(source, offset, end, layouts, options, sink)
            })?;
        } else if let Some(time) =
            record_time(record, layouts)?.filter(|time| *time != 0 && *time != u64::MAX)
        {
            // ordered-events.c rejects zero/~0ULL with -ETIME; session.c then
            // delivers directly. Ties retain input order (file offset).
            source.retain_record(offset)?;
            ordered.queue(offset, time);
        } else {
            sink.apply_fold_record(parse_fold_record(record)?, layouts, options)?;
        }
        offset = next;
    }
    ordered
        .flush_final_with(|offset| deliver_record(source, offset, end, layouts, options, sink))?;
    sink.flush_deferred_samples()
}

fn deliver_record<O: SampleOutput>(
    source: &mut impl RecordSource,
    offset: usize,
    end: usize,
    layouts: &SampleLayouts,
    options: FoldOptions,
    sink: &mut SampleSink<O>,
) -> Result<(), String> {
    let result = (|| {
        let record = source.delivered_record_at(offset, end)?;
        let record_type = record.header.record_type;
        parse_fold_record(record)
            .and_then(|record| sink.apply_fold_record(record, layouts, options))
            .map_err(|error| {
                format!("failed to parse record type {record_type} at offset {offset}: {error}")
            })
    })();
    source.release_record(offset);
    result
}

fn header_build_ids_by_filename(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    build_id_events_from_perfdata(bytes)?
        .into_iter()
        .map(|event| hex_build_id_bytes(&event.build_id).map(|build_id| (event.filename, build_id)))
        .collect()
}

fn file_replay_state(file: &File) -> Result<(PerfHeader, SampleLayouts, SessionState), String> {
    let (header, bytes) = perfdata_header_from_file(file)?;
    let layouts = sample_layouts_from_file(file, header, &bytes)?;
    let ids = header_build_ids_by_filename_from_file(file, header, &bytes)?;
    let arch = perf_arch_from_header(header_arch_from_file(file, header, &bytes)?.as_deref());
    Ok((header, layouts, SessionState::new(ids).with_arch(arch)))
}

fn write_folded_perfdata_from_file<R, W>(
    file: &File,
    options: FoldOptions,
    symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
    writer: &mut W,
) -> Result<(), String>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    let (header, layouts, state) = file_replay_state(file)?;
    let mut sink = SampleSink::new(state, FoldedOutput::new(symbol_cache, options.inline));
    replay_records(
        &mut FileSource::new(file)?,
        header,
        &layouts,
        options,
        &mut sink,
    )?;
    write_fold_counts(sink.output.buffers.counts, writer)
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
    let (header, layouts, state) = file_replay_state(file)?;
    ensure_perfdata_has_event_data(header)?;
    let mut sink = SampleSink::new(
        state,
        PerfScriptOutput {
            symbol_cache,
            writer,
            event_name_width: layouts.event_name_width,
            inline: options.inline,
        },
    );
    replay_records(
        &mut FileSource::new(file)?,
        header,
        &layouts,
        options,
        &mut sink,
    )
}

struct FoldedOutput<'a, 'cache, R> {
    symbol_cache: Option<&'a mut SymbolFrameCache<'cache, R>>,
    inline: bool,
    buffers: FoldedRenderBuffers,
}

impl<'a, 'cache, R: SymbolResolver> FoldedOutput<'a, 'cache, R> {
    fn new(symbol_cache: Option<&'a mut SymbolFrameCache<'cache, R>>, inline: bool) -> Self {
        Self {
            symbol_cache,
            inline,
            buffers: FoldedRenderBuffers::default(),
        }
    }
}

impl<R: SymbolResolver> SampleOutput for FoldedOutput<'_, '_, R> {
    fn write_sample_event(
        &mut self,
        accumulator: &SessionState,
        sample: &PreparedFoldSample,
    ) -> Result<(), String> {
        let frames = sample
            .frames
            .iter()
            .rev()
            .copied()
            .filter(|frame| !is_perf_context_marker(frame.address()));
        let comm = comm_for_ids(&accumulator.thread_comms, sample.tid);
        FoldFrameResolver::new(&accumulator.mmap_table, self.inline)
            .render_folded_stack_for_stack(
                sample.pid,
                comm.as_deref(),
                frames,
                self.symbol_cache.as_deref_mut(),
                &mut self.buffers,
            )?;
        if !self.buffers.current.is_empty() {
            self.buffers
                .counts
                .add_stack(&self.buffers.current, sample.count);
        }
        Ok(())
    }
}

trait SampleOutput {
    fn write_sample_event(
        &mut self,
        accumulator: &SessionState,
        sample: &PreparedFoldSample,
    ) -> Result<(), String>;
}

struct SampleSink<O> {
    accumulator: SessionState,
    output: O,
}

struct PerfScriptOutput<'io, 'cache, R, W: ?Sized> {
    symbol_cache: Option<&'io mut SymbolFrameCache<'cache, R>>,
    writer: &'io mut W,
    event_name_width: usize,
    inline: bool,
}

impl<O: SampleOutput> SampleSink<O> {
    fn new(accumulator: SessionState, output: O) -> Self {
        Self {
            accumulator,
            output,
        }
    }

    fn apply_fold_record(
        &mut self,
        record: FoldRecord<'_>,
        sample_layouts: &SampleLayouts,
        options: FoldOptions,
    ) -> Result<(), String> {
        match record {
            FoldRecord::Sample { misc, payload } => {
                self.write_sample(misc, payload, sample_layouts, options)
            }
            FoldRecord::CallchainDeferred(record) => {
                let tid = deferred_callchain_tid(&record.sample_id, sample_layouts);
                self.write_deferred_callchain(record.cookie, tid, &record.ips)
            }
            record => {
                self.accumulator.apply_metadata(record);
                Ok(())
            }
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
            self.accumulator.deferred_samples.push(DeferredFoldSample {
                cookie,
                pid: sample.pid,
                tid: sample.tid,
                time: sample.time,
                cpu: sample.cpu,
                event_name: Arc::from(sample.event_name),
                count: sample.count,
                frames: sample.frames,
                has_callchain: sample.has_callchain,
            });
            return Ok(());
        }
        let result = self.output.write_sample_event(&self.accumulator, &sample);
        self.accumulator.sample_frames = sample.frames;
        result
    }

    fn write_deferred_callchain(
        &mut self,
        cookie: u64,
        tid: Option<u32>,
        ips: &[u64],
    ) -> Result<(), String> {
        for sample in self
            .accumulator
            .take_resolved_deferred_samples(cookie, tid, ips)
        {
            let sample = PreparedFoldSample {
                pid: sample.pid,
                tid: sample.tid,
                time: sample.time,
                cpu: sample.cpu,
                event_name: &sample.event_name,
                count: sample.count,
                frames: sample.frames,
                deferred_cookie: None,
                has_callchain: sample.has_callchain,
            };
            self.output.write_sample_event(&self.accumulator, &sample)?;
            self.accumulator.sample_frames = sample.frames;
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
                event_name: &sample.event_name,
                count: sample.count,
                frames: sample.frames,
                deferred_cookie: None,
                has_callchain: sample.has_callchain,
            };
            self.output.write_sample_event(&self.accumulator, &sample)?;
            self.accumulator.sample_frames = sample.frames;
        }
        Ok(())
    }
}

impl<R, W> SampleOutput for PerfScriptOutput<'_, '_, R, W>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    fn write_sample_event(
        &mut self,
        accumulator: &SessionState,
        sample: &PreparedFoldSample,
    ) -> Result<(), String> {
        if sample.has_callchain {
            self.write_sample_header(accumulator, sample)?;
            let frame_resolver = FoldFrameResolver::new(&accumulator.mmap_table, self.inline);
            frame_resolver.write_script_frames_for_stack(
                sample.pid,
                &sample.frames,
                self.symbol_cache.as_deref_mut(),
                self.writer,
            )?;
        } else {
            self.write_sample_inline_header(accumulator, sample)?;
            let frame_resolver = FoldFrameResolver::new(&accumulator.mmap_table, self.inline);
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
}

impl<R, W> PerfScriptOutput<'_, '_, R, W>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    fn write_sample_header(
        &mut self,
        accumulator: &SessionState,
        sample: &PreparedFoldSample,
    ) -> Result<(), String> {
        let comm = perf_script_comm(&accumulator.thread_comms, sample);
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

    fn write_sample_inline_header(
        &mut self,
        accumulator: &SessionState,
        sample: &PreparedFoldSample,
    ) -> Result<(), String> {
        let comm = perf_script_comm(&accumulator.thread_comms, sample);
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
        // builtin-script.c writes the event-name colon/trailing space, then
        // fputc(' ', fp) before sample__fprintf_sym() when no callchain cursor
        // is present, so the inline event-line IP starts after two spaces.
        write!(
            self.writer,
            "{:>10} {:>width$}:  ",
            sample.count,
            sample.event_name,
            width = self.event_name_width,
        )
        .map_err(|error| format!("failed to write perf script output: {error}"))
    }
}

fn perf_script_comm<'a>(
    thread_comms: &'a BTreeMap<u32, String>,
    sample: &PreparedFoldSample,
) -> Cow<'a, str> {
    if let Some(tid) = sample.tid {
        return thread_comms.get(&tid).map_or_else(
            || Cow::Owned(format!(":{tid}")),
            |comm| Cow::Borrowed(comm.as_str()),
        );
    }
    if sample.pid.is_some() {
        return Cow::Borrowed("[unknown]");
    }
    Cow::Borrowed(":-1")
}

impl OrderedRecordQueue {
    fn queue(&mut self, offset: usize, time: u64) {
        // perf util/ordered-events.c:queue_event resets max_timestamp when
        // oe->last is NULL, which do_flush sets after emptying the queue.
        self.max_timestamp = Some(if self.pending_records.is_empty() {
            time
        } else {
            self.max_timestamp.map_or(time, |max| max.max(time))
        });
        self.pending_records
            .push(PendingFoldRecord { offset, time });
    }

    fn flush_round_with<F>(&mut self, apply: F) -> Result<(), String>
    where
        F: FnMut(usize) -> Result<(), String>,
    {
        if let Some(limit) = self.next_flush_time {
            self.flush_through_with(Some(limit), apply)?;
        }
        self.next_flush_time = self.max_timestamp;
        Ok(())
    }

    fn flush_final_with<F>(&mut self, apply: F) -> Result<(), String>
    where
        F: FnMut(usize) -> Result<(), String>,
    {
        self.flush_through_with(None, apply)
    }

    fn flush_through_with<F>(&mut self, limit: Option<u64>, mut apply: F) -> Result<(), String>
    where
        F: FnMut(usize) -> Result<(), String>,
    {
        self.pending_records
            .sort_unstable_by_key(|record| (record.time, record.offset));
        let split = limit.map_or(self.pending_records.len(), |limit| {
            self.pending_records
                .partition_point(|record| record.time <= limit)
        });
        for record in self.pending_records.drain(..split) {
            apply(record.offset)?;
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

fn ensure_perfdata_has_event_data(header: PerfHeader) -> Result<(), String> {
    if header.data_size == 0 {
        // tools/perf/util/header.c warns that data.size==0 means perf record
        // likely did not terminate cleanly, and tools/perf/util/session.c
        // reader__process_events() returns before processing events.
        return Err(
            "perf.data data size field is 0; was perf record properly terminated?".to_string(),
        );
    }
    Ok(())
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
        fallback: attrs.first().map(|attr| {
            Arc::new(SampleEventLayout::new(
                layout_from_attr(attr),
                event_names.first().cloned().unwrap_or_default(),
            ))
        }),
        by_identifier: BTreeMap::new(),
        event_name_width,
    };
    for ((attr, event_name), ids) in attrs.iter().zip(event_names).zip(attr_ids) {
        let event = Arc::new(SampleEventLayout::new(layout_from_attr(attr), event_name));
        for id in ids {
            layouts.by_identifier.insert(id, Arc::clone(&event));
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

/// Maps a `HEADER_ARCH` string to the unwinder architecture, defaulting to
/// `x86_64` when the feature is absent or unrecognized. perf records the
/// recording machine's `uname -m`, so an unknown value (an arch pyroclast does
/// not unwind) falls back to the `x86_64` path rather than failing the fold.
fn perf_arch_from_header(arch: Option<&str>) -> PerfArch {
    arch.and_then(PerfArch::from_header_arch)
        .unwrap_or_default()
}

/// Reads the `HEADER_ARCH` feature string from a perf.data `File`.
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
    let mut reader = file
        .try_clone()
        .map_err(|error| format!("failed to clone perf.data handle: {error}"))?;
    feature_sections_from_reader(&mut reader, &header, header_bytes)
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

impl SessionState {
    fn new(header_build_ids: BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            process_comms: BTreeMap::new(),
            exec_process_comms: BTreeMap::new(),
            thread_comms: BTreeMap::new(),
            mmap_table: MmapTable::default(),
            mapping_cache: MappingResolveCache::default(),
            unwind_states: HashMap::with_hasher(FxBuildHasher),
            header_build_ids,
            deferred_samples: Vec::new(),
            sample_frames: FoldFrameStack::new(),
            unwind_debug_dir: current_perf_debug_dir(),
            arch: PerfArch::default(),
        }
    }

    fn with_arch(mut self, arch: PerfArch) -> Self {
        self.arch = arch;
        self
    }

    #[cfg(test)]
    fn apply_record(&mut self, record: ParsedRecord) {
        let record = match record {
            ParsedRecord::Comm(record) => FoldRecord::Comm(record),
            ParsedRecord::Mmap(record) => FoldRecord::Mmap { misc: 0, record },
            ParsedRecord::Mmap2(record) => FoldRecord::Mmap2 { misc: 0, record },
            ParsedRecord::Mmap2BuildId { misc, record } => {
                FoldRecord::Mmap2BuildId { misc, record }
            }
            ParsedRecord::Fork(record) => FoldRecord::Fork(record),
            _ => panic!("test adapter accepts only session metadata"),
        };
        self.apply_metadata(record);
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
            self.mapping_cache = MappingResolveCache::default();
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

fn record_time(
    record: PerfRecord<'_>,
    sample_layouts: &SampleLayouts,
) -> Result<Option<u64>, String> {
    if record.header.record_type >= crate::perfdata::records::PERF_RECORD_USER_TYPE_START {
        // tools/perf/util/session.c perf_session__process_event() dispatches
        // PERF_RECORD_USER_TYPE_START records before ordered-events, so their
        // payload tails must not be interpreted as sample_id timestamps.
        return Ok(None);
    }
    if record.header.record_type == crate::perfdata::records::PERF_RECORD_SAMPLE {
        return sample_layouts
            .layout_for_payload(record.payload)?
            .map_or(Ok(None), |event| {
                event
                    .offsets
                    .time
                    .map(|offset| read_u64(record.payload, offset))
                    .transpose()
            });
    }

    sample_layouts
        .fallback
        .as_ref()
        .filter(|event| event.layout.sample_id_all)
        .map_or(Ok(None), |event| {
            sample_id_payload_time(record.payload, event.layout)
        })
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
    record: &crate::perfdata::records::CommRecord,
) {
    let comm = record.comm.as_ref();
    if record.is_exec {
        upsert_comm(exec_process_comms, record.pid, comm);
    }
    upsert_comm(process_comms, record.pid, comm);
    upsert_comm(thread_comms, record.tid, comm);
}

fn upsert_comm(map: &mut BTreeMap<u32, String>, id: u32, comm: &str) {
    use std::collections::btree_map::Entry;

    match map.entry(id) {
        Entry::Vacant(entry) => {
            entry.insert(comm.to_owned());
        }
        Entry::Occupied(mut entry) => {
            if entry.get() != comm {
                entry.insert(comm.to_owned());
            }
        }
    }
}

impl SessionState {
    fn apply_metadata(&mut self, record: FoldRecord<'_>) {
        match record {
            FoldRecord::Comm(record) => {
                update_comm_tables(
                    &mut self.process_comms,
                    &mut self.exec_process_comms,
                    &mut self.thread_comms,
                    &record,
                );
            }
            FoldRecord::Mmap { misc, record } => {
                self.invalidate_pid_unwinder_if_mapping_overlaps_like_perf(
                    record.pid,
                    record.start,
                    record.len,
                );
                self.mmap_table.insert_mmap_with_misc(record, misc);
                self.mapping_cache = MappingResolveCache::default();
            }
            FoldRecord::Mmap2 { misc, record } => {
                self.invalidate_pid_unwinder_if_mapping_overlaps_like_perf(
                    record.pid,
                    record.start,
                    record.len,
                );
                let build_id = self.header_build_ids.get(&record.path).cloned();
                if let Some(build_id) = build_id {
                    self.mmap_table.insert_mmap2_with_build_id_and_misc(
                        record,
                        Some(build_id),
                        misc,
                    );
                } else {
                    self.mmap_table.insert_mmap2_with_misc(record, misc);
                }
                self.mapping_cache = MappingResolveCache::default();
            }
            FoldRecord::Mmap2BuildId { misc, record } => {
                self.invalidate_pid_unwinder_if_mapping_overlaps_like_perf(
                    record.pid,
                    record.start,
                    record.len,
                );
                self.mmap_table
                    .insert_mmap2_build_id_with_misc(record, misc);
                self.mapping_cache = MappingResolveCache::default();
            }
            FoldRecord::Fork(record) => {
                self.apply_fork_record(record);
            }
            FoldRecord::Ignored => {}
            FoldRecord::Sample { .. } | FoldRecord::CallchainDeferred(_) => {
                unreachable!("samples are delivered by the replay sink")
            }
        }
    }
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

impl SessionState {
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

    fn take_deferred_samples(&mut self) -> Vec<DeferredFoldSample> {
        std::mem::take(&mut self.deferred_samples)
    }

    fn take_resolved_deferred_samples(
        &mut self,
        cookie: u64,
        tid: Option<u32>,
        ips: &[u64],
    ) -> Vec<DeferredFoldSample> {
        let samples = std::mem::take(&mut self.deferred_samples);
        let deferred_frames = ips.iter().copied().map(FoldFrame::UserCallchain);
        let mut matched = Vec::new();
        let mut unmatched = Vec::new();
        for mut sample in samples {
            if tid != sample.tid {
                unmatched.push(sample);
                continue;
            }
            if sample.cookie == cookie {
                sample.frames.extend(deferred_frames.clone());
            }
            matched.push(sample);
        }
        self.deferred_samples = unmatched;
        matched
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

fn stack_bytes<'a>(names: &'a [Arc<str>], stack: &'a [LabelId]) -> impl Iterator<Item = u8> + 'a {
    stack.iter().enumerate().flat_map(move |(index, &id)| {
        std::iter::once(b';')
            .filter(move |_| index != 0)
            .chain(names[id].as_bytes().iter().copied())
    })
}

fn write_fold_counts<W>(counts: FoldCounts, writer: &mut W) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    let FoldCounts { names, stacks, .. } = counts;
    let mut entries = stacks.into_iter().collect::<Vec<_>>();
    // Sort serialized bytes, not IDs or label-wise prefixes.
    entries.sort_unstable_by(|(left, _), (right, _)| {
        stack_bytes(&names, left).cmp(stack_bytes(&names, right))
    });
    for (stack, count) in entries {
        for (index, &id) in stack.iter().enumerate() {
            if index != 0 {
                writer
                    .write_all(b";")
                    .map_err(|error| format!("failed to write folded output: {error}"))?;
            }
            writer
                .write_all(names[id].as_bytes())
                .map_err(|error| format!("failed to write folded output: {error}"))?;
        }
        writeln!(writer, " {count}")
            .map_err(|error| format!("failed to write folded output: {error}"))?;
    }
    Ok(())
}

fn prefetch_sample_symbols<R: SymbolResolver>(
    frames: impl IntoIterator<Item = FoldFrame>,
    context: Option<&FrameMappingContext<'_>>,
    mapping_cache: &mut MappingResolveCache,
    cache: &mut SymbolFrameCache<'_, R>,
    inline: bool,
) -> Result<(), String> {
    let mut full = SmallVec::<[ResolvedMappingRef<'_>; 16]>::new();
    let mut base = SmallVec::<[ResolvedMappingRef<'_>; 16]>::new();
    for frame in frames {
        if let Some(mapping) =
            resolve_frame_in_context(context, frame, mapping_cache).filter(|mapping| {
                matches!(frame, FoldFrame::InlineCurrentIp(_))
                    || !is_kernel_space_frame(frame.address())
                    || mapping.is_kernel()
            })
        {
            let expand = inline && !matches!(frame, FoldFrame::SampleIp { .. });
            if cache.cached_mapping_frames(&mapping, expand).is_some() {
                continue;
            }
            if expand {
                full.push(mapping.resolved_ref());
            } else {
                base.push(mapping.resolved_ref());
            }
        }
    }
    // Batch only the currently delivered sample. Future samples may observe a
    // different map; SymbolFrameCache deduplicates already resolved addresses.
    if !full.is_empty() {
        cache.prefetch_mapping_refs(&full)?;
    }
    if !base.is_empty() {
        cache.prefetch_base_mapping_refs(&base)?;
    }
    Ok(())
}

struct FoldFrameResolver<'a> {
    mmap_table: &'a MmapTable,
    inline: bool,
}

enum FrameMappingDecision<'a> {
    Mapped(MappedFrame<'a>),
    KernelAddress,
    Unknown,
    Address,
}

fn resolve_frame_in_context<'a>(
    context: Option<&FrameMappingContext<'a>>,
    frame: FoldFrame,
    mapping_cache: &mut MappingResolveCache,
) -> Option<MappedFrame<'a>> {
    let context = context?;
    let address = frame.address();
    match frame {
        FoldFrame::Callchain(_) => context.resolve(address, mapping_cache),
        FoldFrame::SampleIp { cpumode, .. }
            if cpumode & PERF_RECORD_MISC_CPUMODE_MASK == PERF_RECORD_MISC_CPUMODE_KERNEL =>
        {
            context.resolve(address, mapping_cache)
        }
        FoldFrame::SampleIp { .. }
        | FoldFrame::UserCallchain(_)
        | FoldFrame::UserUnwind(_)
        | FoldFrame::InlineCurrentIp(_) => context.resolve_user(address, mapping_cache),
    }
}

#[derive(Default)]
struct FoldedRenderBuffers {
    current: String,
    counts: FoldCounts,
    render_scratch: String,
    module_scratch: String,
    mapping_cache: MappingResolveCache,
}

impl FoldedRenderBuffers {
    #[cfg(test)]
    fn rendered(&self) -> String {
        self.current.clone()
    }
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
        frame: FoldFrame,
        mapping_cache: &mut MappingResolveCache,
    ) -> FrameMappingDecision<'a> {
        let context = pid.map(|pid| self.mmap_table.frame_context(pid, mapping_cache));
        Self::mapping_decision_in_context(context.as_ref(), frame, mapping_cache)
    }

    fn mapping_decision_in_context(
        context: Option<&FrameMappingContext<'a>>,
        frame: FoldFrame,
        mapping_cache: &mut MappingResolveCache,
    ) -> FrameMappingDecision<'a> {
        let address = frame.address();
        if let Some(mapping) = resolve_frame_in_context(context, frame, mapping_cache) {
            if is_kernel_space_frame(address) && !mapping.is_kernel() {
                FrameMappingDecision::KernelAddress
            } else {
                FrameMappingDecision::Mapped(mapping)
            }
        } else {
            FrameMappingDecision::Unknown
        }
    }

    fn render_folded_stack_for_stack<R, I>(
        &self,
        pid: Option<u32>,
        comm: Option<&str>,
        callchain: I,
        mut symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
        buffers: &mut FoldedRenderBuffers,
    ) -> Result<(), String>
    where
        R: SymbolResolver,
        I: IntoIterator<Item = FoldFrame>,
        I::IntoIter: Clone,
    {
        buffers.current.clear();
        if let Some(comm) = comm {
            buffers.current.reserve(comm.len());
            for character in comm.chars() {
                match character {
                    ' ' => buffers.current.push('_'),
                    ';' => buffers.current.push_str("\\;"),
                    '\r' | '\n' => buffers.current.push(' '),
                    _ => buffers.current.push(character),
                }
            }
        } else {
            append_cached_inferno_perf_folded_label_to_buffers(buffers, UNKNOWN_FRAME);
        }
        let comm_prefix_len = buffers.current.len();

        let context = pid.map(|pid| {
            self.mmap_table
                .frame_context(pid, &mut buffers.mapping_cache)
        });

        let mut callchain = callchain.into_iter();
        while let Some(frame) = callchain.next() {
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
            let decision =
                if symbol_cache.is_some() && matches!(frame, FoldFrame::InlineCurrentIp(_)) {
                    resolve_frame_in_context(context.as_ref(), frame, &mut buffers.mapping_cache)
                        .map_or(FrameMappingDecision::Unknown, FrameMappingDecision::Mapped)
                } else {
                    Self::mapping_decision_for_folded_frame(
                        context.as_ref(),
                        frame,
                        symbol_cache.is_some(),
                        &mut buffers.mapping_cache,
                    )
                };
            match decision {
                FrameMappingDecision::Mapped(mapping) => {
                    if let Some(cache) = symbol_cache.as_deref_mut() {
                        // Event-line IPs use machine__resolve(), not append_inlines().
                        let expand = self.inline && !matches!(frame, FoldFrame::SampleIp { .. });
                        if let Some((frames, has_base_symbol)) =
                            cache.cached_mapping_frames(&mapping, expand)
                        {
                            append_resolved_folded_frames(
                                buffers,
                                &mapping,
                                frame,
                                expand,
                                frames,
                                has_base_symbol,
                            );
                            continue;
                        }
                        prefetch_sample_symbols(
                            std::iter::once(frame).chain(callchain.clone()),
                            context.as_ref(),
                            &mut buffers.mapping_cache,
                            cache,
                            self.inline,
                        )?;
                        let (frames, has_base_symbol) = cache
                            .cached_mapping_frames(&mapping, expand)
                            .ok_or_else(|| {
                                "symbol frame cache lookup missed after resolution".to_string()
                            })?;
                        append_resolved_folded_frames(
                            buffers,
                            &mapping,
                            frame,
                            expand,
                            frames,
                            has_base_symbol,
                        );
                    } else {
                        append_frame_mapping_fallback(buffers, &mapping);
                    }
                }
                FrameMappingDecision::KernelAddress | FrameMappingDecision::Address => {
                    append_folded_address_label(buffers, frame.address());
                }
                FrameMappingDecision::Unknown => {
                    append_cached_inferno_perf_folded_label_to_buffers(buffers, UNKNOWN_FRAME);
                }
            }
        }
        if buffers.current.len() == comm_prefix_len {
            buffers.current.clear();
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
            if let FoldFrame::InlineCurrentIp(address) = frame {
                // perf's machine.c unwind_entry() runs append_inlines() on
                // EVERY accepted entry, including the initial sampled IP, so
                // in inline-capable mode the leaf expands its inline chain just
                // like a caller frame. Only base-only mode renders the single
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
        match self.mapping_decision(pid, frame, &mut mapping_cache) {
            FrameMappingDecision::Mapped(mapping) => {
                write_perf_script_inline_mapped_decision_frame(
                    writer,
                    address,
                    &mapping.resolved_ref(),
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
        match self.mapping_decision(pid, frame, mapping_cache) {
            FrameMappingDecision::Mapped(mapping) => {
                write_perf_script_mapped_decision_frame(
                    writer,
                    address,
                    frame,
                    &mapping.resolved_ref(),
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
                    .resolve_user_pid_ref_cached(pid, address, mapping_cache)
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
                .resolve_user_pid_ref_cached(pid, address, mapping_cache)
        }) else {
            return Ok(None);
        };
        let Some(frames) = cache.resolve_mapping_ref_with_base_symbol(&mapping)? else {
            return Ok(None);
        };
        Ok(Some(frames))
    }

    fn mapping_decision_for_folded_frame(
        context: Option<&FrameMappingContext<'a>>,
        frame: FoldFrame,
        symbolizing: bool,
        mapping_cache: &mut MappingResolveCache,
    ) -> FrameMappingDecision<'a> {
        let address = frame.address();
        let decision = Self::mapping_decision_in_context(context, frame, mapping_cache);
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

fn append_resolved_folded_frames(
    buffers: &mut FoldedRenderBuffers,
    mapping: &MappedFrame<'_>,
    frame: FoldFrame,
    expand: bool,
    frames: &[String],
    has_base_symbol: bool,
) {
    if matches!(frame, FoldFrame::InlineCurrentIp(_)) && !expand {
        if !has_base_symbol {
            if is_kernel_space_frame(frame.address()) && !mapping.is_kernel() {
                append_folded_address_label(buffers, frame.address());
            } else {
                append_frame_mapping_fallback(buffers, mapping);
            }
            return;
        }
    } else if frames.is_empty() {
        append_frame_mapping_fallback(buffers, mapping);
        return;
    }
    for label in frames {
        append_cached_inferno_perf_raw_function_to_buffers(buffers, label);
    }
}

fn append_folded_address_label(buffers: &mut FoldedRenderBuffers, address: u64) {
    append_separator(&mut buffers.current);
    write!(buffers.current, "0x{address:x}").expect("writing to a string cannot fail");
}

fn append_cached_inferno_perf_raw_function_to_buffers(
    buffers: &mut FoldedRenderBuffers,
    frame: &str,
) {
    append_inferno_perf_raw_function(&mut buffers.current, frame, &mut buffers.render_scratch);
}

fn append_cached_inferno_perf_folded_label_to_buffers(
    buffers: &mut FoldedRenderBuffers,
    label: &str,
) {
    if !label.is_empty() {
        append_inferno_perf_folded_label(&mut buffers.current, label);
    }
}

#[cfg(test)]
fn append_mapping_fallback(buffers: &mut FoldedRenderBuffers, mapping: &ResolvedMappingRef<'_>) {
    let kernel = is_kernel_mapping_ref(mapping);
    let path = if kernel {
        perf_script_dso_name(mapping.path)
    } else {
        mapping.path
    };
    append_module_fallback(buffers, path, &MappingPathLayout::new(path), kernel);
}

fn append_frame_mapping_fallback(buffers: &mut FoldedRenderBuffers, mapping: &MappedFrame<'_>) {
    let raw_path = mapping.path();
    let kernel = mapping.is_kernel();
    let path = if kernel {
        perf_script_dso_name(raw_path)
    } else {
        raw_path
    };
    if path.len() == raw_path.len() {
        append_module_fallback(buffers, path, mapping.path_layout(), kernel);
    } else {
        append_literal_module(&mut buffers.current, path, false);
    }
}

fn append_module_fallback(
    buffers: &mut FoldedRenderBuffers,
    path: &str,
    layout: &MappingPathLayout,
    kernel: bool,
) {
    if layout.fallback == ModuleFallbackKind::Unknown && !kernel {
        append_cached_inferno_perf_folded_label_to_buffers(buffers, UNKNOWN_FRAME);
        return;
    }
    // Inferno perf.rs:stack_line_parts splits at the final literal space.
    // Most whitespace-containing DSO paths therefore do not form a stack row;
    // a final '(' token instead leaves the path prefix in the raw function.
    if layout.fallback == ModuleFallbackKind::Skip {
        return;
    }
    if layout.fallback == ModuleFallbackKind::RawFunction {
        let index = layout.last_space.expect("raw function has a final space");
        buffers.module_scratch.clear();
        buffers.module_scratch.push_str("[unknown] (");
        buffers.module_scratch.push_str(path[..index].trim_end());
        append_inferno_perf_raw_function(
            &mut buffers.current,
            &buffers.module_scratch,
            &mut buffers.render_scratch,
        );
        return;
    }
    // Inferno perf.rs:with_module_fallback uses the literal suffix after '/';
    // tidy_generic then normalizes this synthetic function, including ';' -> ':'.
    let name = &path[layout.basename_start..];
    if layout.fallback == ModuleFallbackKind::Normalized {
        buffers.module_scratch.clear();
        buffers.module_scratch.push('[');
        buffers.module_scratch.push_str(name);
        buffers.module_scratch.push(']');
        // on_stack_line() expands arrows before with_module_fallback(), so
        // synthetic module labels go through tidy_generic only.
        tidy_inferno_perf_generic_into(&mut buffers.render_scratch, &buffers.module_scratch);
        append_separator(&mut buffers.current);
        escape_frame_into(&mut buffers.current, &buffers.render_scratch);
    } else {
        append_literal_module(
            &mut buffers.current,
            name,
            layout.fallback == ModuleFallbackKind::Escaped,
        );
    }
}

fn append_literal_module(output: &mut String, name: &str, escape: bool) {
    output.reserve(name.len() + 2 + usize::from(!output.is_empty()));
    append_separator(output);
    output.push('[');
    if escape {
        append_escaped_spans(output, name, ":");
    } else {
        output.push_str(name);
    }
    output.push(']');
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
    _frame: FoldFrame,
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
    // Base-only mode resolves one object symbol and prints it with the mapping's
    // full DSO name (map__fprintf_dsoname). The CLI parity path keeps inline on
    // so DWARF data can emit the inline rows that real perf prints.
    if !inline {
        return match cache.resolve_mapping_ref_with_base_symbol(mapping)? {
            Some([label, ..]) => {
                write_perf_script_mapped_symbol_frame(writer, address, label, mapping.path)
            }
            _ => write_perf_script_mapped_unknown_symbol_frame(writer, address, mapping.path),
        };
    }
    let (frames, base_offset, has_inline_frames, has_non_inline_base_frame) =
        cache.resolve_mapping_ref_with_offset(mapping)?;
    if frames.is_empty() {
        write_perf_script_mapped_unknown_symbol_frame(writer, address, mapping.path)?;
    } else if frames.len() == 1 && !has_inline_frames && !is_kernel_space_frame(address) {
        // A single non-inline base frame already carries its +0x<off> baked in
        // by perf_frames_with_object_alias_and_offset (the symtab with_offset
        // form), so print it verbatim with the DSO path.
        write_perf_script_mapped_symbol_frame(writer, address, &frames[0], mapping.path)?;
    } else {
        let last = frames.len() - 1;
        for (printed_index, label) in frames.iter().rev().enumerate() {
            let is_inlined = has_inline_frames
                && (frames.len() == 1 || printed_index != last || !has_non_inline_base_frame);
            write_perf_script_inline_chain_frame(
                writer,
                address,
                label,
                base_offset,
                mapping.path,
                is_inlined,
            )?;
        }
    }
    Ok(())
}

/// Prints one perf-script callchain frame for an inline-expanded address.
///
/// Matches `tools/perf/util/evsel_fprintf.c`: the symbol name carries the
/// shared `+0x<off>` offset (`__symbol__fprintf_symname_offs`), inline frames
/// print ` (inlined)` instead of a DSO name (`print_dso && (!sym ||
/// !sym->inlined)`). A trailing frame prints the mapped DSO path only when
/// perf's `new_inline_sym()` reused the real base symbol; if libdw's
/// `dwarf_diename()` differs from that base symbol, perf creates another fake
/// inline symbol and prints ` (inlined)` for that row too.
fn write_perf_script_inline_chain_frame<W>(
    writer: &mut W,
    address: u64,
    label: &str,
    base_offset: Option<u64>,
    path: &str,
    is_inlined: bool,
) -> Result<(), String>
where
    W: IoWrite + ?Sized,
{
    // Fallback labels (raw addresses, [unknown], [module]) keep their existing
    // rendering and never take an offset or the (inlined) marker.
    if label == UNKNOWN_FRAME
        || label.starts_with("0x")
        || module_fallback_label_module(label).is_some()
    {
        return write_perf_script_mapped_symbol_frame(writer, address, label, path);
    }
    if is_inlined {
        match base_offset {
            Some(offset) => writeln!(writer, "\t{address:16x} {label}+0x{offset:x} (inlined)")
                .map_err(|error| format!("failed to write perf script output: {error}")),
            None => writeln!(writer, "\t{address:16x} {label} (inlined)")
                .map_err(|error| format!("failed to write perf script output: {error}")),
        }
    } else {
        let path = perf_script_dso_name(path);
        match base_offset {
            Some(offset) => writeln!(writer, "\t{address:16x} {label}+0x{offset:x} ({path})")
                .map_err(|error| format!("failed to write perf script output: {error}")),
            None => writeln!(writer, "\t{address:16x} {label} ({path})")
                .map_err(|error| format!("failed to write perf script output: {error}")),
        }
    }
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
        let frames = cache.resolve_mapping_ref_with_base_symbol(mapping)?;
        if let Some([label, ..]) = frames {
            return write_perf_script_mapped_symbol_frame_fragment(
                writer,
                "",
                address,
                label,
                mapping.path,
            );
        }
        return write_perf_script_mapped_unknown_symbol_frame_fragment(
            writer,
            "",
            address,
            mapping.path,
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
    let path = perf_script_dso_name(path);
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

fn build_id_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex, "{byte:02x}").expect("writing to a string cannot fail");
    }
    hex
}

#[cfg(test)]
fn is_kernel_mapping_ref(mapping: &ResolvedMappingRef<'_>) -> bool {
    is_kernel_space_frame(mapping.relative_address) && mapping.path.starts_with('[')
}

/// The DSO name perf-script prints for a mapping. The core kernel map is
/// recorded with a relocation reference suffix (e.g. `[kernel.kallsyms]_stext`),
/// but perf names its dso `[kernel.kallsyms]` (`machine__create_kernel_maps`
/// sets the kernel dso short name), so `map__fprintf_dsoname` prints that.
fn perf_script_dso_name(path: &str) -> &str {
    if path.starts_with("[kernel.kallsyms]") {
        "[kernel.kallsyms]"
    } else {
        path
    }
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

fn prepare_sample_for_fold<'layout>(
    accumulator: &mut SessionState,
    misc: u16,
    payload: &[u8],
    sample_layouts: &'layout SampleLayouts,
    options: FoldOptions,
) -> Result<Option<PreparedFoldSample<'layout>>, String> {
    let Some(event) = sample_layouts.layout_for_payload(payload)? else {
        return Ok(None);
    };
    let Some(sample) = parse_sample_record_callchain(payload, event.layout)? else {
        return Ok(None);
    };
    let count = sample_fold_count(sample.period, options);
    accumulator.sample_frames.clear();
    accumulator.sample_frames.reserve(sample.frames.len());
    let has_callchain = event.layout.sample_type & PERF_SAMPLE_CALLCHAIN != 0;
    if has_callchain {
        extend_recorded_callchain_frames_like_perf(
            &mut accumulator.sample_frames,
            sample.frames.clone(),
        );
    } else {
        extend_sample_ip_frame_like_perf_machine_resolve(
            &mut accumulator.sample_frames,
            misc,
            sample.frames.clone(),
        );
    }
    let deferred_cookie = take_deferred_cookie(&mut accumulator.sample_frames);
    append_perf_user_unwind_frames(accumulator, misc, event, &sample);
    Ok(Some(PreparedFoldSample {
        pid: sample.pid,
        tid: sample.tid,
        time: sample.time,
        cpu: sample.cpu,
        event_name: &event.event_name,
        count,
        frames: std::mem::take(&mut accumulator.sample_frames),
        deferred_cookie,
        has_callchain,
    }))
}

fn extend_sample_ip_frame_like_perf_machine_resolve(
    frames: &mut FoldFrameStack,
    misc: u16,
    callchain: impl IntoIterator<Item = u64>,
) {
    // tools/perf/builtin-script.c process_sample_event() calls
    // machine__resolve() for the event-line IP, and tools/perf/util/event.c
    // machine__resolve() looks up sample->ip with sample->cpumode.
    let cpumode = misc & PERF_RECORD_MISC_CPUMODE_MASK;
    frames.extend(
        callchain
            .into_iter()
            .map(|address| FoldFrame::SampleIp { address, cpumode }),
    );
}

fn extend_recorded_callchain_frames_like_perf(
    frames: &mut FoldFrameStack,
    callchain: impl IntoIterator<Item = u64>,
) {
    // tools/perf/util/machine.c add_callchain_ip() switches cpumode only when
    // it encounters PERF_CONTEXT_* markers. A kernel-looking address that is
    // still under PERF_RECORD_MISC_USER must therefore resolve against user
    // maps and normally prints as [unknown], not fall into kernel maps by
    // address alone.
    let mut cpumode = PERF_RECORD_MISC_CPUMODE_USER;
    for ip in callchain {
        match ip {
            PERF_CONTEXT_KERNEL => {
                cpumode = PERF_RECORD_MISC_CPUMODE_KERNEL;
                frames.push(FoldFrame::Callchain(ip));
            }
            PERF_CONTEXT_USER | PERF_CONTEXT_USER_DEFERRED => {
                cpumode = PERF_RECORD_MISC_CPUMODE_USER;
                frames.push(FoldFrame::Callchain(ip));
            }
            _ if cpumode == PERF_RECORD_MISC_CPUMODE_USER => {
                frames.push(FoldFrame::UserCallchain(ip));
            }
            _ => frames.push(FoldFrame::Callchain(ip)),
        }
    }
}

fn append_perf_user_unwind_frames(
    accumulator: &mut SessionState,
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
    accumulator: &SessionState,
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
        module_count: loaded_unwind_module_count(accumulator, sample.pid),
        // x86_64-specific `ebl_unwind` precondition (false on aarch64, whose
        // backend has its own internal accept condition).
        frame_pointer_at_or_above_stack_pointer: regs.frame_pointer_at_or_above_stack_pointer(),
        syscall_return_state: regs.is_syscall_return_state(),
    }
}

fn initial_ip_mapping_state(
    accumulator: &SessionState,
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

fn loaded_unwind_module_count(accumulator: &SessionState, pid: Option<u32>) -> usize {
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
    accumulator: &mut SessionState,
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
    accumulator: &mut SessionState,
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
    // perf's unwind__get_entries reports the module for the initial IP up front
    // (tools/perf/util/unwind-libdw.c): a hard report failure (scenario B)
    // abandons the whole unwind with zero entries.
    if report_unwind_module_for_ip_like_perf(state, mmap_table, pid, regs.ip(), unwind_debug_dir)
        == ReportModuleResult::Failed
    {
        return Vec::new();
    }

    // Evaluate perf/libdw's skip and leaf-only cases before framehop. The result
    // is byte-identical to running framehop because the shared acceptance tail
    // applies the same libdw callback rules to the sampled IP.
    let leaf_only = sample_is_leaf_only(state, pid, mmap_table, regs, context);
    match classify_object_unwind(context, leaf_only) {
        ObjectUnwindClass::SkipUnwind => return Vec::new(),
        ObjectUnwindClass::LeafOnly => {
            return perf_accepted_object_unwind_frames(regs, context.callchain, true, Vec::new());
        }
        ObjectUnwindClass::MustUnwind => {}
    }

    let mut object_unwind =
        unwind_user_stack_with_diagnostics(&mut state.object_unwinder, *regs, stack_bytes, 256);
    for _ in 0..MAX_LIBDW_CALLBACK_REPORT_PASSES {
        // PERF-4: only re-unwind when this pass actually loaded a new module.
        // report_unwind_modules_for_frame_callbacks_like_perf returns whether
        // anything was newly reported; when it returns false there is nothing
        // new for framehop to traverse, so the previous unwind is final and the
        // redundant re-unwind (and its Vec/diagnostics comparison) is skipped.
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
    let mut raw_frames = object_unwind.accepted_frames;
    // perf's frame_callback reports each module, then entry() calls
    // __report_module() again and aborts at the first hard failure.
    let first_unreportable = raw_frames.iter().position(|address| {
        report_unwind_module_for_ip_like_perf(state, mmap_table, pid, *address, unwind_debug_dir)
            == ReportModuleResult::Failed
    });
    if let Some(index) = first_unreportable {
        raw_frames.truncate(index);
    }
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
    perf_accepted_object_unwind_frames(regs, context.callchain, leaf_only, raw_frames)
}

/// Whether perf/libdw would fire the initial-frame callback exactly once and
/// stop: the sampled IP reported into a module, no CFI covers it, and the
/// arch-specific `ebl_unwind` fallback provably cannot advance.
///
/// The `(pid, ip)`-stable half (module reported + no CFI) is memoized in
/// `state.leaf_only_eligibility`; the per-sample register condition
/// (`bp < sp` on `x86_64`, `lr == 0` on aarch64) is combined here fresh.
fn sample_is_leaf_only(
    state: &mut PidUnwindState,
    pid: u32,
    mmap_table: &MmapTable,
    regs: &PerfUserRegs,
    context: UserUnwindContext,
) -> bool {
    // KernelWithUserFrame never appends extra user frames, so a leaf is never
    // emitted there; leave that to the SkipUnwind class.
    if context.callchain == SampleCallchainState::KernelWithUserFrame {
        return false;
    }
    let ip = regs.ip();
    let eligibility = *state
        .leaf_only_eligibility
        .entry(ip)
        .or_insert_with(|| leaf_only_eligibility(pid, ip, mmap_table, &state.object_unwinder));
    if eligibility != LeafOnlyEligibility::Eligible {
        return false;
    }
    arch_fallback_provably_cannot_advance(regs)
}

/// The `(pid, ip)`-stable half of the leaf-only predicate, suitable for
/// memoizing: the module covering `ip` is reported into the unwinder AND no CFI
/// (`.eh_frame`/`.debug_frame` FDE) covers `ip`.
fn leaf_only_eligibility(
    pid: u32,
    ip: u64,
    mmap_table: &MmapTable,
    object_unwinder: &FramehopUnwinder,
) -> LeafOnlyEligibility {
    let reported =
        initial_ip_mapping_has_reported_unwind_module(Some(pid), ip, mmap_table, object_unwinder);
    if reported && !object_unwinder.has_unwind_info_for_ip(ip) {
        LeafOnlyEligibility::Eligible
    } else {
        LeafOnlyEligibility::Ineligible
    }
}

/// The per-sample half of the leaf-only predicate: whether the arch-specific
/// `ebl_unwind` fallback can never produce a caller from these registers.
///
/// `x86_64` (`backends/x86_64_unwind.c`): the rbp fallback is only attempted by
/// pyroclast when `bp >= sp` (the elfutils final guard `if (sp >= fp) return
/// false;` rejects a frame pointer that does not sit above the stack pointer).
/// So `bp < sp` means the fallback contributes nothing.
///
/// aarch64 (`backends/aarch64_unwind.c`): the caller pc comes from `lr`; the
/// fallback returns false immediately when `lr == 0`. So `lr == 0` means no
/// caller.
fn arch_fallback_provably_cannot_advance(regs: &PerfUserRegs) -> bool {
    match *regs {
        PerfUserRegs::X86_64(regs) => regs.bp < regs.sp,
        PerfUserRegs::Aarch64(regs) => regs.lr == 0,
    }
}

/// Classifies a sample's object unwind before framehop runs.
fn classify_object_unwind(context: UserUnwindContext, leaf_only: bool) -> ObjectUnwindClass {
    // Research §3.5: a recorded kernel->user callchain is not extended with
    // extra user DWARF callers — perf emits zero unwound frames here.
    if context.callchain == SampleCallchainState::KernelWithUserFrame {
        return ObjectUnwindClass::SkipUnwind;
    }
    // Without a mapping for the sampled IP, perf's libdw path has no initial
    // module to seed DWFL and emits no object-unwind entries.
    if context.initial_ip_mapping == InitialIpMappingState::NoRecordedMapping {
        return ObjectUnwindClass::SkipUnwind;
    }
    if leaf_only {
        ObjectUnwindClass::LeafOnly
    } else {
        ObjectUnwindClass::MustUnwind
    }
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
        // aarch64's backend has no bp/sp precondition: it accepts the lr-based
        // caller unless lr == 0, with its own internal `fp == 0 || fp+16 > sp`
        // accept condition (backends/aarch64_unwind.c). framehop's aarch64
        // unwinder yields only the seed pc when no CFI covers it, which is
        // exactly when libdwfl invokes ebl_unwind on the leaf, so the fallback
        // fires when framehop produced no caller beyond the sampled pc.
        PerfUserRegs::Aarch64(regs) if frames_are_seed_only(&raw_frames, regs.pc) => {
            unwind_aarch64_frame_pointer_stack_like_elfutils(regs, stack_bytes, 256)
        }
        PerfUserRegs::X86_64(_) | PerfUserRegs::Aarch64(_) => raw_frames,
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
    initial_ip_mapping_has_reported_module: bool,
) -> bool {
    context.initial_ip_mapping != InitialIpMappingState::RecordedMappingMissing
        && initial_ip_mapping_has_reported_module
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
        // PERF-4: only treat a NEWLY loaded module as progress. An
        // already-present module adds no unwind information, so re-unwinding
        // after it would reproduce the same frames.
        loaded |= report_unwind_module_for_ip_like_perf(
            state,
            mmap_table,
            pid,
            *address,
            unwind_debug_dir,
        ) == ReportModuleResult::NewlyReported;
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
        return ReportModuleResult::AlreadyReported;
    }
    if load_unwind_mapping_for_user_mapping_like_perf(state, mapping, unwind_debug_dir) {
        ReportModuleResult::NewlyReported
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

fn take_deferred_cookie(frames: &mut FoldFrameStack) -> Option<u64> {
    match frames.as_slice() {
        [
            ..,
            FoldFrame::Callchain(marker),
            FoldFrame::Callchain(cookie) | FoldFrame::UserCallchain(cookie),
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

/// Maps framehop's unwound frame addresses onto perf's accepted-entry list.
///
/// `leaf_only` is the fully-evaluated scenario-D predicate (see
/// `sample_is_leaf_only`): when framehop produced no frames at all but
/// perf/libdw would still fire the initial-frame callback exactly once, emit
/// the single sampled-IP leaf. perf has no `.so`-vs-executable distinction in
/// this path — `frame_callback` fires for the initial frame regardless of
/// whether the covering module is a shared object or the main binary
/// (`tools/perf/util/unwind-libdw.c` / `libdwfl/dwfl_frame.c`), so the prior
/// `KeepDsoLeaf`/`DropSyntheticCurrentIp` split (which had no perf-source
/// basis) is gone.
fn perf_accepted_object_unwind_frames(
    regs: &PerfUserRegs,
    callchain: SampleCallchainState,
    leaf_only: bool,
    unwound_frames: Vec<u64>,
) -> Vec<u64> {
    if callchain == SampleCallchainState::KernelWithUserFrame {
        return Vec::new();
    }
    // When the leaf-only predicate holds, perf/libdwfl fires frame_callback for
    // the seeded IP and then stops. No FDE row covers the IP, so advancement
    // depends on `ebl_unwind`; the x86_64 backend returns false when `bp < sp`,
    // and the aarch64 backend returns false when `lr == 0`. In that state perf
    // prints exactly the sampled-IP leaf, so a framehop-only caller is discarded.
    if leaf_only {
        return vec![regs.ip()];
    }
    unwound_frames
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
        .map(|debug_dir| {
            perf_build_id_elf_path_for_dso(debug_dir, Path::new(path), &build_id_hex(build_id))
        })
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
        fallback: attrs.first().map(|attr| {
            Arc::new(SampleEventLayout::new(
                layout_from_attr(attr),
                event_names.first().cloned().unwrap_or_default(),
            ))
        }),
        by_identifier: BTreeMap::new(),
        event_name_width,
    };
    for ((attr, event_name), ids) in attrs.iter().zip(event_names).zip(attr_ids) {
        let event = Arc::new(SampleEventLayout::new(layout_from_attr(attr), event_name));
        for id in ids {
            layouts.by_identifier.insert(id, Arc::clone(&event));
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
/// (u32, sizeof `perf_event_attr`), then for each event: `attr_sz` attr bytes, a
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
    fn layout_for_payload(&self, payload: &[u8]) -> Result<Option<&SampleEventLayout>, String> {
        if self.by_identifier.is_empty() {
            return Ok(self.fallback.as_deref());
        }
        let Some(fallback) = self.fallback.as_deref() else {
            return Ok(None);
        };
        if let Some(identifier) = fallback
            .offsets
            .id
            .map(|offset| read_sample_u64(payload, offset))
            .transpose()?
        {
            return Ok(self
                .by_identifier
                .get(&identifier)
                .map(Arc::as_ref)
                .or(Some(fallback)));
        }
        Ok(Some(fallback))
    }
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

    #[derive(Clone)]
    struct CountingCollisionHasher(std::rc::Rc<std::cell::Cell<usize>>);

    impl std::hash::BuildHasher for CountingCollisionHasher {
        type Hasher = ZeroHasher;

        fn build_hasher(&self) -> ZeroHasher {
            self.0.set(self.0.get() + 1);
            ZeroHasher
        }
    }

    struct ZeroHasher;

    impl std::hash::Hasher for ZeroHasher {
        fn finish(&self) -> u64 {
            0
        }

        fn write(&mut self, _: &[u8]) {}
    }

    #[test]
    fn stack_count_hashes_once_per_sample_and_compares_colliding_full_keys() {
        let hashes = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut stacks = super::HashMap::<String, u64, _>::with_capacity_and_hasher(
            32,
            CountingCollisionHasher(hashes.clone()),
        );
        for (index, (key, count)) in [
            ("root;a", 1),
            ("root;a", 2),
            ("root;ab", 4),
            ("", 8),
            ("root;\u{e9}", 16),
            ("root;a", 32),
        ]
        .into_iter()
        .enumerate()
        {
            super::add_stack_count(&mut stacks, key, count);
            assert_eq!(hashes.get(), index + 1);
        }
        assert_eq!(stacks.len(), 4);
        assert_eq!(stacks.get("root;a"), Some(&35));
        assert_eq!(stacks.get("root;ab"), Some(&4));
        assert_eq!(stacks.get(""), Some(&8));
        assert_eq!(stacks.get("root;\u{e9}"), Some(&16));
    }

    #[test]
    fn borrowed_stack_count_supports_boxed_ids_and_survives_table_growth() {
        let mut stacks = super::HashMap::<Box<[usize]>, u64, super::FxBuildHasher>::default();
        for value in 0..1024 {
            let key = [value, 1, 2, 3];
            super::add_stack_count(&mut stacks, key.as_slice(), 2);
            super::add_stack_count(&mut stacks, key.as_slice(), 3);
        }
        for value in 0..1024 {
            assert_eq!(stacks.get([value, 1, 2, 3].as_slice()), Some(&5));
        }
        assert_eq!(stacks.len(), 1024);
    }

    struct RetentionCheckedSource<'a> {
        source: super::SliceSource<'a>,
        pending: std::collections::BTreeSet<usize>,
        delivered: Vec<usize>,
    }

    impl super::RecordSource for RetentionCheckedSource<'_> {
        fn len(&self) -> usize {
            self.source.len()
        }

        fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String> {
            self.source.bytes_at(offset, len)
        }

        fn retain_record(&mut self, offset: usize) -> Result<(), String> {
            assert!(self.pending.insert(offset));
            Ok(())
        }

        fn delivered_record_at(
            &mut self,
            offset: usize,
            end: usize,
        ) -> Result<super::PerfRecord<'_>, String> {
            assert!(
                self.pending.contains(&offset),
                "delivery must retain backing first"
            );
            self.delivered.push(offset);
            self.source.record_at(offset, end)
        }

        fn release_record(&mut self, offset: usize) {
            assert!(
                self.pending.remove(&offset),
                "release must balance retention"
            );
        }
    }

    #[test]
    fn replay_retains_backing_until_ordered_delivery_and_releases_on_parse_errors() {
        let layouts = super::SampleLayouts {
            fallback: Some(std::sync::Arc::new(super::SampleEventLayout::new(
                crate::perfdata::samples::SampleLayout {
                    sample_type: crate::perfdata::samples::PERF_SAMPLE_TIME,
                    read_format: 0,
                    branch_sample_type: 0,
                    sample_regs_user: 0,
                    sample_regs_intr: 0,
                    sample_id_all: true,
                },
                "cycles",
            ))),
            ..super::SampleLayouts::default()
        };
        for malformed in [false, true] {
            let mut bytes = Vec::new();
            for (comm, time) in [("later", 30_u64), ("earlier", 10)] {
                bytes.extend(if malformed { 1_u32 } else { 3 }.to_le_bytes());
                bytes.extend(0_u16.to_le_bytes());
                bytes.extend(32_u16.to_le_bytes());
                bytes.extend(11_u32.to_le_bytes());
                bytes.extend(12_u32.to_le_bytes());
                bytes.extend(comm.as_bytes());
                bytes.resize(bytes.len().next_multiple_of(8), 0);
                bytes.extend(time.to_le_bytes());
            }
            let header = super::PerfHeader {
                header_size: 0,
                attr_offset: 0,
                attr_size: 0,
                data_offset: 0,
                data_size: u64::try_from(bytes.len()).unwrap(),
            };
            let mut source = RetentionCheckedSource {
                source: super::SliceSource(&bytes),
                pending: std::collections::BTreeSet::new(),
                delivered: Vec::new(),
            };
            let mut sink = super::SampleSink::new(
                super::SessionState::new(std::collections::BTreeMap::new()),
                super::FoldedOutput::<super::NoopSymbolResolver>::new(None, false),
            );
            let result = super::replay_records(
                &mut source,
                header,
                &layouts,
                super::FoldOptions::default(),
                &mut sink,
            );
            if malformed {
                assert!(
                    result
                        .unwrap_err()
                        .contains("failed to parse record type 1")
                );
                assert_eq!(source.delivered, [32]);
                assert_eq!(source.pending, std::collections::BTreeSet::from([0]));
            } else {
                result.unwrap();
                assert_eq!(source.delivered, [32, 0]);
                assert!(source.pending.is_empty());
                assert_eq!(sink.accumulator.thread_comms[&12], "later");
            }
        }
    }

    #[test]
    fn ordered_backlog_retains_only_timestamp_and_record_location() {
        assert!(
            std::mem::size_of::<super::PendingFoldRecord>() <= 24,
            "ordering must not retain decoded records or sample payloads: {} bytes",
            std::mem::size_of::<super::PendingFoldRecord>()
        );
    }

    #[test]
    fn ordered_delivery_preserves_ties_and_one_round_lag_like_perf() {
        let mut queue = super::OrderedRecordQueue::default();
        queue.queue(24, 10);
        queue.queue(8, 10);
        queue.queue(16, 20);
        let mut delivered = Vec::new();
        queue
            .flush_round_with(|offset| {
                delivered.push(offset);
                Ok(())
            })
            .unwrap();
        assert!(delivered.is_empty());
        queue.queue(32, 30);
        queue
            .flush_round_with(|offset| {
                delivered.push(offset);
                Ok(())
            })
            .unwrap();
        assert_eq!(delivered, [8, 24, 16]);
        queue
            .flush_final_with(|offset| {
                delivered.push(offset);
                Ok(())
            })
            .unwrap();
        assert_eq!(delivered, [8, 24, 16, 32]);
    }

    #[test]
    fn ordered_delivery_resets_the_watermark_when_an_empty_queue_refills_like_perf() {
        // perf util/ordered-events.c:do_flush clears oe->last when empty;
        // queue_event then sets max_timestamp to the first new timestamp.
        // Older timestamps are counted as unordered, not rejected.
        let mut queue = super::OrderedRecordQueue::default();
        queue.queue(0, 100);
        queue.flush_round_with(|_| Ok(())).unwrap();
        queue.flush_round_with(|_| Ok(())).unwrap();
        assert!(queue.pending_records.is_empty());

        queue.queue(8, 10);
        let mut delivered = Vec::new();
        queue
            .flush_round_with(|offset| {
                delivered.push(offset);
                Ok(())
            })
            .unwrap();
        assert_eq!(delivered, [8]);
        queue.queue(16, 50);
        queue
            .flush_round_with(|offset| {
                delivered.push(offset);
                Ok(())
            })
            .unwrap();
        assert_eq!(delivered, [8], "new round must retain its one-round lag");
        queue
            .flush_final_with(|offset| {
                delivered.push(offset);
                Ok(())
            })
            .unwrap();
        assert_eq!(delivered, [8, 16]);
    }

    // tools/perf/util/header.c write_event_desc: nre(u32), attr_sz(u32), then
    // per event attr_sz attr bytes, nr(u32), do_write_string(name), nr u64 ids.
    fn event_desc_payload(events: &[(&str, &[u64])], attr_sz: usize) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend(
            u32::try_from(events.len())
                .expect("event count fits u32")
                .to_le_bytes(),
        );
        payload.extend(
            u32::try_from(attr_sz)
                .expect("attr size fits u32")
                .to_le_bytes(),
        );
        for (name, ids) in events {
            payload.extend(std::iter::repeat_n(0_u8, attr_sz));
            payload.extend(
                u32::try_from(ids.len())
                    .expect("id count fits u32")
                    .to_le_bytes(),
            );
            // do_write_string: u32 len = PERF_ALIGN(strlen+1, NAME_ALIGN=64),
            // then len bytes of NUL-terminated name plus zero padding.
            let aligned = (name.len() + 1).div_ceil(64) * 64;
            payload.extend(
                u32::try_from(aligned)
                    .expect("name length fits u32")
                    .to_le_bytes(),
            );
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

    #[derive(Default)]
    struct StaticFrameResolver {
        frames: Vec<String>,
        has_base_symbol: bool,
        has_inline_frames: bool,
        has_non_inline_base_frame: bool,
        base_offset: Option<u64>,
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
                    has_inline_frames: self.has_inline_frames,
                    has_non_inline_base_frame: self.has_non_inline_base_frame,
                    base_offset: self.base_offset,
                };
                requests.len()
            ])
        }
    }

    struct SplitFrameResolver;

    impl SymbolResolver for SplitFrameResolver {
        fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
            Ok(vec![None; requests.len()])
        }

        fn resolve_frame_batch_with_metadata(
            &self,
            requests: &[SymbolRequest],
        ) -> Result<Vec<ResolvedSymbolFrames>, String> {
            Ok(vec![
                ResolvedSymbolFrames {
                    frames: vec!["wrong_dwarf_leaf".to_string()],
                    has_base_symbol: true,
                    has_inline_frames: false,
                    has_non_inline_base_frame: true,
                    base_offset: None,
                };
                requests.len()
            ])
        }

        fn resolve_base_frame_batch_with_metadata(
            &self,
            requests: &[SymbolRequest],
        ) -> Result<Vec<ResolvedSymbolFrames>, String> {
            Ok(vec![
                ResolvedSymbolFrames {
                    frames: vec![
                        "pyroclast::parsers::strace::parse_strace_summary+0xaa0".to_string(),
                    ],
                    has_base_symbol: true,
                    has_inline_frames: false,
                    has_non_inline_base_frame: true,
                    base_offset: Some(0xaa0),
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
        full_batch_sizes: RefCell<Vec<usize>>,
        base_batch_sizes: RefCell<Vec<usize>>,
    }

    impl RecordingFrameResolver {
        fn resolved_for(requests: &[SymbolRequest]) -> Vec<ResolvedSymbolFrames> {
            requests
                .iter()
                .map(|request| ResolvedSymbolFrames {
                    frames: vec![format!("symbol_{:x}", request.relative_address)],
                    has_base_symbol: true,
                    has_inline_frames: false,
                    has_non_inline_base_frame: true,
                    base_offset: None,
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
            self.full_batch_sizes.borrow_mut().push(requests.len());
            self.full_requests
                .borrow_mut()
                .extend(requests.iter().map(|request| request.relative_address));
            Ok(Self::resolved_for(requests))
        }

        fn resolve_base_frame_batch_with_metadata(
            &self,
            requests: &[SymbolRequest],
        ) -> Result<Vec<ResolvedSymbolFrames>, String> {
            self.base_batch_sizes.borrow_mut().push(requests.len());
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
        let mut accumulator = super::SessionState::new(std::collections::BTreeMap::default());
        accumulator.apply_record(crate::perfdata::records::ParsedRecord::Mmap(
            crate::perfdata::records::MmapRecord {
                pid: 11,
                tid: 11,
                start: 0,
                len: 0x1000_0000,
                pgoff: 0,
                path: current_exe,
            },
        ));

        accumulator.apply_record(crate::perfdata::records::ParsedRecord::Fork(
            crate::perfdata::records::ForkRecord {
                pid: 22,
                ppid: 11,
                tid: 22,
                ptid: 11,
                time: 99,
                clone_maps: true,
            },
        ));

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
                false,
                vec![0x1000],
            ),
            vec![0x1000]
        );
    }

    #[test]
    fn object_unwind_keeps_short_fallback_stack_with_empty_callchain_like_perf_libdw() {
        // tools/perf/util/unwind-libdw.c does not filter accepted callbacks
        // based on whether PERF_SAMPLE_CALLCHAIN contributed recorded frames.
        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &test_regs(0x1000),
                super::SampleCallchainState::Other {
                    has_callchain: false,
                    has_frames: false,
                },
                false,
                vec![0x1000, 0x1100],
            ),
            vec![0x1000, 0x1100]
        );
    }

    #[test]
    fn object_unwind_acceptance_does_not_invent_sample_ip_for_empty_libdw_callbacks() {
        // tools/perf/util/unwind-libdw.c only appends frames accepted by
        // frame_callback -> entry after dwfl_getthread_frames runs. A captured
        // stack with no accepted callbacks and a sample that is NOT leaf-only
        // (`leaf_only == false`: e.g. CFI covers the IP) stays empty — the
        // sampled IP is never invented absent the scenario-D predicate.
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
                false,
                Vec::new(),
            ),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn folding_stores_repeated_normalized_frame_text_once_across_distinct_stacks() {
        let mut counts = super::FoldCounts::default();
        let leaf = "x".repeat(1024);
        for index in 0..100 {
            counts.add_rendered(&format!("root-{index};{leaf}"), 1);
        }
        assert!(
            counts.frame_text_bytes() < 4096,
            "retained {} bytes for 101 frame labels",
            counts.frame_text_bytes()
        );
    }

    #[test]
    fn fold_counts_coalesce_duplicate_rendered_lines() {
        let mut counts = super::FoldCounts::default();

        counts.add_rendered("alpha;beta", 2);
        counts.add_rendered("alpha;beta", 3);
        counts.add_rendered("alpha;gamma", 5);

        assert_eq!(counts.stacks.len(), 2);

        assert_eq!(counts.count_for_rendered("alpha;beta"), Some(5));
        assert_eq!(counts.count_for_rendered("alpha;gamma"), Some(5));
    }

    #[test]
    fn write_fold_counts_matches_string_sort_order() {
        let mut counts = super::FoldCounts::default();
        let mut expected = vec![
            ("zeta;leaf".to_string(), 4_u64),
            ("alpha;leaf".to_string(), 2_u64),
            ("alpha!;leaf".to_string(), 6_u64),
            ("alpha~;leaf".to_string(), 7_u64),
            ("alpha".to_string(), 8_u64),
            ("alpha;;leaf".to_string(), 9_u64),
            ("alpha\\;beta;leaf".to_string(), 10_u64),
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
    fn normalized_segment_ids_round_trip_delimiters_without_changing_stack_keys() {
        let mut counts = super::FoldCounts::default();
        for text in [
            ";",
            ";leaf",
            "root;",
            "root;;leaf",
            "root\\;leaf",
            "root\\\\;leaf",
        ] {
            let rendered = text.to_owned();
            let pointer = rendered.as_ptr();
            counts.add_stack(&rendered, 1);
            counts.add_stack(&rendered, 2);
            assert_eq!(rendered, text);
            assert_eq!(rendered.as_ptr(), pointer);
            let ids = counts.intern_normalized(text);
            assert_eq!(
                super::stack_bytes(&counts.names, &ids).collect::<Vec<_>>(),
                text.as_bytes()
            );
            assert_eq!(counts.count_for_rendered(text), Some(3));
        }
        assert_eq!(counts.stacks.len(), 6);
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
            has_inline_frames: false,
            has_non_inline_base_frame: false,
            base_offset: None,
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();

        super::FoldFrameResolver::new(&mmap_table, false)
            .render_folded_stack_for_stack(
                Some(11),
                Some("pyroclast"),
                [super::FoldFrame::InlineCurrentIp(0x5555_5567_6876)],
                Some(&mut symbol_cache),
                &mut buffers,
            )
            .expect("render folded stack");

        assert_eq!(buffers.rendered(), "pyroclast;[pyroclast]");
    }

    #[test]
    fn sample_ip_event_line_uses_base_symbol_with_offset_like_perf_machine_resolve() {
        // builtin-script.c process_sample_event() resolves the event-line IP
        // through machine__resolve(); util/event.c machine__resolve() sets
        // al->sym with map__find_symbol(), and evsel_fprintf.c
        // sample__fprintf_sym(cursor == NULL) prints
        // __symbol__fprintf_symname_offs(). It does not use the DWARF inline
        // expansion path used for callchain cursor rows.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x5555_5578_0000,
            len: 0x10_0000,
            pgoff: 0,
            path: "/bin/pyroclast".to_string(),
        });
        let resolver = SplitFrameResolver;
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut written = Vec::new();

        super::FoldFrameResolver::new(&mmap_table, true)
            .write_inline_sample_frame_for_stack(
                Some(11),
                &[super::FoldFrame::SampleIp {
                    address: 0x5555_5578_a940,
                    cpumode: crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_USER,
                }],
                Some(&mut symbol_cache),
                &mut written,
            )
            .expect("write sample ip frame");

        assert_eq!(
            String::from_utf8(written).expect("utf-8"),
            "    55555578a940 pyroclast::parsers::strace::parse_strace_summary+0xaa0 (/bin/pyroclast)"
        );
    }

    #[test]
    fn sample_ip_event_line_without_base_symbol_keeps_mapped_dso_like_perf_machine_resolve() {
        // evsel_fprintf.c sample__fprintf_sym(cursor == NULL) prints
        // __symbol__fprintf_symname_offs(al->sym, al, ...) and then
        // map__fprintf_dsoname_dsoff(al->map, ...). A mapped IP without a
        // symbol is therefore `[unknown] (full-dso-path)`, not Inferno's
        // basename fallback.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x5555_5578_0000,
            len: 0x10_0000,
            pgoff: 0,
            path: "/home/mjc/projects/pyroclast/target/profiling/pyroclast".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec!["wrong_dwarf_leaf".to_string()],
            has_base_symbol: false,
            has_inline_frames: false,
            has_non_inline_base_frame: false,
            base_offset: None,
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut written = Vec::new();

        super::FoldFrameResolver::new(&mmap_table, true)
            .write_inline_sample_frame_for_stack(
                Some(11),
                &[super::FoldFrame::SampleIp {
                    address: 0x5555_5578_b9b9,
                    cpumode: crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_USER,
                }],
                Some(&mut symbol_cache),
                &mut written,
            )
            .expect("write sample ip frame");

        assert_eq!(
            String::from_utf8(written).expect("utf-8"),
            "    55555578b9b9 [unknown] (/home/mjc/projects/pyroclast/target/profiling/pyroclast)"
        );
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
            has_inline_frames: false,
            has_non_inline_base_frame: true,
            base_offset: None,
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();

        super::FoldFrameResolver::new(&mmap_table, false)
            .render_folded_stack_for_stack(
                Some(11),
                Some("pyroclast"),
                [super::FoldFrame::InlineCurrentIp(0x5555_5567_a0be)],
                Some(&mut symbol_cache),
                &mut buffers,
            )
            .expect("render folded stack");

        assert_eq!(
            buffers.rendered(),
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
            has_inline_frames: false,
            has_non_inline_base_frame: false,
            base_offset: None,
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();

        super::FoldFrameResolver::new(&mmap_table, false)
            .render_folded_stack_for_stack(
                Some(11),
                Some("pyroclast"),
                [super::FoldFrame::InlineCurrentIp(0x5555_557a_e068)],
                Some(&mut symbol_cache),
                &mut buffers,
            )
            .expect("render folded stack");

        assert_eq!(buffers.rendered(), "pyroclast;[pyroclast]");
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
            has_inline_frames: true,
            has_non_inline_base_frame: false,
            base_offset: None,
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();

        super::FoldFrameResolver::new(&mmap_table, false)
            .render_folded_stack_for_stack(
                Some(11),
                Some("pyroclast"),
                [super::FoldFrame::InlineCurrentIp(0x5555_556f_bbbb)],
                Some(&mut symbol_cache),
                &mut buffers,
            )
            .expect("render folded stack");

        assert_eq!(
            buffers.rendered(),
            "pyroclast;add<&str>;sort8_stable<&str>;quicksort<&str>"
        );
    }

    #[test]
    fn inline_fold_keeps_abstract_origin_fn0_before_terminal_mix_like_perf_script() {
        // Renderer helpers fold the frame list supplied by symbol resolution.
        // The fn0-vs-mix parity question belongs to resolver construction, not
        // to a name-specific renderer filter.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x4000,
            len: 0x1000,
            pgoff: 0,
            path: "/tmp/entropy_burn_deep".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec!["fn0".to_string(), "mix".to_string()],
            has_base_symbol: true,
            has_inline_frames: true,
            has_non_inline_base_frame: false,
            base_offset: None,
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();

        super::FoldFrameResolver::new(&mmap_table, true)
            .render_folded_stack_for_stack(
                Some(11),
                Some("burn-00"),
                [super::FoldFrame::InlineCurrentIp(0x4010)],
                Some(&mut symbol_cache),
                &mut buffers,
            )
            .expect("render folded stack");

        assert_eq!(buffers.rendered(), "burn-00;fn0;mix");
    }

    #[test]
    fn inline_fold_keeps_abstract_origin_fn0_before_mix_for_user_unwind_chain_like_perf_script() {
        // Renderer helpers fold the resolved inline chain for every supplied
        // user-unwind entry; resolver parity decides which labels are present.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x4000,
            len: 0x1000,
            pgoff: 0,
            path: "/tmp/entropy_burn_deep".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec!["fn0".to_string(), "mix".to_string()],
            has_base_symbol: true,
            has_inline_frames: true,
            has_non_inline_base_frame: false,
            base_offset: None,
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();

        super::FoldFrameResolver::new(&mmap_table, true)
            .render_folded_stack_for_stack(
                Some(11),
                Some("burn-00"),
                [
                    super::FoldFrame::UserUnwind(0x4010),
                    super::FoldFrame::UserUnwind(0x4020),
                ],
                Some(&mut symbol_cache),
                &mut buffers,
            )
            .expect("render folded stack");

        assert_eq!(buffers.rendered(), "burn-00;fn0;mix;fn0;mix");
    }

    #[test]
    fn inline_fold_keeps_real_base_frame_and_abstract_origin_before_terminal_mix_like_perf_script()
    {
        // Renderer helpers preserve every frame returned by symbol resolution;
        // dropping a concrete or abstract-origin frame here would be a renderer
        // hack rather than a perf/libdw model.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x4000,
            len: 0x1000,
            pgoff: 0,
            path: "/tmp/entropy_burn_deep".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec!["fn124".to_string(), "fn0".to_string(), "mix".to_string()],
            has_base_symbol: true,
            has_inline_frames: true,
            has_non_inline_base_frame: false,
            base_offset: None,
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();

        super::FoldFrameResolver::new(&mmap_table, true)
            .render_folded_stack_for_stack(
                Some(11),
                Some("burn-00"),
                [super::FoldFrame::InlineCurrentIp(0x4010)],
                Some(&mut symbol_cache),
                &mut buffers,
            )
            .expect("render folded stack");

        assert_eq!(buffers.rendered(), "burn-00;fn124;fn0;mix");
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
            has_inline_frames: false,
            has_non_inline_base_frame: true,
            base_offset: None,
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
    fn inline_user_unwind_script_frame_keeps_trailing_base_symbol_like_perf_script() {
        // perf script prints inline frames leaf-first, then the trailing
        // non-inline base symbol with the DSO path. The inline-frame offset is
        // shared across the group: __symbol__fprintf_symname_offs uses
        // `al->addr - sym->start`, and an inline frame's fake symbol reuses
        // base_sym->start (srcline.c new_inline_sym).
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x1000,
            len: 0x1000,
            pgoff: 0,
            path: "/tmp/oracle-workload".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec![
                "workload::main".to_string(),
                "workload::churn_allocations".to_string(),
                "core::slice::<impl [T]>::sort_unstable".to_string(),
                "core::slice::sort::unstable::sort".to_string(),
            ],
            has_base_symbol: true,
            has_inline_frames: true,
            has_non_inline_base_frame: true,
            base_offset: Some(0x1fb),
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut written = Vec::new();

        super::FoldFrameResolver::new(&mmap_table, true)
            .write_script_frames_for_stack(
                Some(11),
                &[super::FoldFrame::UserUnwind(0x1427)],
                Some(&mut symbol_cache),
                &mut written,
            )
            .expect("write perf script frames");

        assert_eq!(
            String::from_utf8(written).expect("utf-8"),
            "\t            1427 core::slice::sort::unstable::sort+0x1fb (inlined)\n\
             \t            1427 core::slice::<impl [T]>::sort_unstable+0x1fb (inlined)\n\
             \t            1427 workload::churn_allocations+0x1fb (inlined)\n\
             \t            1427 workload::main+0x1fb (/tmp/oracle-workload)\n"
        );
    }

    #[test]
    fn inline_user_unwind_script_frame_marks_trailing_fake_inline_symbol_like_perf_script() {
        // tools/perf/util/libdw.c libdw_a2l_cb() passes dwarf_diename() to
        // srcline.c new_inline_sym(). If that name differs from base_sym->name,
        // perf creates a fake symbol with sym->inlined = 1. evsel_fprintf.c
        // then suppresses the DSO and prints "(inlined)" even for the final row.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x1000,
            len: 0x1000,
            pgoff: 0,
            path: "/tmp/sftp-s3".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec![
                "new_lookup<Reader>".to_string(),
                "{closure#0}<Reader>".to_string(),
            ],
            has_base_symbol: true,
            has_inline_frames: true,
            has_non_inline_base_frame: false,
            base_offset: Some(0x531),
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut written = Vec::new();

        super::FoldFrameResolver::new(&mmap_table, true)
            .write_script_frames_for_stack(
                Some(11),
                &[super::FoldFrame::UserUnwind(0x1427)],
                Some(&mut symbol_cache),
                &mut written,
            )
            .expect("write perf script frames");

        assert_eq!(
            String::from_utf8(written).expect("utf-8"),
            "\t            1427 {closure#0}<Reader>+0x531 (inlined)\n\
             \t            1427 new_lookup<Reader>+0x531 (inlined)\n"
        );
    }

    #[test]
    fn single_surviving_inline_user_unwind_script_frame_prints_inlined_like_perf_script() {
        // perf util/machine.c append_inlines() suppresses the ordinary base
        // append when inline symbols were appended. If perf util/addr2line.c
        // then drops the concrete `fn0` record as a non-first GNU sentinel,
        // builtin-script still prints the one remaining inline symbol with
        // `(inlined)` and no DSO path.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x4000,
            len: 0x1000,
            pgoff: 0,
            path: "/tmp/fake-perfdata-work/entropy_burn".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec!["mix".to_string()],
            has_base_symbol: true,
            has_inline_frames: true,
            has_non_inline_base_frame: false,
            base_offset: Some(0x4b),
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut written = Vec::new();

        super::FoldFrameResolver::new(&mmap_table, true)
            .write_script_frames_for_stack(
                Some(11),
                &[super::FoldFrame::UserUnwind(0x449b)],
                Some(&mut symbol_cache),
                &mut written,
            )
            .expect("write perf script frames");

        assert_eq!(
            String::from_utf8(written).expect("utf-8"),
            "\t            449b mix+0x4b (inlined)\n"
        );
    }

    #[test]
    fn single_base_user_unwind_script_frame_keeps_its_baked_offset_once_like_perf_script() {
        // A non-inline base frame already carries +0x<off> in its label from the
        // symtab with_offset form; it must not be doubled in inline-capable mode.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x1000,
            len: 0x1000,
            pgoff: 0,
            path: "/tmp/oracle-workload".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec!["core::slice::sort::unstable::quicksort::quicksort+0x6cb".to_string()],
            has_base_symbol: true,
            has_inline_frames: false,
            has_non_inline_base_frame: true,
            base_offset: Some(0x6cb),
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut written = Vec::new();

        super::FoldFrameResolver::new(&mmap_table, true)
            .write_script_frames_for_stack(
                Some(11),
                &[super::FoldFrame::UserUnwind(0x16cb)],
                Some(&mut symbol_cache),
                &mut written,
            )
            .expect("write perf script frames");

        assert_eq!(
            String::from_utf8(written).expect("utf-8"),
            "\t            16cb core::slice::sort::unstable::quicksort::quicksort+0x6cb (/tmp/oracle-workload)\n"
        );
    }

    #[test]
    fn inferno_perf_render_cache_keeps_raw_functions_separate_from_folded_labels() {
        let mut buffers = super::FoldedRenderBuffers::default();

        super::append_cached_inferno_perf_folded_label_to_buffers(&mut buffers, "handler+0x2a");
        assert_eq!(buffers.rendered(), "handler+0x2a");

        buffers.current.clear();
        super::append_cached_inferno_perf_raw_function_to_buffers(&mut buffers, "handler+0x2a");

        assert_eq!(buffers.rendered(), "handler");
    }

    #[test]
    fn serialized_raw_symbols_append_without_owned_frame_segments() {
        let mut buffers = super::FoldedRenderBuffers::default();
        super::append_cached_inferno_perf_raw_function_to_buffers(&mut buffers, "leaf->inner+0x2a");
        assert_eq!(buffers.rendered(), "leaf;inner_[i]");
        assert_eq!(buffers.current.len(), "leaf;inner_[i]".len());
    }

    #[test]
    fn serialized_labels_append_escaped_bytes_without_owned_frame_segments() {
        let mut buffers = super::FoldedRenderBuffers::default();
        super::append_cached_inferno_perf_folded_label_to_buffers(&mut buffers, "root;leaf\n");
        assert_eq!(buffers.rendered(), "root\\;leaf ");
        assert_eq!(buffers.current.len(), "root\\;leaf ".len());
    }

    #[test]
    fn serialized_addresses_append_without_owned_frame_segments() {
        let mut buffers = super::FoldedRenderBuffers::default();
        super::append_folded_address_label(&mut buffers, u64::MAX);
        assert_eq!(buffers.rendered(), "0xffffffffffffffff");
        assert_eq!(buffers.current.len(), "0xffffffffffffffff".len());
    }

    #[test]
    fn delivered_samples_reuse_serialized_comm_and_stack_storage() {
        use super::SampleOutput as _;
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        state.thread_comms.insert(7, "worker task".into());
        let sample = prepared_sample(&[super::FoldFrame::UserUnwind(0x1010)]);
        let mut output = super::FoldedOutput::<super::NoopSymbolResolver>::new(None, false);
        output.write_sample_event(&state, &sample).unwrap();
        assert_eq!(output.buffers.rendered(), "worker_task;[unknown]");
        let capacity = output.buffers.current.capacity();
        output.write_sample_event(&state, &sample).unwrap();
        assert_eq!(output.buffers.rendered(), "worker_task;[unknown]");
        assert_eq!(output.buffers.current.capacity(), capacity);
        assert_eq!(
            output
                .buffers
                .counts
                .count_for_rendered("worker_task;[unknown]"),
            Some(2)
        );
    }

    #[test]
    fn serialized_symbol_stacks_match_native_inferno_normalization() {
        use inferno::collapse::Collapse as _;
        use std::fmt::Write as _;

        // Inferno perf.rs:on_stack_line normalizes each raw function, and
        // after_event inserts its final serialized stack into Occurrences.
        let cases: &[&[&str]] = &[
            &["root", "leaf+0x2a"],
            &["root", "outer->inner"],
            &["root", "->inner"],
            &["root", "outer", "inner_[i]"],
            &["root", "with<T>(argument)", "net/http.(*Client).Do"],
            &["root", "java;semi"],
            &["root", "(process-name)", "leaf"],
            &["root", "_$LT$std..fs..ReadDir$GT$::next::hc14f1750ca79129b"],
            &["root", "unicode_\u{e9}+0x10"],
        ];
        let mut script = String::new();
        let mut buffers = super::FoldedRenderBuffers::default();
        for (index, frames) in cases.iter().enumerate() {
            let count = index as u64 + 1;
            writeln!(script, "worker 7 1.000000: {count} cycles:").unwrap();
            for frame in frames.iter().rev() {
                writeln!(script, "\t1010 {frame} (/bin/demo)").unwrap();
            }
            script.push('\n');
            buffers.current.clear();
            super::append_cached_inferno_perf_folded_label_to_buffers(&mut buffers, "worker");
            for frame in *frames {
                super::append_cached_inferno_perf_raw_function_to_buffers(&mut buffers, frame);
            }
            buffers.counts.add_stack(&buffers.current, count);
        }
        let mut expected = Vec::new();
        let mut options = inferno::collapse::perf::Options::default();
        options.nthreads = 1;
        inferno::collapse::perf::Folder::from(options)
            .collapse(std::io::Cursor::new(script), &mut expected)
            .unwrap();
        let mut actual = Vec::new();
        super::write_fold_counts(buffers.counts, &mut actual).unwrap();
        assert!(!expected.is_empty());
        assert_eq!(actual, expected);
    }

    #[test]
    fn delivered_deep_stacks_reverse_once_and_filter_context_markers() {
        use super::SampleOutput as _;
        use std::fmt::Write as _;
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        state.thread_comms.insert(7, "worker".into());
        let mut frames = Vec::new();
        for index in 1..=40 {
            state
                .mmap_table
                .insert_mmap(crate::perfdata::records::MmapRecord {
                    pid: 7,
                    tid: 7,
                    start: index * 0x1000,
                    len: 0x100,
                    pgoff: 0,
                    path: format!("/bin/frame-{index}"),
                });
            frames.push(super::FoldFrame::UserUnwind(index * 0x1000 + 0x10));
            if index == 20 {
                frames.push(super::FoldFrame::Callchain(super::PERF_CONTEXT_USER));
            }
        }
        let sample = prepared_sample(&frames);
        let original = sample.frames.clone();
        let mut output = super::FoldedOutput::<super::NoopSymbolResolver>::new(None, false);
        output.write_sample_event(&state, &sample).unwrap();
        let expected = (1..=40)
            .rev()
            .fold(String::from("worker"), |mut text, index| {
                write!(text, ";[frame-{index}]").unwrap();
                text
            });
        assert_eq!(output.buffers.rendered(), expected);
        assert_eq!(
            output.buffers.counts.count_for_rendered(expected.as_str()),
            Some(1)
        );
        assert_eq!(sample.frames, original);
    }

    #[test]
    fn symbol_cache_hits_resolve_each_frame_mapping_once() {
        use super::SampleOutput as _;
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        state.thread_comms.insert(7, "worker".into());
        for start in [0x1000, 0x2000] {
            state
                .mmap_table
                .insert_mmap(crate::perfdata::records::MmapRecord {
                    pid: 7,
                    tid: 7,
                    start,
                    len: 0x100,
                    pgoff: 0,
                    path: format!("/bin/app-{start:x}"),
                });
        }
        let resolver = RecordingFrameResolver::default();
        let mut cache = SymbolFrameCache::new(&resolver);
        let mut output = super::FoldedOutput::new(Some(&mut cache), true);
        let sample = prepared_sample(&[
            super::FoldFrame::UserUnwind(0x1010),
            super::FoldFrame::UserUnwind(0x2010),
            super::FoldFrame::UserUnwind(0x1020),
            super::FoldFrame::UserUnwind(0x2020),
        ]);
        output.write_sample_event(&state, &sample).unwrap();
        let searches = state.mmap_table.index_search_count();
        let buckets = state.mmap_table.bucket_search_count();
        output.write_sample_event(&state, &sample).unwrap();
        assert_eq!(
            state.mmap_table.index_search_count() - searches,
            4,
            "cached samples should not scan their mappings again for prefetch"
        );
        assert_eq!(
            state.mmap_table.bucket_search_count() - buckets,
            2,
            "one PID bucket and one global bucket per sample, not per frame"
        );
        assert_eq!(resolver.full_requests.borrow().len(), 4);
        assert_eq!(output.buffers.counts.stacks.len(), 1);
    }

    fn metadata_test_layouts() -> super::SampleLayouts {
        super::SampleLayouts {
            fallback: Some(std::sync::Arc::new(super::SampleEventLayout::new(
                crate::perfdata::samples::SampleLayout {
                    sample_type: super::PERF_SAMPLE_IP,
                    read_format: 0,
                    branch_sample_type: 0,
                    sample_regs_user: 0,
                    sample_regs_intr: 0,
                    sample_id_all: false,
                },
                "cycles",
            ))),
            ..Default::default()
        }
    }

    #[test]
    fn fixed_sample_offsets_follow_perf_evsel_for_all_prefix_field_combinations() {
        // tools/perf/util/evsel.c:__perf_evsel__calc_id_pos() gives identifier
        // precedence; evsel__parse_sample_timestamp() walks identifier/IP/TID.
        let fields = [
            super::PERF_SAMPLE_IDENTIFIER,
            super::PERF_SAMPLE_IP,
            super::PERF_SAMPLE_TID,
            super::PERF_SAMPLE_TIME,
            super::PERF_SAMPLE_ADDR,
            super::PERF_SAMPLE_ID,
        ];
        for mask in 0..64 {
            let mut sample_type = 0;
            let mut payload = Vec::new();
            let mut expected_id = None;
            let mut expected_time = None;
            for (index, field) in fields.iter().copied().enumerate() {
                if mask & (1 << index) == 0 {
                    continue;
                }
                sample_type |= field;
                let value = 100 + index as u64;
                if field == super::PERF_SAMPLE_IDENTIFIER
                    || (field == super::PERF_SAMPLE_ID && expected_id.is_none())
                {
                    expected_id = Some(value);
                }
                if field == super::PERF_SAMPLE_TIME {
                    expected_time = Some(value);
                }
                payload.extend(value.to_le_bytes());
            }
            let offsets = super::SampleOffsets::new(sample_type);
            assert_eq!(
                offsets
                    .id
                    .map(|offset| super::read_sample_u64(&payload, offset).unwrap()),
                expected_id
            );
            assert_eq!(
                offsets
                    .time
                    .map(|offset| super::read_u64(&payload, offset).unwrap()),
                expected_time
            );
            for offset in [offsets.id, offsets.time].into_iter().flatten() {
                assert!(super::read_sample_u64(&payload[..offset + 7], offset).is_err());
            }
        }
    }

    #[test]
    fn sample_layout_selection_borrows_without_arc_reference_churn() {
        let layouts = metadata_test_layouts();
        let stored = layouts.fallback.as_ref().unwrap();
        let owners = std::sync::Arc::strong_count(stored);
        let selected = layouts
            .layout_for_payload(&0x1010_u64.to_le_bytes())
            .unwrap()
            .unwrap();
        assert!(std::ptr::eq(selected, stored.as_ref()));
        assert_eq!(std::sync::Arc::strong_count(stored), owners);
    }

    #[test]
    fn identified_layouts_borrow_selected_or_fallback_and_reject_truncation() {
        let mut layouts = metadata_test_layouts();
        let mut layout = layouts.fallback.as_ref().unwrap().layout;
        layout.sample_type |= super::PERF_SAMPLE_IDENTIFIER;
        layouts.fallback = Some(std::sync::Arc::new(super::SampleEventLayout::new(
            layout, "cycles",
        )));
        let selected = std::sync::Arc::new(super::SampleEventLayout::new(layout, "instructions"));
        layouts.by_identifier.insert(12, selected.clone());
        for identifier in [12_u64, 13] {
            let event = layouts
                .layout_for_payload(&identifier.to_le_bytes())
                .unwrap()
                .unwrap();
            let expected = if identifier == 12 {
                selected.as_ref()
            } else {
                layouts.fallback.as_deref().unwrap()
            };
            assert!(std::ptr::eq(event, expected));
            assert_eq!(std::sync::Arc::strong_count(&selected), 2);
            assert_eq!(
                std::sync::Arc::strong_count(layouts.fallback.as_ref().unwrap()),
                1
            );
        }
        assert!(
            layouts
                .layout_for_payload(&[])
                .unwrap_err()
                .contains("truncated")
        );
    }

    #[test]
    fn lazy_symbol_misses_batch_the_sample_and_keep_base_and_inline_results_separate() {
        use super::SampleOutput as _;
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        state.thread_comms.insert(7, "worker".into());
        state
            .mmap_table
            .insert_mmap(crate::perfdata::records::MmapRecord {
                pid: 7,
                tid: 7,
                start: 0x1000,
                len: 0x100,
                pgoff: 0,
                path: "/bin/app".into(),
            });
        let resolver = RecordingFrameResolver::default();
        let mut cache = SymbolFrameCache::new(&resolver);
        let sample = prepared_sample(&[
            super::FoldFrame::SampleIp {
                address: 0x1010,
                cpumode: super::PERF_RECORD_MISC_CPUMODE_USER,
            },
            super::FoldFrame::InlineCurrentIp(0x1010),
            super::FoldFrame::UserUnwind(0x1020),
            super::FoldFrame::UserUnwind(0x1020),
        ]);
        let mut output = super::FoldedOutput::new(Some(&mut cache), true);
        for _ in 0..2 {
            output.write_sample_event(&state, &sample).unwrap();
        }
        assert_eq!(*resolver.full_batch_sizes.borrow(), [2]);
        assert_eq!(*resolver.base_batch_sizes.borrow(), [1]);
        assert_eq!(*resolver.full_requests.borrow(), [0x20, 0x10]);
        assert_eq!(*resolver.base_requests.borrow(), [0x10]);
        assert_eq!(
            output.buffers.current,
            "worker;symbol_20;symbol_20;symbol_10;symbol_10"
        );
    }

    #[test]
    fn lazy_symbol_hits_use_current_mapping_source_after_replacement() {
        use super::SampleOutput as _;
        for inline in [false, true] {
            let mut state = super::SessionState::new(std::collections::BTreeMap::new());
            let resolver = RecordingFrameResolver::default();
            let mut cache = SymbolFrameCache::new(&resolver);
            let mut output = super::FoldedOutput::new(Some(&mut cache), inline);
            let sample = prepared_sample(&[super::FoldFrame::UserUnwind(0x1010)]);
            for path in ["/bin/first", "/bin/replacement"] {
                state
                    .mmap_table
                    .insert_mmap(crate::perfdata::records::MmapRecord {
                        pid: 7,
                        tid: 7,
                        start: 0x1000,
                        len: 0x100,
                        pgoff: 0,
                        path: path.into(),
                    });
                for _ in 0..2 {
                    output.write_sample_event(&state, &sample).unwrap();
                }
            }
            let (requests, batches) = if inline {
                (
                    resolver.full_requests.borrow(),
                    resolver.full_batch_sizes.borrow(),
                )
            } else {
                (
                    resolver.base_requests.borrow(),
                    resolver.base_batch_sizes.borrow(),
                )
            };
            assert_eq!(*requests, [0x10, 0x10]);
            assert_eq!(*batches, [1, 1]);
        }
    }

    #[test]
    fn prepared_samples_borrow_event_names_until_deferred_ownership_is_needed() {
        let layouts = metadata_test_layouts();
        let stored_name = &layouts.fallback.as_ref().unwrap().event_name;
        let owners = std::sync::Arc::strong_count(stored_name);
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        let sample = super::prepare_sample_for_fold(
            &mut state,
            super::PERF_RECORD_MISC_CPUMODE_USER,
            &0x1010_u64.to_le_bytes(),
            &layouts,
            super::FoldOptions::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(sample.event_name, "cycles");
        assert_eq!(std::sync::Arc::strong_count(stored_name), owners);
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

    fn prepared_sample(frames: &[super::FoldFrame]) -> super::PreparedFoldSample<'static> {
        super::PreparedFoldSample {
            pid: Some(7),
            tid: Some(7),
            time: None,
            cpu: None,
            event_name: "cpu-clock",
            count: 1,
            frames: frames.iter().copied().collect(),
            deferred_cookie: None,
            has_callchain: true,
        }
    }

    #[test]
    fn delivered_samples_retain_only_distinct_normalized_stacks() {
        use super::SampleOutput as _;
        // Inferno after_event() counts final normalized stacks. Distinct raw
        // addresses that all print [unknown] must not build a raw-IP arena.
        let state = super::SessionState::new(std::collections::BTreeMap::new());
        let mut output = super::FoldedOutput::<super::NoopSymbolResolver>::new(None, false);
        for _ in 0..2 {
            for address in 1..=4096 {
                output
                    .write_sample_event(
                        &state,
                        &prepared_sample(&[super::FoldFrame::UserUnwind(address)]),
                    )
                    .unwrap();
            }
        }
        assert_eq!(output.buffers.counts.stacks.len(), 1);
        assert!(output.buffers.counts.stacks.capacity() < 1024);
        assert!(output.buffers.counts.by_name.capacity() < 1024);
        assert_eq!(
            output
                .buffers
                .counts
                .stacks
                .values()
                .copied()
                .collect::<Vec<_>>(),
            [8192]
        );
        assert!(state.deferred_samples.is_empty());
    }

    #[test]
    fn delivered_user_unwind_frames_resolve_before_mapping_replacement() {
        use super::SampleOutput as _;
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        state.thread_comms.insert(7, "pyroclast".into());
        let mut output = super::FoldedOutput::<super::NoopSymbolResolver>::new(None, false);
        for path in ["/tmp/perf.data", "/bin/demo"] {
            state
                .mmap_table
                .insert_mmap(crate::perfdata::records::MmapRecord {
                    pid: 7,
                    tid: 7,
                    start: 0x1000,
                    len: 0x100,
                    pgoff: 0,
                    path: path.into(),
                });
            output
                .write_sample_event(
                    &state,
                    &prepared_sample(&[super::FoldFrame::UserUnwind(0x1010)]),
                )
                .unwrap();
        }
        let mut written = Vec::new();
        super::write_fold_counts(output.buffers.counts, &mut written).unwrap();
        assert_eq!(
            String::from_utf8(written).unwrap(),
            "pyroclast;[demo] 1\npyroclast;[perf.data] 1\n"
        );
    }

    #[test]
    fn user_unwind_frame_does_not_resolve_through_global_mapping_like_perf_libdw() {
        // unwind-libdw.c __report_module()/access_dso_mem() use USER maps.
        let mut table = super::MmapTable::default();
        table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: u32::MAX,
            tid: u32::MAX,
            start: 0x1000,
            len: 0x100,
            pgoff: 0,
            path: "/bin/demo".into(),
        });
        assert!(
            super::resolve_frame_in_context(
                Some(&table.frame_context(7, &mut super::MappingResolveCache::default())),
                super::FoldFrame::UserUnwind(0x1010),
                &mut super::MappingResolveCache::default()
            )
            .is_none()
        );
    }

    #[test]
    fn user_unwind_resolution_ignores_same_pid_kernel_mappings_like_perf_libdw_user_lookup() {
        // perf's thread__find_map(... PERF_RECORD_MISC_USER ...) searches the
        // thread's user maps. Kernel-cpumode maps live in machine__kernel_maps()
        // and must not symbolize libdw user-unwind entries, even when the raw
        // mmap record carries the same pid.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap_with_misc(
            crate::perfdata::records::MmapRecord {
                pid: 7,
                tid: 7,
                start: 0xffff_ffff_8100_0000,
                len: 0x1000,
                pgoff: 0,
                path: "[kernel.kallsyms]".to_string(),
            },
            crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
        );

        let mut written = Vec::new();
        super::FoldFrameResolver::new(&mmap_table, false)
            .write_script_frames_for_stack(
                Some(7),
                &[super::FoldFrame::UserUnwind(0xffff_ffff_8100_0010)],
                None::<&mut SymbolFrameCache<'_, super::NoopSymbolResolver>>,
                &mut written,
            )
            .expect("write perf script frames");

        assert_eq!(
            String::from_utf8(written).expect("utf-8"),
            "\tffffffff81000010 [unknown] ([unknown])\n"
        );
    }

    #[test]
    fn sample_symbol_resolution_deduplicates_addresses_and_expands_seed_inlines() {
        let mut table = super::MmapTable::default();
        table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x1000,
            len: 0x1000,
            pgoff: 0,
            path: "/bin/demo".into(),
        });
        let resolver = RecordingFrameResolver::default();
        let mut cache = SymbolFrameCache::new(&resolver);
        let frames = [
            super::FoldFrame::UserUnwind(0x1010),
            super::FoldFrame::InlineCurrentIp(0x1020),
            super::FoldFrame::UserUnwind(0x1010),
        ];
        for _ in 0..2 {
            let mut mapping_cache = super::MappingResolveCache::default();
            let context = table.frame_context(11, &mut mapping_cache);
            super::prefetch_sample_symbols(
                frames.iter().copied(),
                Some(&context),
                &mut mapping_cache,
                &mut cache,
                true,
            )
            .unwrap();
        }
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
                module_count: 1,
                frame_pointer_at_or_above_stack_pointer: true,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_uses_object_unwind_for_kernel_sample_with_empty_callchain_like_perf_libdw()
     {
        // Real period 4745147 sample from target/profiling-runs/octo-latest-fold/profile.raw.perf.data:
        // perf script records a kernel-mode IP and an empty PERF_SAMPLE_CALLCHAIN
        // payload, but still calls libdw with the captured user regs/stack and
        // emits the user-space memmove leaf.
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::KernelWithoutCallchain,
                initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
                module_count: 1,
                frame_pointer_at_or_above_stack_pointer: false,
                syscall_return_state: false,
            }),
            super::UserUnwindSource::Object
        );
    }

    #[test]
    fn user_unwind_source_attempts_kernel_sample_with_empty_callchain_from_executable_like_perf_libdw()
     {
        // builtin-script.c has already passed the `sample->callchain` gate
        // because the PERF_SAMPLE_CALLCHAIN payload is present. From there,
        // tools/perf/util/machine.c thread__resolve_callchain_unwind() only
        // requires PERF_SAMPLE_REGS_USER, PERF_SAMPLE_STACK_USER, user regs,
        // and a non-empty user stack. tools/perf/util/unwind-libdw.c then calls
        // report_module(ip).
        assert_eq!(
            super::choose_user_unwind_source(super::UserUnwindContext {
                sample_callchain: super::SampleCallchainPresence::Present,
                callchain: super::SampleCallchainState::KernelWithoutCallchain,
                initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
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
                false,
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
                false,
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
                false,
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
        let mut accumulator = super::SessionState::new(std::collections::BTreeMap::new());
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
        let mut accumulator = super::SessionState::new(std::collections::BTreeMap::new());
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
        let mut accumulator = super::SessionState::new(std::collections::BTreeMap::new());
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

        accumulator.apply_record(crate::perfdata::records::ParsedRecord::Fork(
            crate::perfdata::records::ForkRecord {
                pid: 11,
                tid: 11,
                ppid: 10,
                ptid: 10,
                time: 0,
                clone_maps: false,
            },
        ));

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
        let mut accumulator = super::SessionState::new(std::collections::BTreeMap::new());
        accumulator.apply_record(crate::perfdata::records::ParsedRecord::Mmap(
            crate::perfdata::records::MmapRecord {
                pid: 11,
                tid: 11,
                start: 0x5555_5555_4000,
                len: 0x002b_e000,
                pgoff: 0,
                path: current_exe.clone(),
            },
        ));
        accumulator.ensure_unwind_mapping_for_ip(Some(11), 0x5555_5555_5000);
        assert!(accumulator.unwind_states.contains_key(&11));

        accumulator.apply_record(crate::perfdata::records::ParsedRecord::Mmap2(
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
        ));

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
        let mut accumulator = super::SessionState::new(std::collections::BTreeMap::new());
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
        let mut accumulator = super::SessionState::new(std::collections::BTreeMap::new());
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
                false,
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
                false,
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
                false,
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
    fn empty_object_unwind_arch_fallback_requires_initial_reported_module_like_perf_libdw() {
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
            module_count: 1,
            frame_pointer_at_or_above_stack_pointer: true,
            syscall_return_state: true,
        };
        assert!(
            super::should_use_libdw_arch_fallback_after_empty_object_unwind(matching_context, true)
        );

        assert!(
            !super::should_use_libdw_arch_fallback_after_empty_object_unwind(
                super::UserUnwindContext {
                    initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
                    ..matching_context
                },
                false
            ),
            "perf unwind__get_entries exits before dwfl_getthread_frames when report_module(ip) fails"
        );
        assert!(
            !super::should_use_libdw_arch_fallback_after_empty_object_unwind(
                super::UserUnwindContext { ..matching_context },
                false
            ),
            "perf frame_callback reaches ebl_unwind only after the initial IP module is reported"
        );
        assert!(
            !super::should_use_libdw_arch_fallback_after_empty_object_unwind(
                super::UserUnwindContext {
                    syscall_return_state: false,
                    ..matching_context
                },
                false
            ),
            "non-syscall samples still need perf's initial report_module(ip) success"
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
    fn object_unwind_keeps_kernel_empty_callchain_dso_tail_like_perf_libdw() {
        // Real period 144 __strlen_avx2 sample from
        // target/profiling-runs/octo-latest-fold/profile.raw.perf.data:
        // perf script records a kernel-mode sampled IP with a present-but-empty
        // callchain payload, then libdw emits the captured user-space leaf and
        // bash callers. In perf util/unwind-libdw.c, frame_callback reports
        // every accepted frame via entry(); there is no kernel-empty-callchain
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
                false,
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
    fn serialized_module_fallback_reuses_final_stack_storage() {
        let mapping = super::ResolvedMappingRef {
            symbol_source_id: 0,
            path: "/usr/lib/libdemo.so",
            relative_address: 0x1234,
            start: 0,
            end: u64::MAX,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        };
        let mut buffers = super::FoldedRenderBuffers::default();
        super::append_mapping_fallback(&mut buffers, &mapping);
        assert_eq!(buffers.current, "[libdemo.so]");
        let pointer = buffers.current.as_ptr();
        for _ in 0..64 {
            buffers.current.clear();
            super::append_mapping_fallback(&mut buffers, &mapping);
            assert_eq!(buffers.current, "[libdemo.so]");
            assert_eq!(buffers.current.as_ptr(), pointer);
        }
    }

    #[test]
    fn serialized_module_fallback_replaces_semicolons_like_inferno_tidy_generic() {
        let mapping = super::ResolvedMappingRef {
            symbol_source_id: 0,
            path: "/tmp/a;b\\c\r\n\u{e9}",
            relative_address: 0x1234,
            start: 0,
            end: u64::MAX,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        };
        let mut buffers = super::FoldedRenderBuffers::default();
        super::append_mapping_fallback(&mut buffers, &mapping);
        assert_eq!(buffers.rendered(), "[a:b\\c  \u{e9}]");
        assert_eq!(
            buffers.current.len(),
            "[a:b\\c  \u{e9}]".len(),
            "serialized bytes do not require delimiter segmentation"
        );
    }

    #[test]
    fn serialized_module_fallback_normalizes_delimiters_and_preserves_bracket_names() {
        for (path, address, expected) in [
            ("/usr/lib/libdemo.so", 0x1234, "[libdemo.so]"),
            ("[vdso]", 0x10, "[[vdso]]"),
            ("/tmp/semi;line\nname", 0x10, "[semi:line name]"),
            ("[unknown]", 0x10, "[unknown]"),
            ("[kernel.kallsyms]", u64::MAX - 1, "[[kernel.kallsyms]]"),
        ] {
            let mapping = super::ResolvedMappingRef {
                symbol_source_id: 0,
                path,
                relative_address: address,
                start: 0,
                end: u64::MAX,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            };
            let mut buffers = super::FoldedRenderBuffers::default();
            for _ in 0..2 {
                buffers.current.clear();
                super::append_mapping_fallback(&mut buffers, &mapping);
                assert_eq!(buffers.rendered(), expected);
                assert!(buffers.counts.stacks.is_empty());
            }
        }
    }

    #[test]
    fn serialized_frames_coalesce_equivalent_normalized_expansions() {
        let mut buffers = super::FoldedRenderBuffers::default();
        super::append_cached_inferno_perf_raw_function_to_buffers(&mut buffers, "leaf->inner");
        let expanded = buffers.current.clone();
        buffers.current.clear();
        super::append_cached_inferno_perf_raw_function_to_buffers(&mut buffers, "leaf");
        super::append_cached_inferno_perf_raw_function_to_buffers(&mut buffers, "inner_[i]");
        assert_eq!(buffers.current, expanded);
        buffers.counts.add_stack(&expanded, 2);
        buffers.counts.add_stack(&buffers.current, 3);
        let mut written = Vec::new();
        super::write_fold_counts(buffers.counts, &mut written).unwrap();
        assert_eq!(written, b"leaf;inner_[i] 5\n");
    }

    #[test]
    fn module_fallback_uses_literal_basename_and_normalization_like_native_inferno() {
        use super::SampleOutput as _;
        use inferno::collapse::Collapse as _;
        use std::fmt::Write as _;
        let mut script = String::new();
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        state.thread_comms.insert(7, "worker".into());
        let resolver = super::NoopSymbolResolver;
        let mut cache = SymbolFrameCache::new(&resolver);
        let mut output = super::FoldedOutput::new(Some(&mut cache), true);
        for path in [
            "/usr/lib/demo.so",
            "/tmp/demo/",
            "/",
            "/tmp/a;name.so",
            "/tmp/demo///",
            "/tmp/\u{e9}.so",
            "/tmp/\u{4e2d}\u{6587}.so",
            "/tmp/\u{1f642};\u{e9}.so",
            "/tmp/demo(args).so",
            "/tmp/demo->inner.so",
            "/tmp/demo;other->inner(args).so",
            "/tmp/demo<fn(args)>.so",
            "/tmp/(anonymous namespace).so",
            "/tmp/a b.so",
            "/tmp/a (nested)",
            "[vdso]",
            "[unknown]",
        ] {
            state
                .mmap_table
                .insert_mmap(crate::perfdata::records::MmapRecord {
                    pid: 7,
                    tid: 7,
                    start: 0x1000,
                    len: 0x100,
                    pgoff: 0,
                    path: path.into(),
                });
            for _ in 0..2 {
                writeln!(
                    script,
                    "worker 7 1.000000: 1 cycles:\n\t1010 [unknown] ({path})\n"
                )
                .unwrap();
                output
                    .write_sample_event(
                        &state,
                        &prepared_sample(&[super::FoldFrame::UserUnwind(0x1010)]),
                    )
                    .unwrap();
            }
        }
        let mut options = inferno::collapse::perf::Options::default();
        options.nthreads = 1;
        let mut expected = Vec::new();
        inferno::collapse::perf::Folder::from(options)
            .collapse(std::io::Cursor::new(script), &mut expected)
            .unwrap();
        let mut actual = Vec::new();
        super::write_fold_counts(output.buffers.counts, &mut actual).unwrap();
        assert!(!expected.is_empty());
        assert_eq!(actual, expected);
    }

    fn other_callchain() -> super::SampleCallchainState {
        super::SampleCallchainState::Other {
            has_callchain: true,
            has_frames: false,
        }
    }

    #[test]
    fn arch_fallback_cannot_advance_only_when_x86_bp_below_sp() {
        // backends/x86_64_unwind.c: the rbp fallback writes new_sp = fp + 16
        // and rejects the frame with `if (sp >= fp) return false;` — i.e. it
        // advances only when the frame pointer sits above the stack pointer.
        // pyroclast attempts the fallback only when `bp >= sp`, so `bp < sp`
        // means the fallback can never produce a caller.
        let mut below = test_x86_regs(0x4000);
        below.sp = 0x7fff_0000;
        below.bp = 0x7ffe_ff00; // bp < sp
        assert!(super::arch_fallback_provably_cannot_advance(
            &PerfUserRegs::X86_64(below)
        ));

        let mut at_or_above = test_x86_regs(0x4000);
        at_or_above.sp = 0x7fff_0000;
        at_or_above.bp = 0x7fff_0008; // bp > sp
        assert!(!super::arch_fallback_provably_cannot_advance(
            &PerfUserRegs::X86_64(at_or_above)
        ));
    }

    #[test]
    fn arch_fallback_cannot_advance_only_when_aarch64_lr_is_zero() {
        // backends/aarch64_unwind.c: the caller pc comes from lr and the walk
        // returns false immediately when `lr == 0`. fp/sp are irrelevant to
        // whether the FIRST caller can be produced.
        let zero_lr = crate::perfdata::unwind::PerfAarch64Regs {
            pc: 0x4000,
            sp: 0x1000,
            fp: 0x1010,
            lr: 0,
        };
        assert!(super::arch_fallback_provably_cannot_advance(
            &PerfUserRegs::Aarch64(zero_lr)
        ));

        let live_lr = crate::perfdata::unwind::PerfAarch64Regs {
            lr: 0x5000,
            ..zero_lr
        };
        assert!(!super::arch_fallback_provably_cannot_advance(
            &PerfUserRegs::Aarch64(live_lr)
        ));
    }

    #[test]
    fn classify_object_unwind_routes_leaf_skip_and_unwind() {
        let leaf_only_ctx = super::UserUnwindContext {
            sample_callchain: super::SampleCallchainPresence::Present,
            callchain: other_callchain(),
            initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
            module_count: 1,
            frame_pointer_at_or_above_stack_pointer: false,
            syscall_return_state: false,
        };
        assert_eq!(
            super::classify_object_unwind(leaf_only_ctx, true),
            super::ObjectUnwindClass::LeafOnly
        );
        assert_eq!(
            super::classify_object_unwind(leaf_only_ctx, false),
            super::ObjectUnwindClass::MustUnwind
        );

        // A recorded kernel->user callchain is never extended with user DWARF
        // callers, so it skips unwinding entirely regardless of the leaf-only
        // predicate.
        let kernel_user = super::UserUnwindContext {
            callchain: super::SampleCallchainState::KernelWithUserFrame,
            ..leaf_only_ctx
        };
        assert_eq!(
            super::classify_object_unwind(kernel_user, true),
            super::ObjectUnwindClass::SkipUnwind
        );
        assert_eq!(
            super::classify_object_unwind(kernel_user, false),
            super::ObjectUnwindClass::SkipUnwind
        );
    }

    #[test]
    fn accepted_frames_emit_leaf_only_when_predicate_holds() {
        // When the leaf-only predicate holds the accepted list is the single
        // sampled-IP leaf, even if framehop produced a caller; libdwfl would
        // have stopped after the initial-frame callback.
        let regs = test_regs(0x4000);
        assert_eq!(
            super::perf_accepted_object_unwind_frames(&regs, other_callchain(), true, Vec::new()),
            vec![0x4000]
        );
        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &regs,
                other_callchain(),
                true,
                vec![0x4000, 0x9999],
            ),
            vec![0x4000],
            "a framehop heuristic caller is dropped when perf/libdwfl emits only the leaf"
        );
    }

    #[test]
    fn accepted_frames_keep_full_unwind_when_not_leaf_only() {
        // When the predicate does not hold (e.g. CFI covers the IP), framehop
        // is authoritative and every accepted frame is kept.
        let regs = test_regs(0x4000);
        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &regs,
                other_callchain(),
                false,
                vec![0x4000, 0x9999],
            ),
            vec![0x4000, 0x9999]
        );
        // A non-leaf-only sample with no accepted frames stays empty: the
        // sampled IP is never invented absent the leaf-only predicate.
        assert!(
            super::perf_accepted_object_unwind_frames(&regs, other_callchain(), false, Vec::new())
                .is_empty()
        );
    }

    #[test]
    fn accepted_frames_preserve_duplicate_seed_ip_like_perf_libdw_frame_callback() {
        // tools/perf/util/unwind-libdw.c frame_callback() calls entry() for
        // each Dwfl_Frame, including repeated PCs. No deduplication occurs.
        let regs = test_regs(0x4000);
        assert_eq!(
            super::perf_accepted_object_unwind_frames(
                &regs,
                other_callchain(),
                false,
                vec![0x4000, 0x4000, 0x5000],
            ),
            vec![0x4000, 0x4000, 0x5000]
        );
    }

    #[test]
    fn deferred_sample_final_flush_preserves_insertion_order_like_perf_ordered_events() {
        // tools/perf/util/ordered-events.c queue_event() inserts events by
        // timestamp while preserving input order for equal timestamps. Final
        // deferred-callchain flush must therefore not drain by cookie key.
        let mut accumulator = super::SessionState::new(std::collections::BTreeMap::new());
        accumulator
            .deferred_samples
            .push(super::DeferredFoldSample {
                cookie: 2,
                pid: Some(11),
                tid: Some(21),
                time: Some(100),
                cpu: None,
                event_name: std::sync::Arc::from("cpu-clock"),
                count: 1,
                frames: smallvec::smallvec![super::FoldFrame::Callchain(0x2000)],
                has_callchain: true,
            });
        accumulator
            .deferred_samples
            .push(super::DeferredFoldSample {
                cookie: 1,
                pid: Some(11),
                tid: Some(22),
                time: Some(100),
                cpu: None,
                event_name: std::sync::Arc::from("cpu-clock"),
                count: 1,
                frames: smallvec::smallvec![super::FoldFrame::Callchain(0x1000)],
                has_callchain: true,
            });

        let tids = accumulator
            .take_deferred_samples()
            .into_iter()
            .map(|sample| sample.tid)
            .collect::<Vec<_>>();

        assert_eq!(tids, vec![Some(21), Some(22)]);
    }

    #[test]
    fn perf_user_records_do_not_contribute_ordered_event_timestamps_like_perf_session() {
        // tools/perf/util/session.c perf_session__process_event() dispatches
        // PERF_RECORD_USER_TYPE_START records before evlist__parse_sample_timestamp().
        // A user-record payload tail that looks like sample_id_all data must not
        // advance ordered-events next_flush and flush later samples early.
        let layouts = super::SampleLayouts {
            fallback: Some(std::sync::Arc::new(super::SampleEventLayout::new(
                crate::perfdata::samples::SampleLayout {
                    sample_type: crate::perfdata::samples::PERF_SAMPLE_TID
                        | crate::perfdata::samples::PERF_SAMPLE_TIME,
                    read_format: 0,
                    branch_sample_type: 0,
                    sample_regs_user: 0,
                    sample_regs_intr: 0,
                    sample_id_all: true,
                },
                "cpu-clock",
            ))),
            by_identifier: std::collections::BTreeMap::new(),
            event_name_width: 9,
        };
        let mut payload = Vec::new();
        payload.extend([0xaa; 24]);
        payload.extend(11_u32.to_le_bytes());
        payload.extend(22_u32.to_le_bytes());
        payload.extend(8_725_724_278_030_338_u64.to_le_bytes());
        let record = super::PerfRecord {
            offset: 0,
            header: crate::perfdata::records::PerfRecordHeader {
                record_type: crate::perfdata::records::PERF_RECORD_HEADER_ATTR,
                misc: 0,
                size: u16::try_from(payload.len() + 8).unwrap(),
            },
            payload: &payload,
        };

        assert_eq!(super::record_time(record, &layouts).unwrap(), None);
    }

    #[test]
    fn resolved_deferred_samples_emit_by_sample_time_like_perf_ordered_events() {
        // evlist__deliver_deferred_callchain() scans evlist->deferred_samples
        // in the order perf's ordered-events delivery queued those samples.
        // Same-tid entries are delivered in list order even when only one entry
        // matches the deferred-callchain cookie; different tids remain queued.
        let mut accumulator = super::SessionState::new(std::collections::BTreeMap::new());
        accumulator
            .deferred_samples
            .push(super::DeferredFoldSample {
                cookie: 2,
                pid: Some(11),
                tid: Some(20),
                time: Some(100),
                cpu: None,
                event_name: std::sync::Arc::from("cpu-clock"),
                count: 1,
                frames: smallvec::smallvec![super::FoldFrame::Callchain(0x2000)],
                has_callchain: true,
            });
        accumulator
            .deferred_samples
            .push(super::DeferredFoldSample {
                cookie: 7,
                pid: Some(11),
                tid: Some(30),
                time: Some(150),
                cpu: None,
                event_name: std::sync::Arc::from("cpu-clock"),
                count: 1,
                frames: smallvec::smallvec![super::FoldFrame::Callchain(0x3000)],
                has_callchain: true,
            });
        accumulator
            .deferred_samples
            .push(super::DeferredFoldSample {
                cookie: 7,
                pid: Some(11),
                tid: Some(20),
                time: Some(200),
                cpu: None,
                event_name: std::sync::Arc::from("cpu-clock"),
                count: 1,
                frames: smallvec::smallvec![super::FoldFrame::Callchain(0x7000)],
                has_callchain: true,
            });

        let samples = accumulator.take_resolved_deferred_samples(7, Some(20), &[0x4000]);

        assert_eq!(
            samples.iter().map(|sample| sample.tid).collect::<Vec<_>>(),
            vec![Some(20), Some(20)]
        );
        assert_eq!(
            samples
                .iter()
                .map(|sample| sample.frames.as_slice())
                .collect::<Vec<_>>(),
            vec![
                &[super::FoldFrame::Callchain(0x2000)][..],
                &[
                    super::FoldFrame::Callchain(0x7000),
                    super::FoldFrame::UserCallchain(0x4000)
                ][..],
            ]
        );
        assert_eq!(accumulator.deferred_samples.len(), 1);
        assert_eq!(accumulator.deferred_samples[0].tid, Some(30));
    }
}
