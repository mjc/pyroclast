mod metadata;
mod threads;
pub(crate) use metadata::{
    PerfSampleMetadata, recorded_kernel_maps_file, visit_perfdata_file_metadata,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;
use smallvec::SmallVec;

use crate::folded::{
    append_escaped_spans, append_inferno_perf_folded_label, append_inferno_perf_raw_function,
    append_separator, escape_frame_into, tidy_inferno_perf_generic_into,
};
use crate::perfdata::attrs::{PerfFileAttr, parse_file_attr_ids, parse_file_attrs};
use crate::perfdata::build_id::{
    BuildIdEvent, header_build_id_events_from_perfdata, header_build_id_events_from_reader,
    hex_build_id_bytes, parse_build_id_record,
};
use crate::perfdata::endian::{read_u32, read_u64};
use crate::perfdata::header::{
    PerfFeatureSection, PerfHeader, feature_sections_from_reader, parse_header, parse_header_arch,
};
use crate::perfdata::mappings::{
    FileIdentity, FrameMappingContext, MappedFrame, MappingPathLayout, MappingResolveCache,
    MmapTable, ModuleFallbackKind, ResolvedMappingRef, UserMapping,
};
use crate::perfdata::memory::{DsoMemorySources, MappedMemory};
use crate::perfdata::records::{
    PERF_RECORD_FINISHED_ROUND, PERF_RECORD_MISC_COMM_EXEC, PERF_RECORD_MISC_CPUMODE_KERNEL,
    PERF_RECORD_MISC_CPUMODE_MASK, PERF_RECORD_MISC_CPUMODE_USER, PERF_RECORD_MISC_FORK_EXEC,
    PERF_RECORD_MISC_MMAP_BUILD_ID, ParsedRecord, PerfRecord, parse_callchain_deferred_record,
    parse_comm_record, parse_exit_record, parse_fork_record, parse_mmap_record,
    parse_mmap2_build_id_record, parse_mmap2_record, parse_record,
};
use crate::perfdata::samples::{
    PERF_SAMPLE_ADDR, PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_CPU, PERF_SAMPLE_ID,
    PERF_SAMPLE_IDENTIFIER, PERF_SAMPLE_IP, PERF_SAMPLE_STREAM_ID, PERF_SAMPLE_TID,
    PERF_SAMPLE_TIME, SampleLayout, is_kernel_space_frame, is_perf_context_marker,
    parse_sample_record_callchain, parse_sample_record_metadata,
};
use crate::perfdata::source::{
    FileSource, QueuedPerfRecord, RecordSource, SliceSource, WindowStore,
};
use crate::perfdata::unwind::{
    FramehopUnwinder, ObjectMappingResult, PerfArch, PerfUserRegs,
    unwind_aarch64_frame_pointer_stack_like_elfutils,
    unwind_x86_64_frame_pointer_stack_like_elfutils,
};
#[cfg(test)]
use crate::perfdata::unwind::{UserStackUnwindResult, UserStackUnwinder};
use crate::symbols::{
    CachedMappingFrames, LiveVdsoElf, SymbolFrameCache, SymbolRequest, SymbolResolver,
    copy_live_vdso_elf_like_perf, perf_build_id_elf_path_for_dso,
};

const UNKNOWN_FRAME: &str = "[unknown]";
const PROT_EXEC: u32 = 4;
const PERF_CONTEXT_KERNEL: u64 = 0xffff_ffff_ffff_ff80;
const PERF_CONTEXT_HV: u64 = 0xffff_ffff_ffff_ffe0;
const PERF_RECORD_MISC_CPUMODE_HYPERVISOR: u16 = 3;
const PERF_CONTEXT_USER: u64 = 0xffff_ffff_ffff_fe00;
const PERF_CONTEXT_USER_DEFERRED: u64 = 0xffff_ffff_ffff_fd80;
// tools/perf/util/trace-event-scripting.c:24 initializes scripting_max_stack
// to include/uapi/linux/perf_event.h's PERF_MAX_STACK_DEPTH.
const PERF_SCRIPT_MAX_STACK: usize = 127;
type FoldFrameStack = SmallVec<[FoldFrame; 16]>;
type LabelId = usize;
type LabelSpan = SmallVec<[LabelId; 4]>;
enum LabelProjection {
    Empty,
    Single(LabelId),
    Expanded(LabelSpan),
}

impl From<LabelSpan> for LabelProjection {
    fn from(labels: LabelSpan) -> Self {
        match labels.as_slice() {
            [] => Self::Empty,
            [id] => Self::Single(*id),
            _ => Self::Expanded(labels),
        }
    }
}

#[derive(Clone, Copy)]
enum ProjectionRef<'a> {
    Empty,
    Single(LabelId),
    Expanded(&'a [LabelId]),
}

impl LabelProjection {
    #[inline]
    fn view(&self) -> ProjectionRef<'_> {
        match self {
            Self::Empty => ProjectionRef::Empty,
            Self::Single(id) => ProjectionRef::Single(*id),
            Self::Expanded(labels) => {
                #[cfg(test)]
                PROJECTION_SPAN_READS.with(|reads| reads.set(reads.get() + 1));
                ProjectionRef::Expanded(labels.as_slice())
            }
        }
    }

    fn hint(&self, slot: usize) -> ModuleProjectionValue {
        match self {
            Self::Empty => ModuleProjectionValue::Empty,
            Self::Single(id) => ModuleProjectionValue::Single(*id),
            Self::Expanded(_) => ModuleProjectionValue::Expanded(slot),
        }
    }
}

impl ProjectionRef<'_> {
    #[inline]
    fn append_to(self, stack: &mut Vec<LabelId>) {
        match self {
            Self::Empty => {}
            Self::Single(id) => stack.push(id),
            Self::Expanded(ids) => append_projection_ids(stack, ids),
        }
    }

    #[cfg(test)]
    fn as_slice(&self) -> &[LabelId] {
        match self {
            Self::Empty => &[],
            Self::Single(id) => std::slice::from_ref(id),
            Self::Expanded(ids) => ids,
        }
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }
}

#[inline]
fn append_label_projection(stack: &mut Vec<LabelId>, projection: &LabelProjection) {
    projection.view().append_to(stack);
}

fn append_projection_ids(stack: &mut Vec<LabelId>, labels: &[LabelId]) {
    match labels {
        [] => {}
        [id] => stack.push(*id),
        _ => {
            #[cfg(test)]
            PROJECTION_BULK_COPIES.with(|copies| copies.set(copies.get() + 1));
            stack.extend_from_slice(labels);
        }
    }
}

#[cfg(test)]
thread_local! {
    static PROJECTION_BULK_COPIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static FOLD_FRAME_ADDRESS_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PROJECTION_SPAN_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

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
    pub time: Option<u64>,
    pub cpu: Option<u32>,
    /// Effective event period, including the attribute default when omitted.
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
    thread_comms: BTreeMap<u32, ThreadComm>,
    mmap_table: MmapTable,
    mapping_cache: MappingResolveCache,
    unwind_states: HashMap<u32, PidUnwindState, FxBuildHasher>,
    thread_maps: threads::ThreadMaps,
    keep_exited_threads: bool,
    unwind_memory: DsoMemorySources,
    header_build_ids: BTreeMap<String, RecordedBuildId>,
    deferred_samples: Vec<DeferredFoldSample>,
    unwind_debug_dir: Option<PathBuf>,
    /// Architecture of the recording machine (`HEADER_ARCH`), used to decode
    /// `REGS_USER` samples and construct per-pid unwinders. Defaults to `x86_64`
    /// when the feature is absent.
    arch: PerfArch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecordedBuildId {
    bytes: Vec<u8>,
    misc: u16,
}

struct PidUnwindState {
    arch: PerfArch,
    object_unwinder: FramehopUnwinder,
    /// perf unwind-libdw.c caches DWFL on shared maps. `dwfl_attach_state()`
    /// attaches once; `next_thread()` enumerates only that first TID.
    attached_tid: Option<u32>,
    live_vdso_elf: OnceLock<Option<LiveVdsoElf>>,
    attempted_unwind_mappings: BTreeSet<UnwindMappingKey>,
    /// Original DSO path/load base to the reported module's stable identity.
    /// Entries never suppress reporting and are checked against current IP ownership.
    loaded_unwind_modules: BTreeMap<UnwindModuleKey, usize>,
    /// Memo of the ip-intrinsic leaf-only eligibility per sampled IP. Only the
    /// `(pid, ip)`-stable facts are cached here: whether the module covering
    /// `ip` is reported and whether any CFI covers `ip`. The per-sample register
    /// condition (caller-SP advancement on `x86_64` / `lr == 0` on aarch64)
    /// is combined fresh at query time. Mmap mutations clear this mapping-dependent memo
    /// while retaining reported modules, like perf's inline overlap insertion.
    /// New module reports also clear it; process forks start a fresh unwind state.
    leaf_only_eligibility: HashMap<u64, LeafOnlyEligibility, FxBuildHasher>,
}

impl PidUnwindState {
    fn with_arch(arch: PerfArch) -> Self {
        Self {
            arch,
            object_unwinder: FramehopUnwinder::with_arch(arch),
            attached_tid: None,
            live_vdso_elf: OnceLock::new(),
            attempted_unwind_mappings: BTreeSet::new(),
            loaded_unwind_modules: BTreeMap::new(),
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

type UnwindMappingKey = (String, u64, u64, u64);
type UnwindModuleKey = (String, u64);
const MAX_LIBDW_CALLBACK_REPORT_PASSES: usize = 8;

enum FoldRecord<'a> {
    BuildId(BuildIdEvent),
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
    Exit(crate::perfdata::records::ExitRecord),
    Sample {
        misc: u16,
        payload: &'a [u8],
    },
    CallchainDeferred(crate::perfdata::records::CallchainDeferredRecord),
    Ignored,
}

struct PendingFoldRecord {
    record: QueuedPerfRecord,
    time: u64,
}

#[derive(Default)]
struct OrderedRecordQueue {
    pending_records: Vec<PendingFoldRecord>,
    next_flush_time: Option<u64>,
    max_timestamp: Option<u64>,
    windows: WindowStore,
}

struct DeferredFoldSample {
    cookie: u64,
    tid: Option<u32>,
    misc: u16,
    event: Arc<SampleEventLayout>,
    options: FoldOptions,
    payload: Vec<u8>,
    cookie_to_suppress: Option<u64>,
}

struct PreparedFoldSample<'layout, 'frames> {
    pid: Option<u32>,
    map_group: u32,
    sample_ip: Option<u64>,
    cpumode: u16,
    tid: Option<u32>,
    time: Option<u64>,
    cpu: Option<u32>,
    event_name: &'layout str,
    event_fields: &'layout InfernoSampleEventFields,
    count: u64,
    frames: &'frames [FoldFrame],
    cookie_to_suppress: Option<u64>,
    has_callchain: bool,
}

impl PreparedFoldSample<'_, '_> {
    fn map_group(&self) -> Option<u32> {
        self.pid.map(|_| self.map_group)
    }
}

#[derive(Clone, Copy)]
struct UnwindMappingRequest<'a> {
    start: u64,
    len: u64,
    pgoff: u64,
    prot: Option<u32>,
    path: &'a str,
    module_name: &'a str,
    file_identity: Option<FileIdentity>,
    build_id: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum FoldFrame {
    Callchain(u64),
    UserCallchain(u64),
    HypervisorCallchain(u64),
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
        #[cfg(test)]
        FOLD_FRAME_ADDRESS_READS.with(|reads| reads.set(reads.get() + 1));
        match self {
            Self::Callchain(address)
            | Self::UserCallchain(address)
            | Self::HypervisorCallchain(address)
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
    defer_callchain: bool,
    default_period: u64,
    event_name: Arc<str>,
    event_fields: InfernoSampleEventFields,
    offsets: SampleOffsets,
}

#[derive(Clone, Debug)]
struct InfernoSampleEventFields {
    name: std::ops::Range<usize>,
    period_override: Option<u64>,
}

impl InfernoSampleEventFields {
    fn new(event_name: &str, timed: bool) -> Self {
        #[cfg(test)]
        EVENT_NAME_PARSES.with(|parses| parses.set(parses.get() + 1));
        // perf builtin-script.c:process_event (2442-2452) prints period then
        // "%*s: ". Inferno perf.rs:on_event_line (385-393) skips the first
        // colon field, selecting time's successor or, without time, the
        // event-name suffix. The preceding literal-space word is its period.
        let (start, field) = if timed {
            (0, event_name.split(':').next().unwrap())
        } else if let Some((prefix, suffix)) = event_name.split_once(':') {
            (prefix.len() + 1, suffix.split(':').next().unwrap())
        } else {
            (0, "")
        };
        if let Some((prefix, token)) = field.rsplit_once(' ') {
            let start = start + prefix.len() + 1;
            Self {
                name: start..start + token.len(),
                period_override: Some(prefix.rsplit(' ').next().unwrap().parse().unwrap_or(1)),
            }
        } else {
            Self {
                name: start..start + field.len(),
                period_override: if timed { None } else { Some(1) },
            }
        }
    }
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
    fn new(layout: SampleLayout, event_name: impl Into<Arc<str>>, default_period: u64) -> Self {
        let event_name = event_name.into();
        let event_fields =
            InfernoSampleEventFields::new(&event_name, layout.sample_type & PERF_SAMPLE_TIME != 0);
        Self {
            layout,
            defer_callchain: false,
            default_period,
            event_name,
            event_fields,
            offsets: SampleOffsets::new(layout.sample_type),
        }
    }

    fn from_attr(attr: &PerfFileAttr, event_name: impl Into<Arc<str>>) -> Self {
        Self {
            defer_callchain: attr.defer_callchain,
            ..Self::new(layout_from_attr(attr), event_name, attr.sample_period)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FoldOptions {
    /// Weight stacks by periods. Stack aggregation saturates at
    /// `u64::MAX`, consistently with thread and timeline summaries.
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

    fn append_serialized_labels(&mut self, serialized: &str) -> LabelSpan {
        // Inferno perf.rs:after_event counts serialized bytes, not logical
        // frames. Split even escaped semicolons so equal bytes share one key.
        serialized
            .split(';')
            .map(|label| self.intern(label))
            .collect()
    }

    fn add_prepared(&mut self, _: &mut String, count: u64) {
        add_stack_count(&mut self.stacks, self.scratch_stack.as_slice(), count);
    }

    fn add_stack(&mut self, stack: &str, count: u64) {
        let labels = self.append_serialized_labels(stack);
        self.scratch_stack.clear();
        self.scratch_stack.extend_from_slice(&labels);
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
        let labels = self.append_serialized_labels(stack);
        self.stacks.get(labels.as_slice()).copied()
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
        hashbrown::hash_map::RawEntryMut::Occupied(entry) => {
            let total = entry.into_mut();
            *total = total.saturating_add(count);
        }
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
    validate_perfdata_sections(header, bytes.len())?;
    let sample_layouts = sample_layouts(bytes, header)?;
    let arch = perf_arch_from_header(parse_header_arch(bytes, &header)?.as_deref());
    summarize_perfdata_source(&mut SliceSource(bytes), header, &sample_layouts, arch)
}

/// Summarizes a completed perf recording with bounded buffered reads.
///
/// # Errors
///
/// Returns an error when the recording cannot be read or parsed.
pub fn summarize_perfdata_file(path: &Path) -> Result<PerfSummary, String> {
    let file = File::open(path).map_err(|error| format!("failed to open perf.data: {error}"))?;
    let (header, bytes) = perfdata_header_from_file(&file)?;
    let mut source = FileSource::new(&file)?;
    validate_perfdata_sections(header, source.len())?;
    let layouts = sample_layouts_from_file(&file, header, &bytes)?;
    let arch = perf_arch_from_header(header_arch_from_file(&file, header, &bytes)?.as_deref());
    summarize_perfdata_source(&mut source, header, &layouts, arch)
}

fn validate_perfdata_sections(header: PerfHeader, file_len: usize) -> Result<(), String> {
    let file_len =
        u64::try_from(file_len).map_err(|_| "perf.data length exceeds u64".to_string())?;
    let ranges = [
        (0, header.header_size, "perf header"),
        (header.attr_offset, header.attr_size, "perf attr section"),
        (header.data_offset, header.data_size, "perf data section"),
    ];
    for (index, &(start, size, name)) in ranges.iter().enumerate() {
        if size == 0 {
            continue;
        }
        let end = start
            .checked_add(size)
            .ok_or_else(|| format!("{name} range overflows u64"))?;
        if end > file_len {
            return Err(format!("{name} extends past end of file"));
        }
        for &(other_start, other_size, other_name) in &ranges[..index] {
            if other_size != 0 && start < other_start + other_size && other_start < end {
                return Err(format!("{name} overlaps {other_name}"));
            }
        }
    }
    Ok(())
}

fn summarize_perfdata_source(
    source: &mut impl RecordSource,
    header: PerfHeader,
    sample_layouts: &SampleLayouts,
    arch: PerfArch,
) -> Result<PerfSummary, String> {
    let mut offset = usize::try_from(header.data_offset)
        .map_err(|_| "perf data section offset exceeds usize".to_string())?;
    let end = offset
        .checked_add(
            usize::try_from(header.data_size)
                .map_err(|_| "perf data section size exceeds usize".to_string())?,
        )
        .ok_or_else(|| "perf data section range overflows usize".to_string())?;
    let mut summary = PerfSummary::default();

    while offset < end {
        let record = source.record_at(offset, end)?;
        offset += usize::from(record.header.size);
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
                parse_sample_for_summary(record.misc, &record.payload, sample_layouts, arch).map(
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
        crate::perfdata::records::PERF_RECORD_HEADER_BUILD_ID => {
            FoldRecord::BuildId(parse_build_id_record(record.header.misc, record.payload)?)
        }
        crate::perfdata::records::PERF_RECORD_MMAP => FoldRecord::Mmap {
            misc: record.header.misc,
            record: parse_mmap_record(record.payload)?,
        },
        crate::perfdata::records::PERF_RECORD_COMM => {
            let mut comm = parse_comm_record(record.payload)?;
            comm.is_exec = record.header.misc & PERF_RECORD_MISC_COMM_EXEC != 0;
            FoldRecord::Comm(comm)
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
        crate::perfdata::records::PERF_RECORD_FORK => FoldRecord::Fork({
            let mut fork = parse_fork_record(record.payload)?;
            fork.clone_maps = record.header.misc & PERF_RECORD_MISC_FORK_EXEC == 0;
            fork
        }),
        crate::perfdata::records::PERF_RECORD_EXIT => {
            FoldRecord::Exit(parse_exit_record(record.payload)?)
        }
        crate::perfdata::records::PERF_RECORD_SAMPLE => FoldRecord::Sample {
            misc: record.header.misc,
            payload: record.payload,
        },
        crate::perfdata::records::PERF_RECORD_CALLCHAIN_DEFERRED => {
            FoldRecord::CallchainDeferred(parse_callchain_deferred_record(record.payload)?)
        }
        _ => {
            parse_record(record)?;
            FoldRecord::Ignored
        }
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
    validate_perfdata_sections(header, bytes.len())?;
    let layouts = sample_layouts(bytes, header)?;
    let arch = perf_arch_from_header(parse_header_arch(bytes, &header)?.as_deref());
    let state = SessionState::new(header_build_ids_by_filename(bytes)?)
        .with_arch(arch)
        .with_header(bytes)?;
    collect_fold_counts_from_source(
        &mut SliceSource(bytes),
        header,
        &layouts,
        state,
        options,
        symbol_cache,
    )
}

fn collect_fold_counts_from_source<R: SymbolResolver>(
    source: &mut impl RecordSource,
    header: PerfHeader,
    layouts: &SampleLayouts,
    state: SessionState,
    options: FoldOptions,
    symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
) -> Result<FoldCounts, String> {
    if layouts_require_stream_parser(layouts) {
        return collect_stream_fold_counts(source, header, layouts, state, options, symbol_cache);
    }
    let mut sink = SampleSink::new(
        state,
        FoldedOutput::new(symbol_cache, options, layouts.event_name_width),
    );
    replay_records(source, header, layouts, options, &mut sink)?;
    if sink.output.requires_stream_parser {
        // No counts have been emitted yet. Replay with fresh metadata and one
        // Inferno parser so a structural header cannot leak per-event state.
        let cache = sink.output.symbol_cache.take();
        let state = {
            let previous = sink.accumulator;
            let mut state = SessionState::new(previous.header_build_ids).with_arch(previous.arch);
            state.keep_exited_threads = previous.keep_exited_threads;
            state
        };
        drop(sink.output);
        return collect_stream_fold_counts(source, header, layouts, state, options, cache);
    }
    Ok(sink.output.buffers.counts)
}

fn layouts_require_stream_parser(layouts: &SampleLayouts) -> bool {
    layouts
        .fallback
        .iter()
        .chain(layouts.by_identifier.values())
        .any(|event| {
            let post_event = if event.layout.sample_type & PERF_SAMPLE_TIME != 0 {
                event.event_name.split_once(':').map(|(_, suffix)| suffix)
            } else {
                event.event_name.splitn(3, ':').nth(2)
            };
            event.layout.sample_type & (PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_TID)
                != PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_TID
                // builtin-script.c:process_event prints evname verbatim;
                // Inferno process_single_stack splits LF before event parsing.
                || event.event_name.contains('\n')
                // Inferno on_event_line (405-428) skips the first space/colon
                // in the post-event field. An embedded separator leaves the
                // literal ": " that perf appends, hence a combined frame.
                // This changes parser state for the following stack lines.
                || post_event.is_some_and(|suffix| suffix.contains([' ', ':']))
        })
}

fn collect_stream_fold_counts<R: SymbolResolver>(
    source: &mut impl RecordSource,
    header: PerfHeader,
    layouts: &SampleLayouts,
    state: SessionState,
    options: FoldOptions,
    symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
) -> Result<FoldCounts, String> {
    use inferno::collapse::Collapse as _;
    // Inferno process_single_stack can stay in_event after an event-line IP
    // (missing TIME/frames or embedded DSO newlines). Subsequent sample headers
    // then become stack rows, so per-sample parser resets are incorrect.
    // Preserve the complete stream grammar without buffering it all in RAM.
    // Without TID (builtin-script.c:evsel__check_attr), Inferno can instead
    // recognize the period as the numeric header word and change the comm.
    let mut script = tempfile::tempfile().map_err(|error| error.to_string())?;
    {
        let mut writer = std::io::BufWriter::new(&mut script);
        let mut sink = SampleSink::new(
            state,
            PerfScriptOutput {
                symbol_cache,
                writer: &mut writer,
                event_name_width: layouts.event_name_width,
                inline: options.inline,
            },
        );
        replay_records(source, header, layouts, options, &mut sink)?;
        writer.flush().map_err(|error| error.to_string())?;
    }
    script
        .seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut settings = inferno::collapse::perf::Options::default();
    settings.nthreads = 1;
    let mut folded = Vec::new();
    inferno::collapse::perf::Folder::from(settings)
        .collapse(std::io::BufReader::new(script), &mut folded)
        .map_err(|error| format!("failed to fold perf text: {error}"))?;
    let mut counts = FoldCounts::default();
    add_inferno_counts(&mut counts, &folded)?;
    Ok(counts)
}

fn add_inferno_counts(counts: &mut FoldCounts, folded: &[u8]) -> Result<(), String> {
    let folded = std::str::from_utf8(folded).map_err(|error| error.to_string())?;
    for line in folded.lines() {
        let (stack, count) = line
            .rsplit_once(' ')
            .ok_or_else(|| "Inferno output lacks a stack count".to_string())?;
        let count = count.parse::<u64>().map_err(|error| error.to_string())?;
        counts.add_stack(stack, count);
    }
    Ok(())
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
    // builtin-script.c sets ordering_requires_timestamps; session.c disables
    // ordered_events without evlist__sample_id_all (the first event's flag).
    let ordered_events = layouts
        .fallback
        .as_ref()
        .is_some_and(|event| event.layout.sample_id_all);
    while offset < end {
        let (record_type, header, next, queue_time) = {
            let record = source.record_at(offset, end)?;
            let record_type = record.header.record_type;
            let header = record.header;
            let next = offset + usize::from(record.header.size);
            let queue_time = if ordered_events && record_type != PERF_RECORD_FINISHED_ROUND {
                record_time(record, layouts)?.filter(|time| *time != 0 && *time != u64::MAX)
            } else {
                None
            };
            if record_type != PERF_RECORD_FINISHED_ROUND && queue_time.is_none() {
                sink.apply_fold_record(parse_fold_record(record)?, layouts, options)?;
            }
            (record_type, header, next, queue_time)
        };
        if record_type == PERF_RECORD_FINISHED_ROUND {
            ordered.flush_round_with(|record, offset| {
                deliver_record(record, offset, layouts, options, sink)
            })?;
        } else if let Some(time) = queue_time {
            // ordered-events.c rejects zero/~0ULL with -ETIME; session.c then
            // delivers directly. Ties retain input order (file offset).
            let record = source.queue_record(offset, end, header, &mut ordered.windows)?;
            ordered.queue(record, time);
        }
        offset = next;
    }
    ordered.flush_final_with(|record, offset| {
        deliver_record(record, offset, layouts, options, sink)
    })?;
    sink.flush_deferred_samples()
}

fn deliver_record<O: SampleOutput>(
    record: crate::perfdata::records::PerfRecord<'_>,
    offset: usize,
    layouts: &SampleLayouts,
    options: FoldOptions,
    sink: &mut SampleSink<O>,
) -> Result<(), String> {
    let record_type = record.header.record_type;
    parse_fold_record(record)
        .and_then(|record| sink.apply_fold_record(record, layouts, options))
        .map_err(|error| {
            format!("failed to parse record type {record_type} at offset {offset}: {error}")
        })
}

fn header_build_ids_by_filename(bytes: &[u8]) -> Result<BTreeMap<String, RecordedBuildId>, String> {
    recorded_build_ids_by_filename(header_build_id_events_from_perfdata(bytes)?)
}

fn recorded_build_ids_by_filename(
    events: Vec<BuildIdEvent>,
) -> Result<BTreeMap<String, RecordedBuildId>, String> {
    let mut ids = events
        .into_iter()
        .filter(BuildIdEvent::has_valid_cpu_mode)
        // tools/perf/util/build-id.c:build_id__is_defined: empty and all-zero
        // recorded IDs are absent, not identities to require from an ELF.
        .filter(|event| event.build_id.bytes().any(|byte| byte != b'0'))
        .map(|event| {
            hex_build_id_bytes(&event.build_id).map(|bytes| {
                (
                    event.filename,
                    RecordedBuildId {
                        bytes,
                        misc: event.misc,
                    },
                )
            })
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if !ids.contains_key("[vdso]") {
        // Native perf writes the live image using a mkstemp name while MMAP2
        // retains the canonical [vdso] name. Preserve its recorded identity.
        let aliases = ids
            .iter()
            .filter(|(path, _)| is_perf_temporary_vdso_path(path))
            .map(|(_, id)| &id.bytes)
            .collect::<BTreeSet<_>>();
        if aliases.len() > 1 {
            return Err("ambiguous recorded native vDSO build IDs".to_string());
        }
        let alias_id = aliases.into_iter().next().and_then(|bytes| {
            ids.iter()
                .find(|(path, id)| is_perf_temporary_vdso_path(path) && &id.bytes == bytes)
                .map(|(_, id)| id.clone())
        });
        if let Some(id) = alias_id {
            ids.insert("[vdso]".to_string(), id);
        }
    }
    Ok(ids)
}

fn is_perf_temporary_vdso_path(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("perf-vdso.so-"))
        .is_some_and(|suffix| {
            suffix.len() == 6 && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

fn file_replay_state(file: &File) -> Result<(PerfHeader, SampleLayouts, SessionState), String> {
    let (header, bytes) = perfdata_header_from_file(file)?;
    let file_len = usize::try_from(
        file.metadata()
            .map_err(|error| format!("failed to stat perf.data: {error}"))?
            .len(),
    )
    .map_err(|_| "perf.data length exceeds usize".to_string())?;
    validate_perfdata_sections(header, file_len)?;
    let layouts = sample_layouts_from_file(file, header, &bytes)?;
    let ids = header_build_ids_by_filename_from_file(file)?;
    let arch = perf_arch_from_header(header_arch_from_file(file, header, &bytes)?.as_deref());
    Ok((
        header,
        layouts,
        SessionState::new(ids).with_arch(arch).with_header(&bytes)?,
    ))
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
    let counts = collect_fold_counts_from_source(
        &mut FileSource::new(file)?,
        header,
        &layouts,
        state,
        options,
        symbol_cache,
    )?;
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
    count_periods: bool,
    event_name_width: usize,
    event_filter: Option<Box<str>>,
    requires_stream_parser: bool,
    header_scratch: Vec<u8>,
    buffers: FoldedRenderBuffers,
}

impl<'a, 'cache, R: SymbolResolver> FoldedOutput<'a, 'cache, R> {
    fn new(
        symbol_cache: Option<&'a mut SymbolFrameCache<'cache, R>>,
        options: FoldOptions,
        event_name_width: usize,
    ) -> Self {
        Self {
            symbol_cache,
            inline: options.inline,
            count_periods: options.count_periods,
            event_name_width,
            event_filter: None,
            requires_stream_parser: false,
            header_scratch: Vec::new(),
            buffers: FoldedRenderBuffers::default(),
        }
    }

    fn fold_perf_text(
        &mut self,
        accumulator: &SessionState,
        sample: &PreparedFoldSample,
    ) -> Result<(), String> {
        use inferno::collapse::Collapse as _;
        // map.c:map__fprintf_dsoname emits paths verbatim. A DSO can alter
        // stack-row parsing or event boundaries, so parse the whole event
        // with Inferno rather than rewriting or dropping individual names.
        let mut script = Vec::new();
        PerfScriptOutput {
            symbol_cache: self.symbol_cache.as_deref_mut(),
            writer: &mut script,
            event_name_width: self.event_name_width,
            inline: self.inline,
        }
        .write_preprocessed_sample_event(accumulator, sample)?;
        let mut options = inferno::collapse::perf::Options::default();
        options.nthreads = 1;
        options.event_filter = self.event_filter.as_deref().map(str::to_owned);
        let mut folded = Vec::new();
        inferno::collapse::perf::Folder::from(options)
            .collapse(std::io::Cursor::new(script), &mut folded)
            .map_err(|error| format!("failed to fold perf text: {error}"))?;
        add_inferno_counts(&mut self.buffers.counts, &folded)
    }
}

fn inferno_sample_event_fields<'a>(
    sample: &PreparedFoldSample<'a, '_>,
    width: usize,
) -> (&'a str, u64) {
    (
        &sample.event_name[sample.event_fields.name.clone()],
        sample.event_fields.period_override.unwrap_or({
            if width > sample.event_name.len() {
                1
            } else {
                sample.count
            }
        }),
    )
}

fn inferno_numeric_header_word(line: &str) -> Option<(usize, usize)> {
    #[cfg(test)]
    COMM_SYNTAX_SCANS.with(|scans| scans.set(scans.get() + 1));
    // Inferno perf.rs:event_line_parts (328-365) starts recognizing numeric
    // words only after a literal space. Slashes do not unset all_digits;
    // the first unpadded word is never a TID, even if it is numeric.
    let mut start = 0;
    for end in memchr::memchr_iter(b' ', line.as_bytes()) {
        if start != 0
            && end != start
            && line.as_bytes()[start..end]
                .iter()
                .all(|byte| byte.is_ascii_digit() || *byte == b'/')
        {
            return Some((start, end + 1));
        }
        start = end + 1;
    }
    // The script writer appends a space after comm, so include its final word
    // when this helper is called with just comm rather than the full header.
    if start != 0
        && start != line.len()
        && line.as_bytes()[start..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b'/')
    {
        return Some((start, line.len()));
    }
    None
}

#[cfg(test)]
thread_local! {
    static COMM_SYNTAX_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static EVENT_NAME_PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

struct InfernoFoldHeader<'a> {
    comm: &'a str,
    event: Option<&'a str>,
    count: u64,
    combined_frame: bool,
}

fn parse_inferno_fold_header(line: &str) -> Option<InfernoFoldHeader<'_>> {
    let line = line.trim_end();
    let (start, end) = inferno_numeric_header_word(line)?;
    let mut colons = line[end..].splitn(3, ':').skip(1);
    let mut count = 1;
    let event = colons.next().map(|field| {
        let mut words = field.rsplit(' ');
        let event = words.next().unwrap();
        count = words.next().and_then(|word| word.parse().ok()).unwrap_or(1);
        event
    });
    // on_event_line (405-428) interprets nonempty text after the second colon
    // as a combined frame, even if that colon came from comm rather than TIME.
    let combined_frame = colons.next().is_some_and(|field| {
        let offset = field.find([':', ' ']).map_or(0, |index| index + 1);
        !field[offset..].trim().is_empty()
    });
    Some(InfernoFoldHeader {
        comm: line[..start - 1].trim(),
        event,
        count,
        combined_frame,
    })
}

impl<R: SymbolResolver> SampleOutput for FoldedOutput<'_, '_, R> {
    fn write_sample_event(
        &mut self,
        accumulator: &SessionState,
        sample: &PreparedFoldSample,
    ) -> Result<(), String> {
        preprocess_sample_ip(accumulator, sample, self.symbol_cache.as_deref_mut());
        if self.requires_stream_parser {
            return Ok(());
        }
        let mut comm = comm_for_ids(&accumulator.thread_comms, sample.tid);
        // perf_sample__fprintf_start prints comm verbatim. Inferno's
        // process_single_stack skips # lines and read_until splits at LF.
        // These are stream syntax, not characters in a folded comm label.
        if let Some(SampleComm::Stored(name)) = comm
            && name.syntax == CommSyntax::Stream
        {
            self.requires_stream_parser = true;
            return Ok(());
        }
        let (event, count, combined_frame) = if let Some(SampleComm::Stored(name)) = comm
            && name.syntax == CommSyntax::Numeric
        {
            self.header_scratch.clear();
            PerfScriptOutput::<R, _> {
                symbol_cache: None,
                writer: &mut self.header_scratch,
                event_name_width: self.event_name_width,
                inline: self.inline,
            }
            .write_sample_header(accumulator, sample)?;
            let header =
                std::str::from_utf8(&self.header_scratch).map_err(|error| error.to_string())?;
            let parsed = parse_inferno_fold_header(header)
                .expect("numeric comm word is present in the header");
            comm = Some(SampleComm::Name(parsed.comm));
            (parsed.event, parsed.count, parsed.combined_frame)
        } else {
            let (event, count) = inferno_sample_event_fields(sample, self.event_name_width);
            (Some(event), count, false)
        };
        if let Some(event) = event {
            if let Some(selected) = self.event_filter.as_deref() {
                if selected != event {
                    return Ok(());
                }
            } else {
                self.event_filter = Some(event.into());
            }
        }
        // evsel_fprintf.c prints the DSO and inline rows even when the symbol
        // is (cookie). Inferno splits physical lines before omitting that row.
        if combined_frame
            || (sample.time.is_none() && !sample.has_callchain)
            || sample.cookie_to_suppress.is_some()
        {
            return self.fold_perf_text(accumulator, sample);
        }
        let frames = sample.frames.iter().rev().copied().filter(|frame| {
            let address = frame.address();
            !is_perf_context_marker(address)
        });
        self.buffers.projecting = true;
        let status = FoldFrameResolver::new(&accumulator.mmap_table, self.inline)
            .render_folded_stack_for_stack(
                sample.map_group(),
                comm,
                frames,
                self.symbol_cache.as_deref_mut(),
                &mut self.buffers,
            )?;
        if matches!(status, FoldedRenderStatus::RequiresPerfText) {
            return self.fold_perf_text(accumulator, sample);
        }
        if !self.buffers.counts.scratch_stack.is_empty() {
            self.buffers.counts.add_prepared(
                &mut self.buffers.current,
                if self.count_periods {
                    count
                } else {
                    sample.count
                },
            );
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
    sample_frames: FoldFrameStack,
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
            sample_frames: FoldFrameStack::new(),
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
        let Some(event) = sample_layouts.layout_for_payload(payload)? else {
            return Ok(());
        };
        let Some(sample) = parse_sample_record_callchain(payload, event.layout)? else {
            return Ok(());
        };
        // perf evsel.c:3391 and session.c:1486 recognize and queue deferred
        // samples before callchain resolution, not after preparing frames.
        if let Some(cookie) = event
            .defer_callchain
            .then(|| sample.frames.deferred_cookie())
            .flatten()
        {
            self.accumulator.deferred_samples.push(DeferredFoldSample {
                cookie,
                tid: sample.tid,
                misc,
                event: sample_layouts.owned_event_for_payload(payload)?,
                options,
                payload: payload.to_vec(),
                cookie_to_suppress: Some(cookie),
            });
            return Ok(());
        }
        let sample = prepare_parsed_sample_for_fold(
            &mut self.accumulator,
            misc,
            event,
            &sample,
            options,
            &mut self.sample_frames,
        );
        self.output.write_sample_event(&self.accumulator, &sample)
    }

    fn write_deferred_callchain(
        &mut self,
        cookie: u64,
        tid: Option<u32>,
        ips: &[u64],
    ) -> Result<(), String> {
        for deferred in self
            .accumulator
            .take_resolved_deferred_samples(cookie, tid, ips)?
        {
            self.deliver_deferred_sample(&deferred)?;
        }
        Ok(())
    }

    fn flush_deferred_samples(&mut self) -> Result<(), String> {
        let samples = self.accumulator.take_deferred_samples();
        for deferred in samples {
            self.deliver_deferred_sample(&deferred)?;
        }
        Ok(())
    }

    fn deliver_deferred_sample(&mut self, deferred: &DeferredFoldSample) -> Result<(), String> {
        let Some(raw_sample) =
            parse_sample_record_callchain(&deferred.payload, deferred.event.layout)?
        else {
            return Ok(());
        };
        let mut sample = prepare_parsed_sample_for_fold(
            &mut self.accumulator,
            deferred.misc,
            &deferred.event,
            &raw_sample,
            deferred.options,
            &mut self.sample_frames,
        );
        // evsel_fprintf.c:171 prints (cookie) for every equal-IP node while
        // deferred metadata is set. Inferno perf.rs:507 omits those names.
        sample.cookie_to_suppress = deferred.cookie_to_suppress;
        self.output.write_sample_event(&self.accumulator, &sample)
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
        preprocess_sample_ip(accumulator, sample, self.symbol_cache.as_deref_mut());
        self.write_preprocessed_sample_event(accumulator, sample)
    }
}

fn preprocess_sample_ip<R: SymbolResolver>(
    accumulator: &SessionState,
    sample: &PreparedFoldSample,
    cache: Option<&mut SymbolFrameCache<'_, R>>,
) {
    // event.c:thread__find_map selects kernel DSOs only in kernel CPU mode.
    // User event IPs cannot affect this kernel source-loading state.
    if sample.cpumode != PERF_RECORD_MISC_CPUMODE_KERNEL {
        return;
    }
    let (Some(cache), Some(address), Some(pid)) = (cache, sample.sample_ip, sample.map_group())
    else {
        return;
    };
    // perf builtin-script.c:2645 (process_sample_event, call at 2686) and
    // util/event.c:804 (machine__resolve) resolve sample->ip
    // using sample->cpumode before expanding the independently recorded chain.
    // This is load ordering only: never resolve frames or advance cursor hints.
    let mut mapping_cache = MappingResolveCache::default();
    let context = accumulator
        .mmap_table
        .frame_context(pid, &mut mapping_cache);
    let frame = FoldFrame::SampleIp {
        address,
        cpumode: sample.cpumode,
    };
    if let Some(mapping) =
        resolve_frame_in_context(Some(&context), frame, address, &mut mapping_cache)
        && mapping.is_kernel()
    {
        // symbol.c:dso__load discovers an undefined live build ID before
        // choosing cached symbols. Freeze that identity at this first load,
        // even when the independently recorded callchain omits the event IP.
        let mapping = accumulator
            .mmap_table
            .symbol_mapping_ref(mapping, Some(cache.resolver()));
        cache.preprocess_sample_ip(&mapping);
    }
}

impl<R, W> PerfScriptOutput<'_, '_, R, W>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    fn write_preprocessed_sample_event(
        &mut self,
        accumulator: &SessionState,
        sample: &PreparedFoldSample,
    ) -> Result<(), String> {
        let mut frame_resolver = FoldFrameResolver::new(&accumulator.mmap_table, self.inline);
        frame_resolver.cookie_to_suppress = sample.cookie_to_suppress;
        if sample.has_callchain {
            self.write_sample_header(accumulator, sample)?;
            frame_resolver.write_script_frames_for_stack(
                sample.map_group(),
                sample.frames,
                self.symbol_cache.as_deref_mut(),
                self.writer,
            )?;
        } else {
            self.write_sample_inline_header(accumulator, sample)?;
            frame_resolver.write_inline_sample_frame_for_stack(
                sample.map_group(),
                sample.frames,
                self.symbol_cache.as_deref_mut(),
                self.writer,
            )?;
        }
        if let Some(cache) = self.symbol_cache.as_deref_mut() {
            cache.finish_kernel_sample();
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
            "{:>10} {:>padding$}{}: ",
            sample.count,
            "",
            sample.event_name,
            padding = self
                .event_name_width
                .saturating_sub(sample.event_name.len()),
        )
        .map_err(|error| format!("failed to write perf script output: {error}"))
    }

    fn write_sample_inline_header(
        &mut self,
        accumulator: &SessionState,
        sample: &PreparedFoldSample,
    ) -> Result<(), String> {
        let comm = perf_script_comm(&accumulator.thread_comms, sample);
        // perf's %16s pads byte lengths; Rust string widths count characters.
        let padding = match comm {
            SampleComm::Name(name) => 16_usize.saturating_sub(name.len()),
            SampleComm::Stored(name) => 16_usize.saturating_sub(name.name.len()),
            SampleComm::Tid(tid) => 16_usize
                .saturating_sub(usize::try_from(tid.checked_ilog10().unwrap_or(0) + 2).unwrap()),
        };
        self.writer
            .write_all(&[b' '; 16][..padding])
            .map_err(|error| format!("failed to write perf script output: {error}"))?;
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
        // builtin-script.c writes the event-name colon/trailing space, then
        // fputc(' ', fp) before sample__fprintf_sym() when no callchain cursor
        // is present, so the inline event-line IP starts after two spaces.
        write!(
            self.writer,
            "{:>10} {:>padding$}{}:  ",
            sample.count,
            "",
            sample.event_name,
            padding = self
                .event_name_width
                .saturating_sub(sample.event_name.len()),
        )
        .map_err(|error| format!("failed to write perf script output: {error}"))
    }
}

fn perf_script_comm<'a>(
    thread_comms: &'a BTreeMap<u32, ThreadComm>,
    sample: &PreparedFoldSample,
) -> SampleComm<'a> {
    if let Some(tid) = sample.tid {
        return comm_for_ids(thread_comms, Some(tid)).unwrap();
    }
    if sample.pid.is_some() {
        return SampleComm::Name("[unknown]");
    }
    SampleComm::Name(":-1")
}

impl OrderedRecordQueue {
    fn queue(&mut self, record: QueuedPerfRecord, time: u64) {
        // perf util/ordered-events.c:queue_event resets max_timestamp when
        // oe->last is NULL, which do_flush sets after emptying the queue.
        self.max_timestamp = Some(if self.pending_records.is_empty() {
            time
        } else {
            self.max_timestamp.map_or(time, |max| max.max(time))
        });
        self.pending_records
            .push(PendingFoldRecord { record, time });
    }

    fn flush_round_with<F>(&mut self, apply: F) -> Result<(), String>
    where
        F: FnMut(crate::perfdata::records::PerfRecord<'_>, usize) -> Result<(), String>,
    {
        if let Some(limit) = self.next_flush_time {
            self.flush_through_with(Some(limit), apply)?;
        }
        self.next_flush_time = self.max_timestamp;
        Ok(())
    }

    fn flush_final_with<F>(&mut self, apply: F) -> Result<(), String>
    where
        F: FnMut(crate::perfdata::records::PerfRecord<'_>, usize) -> Result<(), String>,
    {
        self.flush_through_with(None, apply)
    }

    fn flush_through_with<F>(&mut self, limit: Option<u64>, mut apply: F) -> Result<(), String>
    where
        F: FnMut(crate::perfdata::records::PerfRecord<'_>, usize) -> Result<(), String>,
    {
        self.pending_records
            .sort_unstable_by_key(|record| (record.time, record.record.offset));
        let split = limit.map_or(self.pending_records.len(), |limit| {
            self.pending_records
                .partition_point(|record| record.time <= limit)
        });
        let mut ready = self.pending_records.drain(..split);
        while let Some(queued) = ready.next() {
            let offset = queued.record.offset;
            let result = apply(self.windows.record(&queued.record), offset);
            self.windows.release(&queued.record);
            if let Err(error) = result {
                for pending in ready {
                    self.windows.release(&pending.record);
                }
                return Err(error);
            }
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

    let event_desc = event_desc_entries_from_file(file, header, header_bytes)?;
    sample_layouts_from_attrs(&attrs, &event_desc, |attr| {
        file_attr_ids_from_file(file, attr)
    })
}

fn sample_layouts_from_attrs(
    attrs: &[PerfFileAttr],
    event_desc: &[EventDescEntry],
    mut load_ids: impl FnMut(&PerfFileAttr) -> Result<Vec<u64>, String>,
) -> Result<SampleLayouts, String> {
    let mut ranges = BTreeMap::<(u64, u64), Vec<usize>>::new();
    for (index, attr) in attrs.iter().enumerate() {
        ranges
            .entry((attr.ids_offset, attr.ids_size))
            .or_default()
            .push(index);
    }
    let mut layouts = SampleLayouts {
        fallback: None,
        by_identifier: BTreeMap::new(),
        event_name_width: 0,
    };
    let mut selected = BTreeMap::<u64, (usize, Arc<SampleEventLayout>)>::new();
    for indices in ranges.values() {
        let first = indices[0];
        let last = *indices.last().expect("each ID range has an attribute");
        // Read each distinct region once and release its vector before the
        // next. Aliases must not multiply retained metadata or ID-map work.
        let ids = load_ids(&attrs[first])?;
        let description = event_desc
            .iter()
            .find(|entry| entry.ids.iter().any(|id| ids.contains(id)));
        let mut selected_event = None;
        for &index in indices {
            let name = description.or_else(|| event_desc.get(index)).map_or_else(
                || perf_event_name(&attrs[index]),
                |entry| entry.name.clone(),
            );
            layouts.event_name_width = layouts.event_name_width.max(name.len());
            if index == 0 || index == last {
                let event = Arc::new(SampleEventLayout::from_attr(&attrs[index], name));
                if index == 0 {
                    layouts.fallback = Some(Arc::clone(&event));
                }
                if index == last {
                    selected_event = Some(event);
                }
            }
        }
        let event = selected_event.expect("each ID range has a selected event");
        for id in ids {
            // perf tools/lib/perf/evlist.c:perf_evlist__id_hash adds at the
            // hash-list head; util/evlist.c:evlist__id2sid picks the latest
            // attribute. Preserve that ordering across overlapping ranges.
            if selected.get(&id).is_none_or(|(index, _)| *index < last) {
                selected.insert(id, (last, Arc::clone(&event)));
            }
        }
    }
    layouts.by_identifier = selected
        .into_iter()
        .map(|(id, (_, event))| (id, event))
        .collect();
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
) -> Result<BTreeMap<String, RecordedBuildId>, String> {
    let mut reader = file
        .try_clone()
        .map_err(|error| format!("failed to clone perf.data handle: {error}"))?;
    recorded_build_ids_by_filename(header_build_id_events_from_reader(&mut reader)?)
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
    parse_event_desc_entries(&payload)
}

fn event_desc_entries_from_bytes(
    bytes: &[u8],
    header: crate::perfdata::header::PerfHeader,
) -> Result<Vec<EventDescEntry>, String> {
    let sections = crate::perfdata::header::parse_feature_sections(bytes, &header)?;
    let Some(section) = sections
        .into_iter()
        .find(|section| section.feature == HEADER_EVENT_DESC_FEATURE)
    else {
        return Ok(Vec::new());
    };
    let offset = usize::try_from(section.offset)
        .map_err(|_| "event desc feature offset exceeds usize".to_string())?;
    let size = usize::try_from(section.size)
        .map_err(|_| "event desc feature size exceeds usize".to_string())?;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| "event desc feature range overflows usize".to_string())?;
    let payload = bytes
        .get(offset..end)
        .ok_or_else(|| "event desc feature payload is truncated".to_string())?;
    parse_event_desc_entries(payload)
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
    let len_u64 = u64::try_from(len).map_err(|_| format!("{range_name} size exceeds u64"))?;
    let end = offset
        .checked_add(len_u64)
        .ok_or_else(|| format!("{range_name} range overflows u64"))?;
    let file_len = file
        .metadata()
        .map_err(|error| format!("failed to stat {range_name}: {error}"))?
        .len();
    if end > file_len {
        return Err(format!("{range_name} extends past end of file"));
    }
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

impl SessionState {
    fn new(header_build_ids: BTreeMap<String, RecordedBuildId>) -> Self {
        Self {
            process_comms: BTreeMap::new(),
            exec_process_comms: BTreeMap::new(),
            thread_comms: BTreeMap::new(),
            mmap_table: MmapTable::default(),
            mapping_cache: MappingResolveCache::default(),
            unwind_states: HashMap::with_hasher(FxBuildHasher),
            thread_maps: threads::ThreadMaps::default(),
            keep_exited_threads: false,
            unwind_memory: DsoMemorySources::default(),
            header_build_ids,
            deferred_samples: Vec::new(),
            unwind_debug_dir: current_perf_debug_dir(),
            arch: PerfArch::default(),
        }
    }

    fn with_arch(mut self, arch: PerfArch) -> Self {
        self.arch = arch;
        self
    }

    fn with_header(mut self, bytes: &[u8]) -> Result<Self, String> {
        // util/session.c:perf_session__open retains exited threads with
        // HEADER_AUXTRACE (util/header.h feature 18).
        self.keep_exited_threads = read_u64(bytes, 72)? & (1 << 18) != 0;
        Ok(self)
    }

    fn maps_for_thread(&mut self, pid: u32, tid: u32) -> u32 {
        let group = self.thread_maps.find_or_create(pid, tid);
        self.release_retired_map_groups();
        group
    }

    fn remove_thread(&mut self, tid: u32) {
        self.thread_maps.remove(tid);
        self.thread_comms.remove(&tid);
        self.release_retired_map_groups();
    }

    fn release_retired_map_groups(&mut self) {
        for group in self.thread_maps.take_retired() {
            self.mmap_table.remove_pid_mappings(group);
            self.unwind_states.remove(&group);
            self.mapping_cache = MappingResolveCache::default();
        }
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
            ParsedRecord::Exit(record) => FoldRecord::Exit(record),
            _ => panic!("test adapter accepts only session metadata"),
        };
        self.apply_metadata(record);
    }

    fn apply_fork_record(&mut self, record: crate::perfdata::records::ForkRecord) {
        // machine.c:machine__process_fork_event replaces an erroneous parent
        // or an existing child TID before thread.c:thread__clone_maps.
        if self
            .thread_maps
            .pid(record.ptid)
            .is_some_and(|pid| pid != u32::MAX && pid != record.ppid)
        {
            self.remove_thread(record.ptid);
        }
        let parent = self.maps_for_thread(record.ppid, record.ptid);
        self.thread_maps.retain(parent);
        let parent_comm = if record.ptid == record.tid {
            self.thread_comms.get(&record.ptid).cloned()
        } else {
            None
        };
        self.remove_thread(record.tid);
        if let Some(comm) = parent_comm {
            self.thread_comms.insert(record.tid, comm);
        }
        let child = self.maps_for_thread(record.pid, record.tid);
        inherit_fork_comm_tables(
            &mut self.process_comms,
            &mut self.exec_process_comms,
            &mut self.thread_comms,
            record,
        );
        if record.pid != record.ppid && record.clone_maps {
            self.mmap_table.clone_pid_mappings(parent, child);
            self.mapping_cache = MappingResolveCache::default();
        }
        self.thread_maps.release(parent);
        self.release_retired_map_groups();
    }

    #[cfg(test)]
    fn unwind_state_mut(&mut self, pid: u32) -> &mut PidUnwindState {
        let arch = self.arch;
        self.unwind_states
            .entry(pid)
            .or_insert_with(|| PidUnwindState::with_arch(arch))
    }

    fn clear_mapping_dependent_unwind_memo(&mut self, pid: u32) {
        if let Some(state) = self.unwind_states.get_mut(&pid) {
            // maps.c __maps__fixup_overlap_and_insert does not call the DWFL
            // invalidation in maps__remove, even when it removes maps inline.
            state.leaf_only_eligibility.clear();
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
    thread_comms: &mut BTreeMap<u32, ThreadComm>,
    record: &crate::perfdata::records::CommRecord,
) {
    use std::collections::btree_map::Entry;

    let comm = record.comm.as_ref();
    if record.is_exec {
        upsert_comm(exec_process_comms, record.pid, comm);
    }
    upsert_comm(process_comms, record.pid, comm);
    match thread_comms.entry(record.tid) {
        Entry::Vacant(entry) => {
            entry.insert(comm.into());
        }
        Entry::Occupied(mut entry) => {
            if entry.get().name != comm {
                entry.insert(comm.into());
            }
        }
    }
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
        self.mmap_table.initialize_native_dso_headers(
            self.header_build_ids
                .iter()
                .map(|(path, id)| (path.as_str(), id.bytes.as_slice(), id.misc)),
        );
        match record {
            FoldRecord::BuildId(event) => {
                // session.c:1649 processes these user records before timestamp
                // queuing. header.c:__event_process_build_id updates that DSO.
                if event.has_valid_cpu_mode() {
                    let id =
                        hex_build_id_bytes(&event.build_id).expect("parsed build-ID hexadecimal");
                    self.mmap_table
                        .update_native_dso_build_id(&event.filename, &id, event.misc);
                    self.header_build_ids.insert(
                        event.filename,
                        RecordedBuildId {
                            bytes: id,
                            misc: event.misc,
                        },
                    );
                }
            }
            FoldRecord::Comm(record) => {
                self.maps_for_thread(record.pid, record.tid);
                update_comm_tables(
                    &mut self.process_comms,
                    &mut self.exec_process_comms,
                    &mut self.thread_comms,
                    &record,
                );
            }
            FoldRecord::Mmap { misc, mut record } => {
                if record.pid != u32::MAX {
                    record.pid = self.maps_for_thread(record.pid, record.tid);
                }
                self.clear_mapping_dependent_unwind_memo(record.pid);
                // map.c:map__new reuses the DSO populated from HEADER_BUILD_ID
                // even for MMAP records, which carry no build ID themselves.
                let build_id = self
                    .header_build_ids
                    .get(&record.path)
                    .map(|id| id.bytes.clone());
                self.mmap_table
                    .insert_mmap_with_build_id_and_misc(record, build_id, misc);
                self.mapping_cache = MappingResolveCache::default();
            }
            FoldRecord::Mmap2 { misc, mut record } => {
                if record.pid != u32::MAX {
                    record.pid = self.maps_for_thread(record.pid, record.tid);
                }
                self.clear_mapping_dependent_unwind_memo(record.pid);
                let build_id = self
                    .header_build_ids
                    .get(&record.path)
                    .map(|id| id.bytes.clone());
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
            FoldRecord::Mmap2BuildId { misc, mut record } => {
                if record.pid != u32::MAX {
                    record.pid = self.maps_for_thread(record.pid, record.tid);
                }
                self.clear_mapping_dependent_unwind_memo(record.pid);
                self.mmap_table
                    .insert_mmap2_build_id_with_misc(record, misc);
                self.mapping_cache = MappingResolveCache::default();
            }
            FoldRecord::Fork(record) => {
                self.apply_fork_record(record);
            }
            FoldRecord::Exit(record) => {
                if !self.keep_exited_threads {
                    self.remove_thread(record.tid);
                }
            }
            FoldRecord::Ignored => {}
            FoldRecord::Sample { .. } | FoldRecord::CallchainDeferred(_) => {
                unreachable!("samples are delivered by the replay sink")
            }
        }
    }
}

fn inherit_fork_comm(
    thread_comms: &mut BTreeMap<u32, ThreadComm>,
    record: crate::perfdata::records::ForkRecord,
) {
    if let Some(comm) = thread_comms.get(&record.ptid).cloned() {
        thread_comms.insert(record.tid, comm);
    }
}

fn inherit_fork_comm_tables(
    process_comms: &mut BTreeMap<u32, String>,
    exec_process_comms: &mut BTreeMap<u32, String>,
    thread_comms: &mut BTreeMap<u32, ThreadComm>,
    record: crate::perfdata::records::ForkRecord,
) {
    inherit_fork_comm(thread_comms, record);
    if let Some(comm) = thread_comms.get(&record.tid).cloned() {
        process_comms.insert(record.pid, comm.name);
    }
    if let Some(comm) = exec_process_comms.get(&record.ppid).cloned() {
        exec_process_comms.insert(record.pid, comm);
    }
}

impl SessionState {
    #[cfg(test)]
    fn ensure_unwind_mapping_for_ip(&mut self, pid: Option<u32>, ip: u64) {
        let Some(pid) = pid else {
            return;
        };
        let state = self
            .unwind_states
            .entry(pid)
            .or_insert_with(|| PidUnwindState::with_arch(self.arch));
        report_unwind_module_for_ip_like_perf(
            state,
            &self.mmap_table,
            pid,
            ip,
            self.unwind_debug_dir.as_deref(),
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
    ) -> Result<Vec<DeferredFoldSample>, String> {
        let samples = std::mem::take(&mut self.deferred_samples);
        let mut matched = Vec::new();
        let mut unmatched = Vec::new();
        for mut sample in samples {
            if tid != sample.tid {
                unmatched.push(sample);
                continue;
            }
            if sample.cookie == cookie {
                merge_deferred_sample_payload(&mut sample, ips)?;
            } else {
                // session.c:1399 clears deferred_callchain on same-TID
                // mismatches, so the original cookie renders as an address.
                sample.cookie_to_suppress = None;
            }
            matched.push(sample);
        }
        self.deferred_samples = unmatched;
        Ok(matched)
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
        let key = unwind_module_key(mapping.path, mapping.start, mapping.pgoff);
        unwind_state
            .loaded_unwind_modules
            .get(&key)
            .is_some_and(|&module| {
                unwind_state.object_unwinder.reported_module_for_ip(ip) == Some(module)
            })
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommSyntax {
    Ordinary,
    Numeric,
    Stream,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ThreadComm {
    name: String,
    syntax: CommSyntax,
    trimmed: std::ops::Range<usize>,
    has_spaces: bool,
}

impl From<String> for ThreadComm {
    fn from(name: String) -> Self {
        // perf builtin-script.c:847 prints comm verbatim. Inferno perf.rs:293,
        // 331 and 431 interpret stream syntax, trim comm and replace spaces.
        let syntax = if name.starts_with('#') || name.contains('\n') {
            CommSyntax::Stream
        } else if inferno_numeric_header_word(&name).is_some() {
            CommSyntax::Numeric
        } else {
            CommSyntax::Ordinary
        };
        let trimmed = name.trim();
        let start = name.len() - name.trim_start().len();
        let end = start + trimmed.len();
        let has_spaces = trimmed.contains(' ');
        Self {
            name,
            syntax,
            trimmed: start..end,
            has_spaces,
        }
    }
}

impl From<&str> for ThreadComm {
    fn from(name: &str) -> Self {
        Self::from(name.to_owned())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SampleComm<'a> {
    Name(&'a str),
    Stored(&'a ThreadComm),
    Tid(u32),
}

impl std::fmt::Display for SampleComm<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Name(name) => formatter.pad(name),
            Self::Stored(comm) => formatter.pad(&comm.name),
            Self::Tid(tid) => {
                // A colon and the ten decimal digits of u32::MAX fit on the stack.
                let mut bytes = [0; 11];
                let mut writer = std::io::Cursor::new(bytes.as_mut_slice());
                write!(writer, ":{tid}").map_err(|_| std::fmt::Error)?;
                let len = usize::try_from(writer.position()).map_err(|_| std::fmt::Error)?;
                let name = std::str::from_utf8(&bytes[..len]).map_err(|_| std::fmt::Error)?;
                formatter.pad(name)
            }
        }
    }
}

fn comm_for_ids(
    thread_comms: &BTreeMap<u32, ThreadComm>,
    tid: Option<u32>,
) -> Option<SampleComm<'_>> {
    let tid = tid?;
    // perf util/thread.c:thread__new initializes ":%d" once per thread.
    // Keep that fallback numeric rather than allocating it for every sample.
    Some(
        thread_comms
            .get(&tid)
            .map_or(SampleComm::Tid(tid), SampleComm::Stored),
    )
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
    table: &MmapTable,
    frames: &[(FoldFrame, FrameMappingDecision<'_>, usize)],
    cache: &mut SymbolFrameCache<'_, R>,
    inline: bool,
) -> Result<(), String> {
    let resolver = cache.resolver();
    // Batch only the currently delivered sample. Future samples may observe a
    // different map; SymbolFrameCache deduplicates already resolved addresses.
    for expand in [true, false] {
        if expand && !inline {
            continue;
        }
        let mappings = frames.iter().filter_map(|(frame, decision, _)| {
            let FrameMappingDecision::Mapped(mapping) = decision else {
                return None;
            };
            (expand == (inline && !matches!(frame, FoldFrame::SampleIp { .. })))
                .then(|| table.symbol_mapping_ref(*mapping, Some(resolver)))
        });
        cache.prefetch_mapping_refs_with_mode(mappings, expand)?;
    }
    Ok(())
}

struct FoldFrameResolver<'a> {
    mmap_table: &'a MmapTable,
    inline: bool,
    cookie_to_suppress: Option<u64>,
}

#[derive(Clone, Copy)]
enum FrameMappingDecision<'a> {
    Mapped(MappedFrame<'a>),
    KernelAddress,
    Unknown,
    Address,
}

#[inline]
fn resolve_frame_in_context<'a>(
    context: Option<&FrameMappingContext<'a>>,
    frame: FoldFrame,
    address: u64,
    mapping_cache: &mut MappingResolveCache,
) -> Option<MappedFrame<'a>> {
    let context = context?;
    match frame {
        FoldFrame::Callchain(_) => context.resolve(address, mapping_cache),
        FoldFrame::HypervisorCallchain(_) => None,
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
struct ModuleProjections {
    by_key: HashMap<(usize, bool), usize, FxBuildHasher>,
    labels: Vec<LabelProjection>,
    last: std::cell::Cell<Option<ModuleProjectionHint>>,
    #[cfg(test)]
    searches: std::cell::Cell<usize>,
    #[cfg(test)]
    slot_reads: std::cell::Cell<usize>,
}

#[derive(Clone, Copy)]
struct ModuleProjectionHint {
    key: (usize, bool),
    value: ModuleProjectionValue,
}

#[derive(Clone, Copy)]
enum ModuleProjectionValue {
    Empty,
    Single(LabelId),
    Expanded(usize),
}

impl ModuleProjections {
    #[inline]
    fn labels_at(&self, slot: usize) -> &LabelProjection {
        #[cfg(test)]
        self.slot_reads.set(self.slot_reads.get() + 1);
        &self.labels[slot]
    }

    #[inline]
    fn get(&self, key: &(usize, bool)) -> Option<ProjectionRef<'_>> {
        if let Some(last) = self.last.get()
            && last.key == *key
        {
            return Some(match last.value {
                ModuleProjectionValue::Empty => ProjectionRef::Empty,
                ModuleProjectionValue::Single(id) => ProjectionRef::Single(id),
                ModuleProjectionValue::Expanded(slot) => self.labels_at(slot).view(),
            });
        }
        #[cfg(test)]
        self.searches.set(self.searches.get() + 1);
        let slot = *self.by_key.get(key)?;
        let labels = self.labels_at(slot);
        self.last.set(Some(ModuleProjectionHint {
            key: *key,
            value: labels.hint(slot),
        }));
        Some(labels.view())
    }

    fn insert(&mut self, key: (usize, bool), labels: LabelSpan) {
        let labels = LabelProjection::from(labels);
        let next = self.labels.len();
        let slot = *self.by_key.entry(key).or_insert(next);
        let value = labels.hint(slot);
        if slot == next {
            self.labels.push(labels);
        } else {
            self.labels[slot] = labels;
        }
        self.last.set(Some(ModuleProjectionHint { key, value }));
    }

    #[cfg(test)]
    fn storage_bytes(&self) -> usize {
        self.by_key.capacity() * std::mem::size_of::<((usize, bool), usize)>()
            + self.labels.capacity() * std::mem::size_of::<LabelProjection>()
    }
}

#[derive(Default)]
struct FoldedRenderBuffers {
    current: String,
    has_comm: bool,
    counts: FoldCounts,
    render_scratch: String,
    module_scratch: String,
    mapping_cache: MappingResolveCache,
    projecting: bool,
    module_labels: ModuleProjections,
    symbol_labels: [Vec<Option<LabelProjection>>; 2],
    unknown_label: Option<LabelId>,
    #[cfg(test)]
    raw_function_normalizations: usize,
    #[cfg(test)]
    segment_copy_entries: usize,
    #[cfg(test)]
    repeat_helper_entries: usize,
    #[cfg(test)]
    stack_len_reads: std::cell::Cell<usize>,
}

enum FoldedRenderStatus {
    Rendered,
    RequiresPerfText,
}

fn fold_frame_runs(
    frames: impl IntoIterator<Item = FoldFrame>,
) -> impl Iterator<Item = (FoldFrame, usize)> {
    let mut frames = frames.into_iter().peekable();
    std::iter::from_fn(move || {
        let frame = frames.next()?;
        let mut repeats = 1;
        while frames.next_if_eq(&frame).is_some() {
            repeats += 1;
        }
        Some((frame, repeats))
    })
}

fn mapping_requires_perf_text(mapping: &MappedFrame<'_>) -> bool {
    mapping.path_layout().text_row_boundary.is_some()
}

impl FoldedRenderBuffers {
    #[cfg(test)]
    fn module_projection_storage_bytes(&self) -> usize {
        self.module_labels.storage_bytes()
    }

    fn stack_len(&self) -> usize {
        #[cfg(test)]
        self.stack_len_reads.set(self.stack_len_reads.get() + 1);
        if self.projecting {
            self.counts.scratch_stack.len()
        } else {
            self.current.len()
        }
    }

    fn take_frame_projection(&mut self) -> LabelSpan {
        // The existing renderer supplies the separator even for an empty
        // frame. No separator means the row emitted no frame at all.
        let labels = self
            .current
            .strip_prefix(';')
            .map_or_else(LabelSpan::new, |text| {
                self.counts.append_serialized_labels(text)
            });
        self.current.clear();
        labels
    }

    fn finish_stack(&mut self, comm_prefix_len: usize) {
        if self.stack_len() == comm_prefix_len {
            self.current.clear();
            if self.projecting {
                self.counts.scratch_stack.clear();
            }
        }
    }

    #[inline]
    fn repeat_segment(&mut self, start: usize, repeats: usize) {
        #[cfg(test)]
        {
            self.repeat_helper_entries += 1;
        }
        if repeats <= 1 {
            return;
        }
        if self.projecting {
            let len = self.counts.scratch_stack.len() - start;
            self.counts.scratch_stack.reserve(len * (repeats - 1));
            for _ in 1..repeats {
                self.counts
                    .scratch_stack
                    .extend_from_within(start..start + len);
            }
            return;
        }
        self.copy_segment(start, repeats);
    }

    fn copy_segment(&mut self, start: usize, repeats: usize) {
        #[cfg(test)]
        {
            self.segment_copy_entries += 1;
        }
        if start == self.current.len() {
            return;
        }
        // Each rendered run starts after comm and contains its separator.
        // Duplicate whole UTF-8 segments, including any expanded inline chain.
        let len = self.current.len() - start;
        self.current.reserve(len * (repeats - 1));
        let mut copied = 1;
        while copied < repeats {
            let batch = copied.min(repeats - copied);
            self.current.extend_from_within(start..start + len * batch);
            copied += batch;
        }
    }

    fn start_stack(&mut self, comm: Option<SampleComm<'_>>) -> Result<(), String> {
        self.current.clear();
        self.has_comm = false;
        let projecting = std::mem::replace(&mut self.projecting, false);
        if let Some(SampleComm::Stored(comm)) = comm {
            let name = &comm.name[comm.trimmed.clone()];
            if comm.has_spaces {
                self.append_comm_with_spaces(name);
            } else {
                self.current.push_str(name);
            }
        } else if let Some(SampleComm::Name(comm)) = comm {
            // Inferno perf.rs:event_line_parts trims the comm; on_event_line
            // replaces only literal spaces. after_event copies pname verbatim.
            self.append_comm_with_spaces(comm.trim());
        } else if let Some(SampleComm::Tid(tid)) = comm {
            write!(self.current, ":{tid}").map_err(|error| error.to_string())?;
        } else {
            append_cached_inferno_perf_folded_label_to_buffers(self, UNKNOWN_FRAME);
        }
        self.has_comm = true;
        self.projecting = projecting;
        if projecting {
            let labels = self.counts.append_serialized_labels(&self.current);
            self.counts.scratch_stack.clear();
            append_projection_ids(&mut self.counts.scratch_stack, &labels);
            self.current.clear();
        }
        Ok(())
    }

    fn append_comm_with_spaces(&mut self, comm: &str) {
        self.current.reserve(comm.len());
        let mut start = 0;
        for index in memchr::memchr_iter(b' ', comm.as_bytes()) {
            self.current.push_str(&comm[start..index]);
            self.current.push('_');
            start = index + 1;
        }
        self.current.push_str(&comm[start..]);
    }

    #[cfg(test)]
    fn rendered(&self) -> String {
        if self.projecting {
            self.counts
                .scratch_stack
                .iter()
                .map(|&id| self.counts.names[id].as_ref())
                .collect::<Vec<_>>()
                .join(";")
        } else {
            self.current.clone()
        }
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
        Self {
            mmap_table,
            inline,
            cookie_to_suppress: None,
        }
    }

    fn mapping_decision(
        &self,
        pid: Option<u32>,
        frame: FoldFrame,
        mapping_cache: &mut MappingResolveCache,
    ) -> FrameMappingDecision<'a> {
        let context = pid.map(|pid| self.mmap_table.frame_context(pid, mapping_cache));
        Self::mapping_decision_in_context(context.as_ref(), frame, frame.address(), mapping_cache)
    }

    fn mapping_decision_in_context(
        context: Option<&FrameMappingContext<'a>>,
        frame: FoldFrame,
        address: u64,
        mapping_cache: &mut MappingResolveCache,
    ) -> FrameMappingDecision<'a> {
        if let Some(mapping) = resolve_frame_in_context(context, frame, address, mapping_cache) {
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
        comm: Option<SampleComm<'_>>,
        callchain: I,
        mut symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
        buffers: &mut FoldedRenderBuffers,
    ) -> Result<FoldedRenderStatus, String>
    where
        R: SymbolResolver,
        I: IntoIterator<Item = FoldFrame>,
    {
        buffers.start_stack(comm)?;
        let comm_prefix_len = buffers.stack_len();

        let context = pid.map(|pid| {
            self.mmap_table
                .frame_context(pid, &mut buffers.mapping_cache)
        });

        let mut callchain = fold_frame_runs(callchain);
        while let Some((frame, repeats)) = callchain.next() {
            let segment_start = if repeats > 1 { buffers.stack_len() } else { 0 };
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
            let decision = Self::mapping_decision_for_folded_frame(
                context.as_ref(),
                frame,
                symbol_cache.is_some(),
                &mut buffers.mapping_cache,
            );
            match decision {
                FrameMappingDecision::Mapped(mapping) => {
                    if mapping_requires_perf_text(&mapping) {
                        return Ok(FoldedRenderStatus::RequiresPerfText);
                    }
                    if let Some(cache) = symbol_cache.as_deref_mut() {
                        // Event-line IPs use machine__resolve(), not append_inlines().
                        let expand = self.inline && !matches!(frame, FoldFrame::SampleIp { .. });
                        if let Some((identity, cached)) =
                            cache.cached_mapping_frames_with_identity(&mapping, expand)
                        {
                            if matches!(
                                cached.render_mode,
                                crate::symbols::SymbolFrameRenderMode::PerfScript
                            ) {
                                return Ok(FoldedRenderStatus::RequiresPerfText);
                            }
                            append_projected_resolved_frames(
                                buffers, &mapping, frame, expand, identity, cached,
                            );
                            if repeats > 1 {
                                buffers.repeat_segment(segment_start, repeats);
                            }
                            continue;
                        }
                        // Keep decisions only on a cold miss. Warm samples stream
                        // directly; cold samples consume each remaining frame once.
                        let mut pending =
                            SmallVec::<[(FoldFrame, FrameMappingDecision<'_>, usize); 16]>::new();
                        pending.push((frame, decision, repeats));
                        pending.extend(callchain.by_ref().map(|(frame, repeats)| {
                            let decision = Self::mapping_decision_for_folded_frame(
                                context.as_ref(),
                                frame,
                                true,
                                &mut buffers.mapping_cache,
                            );
                            (frame, decision, repeats)
                        }));
                        let status = append_pending_folded_frames(
                            self.mmap_table,
                            &pending,
                            buffers,
                            cache,
                            self.inline,
                        )?;
                        if matches!(status, FoldedRenderStatus::RequiresPerfText) {
                            return Ok(status);
                        }
                        break;
                    }
                    append_frame_mapping_fallback(buffers, &mapping);
                }
                FrameMappingDecision::KernelAddress | FrameMappingDecision::Address => {
                    append_folded_address_label(buffers, frame.address());
                }
                FrameMappingDecision::Unknown => {
                    append_cached_inferno_perf_folded_label_to_buffers(buffers, UNKNOWN_FRAME);
                }
            }
            if repeats > 1 {
                buffers.repeat_segment(segment_start, repeats);
            }
        }
        buffers.finish_stack(comm_prefix_len);
        Ok(FoldedRenderStatus::Rendered)
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
                && self.cookie_to_suppress != Some(frame.address())
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
                if self.inline || self.cookie_to_suppress == Some(address) {
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
                    mapping.display_path(),
                    &self.mmap_table.symbol_mapping_ref(
                        mapping,
                        symbol_cache.as_ref().map(|cache| cache.resolver()),
                    ),
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
        let is_cookie = self.cookie_to_suppress == Some(address);
        let decision = if is_cookie {
            let context = pid.map(|pid| self.mmap_table.frame_context(pid, mapping_cache));
            resolve_frame_in_context(context.as_ref(), frame, address, mapping_cache)
                .map_or(FrameMappingDecision::Unknown, FrameMappingDecision::Mapped)
        } else {
            self.mapping_decision(pid, frame, mapping_cache)
        };
        match decision {
            FrameMappingDecision::Mapped(mapping) => {
                write_perf_script_mapped_decision_frame(
                    writer,
                    address,
                    is_cookie,
                    mapping.display_path(),
                    &self.mmap_table.symbol_mapping_ref(
                        mapping,
                        symbol_cache.as_ref().map(|cache| cache.resolver()),
                    ),
                    symbol_cache,
                    self.inline,
                )?;
            }
            FrameMappingDecision::KernelAddress | FrameMappingDecision::Address => {
                write_perf_script_address_frame(writer, address)?;
            }
            FrameMappingDecision::Unknown => {
                if is_cookie {
                    write_perf_script_mapped_symbol_frame(
                        writer,
                        address,
                        "(cookie)",
                        UNKNOWN_FRAME,
                    )?;
                } else {
                    write_perf_script_unknown_frame(writer, address)?;
                }
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
        if symbolizing && matches!(frame, FoldFrame::InlineCurrentIp(_)) {
            return resolve_frame_in_context(context, frame, address, mapping_cache)
                .map_or(FrameMappingDecision::Unknown, FrameMappingDecision::Mapped);
        }
        let decision = Self::mapping_decision_in_context(context, frame, address, mapping_cache);
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

fn append_pending_folded_frames<R: SymbolResolver>(
    table: &MmapTable,
    pending: &[(FoldFrame, FrameMappingDecision<'_>, usize)],
    buffers: &mut FoldedRenderBuffers,
    cache: &mut SymbolFrameCache<'_, R>,
    inline: bool,
) -> Result<FoldedRenderStatus, String> {
    if pending.iter().any(|(_, decision, _)| {
        matches!(decision, FrameMappingDecision::Mapped(mapping) if mapping_requires_perf_text(mapping))
    }) {
        return Ok(FoldedRenderStatus::RequiresPerfText);
    }
    // A native kernel source can replace module maps between cursor nodes.
    // Until initialized, use the existing ordered script path, before reversed
    // folded-frame prefetch can resolve a later node ahead of an earlier one.
    if pending.iter().any(|(_, decision, _)| {
        matches!(decision,
        FrameMappingDecision::Mapped(mapping) if mapping.is_kernel())
    }) && cache.requires_kernel_cursor_order()
    {
        return Ok(FoldedRenderStatus::RequiresPerfText);
    }
    prefetch_sample_symbols(table, pending, cache, inline)?;
    for &(frame, decision, repeats) in pending {
        let segment_start = if repeats > 1 { buffers.stack_len() } else { 0 };
        let status = append_prefetched_folded_frame(buffers, frame, decision, cache, inline)?;
        if matches!(status, FoldedRenderStatus::RequiresPerfText) {
            return Ok(status);
        }
        if repeats > 1 {
            buffers.repeat_segment(segment_start, repeats);
        }
    }
    Ok(FoldedRenderStatus::Rendered)
}

fn append_prefetched_folded_frame<R: SymbolResolver>(
    buffers: &mut FoldedRenderBuffers,
    frame: FoldFrame,
    decision: FrameMappingDecision<'_>,
    cache: &SymbolFrameCache<'_, R>,
    inline: bool,
) -> Result<FoldedRenderStatus, String> {
    match decision {
        FrameMappingDecision::Mapped(mapping) => {
            let expand = inline && !matches!(frame, FoldFrame::SampleIp { .. });
            let (identity, cached) = cache
                .cached_mapping_frames_with_identity(&mapping, expand)
                .ok_or_else(|| "symbol frame cache lookup missed after resolution".to_string())?;
            if matches!(
                cached.render_mode,
                crate::symbols::SymbolFrameRenderMode::PerfScript
            ) {
                return Ok(FoldedRenderStatus::RequiresPerfText);
            }
            append_projected_resolved_frames(buffers, &mapping, frame, expand, identity, cached);
        }
        FrameMappingDecision::KernelAddress | FrameMappingDecision::Address => {
            append_folded_address_label(buffers, frame.address());
        }
        FrameMappingDecision::Unknown => {
            append_cached_inferno_perf_folded_label_to_buffers(buffers, UNKNOWN_FRAME);
        }
    }
    Ok(FoldedRenderStatus::Rendered)
}

#[inline]
fn append_projected_resolved_frames(
    buffers: &mut FoldedRenderBuffers,
    mapping: &MappedFrame<'_>,
    frame: FoldFrame,
    expand: bool,
    identity: Option<crate::symbols::MappingFramesIdentity>,
    cached: &CachedMappingFrames,
) {
    if !buffers.projecting {
        append_resolved_folded_frames(buffers, mapping, frame, expand, cached);
        return;
    }
    if matches!(frame, FoldFrame::InlineCurrentIp(_)) && !expand {
        if !cached.has_base_symbol {
            if is_kernel_space_frame(frame.address()) && !mapping.is_kernel() {
                append_folded_address_label(buffers, frame.address());
            } else {
                append_frame_mapping_fallback(buffers, mapping);
            }
            return;
        }
    } else if cached.frames.is_empty() {
        append_frame_mapping_fallback(buffers, mapping);
        return;
    }
    let identity = identity.expect("nonnegative cached frames have a projection identity");
    let (namespace, index) = identity.projection_index();
    if let Some(Some(labels)) = buffers.symbol_labels[namespace].get(index) {
        append_label_projection(&mut buffers.counts.scratch_stack, labels);
        return;
    }
    cache_resolved_frame_projection(buffers, mapping, frame, expand, namespace, index, cached);
}

#[cold]
#[inline(never)]
fn cache_resolved_frame_projection(
    buffers: &mut FoldedRenderBuffers,
    mapping: &MappedFrame<'_>,
    frame: FoldFrame,
    expand: bool,
    namespace: usize,
    index: usize,
    cached: &CachedMappingFrames,
) {
    append_resolved_folded_frames(buffers, mapping, frame, expand, cached);
    let labels = LabelProjection::from(buffers.take_frame_projection());
    append_label_projection(&mut buffers.counts.scratch_stack, &labels);
    let slots = &mut buffers.symbol_labels[namespace];
    if slots.len() <= index {
        slots.resize_with(index + 1, || None);
    }
    slots[index] = Some(labels);
}

fn append_resolved_folded_frames(
    buffers: &mut FoldedRenderBuffers,
    mapping: &MappedFrame<'_>,
    frame: FoldFrame,
    expand: bool,
    cached: &CachedMappingFrames,
) {
    if matches!(frame, FoldFrame::InlineCurrentIp(_)) && !expand {
        if !cached.has_base_symbol {
            if is_kernel_space_frame(frame.address()) && !mapping.is_kernel() {
                append_folded_address_label(buffers, frame.address());
            } else {
                append_frame_mapping_fallback(buffers, mapping);
            }
            return;
        }
    } else if cached.frames.is_empty() {
        append_frame_mapping_fallback(buffers, mapping);
        return;
    }
    debug_assert_eq!(cached.frames.len(), cached.literal_ends.len());
    for (index, label) in cached.frames.iter().enumerate() {
        if let Some(end) = cached.literal_ends[index] {
            append_separator(&mut buffers.current, buffers.has_comm);
            buffers.current.push_str(&label[..end]);
        } else {
            append_cached_inferno_perf_raw_function_to_buffers(buffers, label);
        }
    }
}

fn append_folded_address_label(buffers: &mut FoldedRenderBuffers, address: u64) {
    if buffers.projecting {
        buffers.current.clear();
        write!(buffers.current, "0x{address:x}").expect("writing to a string cannot fail");
        let label = buffers.counts.intern(&buffers.current);
        buffers.counts.scratch_stack.push(label);
        buffers.current.clear();
        return;
    }
    append_separator(&mut buffers.current, buffers.has_comm);
    write!(buffers.current, "0x{address:x}").expect("writing to a string cannot fail");
}

fn append_cached_inferno_perf_raw_function_to_buffers(
    buffers: &mut FoldedRenderBuffers,
    frame: &str,
) {
    #[cfg(test)]
    {
        buffers.raw_function_normalizations += 1;
    }
    append_inferno_perf_raw_function(
        &mut buffers.current,
        frame,
        &mut buffers.render_scratch,
        buffers.has_comm,
    );
}

fn append_cached_inferno_perf_folded_label_to_buffers(
    buffers: &mut FoldedRenderBuffers,
    label: &str,
) {
    if buffers.projecting && label == UNKNOWN_FRAME {
        let id = *buffers
            .unknown_label
            .get_or_insert_with(|| buffers.counts.intern(UNKNOWN_FRAME));
        buffers.counts.scratch_stack.push(id);
        return;
    }
    if !label.is_empty() {
        append_inferno_perf_folded_label(&mut buffers.current, label, buffers.has_comm);
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

#[inline]
fn append_frame_mapping_fallback(buffers: &mut FoldedRenderBuffers, mapping: &MappedFrame<'_>) {
    if buffers.projecting {
        // Symbol source aliases can share debuginfo while perf still prints
        // different DSO names (symbol.c:maps__split_kallsyms). Key display
        // projections by the actual path and address-dependent kernel class.
        let key = (mapping.display_path_id(), mapping.is_kernel());
        if let Some(labels) = buffers.module_labels.get(&key) {
            labels.append_to(&mut buffers.counts.scratch_stack);
            return;
        }
        cache_frame_mapping_fallback(buffers, mapping, key);
    } else {
        render_frame_mapping_fallback(buffers, mapping);
    }
}

#[cold]
#[inline(never)]
fn cache_frame_mapping_fallback(
    buffers: &mut FoldedRenderBuffers,
    mapping: &MappedFrame<'_>,
    key: (usize, bool),
) {
    buffers.projecting = false;
    render_frame_mapping_fallback(buffers, mapping);
    buffers.projecting = true;
    let labels = buffers.take_frame_projection();
    append_projection_ids(&mut buffers.counts.scratch_stack, &labels);
    buffers.module_labels.insert(key, labels);
}

fn render_frame_mapping_fallback(buffers: &mut FoldedRenderBuffers, mapping: &MappedFrame<'_>) {
    // Inferno src/collapse/perf.rs:450,610 consumes perf's displayed DSO,
    // not the long source path retained for ELF selection.
    let raw_path = mapping.display_path();
    let kernel = mapping.is_kernel();
    let path = if kernel {
        perf_script_dso_name(raw_path)
    } else {
        raw_path
    };
    if path.len() == raw_path.len() {
        append_module_fallback(buffers, path, mapping.path_layout(), kernel);
    } else {
        append_literal_module(&mut buffers.current, path, false, buffers.has_comm);
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
            buffers.has_comm,
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
        append_separator(&mut buffers.current, buffers.has_comm);
        escape_frame_into(&mut buffers.current, &buffers.render_scratch);
    } else {
        append_literal_module(
            &mut buffers.current,
            name,
            layout.fallback == ModuleFallbackKind::Escaped,
            buffers.has_comm,
        );
    }
}

fn append_literal_module(output: &mut String, name: &str, escape: bool, has_prefix: bool) {
    output.reserve(name.len() + 2 + usize::from(!output.is_empty()));
    append_separator(output, has_prefix);
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
    is_cookie: bool,
    display_path: &str,
    mapping: &ResolvedMappingRef<'_>,
    mut symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
    inline: bool,
) -> Result<(), String>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    let result = write_perf_script_mapped_decision_cursor(
        writer,
        address,
        is_cookie,
        display_path,
        mapping,
        symbol_cache.as_deref_mut(),
        inline,
    );
    if let Some(cache) = symbol_cache {
        cache.finish_kernel_cursor();
    }
    result
}

fn write_perf_script_mapped_decision_cursor<R, W>(
    writer: &mut W,
    address: u64,
    is_cookie: bool,
    display_path: &str,
    mapping: &ResolvedMappingRef<'_>,
    symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
    inline: bool,
) -> Result<(), String>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    let Some(cache) = symbol_cache else {
        if is_cookie {
            write_perf_script_mapped_symbol_frame(writer, address, "(cookie)", display_path)?;
        } else {
            write_perf_script_mapped_unknown_symbol_frame(writer, address, display_path)?;
        }
        return Ok(());
    };
    let cached = cache.resolve_script_mapping_ref(mapping, inline)?;
    let dso_name = if cached.kernel_dso == crate::symbols::SymbolDsoName::KernelKallsyms {
        "[kernel.kallsyms]"
    } else {
        display_path
    };
    if !inline {
        if is_cookie {
            return write_perf_script_mapped_symbol_frame(writer, address, "(cookie)", dso_name);
        }
        return match (cached.has_base_symbol, cached.frames.first()) {
            (true, Some(label)) => {
                write_perf_script_mapped_symbol_frame(writer, address, label, dso_name)
            }
            _ => write_perf_script_mapped_unknown_symbol_frame(writer, address, dso_name),
        };
    }
    let frames = &cached.frames;
    let base_offset = cached.base_offset;
    let has_inline_frames = cached.has_inline_frames;
    let has_non_inline_base_frame = cached.has_non_inline_base_frame;
    if frames.is_empty() {
        if is_cookie {
            write_perf_script_mapped_symbol_frame(writer, address, "(cookie)", dso_name)?;
        } else {
            write_perf_script_mapped_unknown_symbol_frame(writer, address, dso_name)?;
        }
    } else if frames.len() == 1 && !has_inline_frames {
        // A single non-inline base frame already carries its +0x<off> baked in
        // by perf_frames_with_object_alias_and_offset (the symtab with_offset
        // form), so print it verbatim with the DSO path.
        let label = if is_cookie { "(cookie)" } else { &frames[0] };
        write_perf_script_mapped_symbol_frame(writer, address, label, dso_name)?;
    } else {
        let last = frames.len() - 1;
        for (printed_index, label) in frames.iter().rev().enumerate() {
            let is_inlined = has_inline_frames
                && (frames.len() == 1 || printed_index != last || !has_non_inline_base_frame);
            // evsel_fprintf.c:171 changes only the symbol text after cursor
            // expansion; lines 185 and 195 preserve each node's inline suffix.
            let (label, base_offset) = if is_cookie {
                ("(cookie)", None)
            } else {
                (label.as_str(), base_offset)
            };
            write_perf_script_inline_chain_frame(
                writer,
                address,
                label,
                base_offset,
                dso_name,
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
    display_path: &str,
    mapping: &ResolvedMappingRef<'_>,
    mut symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
) -> Result<(), String>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    let result = write_perf_script_inline_mapped_decision_cursor(
        writer,
        address,
        display_path,
        mapping,
        symbol_cache.as_deref_mut(),
    );
    if let Some(cache) = symbol_cache {
        cache.finish_kernel_cursor();
    }
    result
}

fn write_perf_script_inline_mapped_decision_cursor<R, W>(
    writer: &mut W,
    address: u64,
    display_path: &str,
    mapping: &ResolvedMappingRef<'_>,
    symbol_cache: Option<&mut SymbolFrameCache<'_, R>>,
) -> Result<(), String>
where
    R: SymbolResolver,
    W: IoWrite + ?Sized,
{
    if let Some(cache) = symbol_cache {
        let cached = cache.resolve_script_mapping_ref(mapping, false)?;
        let dso_name = if cached.kernel_dso == crate::symbols::SymbolDsoName::KernelKallsyms {
            "[kernel.kallsyms]"
        } else {
            display_path
        };
        if let (true, Some(label)) = (cached.has_base_symbol, cached.frames.first()) {
            return write_perf_script_mapped_symbol_frame_fragment(
                writer, "", address, label, dso_name,
            );
        }
        return write_perf_script_mapped_unknown_symbol_frame_fragment(
            writer, "", address, dso_name,
        );
    }
    write_perf_script_mapped_unknown_symbol_frame_fragment(writer, "", address, display_path)
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
    arch: PerfArch,
) -> Result<Option<PerfSampleStack>, String> {
    if let Some(event) = sample_layouts.layout_for_payload(payload)? {
        parse_sample_record_metadata(payload, event.layout).map(|sample| {
            sample.map(|sample| PerfSampleStack {
                misc: sample_misc,
                cpumode: sample_misc & PERF_RECORD_MISC_CPUMODE_MASK,
                pid: sample.pid,
                tid: sample.tid,
                time: sample.time,
                cpu: sample.cpu,
                period: Some(sample.period.unwrap_or(event.default_period)),
                callchain: sample.frames.collect(),
                has_user_stack: sample.user_stack.is_some(),
                user_register_count: sample
                    .user_regs
                    .as_ref()
                    .map_or(0, |regs| regs.values.len()),
                user_register_ip: sample.user_regs.as_ref().and_then(|regs| {
                    perf_user_reg_value(
                        event.layout.sample_regs_user,
                        &regs.values,
                        arch.instruction_pointer_register(),
                    )
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

#[cfg(test)]
fn prepare_sample_for_fold<'layout, 'frames>(
    accumulator: &mut SessionState,
    misc: u16,
    payload: &[u8],
    sample_layouts: &'layout SampleLayouts,
    options: FoldOptions,
    frames: &'frames mut FoldFrameStack,
) -> Result<Option<PreparedFoldSample<'layout, 'frames>>, String> {
    let Some(event) = sample_layouts.layout_for_payload(payload)? else {
        return Ok(None);
    };
    let Some(sample) = parse_sample_record_callchain(payload, event.layout)? else {
        return Ok(None);
    };
    Ok(Some(prepare_parsed_sample_for_fold(
        accumulator,
        misc,
        event,
        &sample,
        options,
        frames,
    )))
}

fn prepare_parsed_sample_for_fold<'layout, 'frames>(
    accumulator: &mut SessionState,
    misc: u16,
    event: &'layout SampleEventLayout,
    sample: &crate::perfdata::samples::SampleCallchain<'_>,
    options: FoldOptions,
    frames: &'frames mut FoldFrameStack,
) -> PreparedFoldSample<'layout, 'frames> {
    let map_group = sample
        .pid
        .map(|pid| accumulator.maps_for_thread(pid, sample.tid.unwrap_or(pid)));
    let count = sample_fold_count(sample.period, event.default_period, options);
    frames.clear();
    frames.reserve(sample.frames.len());
    let has_callchain = event.layout.sample_type & PERF_SAMPLE_CALLCHAIN != 0;
    if has_callchain {
        extend_recorded_callchain_frames_like_perf(
            frames,
            sample.frames.clone(),
            PERF_SCRIPT_MAX_STACK,
        );
    } else {
        extend_sample_ip_frame_like_perf_machine_resolve(frames, misc, sample.frames.clone());
    }
    append_perf_user_unwind_frames(accumulator, misc, event, sample, map_group, frames);
    PreparedFoldSample {
        pid: sample.pid,
        map_group: map_group.unwrap_or_default(),
        sample_ip: sample.sample_ip,
        cpumode: misc & PERF_RECORD_MISC_CPUMODE_MASK,
        tid: sample.tid,
        time: sample.time,
        cpu: sample.cpu,
        event_name: &event.event_name,
        event_fields: &event.event_fields,
        count,
        frames,
        cookie_to_suppress: None,
        has_callchain,
    }
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
    max_stack: usize,
) {
    // tools/perf/util/machine.c add_callchain_ip() switches cpumode only when
    // it encounters PERF_CONTEXT_* markers. A kernel-looking address that is
    // still under PERF_RECORD_MISC_USER must therefore resolve against user
    // maps and normally prints as [unknown], not fall into kernel maps by
    // address alone.
    let mut cpumode = PERF_RECORD_MISC_CPUMODE_USER;
    let mut addresses = 0;
    let callchain = callchain.into_iter();
    frames.reserve(callchain.size_hint().0.min(max_stack));
    for ip in callchain {
        // machine.c:__thread__resolve_callchain_sample tests nr_entries before
        // each iteration and increments it only for IPs below PERF_CONTEXT_MAX.
        if addresses == max_stack {
            break;
        }
        if is_perf_context_marker(ip) {
            // machine.c:2171-2198 consumes supported contexts without adding
            // cursor nodes; an unsupported context discards the whole cursor.
            cpumode = match ip {
                PERF_CONTEXT_HV => PERF_RECORD_MISC_CPUMODE_HYPERVISOR,
                PERF_CONTEXT_KERNEL => PERF_RECORD_MISC_CPUMODE_KERNEL,
                PERF_CONTEXT_USER | PERF_CONTEXT_USER_DEFERRED => PERF_RECORD_MISC_CPUMODE_USER,
                _ => {
                    frames.clear();
                    break;
                }
            };
            continue;
        }
        addresses += 1;
        frames.push(match cpumode {
            PERF_RECORD_MISC_CPUMODE_USER => FoldFrame::UserCallchain(ip),
            PERF_RECORD_MISC_CPUMODE_HYPERVISOR => FoldFrame::HypervisorCallchain(ip),
            _ => FoldFrame::Callchain(ip),
        });
    }
}

fn append_perf_user_unwind_frames(
    accumulator: &mut SessionState,
    misc: u16,
    event: &SampleEventLayout,
    sample: &crate::perfdata::samples::SampleCallchain<'_>,
    map_group: Option<u32>,
    frames: &mut FoldFrameStack,
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
    let context = build_user_unwind_context(
        accumulator,
        misc,
        event,
        sample,
        map_group,
        &regs,
        !frames.is_empty(),
    );
    let mut unwound_frames =
        unwind_user_stack_like_perf(accumulator, sample, map_group, &regs, context);
    let mut mapping_cache = MappingResolveCache::default();
    truncate_user_unwind_at_first_unmapped_frame(
        map_group,
        &mut unwound_frames,
        &accumulator.mmap_table,
        &mut mapping_cache,
    );
    frames.extend(unwound_frames);
}

fn build_user_unwind_context(
    accumulator: &SessionState,
    misc: u16,
    event: &SampleEventLayout,
    sample: &crate::perfdata::samples::SampleCallchain<'_>,
    map_group: Option<u32>,
    regs: &PerfUserRegs,
    has_sample_frames: bool,
) -> UserUnwindContext {
    let sample_callchain = if event.layout.sample_type & PERF_SAMPLE_CALLCHAIN != 0 {
        SampleCallchainPresence::Present
    } else {
        SampleCallchainPresence::Absent
    };
    UserUnwindContext {
        sample_callchain,
        callchain: sample_callchain_state(misc, event, sample, has_sample_frames),
        initial_ip_mapping: initial_ip_mapping_state(accumulator, map_group, regs.ip()),
        module_count: loaded_unwind_module_count(accumulator, map_group),
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
    map_group: Option<u32>,
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
        UserUnwindSource::Object => unwind_object_stack_like_perf(
            accumulator,
            sample,
            map_group,
            regs,
            stack_bytes,
            context,
        ),
    }
}

fn unwind_object_stack_like_perf(
    accumulator: &mut SessionState,
    sample: &crate::perfdata::samples::SampleCallchain<'_>,
    map_group: Option<u32>,
    regs: &PerfUserRegs,
    stack_bytes: &[u8],
    context: UserUnwindContext,
) -> Vec<FoldFrame> {
    let (Some(pid_value), Some(tid)) = (map_group, sample.tid) else {
        return Vec::new();
    };
    let mut state = accumulator
        .unwind_states
        .remove(&pid_value)
        .unwrap_or_else(|| PidUnwindState::with_arch(accumulator.arch));
    let unwind_debug_dir = accumulator.unwind_debug_dir.clone();
    let frames = unwind_object_frame_addresses_like_perf(
        &mut state,
        (pid_value, tid),
        &mut MappedMemory::new(
            pid_value,
            &accumulator.mmap_table,
            &mut accumulator.unwind_memory,
            unwind_debug_dir.as_deref(),
        ),
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
    (pid, tid): (u32, u32),
    memory: &mut MappedMemory<'_>,
    regs: &PerfUserRegs,
    stack_bytes: &[u8],
    mut context: UserUnwindContext,
) -> Vec<u64> {
    let mmap_table = memory.table;
    let unwind_debug_dir = memory.debug_dir;
    // perf's unwind__get_entries reports the module for the initial IP up front
    // (tools/perf/util/unwind-libdw.c): a hard report failure (scenario B)
    // abandons the whole unwind with zero entries.
    match report_unwind_module_for_ip_like_perf(state, mmap_table, pid, regs.ip(), unwind_debug_dir)
    {
        ReportModuleResult::Failed => return Vec::new(),
        ReportModuleResult::NewlyReported | ReportModuleResult::AlreadyReported => {
            context.initial_ip_mapping = InitialIpMappingState::RecordedMappingLoaded;
        }
        ReportModuleResult::NoDso => {}
    }

    // unwind-libdw.c:403-408 attempts attachment after reporting the initial
    // module, then requests this TID. elfutils dwfl_frame.c:136-144 rejects
    // reattachment; getthread() enumerates only dwfl_pid() via next_thread()
    // and returns ESRCH for another TID. With no module, attachment cannot
    // identify the architecture (dwfl_frame.c:166-195) and may be retried.
    match state.attached_tid {
        Some(attached) if attached != tid => return Vec::new(),
        Some(_) => {}
        None if state.object_unwinder.module_count() == 0 => return Vec::new(),
        None => state.attached_tid = Some(tid),
    }

    // unwind-libdw.c:84-85 succeeds with no user DSO. Once attachment is
    // available, an unmapped initial PC still receives its frame callback
    // (elfutils dwfl_frame.c:465-473). Only the no-CFI leaf shortcut remains.
    let leaf_only = sample_is_leaf_only(state, pid, mmap_table, regs);
    if leaf_only {
        return perf_accepted_object_unwind_frames(regs, true, Vec::new());
    }

    let (raw_frames, failed) =
        unwind_reported_frame_addresses_like_perf(state, pid, memory, regs, stack_bytes);
    if failed {
        return perf_accepted_object_unwind_frames(regs, false, raw_frames);
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
    let mut raw_frames = libdw_arch_fallback_after_empty_object_unwind(
        raw_frames,
        regs,
        stack_bytes,
        use_libdw_arch_fallback,
    );
    report_callback_entries_like_perf(state, mmap_table, pid, &mut raw_frames, unwind_debug_dir);
    let raw_frames = truncate_syscall_return_unwind_after_first_executable_frame(
        raw_frames,
        Some(pid),
        mmap_table,
        context,
    );
    perf_accepted_object_unwind_frames(regs, leaf_only, raw_frames)
}

fn unwind_reported_frame_addresses_like_perf(
    state: &mut PidUnwindState,
    pid: u32,
    memory: &mut MappedMemory<'_>,
    regs: &PerfUserRegs,
    stack: &[u8],
) -> (Vec<u64>, bool) {
    let mut unwind = state
        .object_unwinder
        .unwind_stack_with_diagnostics_and_memory(*regs, stack, 256, |address| {
            memory.read_u64(address)
        });
    for _ in 0..MAX_LIBDW_CALLBACK_REPORT_PASSES {
        let (added, failed) = report_callback_entries_like_perf(
            state,
            memory.table,
            pid,
            &mut unwind.accepted_frames,
            memory.debug_dir,
        );
        if failed {
            return (unwind.accepted_frames, true);
        }
        if !added {
            break;
        }
        let next = state
            .object_unwinder
            .unwind_stack_with_diagnostics_and_memory(*regs, stack, 256, |address| {
                memory.read_u64(address)
            });
        if next == unwind {
            break;
        }
        unwind = next;
    }
    (unwind.accepted_frames, false)
}

fn report_callback_entries_like_perf(
    state: &mut PidUnwindState,
    mmap_table: &MmapTable,
    pid: u32,
    frames: &mut Vec<u64>,
    debug_dir: Option<&Path>,
) -> (bool, bool) {
    let mut added = false;
    for (index, &ip) in frames.iter().enumerate() {
        // framehop's accepted caller PCs have already been decremented. perf
        // first reports the raw callback PC, ignores failure, then entry reports
        // the adjusted PC and gates acceptance (unwind-libdw.c:326-338,158).
        let callback_ip = if index == 0 { ip } else { ip.saturating_add(1) };
        added |= report_unwind_modules_for_frame_callbacks_like_perf(
            state,
            mmap_table,
            pid,
            &[callback_ip],
            debug_dir,
        );
        match report_unwind_module_for_ip_like_perf(state, mmap_table, pid, ip, debug_dir) {
            ReportModuleResult::Failed => {
                frames.truncate(index);
                return (added, true);
            }
            ReportModuleResult::NewlyReported => added = true,
            ReportModuleResult::NoDso | ReportModuleResult::AlreadyReported => {}
        }
    }
    (added, false)
}

/// Whether perf/libdw would fire the initial-frame callback exactly once and
/// stop: the sampled IP reported into a module, no CFI covers it, and the
/// arch-specific `ebl_unwind` fallback provably cannot advance.
///
/// The `(pid, ip)`-stable half (module reported + no CFI) is memoized in
/// `state.leaf_only_eligibility`; the per-sample register condition
/// (caller-SP advancement on `x86_64`, `lr == 0` on aarch64) is combined here fresh.
fn sample_is_leaf_only(
    state: &mut PidUnwindState,
    pid: u32,
    mmap_table: &MmapTable,
    regs: &PerfUserRegs,
) -> bool {
    let ip = regs.ip();
    if !mmap_table
        .user_mapping_for_pid_ip(pid, ip)
        .is_some_and(|mapping| {
            reported_unwind_module_for_mapping(&state.object_unwinder, mapping, ip).is_some()
        })
    {
        // A no-CFI leaf still runs callback reporting. It cannot take this
        // shortcut when a base mismatch would reopen and GC the seed module.
        return false;
    }
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
/// `x86_64` (`backends/x86_64_unwind.c:54,79-91`): a zero frame pointer stops
/// immediately; otherwise the caller SP after popping both words must advance.
///
/// aarch64 (`backends/aarch64_unwind.c`): the caller pc comes from `lr`; the
/// fallback returns false immediately when `lr == 0`. So `lr == 0` means no
/// caller.
fn arch_fallback_provably_cannot_advance(regs: &PerfUserRegs) -> bool {
    match *regs {
        PerfUserRegs::X86_64(regs) => regs.bp == 0 || regs.sp >= regs.bp.wrapping_add(16),
        PerfUserRegs::Aarch64(regs) => regs.lr == 0,
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
    let module_key = unwind_module_key(mapping.path, mapping.start, mapping.pgoff);
    let result = if let Some(module) =
        reported_unwind_module_for_mapping(&state.object_unwinder, mapping, ip)
    {
        ObjectMappingResult::Reused(module)
    } else {
        load_unwind_mapping_for_user_mapping_like_perf(state, mapping, unwind_debug_dir)
    };
    // unwind-libdw.c:133 compares the returned module with addrmodule(ip), not
    // addrmodule(map.start): the map can start in a PT_LOAD prefix or gap.
    if result.module().is_none()
        || result.module() != state.object_unwinder.reported_module_for_ip(ip)
    {
        return ReportModuleResult::Failed;
    }
    state
        .loaded_unwind_modules
        .insert(module_key, result.module().expect("reported module"));
    match result {
        ObjectMappingResult::Added(_) => {
            state.leaf_only_eligibility.clear();
            ReportModuleResult::NewlyReported
        }
        ObjectMappingResult::Reused(_) => ReportModuleResult::AlreadyReported,
        ObjectMappingResult::Rejected => ReportModuleResult::Failed,
    }
}

fn reported_unwind_module_for_mapping(
    unwinder: &FramehopUnwinder,
    mapping: UserMapping<'_>,
    ip: u64,
) -> Option<usize> {
    let base = if mapping.path.starts_with("/tmp/jitted-") {
        mapping.start
    } else {
        mapping.start.wrapping_sub(mapping.pgoff)
    };
    unwinder
        .reported_module_for_ip(ip)
        .filter(|&module| unwinder.reported_module_start(module) == base)
}

fn load_unwind_mapping_for_user_mapping_like_perf(
    state: &mut PidUnwindState,
    mapping: UserMapping<'_>,
    unwind_debug_dir: Option<&Path>,
) -> ObjectMappingResult {
    let path = mapping.path.to_string();
    let name = Path::new(mapping.path)
        .file_name()
        .unwrap_or(std::ffi::OsStr::new(mapping.path))
        .to_string_lossy();
    let build_id = mapping
        .build_id
        .filter(|id| id.iter().any(|byte| *byte != 0))
        .map(<[u8]>::to_vec);
    let request = UnwindMappingRequest {
        start: mapping.start,
        len: mapping.len,
        pgoff: mapping.pgoff,
        prot: mapping.prot,
        path: &path,
        module_name: &name,
        file_identity: mapping.file_identity,
        build_id: build_id.as_deref(),
    };
    // Actual reporting can add or GC a module even when its result is failure.
    state.leaf_only_eligibility.clear();
    let result = report_unwind_mapping_source(state, request, unwind_debug_dir);
    let key = unwind_module_key(mapping.path, mapping.start, mapping.pgoff);
    if let Some(module) = result.module() {
        state.loaded_unwind_modules.insert(key, module);
    } else {
        state.loaded_unwind_modules.remove(&key);
    }
    result
}

fn report_unwind_mapping_source(
    state: &mut PidUnwindState,
    request: UnwindMappingRequest<'_>,
    unwind_debug_dir: Option<&Path>,
) -> ObjectMappingResult {
    // perf reports the native vDSO from its live ELF image when no recorded
    // cache object is available. Symbolization already follows this fallback;
    // unwinding must report the same module before accepting the initial IP.
    // Compat names need their own recorded object and cannot use the host image.
    if request.path == "[vdso]"
        && request.build_id.is_none_or(|id| {
            cached_unwind_object_path_for_build_id(request.path, id, unwind_debug_dir)
                == Path::new(request.path)
        })
    {
        load_live_vdso_unwind_mapping(state, request)
    } else {
        let reported = load_unwind_mapping(
            &mut state.object_unwinder,
            &mut state.attempted_unwind_mappings,
            request,
        );
        // perf unwind-libdw.c reports the live regular ELF first. A reported
        // module wins even with a different build ID or no CFI at all.
        if reported.module().is_some() {
            return reported;
        }
        let Some(build_id) = request.build_id else {
            return ObjectMappingResult::Rejected;
        };
        let cached =
            cached_unwind_object_path_for_build_id(request.path, build_id, unwind_debug_dir);
        let cached = cached.to_string_lossy();
        load_unwind_mapping(
            &mut state.object_unwinder,
            &mut state.attempted_unwind_mappings,
            UnwindMappingRequest {
                path: &cached,
                ..request
            },
        )
    }
}

fn load_live_vdso_unwind_mapping(
    state: &mut PidUnwindState,
    request: UnwindMappingRequest<'_>,
) -> ObjectMappingResult {
    let Some(image) = state
        .live_vdso_elf
        .get_or_init(copy_live_vdso_elf_like_perf)
        .as_ref()
    else {
        return ObjectMappingResult::Rejected;
    };
    let architecture = match state.arch {
        PerfArch::X86_64 => object::Architecture::X86_64,
        PerfArch::Aarch64 => object::Architecture::Aarch64,
    };
    if image.architecture != architecture
        || request
            .build_id
            .is_some_and(|id| image.build_id.as_deref() != Some(id))
    {
        return ObjectMappingResult::Rejected;
    }
    let path = image.path.to_string_lossy();
    load_unwind_mapping(
        &mut state.object_unwinder,
        &mut state.attempted_unwind_mappings,
        UnwindMappingRequest {
            path: &path,
            pgoff: 0,
            build_id: None,
            ..request
        },
    )
}

#[cfg(test)]
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

fn sample_fold_count(period: Option<u64>, default_period: u64, options: FoldOptions) -> u64 {
    // evsel.c:evsel__parse_sample initializes data->period from the selected
    // attr.sample_period, then reads the payload only with PERF_SAMPLE_PERIOD.
    if options.count_periods {
        period.unwrap_or(default_period)
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

fn merge_deferred_sample_payload(
    sample: &mut DeferredFoldSample,
    ips: &[u64],
) -> Result<(), String> {
    // perf callchain.c:1919 copies the original including USER_DEFERRED,
    // replacing only its cookie with the deferred addresses. Keep all
    // remaining sample fields intact for the shared parser and unwinder.
    let parsed = parse_sample_record_callchain(&sample.payload, sample.event.layout)?
        .ok_or_else(|| "deferred sample has no callchain".to_string())?;
    let range = parsed
        .callchain_range
        .ok_or_else(|| "deferred sample has no recorded callchain".to_string())?;
    let count = parsed
        .frames
        .len()
        .checked_sub(1)
        .and_then(|count| count.checked_add(ips.len()))
        .and_then(|count| u64::try_from(count).ok())
        .ok_or_else(|| "merged deferred callchain length overflows".to_string())?;
    sample.payload[range.start..range.start + 8].copy_from_slice(&count.to_le_bytes());
    sample.payload.splice(
        range.end - 8..range.end,
        ips.iter().flat_map(|ip| ip.to_le_bytes()),
    );
    Ok(())
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
    leaf_only: bool,
    unwound_frames: Vec<u64>,
) -> Vec<u64> {
    // When the leaf-only predicate holds, perf/libdwfl fires frame_callback for
    // the seeded IP and then stops. No FDE row covers the IP, so advancement
    // depends on `ebl_unwind`; the x86_64 backend rejects zero BP or a caller
    // SP that does not advance after popping both saved words,
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
    request: UnwindMappingRequest<'_>,
) -> ObjectMappingResult {
    if !should_load_unwind_object(request.path, request.file_identity) {
        return ObjectMappingResult::Rejected;
    }
    if request.prot.is_some_and(|prot| prot & PROT_EXEC == 0) {
        return ObjectMappingResult::Rejected;
    }
    let key = unwind_mapping_key(request.path, request.start, request.len, request.pgoff);
    // This is attempt bookkeeping, not a report-result cache. A genuine
    // re-report must reopen the ELF and can GC an existing DWFL identity.
    attempted_unwind_mappings.insert(key);
    object_unwinder
        .report_object_mapping(
            Path::new(request.path),
            request.module_name,
            request.start,
            request.len,
            request.pgoff,
        )
        .unwrap_or(ObjectMappingResult::Rejected)
}

fn unwind_mapping_key(path: &str, start: u64, len: u64, pgoff: u64) -> UnwindMappingKey {
    (path.to_string(), start, len, pgoff)
}

fn unwind_module_key(path: &str, start: u64, pgoff: u64) -> UnwindModuleKey {
    (path.to_string(), start.saturating_sub(pgoff))
}

fn cached_unwind_object_path_for_build_id(
    path: &str,
    build_id: &[u8],
    debug_dir: Option<&Path>,
) -> PathBuf {
    if !build_id.iter().any(|byte| *byte != 0) {
        return PathBuf::from(path);
    }
    debug_dir
        .map(|debug_dir| {
            perf_build_id_elf_path_for_dso(debug_dir, Path::new(path), &build_id_hex(build_id))
        })
        .filter(|cached| cached.exists())
        .unwrap_or_else(|| PathBuf::from(path))
}

fn should_load_unwind_object(path: &str, _file_identity: Option<FileIdentity>) -> bool {
    !path.starts_with('[') && std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

fn current_perf_debug_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".debug"))
}

fn sample_layouts(
    bytes: &[u8],
    header: crate::perfdata::header::PerfHeader,
) -> Result<SampleLayouts, String> {
    let attrs = parse_file_attrs(bytes, header)?;
    let event_desc = event_desc_entries_from_bytes(bytes, header)?;
    sample_layouts_from_attrs(&attrs, &event_desc, |attr| parse_file_attr_ids(bytes, attr))
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
fn parse_event_desc_entries(payload: &[u8]) -> Result<Vec<EventDescEntry>, String> {
    let event_count = read_u32(payload, 0)?;
    let attr_size = usize::try_from(read_u32(payload, 4)?)
        .map_err(|_| "event desc attr size exceeds usize".to_string())?;
    let mut offset = 8usize;
    let minimum_event_size = attr_size
        .checked_add(8)
        .ok_or_else(|| "event desc event size overflows usize".to_string())?;
    if event_count as usize > payload.len().saturating_sub(offset) / minimum_event_size {
        return Err("event desc event count exceeds payload".to_string());
    }
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
        let name_end = offset
            .checked_add(name_len)
            .ok_or_else(|| "event desc name range overflows usize".to_string())?;
        let name_bytes = payload
            .get(offset..name_end)
            .ok_or_else(|| "event desc name truncated".to_string())?;
        let name = event_desc_name_from_bytes(name_bytes);
        offset = name_end;
        if id_count > payload.len().saturating_sub(offset) / 8 {
            return Err("event desc ID count exceeds payload".to_string());
        }
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
        Ok(self.event_for_payload(payload)?.map(Arc::as_ref))
    }

    fn owned_event_for_payload(&self, payload: &[u8]) -> Result<Arc<SampleEventLayout>, String> {
        self.event_for_payload(payload)?
            .cloned()
            .ok_or_else(|| "deferred sample has no event layout".to_string())
    }

    fn event_for_payload(&self, payload: &[u8]) -> Result<Option<&Arc<SampleEventLayout>>, String> {
        if self.by_identifier.is_empty() {
            return Ok(self.fallback.as_ref());
        }
        let Some(fallback) = self.fallback.as_ref() else {
            return Ok(None);
        };
        if let Some(identifier) = fallback
            .offsets
            .id
            .map(|offset| read_sample_u64(payload, offset))
            .transpose()?
        {
            return Ok(self.by_identifier.get(&identifier).or(Some(fallback)));
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

    fn attr_with_id_range(offset: u64, size: u64, config: u64) -> super::PerfFileAttr {
        super::PerfFileAttr {
            event_type: 1,
            config,
            sample_period: 1,
            sample_type: super::PERF_SAMPLE_IDENTIFIER,
            read_format: 0,
            branch_sample_type: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
            sample_id_all: false,
            defer_callchain: false,
            ids_offset: offset,
            ids_size: size,
        }
    }

    #[test]
    fn shared_attribute_id_ranges_are_loaded_once_without_alias_amplification() {
        let attrs = vec![attr_with_id_range(4096, 256, 0); 512];
        let mut reads = 0;
        let layouts = super::sample_layouts_from_attrs(&attrs, &[], |_| {
            reads += 1;
            Ok((0..32).collect())
        })
        .unwrap();
        assert_eq!(reads, 1, "512 aliases must not load 512 owned ID vectors");
        assert_eq!(layouts.by_identifier.len(), 32);
        assert_eq!(layouts.fallback.unwrap().event_name.as_ref(), "cpu-clock");
    }

    #[test]
    fn aliased_and_overlapping_id_ranges_preserve_last_attribute_selection() {
        let attrs = [
            attr_with_id_range(4096, 16, 0),
            attr_with_id_range(4104, 16, 1),
            attr_with_id_range(4096, 16, 2),
        ];
        let mut reads = 0;
        let layouts = super::sample_layouts_from_attrs(&attrs, &[], |attr| {
            reads += 1;
            Ok(if attr.ids_offset == 4096 {
                vec![1, 2]
            } else {
                vec![2, 3]
            })
        })
        .unwrap();
        assert_eq!(reads, 2);
        for id in [1, 2] {
            assert_eq!(
                layouts.by_identifier[&id].event_name.as_ref(),
                "page-faults"
            );
        }
        assert_eq!(layouts.by_identifier[&3].event_name.as_ref(), "task-clock");
        assert_eq!(layouts.fallback.unwrap().event_name.as_ref(), "cpu-clock");
    }

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

    struct OnePassSource<'a> {
        source: super::SliceSource<'a>,
        reads: Vec<usize>,
    }

    impl super::RecordSource for OnePassSource<'_> {
        fn len(&self) -> usize {
            self.source.len()
        }

        fn bytes_at(&mut self, offset: usize, len: usize) -> Result<&[u8], String> {
            self.source.bytes_at(offset, len)
        }

        fn queue_record(
            &mut self,
            offset: usize,
            end: usize,
            header: crate::perfdata::records::PerfRecordHeader,
            windows: &mut super::WindowStore,
        ) -> Result<super::QueuedPerfRecord, String> {
            self.reads.push(offset);
            self.source.queue_record(offset, end, header, windows)
        }
    }

    #[test]
    fn replay_delivers_timestamp_ordered_records_without_reading_them_twice() {
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
                1,
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
            let mut source = OnePassSource {
                source: super::SliceSource(&bytes),
                reads: Vec::new(),
            };
            let mut sink = super::SampleSink::new(
                super::SessionState::new(std::collections::BTreeMap::new()),
                super::FoldedOutput::<super::NoopSymbolResolver>::new(
                    None,
                    super::FoldOptions {
                        inline: false,
                        ..Default::default()
                    },
                    0,
                ),
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
                assert_eq!(source.reads, [0, 32]);
            } else {
                result.unwrap();
                assert_eq!(source.reads, [0, 32]);
                assert_eq!(sink.accumulator.thread_comms[&12].name, "later");
            }
        }
    }

    #[test]
    fn replay_retains_only_timed_samples_in_physical_file_order() {
        let layouts = super::SampleLayouts {
            fallback: Some(std::sync::Arc::new(super::SampleEventLayout::new(
                crate::perfdata::samples::SampleLayout {
                    sample_type: crate::perfdata::samples::PERF_SAMPLE_TIME,
                    sample_id_all: true,
                    read_format: 0,
                    branch_sample_type: 0,
                    sample_regs_user: 0,
                    sample_regs_intr: 0,
                },
                "cycles",
                1,
            ))),
            ..super::SampleLayouts::default()
        };
        let mut bytes = Vec::new();
        let mut rounds = Vec::new();
        for times in [[50_u64, 10], [70, 60]] {
            for time in times {
                bytes.extend(3_u32.to_le_bytes());
                bytes.extend(0_u16.to_le_bytes());
                bytes.extend(32_u16.to_le_bytes());
                bytes.extend(11_u32.to_le_bytes());
                bytes.extend(12_u32.to_le_bytes());
                bytes.extend(b"command\0");
                bytes.extend(time.to_le_bytes());
            }
            bytes.extend(super::PERF_RECORD_FINISHED_ROUND.to_le_bytes());
            bytes.extend(0_u16.to_le_bytes());
            bytes.extend(8_u16.to_le_bytes());
            rounds.push(bytes.len());
        }
        let header = super::PerfHeader {
            header_size: 0,
            attr_offset: 0,
            attr_size: 0,
            data_offset: 0,
            data_size: u64::try_from(bytes.len()).unwrap(),
        };
        let mut source = OnePassSource {
            source: super::SliceSource(&bytes),
            reads: Vec::new(),
        };
        let mut sink = super::SampleSink::new(
            super::SessionState::new(std::collections::BTreeMap::new()),
            super::FoldedOutput::<super::NoopSymbolResolver>::new(
                None,
                super::FoldOptions::default(),
                0,
            ),
        );
        super::replay_records(
            &mut source,
            header,
            &layouts,
            super::FoldOptions::default(),
            &mut sink,
        )
        .unwrap();
        assert_eq!(source.reads, [0, 32, 72, 104]);
        assert_eq!(rounds, [72, bytes.len()]);
    }

    #[test]
    fn ordered_backlog_retains_a_window_reference_not_a_record_copy() {
        assert!(
            std::mem::size_of::<super::PendingFoldRecord>() <= 64,
            "ordering metadata should stay pointer-sized: {} bytes",
            std::mem::size_of::<super::PendingFoldRecord>()
        );
    }

    #[test]
    fn ordered_backlog_stores_only_timestamp_offset_and_window_slot() {
        assert!(
            std::mem::size_of::<super::PendingFoldRecord>()
                <= std::mem::size_of::<u64>() + 2 * std::mem::size_of::<usize>(),
            "pending records duplicate data already retained in the window: {} bytes",
            std::mem::size_of::<super::PendingFoldRecord>()
        );
    }

    fn ordered_record(
        offset: usize,
        queue: &mut super::OrderedRecordQueue,
    ) -> super::QueuedPerfRecord {
        let window = queue.windows.retain_with(offset, || {
            let mut bytes = crate::perfdata::records::PERF_RECORD_SAMPLE
                .to_le_bytes()
                .to_vec();
            bytes.extend(0_u16.to_le_bytes());
            bytes.extend(8_u16.to_le_bytes());
            std::sync::Arc::new(bytes)
        });
        super::QueuedPerfRecord { offset, window }
    }

    #[test]
    fn ordered_delivery_preserves_ties_and_one_round_lag_like_perf() {
        let mut queue = super::OrderedRecordQueue::default();
        let record = ordered_record(24, &mut queue);
        queue.queue(record, 10);
        let record = ordered_record(8, &mut queue);
        queue.queue(record, 10);
        let record = ordered_record(16, &mut queue);
        queue.queue(record, 20);
        let mut delivered = Vec::new();
        queue
            .flush_round_with(|record, _| {
                delivered.push(record.offset);
                Ok(())
            })
            .unwrap();
        assert!(delivered.is_empty());
        let record = ordered_record(32, &mut queue);
        queue.queue(record, 30);
        queue
            .flush_round_with(|record, _| {
                delivered.push(record.offset);
                Ok(())
            })
            .unwrap();
        assert_eq!(delivered, [8, 24, 16]);
        queue
            .flush_final_with(|record, _| {
                delivered.push(record.offset);
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
        let record = ordered_record(0, &mut queue);
        queue.queue(record, 100);
        queue.flush_round_with(|_, _| Ok(())).unwrap();
        queue.flush_round_with(|_, _| Ok(())).unwrap();
        assert!(queue.pending_records.is_empty());

        let record = ordered_record(8, &mut queue);
        queue.queue(record, 10);
        let mut delivered = Vec::new();
        queue
            .flush_round_with(|record, _| {
                delivered.push(record.offset);
                Ok(())
            })
            .unwrap();
        assert_eq!(delivered, [8]);
        let record = ordered_record(16, &mut queue);
        queue.queue(record, 50);
        queue
            .flush_round_with(|record, _| {
                delivered.push(record.offset);
                Ok(())
            })
            .unwrap();
        assert_eq!(delivered, [8], "new round must retain its one-round lag");
        queue
            .flush_final_with(|record, _| {
                delivered.push(record.offset);
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
        let entries = super::parse_event_desc_entries(&payload).expect("event descriptions");
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
        let layouts =
            super::sample_layouts_from_attrs(&[attr_with_id_range(4096, 8, 0)], &entries, |_| {
                Ok(vec![21])
            })
            .unwrap();
        assert_eq!(
            layouts.fallback.unwrap().event_name.as_ref(),
            "task-clock:ppp"
        );
    }

    #[test]
    fn event_desc_name_falls_back_to_event_index_without_ids() {
        let entries = vec![super::EventDescEntry {
            name: "task-clock:ppp".to_string(),
            ids: Vec::new(),
        }];
        let layouts =
            super::sample_layouts_from_attrs(&[attr_with_id_range(0, 0, 0)], &entries, |_| {
                Ok(Vec::new())
            })
            .unwrap();
        assert_eq!(
            layouts.fallback.unwrap().event_name.as_ref(),
            "task-clock:ppp"
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
                    source_state: crate::symbols::SymbolSourceState::AddressDependent,
                    kernel_dso: crate::symbols::SymbolDsoName::Mapping,
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
                    source_state: crate::symbols::SymbolSourceState::AddressDependent,
                    kernel_dso: crate::symbols::SymbolDsoName::Mapping,
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
                    source_state: crate::symbols::SymbolSourceState::AddressDependent,
                    kernel_dso: crate::symbols::SymbolDsoName::Mapping,
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
                    source_state: crate::symbols::SymbolSourceState::AddressDependent,
                    kernel_dso: crate::symbols::SymbolDsoName::Mapping,
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

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_non_regular_unwind_sources_before_opening_like_perf_libdw() {
        let root = tempfile::tempdir().expect("tempdir");
        let fifo = root.path().join("fifo");
        let output = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .output()
            .expect("create FIFO");
        assert!(output.status.success(), "{output:?}");
        for path in [
            root.path(),
            fifo.as_path(),
            std::path::Path::new("/dev/zero"),
        ] {
            assert!(!super::should_load_unwind_object(
                path.to_str().unwrap(),
                None
            ));
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn reports_live_vdso_for_unwinding_without_a_recorded_build_id() {
        let start = 0x7000_0000;
        let mut maps = super::MmapTable::default();
        maps.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start,
            len: 0x1_0000,
            pgoff: 0,
            path: "[vdso]".into(),
        });
        let mapping = maps.user_mapping_for_pid_ip(11, start + 0x400).unwrap();
        let mut state = super::PidUnwindState::with_arch(PerfArch::X86_64);
        assert!(
            matches!(
                super::load_unwind_mapping_for_user_mapping_like_perf(&mut state, mapping, None),
                super::ObjectMappingResult::Added(_)
            ),
            "perf reports the live vDSO before unwinding a sampled vDSO IP"
        );
        assert!(
            state
                .object_unwinder
                .has_reported_module_for_ip(start + 0x400)
        );
        assert!(
            state
                .loaded_unwind_modules
                .contains_key(&super::unwind_module_key("[vdso]", start, 0,))
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn reports_live_vdso_when_recorded_build_id_is_undefined_like_perf() {
        for build_id in [&[][..], &[0; 20][..]] {
            let mapping = super::UserMapping {
                pid: 11,
                start: 0x7000_0000,
                len: 0x1_0000,
                pgoff: 0,
                prot: None,
                path: "[vdso]",
                build_id: Some(build_id),
                file_identity: None,
            };
            let mut state = super::PidUnwindState::with_arch(PerfArch::X86_64);
            // tools/perf/util/build-id.c:build_id__is_defined rejects empty
            // and all-zero IDs; neither constrains the native vDSO image.
            assert!(matches!(
                super::load_unwind_mapping_for_user_mapping_like_perf(&mut state, mapping, None),
                super::ObjectMappingResult::Added(_)
            ));
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn rejects_live_vdso_for_defined_mismatching_identity_or_foreign_architecture() {
        let mapping = super::UserMapping {
            pid: 11,
            start: 0x7000_0000,
            len: 0x1_0000,
            pgoff: 0,
            prot: None,
            path: "[vdso]",
            build_id: Some(&[0xff; 20]),
            file_identity: None,
        };
        let mut state = super::PidUnwindState::with_arch(PerfArch::X86_64);
        assert_eq!(
            super::load_unwind_mapping_for_user_mapping_like_perf(&mut state, mapping, None),
            super::ObjectMappingResult::Rejected
        );
        let mut foreign = super::PidUnwindState::with_arch(PerfArch::Aarch64);
        assert_eq!(
            super::load_unwind_mapping_for_user_mapping_like_perf(
                &mut foreign,
                super::UserMapping {
                    build_id: None,
                    ..mapping
                },
                None
            ),
            super::ObjectMappingResult::Rejected
        );
    }

    #[test]
    fn undefined_recorded_build_ids_do_not_constrain_mappings_like_perf() {
        let events = ["", "0000000000000000000000000000000000000000"]
            .into_iter()
            .enumerate()
            .map(|(index, build_id)| super::BuildIdEvent {
                pid: 11,
                misc: crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_USER,
                filename: format!("/object-{index}"),
                build_id: build_id.into(),
            })
            .collect();
        assert!(
            super::recorded_build_ids_by_filename(events)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn header_build_ids_do_not_preload_vdso_aliases_from_later_stream_records() {
        let filename = b"/tmp/perf-vdso.so-ABC123\0";
        let mut record = Vec::new();
        record.extend(67_u32.to_le_bytes());
        record.extend(crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_USER.to_le_bytes());
        record.extend(
            u16::try_from(8 + 4 + 24 + filename.len())
                .unwrap()
                .to_le_bytes(),
        );
        record.extend(0_u32.to_le_bytes());
        record.extend([0xaa; 20]);
        record.extend([0; 4]);
        record.extend(filename);
        let mut bytes = vec![0_u8; 104];
        bytes[..8].copy_from_slice(b"PERFILE2");
        bytes[8..16].copy_from_slice(&104_u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&144_u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&104_u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&104_u64.to_le_bytes());
        bytes[48..56].copy_from_slice(&u64::try_from(record.len()).unwrap().to_le_bytes());
        bytes.extend(record);
        let ids = super::header_build_ids_by_filename(&bytes).unwrap();
        assert!(
            ids.is_empty(),
            "stream IDs are applied during replay, not header loading"
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn cached_recorded_vdso_elf_is_preferred_to_the_host_image() {
        let root = tempfile::tempdir().unwrap();
        let cached = root.path().join("[vdso]/aa/vdso");
        std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
        std::fs::copy(std::env::current_exe().unwrap(), &cached).unwrap();
        let mapping = super::UserMapping {
            pid: 11,
            start: 0x7000_0000,
            len: 0x1000_0000,
            pgoff: 0,
            prot: None,
            path: "[vdso]",
            build_id: Some(&[0xaa]),
            file_identity: None,
        };
        let mut state = super::PidUnwindState::with_arch(PerfArch::X86_64);
        assert!(matches!(
            super::load_unwind_mapping_for_user_mapping_like_perf(
                &mut state,
                mapping,
                Some(root.path())
            ),
            super::ObjectMappingResult::Added(_)
        ));
        assert!(
            state.live_vdso_elf.get().is_none(),
            "the recorded cache must win without consulting host ELF"
        );
        assert!(
            state
                .loaded_unwind_modules
                .contains_key(&super::unwind_module_key(
                    "[vdso]",
                    mapping.start,
                    mapping.pgoff,
                ))
        );
    }

    #[test]
    fn ambiguous_native_vdso_build_ids_do_not_choose_an_arbitrary_host_image() {
        let events = [
            crate::perfdata::build_id::BuildIdEvent {
                pid: 1,
                misc: crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_USER,
                filename: "/tmp/perf-vdso.so-ABC123".into(),
                build_id: "aa".into(),
            },
            crate::perfdata::build_id::BuildIdEvent {
                pid: 2,
                misc: crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_USER,
                filename: "/tmp/perf-vdso.so-XYZ987".into(),
                build_id: "bb".into(),
            },
        ];
        assert!(super::recorded_build_ids_by_filename(events.into()).is_err());
    }

    #[test]
    fn prefers_live_elf_to_build_id_cache_for_unwind_module_reporting() {
        let root = tempfile::tempdir().expect("tempdir");
        let debug_dir = root.path().join(".debug");
        let cached = debug_dir
            .join(".build-id")
            .join("aa")
            .join("bbcc")
            .join("elf");
        std::fs::create_dir_all(cached.parent().expect("parent")).expect("cache dir");
        let live = root.path().join("live.elf");
        let executable = std::env::current_exe().expect("live ELF");
        std::fs::copy(&executable, &live).expect("live ELF");
        std::fs::copy(&executable, &cached).expect("cached ELF");
        let mut accumulator = super::SessionState::new(std::collections::BTreeMap::new());
        accumulator.unwind_debug_dir = Some(debug_dir);
        accumulator.mmap_table.insert_mmap2_build_id(
            crate::perfdata::records::Mmap2BuildIdRecord {
                pid: 11,
                tid: 11,
                start: 0x1000,
                len: 0x1000_0000,
                pgoff: 0,
                build_id_size: 3,
                build_id: vec![0xaa, 0xbb, 0xcc],
                prot: super::PROT_EXEC,
                flags: 2,
                path: live.to_str().expect("live path").into(),
            },
        );

        // perf util/unwind-libdw.c:108-123 reports live before cache, without
        // checking the symbol build-ID or requiring that the ELF contain CFI.
        accumulator.ensure_unwind_mapping_for_ip(Some(11), 0x2000);
        assert!(accumulator.has_loaded_unwind_mapping_for_ip(Some(11), 0x2000));
        let state = accumulator.unwind_states.get(&11).expect("unwind state");
        assert!(
            state
                .attempted_unwind_mappings
                .contains(&super::unwind_mapping_key(
                    live.to_str().unwrap(),
                    0x1000,
                    0x1000_0000,
                    0,
                ))
        );
        assert!(
            !state
                .attempted_unwind_mappings
                .contains(&super::unwind_mapping_key(
                    cached.to_str().unwrap(),
                    0x1000,
                    0x1000_0000,
                    0,
                ))
        );
        std::fs::remove_file(&live).expect("remove reported live path");
        assert!(accumulator.has_loaded_unwind_mapping_for_ip(Some(11), 0x2000));
        accumulator.ensure_unwind_mapping_for_ip(Some(11), 0x2000);
        assert_eq!(
            accumulator.unwind_states[&11]
                .object_unwinder
                .module_count(),
            1
        );
    }

    #[test]
    fn cached_unwind_reporting_tracks_original_mapping_without_reselecting_source() {
        let root = tempfile::tempdir().expect("tempdir");
        let debug_dir = root.path().join(".debug");
        let cached = debug_dir.join(".build-id/aa/bbcc/elf");
        std::fs::create_dir_all(cached.parent().unwrap()).expect("cache dir");
        std::fs::copy(std::env::current_exe().unwrap(), &cached).expect("cached ELF");
        let live = root.path().join("invalid.elf");
        std::fs::write(&live, b"not an ELF").expect("invalid live ELF");
        let mut accumulator = super::SessionState::new(std::collections::BTreeMap::new());
        accumulator.unwind_debug_dir = Some(debug_dir);
        accumulator.mmap_table.insert_mmap2_build_id(
            crate::perfdata::records::Mmap2BuildIdRecord {
                pid: 11,
                tid: 11,
                start: 0x1000,
                len: 0x1000_0000,
                pgoff: 0,
                build_id_size: 3,
                build_id: vec![0xaa, 0xbb, 0xcc],
                prot: super::PROT_EXEC,
                flags: 2,
                path: live.to_str().unwrap().into(),
            },
        );
        accumulator.ensure_unwind_mapping_for_ip(Some(11), 0x2000);
        assert!(accumulator.has_loaded_unwind_mapping_for_ip(Some(11), 0x2000));
        assert!(
            accumulator.unwind_states[&11]
                .attempted_unwind_mappings
                .contains(&super::unwind_mapping_key(
                    cached.to_str().unwrap(),
                    0x1000,
                    0x1000_0000,
                    0
                ))
        );
        std::fs::remove_file(&cached).expect("remove reported cache path");
        assert!(accumulator.has_loaded_unwind_mapping_for_ip(Some(11), 0x2000));
        accumulator.ensure_unwind_mapping_for_ip(Some(11), 0x2000);
        assert_eq!(
            accumulator.unwind_states[&11]
                .object_unwinder
                .module_count(),
            1
        );
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
            super::perf_accepted_object_unwind_frames(&test_regs(0x1000), false, vec![0x1000],),
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
            let ids = counts.append_serialized_labels(text);
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
                Some(super::SampleComm::Name("pyroclast")),
                [super::FoldFrame::InlineCurrentIp(0x5555_5567_6876)],
                Some(&mut symbol_cache),
                &mut buffers,
            )
            .expect("render folded stack");

        assert_eq!(buffers.rendered(), "pyroclast;[pyroclast]");
    }

    #[test]
    fn script_frames_use_the_resolvers_validated_kernel_dso_name_in_both_inline_modes() {
        struct KcoreResolver;
        impl SymbolResolver for KcoreResolver {
            fn resolve_batch(
                &self,
                requests: &[SymbolRequest],
            ) -> Result<Vec<Option<String>>, String> {
                Ok(vec![Some("module_function+0x10".into()); requests.len()])
            }
            fn resolve_frame_batch_with_metadata(
                &self,
                requests: &[SymbolRequest],
            ) -> Result<Vec<ResolvedSymbolFrames>, String> {
                Ok(vec![
                    ResolvedSymbolFrames {
                        kernel_dso: crate::symbols::SymbolDsoName::KernelKallsyms,
                        ..ResolvedSymbolFrames::from_frames(vec!["module_function+0x10".into()])
                    };
                    requests.len()
                ])
            }
        }
        let mapping = crate::perfdata::mappings::ResolvedMappingRef {
            symbol_source_id: 1,
            path: "[module]",
            relative_address: 0xffff_ffff_c100_0010,
            kernel_module_address: None,
            start: 0xffff_ffff_c100_0000,
            end: 0xffff_ffff_c100_1000,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        };
        for inline in [false, true] {
            let mut cache = SymbolFrameCache::new(&KcoreResolver);
            let mut output = Vec::new();
            super::write_perf_script_mapped_decision_frame(
                &mut output,
                mapping.relative_address,
                false,
                mapping.path,
                &mapping,
                Some(&mut cache),
                inline,
            )
            .unwrap();
            assert_eq!(
                String::from_utf8(output).unwrap(),
                "\tffffffffc1000010 module_function+0x10 ([kernel.kallsyms])\n"
            );
        }
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
                Some(super::SampleComm::Name("pyroclast")),
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
                Some(super::SampleComm::Name("pyroclast")),
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
                Some(super::SampleComm::Name("pyroclast")),
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
                Some(super::SampleComm::Name("burn-00")),
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
                Some(super::SampleComm::Name("burn-00")),
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
                Some(super::SampleComm::Name("burn-00")),
                [super::FoldFrame::InlineCurrentIp(0x4010)],
                Some(&mut symbol_cache),
                &mut buffers,
            )
            .expect("render folded stack");

        assert_eq!(buffers.rendered(), "burn-00;fn124;fn0;mix");
    }

    #[test]
    fn cookie_script_frames_preserve_inline_nodes_and_base_symbol_metadata_like_perf() {
        // machine.c:append_inlines appends each expanded node with the same IP.
        // evsel_fprintf.c:171 substitutes (cookie) per node, without offsets;
        // lines 185 and 195 still select the DSO or (inlined) suffix per node.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x1000,
            len: 0x1000,
            pgoff: 0,
            path: "/missing/inline-cookie".to_string(),
        });
        for has_non_inline_base_frame in [true, false] {
            let resolver = StaticFrameResolver {
                frames: vec!["base_symbol".to_string(), "inline_leaf".to_string()],
                has_base_symbol: true,
                has_inline_frames: true,
                has_non_inline_base_frame,
                base_offset: Some(0x27),
            };
            let base_suffix = if has_non_inline_base_frame {
                "/missing/inline-cookie"
            } else {
                "inlined"
            };
            for frame in [
                super::FoldFrame::UserCallchain(0x1427),
                super::FoldFrame::UserUnwind(0x1427),
                super::FoldFrame::InlineCurrentIp(0x1427),
            ] {
                let mut symbol_cache = SymbolFrameCache::new(&resolver);
                let mut written = Vec::new();
                let mut frame_resolver = super::FoldFrameResolver::new(&mmap_table, true);
                frame_resolver.cookie_to_suppress = Some(0x1427);
                frame_resolver
                    .write_script_frames_for_stack(
                        Some(11),
                        &[frame],
                        Some(&mut symbol_cache),
                        &mut written,
                    )
                    .expect("write cookie inline nodes");
                assert_eq!(
                    String::from_utf8(written).expect("utf-8"),
                    format!(
                        "\t            1427 (cookie) (inlined)\n\
                         \t            1427 (cookie) ({base_suffix})\n"
                    ),
                    "frame={frame:?}, has_non_inline_base_frame={has_non_inline_base_frame}"
                );
            }
        }
    }

    #[test]
    fn cookie_script_frame_preserves_a_single_fake_inline_node_like_perf() {
        // machine.c:append_inlines can emit one fake inline symbol; its node
        // retains sym->inlined even when the expanded chain has length one.
        // evsel_fprintf.c:171 and 195 print (cookie) (inlined), never an offset.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x1000,
            len: 0x1000,
            pgoff: 0,
            path: "/missing/single-inline-cookie".to_string(),
        });
        let resolver = StaticFrameResolver {
            frames: vec!["inline_leaf".to_string()],
            has_base_symbol: true,
            has_inline_frames: true,
            has_non_inline_base_frame: false,
            base_offset: Some(0x27),
        };
        let mut symbol_cache = SymbolFrameCache::new(&resolver);
        let mut written = Vec::new();
        let mut frame_resolver = super::FoldFrameResolver::new(&mmap_table, true);
        frame_resolver.cookie_to_suppress = Some(0x1427);
        frame_resolver
            .write_script_frames_for_stack(
                Some(11),
                &[super::FoldFrame::UserCallchain(0x1427)],
                Some(&mut symbol_cache),
                &mut written,
            )
            .expect("write single cookie inline node");
        assert_eq!(written, b"\t            1427 (cookie) (inlined)\n");
    }

    #[test]
    fn cookie_script_frames_without_symbols_preserve_mapping_domains_like_perf() {
        // evsel_fprintf.c:171 substitutes the cookie even without a symbol.
        // event.c:thread__find_map leaves hypervisor nodes unmapped.
        let address = 0xffff_ffff_8100_0010;
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: address - 0x10,
            len: 0x100,
            pgoff: 0,
            path: "/missing/cookie-source".to_string(),
        });
        for (frame, path) in [
            (
                super::FoldFrame::UserCallchain(address),
                "/missing/cookie-source",
            ),
            (super::FoldFrame::HypervisorCallchain(address), "[unknown]"),
            (super::FoldFrame::UserUnwind(0x1040), "[unknown]"),
        ] {
            let mut frame_resolver = super::FoldFrameResolver::new(&mmap_table, true);
            frame_resolver.cookie_to_suppress = Some(frame.address());
            let mut written = Vec::new();
            frame_resolver
                .write_script_frames_for_stack(
                    Some(11),
                    &[frame],
                    None::<&mut SymbolFrameCache<'_, super::NoopSymbolResolver>>,
                    &mut written,
                )
                .expect("write unsymbolized cookie frame");
            assert_eq!(
                String::from_utf8(written).expect("utf-8"),
                format!("\t{:16x} (cookie) ({path})\n", frame.address()),
                "frame={frame:?}"
            );
        }
    }

    #[test]
    fn cookie_script_base_only_and_negative_symbols_keep_one_cookie_row_like_perf() {
        // machine.c:append_inlines bypasses expansion with inline_name=false;
        // evsel_fprintf.c:171 still replaces unknown and base-symbol names.
        let mut mmap_table = super::MmapTable::default();
        mmap_table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 11,
            tid: 11,
            start: 0x1000,
            len: 0x1000,
            pgoff: 0,
            path: "/missing/base-cookie".to_string(),
        });
        for inline in [false, true] {
            for has_base_symbol in [false, true] {
                let resolver = StaticFrameResolver {
                    frames: if has_base_symbol {
                        vec!["base_symbol+0x27".to_string()]
                    } else {
                        Vec::new()
                    },
                    has_base_symbol,
                    has_non_inline_base_frame: has_base_symbol,
                    base_offset: Some(0x27),
                    ..StaticFrameResolver::default()
                };
                let mut symbol_cache = SymbolFrameCache::new(&resolver);
                let mut frame_resolver = super::FoldFrameResolver::new(&mmap_table, inline);
                frame_resolver.cookie_to_suppress = Some(0x1427);
                for frame in [
                    super::FoldFrame::UserCallchain(0x1427),
                    super::FoldFrame::InlineCurrentIp(0x1427),
                ] {
                    let mut written = Vec::new();
                    frame_resolver
                        .write_script_frames_for_stack(
                            Some(11),
                            &[frame],
                            Some(&mut symbol_cache),
                            &mut written,
                        )
                        .expect("write base-only or unresolved cookie frame");
                    assert_eq!(
                        written, b"\t            1427 (cookie) (/missing/base-cookie)\n",
                        "frame={frame:?}, inline={inline}, has_base_symbol={has_base_symbol}"
                    );
                }
            }
        }
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
        let mut output = super::FoldedOutput::<super::NoopSymbolResolver>::new(
            None,
            super::FoldOptions {
                inline: false,
                ..Default::default()
            },
            0,
        );
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
    fn folded_comms_match_native_inferno_space_replacement_without_frame_escaping() {
        for comm in [
            "worker",
            "work;er",
            "work\\;er",
            "worker task",
            "\u{e9};\u{4e2d} task",
        ] {
            assert_comm_matches_native_inferno(comm);
        }
    }

    #[test]
    fn folded_comms_trim_header_whitespace_like_native_inferno() {
        for comm in ["  worker task  ", "\tworker\t", "\u{2003}worker\u{2003}"] {
            assert_comm_matches_native_inferno(comm);
        }
    }

    #[test]
    fn empty_comms_keep_the_separator_before_the_first_frame_like_native_inferno() {
        for comm in ["", "   ", "\t"] {
            assert_comm_matches_native_inferno(comm);
        }
    }

    fn assert_comm_matches_native_inferno(comm: &str) {
        use super::SampleOutput as _;
        use inferno::collapse::Collapse as _;
        // perf builtin-script.c:perf_sample__fprintf_start prints comm with %s.
        // Inferno perf.rs:event_line_parts trims it, on_event_line replaces
        // spaces, and after_event copies pname verbatim (not frame escaping).
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        state.thread_comms.insert(7, comm.into());
        let sample = prepared_sample(&[super::FoldFrame::UserUnwind(0x1010)]);
        let mut output = super::FoldedOutput::<super::NoopSymbolResolver>::new(
            None,
            super::FoldOptions {
                inline: false,
                ..Default::default()
            },
            0,
        );
        output.write_sample_event(&state, &sample).unwrap();
        let mut actual = Vec::new();
        super::write_fold_counts(output.buffers.counts, &mut actual).unwrap();
        let script = format!("{comm} 7 1.000000: 1 cpu-clock:\n\t1010 [unknown] ([unknown])\n\n");
        let mut options = inferno::collapse::perf::Options::default();
        options.nthreads = 1;
        let mut expected = Vec::new();
        inferno::collapse::perf::Folder::from(options)
            .collapse(std::io::Cursor::new(script), &mut expected)
            .unwrap();
        assert!(!expected.is_empty(), "comm {comm:?}");
        assert_eq!(actual, expected, "comm {comm:?}");
    }

    #[test]
    fn direct_folding_filters_distinct_event_names_like_native_inferno() {
        assert_events_match_native_inferno(&[
            ("cycles", 2, true),
            ("instructions", 100, true),
            ("cycles", 3, true),
        ]);
    }

    #[test]
    fn direct_folding_selects_the_first_event_even_without_stack_frames() {
        assert_events_match_native_inferno(&[
            ("cycles", 2, false),
            ("instructions", 100, true),
            ("cycles", 3, true),
        ]);
    }

    #[test]
    fn direct_folding_uses_infernos_event_token_for_modifiers_and_tracepoints() {
        for names in [
            ["cycles:u", "cycles:k", "instructions:u"],
            [
                "syscalls:sys_enter_write",
                "syscalls:sys_enter_read",
                "cycles",
            ],
        ] {
            assert_events_match_native_inferno(&[
                (names[0], 2, true),
                (names[1], 3, true),
                (names[2], 100, true),
            ]);
        }
    }

    #[test]
    fn untimed_events_use_infernos_empty_filter_and_unit_weight() {
        assert_events_match_native_inferno_with_time(
            &[
                ("cycles", 2, true),
                ("instructions", 100, true),
                ("cycles", 3, true),
            ],
            None,
        );
    }

    #[test]
    fn prepared_event_fields_preserve_inferno_spaces_modifiers_tracepoints_and_padding() {
        // perf builtin-script.c:process_event prints "%*s: ", while Inferno
        // perf.rs:on_event_line splits at colons and then literal spaces.
        for time in [Some(1_000_000_000), None] {
            for names in [
                ["cycles", "instructions", "cycles"],
                ["cycles:u", "cycles:k", "instructions:u"],
                [
                    "syscalls:sys_enter_write",
                    "syscalls:sys_enter_read",
                    "cycles",
                ],
                ["17 cycles", "23 cycles", "a much longer cycles"],
                ["cpu clock", "other clock", "trailing "],
                ["trailing ", "trailing ", "longer "],
                ["7 \u{e9}v:u", "9 \u{e9}v:k", "a longer \u{e9}v:u"],
            ] {
                assert_events_match_native_inferno_with_time(
                    &[
                        (names[0], 2, true),
                        (names[1], 3, true),
                        (names[2], 100, true),
                    ],
                    time,
                );
            }
        }
        assert_events_match_native_inferno_with_time(
            &[
                ("cycles:7 task", 2, true),
                ("cycles:9 task", 3, true),
                ("instructions:7 other", 100, true),
            ],
            None,
        );
    }

    #[test]
    fn repeated_prepared_samples_borrow_event_fields_without_reparsing_names() {
        use super::SampleOutput as _;
        for (name, time) in [
            ("cycles", Some(1_000_000_000)),
            ("17 cycles", Some(1_000_000_000)),
            ("cycles:7 task", None),
        ] {
            super::EVENT_NAME_PARSES.with(|parses| parses.set(0));
            let (layouts, payload) = event_test_sample(name, 3, time, true);
            super::EVENT_NAME_PARSES.with(|parses| assert_eq!(parses.get(), 1, "{name:?}"));
            let mut state = super::SessionState::new(std::collections::BTreeMap::new());
            state.thread_comms.insert(7, "worker".into());
            let mut frames = super::FoldFrameStack::new();
            let mut output = super::FoldedOutput::<super::NoopSymbolResolver>::new(
                None,
                super::FoldOptions {
                    count_periods: true,
                    inline: false,
                },
                name.len(),
            );
            super::EVENT_NAME_PARSES.with(|parses| parses.set(0));
            for _ in 0..512 {
                let sample = super::prepare_sample_for_fold(
                    &mut state,
                    super::PERF_RECORD_MISC_CPUMODE_USER,
                    &payload,
                    &layouts,
                    super::FoldOptions {
                        count_periods: true,
                        inline: false,
                    },
                    &mut frames,
                )
                .unwrap()
                .unwrap();
                assert!(std::ptr::eq(
                    std::ptr::from_ref(sample.event_fields),
                    std::ptr::from_ref(&layouts.fallback.as_ref().unwrap().event_fields),
                ));
                output.write_sample_event(&state, &sample).unwrap();
            }
            assert!(!output.buffers.counts.scratch_stack.is_empty());
            super::EVENT_NAME_PARSES.with(|parses| assert_eq!(parses.get(), 0, "{name:?}"));
        }
    }

    #[test]
    fn structural_event_name_suffixes_preserve_inferno_stream_state() {
        // perf process_event prints the event name verbatim, followed by ": ".
        // Inferno perf.rs:on_event_line (405-428) can treat a suffix as an
        // event-line frame and then parse subsequent lines as new headers.
        for (name, time) in [
            ("cycles:7 task", Some(1_000_000_000)),
            ("cycles:u handler", Some(1_000_000_000)),
            ("cycles:u:7 task", Some(1_000_000_000)),
            ("cycles:u:7 task", None),
            ("cycles:u", Some(1_000_000_000)),
        ] {
            let (mut layouts, payload) = event_test_sample(name, 2, time, true);
            layouts.event_name_width = name.len();
            let mut bytes = Vec::new();
            for _ in 0..2 {
                bytes.extend(crate::perfdata::records::PERF_RECORD_SAMPLE.to_le_bytes());
                bytes.extend(super::PERF_RECORD_MISC_CPUMODE_USER.to_le_bytes());
                bytes.extend(u16::try_from(payload.len() + 8).unwrap().to_le_bytes());
                bytes.extend_from_slice(&payload);
            }
            let header = crate::perfdata::header::PerfHeader {
                header_size: 104,
                attr_offset: 0,
                attr_size: 0,
                data_offset: 0,
                data_size: u64::try_from(bytes.len()).unwrap(),
            };
            let state = || {
                let mut state = super::SessionState::new(std::collections::BTreeMap::new());
                state.thread_comms.insert(7, "worker".into());
                state
            };
            let options = super::FoldOptions {
                count_periods: true,
                inline: false,
            };
            let actual = super::collect_fold_counts_from_source::<super::NoopSymbolResolver>(
                &mut super::SliceSource(&bytes),
                header,
                &layouts,
                state(),
                options,
                None,
            )
            .unwrap();
            let expected = super::collect_stream_fold_counts::<super::NoopSymbolResolver>(
                &mut super::SliceSource(&bytes),
                header,
                &layouts,
                state(),
                options,
                None,
            )
            .unwrap();
            let mut actual_text = Vec::new();
            let mut expected_text = Vec::new();
            super::write_fold_counts(actual, &mut actual_text).unwrap();
            super::write_fold_counts(expected, &mut expected_text).unwrap();
            assert_eq!(actual_text, expected_text, "{name:?}, time {time:?}");
        }
    }

    fn event_test_sample(
        name: &str,
        count: u64,
        time: Option<u64>,
        has_frames: bool,
    ) -> (super::SampleLayouts, Vec<u8>) {
        let layout = crate::perfdata::samples::SampleLayout {
            sample_type: super::PERF_SAMPLE_TID
                | crate::perfdata::samples::PERF_SAMPLE_PERIOD
                | super::PERF_SAMPLE_CALLCHAIN
                | if time.is_some() {
                    super::PERF_SAMPLE_TIME
                } else {
                    0
                },
            read_format: 0,
            branch_sample_type: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
            sample_id_all: false,
        };
        let layouts = super::SampleLayouts {
            fallback: Some(std::sync::Arc::new(super::SampleEventLayout::new(
                layout, name, 1,
            ))),
            ..Default::default()
        };
        let mut payload = Vec::new();
        payload.extend(7_u32.to_le_bytes());
        payload.extend(7_u32.to_le_bytes());
        if let Some(time) = time {
            payload.extend(time.to_le_bytes());
        }
        payload.extend(count.to_le_bytes());
        payload.extend(u64::from(has_frames).to_le_bytes());
        if has_frames {
            payload.extend(0x1010_u64.to_le_bytes());
        }
        (layouts, payload)
    }

    fn assert_events_match_native_inferno(events: &[(&str, u64, bool)]) {
        assert_events_match_native_inferno_with_time(events, Some(1_000_000_000));
    }

    fn assert_events_match_native_inferno_with_time(
        events: &[(&str, u64, bool)],
        time: Option<u64>,
    ) {
        use super::SampleOutput as _;
        use inferno::collapse::Collapse as _;
        // builtin-script.c:perf_sample__fprintf_start prints evname verbatim.
        // Inferno perf.rs:on_event_line selects its first event token even
        // without frames, ignoring modifiers/tracepoint suffixes after ':'.
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        state.thread_comms.insert(7, "worker".into());
        let width = events.iter().map(|(name, _, _)| name.len()).max().unwrap();
        let mut direct = super::FoldedOutput::<super::NoopSymbolResolver>::new(
            None,
            super::FoldOptions {
                count_periods: true,
                inline: false,
            },
            width,
        );
        let mut frames = super::FoldFrameStack::new();
        let mut script = Vec::new();
        let mut text = super::PerfScriptOutput::<super::NoopSymbolResolver, _> {
            symbol_cache: None,
            writer: &mut script,
            event_name_width: width,
            inline: false,
        };
        for &(name, count, has_frames) in events {
            let (layouts, payload) = event_test_sample(name, count, time, has_frames);
            let sample = super::prepare_sample_for_fold(
                &mut state,
                super::PERF_RECORD_MISC_CPUMODE_USER,
                &payload,
                &layouts,
                super::FoldOptions {
                    count_periods: true,
                    inline: false,
                },
                &mut frames,
            )
            .unwrap()
            .unwrap();
            direct.write_sample_event(&state, &sample).unwrap();
            text.write_sample_event(&state, &sample).unwrap();
        }
        let mut options = inferno::collapse::perf::Options::default();
        options.nthreads = 1;
        let mut expected = Vec::new();
        inferno::collapse::perf::Folder::from(options)
            .collapse(std::io::Cursor::new(script), &mut expected)
            .unwrap();
        let mut actual = Vec::new();
        super::write_fold_counts(direct.buffers.counts, &mut actual).unwrap();
        assert!(!expected.is_empty(), "events {events:?}, time {time:?}");
        assert_eq!(actual, expected, "events {events:?}, time {time:?}");
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
    fn cold_symbol_batch_resolves_each_frame_mapping_once() {
        let mut table = super::MmapTable::default();
        for start in [0x1000, 0x2000] {
            table.insert_mmap(crate::perfdata::records::MmapRecord {
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
        let mut buffers = super::FoldedRenderBuffers::default();
        super::FoldFrameResolver::new(&table, true)
            .render_folded_stack_for_stack(
                Some(7),
                Some(super::SampleComm::Name("worker")),
                [
                    super::FoldFrame::UserUnwind(0x1010),
                    super::FoldFrame::UserUnwind(0x2020),
                    super::FoldFrame::UserUnwind(0x1030),
                    super::FoldFrame::UserUnwind(0x2040),
                ],
                Some(&mut cache),
                &mut buffers,
            )
            .unwrap();
        assert_eq!(
            buffers.rendered(),
            "worker;symbol_10;symbol_20;symbol_30;symbol_40"
        );
        assert_eq!(*resolver.full_batch_sizes.borrow(), [4]);
        assert_eq!(
            cache.mapping_frame_lookup_count(),
            13,
            "one initial miss plus one miss check, insertion probe and render lookup per frame"
        );
        assert_eq!(
            table.index_search_count(),
            4,
            "cold prefetch must retain map decisions, not re-walk frames"
        );
    }

    #[test]
    fn cold_symbol_batch_consumes_the_frame_iterator_only_once() {
        struct CountingFrames<'a> {
            frames: std::slice::Iter<'a, super::FoldFrame>,
            visits: &'a std::cell::Cell<usize>,
        }
        impl Iterator for CountingFrames<'_> {
            type Item = super::FoldFrame;
            fn next(&mut self) -> Option<Self::Item> {
                let frame = self.frames.next().copied()?;
                self.visits.set(self.visits.get() + 1);
                Some(frame)
            }
        }
        let mut table = super::MmapTable::default();
        table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x100,
            pgoff: 0,
            path: "/bin/demo".into(),
        });
        let frames = [
            super::FoldFrame::UserUnwind(0x1010),
            super::FoldFrame::InlineCurrentIp(0x1020),
            super::FoldFrame::SampleIp {
                address: 0x1030,
                cpumode: super::PERF_RECORD_MISC_CPUMODE_USER,
            },
        ];
        let visits = std::cell::Cell::new(0);
        let resolver = RecordingFrameResolver::default();
        let mut cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();
        super::FoldFrameResolver::new(&table, true)
            .render_folded_stack_for_stack(
                Some(7),
                Some(super::SampleComm::Name("worker")),
                CountingFrames {
                    frames: frames.iter(),
                    visits: &visits,
                },
                Some(&mut cache),
                &mut buffers,
            )
            .unwrap();
        assert_eq!(buffers.rendered(), "worker;symbol_10;symbol_20;symbol_30");
        assert_eq!(*resolver.full_requests.borrow(), [0x10, 0x20]);
        assert_eq!(*resolver.base_requests.borrow(), [0x30]);
        assert_eq!(
            visits.get(),
            frames.len(),
            "prefetch must not clone and traverse the remaining iterator"
        );
    }

    #[test]
    fn cold_symbol_batch_keeps_a_warm_prefix_and_unmapped_frames_in_deep_stacks() {
        let mut table = super::MmapTable::default();
        table.insert_mmap(crate::perfdata::records::MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x100,
            pgoff: 0,
            path: "/bin/demo".into(),
        });
        let resolver = RecordingFrameResolver::default();
        let mut cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();
        let renderer = super::FoldFrameResolver::new(&table, true);
        renderer
            .render_folded_stack_for_stack(
                Some(7),
                Some(super::SampleComm::Name("worker")),
                [super::FoldFrame::UserUnwind(0x1001)],
                Some(&mut cache),
                &mut buffers,
            )
            .unwrap();
        let frames = (1..=40).map(|offset| {
            if offset == 20 {
                super::FoldFrame::UserUnwind(0x6)
            } else {
                super::FoldFrame::UserUnwind(0x1000 + offset)
            }
        });
        renderer
            .render_folded_stack_for_stack(
                Some(7),
                Some(super::SampleComm::Name("worker")),
                frames,
                Some(&mut cache),
                &mut buffers,
            )
            .unwrap();
        let expected = (1..=40).fold(String::from("worker"), |mut stack, offset| {
            use std::fmt::Write as _;
            if offset == 20 {
                stack.push_str(";[unknown]");
            } else {
                write!(stack, ";symbol_{offset:x}").unwrap();
            }
            stack
        });
        assert_eq!(buffers.rendered(), expected);
        assert_eq!(*resolver.full_batch_sizes.borrow(), [1, 38]);
        assert!(resolver.base_requests.borrow().is_empty());
        assert_eq!(
            resolver
                .full_requests
                .borrow()
                .iter()
                .filter(|&&ip| ip == 1)
                .count(),
            1
        );
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
        let original = sample.frames.to_vec();
        let mut output = super::FoldedOutput::<super::NoopSymbolResolver>::new(
            None,
            super::FoldOptions {
                inline: false,
                ..Default::default()
            },
            0,
        );
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
    fn fold_frame_is_sixteen_bytes() {
        assert_eq!(std::mem::size_of::<super::FoldFrame>(), 16);
    }

    #[test]
    fn fold_frame_preserves_full_address_and_cpu_mode() {
        use super::FoldFrame;

        for address in [0, 1, 0x8000_0000_0000_0000, u64::MAX] {
            for frame in [
                FoldFrame::Callchain(address),
                FoldFrame::UserCallchain(address),
                FoldFrame::UserUnwind(address),
                FoldFrame::InlineCurrentIp(address),
            ] {
                assert_eq!(frame.address(), address);
            }
            for cpumode in 0..=u16::MAX {
                let frame = FoldFrame::SampleIp { address, cpumode };
                assert_eq!(frame.address(), address);
                let FoldFrame::SampleIp {
                    cpumode: stored, ..
                } = frame
                else {
                    unreachable!("constructed a sample IP frame");
                };
                assert_eq!(stored, cpumode);
            }
        }
    }

    #[test]
    fn recursive_run_identity_includes_frame_variant_cpu_mode_and_order() {
        use super::FoldFrame;
        let a = FoldFrame::UserUnwind(0x1010);
        let b = FoldFrame::InlineCurrentIp(0x1010);
        let user = FoldFrame::SampleIp {
            address: 0x1010,
            cpumode: super::PERF_RECORD_MISC_CPUMODE_USER,
        };
        let kernel = FoldFrame::SampleIp {
            address: 0x1010,
            cpumode: super::PERF_RECORD_MISC_CPUMODE_KERNEL,
        };
        let frames = [a, a, b, b, a, a, user, user, kernel, kernel];
        assert_eq!(
            super::fold_frame_runs(frames).collect::<Vec<_>>(),
            [(a, 2), (b, 2), (a, 2), (user, 2), (kernel, 2)]
        );
        assert_eq!(frames[0], a);
        assert_eq!(super::fold_frame_runs([]).count(), 0);
    }

    #[test]
    fn repeated_folded_segments_preserve_utf8_empty_labels_and_odd_run_lengths() {
        for repeats in [1, 2, 3, 5, 511, 512, 513] {
            for segment in [";", ";unicode_\u{e9}", ";outer;inner_[i]", ""] {
                let mut buffers = super::FoldedRenderBuffers::default();
                buffers
                    .start_stack(Some(super::SampleComm::Name("comm_\u{e9}")))
                    .unwrap();
                let start = buffers.current.len();
                buffers.current.push_str(segment);
                buffers.repeat_segment(start, repeats);
                assert_eq!(
                    buffers.rendered(),
                    format!("comm_\u{e9}{}", segment.repeat(repeats))
                );
            }
        }
    }

    #[test]
    fn stable_comm_names_are_classified_only_at_metadata_insertion() {
        use super::SampleOutput as _;
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        state.thread_comms.insert(7, "worker task".into());
        let mut output = super::FoldedOutput::<super::NoopSymbolResolver>::new(
            None,
            super::FoldOptions::default(),
            0,
        );
        let frames = [super::FoldFrame::Callchain(0x1010)];
        let sample = prepared_sample(&frames);
        let before = super::COMM_SYNTAX_SCANS.with(std::cell::Cell::get);
        for _ in 0..512 {
            output.write_sample_event(&state, &sample).unwrap();
        }
        let after = super::COMM_SYNTAX_SCANS.with(std::cell::Cell::get);
        assert_eq!(
            after - before,
            0,
            "stable comm syntax must not be rescanned for every sample"
        );
        assert_eq!(output.buffers.rendered(), "worker_task;[unknown]");
    }

    #[test]
    fn comm_source_metadata_changes_with_replacement_and_fork_inheritance() {
        // Perf thread.c:250 updates the current name; thread.c:414 inherits
        // it at fork. Cached syntax/ranges belong to that name, not to the TID.
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        for (name, syntax, trimmed, has_spaces) in [
            ("worker", super::CommSyntax::Ordinary, "worker", false),
            (
                " \u{2003}worker task\u{2003} ",
                super::CommSyntax::Ordinary,
                "worker task",
                true,
            ),
            ("worker 123", super::CommSyntax::Numeric, "worker 123", true),
            ("#comment", super::CommSyntax::Stream, "#comment", false),
            (
                "line\nbreak",
                super::CommSyntax::Stream,
                "line\nbreak",
                false,
            ),
            ("", super::CommSyntax::Ordinary, "", false),
            ("   ", super::CommSyntax::Ordinary, "", false),
        ] {
            let record = crate::perfdata::records::CommRecord {
                pid: 7,
                tid: 7,
                comm: name.into(),
                is_exec: true,
            };
            state.apply_metadata(super::FoldRecord::Comm(record.clone()));
            let comm = &state.thread_comms[&7];
            assert_eq!(comm.name, name);
            assert_eq!(comm.syntax, syntax);
            assert_eq!(&comm.name[comm.trimmed.clone()], trimmed);
            assert_eq!(comm.has_spaces, has_spaces);
            let scans = super::COMM_SYNTAX_SCANS.with(std::cell::Cell::get);
            let pointer = comm.name.as_ptr();
            state.apply_metadata(super::FoldRecord::Comm(record));
            assert_eq!(state.thread_comms[&7].name.as_ptr(), pointer);
            assert_eq!(super::COMM_SYNTAX_SCANS.with(std::cell::Cell::get), scans);
            state.apply_fork_record(crate::perfdata::records::ForkRecord {
                pid: 8,
                ppid: 7,
                tid: 8,
                ptid: 7,
                time: 1,
                clone_maps: false,
            });
            assert_eq!(state.thread_comms[&7], state.thread_comms[&8]);
            assert_eq!(state.process_comms[&8], name);
            let mut stored = super::FoldedRenderBuffers::default();
            let mut borrowed = super::FoldedRenderBuffers::default();
            stored
                .start_stack(Some(super::SampleComm::Stored(&state.thread_comms[&8])))
                .unwrap();
            borrowed
                .start_stack(Some(super::SampleComm::Name(name)))
                .unwrap();
            assert_eq!(stored.rendered(), borrowed.rendered());
        }
        state.apply_metadata(super::FoldRecord::Comm(
            crate::perfdata::records::CommRecord {
                pid: 8,
                tid: 8,
                comm: "child renamed".into(),
                is_exec: false,
            },
        ));
        assert_eq!(state.thread_comms[&7].name, "   ");
        assert_eq!(state.thread_comms[&8].name, "child renamed");
        assert!(state.thread_comms[&8].has_spaces);
    }

    #[test]
    fn singleton_frame_runs_never_enter_the_segment_copy_path() {
        let maps = super::MmapTable::default();
        let mut buffers = super::FoldedRenderBuffers::default();
        super::FoldFrameResolver::new(&maps, true)
            .render_folded_stack_for_stack::<super::NoopSymbolResolver, _>(
                Some(7),
                Some(super::SampleComm::Name("worker")),
                (1..=512).map(super::FoldFrame::Callchain),
                None,
                &mut buffers,
            )
            .unwrap();
        assert_eq!(
            buffers.segment_copy_entries, 0,
            "singleton runs must not dispatch to the segment copy routine"
        );
        assert_eq!(
            buffers.rendered(),
            format!("worker{}", ";[unknown]".repeat(512))
        );
    }

    #[test]
    fn comm_replacements_and_forked_names_match_inferno_on_the_whole_stream() {
        use super::SampleOutput as _;
        use inferno::collapse::Collapse as _;
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        let mut direct = super::FoldedOutput::<super::NoopSymbolResolver>::new(
            None,
            super::FoldOptions {
                inline: true,
                count_periods: true,
            },
            9,
        );
        let frames = [super::FoldFrame::Callchain(0x1010)];
        let (layouts, _) = event_test_sample("cpu-clock", 17, Some(1_000_000_000), true);
        let mut sample = prepared_sample_for_event(&frames, layouts.fallback.as_ref().unwrap());
        sample.count = 17;
        let mut script = Vec::new();
        for comm in [
            "worker",
            "worker 123",
            "\u{2003}wide name\u{2003}",
            "",
            "renamed",
        ] {
            state.apply_metadata(super::FoldRecord::Comm(
                crate::perfdata::records::CommRecord {
                    pid: 7,
                    tid: 7,
                    comm: comm.into(),
                    is_exec: false,
                },
            ));
            state.apply_fork_record(crate::perfdata::records::ForkRecord {
                pid: 8,
                ppid: 7,
                tid: 8,
                ptid: 7,
                time: 1,
                clone_maps: false,
            });
            for tid in [7, 8] {
                sample.pid = Some(tid);
                sample.tid = Some(tid);
                direct.write_sample_event(&state, &sample).unwrap();
                super::PerfScriptOutput::<super::NoopSymbolResolver, _> {
                    symbol_cache: None,
                    writer: &mut script,
                    event_name_width: 9,
                    inline: true,
                }
                .write_sample_event(&state, &sample)
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
        super::write_fold_counts(direct.buffers.counts, &mut actual).unwrap();
        assert_eq!(actual, expected);
        assert!(!direct.requires_stream_parser);
    }

    #[test]
    fn comm_replacement_with_stream_syntax_requests_whole_stream_parsing() {
        use super::SampleOutput as _;
        for comm in ["#comment", "line\nbreak"] {
            let mut state = super::SessionState::new(std::collections::BTreeMap::new());
            let mut output = super::FoldedOutput::<super::NoopSymbolResolver>::new(
                None,
                super::FoldOptions::default(),
                0,
            );
            let frames = [super::FoldFrame::Callchain(0x1010)];
            let sample = prepared_sample(&frames);
            for name in ["ordinary", comm] {
                state.apply_metadata(super::FoldRecord::Comm(
                    crate::perfdata::records::CommRecord {
                        pid: 7,
                        tid: 7,
                        comm: name.into(),
                        is_exec: false,
                    },
                ));
                output.write_sample_event(&state, &sample).unwrap();
            }
            assert!(output.requires_stream_parser, "comm {comm:?}");
        }
    }

    #[test]
    fn recursive_runs_preserve_native_inferno_labels_modes_and_text_fallbacks() {
        use super::SampleOutput as _;
        use inferno::collapse::Collapse as _;
        // Perf machine.c:append_inlines/unwind_entry emits every accepted
        // entry; Inferno perf.rs:on_stack_line/after_event preserves repeats.
        for (path, labels) in [
            ("/bin/demo", vec![]),
            ("/bin/unicode_\u{e9}", vec![]),
            ("/bin/semi;colon", vec![]),
            ("/bin/(params)", vec![]),
            ("/bin/with space", vec![]),
            ("/bin/line\nbreak", vec![]),
            ("/bin/demo", vec!["outer+0x10", "inner_[i]"]),
            ("/bin/demo", vec!["java->inlined", "unicode_\u{e9}"]),
            ("/bin/demo", vec!["(process)"]),
            ("/bin/demo", vec![" padded "]),
            ("/bin/demo", vec!["line\nbreak"]),
        ] {
            for comm in ["worker", ""] {
                let mut state = super::SessionState::new(std::collections::BTreeMap::new());
                state.thread_comms.insert(7, comm.into());
                insert_test_mapping(&mut state.mmap_table, 7, 0x1000, 0x100, path);
                let resolver = StaticFrameResolver {
                    frames: labels.iter().map(|label| (*label).into()).collect(),
                    has_base_symbol: !labels.is_empty(),
                    has_inline_frames: labels.len() > 1,
                    has_non_inline_base_frame: !labels.is_empty(),
                    ..Default::default()
                };
                let mut cache = SymbolFrameCache::new(&resolver);
                let mut direct = super::FoldedOutput::new(
                    Some(&mut cache),
                    super::FoldOptions {
                        inline: true,
                        count_periods: true,
                    },
                    6,
                );
                let mut frames = vec![super::FoldFrame::UserUnwind(0x1010); 33];
                frames.extend([super::FoldFrame::InlineCurrentIp(0x1010); 17]);
                frames.extend(
                    [super::FoldFrame::SampleIp {
                        address: 0x1010,
                        cpumode: super::PERF_RECORD_MISC_CPUMODE_USER,
                    }; 5],
                );
                frames.extend([super::FoldFrame::UserUnwind(0x2000); 9]);
                let sample = prepared_sample(&frames);
                let mut script = Vec::new();
                let mut text_cache = SymbolFrameCache::new(&resolver);
                let mut text = super::PerfScriptOutput {
                    symbol_cache: Some(&mut text_cache),
                    writer: &mut script,
                    event_name_width: 6,
                    inline: true,
                };
                for _ in 0..2 {
                    direct.write_sample_event(&state, &sample).unwrap();
                    text.write_sample_event(&state, &sample).unwrap();
                }
                let mut options = inferno::collapse::perf::Options::default();
                options.nthreads = 1;
                let mut expected = Vec::new();
                inferno::collapse::perf::Folder::from(options)
                    .collapse(std::io::Cursor::new(script), &mut expected)
                    .unwrap();
                let mut actual = Vec::new();
                super::write_fold_counts(direct.buffers.counts, &mut actual).unwrap();
                assert_eq!(
                    actual, expected,
                    "path {path:?}, labels {labels:?}, comm {comm:?}"
                );
            }
        }
    }

    #[test]
    fn module_projection_slots_survive_growth_replacement_and_kernel_class_changes() {
        let mut projections = super::ModuleProjections::default();
        let key = (usize::MAX, false);
        projections.insert(key, super::LabelSpan::from_slice(&[7]));
        projections.insert((usize::MAX, true), super::LabelSpan::new());
        for id in 0..1024 {
            projections.insert((id, false), super::LabelSpan::from_slice(&[id, id + 1]));
        }
        assert_eq!(projections.get(&key).unwrap().as_slice(), [7]);
        assert!(projections.get(&(usize::MAX, true)).unwrap().is_empty());
        assert_eq!(
            projections.get(&(128, false)).unwrap().as_slice(),
            [128, 129]
        );
        assert!(projections.get(&(128, true)).is_none());
        let slots = projections.labels.len();
        projections.insert(key, super::LabelSpan::from_slice(&[9, 8]));
        assert_eq!(projections.labels.len(), slots);
        assert_eq!(projections.get(&key).unwrap().as_slice(), [9, 8]);
        assert!(projections.get(&(2048, false)).is_none());
        assert_eq!(projections.get(&key).unwrap().as_slice(), [9, 8]);
        let before = projections.searches.get();
        for _ in 0..512 {
            assert_eq!(projections.get(&key).unwrap().as_slice(), [9, 8]);
        }
        assert_eq!(projections.searches.get(), before);
    }

    #[test]
    fn warm_empty_and_single_module_projections_do_not_reread_backing_slots() {
        // Inferno perf.rs:on_stack_line can omit a row or emit one label;
        // neither case needs an inline-frame span on repeated lookups.
        let key = (19, false);
        let mut projections = super::ModuleProjections::default();
        let mut reads = Vec::new();
        for ids in [&[][..], &[0][..], &[37][..]] {
            projections.insert(key, super::LabelSpan::from_slice(ids));
            assert_eq!(projections.get(&key).unwrap().as_slice(), ids);
            let before = projections.slot_reads.get();
            for _ in 0..512 {
                assert_eq!(projections.get(&key).unwrap().as_slice(), ids);
            }
            reads.push(projections.slot_reads.get() - before);
        }
        assert_eq!(reads, [0, 0, 0]);
    }

    #[test]
    fn empty_and_single_label_projections_do_not_decode_smallvec_spans() {
        let mut reads = Vec::new();
        for ids in [&[][..], &[0][..], &[41][..]] {
            let projection: super::LabelProjection = super::LabelSpan::from_slice(ids).into();
            let mut actual = Vec::with_capacity(512);
            let before = super::PROJECTION_SPAN_READS.with(std::cell::Cell::get);
            for _ in 0..512 {
                super::append_label_projection(&mut actual, &projection);
            }
            assert_eq!(actual, ids.repeat(512));
            reads.push(super::PROJECTION_SPAN_READS.with(std::cell::Cell::get) - before);
        }
        assert_eq!(reads, [0, 0, 0]);
    }

    #[test]
    fn expanded_label_projections_preserve_all_inline_ids_and_read_the_span() {
        for ids in [&[0, 1][..], &[3, 7, 2, 8, 11][..]] {
            let projection: super::LabelProjection = super::LabelSpan::from_slice(ids).into();
            let mut actual = Vec::new();
            let before = super::PROJECTION_SPAN_READS.with(std::cell::Cell::get);
            for _ in 0..7 {
                super::append_label_projection(&mut actual, &projection);
            }
            assert_eq!(actual, ids.repeat(7));
            assert_eq!(
                super::PROJECTION_SPAN_READS.with(std::cell::Cell::get) - before,
                7
            );
        }
    }

    #[test]
    fn module_projection_hints_follow_scalar_span_replacements_and_display_classes() {
        let mut projections = super::ModuleProjections::default();
        let mut stack = Vec::new();
        let mut expected = Vec::new();
        for ids in [&[0][..], &[3, 4, 7, 8, 9][..], &[][..], &[11][..]] {
            projections.insert((17, false), super::LabelSpan::from_slice(ids));
            projections.insert((17, true), super::LabelSpan::from_slice(&[91, 92]));
            for key in [(17, false), (17, true), (17, false), (17, false)] {
                let wanted = if key.1 { &[91, 92][..] } else { ids };
                projections.get(&key).unwrap().append_to(&mut stack);
                expected.extend_from_slice(wanted);
                assert_eq!(stack, expected);
                assert!(projections.get(&(usize::MAX, false)).is_none());
                assert_eq!(projections.get(&key).unwrap().as_slice(), wanted);
            }
        }
        assert_eq!(projections.labels.len(), 2);
    }

    #[test]
    fn projection_id_append_preserves_empty_single_and_expanded_segments() {
        let mut actual = Vec::new();
        let mut expected = Vec::new();
        for labels in [&[][..], &[0][..], &[4, 3][..], &[7, 8, 9, 10, 11][..]] {
            for _ in 0..3 {
                super::append_projection_ids(&mut actual, labels);
                expected.extend_from_slice(labels);
            }
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn prepared_fold_frames_fit_address_and_domain_in_two_words() {
        assert!(std::mem::size_of::<super::FoldFrame>() <= 16);
    }

    #[test]
    fn single_label_projections_push_ids_without_entering_bulk_copy() {
        let mut ids = Vec::with_capacity(512);
        let before = super::PROJECTION_BULK_COPIES.with(std::cell::Cell::get);
        for _ in 0..512 {
            super::append_projection_ids(&mut ids, &[13]);
        }
        assert_eq!(ids, vec![13; 512]);
        assert_eq!(
            super::PROJECTION_BULK_COPIES.with(std::cell::Cell::get) - before,
            0
        );
    }

    #[test]
    fn recorded_frame_extension_uses_iterator_bounds_for_bulk_reservation() {
        use std::cell::Cell;
        struct HintSpy<'a> {
            iter: std::slice::Iter<'a, u64>,
            queries: &'a Cell<usize>,
        }
        impl Iterator for HintSpy<'_> {
            type Item = u64;
            fn next(&mut self) -> Option<u64> {
                self.iter.next().copied()
            }
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.queries.set(self.queries.get() + 1);
                self.iter.size_hint()
            }
        }
        for depth in [0, 1, 16, 17, 64, 512] {
            let input = (0..depth).map(|ip| 0x1000 + ip).collect::<Vec<_>>();
            let queries = Cell::new(0);
            let mut frames = super::FoldFrameStack::new();
            super::extend_recorded_callchain_frames_like_perf(
                &mut frames,
                HintSpy {
                    iter: input.iter(),
                    queries: &queries,
                },
                usize::MAX,
            );
            assert_eq!(frames.len(), input.len());
            assert_eq!(queries.get(), 1);
            assert!(frames.capacity() >= input.len());
            assert_eq!(
                frames
                    .iter()
                    .map(|frame| frame.address())
                    .collect::<Vec<_>>(),
                input
            );
        }
    }

    #[test]
    fn recorded_frame_extension_preserves_prefixes_across_depth_and_storage_reuse() {
        use super::FoldFrame;
        let mut frames = super::FoldFrameStack::new();
        for depth in [0, 1, 16, 17, 64, 512, 1, 64] {
            frames.clear();
            frames.push(FoldFrame::Callchain(0x999));
            frames.reserve(depth);
            super::extend_recorded_callchain_frames_like_perf(
                &mut frames,
                (0..depth).map(|index| 0x1000 + u64::try_from(index).unwrap()),
                usize::MAX,
            );
            assert_eq!(frames.len(), depth + 1);
            assert_eq!(frames[0], FoldFrame::Callchain(0x999));
            for (index, frame) in frames[1..].iter().enumerate() {
                assert_eq!(
                    *frame,
                    FoldFrame::UserCallchain(0x1000 + u64::try_from(index).unwrap())
                );
            }
        }
    }

    #[test]
    fn recorded_frame_extension_consumes_context_markers_and_preserves_deferred_cookie() {
        use super::FoldFrame;
        // perf util/machine.c:2171-2198 updates cpumode and returns before
        // appending a cursor node; USER_DEFERRED is handled as USER here.
        let mut frames = super::FoldFrameStack::new();
        super::extend_recorded_callchain_frames_like_perf(
            &mut frames,
            [
                0xffff_8000_0000_0010,
                super::PERF_CONTEXT_KERNEL,
                0x1010,
                super::PERF_CONTEXT_USER,
                0x2020,
                super::PERF_CONTEXT_USER_DEFERRED,
                73,
            ],
            super::PERF_SCRIPT_MAX_STACK,
        );
        assert_eq!(
            frames.as_slice(),
            [
                FoldFrame::UserCallchain(0xffff_8000_0000_0010),
                FoldFrame::Callchain(0x1010),
                FoldFrame::UserCallchain(0x2020),
                FoldFrame::UserCallchain(73),
            ]
        );
        assert_eq!(frames.last(), Some(&FoldFrame::UserCallchain(73)));
    }

    #[test]
    fn prepared_marker_only_samples_have_an_empty_resolved_callchain_like_perf() {
        // perf util/machine.c:add_callchain_ip consumes mode markers without
        // cursor nodes. Preparing the sample must not mistake them for frames.
        let (layouts, mut payload) = event_test_sample("cycles", 3, Some(1_000_000_000), false);
        payload.truncate(payload.len() - 8);
        payload.extend(4_u64.to_le_bytes());
        for marker in [
            super::PERF_CONTEXT_HV,
            super::PERF_CONTEXT_KERNEL,
            super::PERF_CONTEXT_USER,
            super::PERF_CONTEXT_USER_DEFERRED,
        ] {
            payload.extend(marker.to_le_bytes());
        }
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        let mut frames = super::FoldFrameStack::new();
        let sample = super::prepare_sample_for_fold(
            &mut state,
            super::PERF_RECORD_MISC_CPUMODE_USER,
            &payload,
            &layouts,
            super::FoldOptions {
                count_periods: true,
                inline: true,
            },
            &mut frames,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            (sample.pid, sample.tid, sample.count),
            (Some(7), Some(7), 3)
        );
        assert!(sample.has_callchain);
        assert!(
            sample.frames.is_empty(),
            "resolved cursor contains markers: {:?}",
            sample.frames
        );
    }

    #[test]
    fn recorded_frame_extension_marker_only_input_has_no_cursor_nodes_like_perf() {
        // perf util/machine.c:2171-2198 takes goto out for every context.
        let mut frames = super::FoldFrameStack::new();
        super::extend_recorded_callchain_frames_like_perf(
            &mut frames,
            [
                super::PERF_CONTEXT_HV,
                super::PERF_CONTEXT_KERNEL,
                super::PERF_CONTEXT_USER,
                super::PERF_CONTEXT_USER_DEFERRED,
            ],
            super::PERF_SCRIPT_MAX_STACK,
        );
        assert!(
            frames.is_empty(),
            "markers are mode changes, not frames: {frames:?}"
        );
    }

    #[test]
    fn recorded_frame_extension_consumes_markers_without_spending_the_address_budget() {
        use super::FoldFrame;
        // perf util/machine.c:2899-2914 checks the limit before each entry
        // and increments nr_entries only for non-marker addresses.
        let mut frames = super::FoldFrameStack::new();
        super::extend_recorded_callchain_frames_like_perf(
            &mut frames,
            [
                super::PERF_CONTEXT_HV,
                0x1000,
                super::PERF_CONTEXT_KERNEL,
                0x2000,
                super::PERF_CONTEXT_USER,
                0x3000,
                u64::MAX,
            ],
            3,
        );
        assert_eq!(
            frames.as_slice(),
            [
                FoldFrame::HypervisorCallchain(0x1000),
                FoldFrame::Callchain(0x2000),
                FoldFrame::UserCallchain(0x3000),
            ]
        );
        frames.clear();
        super::extend_recorded_callchain_frames_like_perf(&mut frames, [0x1000, u64::MAX], 3);
        assert!(frames.is_empty(), "unsupported context resets the cursor");
    }

    #[test]
    fn folded_mapping_decisions_decode_frame_addresses_once() {
        use super::FoldFrame;
        let mut maps = super::MmapTable::default();
        insert_test_mapping(&mut maps, 7, 0x1000, 0x100, "/user");
        insert_test_mapping(&mut maps, u32::MAX, 0x1008, 0x80, "/global");
        let mut cache = super::MappingResolveCache::default();
        let context = maps.frame_context(7, &mut cache);
        for (frame, path, offset) in [
            (FoldFrame::Callchain(0x1010), "/global", 8),
            (FoldFrame::UserCallchain(0x1010), "/user", 0x10),
            (FoldFrame::UserUnwind(0x1010), "/user", 0x10),
            (FoldFrame::InlineCurrentIp(0x1010), "/user", 0x10),
            (
                FoldFrame::SampleIp {
                    address: 0x1010,
                    cpumode: super::PERF_RECORD_MISC_CPUMODE_USER,
                },
                "/user",
                0x10,
            ),
            (
                FoldFrame::SampleIp {
                    address: 0x1010,
                    cpumode: super::PERF_RECORD_MISC_CPUMODE_KERNEL,
                },
                "/global",
                8,
            ),
        ] {
            for symbolizing in [false, true] {
                let before = super::FOLD_FRAME_ADDRESS_READS.with(std::cell::Cell::get);
                let decision = super::FoldFrameResolver::mapping_decision_for_folded_frame(
                    Some(&context),
                    frame,
                    symbolizing,
                    &mut cache,
                );
                let super::FrameMappingDecision::Mapped(mapping) = decision else {
                    panic!("expected {path} at offset {offset:#x}");
                };
                assert_eq!(mapping.path(), path);
                assert_eq!(mapping.relative_address, offset);
                assert_eq!(
                    super::FOLD_FRAME_ADDRESS_READS.with(std::cell::Cell::get) - before,
                    1
                );
            }
        }
    }

    #[test]
    fn singleton_symbolized_frames_read_only_sample_boundaries_on_cold_and_warm_paths() {
        use std::fmt::Write as _;
        let mut maps = super::MmapTable::default();
        insert_test_mapping(&mut maps, 7, 0x1000, 0x100, "/bin/demo");
        for projecting in [false, true] {
            let resolver = RecordingFrameResolver::default();
            let mut cache = SymbolFrameCache::new(&resolver);
            let mut buffers = super::FoldedRenderBuffers {
                projecting,
                ..Default::default()
            };
            for _ in 0..2 {
                let before = buffers.stack_len_reads.get();
                let span_reads = super::PROJECTION_SPAN_READS.with(std::cell::Cell::get);
                super::FoldFrameResolver::new(&maps, true)
                    .render_folded_stack_for_stack(
                        Some(7),
                        Some(super::SampleComm::Name("worker")),
                        (1..=40).map(|offset| super::FoldFrame::UserUnwind(0x1000 + offset)),
                        Some(&mut cache),
                        &mut buffers,
                    )
                    .unwrap();
                assert_eq!(buffers.stack_len_reads.get() - before, 2);
                assert_eq!(
                    super::PROJECTION_SPAN_READS.with(std::cell::Cell::get) - span_reads,
                    0,
                    "singleton symbol projections must not decode cached spans"
                );
                let mut expected = String::from("worker");
                for offset in 1..=40 {
                    write!(expected, ";symbol_{offset:x}").unwrap();
                }
                assert_eq!(buffers.rendered(), expected);
            }
            assert_eq!(*resolver.full_batch_sizes.borrow(), [40]);
        }
    }

    #[test]
    fn singleton_frames_do_not_read_stack_lengths_for_unused_repeat_segments() {
        let maps = super::MmapTable::default();
        for projecting in [false, true] {
            let mut buffers = super::FoldedRenderBuffers {
                projecting,
                ..Default::default()
            };
            super::FoldFrameResolver::new(&maps, true)
                .render_folded_stack_for_stack::<super::NoopSymbolResolver, _>(
                    Some(7),
                    Some(super::SampleComm::Name("worker")),
                    (1..=512).map(super::FoldFrame::Callchain),
                    None,
                    &mut buffers,
                )
                .unwrap();
            assert_eq!(
                buffers.rendered(),
                format!("worker{}", ";[unknown]".repeat(512))
            );
            assert_eq!(buffers.stack_len_reads.get(), 2);
        }
    }

    #[test]
    fn singleton_projected_frames_do_not_enter_the_repeat_helper() {
        use super::SampleOutput as _;
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        state.thread_comms.insert(7, "worker".into());
        let mut output = super::FoldedOutput::<super::NoopSymbolResolver>::new(
            None,
            super::FoldOptions::default(),
            0,
        );
        for address in 1..=512 {
            let frames = [super::FoldFrame::Callchain(address)];
            output
                .write_sample_event(&state, &prepared_sample(&frames))
                .unwrap();
        }
        assert_eq!(output.buffers.rendered(), "worker;[unknown]");
        assert_eq!(output.buffers.repeat_helper_entries, 0);
    }

    #[test]
    fn warm_module_projection_reuses_its_slot_without_reprobing_the_table() {
        let mut projections = super::ModuleProjections::default();
        let key = (9, false);
        projections.insert(key, super::LabelSpan::from_slice(&[3, 4]));
        for _ in 0..512 {
            assert_eq!(projections.get(&key).unwrap().as_slice(), [3, 4]);
        }
        assert_eq!(
            projections.searches.get(),
            0,
            "a warm module projection must reuse its stable slot, not rehash the key each time"
        );
    }

    #[test]
    fn one_module_projection_does_not_allocate_spans_for_unsampled_metadata() {
        let mut table = super::MmapTable::default();
        for index in 0..1024 {
            insert_test_mapping(
                &mut table,
                7,
                0x1000 + index * 0x1000,
                0x1000,
                &format!("/bin/object-{index}"),
            );
        }
        let mut buffers = super::FoldedRenderBuffers {
            projecting: true,
            ..Default::default()
        };
        super::FoldFrameResolver::new(&table, true)
            .render_folded_stack_for_stack::<super::NoopSymbolResolver, _>(
                Some(7),
                Some(super::SampleComm::Name("worker")),
                [super::FoldFrame::Callchain(0x40_0010)],
                None,
                &mut buffers,
            )
            .unwrap();
        assert_eq!(buffers.rendered(), "worker;[object-1023]");
        assert!(
            buffers.module_projection_storage_bytes() < 4096,
            "one projected module retained {} bytes of projection slots",
            buffers.module_projection_storage_bytes()
        );
    }

    #[test]
    fn projected_kernel_module_names_remain_distinct_when_symbol_sources_are_shared() {
        // perf symbol.c:maps__split_kallsyms creates [kernel].N maps.
        // Inferno perf.rs:with_module_fallback retains each printed DSO name.
        let mut table = super::MmapTable::default();
        for (start, path) in [
            (0xffff_ffff_8100_0000, "[kernel].0"),
            (0xffff_ffff_8200_0000, "[kernel].1"),
        ] {
            insert_test_mapping(&mut table, u32::MAX, start, 0x1000, path);
        }
        let mut hint = super::MappingResolveCache::default();
        let first = table
            .resolve_frame_cached(7, 0xffff_ffff_8100_0010, &mut hint)
            .unwrap();
        let second = table
            .resolve_frame_cached(7, 0xffff_ffff_8200_0010, &mut hint)
            .unwrap();
        assert_eq!(first.symbol_source_id(), second.symbol_source_id());
        let mut buffers = super::FoldedRenderBuffers {
            projecting: true,
            ..Default::default()
        };
        for _ in 0..2 {
            super::FoldFrameResolver::new(&table, true)
                .render_folded_stack_for_stack::<super::NoopSymbolResolver, _>(
                    Some(7),
                    Some(super::SampleComm::Name("worker")),
                    [
                        super::FoldFrame::Callchain(0xffff_ffff_8100_0010),
                        super::FoldFrame::Callchain(0xffff_ffff_8200_0010),
                    ],
                    None,
                    &mut buffers,
                )
                .unwrap();
            assert_eq!(buffers.rendered(), "worker;[[kernel].0];[[kernel].1]");
        }
    }

    #[test]
    fn projected_segments_use_serialized_equality_including_empty_and_escaped_separators() {
        let mut counts = super::FoldCounts::default();
        for text in ["", ";", "a\\;b", "a;;unicode_\u{e9};"] {
            let whole = counts.append_serialized_labels(text);
            let separate = text
                .split(';')
                .flat_map(|part| counts.append_serialized_labels(part))
                .collect::<Vec<_>>();
            assert_eq!(whole.as_slice(), separate);
            counts.scratch_stack.clear();
            counts.scratch_stack.extend_from_slice(&whole);
            let mut rendered = String::new();
            counts.add_prepared(&mut rendered, 2);
            counts.add_stack(text, 3);
            assert_eq!(counts.count_for_rendered(text), Some(5));
        }
    }

    #[test]
    fn projected_rendering_matches_text_rendering_for_empty_skipped_and_recursive_frames() {
        let mut table = super::MmapTable::default();
        insert_test_mapping(&mut table, 7, 0x1000, 0x1000, "/bin/demo");
        for labels in [
            vec![""],
            vec!["(skip)"],
            vec!["->inner", "unicode_\u{e9}"],
            vec!["root", "leaf+0x2a"],
        ] {
            for inline in [false, true] {
                let resolver = StaticFrameResolver {
                    frames: labels.iter().map(|label| (*label).into()).collect(),
                    has_base_symbol: false,
                    ..Default::default()
                };
                let mut cache = SymbolFrameCache::new(&resolver);
                let renderer = super::FoldFrameResolver::new(&table, inline);
                let frames = [
                    super::FoldFrame::Callchain(0x1010),
                    super::FoldFrame::Callchain(0x1010),
                    super::FoldFrame::InlineCurrentIp(0x1020),
                    super::FoldFrame::Callchain(0x3000),
                ];
                let mut text = super::FoldedRenderBuffers::default();
                let mut projected = super::FoldedRenderBuffers {
                    projecting: true,
                    ..Default::default()
                };
                for _ in 0..3 {
                    renderer
                        .render_folded_stack_for_stack(
                            Some(7),
                            Some(super::SampleComm::Name(" ;comm_\u{e9}; ")),
                            frames,
                            Some(&mut cache),
                            &mut text,
                        )
                        .unwrap();
                    renderer
                        .render_folded_stack_for_stack(
                            Some(7),
                            Some(super::SampleComm::Name(" ;comm_\u{e9}; ")),
                            frames,
                            Some(&mut cache),
                            &mut projected,
                        )
                        .unwrap();
                    assert_eq!(
                        projected.rendered(),
                        text.rendered(),
                        "{labels:?}, inline {inline}"
                    );
                }
            }
        }
    }

    #[test]
    fn delivered_cached_symbols_normalize_once_per_projection_not_per_sample() {
        use super::SampleOutput as _;
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        state.thread_comms.insert(7, "worker".into());
        insert_test_mapping(&mut state.mmap_table, 7, 0x1000, 0x1000, "/bin/demo");
        let resolver = StaticFrameResolver {
            frames: vec!["outer(argument)->inner".into()],
            has_base_symbol: true,
            has_non_inline_base_frame: true,
            ..Default::default()
        };
        let mut cache = SymbolFrameCache::new(&resolver);
        let mut output = super::FoldedOutput::new(
            Some(&mut cache),
            super::FoldOptions {
                inline: true,
                count_periods: true,
            },
            0,
        );
        let frames = [super::FoldFrame::Callchain(0x1010)];
        let sample = prepared_sample(&frames);
        for _ in 0..512 {
            output.write_sample_event(&state, &sample).unwrap();
        }
        assert_eq!(output.buffers.rendered(), "worker;outer;inner_[i]");
        assert_eq!(
            output.buffers.raw_function_normalizations, 1,
            "a warm canonical projection must not parse and copy raw function text for each sample"
        );
    }

    #[test]
    fn cached_literal_symbols_skip_repeated_raw_function_normalization() {
        let mut table = super::MmapTable::default();
        insert_test_mapping(&mut table, 7, 0x1000, 0x1000, "/bin/demo");
        let resolver = StaticFrameResolver {
            frames: vec!["literal_symbol+0x10".into()],
            has_base_symbol: true,
            has_non_inline_base_frame: true,
            ..Default::default()
        };
        let mut cache = SymbolFrameCache::new(&resolver);
        let mut buffers = super::FoldedRenderBuffers::default();
        for _ in 0..2 {
            let frames = (0..512).map(|offset| super::FoldFrame::UserUnwind(0x1000 + offset));
            super::FoldFrameResolver::new(&table, true)
                .render_folded_stack_for_stack(
                    Some(7),
                    Some(super::SampleComm::Name("worker")),
                    frames,
                    Some(&mut cache),
                    &mut buffers,
                )
                .unwrap();
            assert_eq!(
                buffers.rendered(),
                format!("worker{}", ";literal_symbol".repeat(512))
            );
            assert_eq!(
                buffers.raw_function_normalizations, 0,
                "cached literal source ranges must not rerun offset, Rust-hash, and arrow parsing"
            );
        }
    }

    #[test]
    fn recursive_folded_runs_probe_cached_symbols_once_without_dropping_frames() {
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
                path: "/bin/demo".into(),
            });
        let resolver = RecordingFrameResolver::default();
        let mut cache = SymbolFrameCache::new(&resolver);
        let mut output = super::FoldedOutput::new(
            Some(&mut cache),
            super::FoldOptions {
                inline: true,
                ..Default::default()
            },
            0,
        );
        let frames = [super::FoldFrame::UserUnwind(0x1010); 512];
        let sample = prepared_sample(&frames);
        output.write_sample_event(&state, &sample).unwrap();
        assert_eq!(
            output.buffers.rendered(),
            format!("worker{}", ";symbol_10".repeat(512))
        );
        assert_eq!(resolver.full_requests.borrow().as_slice(), &[0x10]);
        let lookups = output
            .symbol_cache
            .as_ref()
            .unwrap()
            .mapping_frame_lookup_count();
        assert_eq!(
            lookups, 4,
            "cold runs need one miss, prefetch, insert, and render lookup"
        );
        output.write_sample_event(&state, &sample).unwrap();
        assert_eq!(
            output
                .symbol_cache
                .as_ref()
                .unwrap()
                .mapping_frame_lookup_count()
                - lookups,
            1,
            "a warm recursive run must not resolve the same cached frame 512 times"
        );
        assert_eq!(
            output
                .buffers
                .counts
                .stacks
                .values()
                .copied()
                .collect::<Vec<_>>(),
            [2]
        );
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
        let mut output = super::FoldedOutput::new(
            Some(&mut cache),
            super::FoldOptions {
                inline: true,
                ..Default::default()
            },
            0,
        );
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
            1,
            "one PID bucket per sample; no global bucket exists"
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
                1,
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
            layout, "cycles", 1,
        )));
        let selected =
            std::sync::Arc::new(super::SampleEventLayout::new(layout, "instructions", 1));
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
        let mut output = super::FoldedOutput::new(
            Some(&mut cache),
            super::FoldOptions {
                inline: true,
                ..Default::default()
            },
            0,
        );
        for _ in 0..2 {
            output.write_sample_event(&state, &sample).unwrap();
        }
        assert_eq!(*resolver.full_batch_sizes.borrow(), [2]);
        assert_eq!(*resolver.base_batch_sizes.borrow(), [1]);
        assert_eq!(*resolver.full_requests.borrow(), [0x20, 0x10]);
        assert_eq!(*resolver.base_requests.borrow(), [0x10]);
        assert_eq!(
            output.buffers.rendered(),
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
            let mut output = super::FoldedOutput::new(
                Some(&mut cache),
                super::FoldOptions {
                    inline,
                    ..Default::default()
                },
                0,
            );
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
    fn synchronous_sample_frames_stay_in_delivery_scratch() {
        let layouts = metadata_test_layouts();
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        let mut frames = super::FoldFrameStack::new();
        let scratch = frames.as_ptr();
        let payload = 0x1010_u64.to_le_bytes();
        let sample = super::prepare_sample_for_fold(
            &mut state,
            super::PERF_RECORD_MISC_CPUMODE_USER,
            &payload,
            &layouts,
            super::FoldOptions::default(),
            &mut frames,
        )
        .unwrap()
        .unwrap();
        assert_eq!(sample.frames.len(), 1);
        assert_eq!(
            sample.frames.as_ptr(),
            scratch,
            "delivery must borrow frames, not move their inline array out of scratch"
        );
    }

    #[test]
    fn borrowed_sample_delivery_reuses_inline_and_spilled_storage_after_output_errors() {
        struct ObservingOutput {
            seen: Vec<(usize, usize)>,
            fail_next: bool,
        }
        impl super::SampleOutput for ObservingOutput {
            fn write_sample_event(
                &mut self,
                _state: &super::SessionState,
                sample: &super::PreparedFoldSample,
            ) -> Result<(), String> {
                self.seen
                    .push((sample.frames.as_ptr() as usize, sample.frames.len()));
                if std::mem::take(&mut self.fail_next) {
                    Err("output failed".into())
                } else {
                    Ok(())
                }
            }
        }
        let mut layout = metadata_test_layouts().fallback.unwrap().layout;
        layout.sample_type = super::PERF_SAMPLE_CALLCHAIN;
        let layouts = super::SampleLayouts {
            fallback: Some(std::sync::Arc::new(super::SampleEventLayout::new(
                layout, "cycles", 1,
            ))),
            ..Default::default()
        };
        let mut sink = super::SampleSink::new(
            super::SessionState::new(std::collections::BTreeMap::new()),
            ObservingOutput {
                seen: Vec::new(),
                fail_next: true,
            },
        );
        let mut spilled_pointer = None;
        for depth in [3_u64, 64, 2, 64] {
            let mut payload = depth.to_le_bytes().to_vec();
            for offset in 0..depth {
                payload.extend((0x1000 + offset).to_le_bytes());
            }
            let result = sink.write_sample(
                super::PERF_RECORD_MISC_CPUMODE_USER,
                &payload,
                &layouts,
                super::FoldOptions::default(),
            );
            assert_eq!(result.is_err(), sink.output.seen.len() == 1);
            assert_eq!(
                sink.output.seen.last(),
                Some(&(
                    sink.sample_frames.as_ptr() as usize,
                    usize::try_from(depth).unwrap()
                ))
            );
            if let Some(pointer) = spilled_pointer {
                assert_eq!(sink.sample_frames.as_ptr(), pointer);
            }
            if depth == 64 {
                spilled_pointer = Some(sink.sample_frames.as_ptr());
            }
        }
        assert!(sink.sample_frames.spilled());
        assert!(
            std::mem::size_of::<super::PreparedFoldSample>() <= 128,
            "a delivered sample is metadata and a borrowed frame view"
        );
    }

    #[test]
    fn missing_comm_stays_numeric_until_output() {
        let names = std::collections::BTreeMap::new();
        let comm = super::comm_for_ids(&names, Some(7)).unwrap();
        assert_eq!(comm, super::SampleComm::Tid(7));
        assert_eq!(comm.to_string(), ":7");
    }

    #[test]
    fn numeric_and_borrowed_comms_preserve_header_padding() {
        let mut names = std::collections::BTreeMap::new();
        names.insert(7, "worker".into());
        names.insert(8, "w\u{e9}".into());
        for tid in [0, 7, 8, 12345, u32::MAX] {
            let expected = names.get(&tid).map_or_else(
                || format!(":{tid}"),
                |comm: &super::ThreadComm| comm.name.clone(),
            );
            let comm = super::comm_for_ids(&names, Some(tid)).unwrap();
            assert_eq!(comm.to_string(), expected);
            for width in [0, 16, 32] {
                assert_eq!(format!("{comm:>width$}"), format!("{expected:>width$}"));
                assert_eq!(format!("{comm:<width$}"), format!("{expected:<width$}"));
            }
            if let super::SampleComm::Stored(comm) = comm {
                assert_eq!(comm.name.as_ptr(), names[&tid].name.as_ptr());
            }
        }
        assert_eq!(super::comm_for_ids(&names, None), None);
        let mut sample = prepared_sample(&[]);
        sample.tid = None;
        assert_eq!(
            super::perf_script_comm(&names, &sample).to_string(),
            "[unknown]"
        );
        sample.pid = None;
        assert_eq!(super::perf_script_comm(&names, &sample).to_string(), ":-1");
    }

    #[test]
    fn perf_script_header_padding_counts_utf8_bytes_like_perf_printf() {
        // builtin-script.c:perf_sample__fprintf_start uses %16s for comm;
        // process_event uses %*s for evname. Both widths count bytes, not chars.
        for (comm, event) in [
            ("worker", "\u{e9}"),
            ("\u{e9}", "cycles"),
            ("\u{4e2d}\u{6587}", "\u{4e2d}\u{6587}"),
        ] {
            let mut state = super::SessionState::new(std::collections::BTreeMap::new());
            state.thread_comms.insert(7, comm.into());
            let (layouts, _) = event_test_sample(event, 5, Some(1_000_000_000), false);
            let mut sample = prepared_sample_for_event(&[], layouts.fallback.as_ref().unwrap());
            sample.count = 5;
            let mut actual = Vec::new();
            let mut output = super::PerfScriptOutput::<super::NoopSymbolResolver, _> {
                symbol_cache: None,
                writer: &mut actual,
                event_name_width: event.len(),
                inline: false,
            };
            output.write_sample_inline_header(&state, &sample).unwrap();
            let expected = format!(
                "{}{comm} {:>7} {:>5}.000000: {:>10} {event}:  ",
                " ".repeat(16_usize.saturating_sub(comm.len())),
                7,
                1,
                5
            );
            assert_eq!(actual, expected.as_bytes());
            actual.clear();
            let mut output = super::PerfScriptOutput::<super::NoopSymbolResolver, _> {
                symbol_cache: None,
                writer: &mut actual,
                event_name_width: event.len(),
                inline: false,
            };
            output.write_sample_header(&state, &sample).unwrap();
            let expected = format!("{comm} {:>7} {:>5}.000000: {:>10} {event}: \n", 7, 1, 5);
            assert_eq!(actual, expected.as_bytes());
        }
    }

    #[test]
    fn prepared_samples_borrow_event_names_until_deferred_ownership_is_needed() {
        let layouts = metadata_test_layouts();
        let stored_name = &layouts.fallback.as_ref().unwrap().event_name;
        let owners = std::sync::Arc::strong_count(stored_name);
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        let mut frames = super::FoldFrameStack::new();
        let sample = super::prepare_sample_for_fold(
            &mut state,
            super::PERF_RECORD_MISC_CPUMODE_USER,
            &0x1010_u64.to_le_bytes(),
            &layouts,
            super::FoldOptions::default(),
            &mut frames,
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

    fn prepared_sample(frames: &[super::FoldFrame]) -> super::PreparedFoldSample<'static, '_> {
        static EVENT: std::sync::OnceLock<std::sync::Arc<super::SampleEventLayout>> =
            std::sync::OnceLock::new();
        let event = EVENT.get_or_init(|| {
            event_test_sample("cpu-clock", 1, None, true)
                .0
                .fallback
                .unwrap()
        });
        prepared_sample_for_event(frames, event)
    }

    fn prepared_sample_for_event<'layout, 'frames>(
        frames: &'frames [super::FoldFrame],
        event: &'layout super::SampleEventLayout,
    ) -> super::PreparedFoldSample<'layout, 'frames> {
        super::PreparedFoldSample {
            pid: Some(7),
            map_group: 7,
            sample_ip: None,
            cpumode: super::PERF_RECORD_MISC_CPUMODE_USER,
            tid: Some(7),
            time: (event.layout.sample_type & super::PERF_SAMPLE_TIME != 0)
                .then_some(1_000_000_000),
            cpu: None,
            event_name: &event.event_name,
            event_fields: &event.event_fields,
            count: 1,
            frames,
            cookie_to_suppress: None,
            has_callchain: true,
        }
    }

    #[test]
    fn delivered_samples_retain_only_distinct_normalized_stacks() {
        use super::SampleOutput as _;
        // Inferno after_event() counts final normalized stacks. Distinct raw
        // addresses that all print [unknown] must not build a raw-IP arena.
        let state = super::SessionState::new(std::collections::BTreeMap::new());
        let mut output = super::FoldedOutput::<super::NoopSymbolResolver>::new(
            None,
            super::FoldOptions {
                inline: false,
                ..Default::default()
            },
            0,
        );
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
        let mut output = super::FoldedOutput::<super::NoopSymbolResolver>::new(
            None,
            super::FoldOptions {
                inline: false,
                ..Default::default()
            },
            0,
        );
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
                0x1010,
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
            let decisions = frames
                .iter()
                .copied()
                .map(|frame| {
                    (
                        frame,
                        super::FoldFrameResolver::mapping_decision_for_folded_frame(
                            Some(&context),
                            frame,
                            true,
                            &mut mapping_cache,
                        ),
                        1,
                    )
                })
                .collect::<Vec<_>>();
            super::prefetch_sample_symbols(&table, &decisions, &mut cache, true).unwrap();
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
        let state = accumulator.unwind_state_mut(11);
        assert!(
            state
                .object_unwinder
                .add_object_mapping(
                    &std::env::current_exe().unwrap(),
                    0x7fff_f7d8_2000,
                    0x1000_0000,
                    0,
                )
                .unwrap()
        );
        let module = state
            .object_unwinder
            .reported_module_for_ip(0x7fff_f7e3_2455)
            .unwrap();
        state
            .loaded_unwind_modules
            .insert((path.to_string(), 0x7fff_f7d8_2000), module);

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
        accumulator.apply_record(crate::perfdata::records::ParsedRecord::Mmap(
            crate::perfdata::records::MmapRecord {
                pid: 11,
                tid: 11,
                start: 0x1000,
                len: 0x1000_0000,
                pgoff: 0,
                path: current_exe.clone(),
            },
        ));
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

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn overlapping_mmap_replacement_preserves_dwfl_and_reports_pie_split_like_perf() {
        // maps.c:844-1030 fixes overlaps inline without maps__remove's DWFL
        // invalidation. Native perf accepts this exact PIE split with both
        // reports retained (native-replacement-20261008/pie-overlap.data).
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
            accumulator.unwind_states.contains_key(&11),
            "inline overlap insertion must preserve the reported address space"
        );
        accumulator.ensure_unwind_mapping_for_ip(Some(11), 0x5555_5567_66de);
        let state = accumulator.unwind_states.get(&11).expect("reloaded state");
        assert!(
            state
                .object_unwinder
                .has_reported_module_for_ip(0x5555_5567_66de),
            "native reports the later PIE executable split without resetting DWFL"
        );
        assert!(
            !state
                .object_unwinder
                .has_rejected_mapping_for_ip(0x5555_5567_66de),
            "native accepts this overlapping PIE report"
        );
        assert_eq!(state.object_unwinder.module_count(), 2);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    struct FixedUnwindReplacementFixture {
        _root: tempfile::TempDir,
        accumulator: super::SessionState,
        old: String,
        replacement: std::path::PathBuf,
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn fixed_unwind_replacement_fixture(vdso: bool, valid: bool) -> FixedUnwindReplacementFixture {
        let root = tempfile::tempdir().expect("replacement fixture");
        let debug_dir = root.path().join(".debug");
        let old = if vdso {
            "[vdso]".to_string()
        } else {
            root.path().join("old-missing.elf").to_str().unwrap().into()
        };
        let cached = crate::symbols::perf_build_id_elf_path_for_dso(
            &debug_dir,
            std::path::Path::new(&old),
            "aabbccdd",
        );
        std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
        let source = root.path().join("fixed.S");
        std::fs::write(&source, ".text\n.globl leaf\nleaf:\n.cfi_startproc\n.cfi_def_cfa %rsp,16\n.cfi_offset %rip,-8\n.fill 16,1,0x90\nret\n.cfi_endproc\n.section .note.GNU-stack,\"\",@progbits\n").unwrap();
        let output = std::process::Command::new("cc")
            .args([
                "-nostdlib",
                "-no-pie",
                "-Wl,-e,leaf",
                "-Wl,-Ttext=0x401000",
                "-Wl,--build-id=0xaabbccdd",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&cached)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let replacement = root.path().join("replacement.elf");
        if valid {
            std::fs::copy(&cached, &replacement).unwrap();
        }
        let mut accumulator = super::SessionState::new(std::collections::BTreeMap::new());
        accumulator.unwind_debug_dir = Some(debug_dir);
        accumulator.apply_record(fixed_unwind_replacement_record(
            2,
            old.clone(),
            0x0040_0000,
            vec![0xaa, 0xbb, 0xcc, 0xdd],
        ));
        FixedUnwindReplacementFixture {
            _root: root,
            accumulator,
            old,
            replacement,
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn fixed_unwind_replacement_record(
        form: usize,
        path: String,
        start: u64,
        build_id: Vec<u8>,
    ) -> crate::perfdata::records::ParsedRecord {
        use crate::perfdata::records::{Mmap2BuildIdRecord, Mmap2Record, MmapRecord, ParsedRecord};
        match form {
            0 => ParsedRecord::Mmap(MmapRecord {
                pid: 11,
                tid: 11,
                start,
                len: 0x0041_0000 - start,
                pgoff: 0,
                path,
            }),
            1 => ParsedRecord::Mmap2(Mmap2Record {
                pid: 11,
                tid: 11,
                start,
                len: 0x0041_0000 - start,
                pgoff: 0,
                major: 0,
                minor: 0,
                inode: 0,
                inode_generation: 0,
                prot: super::PROT_EXEC,
                flags: 2,
                path,
            }),
            _ => ParsedRecord::Mmap2BuildId {
                misc: super::PERF_RECORD_MISC_CPUMODE_USER | super::PERF_RECORD_MISC_MMAP_BUILD_ID,
                record: Mmap2BuildIdRecord {
                    pid: 11,
                    tid: 11,
                    start,
                    len: 0x0041_0000 - start,
                    pgoff: 0,
                    build_id_size: 4,
                    build_id,
                    prot: super::PROT_EXEC,
                    flags: 2,
                    path,
                },
            },
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn assert_fixed_unwind_replacement_report(
        accumulator: &mut super::SessionState,
        original: usize,
        changed_base: bool,
        valid: bool,
    ) {
        let state = accumulator
            .unwind_states
            .get_mut(&11)
            .expect("inline mmap replacement must retain DWFL state");
        assert_eq!(state.object_unwinder.module_count(), 1);
        assert!(state.leaf_only_eligibility.is_empty());
        let result = super::report_unwind_module_for_ip_like_perf(
            state,
            &accumulator.mmap_table,
            11,
            0x0040_1001,
            accumulator.unwind_debug_dir.as_deref(),
        );
        assert_eq!(
            result,
            if changed_base && valid {
                super::ReportModuleResult::NewlyReported
            } else if changed_base {
                super::ReportModuleResult::Failed
            } else {
                super::ReportModuleResult::AlreadyReported
            }
        );
        if changed_base {
            assert_eq!(
                super::report_unwind_module_for_ip_like_perf(
                    state,
                    &accumulator.mmap_table,
                    11,
                    0x0040_1001,
                    accumulator.unwind_debug_dir.as_deref(),
                ),
                super::ReportModuleResult::Failed
            );
            assert_eq!(
                state.object_unwinder.reported_module_for_ip(0x0040_1001),
                Some(original)
            );
            assert!(state.object_unwinder.has_unwind_info_for_ip(0x0040_1001));
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn check_fixed_unwind_replacement_reporting(vdso: bool, changed_base: bool) {
        for valid in [false, true] {
            for form in 0..3 {
                let mut fixture = fixed_unwind_replacement_fixture(vdso, valid);
                let accumulator = &mut fixture.accumulator;
                accumulator.ensure_unwind_mapping_for_ip(Some(11), 0x0040_1001);
                assert!(accumulator.has_loaded_unwind_mapping_for_ip(Some(11), 0x0040_1001));
                let original = accumulator.unwind_states[&11]
                    .object_unwinder
                    .reported_module_for_ip(0x0040_1001)
                    .unwrap();
                accumulator
                    .unwind_states
                    .get_mut(&11)
                    .unwrap()
                    .leaf_only_eligibility
                    .insert(0x0040_1001, super::LeafOnlyEligibility::Ineligible);
                let start = if changed_base {
                    0x0040_1000
                } else {
                    0x0040_0000
                };
                accumulator.apply_record(fixed_unwind_replacement_record(
                    form,
                    fixture.replacement.to_str().unwrap().into(),
                    start,
                    vec![0x11; 4],
                ));
                assert_fixed_unwind_replacement_report(accumulator, original, changed_base, valid);
                accumulator.apply_record(fixed_unwind_replacement_record(
                    form,
                    fixture.old.clone(),
                    0x0040_0000,
                    vec![0xaa, 0xbb, 0xcc, 0xdd],
                ));
                accumulator.ensure_unwind_mapping_for_ip(Some(11), 0x0040_1001);
                assert_eq!(
                    accumulator.unwind_states[&11]
                        .object_unwinder
                        .reported_module_for_ip(0x0040_1001),
                    Some(original)
                );
                assert!(accumulator.has_loaded_unwind_mapping_for_ip(Some(11), 0x0040_1001));
            }
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn ordinary_same_base_replacement_retains_cached_module_like_perf_dwfl() {
        check_fixed_unwind_replacement_reporting(false, false);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn ordinary_changed_base_replacement_rejects_fixed_module_like_perf_dwfl() {
        check_fixed_unwind_replacement_reporting(false, true);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn vdso_changed_base_replacement_rejects_fixed_module_like_perf_dwfl() {
        check_fixed_unwind_replacement_reporting(true, true);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn vdso_same_base_replacement_retains_cached_module_like_perf_dwfl() {
        check_fixed_unwind_replacement_reporting(true, false);
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
    fn sample_fold_count_uses_recorded_period_before_event_default_when_requested() {
        assert_eq!(
            super::sample_fold_count(
                Some(37),
                99,
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
                99,
                super::FoldOptions {
                    count_periods: false,
                    ..super::FoldOptions::default()
                }
            ),
            1
        );
    }

    #[test]
    fn sample_fold_count_uses_event_default_including_zero_when_period_is_absent() {
        // evsel.c:evsel__parse_sample initializes period from attr.sample_period,
        // not a universal 1. A zero attribute remains zero without PERIOD.
        assert_eq!(
            super::sample_fold_count(
                None,
                0,
                super::FoldOptions {
                    count_periods: true,
                    ..super::FoldOptions::default()
                }
            ),
            0
        );
        let weighted = super::FoldOptions {
            count_periods: true,
            inline: false,
        };
        assert_eq!(super::sample_fold_count(None, 37, weighted), 37);
        assert_eq!(super::sample_fold_count(Some(0), 37, weighted), 0);
        assert_eq!(
            super::sample_fold_count(None, 37, super::FoldOptions::default()),
            1
        );
    }

    #[test]
    fn serialized_module_fallback_reuses_final_stack_storage() {
        let mapping = super::ResolvedMappingRef {
            symbol_source_id: 0,
            path: "/usr/lib/libdemo.so",
            relative_address: 0x1234,
            kernel_module_address: None,
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
            kernel_module_address: None,
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
                kernel_module_address: None,
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
    fn newline_dso_rows_match_native_inferno_instead_of_sanitizing_paths() {
        for path in [
            "/tmp/a\r\nb.so",
            "/tmp/a\n0010 injected (/bin/n)",
            "/tmp/a\n\nworker 7 1.000000: 2 cpu-clock:\n 1000 injected (/x)",
        ] {
            assert_path_rows_match_native_inferno(path, false);
        }
    }

    #[test]
    fn resolved_symbols_in_space_containing_dso_paths_follow_infernos_row_parser() {
        for path in ["/tmp/a b.so", "/tmp/a (nested)", "/tmp/a\nb.so"] {
            assert_path_rows_match_native_inferno(path, true);
        }
    }

    fn assert_path_rows_match_native_inferno(path: &str, has_symbol: bool) {
        use super::SampleOutput as _;
        use inferno::collapse::Collapse as _;
        // perf map.c:map__fprintf_dsoname prints path verbatim. Inferno
        // process_single_stack reads lines, then stack_line_parts uses the
        // final literal space, even when that space came from the DSO name.
        let mut state = super::SessionState::new(std::collections::BTreeMap::new());
        state.thread_comms.insert(7, "worker".into());
        for (start, path) in [(0x1000, path), (0x2000, "/bin/normal")] {
            state
                .mmap_table
                .insert_mmap(crate::perfdata::records::MmapRecord {
                    pid: 7,
                    tid: 7,
                    start,
                    len: 0x100,
                    pgoff: 0,
                    path: path.into(),
                });
        }
        let resolver = StaticFrameResolver {
            frames: if has_symbol {
                vec!["entry".into()]
            } else {
                Vec::new()
            },
            has_base_symbol: has_symbol,
            has_inline_frames: false,
            has_non_inline_base_frame: has_symbol,
            base_offset: has_symbol.then_some(0x10),
        };
        let mut cache = SymbolFrameCache::new(&resolver);
        let mut direct = super::FoldedOutput::new(
            Some(&mut cache),
            super::FoldOptions {
                count_periods: true,
                inline: false,
            },
            9,
        );
        let frames = [
            super::FoldFrame::UserUnwind(0x1010),
            super::FoldFrame::UserUnwind(0x2010),
        ];
        let (layouts, _) = event_test_sample("cpu-clock", 1, Some(1_000_000_000), true);
        let sample = prepared_sample_for_event(&frames, layouts.fallback.as_ref().unwrap());
        direct.write_sample_event(&state, &sample).unwrap();
        let mut script = Vec::new();
        let mut cache = SymbolFrameCache::new(&resolver);
        let mut text = super::PerfScriptOutput {
            symbol_cache: Some(&mut cache),
            writer: &mut script,
            event_name_width: 9,
            inline: false,
        };
        text.write_sample_event(&state, &sample).unwrap();
        let mut options = inferno::collapse::perf::Options::default();
        options.nthreads = 1;
        let mut expected = Vec::new();
        inferno::collapse::perf::Folder::from(options)
            .collapse(std::io::Cursor::new(script), &mut expected)
            .unwrap();
        let mut actual = Vec::new();
        super::write_fold_counts(direct.buffers.counts, &mut actual).unwrap();
        assert_eq!(actual, expected, "path {path:?}, has_symbol {has_symbol}");
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
        let mut output = super::FoldedOutput::new(
            Some(&mut cache),
            super::FoldOptions {
                inline: true,
                ..Default::default()
            },
            0,
        );
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
    fn arch_fallback_cannot_advance_when_x86_bp_is_zero_or_caller_sp_does_not_advance() {
        // elfutils 0.195 backends/x86_64_unwind.c:54,79-91 rejects fp == 0,
        // then checks old_sp >= (fp + 16), after popping both saved words.
        let sp = 0x7fff_0000;
        for (bp, cannot_advance) in [
            (0, true),
            (sp - 16, true),
            (sp - 8, false),
            (sp, false),
            (sp + 8, false),
            (u64::MAX - 7, true),
        ] {
            let mut regs = test_x86_regs(0x4000);
            regs.sp = sp;
            regs.bp = bp;
            assert_eq!(
                super::arch_fallback_provably_cannot_advance(&PerfUserRegs::X86_64(regs)),
                cannot_advance,
                "bp={bp:#x}, sp={sp:#x}"
            );
        }
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

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn attached_object_unwind_keeps_mixed_and_unmapped_pcs_like_perf() {
        let object = std::env::current_exe().unwrap();
        let mut table = super::MmapTable::default();
        insert_test_mapping(&mut table, 11, 0x4000, 0x1000, object.to_str().unwrap());
        let mut state = super::PidUnwindState::with_arch(super::PerfArch::X86_64);
        let mut sources = super::DsoMemorySources::default();
        let leaf_only_ctx = super::UserUnwindContext {
            sample_callchain: super::SampleCallchainPresence::Present,
            callchain: other_callchain(),
            initial_ip_mapping: super::InitialIpMappingState::RecordedMappingLoaded,
            module_count: 1,
            frame_pointer_at_or_above_stack_pointer: false,
            syscall_return_state: false,
        };
        // tools/perf/util/machine.c __thread__resolve_callchain() does not
        // suppress the register/stack unwind after a recorded user frame.
        let kernel_user = super::UserUnwindContext {
            callchain: super::SampleCallchainState::KernelWithUserFrame,
            ..leaf_only_ctx
        };
        // unwind-libdw.c:84-85: no user DSO is a successful report, not a
        // failure. An existing DWFL attachment still delivers this seed PC.
        let unmapped = super::UserUnwindContext {
            initial_ip_mapping: super::InitialIpMappingState::NoRecordedMapping,
            ..leaf_only_ctx
        };
        for (context, ip) in [
            (leaf_only_ctx, 0x4000),
            (kernel_user, 0x4000),
            (unmapped, 0x1_0000_0000),
        ] {
            let mut regs = test_x86_regs(ip);
            regs.bp = 0;
            regs.sp = 0x7fff_0000;
            assert_eq!(
                super::unwind_object_frame_addresses_like_perf(
                    &mut state,
                    (11, 12),
                    &mut super::MappedMemory::new(11, &table, &mut sources, None),
                    &PerfUserRegs::X86_64(regs),
                    &[0; 24],
                    context,
                ),
                [ip]
            );
        }
    }

    #[test]
    fn accepted_frames_emit_leaf_only_when_predicate_holds() {
        // When the leaf-only predicate holds the accepted list is the single
        // sampled-IP leaf, even if framehop produced a caller; libdwfl would
        // have stopped after the initial-frame callback.
        let regs = test_regs(0x4000);
        assert_eq!(
            super::perf_accepted_object_unwind_frames(&regs, true, Vec::new()),
            vec![0x4000]
        );
        assert_eq!(
            super::perf_accepted_object_unwind_frames(&regs, true, vec![0x4000, 0x9999],),
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
            super::perf_accepted_object_unwind_frames(&regs, false, vec![0x4000, 0x9999],),
            vec![0x4000, 0x9999]
        );
        // A non-leaf-only sample with no accepted frames stays empty: the
        // sampled IP is never invented absent the leaf-only predicate.
        assert!(super::perf_accepted_object_unwind_frames(&regs, false, Vec::new()).is_empty());
    }

    #[test]
    fn accepted_frames_preserve_duplicate_seed_ip_like_perf_libdw_frame_callback() {
        // tools/perf/util/unwind-libdw.c frame_callback() calls entry() for
        // each Dwfl_Frame, including repeated PCs. No deduplication occurs.
        let regs = test_regs(0x4000);
        assert_eq!(
            super::perf_accepted_object_unwind_frames(&regs, false, vec![0x4000, 0x4000, 0x5000],),
            vec![0x4000, 0x4000, 0x5000]
        );
    }

    fn queued_deferred_sample(
        cookie: u64,
        tid: u32,
        time: u64,
        ip: u64,
    ) -> super::DeferredFoldSample {
        let event = super::SampleEventLayout::new(
            crate::perfdata::samples::SampleLayout {
                sample_type: super::PERF_SAMPLE_IP
                    | super::PERF_SAMPLE_TID
                    | super::PERF_SAMPLE_TIME
                    | super::PERF_SAMPLE_CALLCHAIN,
                read_format: 0,
                branch_sample_type: 0,
                sample_regs_user: 0,
                sample_regs_intr: 0,
                sample_id_all: false,
            },
            "cpu-clock",
            1,
        );
        let mut payload = ip.to_le_bytes().to_vec();
        payload.extend(11_u32.to_le_bytes());
        payload.extend(tid.to_le_bytes());
        payload.extend(time.to_le_bytes());
        payload.extend(3_u64.to_le_bytes());
        for address in [ip, super::PERF_CONTEXT_USER_DEFERRED, cookie] {
            payload.extend(address.to_le_bytes());
        }
        super::DeferredFoldSample {
            cookie,
            tid: Some(tid),
            misc: super::PERF_RECORD_MISC_CPUMODE_USER,
            event: std::sync::Arc::new(event),
            options: super::FoldOptions::default(),
            payload,
            cookie_to_suppress: Some(cookie),
        }
    }

    #[test]
    fn deferred_merge_preserves_registers_and_stack_bytes_after_the_callchain() {
        use crate::perfdata::samples::{PERF_SAMPLE_REGS_USER, PERF_SAMPLE_STACK_USER};

        let mut queued = queued_deferred_sample(u64::MAX, 21, 100, 0x2000);
        let event = std::sync::Arc::make_mut(&mut queued.event);
        event.layout.sample_type |= PERF_SAMPLE_REGS_USER | PERF_SAMPLE_STACK_USER;
        event.layout.sample_regs_user = 1 << 8;
        let mut tail = 2_u64.to_le_bytes().to_vec();
        tail.extend(0xabcd_u64.to_le_bytes());
        tail.extend(3_u64.to_le_bytes());
        tail.extend([1, 2, 3, 0, 0, 0, 0, 0]);
        tail.extend(3_u64.to_le_bytes());
        queued.payload.extend_from_slice(&tail);

        super::merge_deferred_sample_payload(&mut queued, &[0x3000, 0x4000]).unwrap();
        let parsed = super::parse_sample_record_callchain(&queued.payload, queued.event.layout)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.pid, Some(11));
        assert_eq!(parsed.tid, Some(21));
        assert_eq!(parsed.time, Some(100));
        assert_eq!(
            parsed.frames.collect::<Vec<_>>(),
            [0x2000, super::PERF_CONTEXT_USER_DEFERRED, 0x3000, 0x4000]
        );
        assert_eq!(parsed.user_regs.unwrap().values, [0xabcd]);
        let stack = parsed.user_stack.unwrap();
        assert_eq!(stack.bytes, [1, 2, 3]);
        assert_eq!(stack.dynamic_size, 3);
        assert!(queued.payload.ends_with(&tail));
    }

    #[test]
    fn deferred_sample_final_flush_preserves_insertion_order_like_perf_ordered_events() {
        // tools/perf/util/ordered-events.c queue_event() inserts events by
        // timestamp while preserving input order for equal timestamps. Final
        // deferred-callchain flush must therefore not drain by cookie key.
        let mut accumulator = super::SessionState::new(std::collections::BTreeMap::new());
        accumulator
            .deferred_samples
            .push(queued_deferred_sample(2, 21, 100, 0x2000));
        accumulator
            .deferred_samples
            .push(queued_deferred_sample(1, 22, 100, 0x1000));

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
                1,
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
            .push(queued_deferred_sample(2, 20, 100, 0x2000));
        accumulator
            .deferred_samples
            .push(queued_deferred_sample(7, 30, 150, 0x3000));
        accumulator
            .deferred_samples
            .push(queued_deferred_sample(7, 20, 200, 0x7000));

        let samples = accumulator
            .take_resolved_deferred_samples(7, Some(20), &[0x4000])
            .unwrap();

        assert_eq!(
            samples.iter().map(|sample| sample.tid).collect::<Vec<_>>(),
            vec![Some(20), Some(20)]
        );
        assert_eq!(
            samples
                .iter()
                .map(|sample| super::parse_sample_record_callchain(
                    &sample.payload,
                    sample.event.layout
                )
                .unwrap()
                .unwrap()
                .frames
                .collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            vec![
                vec![0x2000, super::PERF_CONTEXT_USER_DEFERRED, 2],
                vec![0x7000, super::PERF_CONTEXT_USER_DEFERRED, 0x4000],
            ]
        );
        assert_eq!(samples[0].cookie_to_suppress, None);
        assert_eq!(samples[1].cookie_to_suppress, Some(7));
        assert_eq!(accumulator.deferred_samples.len(), 1);
        assert_eq!(accumulator.deferred_samples[0].tid, Some(30));
    }
}
