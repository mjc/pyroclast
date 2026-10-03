use std::borrow::{Borrow, Cow};
use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write;
use std::hash::{Hash, Hasher};
use std::io::{Read, Seek, SeekFrom, Write as IoWrite};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use clap::ValueEnum;
use hashbrown::{HashMap, HashSet, hash_map::RawEntryMut};
use object::{
    Object, ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable, SymbolIndex, SymbolKind,
};
use rustc_hash::FxBuildHasher;
use serde::Serialize;
use smallvec::SmallVec;

use crate::perfdata::build_id::{
    kernel_build_id_from_perfdata, kernel_build_id_from_perfdata_file,
};
use crate::perfdata::mappings::{FileIdentity, MappedFrame, ResolvedMappingRef};
use crate::process::{CommandRunner, CommandSpec};

type FxHashMap<K, V> = HashMap<K, V, FxBuildHasher>;
type FxHashSet<T> = HashSet<T, FxBuildHasher>;

const X86_64_PLT_ENTRY_SIZE: u64 = 16;
const ELF64_RELA_ENTRY_SIZE: usize = 24;

#[cfg(test)]
thread_local! {
    static MODULE_KALLSYMS_TREE_BUILDS: Cell<usize> = const { Cell::new(0) };
    static MODULE_KALLSYMS_ROW_VISITS: Cell<usize> = const { Cell::new(0) };
    static MODULE_KALLSYMS_SYMBOL_INSERTIONS: Cell<usize> = const { Cell::new(0) };
    static MODULE_KALLSYMS_END_FIXUP_PASSES: Cell<usize> = const { Cell::new(0) };
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KernelRelocation {
    pub reference_symbol: String,
    pub recorded_reference_address: u64,
}

#[derive(Clone, Debug)]
pub struct SymbolRequest {
    pub path: PathBuf,
    pub relative_address: u64,
    pub kernel_mapping_range: Option<(u64, u64)>,
    pub build_id: Option<String>,
    pub file_identity: Option<FileIdentity>,
    pub kernel_relocation: Option<KernelRelocation>,
}

impl SymbolRequest {
    /// Returns the `file_identity` that participates in identity comparison.
    ///
    /// perf's `__dso_id__cmp` (tools/perf/util/dso.c) treats a defined `build_id`
    /// as the decisive backing-store discriminator and only weighs the mmap2
    /// maj/min/ino when both dso ids recorded them. The same on-disk object can
    /// arrive with the `build_id` but no `file_identity` (inline MMAP2-build-id) or
    /// with both (plain MMAP2 + `HEADER_BUILD_ID`), so once a `build_id` is present
    /// we ignore `file_identity` to keep the request — and thus the symbol cache
    /// entry — unified. Distinct `build_ids` at the same path still differ via
    /// `build_id`; `file_identity` remains the discriminator only when no
    /// `build_id` exists.
    fn identity_file_identity(&self) -> Option<FileIdentity> {
        if self.build_id.is_some() {
            None
        } else {
            self.file_identity
        }
    }
}

impl PartialEq for SymbolRequest {
    fn eq(&self, other: &Self) -> bool {
        self.relative_address == other.relative_address
            && self.kernel_mapping_range == other.kernel_mapping_range
            && self.build_id == other.build_id
            && self.identity_file_identity() == other.identity_file_identity()
            && self.kernel_relocation == other.kernel_relocation
            && self.path.as_os_str() == other.path.as_os_str()
    }
}

impl Eq for SymbolRequest {}

impl Hash for SymbolRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.as_os_str().hash(state);
        self.relative_address.hash(state);
        self.kernel_mapping_range.hash(state);
        self.build_id.hash(state);
        self.identity_file_identity().hash(state);
        self.kernel_relocation.hash(state);
    }
}

impl PartialOrd for SymbolRequest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SymbolRequest {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path
            .as_os_str()
            .cmp(other.path.as_os_str())
            .then_with(|| self.relative_address.cmp(&other.relative_address))
            .then_with(|| self.kernel_mapping_range.cmp(&other.kernel_mapping_range))
            .then_with(|| self.build_id.cmp(&other.build_id))
            .then_with(|| {
                self.identity_file_identity()
                    .cmp(&other.identity_file_identity())
            })
            .then_with(|| self.kernel_relocation.cmp(&other.kernel_relocation))
    }
}

pub trait SymbolResolver {
    /// Resolves a batch of object-relative addresses.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing symbolizer cannot complete the batch.
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String>;

    /// Resolves a batch of object-relative addresses to display frame lists.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing symbolizer cannot complete the batch.
    fn resolve_frame_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
        self.resolve_batch(requests).map(|symbols| {
            symbols
                .into_iter()
                .map(|symbol| symbol.into_iter().collect())
                .collect()
        })
    }

    /// Resolves a batch of object-relative addresses to display frame lists and
    /// records whether perf would have had a base object symbol for each IP.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing symbolizer cannot complete the batch.
    fn resolve_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        self.resolve_frame_batch(requests).map(|frames| {
            frames
                .into_iter()
                .map(ResolvedSymbolFrames::from_frames)
                .collect()
        })
    }

    /// Resolves a batch to only the base object symbol frame perf would use
    /// before expanding inline frames.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing symbolizer cannot complete the batch.
    fn resolve_base_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        self.resolve_frame_batch_with_metadata(requests)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SymbolSourceState {
    #[default]
    AddressDependent,
    /// Object loading established that every address is unresolved, not merely
    /// a symbol gap. perf `util/symbol.c:dso__load` records `dso__set_loaded`
    /// on failure as well as success.
    Unavailable,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResolvedSymbolFrames {
    pub frames: Vec<String>,
    pub source_state: SymbolSourceState,
    pub has_base_symbol: bool,
    pub has_inline_frames: bool,
    pub has_non_inline_base_frame: bool,
    /// The `+0x<off>` suffix value (relative to the containing symtab symbol)
    /// that perf prints on every inline AND base frame for this address.
    /// `tools/perf/util/symbol_fprintf.c __symbol__fprintf_symname_offs` uses
    /// `al->addr - sym->start`, and an inline frame's fake symbol reuses
    /// `base_sym->start` (`tools/perf/util/srcline.c new_inline_sym`), so the
    /// whole group shares one offset.
    pub base_offset: Option<u64>,
}

impl ResolvedSymbolFrames {
    #[must_use]
    pub fn from_frames(frames: Vec<String>) -> Self {
        let has_base_symbol = !frames.is_empty();
        let has_inline_frames = frames.len() > 1;
        let has_non_inline_base_frame = has_base_symbol && !has_inline_frames;
        Self {
            frames,
            source_state: SymbolSourceState::AddressDependent,
            has_base_symbol,
            has_inline_frames,
            has_non_inline_base_frame,
            base_offset: None,
        }
    }
}

pub struct SymbolCache<'a, R> {
    resolver: &'a R,
    resolved: FxHashMap<SymbolRequest, Option<String>>,
}

pub struct SymbolFrameCache<'a, R> {
    resolver: &'a R,
    resolved: FxHashMap<SymbolRequest, Vec<String>>,
    resolved_by_mapping: MappingFrameTable,
    resolved_base_by_mapping: MappingFrameTable,
    scratch_seen_mapping: FxHashSet<MappingFrameKey>,
    scratch_missing_keys: Vec<MappingFrameKey>,
    scratch_missing_requests: Vec<SymbolRequest>,
}

type ResolvedFrameSlice<'a> = (&'a [String], Option<u64>, bool, bool);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MappingFrameKey {
    symbol_source_id: usize,
    relative_address: u64,
    kernel_mapping_range: Option<(u64, u64)>,
}

pub(crate) struct CachedMappingFrames {
    revision: u64,
    pub(crate) frames: Vec<String>,
    pub(crate) literal_ends: Vec<Option<usize>>,
    pub(crate) has_base_symbol: bool,
    pub(crate) render_mode: SymbolFrameRenderMode,
    has_inline_frames: bool,
    has_non_inline_base_frame: bool,
    base_offset: Option<u64>,
}

/// Opaque projection key scoped to one `SymbolFrameCache` session.
/// The low bit distinguishes inline from base frames; replacements get a new revision.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct MappingFramesIdentity(NonZeroU64);

impl MappingFramesIdentity {
    pub(crate) fn projection_index(self) -> (usize, usize) {
        let identity = self.0.get();
        let namespace = usize::from(identity & 1 != 0);
        let index =
            usize::try_from((identity >> 1) - 1).expect("symbol projection identity exceeds usize");
        (namespace, index)
    }
}

pub(crate) enum SymbolFrameRenderMode {
    Direct,
    PerfScript,
}

#[derive(Default)]
struct UserFrameAddresses {
    by_address: FxHashMap<u64, usize>,
    // Terminal object failure, not an individual unresolved address.
    unavailable: bool,
    // A per-source hint survives intervening lookups in other objects.
    last_address: Cell<Option<(u64, Option<usize>)>>,
}

#[derive(Clone, Copy)]
struct UserFrameSourceHint {
    source: usize,
    index: Option<usize>,
    last_address: Option<(u64, Option<usize>)>,
}

#[derive(Default)]
struct UserFrameTable {
    by_source: FxHashMap<usize, usize>,
    sources: Vec<UserFrameAddresses>,
    // A cached source with no index is terminal unavailable, including all IPs.
    last_source: Cell<Option<UserFrameSourceHint>>,
    #[cfg(test)]
    source_searches: Cell<usize>,
    #[cfg(test)]
    source_accesses: Cell<usize>,
    #[cfg(test)]
    source_state_checks: Cell<usize>,
    #[cfg(test)]
    address_hint_checks: Cell<usize>,
    #[cfg(test)]
    address_searches: Cell<usize>,
}

impl UserFrameTable {
    #[inline]
    fn slot(&self, source: usize, address: u64) -> Option<usize> {
        let (index, addresses, last_address) = if let Some(hint) = self.last_source.get()
            && hint.source == source
        {
            // perf util/symbol.c:dso__find_symbol (575-583) keys a hit by IP.
            // Keep the source-qualified result beside the source index so
            // repeated IPs need no source-vector access. Mutations reset it.
            if let Some((cached_address, slot)) = hint.last_address
                && cached_address == address
            {
                return slot;
            }
            match hint.index {
                // The source hint establishes availability and rules out the
                // per-source IP hint. Mutations reset both hints.
                Some(index) => {
                    #[cfg(test)]
                    self.source_accesses.set(self.source_accesses.get() + 1);
                    (index, &self.sources[index], None)
                }
                None => return Some(0),
            }
        } else {
            #[cfg(test)]
            self.source_searches.set(self.source_searches.get() + 1);
            let index = *self.by_source.get(&source)?;
            #[cfg(test)]
            self.source_accesses.set(self.source_accesses.get() + 1);
            let addresses = &self.sources[index];
            #[cfg(test)]
            self.source_state_checks
                .set(self.source_state_checks.get() + 1);
            if addresses.unavailable {
                self.last_source.set(Some(UserFrameSourceHint {
                    source,
                    index: None,
                    last_address: None,
                }));
                return Some(0);
            }
            #[cfg(test)]
            self.address_hint_checks
                .set(self.address_hint_checks.get() + 1);
            (index, addresses, addresses.last_address.get())
        };
        let slot = if let Some((cached_address, slot)) = last_address
            && cached_address == address
        {
            slot
        } else {
            #[cfg(test)]
            self.address_searches.set(self.address_searches.get() + 1);
            let slot = addresses.by_address.get(&address).copied();
            addresses.last_address.set(Some((address, slot)));
            slot
        };
        self.last_source.set(Some(UserFrameSourceHint {
            source,
            index: Some(index),
            last_address: Some((address, slot)),
        }));
        slot
    }

    fn source_index(&mut self, source: usize) -> usize {
        *self.by_source.entry(source).or_insert_with(|| {
            let index = self.sources.len();
            self.sources.push(UserFrameAddresses::default());
            index
        })
    }

    fn insert(&mut self, source: usize, address: u64, slot: usize) {
        let index = self.source_index(source);
        let addresses = &mut self.sources[index];
        addresses.unavailable = false;
        addresses.by_address.insert(address, slot);
        addresses.last_address.set(None);
        self.last_source.set(Some(UserFrameSourceHint {
            source,
            index: Some(index),
            last_address: None,
        }));
    }

    fn mark_unavailable(&mut self, source: usize) {
        let index = self.source_index(source);
        self.sources[index] = UserFrameAddresses {
            unavailable: true,
            ..UserFrameAddresses::default()
        };
        self.last_source.set(Some(UserFrameSourceHint {
            source,
            index: None,
            last_address: None,
        }));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.sources
            .iter()
            .map(|addresses| addresses.by_address.len())
            .sum()
    }
}

static UNRESOLVED_MAPPING_FRAMES: CachedMappingFrames = CachedMappingFrames {
    revision: 0,
    frames: Vec::new(),
    literal_ends: Vec::new(),
    has_base_symbol: false,
    render_mode: SymbolFrameRenderMode::Direct,
    has_inline_frames: false,
    has_non_inline_base_frame: false,
    base_offset: None,
};

impl CachedMappingFrames {
    fn is_fully_unresolved(&self) -> bool {
        self.frames.is_empty()
            && !self.has_base_symbol
            && !self.has_inline_frames
            && !self.has_non_inline_base_frame
            && self.base_offset.is_none()
    }
}

#[derive(Default)]
struct MappingFrameTable {
    user: UserFrameTable,
    kernel: FxHashMap<MappingFrameKey, usize>,
    frames: Vec<CachedMappingFrames>,
    last_revision: u64,
    #[cfg(test)]
    lookups: Cell<usize>,
}

impl MappingFrameTable {
    #[inline]
    fn user_slot(&self, symbol_source_id: usize, relative_address: u64) -> Option<usize> {
        self.user.slot(symbol_source_id, relative_address)
    }

    fn slot(&self, key: &MappingFrameKey) -> Option<usize> {
        #[cfg(test)]
        self.lookups.set(self.lookups.get() + 1);
        if key.kernel_mapping_range.is_some() {
            self.kernel.get(key).copied()
        } else {
            self.user_slot(key.symbol_source_id, key.relative_address)
        }
    }

    fn contains_key(&self, key: &MappingFrameKey) -> bool {
        self.slot(key).is_some()
    }

    #[cfg(test)]
    fn get(&self, key: &MappingFrameKey) -> Option<&CachedMappingFrames> {
        self.slot(key).map(|slot| self.at_slot(slot))
    }

    #[inline]
    fn at_slot(&self, slot: usize) -> &CachedMappingFrames {
        // Zero represents a resolved negative result, not a cache miss.
        if slot == 0 {
            &UNRESOLVED_MAPPING_FRAMES
        } else {
            &self.frames[slot - 1]
        }
    }

    #[inline]
    fn get_frame(&self, mapping: &MappedFrame<'_>) -> Option<&CachedMappingFrames> {
        #[cfg(test)]
        self.lookups.set(self.lookups.get() + 1);
        let slot = if let Some(range) = mapping.kernel_range() {
            self.kernel
                .get(&MappingFrameKey {
                    symbol_source_id: mapping.symbol_source_id(),
                    relative_address: mapping.relative_address,
                    kernel_mapping_range: Some(range),
                })
                .copied()
        } else {
            self.user_slot(mapping.symbol_source_id(), mapping.relative_address)
        };
        slot.map(|slot| self.at_slot(slot))
    }

    fn insert(&mut self, key: MappingFrameKey, mut frames: CachedMappingFrames) {
        let fully_unresolved = frames.is_fully_unresolved();
        frames.revision = if fully_unresolved {
            0
        } else {
            self.last_revision = self
                .last_revision
                .checked_add(1)
                .filter(|revision| *revision <= u64::MAX >> 1)
                .expect("symbol frame cache revision exhausted");
            self.last_revision
        };
        if let Some(slot) = self.slot(&key) {
            if slot != 0 {
                self.frames[slot - 1] = frames;
                return;
            }
            if fully_unresolved {
                return;
            }
        }
        let slot = if fully_unresolved {
            0
        } else {
            self.frames.push(frames);
            self.frames.len()
        };
        if key.kernel_mapping_range.is_some() {
            self.kernel.insert(key, slot);
        } else {
            self.user
                .insert(key.symbol_source_id, key.relative_address, slot);
        }
    }
}

pub struct Addr2lineResolver<'a, R> {
    runner: &'a R,
    metadata_cache: OnceLock<Mutex<FxHashMap<OsString, Option<Arc<CachedObjectMetadata>>>>>,
}

pub enum SelectedObjectResolver<'a, R> {
    Addr2line(Addr2lineResolver<'a, R>),
    RustAddr2line(RustAddr2lineResolver),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolizerKind {
    Addr2line,
    RustAddr2line,
}

#[derive(Default)]
pub struct RustAddr2lineResolver {
    metadata_cache: OnceLock<Mutex<FxHashMap<OsString, Option<Arc<CachedObjectMetadata>>>>>,
}

#[derive(Default)]
struct ObjectAddressCache {
    segments_by_path: FxHashMap<OsString, Option<Vec<ObjectSegmentRange>>>,
}

struct ObjectSegmentRange {
    file_offset: u64,
    file_end: u64,
    virtual_address: u64,
}

struct PerfDwarfNameResolver {
    names: Vec<String>,
    units: Vec<PerfDwarfUnitIndex>,
}

type PerfDwarfNameId = u32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PerfAddressRange {
    begin: u64,
    end: u64,
}

#[derive(Debug)]
struct PerfDwarfUnitIndex {
    ranges: Option<Vec<PerfAddressRange>>,
    segments: Vec<PerfDwarfFrameRange>,
}

#[derive(Debug)]
struct PerfDwarfDieNode {
    kind: PerfDwarfDieKind,
    ranges: Vec<PerfAddressRange>,
    name: Option<PerfDwarfNameId>,
    children: Vec<PerfDwarfDieNode>,
}

#[derive(Debug)]
struct PerfDwarfFrameRange {
    range: PerfAddressRange,
    frames: Arc<[PerfDwarfNameId]>,
    has_inline_frames: bool,
    has_source_line: bool,
    order: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PerfDwarfDieKind {
    Subprogram,
    Inline,
}

#[derive(Default)]
struct PreparedObjectMetadata {
    object_symbols: PerfObjectSymbolIndex,
}

struct CachedObjectMetadata {
    object_metadata: PreparedObjectMetadata,
    object_bytes: Arc<[u8]>,
    dwarf_index: Mutex<PerfDwarfIndexCache>,
}

/// Per-object memo of DWARF inline-frame indexes.
///
/// Folding queries the same hot objects every round; re-parsing their DWARF
/// and re-walking the DIE trees per batch dominated fold time. Unit ranges are
/// scanned once, and each unit's frame index is built on the first batch whose
/// addresses land in it. The name interner is append-only so frame name ids
/// stay valid across incremental builds.
#[derive(Default)]
struct PerfDwarfIndexCache {
    names: PerfDwarfNameInterner,
    units: Option<Vec<PerfDwarfCachedUnit>>,
    failed: bool,
}

struct PerfDwarfCachedUnit {
    ranges: Option<Vec<PerfAddressRange>>,
    source_line_ranges: Option<Vec<PerfAddressRange>>,
    segments: Option<Vec<PerfDwarfFrameRange>>,
}

struct LiveVdsoElf {
    path: PathBuf,
}

impl Drop for LiveVdsoElf {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Default)]
struct PerfObjectSymbolNames<'a> {
    bare: Option<&'a str>,
    offset: Option<u64>,
}

#[derive(Default)]
struct PerfObjectSymbolIndex {
    symbols: Vec<PerfSymbolCandidate>,
    max_end_by_index: Vec<u64>,
}

pub struct PerfSymbolResolver<O> {
    object_resolver: O,
    address_cache: Mutex<ObjectAddressCache>,
    debug_dir: Option<PathBuf>,
    kernel_elf: Option<PathBuf>,
    recorded_kernel_build_id: Option<String>,
    file_kernel_cache: Option<FileKernelCache>,
    kallsyms: Option<Kallsyms>,
    live_kallsyms: Option<Kallsyms>,
    live_kallsyms_path: Option<PathBuf>,
    live_kallsyms_cache: OnceLock<Option<Kallsyms>>,
    live_module_kallsyms_cache: OnceLock<FxHashMap<String, Arc<Kallsyms>>>,
    system_map_kallsyms: Option<Kallsyms>,
    system_map_candidates: Vec<PathBuf>,
    system_map_kallsyms_cache: OnceLock<Option<Kallsyms>>,
    live_vdso_elf_cache: OnceLock<Option<LiveVdsoElf>>,
    /// `/sys/kernel/notes` (or a test override) — the live kernel's GNU
    /// build-id note. Used only for System.map-style fallbacks; perf's
    /// `dso__find_kallsyms()` may still use kallsyms and `kallsyms__delta()`
    /// relocates it through the recorded reference symbol.
    live_kernel_notes_path: Option<PathBuf>,
    live_kernel_build_id_cache: OnceLock<Option<String>>,
}

struct FileKernelCache {
    perfdata: PathBuf,
    debug_dir: PathBuf,
    loaded: OnceLock<CachedKernelSymbols>,
}

#[derive(Default)]
struct CachedKernelSymbols {
    build_id: Option<String>,
    kallsyms: Option<Kallsyms>,
    elf: Option<PathBuf>,
}

impl FileKernelCache {
    fn symbols(&self) -> &CachedKernelSymbols {
        self.loaded.get_or_init(|| {
            let Some(build_id) = kernel_build_id_from_perfdata_file(&self.perfdata)
                .ok()
                .flatten()
            else {
                return CachedKernelSymbols::default();
            };
            let elf = perf_build_id_elf_path(&self.debug_dir, &build_id);
            CachedKernelSymbols {
                kallsyms: Kallsyms::load_perf_build_id_cache(&self.debug_dir, &build_id),
                elf: elf.exists().then_some(elf),
                build_id: Some(build_id),
            }
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Kallsyms {
    symbols: BTreeMap<u64, KallsymsSymbol>,
    addresses_by_name: BTreeMap<String, u64>,
    module_indexes: FxHashMap<String, ModuleKallsymsIndex>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ModuleKallsymsIndex {
    nodes: Vec<ModuleKallsymsNode>,
    root: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModuleKallsymsNode {
    address: u64,
    end: u64,
    parent: Option<usize>,
    left: Option<usize>,
    right: Option<usize>,
    red: bool,
}

impl ModuleKallsymsIndex {
    fn insert_ascending(&mut self, address: u64, end: u64) {
        // symbol.c:878-991 moves ascending survivors into fresh module trees;
        // __symbols__insert:361 + tools/lib/rbtree.c:90 balance each insertion.
        // The previous row is the rightmost node, so no insertion search or
        // left-right zigzag is needed. Core kernel trees are NOT rebuilt here.
        let new = self.nodes.len();
        let parent = new.checked_sub(1);
        self.nodes.push(ModuleKallsymsNode {
            address,
            end,
            parent,
            left: None,
            right: None,
            red: true,
        });
        if let Some(parent) = parent {
            debug_assert!(self.nodes[parent].address < address);
            self.nodes[parent].right = Some(new);
        }
        let mut node = new;
        loop {
            let Some(parent) = self.nodes[node].parent else {
                self.root = Some(node);
                self.nodes[node].red = false;
                break;
            };
            if !self.nodes[parent].red {
                break;
            }
            let grandparent = self.nodes[parent]
                .parent
                .expect("a red parent cannot be the black root");
            debug_assert_eq!(self.nodes[grandparent].right, Some(parent));
            if let Some(uncle) = self.nodes[grandparent].left
                && self.nodes[uncle].red
            {
                self.nodes[uncle].red = false;
                self.nodes[parent].red = false;
                self.nodes[grandparent].red = true;
                node = grandparent;
                continue;
            }
            self.rotate_left(grandparent, parent);
            break;
        }
    }

    fn rotate_left(&mut self, grandparent: usize, parent: usize) {
        let middle = self.nodes[parent].left;
        self.nodes[grandparent].right = middle;
        if let Some(middle) = middle {
            self.nodes[middle].parent = Some(grandparent);
        }
        self.nodes[parent].left = Some(grandparent);
        let ancestor = self.nodes[grandparent].parent;
        self.nodes[parent].parent = ancestor;
        self.nodes[parent].red = self.nodes[grandparent].red;
        self.nodes[grandparent].parent = Some(parent);
        self.nodes[grandparent].red = true;
        if let Some(ancestor) = ancestor {
            if self.nodes[ancestor].left == Some(grandparent) {
                self.nodes[ancestor].left = Some(parent);
            } else {
                self.nodes[ancestor].right = Some(parent);
            }
        } else {
            self.root = Some(parent);
        }
    }

    fn find(&self, address: u64) -> Option<&ModuleKallsymsNode> {
        // symbol.c:401 symbols__find returns the FIRST containing node in
        // the root walk, including an exact match to a zero-length symbol.
        let mut cursor = self.root;
        while let Some(index) = cursor {
            let node = &self.nodes[index];
            if address < node.address {
                cursor = node.left;
            } else if address > node.end || (address == node.end && node.end != node.address) {
                cursor = node.right;
            } else {
                return Some(node);
            }
        }
        None
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KallsymsSymbol {
    name: String,
    end: Option<u64>,
    module: Option<String>,
}

impl KallsymsSymbol {
    fn kernel(name: String) -> Self {
        Self {
            name,
            end: None,
            module: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct BorrowedKallsymsRow<'a> {
    address: u64,
    end: u64,
    name: &'a str,
    full_name: &'a str,
    module: Option<&'a str>,
    symbol_type: char,
}

impl BorrowedKallsymsRow<'_> {
    fn into_module_symbol(self, module: &str) -> KallsymsSymbol {
        KallsymsSymbol {
            name: self.name.to_owned(),
            end: Some(self.end),
            module: Some(module.to_owned()),
        }
    }
}

#[must_use]
pub fn perf_debug_dir(home: &Path) -> PathBuf {
    home.join(".debug")
}

#[must_use]
pub fn perf_build_id_elf_path(debug_dir: &Path, build_id: &str) -> PathBuf {
    let (prefix, suffix) = build_id.split_at(2);
    debug_dir
        .join(".build-id")
        .join(prefix)
        .join(suffix)
        .join("elf")
}

#[must_use]
pub fn perf_build_id_elf_path_for_dso(
    debug_dir: &Path,
    dso_path: &Path,
    build_id: &str,
) -> PathBuf {
    if is_perf_vdso_dso_path(dso_path) {
        // perf's build-id cache uses [vdso]/<build-id>/vdso for VDSO DSOs
        // (tools/perf/util/build-id.c: build_id_cache__basename with is_vdso).
        return debug_dir.join("[vdso]").join(build_id).join("vdso");
    }

    perf_build_id_elf_path(debug_dir, build_id)
}

fn is_perf_vdso_dso_path(path: &Path) -> bool {
    matches!(path.to_str(), Some("[vdso]" | "[vdso32]" | "[vdsox32]"))
}

fn copy_live_vdso_elf_like_perf() -> Option<LiveVdsoElf> {
    // perf special-cases VDSO maps in tools/perf/util/map.c: map__new()
    // clears namespace handling, forces pgoff = 0, and calls
    // machine__findnew_vdso(). tools/perf/util/vdso.c get_file() then copies
    // the host [vdso] mapping bytes into a temporary ELF and uses that DSO for
    // symbolization. Do the same for recordings with no VDSO build-id cache.
    #[cfg(target_os = "linux")]
    {
        copy_live_vdso_elf_linux()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn copy_live_vdso_elf_linux() -> Option<LiveVdsoElf> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let vdso_range = maps.lines().find_map(|line| {
        if !line.split_whitespace().any(|field| field == "[vdso]") {
            return None;
        }
        let range = line.split_whitespace().next()?;
        let (start, end) = range.split_once('-')?;
        let start = u64::from_str_radix(start, 16).ok()?;
        let end = u64::from_str_radix(end, 16).ok()?;
        (end > start).then_some((start, end))
    })?;
    let len = usize::try_from(vdso_range.1.checked_sub(vdso_range.0)?).ok()?;
    let mut bytes = vec![0; len];
    let mut mem = std::fs::File::open("/proc/self/mem").ok()?;
    mem.seek(SeekFrom::Start(vdso_range.0)).ok()?;
    mem.read_exact(&mut bytes).ok()?;

    let path = std::env::temp_dir().join(format!(
        "pyroclast-vdso-{}-{}.so",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .ok()?;
    if file.write_all(&bytes).is_err() {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    Some(LiveVdsoElf { path })
}

#[must_use]
pub fn nixos_system_map_path(kernel_image: &Path) -> Option<PathBuf> {
    linux_system_map_candidates(Some(&std::fs::canonicalize(kernel_image).ok()?), "")
        .into_iter()
        .next()
        .filter(|path| path.exists())
}

#[must_use]
pub fn linux_system_map_candidates(
    kernel_image: Option<&Path>,
    kernel_release: &str,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(kernel_image) = kernel_image
        && let Some(parent) = kernel_image.parent()
    {
        candidates.push(parent.join("System.map"));
    }
    candidates.extend([
        PathBuf::from(format!("/boot/System.map-{kernel_release}")),
        PathBuf::from(format!("/usr/lib/debug/boot/System.map-{kernel_release}")),
        PathBuf::from(format!("/lib/modules/{kernel_release}/System.map")),
        PathBuf::from(format!(
            "/usr/lib/debug/lib/modules/{kernel_release}/System.map"
        )),
    ]);
    candidates
}

#[must_use]
pub fn linux_system_map_candidates_for_system(
    kernel_images: impl IntoIterator<Item = PathBuf>,
    kernel_release: &str,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    for kernel_image in kernel_images {
        candidates.extend(linux_system_map_candidates(
            Some(&kernel_image),
            kernel_release,
        ));
    }
    candidates.extend(linux_system_map_candidates(None, kernel_release));
    dedup_paths(candidates)
}

#[must_use]
pub fn perf_symbol_resolver_for_perfdata_file<'a, R>(
    runner: &'a R,
    perfdata: &Path,
    home: &Path,
) -> PerfSymbolResolver<Addr2lineResolver<'a, R>>
where
    R: CommandRunner,
{
    perf_symbol_resolver_for_perfdata_file_with_object(
        Addr2lineResolver::new(runner),
        perfdata,
        home,
    )
}

#[must_use]
pub fn perf_symbol_resolver_for_perfdata_file_with_object<O>(
    object_resolver: O,
    perfdata: &Path,
    home: &Path,
) -> PerfSymbolResolver<O>
where
    O: SymbolResolver,
{
    PerfSymbolResolver::from_object_resolver(object_resolver)
        .with_perfdata_file_kernel_cache(perfdata, &perf_debug_dir(home))
}

#[must_use]
pub fn perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources<O>(
    object_resolver: O,
    perfdata: &Path,
    home: &Path,
    system_map_candidates: impl IntoIterator<Item = PathBuf>,
    kallsyms_path: &Path,
) -> PerfSymbolResolver<O>
where
    O: SymbolResolver,
{
    perf_symbol_resolver_for_perfdata_file_with_object(object_resolver, perfdata, home)
        .with_system_map_candidates(system_map_candidates)
        .with_system_kallsyms_from_path(kallsyms_path)
}

#[must_use]
pub fn perf_symbol_resolver_for_perfdata_file_with_symbolizer<'a, R>(
    runner: &'a R,
    perfdata: &Path,
    home: &Path,
    symbolizer: SymbolizerKind,
) -> PerfSymbolResolver<SelectedObjectResolver<'a, R>>
where
    R: CommandRunner,
{
    perf_symbol_resolver_for_perfdata_file_with_object(
        SelectedObjectResolver::new(runner, symbolizer),
        perfdata,
        home,
    )
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut deduped = Vec::new();
    for path in paths {
        if !deduped.contains(&path) {
            deduped.push(path);
        }
    }
    deduped
}

#[must_use]
pub fn current_linux_system_map_candidates() -> Vec<PathBuf> {
    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    let kernel_images = ["/run/booted-system/kernel", "/run/current-system/kernel"]
        .into_iter()
        .filter_map(|path| std::fs::canonicalize(path).ok());
    linux_system_map_candidates_for_system(kernel_images, &kernel_release)
}

#[must_use]
pub fn perf_symbol_resolver_for_current_home<'a, R>(
    runner: &'a R,
    perfdata: &Path,
) -> PerfSymbolResolver<Addr2lineResolver<'a, R>>
where
    R: CommandRunner,
{
    perf_symbol_resolver_for_current_home_with_object(Addr2lineResolver::new(runner), perfdata)
}

#[must_use]
pub fn perf_symbol_resolver_for_current_home_with_symbolizer<'a, R>(
    runner: &'a R,
    perfdata: &Path,
    symbolizer: SymbolizerKind,
) -> PerfSymbolResolver<SelectedObjectResolver<'a, R>>
where
    R: CommandRunner,
{
    perf_symbol_resolver_for_current_home_with_object(
        SelectedObjectResolver::new(runner, symbolizer),
        perfdata,
    )
}

#[must_use]
pub fn perf_symbol_resolver_for_current_home_with_object<O>(
    object_resolver: O,
    perfdata: &Path,
) -> PerfSymbolResolver<O>
where
    O: SymbolResolver,
{
    match std::env::var_os("HOME") {
        Some(home) => perf_symbol_resolver_for_perfdata_file_with_object_and_system_sources(
            object_resolver,
            perfdata,
            Path::new(&home),
            current_linux_system_map_candidates(),
            Path::new("/proc/kallsyms"),
        ),
        None => PerfSymbolResolver::from_object_resolver(object_resolver).with_system_kallsyms(),
    }
}

impl RustAddr2lineResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn object_metadata(&self, path: &Path) -> Option<Arc<CachedObjectMetadata>> {
        let cache = self
            .metadata_cache
            .get_or_init(|| Mutex::new(FxHashMap::default()));
        let mut cache = cache.lock().expect("rust addr2line metadata cache lock");
        match cache.raw_entry_mut().from_key(path.as_os_str()) {
            RawEntryMut::Occupied(entry) => entry.get().clone(),
            RawEntryMut::Vacant(entry) => {
                let loaded = std::fs::read(path).ok().map(|bytes| {
                    Arc::new(CachedObjectMetadata {
                        object_metadata: PreparedObjectMetadata::from_object_bytes(&bytes),
                        object_bytes: bytes.into(),
                        dwarf_index: Mutex::new(PerfDwarfIndexCache::default()),
                    })
                });
                entry.insert(path.as_os_str().to_owned(), loaded).1.clone()
            }
        }
    }

    #[cfg(test)]
    fn cached_object_count(&self) -> usize {
        self.metadata_cache.get().map_or(0, |cache| {
            cache
                .lock()
                .expect("rust addr2line metadata cache lock")
                .len()
        })
    }
}

impl<'a, R> SelectedObjectResolver<'a, R>
where
    R: CommandRunner,
{
    #[must_use]
    pub fn new(runner: &'a R, symbolizer: SymbolizerKind) -> Self {
        match symbolizer {
            SymbolizerKind::Addr2line => Self::Addr2line(Addr2lineResolver::new(runner)),
            SymbolizerKind::RustAddr2line => Self::RustAddr2line(RustAddr2lineResolver::new()),
        }
    }
}

impl<'a, R> Addr2lineResolver<'a, R>
where
    R: CommandRunner,
{
    #[must_use]
    pub fn new(runner: &'a R) -> Self {
        Self {
            runner,
            metadata_cache: OnceLock::new(),
        }
    }

    fn object_metadata(&self, path: &Path) -> Option<Arc<CachedObjectMetadata>> {
        let cache = self
            .metadata_cache
            .get_or_init(|| Mutex::new(FxHashMap::default()));
        let mut cache = cache.lock().expect("addr2line metadata cache lock");
        match cache.raw_entry_mut().from_key(path.as_os_str()) {
            RawEntryMut::Occupied(entry) => entry.get().clone(),
            RawEntryMut::Vacant(entry) => {
                let loaded = std::fs::read(path).ok().map(|bytes| {
                    Arc::new(CachedObjectMetadata {
                        object_metadata: PreparedObjectMetadata::from_object_bytes(&bytes),
                        object_bytes: bytes.into(),
                        dwarf_index: Mutex::new(PerfDwarfIndexCache::default()),
                    })
                });
                entry.insert(path.as_os_str().to_owned(), loaded).1.clone()
            }
        }
    }

    fn resolve_group_symbols(
        &self,
        path: &Path,
        requests: &[SymbolRequest],
        indexes: &[usize],
    ) -> Result<Vec<Option<String>>, String> {
        let mut stdin = String::new();
        for index in indexes {
            writeln!(stdin, "0x{:x}", requests[*index].relative_address)
                .expect("writing to a string cannot fail");
        }
        let output = self
            .runner
            .run(
                &CommandSpec::new("addr2line")
                    .args(["-f", "-C", "-e", path.to_string_lossy().as_ref()])
                    .stdin(stdin.into_bytes()),
            )
            .map_err(|error| format!("failed to run addr2line: {error}"))?;
        if output.status_code == Some(0) {
            parse_addr2line_stdout(&output.stdout, indexes.len())
        } else {
            Ok(vec![None; indexes.len()])
        }
    }
}

impl<'a, R> PerfSymbolResolver<Addr2lineResolver<'a, R>>
where
    R: CommandRunner,
{
    #[must_use]
    pub fn new(runner: &'a R) -> Self {
        Self::from_object_resolver(Addr2lineResolver::new(runner))
    }
}

impl<O> PerfSymbolResolver<O>
where
    O: SymbolResolver,
{
    #[must_use]
    pub fn from_object_resolver(object_resolver: O) -> Self {
        Self {
            object_resolver,
            address_cache: Mutex::new(ObjectAddressCache::default()),
            debug_dir: None,
            kernel_elf: None,
            recorded_kernel_build_id: None,
            file_kernel_cache: None,
            kallsyms: None,
            live_kallsyms: None,
            live_kallsyms_path: None,
            live_kallsyms_cache: OnceLock::new(),
            live_module_kallsyms_cache: OnceLock::new(),
            system_map_kallsyms: None,
            system_map_candidates: Vec::new(),
            system_map_kallsyms_cache: OnceLock::new(),
            live_vdso_elf_cache: OnceLock::new(),
            live_kernel_notes_path: None,
            live_kernel_build_id_cache: OnceLock::new(),
        }
    }

    #[must_use]
    pub fn object_resolver(&self) -> &O {
        &self.object_resolver
    }

    #[must_use]
    pub fn with_debug_dir(mut self, path: PathBuf) -> Self {
        self.debug_dir = Some(path);
        self
    }

    #[must_use]
    pub fn with_kernel_elf(mut self, path: PathBuf) -> Self {
        self.kernel_elf = Some(path);
        self
    }

    #[must_use]
    pub fn with_kallsyms(mut self, kallsyms: Kallsyms) -> Self {
        self.kallsyms = Some(kallsyms);
        self
    }

    #[must_use]
    pub fn with_live_kallsyms(mut self, kallsyms: Kallsyms) -> Self {
        self.live_kallsyms = Some(kallsyms);
        self.live_kallsyms_path = None;
        self
    }

    #[must_use]
    pub fn with_system_map_kallsyms(mut self, kallsyms: Kallsyms) -> Self {
        self.system_map_kallsyms = Some(kallsyms);
        self.system_map_candidates.clear();
        self
    }

    #[must_use]
    pub fn with_system_map_candidates(self, candidates: impl IntoIterator<Item = PathBuf>) -> Self {
        if self.kernel_elf.is_some() {
            return self;
        }
        let mut this = self;
        if this.system_map_kallsyms.is_none() {
            this.system_map_candidates = dedup_paths(candidates.into_iter().collect());
        }
        this
    }

    #[must_use]
    pub fn with_perfdata_kernel_cache(self, perfdata: &[u8], debug_dir: &Path) -> Self {
        let Some(build_id) = kernel_build_id_from_perfdata(perfdata).ok().flatten() else {
            return self.with_debug_dir(debug_dir.to_path_buf());
        };
        self.with_perfdata_kernel_build_id(&build_id, debug_dir)
    }

    #[must_use]
    pub fn with_perfdata_file_kernel_cache(mut self, perfdata: &Path, debug_dir: &Path) -> Self {
        // tools/perf/util/symbol.c:dso__load loads symbols on demand. A
        // user-only recording must not first be traversed to find kernel IDs.
        self.file_kernel_cache = Some(FileKernelCache {
            perfdata: perfdata.to_path_buf(),
            debug_dir: debug_dir.to_path_buf(),
            loaded: OnceLock::new(),
        });
        self.debug_dir = Some(debug_dir.to_path_buf());
        self
    }

    fn with_perfdata_kernel_build_id(self, build_id: &str, debug_dir: &Path) -> Self {
        let mut self_with_debug_dir = self.with_debug_dir(debug_dir.to_path_buf());
        self_with_debug_dir.recorded_kernel_build_id = Some(build_id.to_string());
        let kernel_elf = perf_build_id_elf_path(debug_dir, build_id);
        let self_with_kallsyms = match Kallsyms::load_perf_build_id_cache(debug_dir, build_id) {
            Some(kallsyms) => self_with_debug_dir.with_kallsyms(kallsyms),
            None => self_with_debug_dir,
        };
        if kernel_elf.exists() {
            self_with_kallsyms.with_kernel_elf(kernel_elf)
        } else {
            self_with_kallsyms
        }
    }

    #[must_use]
    pub fn with_system_kallsyms(self) -> Self {
        self.with_system_kallsyms_from_path(Path::new("/proc/kallsyms"))
    }

    #[must_use]
    pub fn with_system_kallsyms_from_path(self, path: &Path) -> Self {
        let mut this = self;
        if this.live_kallsyms.is_none() {
            this.live_kallsyms_path = Some(path.to_path_buf());
            // Pair the live kallsyms with the running kernel's build-id note so
            // we only trust it for [kernel.kallsyms] frames when it matches the
            // perf.data's recorded kernel build-id.
            if this.live_kernel_notes_path.is_none() {
                this.live_kernel_notes_path = Some(PathBuf::from("/sys/kernel/notes"));
            }
        }
        this
    }

    #[must_use]
    pub fn with_live_kernel_notes_path(mut self, path: PathBuf) -> Self {
        self.live_kernel_notes_path = Some(path);
        self
    }

    fn live_kernel_build_id(&self) -> Option<&str> {
        self.live_kernel_build_id_cache
            .get_or_init(|| {
                let path = self.live_kernel_notes_path.as_ref()?;
                let bytes = std::fs::read(path).ok()?;
                gnu_build_id_from_notes(&bytes)
            })
            .as_deref()
    }

    /// True when the running kernel's build-id matches the build-id recorded in
    /// the perf.data, so live `/proc/kallsyms` describes the same kernel perf
    /// symbolized against. perf trusts kallsyms for the recorded kernel; this is
    /// the equivalent guard for the direct-fold path on the recording machine.
    fn live_kernel_matches_recorded(&self) -> bool {
        match self.recorded_kernel_build_id_ref() {
            Some(recorded) => self
                .live_kernel_build_id()
                .is_some_and(|live| live == recorded),
            None => false,
        }
    }

    fn recorded_kernel_build_id_ref(&self) -> Option<&str> {
        self.recorded_kernel_build_id.as_deref().or_else(|| {
            self.file_kernel_cache
                .as_ref()?
                .symbols()
                .build_id
                .as_deref()
        })
    }

    fn kernel_elf_ref(&self) -> Option<&PathBuf> {
        self.kernel_elf
            .as_ref()
            .or_else(|| self.file_kernel_cache.as_ref()?.symbols().elf.as_ref())
    }

    fn kallsyms_ref(&self) -> Option<&Kallsyms> {
        self.kallsyms
            .as_ref()
            .or_else(|| self.file_kernel_cache.as_ref()?.symbols().kallsyms.as_ref())
    }
}

impl Kallsyms {
    /// Parses `/proc/kallsyms`-style text.
    ///
    /// # Errors
    ///
    /// Returns an error when no valid symbols are present.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut symbols = BTreeMap::new();
        let mut addresses_by_name = BTreeMap::new();
        for (address, symbol) in text
            .lines()
            .filter_map(parse_kallsyms_line)
            .filter(|(address, _)| *address != 0)
        {
            insert_kallsyms_symbol(
                &mut symbols,
                Some(&mut addresses_by_name),
                address,
                KallsymsSymbol::kernel(symbol),
            );
        }
        if symbols.is_empty() {
            return Err("kallsyms did not contain any parseable symbols".to_string());
        }
        Ok(Self {
            symbols,
            addresses_by_name,
            module_indexes: FxHashMap::default(),
        })
    }

    /// Parses only module-backed `/proc/kallsyms` lines.
    ///
    /// # Errors
    ///
    /// Returns an error when no valid module symbols are present.
    pub fn parse_modules(text: &str) -> Result<Self, String> {
        let mut addresses_by_name = BTreeMap::new();
        let symbols = Self::parse_module_symbols(text)
            .into_iter()
            .filter_map(|row| {
                let module = row.module?;
                addresses_by_name
                    .entry(row.name.to_owned())
                    .or_insert(row.address);
                Some((row.address, row.into_module_symbol(module)))
            })
            .collect::<BTreeMap<_, _>>();
        if symbols.is_empty() {
            return Err("kallsyms did not contain any parseable module symbols".to_string());
        }
        let mut result = Self {
            symbols,
            addresses_by_name,
            module_indexes: FxHashMap::default(),
        };
        result.build_module_indexes();
        Ok(result)
    }

    /// Parses only `/proc/kallsyms` lines for a specific module path like `[zfs]`.
    ///
    /// # Errors
    ///
    /// Returns an error when no valid module symbols are present for that module.
    pub fn parse_modules_for_path(text: &str, module_path: &str) -> Result<Self, String> {
        let symbols = Self::parse_module_symbols(text)
            .into_iter()
            .filter(|row| row.module == Some(module_path))
            .map(|row| (row.address, row.into_module_symbol(module_path)))
            .collect::<BTreeMap<_, _>>();
        if symbols.is_empty() {
            return Err(format!(
                "kallsyms did not contain any parseable module symbols for {module_path}"
            ));
        }
        let mut addresses_by_name = BTreeMap::new();
        for (address, symbol) in &symbols {
            addresses_by_name
                .entry(symbol.name.clone())
                .or_insert(*address);
        }
        let mut result = Self {
            symbols,
            addresses_by_name,
            module_indexes: FxHashMap::default(),
        };
        result.build_module_indexes();
        Ok(result)
    }

    fn parse_module_symbols(text: &str) -> Vec<BorrowedKallsymsRow<'_>> {
        #[cfg(test)]
        MODULE_KALLSYMS_TREE_BUILDS.with(|count| count.set(count.get() + 1));
        let mut symbols = Vec::new();
        for row in text
            .lines()
            .filter_map(parse_module_kallsyms_line)
            .filter(|row| row.address != 0)
        {
            #[cfg(test)]
            MODULE_KALLSYMS_SYMBOL_INSERTIONS.with(|count| count.set(count.get() + 1));
            symbols.push(row);
        }
        // symbol.c:1512-1523: fix all accepted core/module ends, then remove
        // duplicates, then split DSOs. Stable order matches equal-IP insertion
        // to the right in __symbols__insert (361). Own only module survivors.
        symbols.sort_by_key(|row| row.address);
        if !symbols.is_empty() {
            fixup_kallsyms_symbol_ends_like_perf(&mut symbols);
        }
        symbols.dedup_by(|next, current| {
            if next.address != current.address {
                return false;
            }
            if kallsyms_next_alias_is_better(current, next) {
                *current = *next;
            }
            true
        });
        symbols
    }

    fn parse_module_views(text: &str) -> FxHashMap<String, Arc<Self>> {
        let mut modules = FxHashMap::<String, Self>::default();
        for row in Self::parse_module_symbols(text) {
            let Some(module) = row.module else {
                continue;
            };
            let view = match modules.raw_entry_mut().from_key(module) {
                RawEntryMut::Occupied(entry) => entry.into_mut(),
                RawEntryMut::Vacant(entry) => entry.insert(module.to_owned(), Self::default()).1,
            };
            // Ascending global addresses preserve the path API's first-by-IP
            // name index, even when the input rows were not address ordered.
            view.addresses_by_name
                .entry(row.name.to_owned())
                .or_insert(row.address);
            view.symbols
                .insert(row.address, row.into_module_symbol(module));
        }
        modules
            .into_iter()
            .map(|(module, mut symbols)| {
                symbols.build_module_indexes();
                (module, Arc::new(symbols))
            })
            .collect()
    }

    fn build_module_indexes(&mut self) {
        for (&address, symbol) in &self.symbols {
            let Some(module) = symbol.module.as_deref() else {
                continue;
            };
            let index = match self.module_indexes.raw_entry_mut().from_key(module) {
                RawEntryMut::Occupied(entry) => entry.into_mut(),
                RawEntryMut::Vacant(entry) => {
                    entry
                        .insert(module.to_owned(), ModuleKallsymsIndex::default())
                        .1
                }
            };
            index.insert_ascending(
                address,
                symbol.end.expect("module ends were fixed globally"),
            );
        }
    }

    #[must_use]
    pub fn load_perf_build_id_cache(debug_dir: &Path, build_id: &str) -> Option<Self> {
        perf_build_id_kallsyms_paths(debug_dir, build_id)
            .into_iter()
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .find_map(|text| Self::parse(&text).ok())
    }

    pub fn load_first_system_map_candidate(
        candidates: impl IntoIterator<Item = PathBuf>,
    ) -> Option<Self> {
        candidates
            .into_iter()
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .find_map(|text| Self::parse(&text).ok())
    }

    #[must_use]
    pub fn resolve(&self, address: u64) -> Option<String> {
        self.symbols
            .range(..=address)
            .next_back()
            .map(|(_, symbol)| symbol.name.clone())
    }

    /// Resolves an address to `name+0x<off>`, matching perf-script kernel
    /// frames (`tools/perf/util/symbol_fprintf.c __symbol__fprintf_symname_offs`
    /// prints the offset from the containing symbol, including `+0x0`).
    #[must_use]
    pub fn resolve_with_offset(&self, address: u64) -> Option<String> {
        self.symbols
            .range(..=address)
            .next_back()
            .map(|(start, symbol)| format!("{}+0x{:x}", symbol.name, address - start))
    }

    #[must_use]
    pub fn resolve_module_with_offset(&self, address: u64) -> Option<String> {
        self.resolve_module_with_offset_in_range(address, None)
    }

    #[must_use]
    pub fn resolve_module_with_offset_in_range(
        &self,
        address: u64,
        range: Option<(u64, u64)>,
    ) -> Option<String> {
        let module = self
            .symbols
            .range(..=address)
            .next_back()?
            .1
            .module
            .as_deref()?;
        self.resolve_module_with_offset_for_path(address, range, module)
    }

    fn resolve_module_with_offset_for_path(
        &self,
        address: u64,
        range: Option<(u64, u64)>,
        module: &str,
    ) -> Option<String> {
        let node = self.module_indexes.get(module)?.find(address)?;
        if let Some((range_start, range_end)) = range
            && (node.address < range_start || range_end <= address)
        {
            return None;
        }
        let symbol = self.symbols.get(&node.address)?;
        Some(format!("{}+0x{:x}", symbol.name, address - node.address))
    }

    #[must_use]
    pub fn resolve_relocated(
        &self,
        address: u64,
        reference_symbol: &str,
        recorded_reference_address: u64,
    ) -> Option<String> {
        let symbol_file_address = self.address_of(reference_symbol)?;
        let delta = symbol_file_address.wrapping_sub(recorded_reference_address);
        self.resolve(address.wrapping_add(delta))
    }

    #[must_use]
    pub fn resolve_relocated_with_offset(
        &self,
        address: u64,
        reference_symbol: &str,
        recorded_reference_address: u64,
    ) -> Option<String> {
        let symbol_file_address = self.address_of(reference_symbol)?;
        let delta = symbol_file_address.wrapping_sub(recorded_reference_address);
        self.resolve_with_offset(address.wrapping_add(delta))
    }

    fn address_of(&self, name: &str) -> Option<u64> {
        self.addresses_by_name.get(name).copied()
    }
}

#[must_use]
pub fn build_addr2line_command(path: &Path, requests: &[SymbolRequest]) -> CommandSpec {
    let mut stdin = String::new();
    for request in requests {
        writeln!(stdin, "0x{:x}", request.relative_address)
            .expect("writing to a string cannot fail");
    }
    CommandSpec::new("addr2line")
        .args(["-f", "-C", "-e", path.to_string_lossy().as_ref()])
        .stdin(stdin.into_bytes())
}

impl<'a, R> SymbolCache<'a, R>
where
    R: SymbolResolver,
{
    #[must_use]
    pub fn new(resolver: &'a R) -> Self {
        Self {
            resolver,
            resolved: FxHashMap::default(),
        }
    }

    /// Resolves one object-relative address through the cache.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails.
    pub fn resolve(&mut self, request: &SymbolRequest) -> Result<Option<String>, String> {
        self.resolve_many(std::slice::from_ref(request))
            .map(|resolved| resolved.into_iter().next().flatten())
    }

    /// Resolves many object-relative addresses, batching cache misses.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails or returns the wrong
    /// number of results.
    pub fn resolve_many(
        &mut self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<Option<String>>, String> {
        let missing = self.unique_misses(requests);
        if !missing.is_empty() {
            self.resolve_missing(missing)?;
        }

        requests
            .iter()
            .map(|request| {
                self.resolved
                    .get(request)
                    .cloned()
                    .ok_or_else(|| "symbol cache lookup missed after resolution".to_string())
            })
            .collect()
    }

    fn unique_misses(&self, requests: &[SymbolRequest]) -> Vec<SymbolRequest> {
        let mut seen = FxHashSet::default();
        let mut missing = Vec::new();
        for request in requests {
            if self.resolved.contains_key(request) || !seen.insert(request) {
                continue;
            }
            missing.push(request.clone());
        }
        missing
    }

    fn resolve_missing(&mut self, missing: Vec<SymbolRequest>) -> Result<(), String> {
        let resolved = self.resolver.resolve_batch(&missing)?;
        if resolved.len() != missing.len() {
            return Err(format!(
                "symbol resolver returned {} results for {} requests",
                resolved.len(),
                missing.len()
            ));
        }
        self.resolved.reserve(missing.len());
        for (request, symbol) in missing.into_iter().zip(resolved) {
            self.resolved.insert(request, symbol);
        }
        Ok(())
    }
}

impl<'a, R> SymbolFrameCache<'a, R>
where
    R: SymbolResolver,
{
    #[must_use]
    pub fn new(resolver: &'a R) -> Self {
        Self {
            resolver,
            resolved: FxHashMap::default(),
            resolved_by_mapping: MappingFrameTable::default(),
            resolved_base_by_mapping: MappingFrameTable::default(),
            scratch_seen_mapping: FxHashSet::default(),
            scratch_missing_keys: Vec::new(),
            scratch_missing_requests: Vec::new(),
        }
    }

    /// Resolves one object-relative address through the cache.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails.
    pub fn resolve(&mut self, request: &SymbolRequest) -> Result<Vec<String>, String> {
        self.resolve_many(std::slice::from_ref(request))
            .map(|resolved| resolved.into_iter().next().unwrap_or_default())
    }

    /// Resolves one object-relative address through the cache and returns a
    /// borrowed frame slice.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails.
    pub fn resolve_ref(&mut self, request: &SymbolRequest) -> Result<&[String], String> {
        self.prefetch_many(std::slice::from_ref(request))?;
        self.resolved
            .get(request)
            .map(Vec::as_slice)
            .ok_or_else(|| "symbol frame cache lookup missed after resolution".to_string())
    }

    /// Resolves one borrowed perfdata mapping through the cache and returns a
    /// borrowed frame slice.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails.
    pub fn resolve_mapping_ref(
        &mut self,
        mapping: &ResolvedMappingRef<'_>,
    ) -> Result<&[String], String> {
        let cached = self.resolve_cached_mapping(mapping, true)?;
        Ok(cached.frames.as_slice())
    }

    /// Resolves one borrowed perfdata mapping through the cache and returns the
    /// inline frame slice together with the shared `+0x<off>` offset suffix
    /// perf prints on every inline and base frame at this address.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails.
    pub fn resolve_mapping_ref_with_offset(
        &mut self,
        mapping: &ResolvedMappingRef<'_>,
    ) -> Result<ResolvedFrameSlice<'_>, String> {
        let cached = self.resolve_cached_mapping(mapping, true)?;
        Ok((
            cached.frames.as_slice(),
            cached.base_offset,
            cached.has_inline_frames,
            cached.has_non_inline_base_frame,
        ))
    }

    /// Resolves one borrowed perfdata mapping and returns frames only when perf
    /// would have had a base object symbol for the IP.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails.
    pub fn resolve_mapping_ref_with_base_symbol(
        &mut self,
        mapping: &ResolvedMappingRef<'_>,
    ) -> Result<Option<&[String]>, String> {
        let cached = self.resolve_cached_mapping(mapping, false)?;
        Ok(cached.has_base_symbol.then_some(cached.frames.as_slice()))
    }

    /// Resolves one borrowed perfdata mapping to its single base object symbol
    /// frames (no DWARF inline expansion).
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails.
    pub fn resolve_base_mapping_ref(
        &mut self,
        mapping: &ResolvedMappingRef<'_>,
    ) -> Result<&[String], String> {
        let cached = self.resolve_cached_mapping(mapping, false)?;
        Ok(cached.frames.as_slice())
    }

    fn resolve_cached_mapping(
        &mut self,
        mapping: &ResolvedMappingRef<'_>,
        inline: bool,
    ) -> Result<&CachedMappingFrames, String> {
        let key = mapping_frame_key(mapping);
        let table = if inline {
            &self.resolved_by_mapping
        } else {
            &self.resolved_base_by_mapping
        };
        let slot = table.slot(&key);
        let slot = if let Some(slot) = slot {
            slot
        } else {
            self.prefetch_mapping_refs_with_mode(std::slice::from_ref(mapping), inline)?;
            let table = if inline {
                &self.resolved_by_mapping
            } else {
                &self.resolved_base_by_mapping
            };
            table
                .slot(&key)
                .ok_or_else(|| "symbol frame cache lookup missed after resolution".to_string())?
        };
        let table = if inline {
            &self.resolved_by_mapping
        } else {
            &self.resolved_base_by_mapping
        };
        Ok(table.at_slot(slot))
    }

    /// Resolves many borrowed perfdata mappings to base symbols only.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails or returns the wrong
    /// number of results.
    pub fn prefetch_base_mapping_refs(
        &mut self,
        mappings: &[ResolvedMappingRef<'_>],
    ) -> Result<(), String> {
        self.prefetch_mapping_refs_with_mode(mappings, false)
    }

    /// Resolves many object-relative addresses to frame lists, batching cache misses.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails or returns the wrong
    /// number of results.
    pub fn resolve_many(&mut self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
        self.prefetch_many(requests)?;

        requests
            .iter()
            .map(|request| {
                self.resolved
                    .get(request)
                    .cloned()
                    .ok_or_else(|| "symbol frame cache lookup missed after resolution".to_string())
            })
            .collect()
    }

    /// Resolves many object-relative addresses through the cache without
    /// cloning the cached frame vectors back out.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails or returns the wrong
    /// number of results.
    pub fn prefetch_many(&mut self, requests: &[SymbolRequest]) -> Result<(), String> {
        let missing = self.unique_misses(requests);
        if !missing.is_empty() {
            self.resolve_missing(missing)?;
        }
        Ok(())
    }

    /// Resolves many borrowed perfdata mappings through the cache without
    /// materializing path-keyed lookups on cache hits.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails or returns the wrong
    /// number of results.
    pub fn prefetch_mapping_refs(
        &mut self,
        mappings: &[ResolvedMappingRef<'_>],
    ) -> Result<(), String> {
        self.prefetch_mapping_refs_with_mode(mappings, true)
    }

    pub(crate) fn mapping_ref_cached(
        &self,
        mapping: &ResolvedMappingRef<'_>,
        inline: bool,
    ) -> bool {
        let table = if inline {
            &self.resolved_by_mapping
        } else {
            &self.resolved_base_by_mapping
        };
        table.contains_key(&mapping_frame_key(mapping))
    }

    #[cfg(test)]
    pub(crate) fn mapping_frame_lookup_count(&self) -> usize {
        self.resolved_by_mapping.lookups.get() + self.resolved_base_by_mapping.lookups.get()
    }

    #[inline]
    pub(crate) fn cached_mapping_frames(
        &self,
        mapping: &MappedFrame<'_>,
        inline: bool,
    ) -> Option<&CachedMappingFrames> {
        let table = if inline {
            &self.resolved_by_mapping
        } else {
            &self.resolved_base_by_mapping
        };
        table.get_frame(mapping)
    }

    /// Returns a session-local projection identity and borrowed frames in one lookup.
    /// A miss is outer `None`; fully unresolved frames have no identity.
    #[inline]
    pub(crate) fn cached_mapping_frames_with_identity(
        &self,
        mapping: &MappedFrame<'_>,
        inline: bool,
    ) -> Option<(Option<MappingFramesIdentity>, &CachedMappingFrames)> {
        let cached = self.cached_mapping_frames(mapping, inline)?;
        let identity = (cached.revision != 0).then(|| {
            MappingFramesIdentity(
                NonZeroU64::new((cached.revision << 1) | u64::from(inline))
                    .expect("symbol projection identity is nonzero"),
            )
        });
        Some((identity, cached))
    }

    pub(crate) fn prefetch_mapping_refs_with_mode<'mapping, M>(
        &mut self,
        mappings: impl IntoIterator<Item = M>,
        inline: bool,
    ) -> Result<(), String>
    where
        M: Borrow<ResolvedMappingRef<'mapping>>,
    {
        let mut seen = std::mem::take(&mut self.scratch_seen_mapping);
        let mut keys = std::mem::take(&mut self.scratch_missing_keys);
        let mut requests = std::mem::take(&mut self.scratch_missing_requests);
        seen.clear();
        keys.clear();
        let result = (|| {
            for mapping in mappings {
                let mapping = mapping.borrow();
                let key = mapping_frame_key(mapping);
                if self.mapping_ref_cached(mapping, inline) || !seen.insert(key) {
                    continue;
                }
                keys.push(key);
                let index = keys.len() - 1;
                if let Some(request) = requests.get_mut(index) {
                    update_symbol_request_from_mapping_ref(request, mapping);
                } else {
                    requests.push(symbol_request_from_mapping_ref(mapping));
                }
            }
            if keys.is_empty() {
                return Ok(());
            }
            let requests = &requests[..keys.len()];
            let resolved = if inline {
                self.resolver.resolve_frame_batch_with_metadata(requests)?
            } else {
                self.resolver
                    .resolve_base_frame_batch_with_metadata(requests)?
            };
            if resolved.len() != requests.len() {
                return Err(format!(
                    "symbol resolver returned {} frame results for {} requests",
                    resolved.len(),
                    requests.len()
                ));
            }
            for (key, frames) in keys.drain(..).zip(resolved) {
                let unavailable = frames.source_state == SymbolSourceState::Unavailable;
                let frames = CachedMappingFrames {
                    revision: 0,
                    literal_ends: frames
                        .frames
                        .iter()
                        .map(|frame| crate::folded::inferno_perf_raw_function_literal_end(frame))
                        .collect(),
                    // symbol_fprintf.c prints names verbatim. Inferno splits
                    // LF before stack_line_parts trims rawfunc, so these labels
                    // require row parsing, not folded-label escaping. Classify
                    // once on cache insertion, not on each sampled stack.
                    render_mode: if frames
                        .frames
                        .iter()
                        .any(|name| name.contains('\n') || name.trim().len() != name.len())
                    {
                        SymbolFrameRenderMode::PerfScript
                    } else {
                        SymbolFrameRenderMode::Direct
                    },
                    frames: frames.frames,
                    has_base_symbol: frames.has_base_symbol,
                    has_inline_frames: frames.has_inline_frames,
                    has_non_inline_base_frame: frames.has_non_inline_base_frame,
                    base_offset: frames.base_offset,
                };
                if unavailable && key.kernel_mapping_range.is_none() && frames.is_fully_unresolved()
                {
                    self.resolved_by_mapping
                        .user
                        .mark_unavailable(key.symbol_source_id);
                    self.resolved_base_by_mapping
                        .user
                        .mark_unavailable(key.symbol_source_id);
                } else {
                    let table = if inline {
                        &mut self.resolved_by_mapping
                    } else {
                        &mut self.resolved_base_by_mapping
                    };
                    table.insert(key, frames);
                }
            }
            Ok(())
        })();
        self.scratch_seen_mapping = seen;
        self.scratch_missing_keys = keys;
        self.scratch_missing_requests = requests;
        result
    }

    fn unique_misses(&self, requests: &[SymbolRequest]) -> Vec<SymbolRequest> {
        let mut seen = FxHashSet::default();
        let mut missing = Vec::new();
        for request in requests {
            if self.resolved.contains_key(request) || !seen.insert(request) {
                continue;
            }
            missing.push(request.clone());
        }
        missing
    }

    fn resolve_missing(&mut self, missing: Vec<SymbolRequest>) -> Result<(), String> {
        let resolved = self.resolver.resolve_frame_batch(&missing)?;
        if resolved.len() != missing.len() {
            return Err(format!(
                "symbol resolver returned {} frame results for {} requests",
                resolved.len(),
                missing.len()
            ));
        }
        self.resolved.reserve(missing.len());
        for (request, frames) in missing.into_iter().zip(resolved) {
            self.resolved.insert(request, frames);
        }
        Ok(())
    }
}

impl<O> SymbolResolver for PerfSymbolResolver<O>
where
    O: SymbolResolver,
{
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        let mut resolved = vec![None; requests.len()];
        let mut kernel_elf_requests = Vec::new();
        let mut kernel_elf_indexes = Vec::new();
        let mut user_requests = Vec::new();
        let mut user_indexes = Vec::new();
        let mut address_cache = self
            .address_cache
            .lock()
            .expect("object address cache lock");

        for (index, request) in requests.iter().enumerate() {
            if is_kernel_module_symbol_path(&request.path) {
                if let Some(object_request) =
                    self.cached_object_symbol_request(request, &mut address_cache)
                {
                    user_indexes.push(index);
                    user_requests.push(object_request);
                } else {
                    resolved[index] = self.resolve_kernel_symbol(request);
                }
            } else if is_kernel_symbol_path(&request.path) {
                if let Some(symbol) = self.resolve_kernel_symbol(request) {
                    resolved[index] = Some(symbol);
                } else if let Some(kernel_elf) = self.kernel_elf_ref() {
                    kernel_elf_indexes.push(index);
                    kernel_elf_requests.push(clean_object_symbol_request_with_cache(
                        kernel_elf.clone(),
                        request.relative_address,
                        &mut address_cache,
                    ));
                }
            } else {
                let object_request = self.object_symbol_request(request, &mut address_cache);
                user_indexes.push(index);
                user_requests.push(object_request);
            }
        }

        drop(address_cache);
        if !kernel_elf_requests.is_empty() {
            let kernel_symbols = self.object_resolver.resolve_batch(&kernel_elf_requests)?;
            for (index, symbol) in kernel_elf_indexes.into_iter().zip(kernel_symbols) {
                resolved[index] = symbol;
            }
        }

        if !user_requests.is_empty() {
            let user_symbols = self.object_resolver.resolve_batch(&user_requests)?;
            for (index, symbol) in user_indexes.into_iter().zip(user_symbols) {
                resolved[index] = symbol.or_else(|| {
                    is_kernel_module_symbol_path(&requests[index].path)
                        .then(|| self.resolve_kernel_symbol(&requests[index]))
                        .flatten()
                });
            }
        }
        Ok(resolved)
    }

    fn resolve_frame_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
        self.resolve_frame_batch_with_metadata(requests)
            .map(|resolved| {
                resolved
                    .into_iter()
                    .map(|resolved| resolved.frames)
                    .collect()
            })
    }

    fn resolve_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        self.resolve_routed_frame_batch(requests, true)
    }

    fn resolve_base_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        self.resolve_routed_frame_batch(requests, false)
    }
}

impl<O> PerfSymbolResolver<O>
where
    O: SymbolResolver,
{
    fn resolve_routed_frame_batch(
        &self,
        requests: &[SymbolRequest],
        inline: bool,
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        let mut resolved = vec![ResolvedSymbolFrames::default(); requests.len()];
        let mut kernel_elf_requests = SmallVec::<[SymbolRequest; 16]>::new();
        let mut kernel_elf_indexes = RequestIndexes::new();
        let mut user_requests = SmallVec::<[SymbolRequest; 16]>::new();
        let mut user_indexes = RequestIndexes::new();
        let mut address_cache = self
            .address_cache
            .lock()
            .expect("object address cache lock");

        for (index, request) in requests.iter().enumerate() {
            if is_kernel_module_symbol_path(&request.path) {
                if let Some(object_request) =
                    self.cached_object_symbol_request(request, &mut address_cache)
                {
                    user_indexes.push(index);
                    user_requests.push(object_request);
                } else if let Some(symbol) = self.resolve_kernel_symbol(request) {
                    resolved[index] = ResolvedSymbolFrames::from_frames(vec![symbol]);
                }
            } else if is_kernel_symbol_path(&request.path) {
                if let Some(symbol) = self.resolve_kernel_symbol(request) {
                    resolved[index] = ResolvedSymbolFrames::from_frames(vec![symbol]);
                } else if let Some(kernel_elf) = self.kernel_elf_ref() {
                    kernel_elf_indexes.push(index);
                    kernel_elf_requests.push(clean_object_symbol_request_with_cache(
                        kernel_elf.clone(),
                        request.relative_address,
                        &mut address_cache,
                    ));
                }
            } else {
                let object_request = self.object_symbol_request(request, &mut address_cache);
                user_indexes.push(index);
                user_requests.push(object_request);
            }
        }

        drop(address_cache);
        if !kernel_elf_requests.is_empty() {
            let kernel_frames = self.resolve_object_frame_batch(&kernel_elf_requests, inline)?;
            for (index, mut frames) in kernel_elf_indexes.into_iter().zip(kernel_frames) {
                frames.source_state = SymbolSourceState::AddressDependent;
                resolved[index] = frames;
            }
        }

        if !user_requests.is_empty() {
            let user_frames = self.resolve_object_frame_batch(&user_requests, inline)?;
            for (index, frames) in user_indexes.into_iter().zip(user_frames) {
                let module = is_kernel_module_symbol_path(&requests[index].path);
                let mut frames = if frames.frames.is_empty() && module {
                    self.resolve_kernel_symbol(&requests[index])
                        .map(|symbol| ResolvedSymbolFrames::from_frames(vec![symbol]))
                        .unwrap_or(frames)
                } else {
                    frames
                };
                // A missing module ELF does not rule out its kallsyms source.
                if module {
                    frames.source_state = SymbolSourceState::AddressDependent;
                }
                resolved[index] = frames;
            }
        }
        Ok(resolved)
    }

    fn resolve_object_frame_batch(
        &self,
        requests: &[SymbolRequest],
        inline: bool,
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        if inline {
            self.object_resolver
                .resolve_frame_batch_with_metadata(requests)
        } else {
            self.object_resolver
                .resolve_base_frame_batch_with_metadata(requests)
        }
    }

    fn object_symbol_request(
        &self,
        request: &SymbolRequest,
        address_cache: &mut ObjectAddressCache,
    ) -> SymbolRequest {
        self.cached_object_symbol_request(request, address_cache)
            .or_else(|| self.live_vdso_symbol_request(request, address_cache))
            .unwrap_or_else(|| Self::live_object_symbol_request(request, address_cache))
    }

    fn cached_object_symbol_request(
        &self,
        request: &SymbolRequest,
        address_cache: &mut ObjectAddressCache,
    ) -> Option<SymbolRequest> {
        let debug_dir = self.debug_dir.as_ref()?;
        let build_id = request.build_id.as_ref()?;
        let elf = perf_build_id_elf_path_for_dso(debug_dir, &request.path, build_id);
        elf.exists().then(|| {
            clean_object_symbol_request_with_cache(elf, request.relative_address, address_cache)
        })
    }

    fn live_object_symbol_request(
        request: &SymbolRequest,
        address_cache: &mut ObjectAddressCache,
    ) -> SymbolRequest {
        // perf's __report_module reports the live DSO path (or build-id path)
        // without rejecting it for recorded dev/inode drift.
        clean_object_symbol_request_with_cache(
            request.path.clone(),
            request.relative_address,
            address_cache,
        )
    }

    fn live_vdso_symbol_request(
        &self,
        request: &SymbolRequest,
        address_cache: &mut ObjectAddressCache,
    ) -> Option<SymbolRequest> {
        // perf map.c:map__new uses vdso.h:is_vdso_map, which accepts only
        // "[vdso]". Compat DSO names do not identify this process's vDSO.
        // Build-id cached compat images are handled before this fallback.
        if request.path != Path::new("[vdso]") {
            return None;
        }
        let live_vdso = self
            .live_vdso_elf_cache
            .get_or_init(copy_live_vdso_elf_like_perf)
            .as_ref()?;
        Some(clean_object_symbol_request_with_cache(
            live_vdso.path.clone(),
            request.relative_address,
            address_cache,
        ))
    }

    fn live_kallsyms_ref(&self) -> Option<&Kallsyms> {
        self.live_kallsyms.as_ref().or_else(|| {
            self.live_kallsyms_cache
                .get_or_init(|| {
                    self.live_kallsyms_path.as_ref().and_then(|path| {
                        std::fs::read_to_string(path)
                            .ok()
                            .and_then(|text| Kallsyms::parse(&text).ok())
                    })
                })
                .as_ref()
        })
    }

    fn live_module_kallsyms_for_path(&self, module_path: &str) -> Option<Arc<Kallsyms>> {
        if !is_kernel_module_symbol_path_str(module_path) {
            return None;
        }
        self.live_module_kallsyms_cache
            .get_or_init(|| {
                self.live_kallsyms_path
                    .as_ref()
                    .and_then(|path| std::fs::read_to_string(path).ok())
                    .map(|text| Kallsyms::parse_module_views(&text))
                    .unwrap_or_default()
            })
            .get(module_path)
            .cloned()
    }

    fn system_map_kallsyms_ref(&self) -> Option<&Kallsyms> {
        self.system_map_kallsyms.as_ref().or_else(|| {
            self.system_map_kallsyms_cache
                .get_or_init(|| {
                    Kallsyms::load_first_system_map_candidate(
                        self.system_map_candidates.iter().cloned(),
                    )
                })
                .as_ref()
        })
    }

    fn resolve_kernel_symbol(&self, request: &SymbolRequest) -> Option<String> {
        if is_kernel_module_symbol_path(&request.path) {
            self.kallsyms_ref()
                .and_then(|kallsyms| resolve_module_kallsyms(kallsyms, request))
                .or_else(|| {
                    // tools/perf/util/symbol.c dso__find_kallsyms() does not
                    // reject /proc/kallsyms for kernel/module maps merely
                    // because the DSO has a build-id; after build-id/kcore
                    // attempts it falls through to machine->root_dir/proc/kallsyms.
                    self.live_kallsyms
                        .as_ref()
                        .and_then(|kallsyms| resolve_module_kallsyms(kallsyms, request))
                })
                .or_else(|| {
                    request
                        .path
                        .to_str()
                        .and_then(|module_path| self.live_module_kallsyms_for_path(module_path))
                        .and_then(|kallsyms| resolve_module_kallsyms(kallsyms.as_ref(), request))
                })
        } else {
            self.kallsyms_ref()
                .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request))
                .or_else(|| {
                    // tools/perf/util/symbol.c dso__find_kallsyms() tries the
                    // host/root /proc/kallsyms path before the final cached
                    // kallsyms fallback for host kernel maps.
                    self.live_kallsyms_ref()
                        .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request))
                })
                .or_else(|| {
                    if !self.can_use_system_kernel_symbols(request) {
                        return None;
                    }
                    self.system_map_kallsyms_ref()
                        .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request))
                })
        }
    }

    fn can_use_system_kernel_symbols(&self, request: &SymbolRequest) -> bool {
        // Safe to use system/live kernel symbols when either the perf.data
        // recorded no kernel build-id, the request is not for the core kernel,
        // or the running kernel's build-id matches the recorded one (the
        // recording machine: live /proc/kallsyms describes the same kernel).
        self.recorded_kernel_build_id_ref().is_none()
            || request.path != Path::new("[kernel.kallsyms]")
            || self.live_kernel_matches_recorded()
    }
}

#[cfg(test)]
fn clean_object_symbol_request(path: PathBuf, relative_address: u64) -> SymbolRequest {
    let mut address_cache = ObjectAddressCache::default();
    clean_object_symbol_request_with_cache(path, relative_address, &mut address_cache)
}

fn clean_object_symbol_request_with_cache(
    path: PathBuf,
    relative_address: u64,
    address_cache: &mut ObjectAddressCache,
) -> SymbolRequest {
    let relative_address =
        object_virtual_address_for_file_offset_cached(&path, relative_address, address_cache)
            .unwrap_or(relative_address);
    SymbolRequest {
        path,
        relative_address,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    }
}

fn object_virtual_address_for_file_offset_cached(
    path: &Path,
    file_offset: u64,
    address_cache: &mut ObjectAddressCache,
) -> Option<u64> {
    let segments = match address_cache
        .segments_by_path
        .raw_entry_mut()
        .from_key(path.as_os_str())
    {
        RawEntryMut::Occupied(entry) => entry.into_mut(),
        RawEntryMut::Vacant(entry) => {
            let segments = object_load_segment_ranges(path);
            entry.insert(path.as_os_str().to_owned(), segments).1
        }
    };
    segments.as_ref()?.iter().find_map(|segment| {
        (file_offset >= segment.file_offset && file_offset < segment.file_end)
            .then(|| segment.virtual_address + (file_offset - segment.file_offset))
    })
}

fn object_load_segment_ranges(path: &Path) -> Option<Vec<ObjectSegmentRange>> {
    let bytes = std::fs::read(path).ok()?;
    let object = object::File::parse(bytes.as_slice()).ok()?;
    let segments = object
        .segments()
        .filter_map(|segment| {
            let (file_offset, file_size) = segment.file_range();
            Some(ObjectSegmentRange {
                file_offset,
                file_end: file_offset.checked_add(file_size)?,
                virtual_address: segment.address(),
            })
        })
        .collect::<Vec<_>>();
    (!segments.is_empty()).then_some(segments)
}

impl<R> SymbolResolver for Addr2lineResolver<'_, R>
where
    R: CommandRunner,
{
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        let mut resolved = vec![None; requests.len()];
        for (path, indexes) in grouped_request_indexes(requests) {
            let path = Path::new(path);
            let symbols = self.resolve_group_symbols(path, requests, &indexes)?;
            let object_metadata = self.object_metadata(path);
            for (index, symbol) in indexes.into_iter().zip(symbols) {
                let request = &requests[index];
                let object_symbol = object_metadata.as_ref().and_then(|metadata| {
                    metadata
                        .object_metadata
                        .object_symbol(request.relative_address)
                });
                let symbol = perf_name_with_object_alias(symbol, object_symbol);
                resolved[index] = symbol;
            }
        }
        Ok(resolved)
    }

    fn resolve_frame_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
        self.resolve_frame_batch_with_metadata(requests)
            .map(|resolved| {
                resolved
                    .into_iter()
                    .map(|resolved| resolved.frames)
                    .collect()
            })
    }

    fn resolve_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        let mut resolved = vec![ResolvedSymbolFrames::default(); requests.len()];
        for (path, indexes) in grouped_request_indexes(requests) {
            let path = Path::new(path);
            let object_metadata = self.object_metadata(path);
            if object_source_state(object_metadata.as_deref()) == SymbolSourceState::Unavailable {
                for index in indexes {
                    resolved[index].source_state = SymbolSourceState::Unavailable;
                }
                continue;
            }
            let object_symbols = object_metadata
                .as_ref()
                .map_or_else(SmallVec::new, |metadata| {
                    prepare_inline_object_symbols(metadata, requests, &indexes)
                });
            for (index, object_symbols) in indexes.into_iter().zip(object_symbols) {
                let request = &requests[index];
                let object_symbol = object_symbols.bare;
                let has_base_symbol = object_symbol.is_some();
                let (mut frames, has_inline_frames, has_non_inline_base_frame) =
                    if let Some(object_symbol) = object_symbol {
                        object_metadata
                            .as_ref()
                            .and_then(|metadata| {
                                metadata.dwarf_frame_names_for_base_symbol(
                                    request.relative_address,
                                    Some(object_symbol),
                                )
                            })
                            .map_or_else(
                                || (vec![object_symbol.to_string()], false, true),
                                |dwarf_frames| {
                                    let has_non_inline_base_frame = dwarf_frames
                                        .frames
                                        .iter()
                                        .any(|frame| frame == object_symbol);
                                    (
                                        perf_inline_frame_order(dwarf_frames.frames),
                                        dwarf_frames.has_inline_frames,
                                        has_non_inline_base_frame,
                                    )
                                },
                            )
                    } else {
                        // perf util/machine.c:append_inlines requires a base
                        // symbol before calling either addr2line backend.
                        (Vec::new(), false, false)
                    };
                frames = perf_frames_with_object_alias_and_offset(
                    frames,
                    object_symbol,
                    object_symbols.offset,
                    has_inline_frames,
                );
                resolved[index] = ResolvedSymbolFrames {
                    frames,
                    source_state: SymbolSourceState::AddressDependent,
                    has_base_symbol,
                    has_inline_frames,
                    has_non_inline_base_frame,
                    base_offset: object_symbols.offset,
                };
            }
        }
        Ok(resolved)
    }

    fn resolve_base_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        Ok(resolve_base_frames_from_object_metadata(requests, |path| {
            self.object_metadata(path)
        }))
    }
}

impl<R> SymbolResolver for SelectedObjectResolver<'_, R>
where
    R: CommandRunner,
{
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        match self {
            Self::Addr2line(resolver) => resolver.resolve_batch(requests),
            Self::RustAddr2line(resolver) => resolver.resolve_batch(requests),
        }
    }

    fn resolve_frame_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
        match self {
            Self::Addr2line(resolver) => resolver.resolve_frame_batch(requests),
            Self::RustAddr2line(resolver) => resolver.resolve_frame_batch(requests),
        }
    }

    fn resolve_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        match self {
            Self::Addr2line(resolver) => resolver.resolve_frame_batch_with_metadata(requests),
            Self::RustAddr2line(resolver) => resolver.resolve_frame_batch_with_metadata(requests),
        }
    }

    fn resolve_base_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        match self {
            Self::Addr2line(resolver) => resolver.resolve_base_frame_batch_with_metadata(requests),
            Self::RustAddr2line(resolver) => {
                resolver.resolve_base_frame_batch_with_metadata(requests)
            }
        }
    }
}

impl SymbolResolver for RustAddr2lineResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        let mut resolved = vec![None; requests.len()];
        for (path, indexes) in grouped_request_indexes(requests) {
            let path = Path::new(path);
            let Ok(loader) = addr2line::Loader::new(path) else {
                continue;
            };
            let object_metadata = self.object_metadata(path);
            for index in indexes {
                let request = &requests[index];
                let object_symbol = object_metadata.as_ref().and_then(|metadata| {
                    metadata
                        .object_metadata
                        .object_symbol(request.relative_address)
                });
                let symbol = loader
                    .find_symbol(request.relative_address)
                    .map(demangle_addr2line_name_qualified)
                    .or_else(|| rust_addr2line_frame_name(&loader, request.relative_address));
                resolved[index] = perf_name_with_object_alias(symbol, object_symbol);
            }
        }
        Ok(resolved)
    }

    fn resolve_frame_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
        self.resolve_frame_batch_with_metadata(requests)
            .map(|resolved| {
                resolved
                    .into_iter()
                    .map(|resolved| resolved.frames)
                    .collect()
            })
    }

    fn resolve_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        let mut resolved = vec![ResolvedSymbolFrames::default(); requests.len()];
        for (path, indexes) in grouped_request_indexes(requests) {
            let path = Path::new(path);
            let object_metadata = self.object_metadata(path);
            if object_source_state(object_metadata.as_deref()) == SymbolSourceState::Unavailable {
                for index in indexes {
                    resolved[index].source_state = SymbolSourceState::Unavailable;
                }
                continue;
            }
            let object_symbols = object_metadata
                .as_ref()
                .map_or_else(SmallVec::new, |metadata| {
                    prepare_inline_object_symbols(metadata, requests, &indexes)
                });
            for (index, object_symbols) in indexes.into_iter().zip(object_symbols) {
                let request = &requests[index];
                let address = request.relative_address;
                let object_symbol = object_symbols.bare;
                let has_base_symbol = object_symbol.is_some();
                let (mut frames, has_inline_frames, has_non_inline_base_frame) =
                    if let Some(object_symbol) = object_symbol {
                        object_metadata
                            .as_ref()
                            .and_then(|metadata| {
                                metadata
                                    .dwarf_frame_names_for_base_symbol(address, Some(object_symbol))
                            })
                            .map_or_else(
                                || {
                                    let record_name = object_metadata
                                        .as_ref()
                                        .filter(|metadata| {
                                            !metadata.dwarf_has_source_line_for_address(address)
                                        })
                                        .and_then(|metadata| {
                                            metadata
                                                .object_metadata
                                                .bfd_function_record_name(address)
                                        })
                                        .filter(|record_name| *record_name != object_symbol);
                                    record_name.map_or_else(
                                        || (vec![object_symbol.to_string()], false, true),
                                        |record_name| (vec![record_name.to_string()], true, false),
                                    )
                                },
                                |dwarf_frames| {
                                    let has_non_inline_base_frame = dwarf_frames
                                        .frames
                                        .iter()
                                        .any(|frame| frame == object_symbol);
                                    (
                                        perf_inline_frame_order(dwarf_frames.frames),
                                        dwarf_frames.has_inline_frames,
                                        has_non_inline_base_frame,
                                    )
                                },
                            )
                    } else {
                        // perf util/machine.c:append_inlines never calls
                        // libdw/addr2line without an eligible base symbol.
                        (Vec::new(), false, false)
                    };
                frames = perf_frames_with_object_alias_and_offset(
                    frames,
                    object_symbol,
                    object_symbols.offset,
                    has_inline_frames,
                );
                // No .debug_str generic specialization here: inline-frame names
                // already follow perf's libdw `dwarf_diename` path. Rewriting
                // them again can invent spellings perf never printed.
                resolved[index] = ResolvedSymbolFrames {
                    frames,
                    source_state: SymbolSourceState::AddressDependent,
                    has_base_symbol,
                    has_inline_frames,
                    has_non_inline_base_frame,
                    base_offset: object_symbols.offset,
                };
            }
        }
        Ok(resolved)
    }

    fn resolve_base_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        Ok(resolve_base_frames_from_object_metadata(requests, |path| {
            self.object_metadata(path)
        }))
    }
}

fn object_source_state(metadata: Option<&CachedObjectMetadata>) -> SymbolSourceState {
    if metadata.is_none_or(|metadata| metadata.object_metadata.object_symbols.symbols.is_empty()) {
        SymbolSourceState::Unavailable
    } else {
        SymbolSourceState::AddressDependent
    }
}

fn prepare_inline_object_symbols<'a>(
    metadata: &'a CachedObjectMetadata,
    requests: &[SymbolRequest],
    indexes: &[usize],
) -> SmallVec<[PerfObjectSymbolNames<'a>; 16]> {
    let symbols: SmallVec<[PerfObjectSymbolNames<'a>; 16]> = indexes
        .iter()
        .map(|&index| {
            metadata
                .object_metadata
                .object_symbol_names(requests[index].relative_address)
        })
        .collect();
    // perf machine.c:append_inlines never calls libdw/addr2line for symbol gaps.
    let addresses: SmallVec<[u64; 16]> = indexes
        .iter()
        .zip(&symbols)
        .filter_map(|(&index, symbol)| symbol.bare.map(|_| requests[index].relative_address))
        .collect();
    if !addresses.is_empty() {
        metadata.prepare_dwarf_frames_for_addresses(&addresses);
    }
    symbols
}

fn resolve_base_frames_from_object_metadata(
    requests: &[SymbolRequest],
    object_metadata: impl Fn(&Path) -> Option<Arc<CachedObjectMetadata>>,
) -> Vec<ResolvedSymbolFrames> {
    let mut resolved = vec![ResolvedSymbolFrames::default(); requests.len()];
    for (path, indexes) in grouped_request_indexes(requests) {
        let path = Path::new(path);
        let metadata = object_metadata(path);
        if object_source_state(metadata.as_deref()) == SymbolSourceState::Unavailable {
            for index in indexes {
                resolved[index].source_state = SymbolSourceState::Unavailable;
            }
            continue;
        }
        for index in indexes {
            let request = &requests[index];
            let object_symbols =
                object_symbols_for_frame(metadata.as_ref(), request.relative_address);
            let Some(object_symbol) = object_symbols.bare else {
                continue;
            };
            let mut frames = vec![object_symbol.to_string()];
            frames = perf_frames_with_object_alias_and_offset(
                frames,
                Some(object_symbol),
                object_symbols.offset,
                false,
            );
            // perf's event-line IP path is machine__resolve() -> map__find_symbol()
            // -> __symbol__fprintf_symname_offs(); it uses the demangled ELF
            // symtab name and does not replace it with a DWARF debug-string
            // leaf name.
            resolved[index] = ResolvedSymbolFrames {
                frames,
                source_state: SymbolSourceState::AddressDependent,
                has_base_symbol: true,
                has_inline_frames: false,
                has_non_inline_base_frame: true,
                // The no-inline base path bakes +0x<off> into the single frame
                // name via with_offset, so no separate per-line offset is used.
                base_offset: object_symbols.offset,
            };
        }
    }
    resolved
}

/// Demangles a mangled (linkage) symbol the way perf's external-addr2line
/// srcline backend does: fully qualified, no trailing `::h<hash>`, generic
/// args preserved (`dso__demangle_sym` ->
/// `rust_demangle_display_demangle(..., /*alternate=*/true)`).
fn demangle_addr2line_name_qualified(name: &str) -> String {
    addr2line::demangle_auto(Cow::Borrowed(name), None).into_owned()
}

fn perf_name_with_object_alias(name: Option<String>, object_alias: Option<&str>) -> Option<String> {
    match (name, object_alias) {
        (Some(name), Some(object_alias))
            if perf_object_alias_improves_name(&name, object_alias) =>
        {
            Some(object_alias.to_string())
        }
        (Some(name), _) => Some(name),
        (None, object_alias) => object_alias.map(str::to_string),
    }
}

fn perf_frames_with_object_alias(
    mut frames: Vec<String>,
    object_alias: Option<&str>,
) -> Vec<String> {
    if frames.len() == 1
        && let Some(alias) = object_alias
    {
        frames[0] = alias.to_string();
    }
    frames
}

fn perf_frames_with_object_alias_and_offset(
    frames: Vec<String>,
    object_alias: Option<&str>,
    object_alias_offset: Option<u64>,
    has_inline_frames: bool,
) -> Vec<String> {
    if has_inline_frames {
        return frames;
    }
    let mut frames = perf_frames_with_object_alias(frames, object_alias);
    if frames.len() == 1
        && let Some(alias) = object_alias
        && let Some(offset) = object_alias_offset
    {
        frames[0] = format!("{alias}+0x{offset:x}");
    }
    frames
}

fn object_symbols_for_frame(
    metadata: Option<&Arc<CachedObjectMetadata>>,
    address: u64,
) -> PerfObjectSymbolNames<'_> {
    metadata.map_or_else(PerfObjectSymbolNames::default, |metadata| {
        metadata.object_metadata.object_symbol_names(address)
    })
}

fn perf_object_alias_improves_name(name: &str, object_alias: &str) -> bool {
    leading_underscore_count(object_alias) < leading_underscore_count(name)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PerfSymbolCandidate {
    name: String,
    address: u64,
    size: u64,
    bfd_size: u64,
    elf_type: Option<u8>,
    scope: PerfSymbolScope,
    binding: PerfSymbolBinding,
    bfd_function_like: bool,
    bfd_function: bool,
    bfd_has_filename: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PerfSymbolScope {
    Global,
    Local,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PerfSymbolBinding {
    Global,
    Weak,
}

fn perf_symbol_is_candidate(object: &object::File<'_>, symbol: &object::Symbol<'_, '_>) -> bool {
    if symbol.is_undefined() || symbol.name().unwrap_or_default().is_empty() {
        return false;
    }
    let object::SymbolFlags::Elf { st_info, st_other } = symbol.flags() else {
        return matches!(
            symbol.kind(),
            SymbolKind::Text | SymbolKind::Data | SymbolKind::Label | SymbolKind::Unknown
        );
    };
    // perf rejects mapping markers before inserting them into the symbol tree.
    let name = symbol.name().unwrap_or_default().as_bytes();
    if let [b'$', marker, suffix @ ..] = name {
        let is_mapping_marker = match object.architecture() {
            object::Architecture::Arm | object::Architecture::Aarch64 => {
                matches!(marker, b'a' | b'd' | b't' | b'x')
                    && (suffix.is_empty() || suffix.first() == Some(&b'.'))
            }
            object::Architecture::Riscv32 | object::Architecture::Riscv64 => {
                matches!(marker, b'd' | b'x')
            }
            _ => false,
        };
        if is_mapping_marker {
            return false;
        }
    }
    // perf util/symbol-elf.c:elf_sym__is_label/elf_sym__filter and dso__load_sym:
    // FUNC/IFUNC/OBJECT may be hidden, but NOTYPE labels may not. All require
    // an allocated section; labels additionally need a text/data section name.
    let symbol_type = st_info & 0xf;
    match symbol_type {
        object::elf::STT_FUNC | object::elf::STT_GNU_IFUNC | object::elf::STT_OBJECT => {}
        object::elf::STT_NOTYPE
            if !matches!(
                st_other & 3,
                object::elf::STV_HIDDEN | object::elf::STV_INTERNAL
            ) => {}
        _ => return false,
    }
    let Some(section) = symbol
        .section_index()
        .and_then(|index| object.section_by_index(index).ok())
    else {
        return false;
    };
    let object::SectionFlags::Elf { sh_flags } = section.flags() else {
        return false;
    };
    sh_flags & u64::from(object::elf::SHF_ALLOC) != 0
        && (symbol_type != object::elf::STT_NOTYPE
            || section
                .name()
                .is_ok_and(|name| name.contains("text") || name.contains("data")))
}

fn perf_symbol_candidate_search_end(candidate: &PerfSymbolCandidate) -> u64 {
    candidate.address.saturating_add(if candidate.size == 0 {
        1
    } else {
        candidate.size
    })
}

fn perf_symbol_candidate_contains_address(candidate: &PerfSymbolCandidate, address: u64) -> bool {
    if candidate.size == 0 {
        candidate.address == address
    } else {
        address >= candidate.address && address < candidate.address.saturating_add(candidate.size)
    }
}

fn perf_best_duplicate_symbol<'a>(
    current: &'a PerfSymbolCandidate,
    candidate: &'a PerfSymbolCandidate,
) -> &'a PerfSymbolCandidate {
    // tools/perf/util/symbol.c choose_best_symbol(): size, typed, non-weak,
    // global, fewer leading underscores, then longest name.
    if current.size == 0 && candidate.size > 0 {
        return candidate;
    }
    if candidate.size == 0 && current.size > 0 {
        return current;
    }
    if let (Some(current_type), Some(candidate_type)) = (current.elf_type, candidate.elf_type)
        && current_type != candidate_type
    {
        if current_type == object::elf::STT_NOTYPE {
            return candidate;
        }
        if candidate_type == object::elf::STT_NOTYPE {
            return current;
        }
    }
    if candidate.binding == PerfSymbolBinding::Weak && current.binding != PerfSymbolBinding::Weak {
        return current;
    }
    if current.binding == PerfSymbolBinding::Weak && candidate.binding != PerfSymbolBinding::Weak {
        return candidate;
    }
    if current.scope == PerfSymbolScope::Global && candidate.scope != PerfSymbolScope::Global {
        return current;
    }
    if candidate.scope == PerfSymbolScope::Global && current.scope != PerfSymbolScope::Global {
        return candidate;
    }
    let current_underscores = leading_underscore_count(&current.name);
    let candidate_underscores = leading_underscore_count(&candidate.name);
    if candidate_underscores > current_underscores {
        return current;
    }
    if current_underscores > candidate_underscores {
        return candidate;
    }
    if current.name.len() >= candidate.name.len() {
        current
    } else {
        candidate
    }
}

fn leading_underscore_count(name: &str) -> usize {
    name.bytes().take_while(|byte| *byte == b'_').count()
}

impl PreparedObjectMetadata {
    fn from_object_bytes(object_bytes: &[u8]) -> Self {
        Self {
            object_symbols: PerfObjectSymbolIndex::from_object_bytes(object_bytes),
        }
    }

    fn object_symbol(&self, address: u64) -> Option<&str> {
        self.object_symbols.symbol_name(address)
    }

    fn object_symbol_names(&self, address: u64) -> PerfObjectSymbolNames<'_> {
        self.object_symbols
            .symbol(address)
            .map_or_else(PerfObjectSymbolNames::default, |symbol| {
                PerfObjectSymbolNames {
                    bare: Some(&symbol.name),
                    offset: Some(address.saturating_sub(symbol.address)),
                }
            })
    }

    fn bfd_function_record_name(&self, address: u64) -> Option<&str> {
        self.object_symbols.bfd_function_record_name(address)
    }
}

impl PerfObjectSymbolIndex {
    fn from_object_bytes(object_bytes: &[u8]) -> Self {
        let Ok(object) = object::File::parse(object_bytes) else {
            return Self::default();
        };
        let mut symbols =
            Vec::with_capacity(object.symbols().count() + object.dynamic_symbols().count());
        // bfd/dwarf2.c _bfd_elf_find_function() assigns the last STT_FILE
        // name to eligible function symbols while scanning the symtab.
        let (mut file_seen, mut symbol_seen, mut file_after_symbol) = (false, false, false);
        for symbol in object.symbols() {
            if symbol.kind() == SymbolKind::File {
                file_seen = true;
                file_after_symbol |= symbol_seen;
                continue;
            }
            symbol_seen = true;
            if let Some(mut candidate) = perf_symbol_candidate_from_object_symbol(&object, &symbol)
            {
                candidate.bfd_has_filename = file_seen
                    && (symbol.scope() == object::SymbolScope::Compilation || !file_after_symbol);
                symbols.push(candidate);
            }
        }
        symbols.extend(
            object
                .dynamic_symbols()
                .filter_map(|symbol| perf_symbol_candidate_from_object_symbol(&object, &symbol)),
        );
        symbols.extend(perf_synthesized_plt_symbols(&object, &symbols));
        symbols.sort_by_key(|symbol| symbol.address);
        fixup_object_symbol_ends_like_perf(&mut symbols);
        let mut max_end = 0_u64;
        let max_end_by_index = symbols
            .iter()
            .map(|symbol| {
                max_end = max_end.max(perf_symbol_candidate_search_end(symbol));
                max_end
            })
            .collect();
        Self {
            symbols,
            max_end_by_index,
        }
    }

    fn symbol_name(&self, address: u64) -> Option<&str> {
        self.symbol(address)
            .map(|candidate| candidate.name.as_str())
    }

    fn bfd_function_record_name(&self, address: u64) -> Option<&str> {
        self.bfd_function_record_symbol(address)
            .filter(|candidate| candidate.bfd_has_filename)
            .map(|candidate| candidate.name.as_str())
    }

    #[cfg(test)]
    fn symbol_name_with_offset(&self, address: u64) -> Option<String> {
        let candidate = self.symbol(address)?;
        let offset = address.saturating_sub(candidate.address);
        Some(format!("{}+0x{offset:x}", candidate.name))
    }

    fn symbol(&self, address: u64) -> Option<&PerfSymbolCandidate> {
        let mut index = self
            .symbols
            .partition_point(|candidate| candidate.address <= address);
        let mut best = None::<&PerfSymbolCandidate>;
        while index > 0 {
            index -= 1;
            if self.max_end_by_index[index] <= address {
                break;
            }
            let mut candidate = &self.symbols[index];
            // perf symbol.c:symbols__fixup_duplicate selects the winner
            // before address lookup, not only among aliases covering the IP.
            // Keep the raw candidates for BFD's independent function lookup.
            while index > 0 && self.symbols[index - 1].address == candidate.address {
                index -= 1;
                // In-order perf insertion prefers the earlier alias on ties.
                candidate = perf_best_duplicate_symbol(&self.symbols[index], candidate);
            }
            if !perf_symbol_candidate_contains_address(candidate, address) {
                continue;
            }
            best = Some(match best {
                Some(current) if current.address > candidate.address => current,
                _ => candidate,
            });
        }
        best
    }

    fn bfd_function_record_symbol(&self, address: u64) -> Option<&PerfSymbolCandidate> {
        // binutils-gdb bfd/dwarf2.c _bfd_elf_find_function() walks BFD's
        // canonical symbol array and applies better_fit(). bfd/elf.c sorts
        // that array with local symbols before globals, so equal-start/equal-
        // size aliases keep the earlier local entry rather than perf's normal
        // choose_best_symbol() global preference.
        let end = self
            .symbols
            .partition_point(|candidate| candidate.address <= address);
        let mut best = None::<&PerfSymbolCandidate>;
        for candidate in &self.symbols[..end] {
            if !candidate.bfd_function_like {
                continue;
            }
            best = Some(match best {
                Some(current) if !bfd_function_record_better_fit(current, candidate, address) => {
                    current
                }
                _ => candidate,
            });
        }
        best
    }
}

fn bfd_function_record_size(candidate: &PerfSymbolCandidate) -> u64 {
    // bfd/elf.c:_bfd_elf_maybe_function_sym reads the unmodified ELF size,
    // treating zero (including synthetic symbols) as one. Perf's end fixup
    // must affect only candidate.size, not BFD's independent lookup extent.
    candidate.bfd_size.max(1)
}

fn bfd_function_record_better_fit(
    current: &PerfSymbolCandidate,
    candidate: &PerfSymbolCandidate,
    address: u64,
) -> bool {
    // Mirrors binutils-gdb bfd/dwarf2.c better_fit() for the tie-breakers we
    // can represent from object::Symbol data: closest start, covering range,
    // function over non-function, then smaller range. BFD's final equal case
    // returns false, preserving the earlier canonical symbol.
    if candidate.address > address {
        return false;
    }
    if candidate.address < current.address {
        return false;
    }
    if candidate.address > current.address {
        return true;
    }

    let current_size = bfd_function_record_size(current);
    let candidate_size = bfd_function_record_size(candidate);
    if current.address.saturating_add(current_size) <= address {
        return candidate_size > current_size;
    }
    if candidate.address.saturating_add(candidate_size) <= address {
        return false;
    }
    if current.bfd_function && !candidate.bfd_function {
        return false;
    }
    if candidate.bfd_function && !current.bfd_function {
        return true;
    }
    candidate_size < current_size
}

fn fixup_object_symbol_ends_like_perf(symbols: &mut [PerfSymbolCandidate]) {
    // tools/perf/util/symbol-elf.c dso__load_sym_internal() and libbfd.c
    // bfd2elf__load_symbols() call symbols__fixup_end(..., false) before
    // duplicate cleanup, extending zero-sized ASM labels to the next symbol.
    for index in 1..symbols.len() {
        let current_address = symbols[index].address;
        let previous = &mut symbols[index - 1];
        if previous.size == 0 {
            previous.size = current_address.saturating_sub(previous.address);
        }
    }
    if let Some(last) = symbols.last_mut()
        && last.size == 0
    {
        last.size = round_up_to_page(last.address)
            .saturating_add(4096)
            .saturating_sub(last.address);
    }
}

fn perf_synthesized_plt_symbols(
    object: &object::File<'_>,
    base_symbols: &[PerfSymbolCandidate],
) -> Vec<PerfSymbolCandidate> {
    if object.architecture() != object::Architecture::X86_64 {
        return Vec::new();
    }
    let Some(plt) = object.section_by_name(".plt") else {
        return Vec::new();
    };
    let Some((plt_sec_offset, lazy_plt)) = object
        .section_by_name(".plt.sec")
        .and_then(|section| section.file_range().map(|(offset, _)| (offset, false)))
        .or_else(|| {
            let (offset, size) = plt.file_range()?;
            let has_header = perf_x86_64_plt_relocations(object).is_none_or(|relocations| {
                u64::try_from(relocations.len())
                    .map_or(true, |len| len * X86_64_PLT_ENTRY_SIZE != size)
            });
            Some((offset + u64::from(has_header) * X86_64_PLT_ENTRY_SIZE, true))
        })
    else {
        return Vec::new();
    };

    let Some(mut relocations) = perf_x86_64_plt_relocations(object) else {
        return Vec::new();
    };
    relocations.sort_by_key(|relocation| relocation.offset);

    let mut plt_offset = plt_sec_offset;
    let mut symbols = Vec::with_capacity(relocations.len() + usize::from(lazy_plt));
    if lazy_plt {
        symbols.push(PerfSymbolCandidate {
            name: ".plt".to_string(),
            address: plt.file_range().map_or(plt.address(), |(offset, _)| offset),
            size: X86_64_PLT_ENTRY_SIZE,
            bfd_size: 0,
            elf_type: Some(object::elf::STT_FUNC),
            scope: PerfSymbolScope::Global,
            binding: PerfSymbolBinding::Global,
            bfd_function_like: true,
            bfd_function: true,
            bfd_has_filename: false,
        });
    }
    for relocation in relocations {
        let name = relocation
            .symbol_name
            .filter(|name| !name.is_empty())
            .map(|name| format!("{name}@plt"))
            .or_else(|| {
                relocation
                    .ifunc_addend
                    .and_then(|addend| perf_best_symbol_at(base_symbols, addend))
                    .map(|symbol| format!("{}@plt", symbol.name))
            })
            .unwrap_or_else(|| format!("offset_{plt_offset:#x}@plt"));
        symbols.push(PerfSymbolCandidate {
            name,
            address: plt_offset,
            size: X86_64_PLT_ENTRY_SIZE,
            bfd_size: 0,
            elf_type: Some(object::elf::STT_FUNC),
            scope: PerfSymbolScope::Global,
            binding: PerfSymbolBinding::Global,
            bfd_function_like: true,
            bfd_function: true,
            bfd_has_filename: false,
        });
        plt_offset += X86_64_PLT_ENTRY_SIZE;
    }
    symbols
}

struct PerfPltRelocation {
    offset: u64,
    symbol_name: Option<String>,
    ifunc_addend: Option<u64>,
}

fn perf_x86_64_plt_relocations(object: &object::File<'_>) -> Option<Vec<PerfPltRelocation>> {
    let dynamic_symbols = object.dynamic_symbol_table()?;
    let rela_plt = object.section_by_name(".rela.plt")?.data().ok()?;
    let relocations = rela_plt
        .as_chunks::<ELF64_RELA_ENTRY_SIZE>()
        .0
        .iter()
        .filter_map(parse_elf64_rela_entry)
        .filter_map(|rela| perf_x86_64_plt_relocation_from_rela(&dynamic_symbols, rela))
        .collect::<Vec<_>>();
    (!relocations.is_empty()).then_some(relocations)
}

#[derive(Clone, Copy)]
struct Elf64RelaEntry {
    offset: u64,
    symbol_index: usize,
    relocation_type: u32,
    addend: i64,
}

fn parse_elf64_rela_entry(entry: &[u8; ELF64_RELA_ENTRY_SIZE]) -> Option<Elf64RelaEntry> {
    let offset = u64::from_le_bytes(entry[0..8].try_into().ok()?);
    let info = u64::from_le_bytes(entry[8..16].try_into().ok()?);
    let addend = i64::from_le_bytes(entry[16..24].try_into().ok()?);
    Some(Elf64RelaEntry {
        offset,
        symbol_index: usize::try_from(info >> 32).ok()?,
        relocation_type: u32::try_from(info & 0xffff_ffff).ok()?,
        addend,
    })
}

fn perf_x86_64_plt_relocation_from_rela<'data>(
    dynamic_symbols: &impl ObjectSymbolTable<'data>,
    rela: Elf64RelaEntry,
) -> Option<PerfPltRelocation> {
    match rela.relocation_type {
        object::elf::R_X86_64_JUMP_SLOT => dynamic_symbols
            .symbol_by_index(SymbolIndex(rela.symbol_index))
            .ok()
            .and_then(|symbol| symbol.name().ok())
            .map(|name| PerfPltRelocation {
                offset: rela.offset,
                symbol_name: Some(perf_symbol_name(&addr2line::demangle_auto(
                    Cow::Borrowed(name),
                    None,
                ))),
                ifunc_addend: None,
            }),
        object::elf::R_X86_64_IRELATIVE => {
            u64::try_from(rela.addend)
                .ok()
                .map(|addend| PerfPltRelocation {
                    offset: rela.offset,
                    symbol_name: None,
                    ifunc_addend: Some(addend),
                })
        }
        _ => None,
    }
}

fn perf_best_symbol_at(
    symbols: &[PerfSymbolCandidate],
    address: u64,
) -> Option<&PerfSymbolCandidate> {
    symbols
        .iter()
        .filter(|symbol| symbol.address == address)
        .reduce(perf_best_duplicate_symbol)
}

fn perf_symbol_candidate_from_object_symbol(
    object: &object::File<'_>,
    symbol: &object::Symbol<'_, '_>,
) -> Option<PerfSymbolCandidate> {
    let kind = symbol.kind();
    perf_symbol_is_candidate(object, symbol).then(|| PerfSymbolCandidate {
        name: perf_symbol_name(&addr2line::demangle_auto(
            Cow::Borrowed(symbol.name().unwrap_or_default()),
            None,
        )),
        address: symbol.address(),
        size: symbol.size(),
        bfd_size: symbol.size(),
        elf_type: match symbol.flags() {
            object::SymbolFlags::Elf { st_info, .. } => Some(st_info & 0xf),
            _ => None,
        },
        scope: if symbol.is_global() {
            PerfSymbolScope::Global
        } else {
            PerfSymbolScope::Local
        },
        binding: if symbol.is_weak() {
            PerfSymbolBinding::Weak
        } else {
            PerfSymbolBinding::Global
        },
        bfd_function_like: !matches!(kind, SymbolKind::Data),
        bfd_function: matches!(kind, SymbolKind::Text),
        bfd_has_filename: false,
    })
}

fn rust_addr2line_frame_name(loader: &addr2line::Loader, address: u64) -> Option<String> {
    rust_addr2line_frame_names(loader, address).and_then(|frames| frames.into_iter().last())
}

fn rust_addr2line_frame_names(loader: &addr2line::Loader, address: u64) -> Option<Vec<String>> {
    let mut frames = loader.find_frames(address).ok()?;
    let mut names = Vec::new();
    while let Ok(Some(frame)) = frames.next() {
        if let Some(function) = frame.function
            && let Ok(name) = function.demangle()
        {
            names.push(perf_dwarf_function_name(&name));
        }
    }
    (!names.is_empty()).then(|| perf_inline_frame_order(names))
}

#[must_use]
pub fn perf_dwarf_frame_names_from_object(path: &Path, address: u64) -> Option<Vec<String>> {
    let bytes = std::fs::read(path).ok()?;
    perf_dwarf_frame_names_from_object_bytes(&bytes, address)
}

#[must_use]
pub fn perf_dwarf_frame_names_from_object_bytes(bytes: &[u8], address: u64) -> Option<Vec<String>> {
    let base_symbol = PerfObjectSymbolIndex::from_object_bytes(bytes)
        .symbol_name(address)
        .map(str::to_string);
    PerfDwarfNameResolver::from_object_bytes_for_addresses(bytes, &[address])
        .ok()?
        .frame_names_for_base_symbol(address, base_symbol.as_deref())
        .map(|frames| frames.frames)
        .or(base_symbol.map(|symbol| vec![symbol]))
}

impl PerfDwarfNameResolver {
    fn from_object_bytes_for_addresses(
        bytes: &[u8],
        addresses: &[u64],
    ) -> Result<Self, gimli::Error> {
        Self::from_object_bytes_matching_addresses(bytes, Some(addresses))
    }

    fn from_object_bytes_matching_addresses(
        bytes: &[u8],
        addresses: Option<&[u64]>,
    ) -> Result<Self, gimli::Error> {
        let object = object::File::parse(bytes).map_err(|_| gimli::Error::Io)?;
        let endian = if object.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };
        let mut names = PerfDwarfNameInterner::default();
        let dwarf_sections = gimli::DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                object
                    .section_by_name(id.name())
                    .and_then(|section| section.uncompressed_data().ok())
                    .unwrap_or(Cow::Borrowed(&[][..])),
            )
        })?;
        let dwarf =
            dwarf_sections.borrow(|section| gimli::EndianSlice::new(section.as_ref(), endian));
        let mut units = Vec::new();
        let mut headers = dwarf.units();
        while let Ok(Some(header)) = headers.next() {
            let Ok(unit) = dwarf.unit(header) else {
                continue;
            };
            let ranges = perf_dwarf_ranges(dwarf.unit_ranges(&unit).ok());
            if let Some(addresses) = addresses
                && !perf_dwarf_unit_ranges_match_addresses(ranges.as_deref(), addresses)
            {
                continue;
            }
            let source_line_ranges = perf_dwarf_source_line_ranges(&unit);
            let roots = perf_dwarf_unit_roots(&dwarf, &unit, &mut names);
            units.push(PerfDwarfUnitIndex {
                ranges,
                segments: perf_dwarf_frame_ranges_from_roots(&roots, &source_line_ranges),
            });
        }
        Ok(Self {
            names: names.into_names(),
            units,
        })
    }

    fn frame_names_for_base_symbol(
        &self,
        address: u64,
        base_symbol: Option<&str>,
    ) -> Option<PerfDwarfFrameNames> {
        for unit in &self.units {
            if !perf_dwarf_unit_contains_address(unit, address) {
                continue;
            }
            if let Some(frames) =
                perf_dwarf_frame_names_from_index(&unit.segments, &self.names, address, base_symbol)
            {
                return Some(frames);
            }
        }
        None
    }
}

impl CachedObjectMetadata {
    /// Builds frame indexes for every DWARF unit covering `addresses` that has
    /// not been indexed by an earlier batch.
    fn prepare_dwarf_frames_for_addresses(&self, addresses: &[u64]) {
        let mut cache = self.dwarf_index.lock().expect("dwarf index cache lock");
        if cache.failed {
            return;
        }
        if let Some(units) = &cache.units {
            let needs_build = units.iter().any(|unit| {
                unit.segments.is_none()
                    && perf_dwarf_unit_ranges_match_addresses(unit.ranges.as_deref(), addresses)
            });
            if !needs_build {
                return;
            }
        }
        if build_dwarf_index_cache_for_addresses(&mut cache, &self.object_bytes, addresses).is_err()
        {
            cache.failed = true;
        }
    }

    /// Resolves the perf-style inline frame chain for one address from the
    /// units prepared by [`Self::prepare_dwarf_frames_for_addresses`].
    fn dwarf_frame_names_for_base_symbol(
        &self,
        address: u64,
        base_symbol: Option<&str>,
    ) -> Option<PerfDwarfFrameNames> {
        let cache = self.dwarf_index.lock().expect("dwarf index cache lock");
        for unit in cache.units.as_deref()? {
            let Some(segments) = &unit.segments else {
                continue;
            };
            if !unit
                .ranges
                .as_ref()
                .is_none_or(|ranges| perf_dwarf_ranges_contain(ranges, address))
            {
                continue;
            }
            if let Some(frames) = perf_dwarf_frame_names_from_index(
                segments,
                &cache.names.names,
                address,
                base_symbol,
            ) {
                return Some(frames);
            }
        }
        None
    }

    fn dwarf_has_source_line_for_address(&self, address: u64) -> bool {
        let cache = self.dwarf_index.lock().expect("dwarf index cache lock");
        cache.units.as_deref().is_some_and(|units| {
            units.iter().any(|unit| {
                unit.ranges
                    .as_ref()
                    .is_none_or(|ranges| perf_dwarf_ranges_contain(ranges, address))
                    && unit
                        .source_line_ranges
                        .as_deref()
                        .is_some_and(|ranges| perf_dwarf_ranges_contain(ranges, address))
            })
        })
    }
}

fn build_dwarf_index_cache_for_addresses(
    cache: &mut PerfDwarfIndexCache,
    bytes: &[u8],
    addresses: &[u64],
) -> Result<(), gimli::Error> {
    let object = object::File::parse(bytes).map_err(|_| gimli::Error::Io)?;
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let dwarf_sections = gimli::DwarfSections::load(|id| {
        Ok::<_, gimli::Error>(
            object
                .section_by_name(id.name())
                .and_then(|section| section.uncompressed_data().ok())
                .unwrap_or(Cow::Borrowed(&[][..])),
        )
    })?;
    let dwarf = dwarf_sections.borrow(|section| gimli::EndianSlice::new(section.as_ref(), endian));

    let scanning = cache.units.is_none();
    let mut units = cache.units.take().unwrap_or_default();
    let mut headers = dwarf.units();
    let mut ordinal = 0_usize;
    while let Ok(Some(header)) = headers.next() {
        let Ok(unit) = dwarf.unit(header) else {
            if scanning {
                units.push(PerfDwarfCachedUnit {
                    ranges: Some(Vec::new()),
                    source_line_ranges: Some(Vec::new()),
                    segments: Some(Vec::new()),
                });
            }
            ordinal += 1;
            continue;
        };
        if scanning {
            units.push(PerfDwarfCachedUnit {
                ranges: perf_dwarf_ranges(dwarf.unit_ranges(&unit).ok()),
                source_line_ranges: Some(perf_dwarf_source_line_ranges(&unit)),
                segments: None,
            });
        }
        let Some(cached_unit) = units.get_mut(ordinal) else {
            break;
        };
        if cached_unit.segments.is_none()
            && perf_dwarf_unit_ranges_match_addresses(cached_unit.ranges.as_deref(), addresses)
        {
            let source_line_ranges = cached_unit
                .source_line_ranges
                .get_or_insert_with(|| perf_dwarf_source_line_ranges(&unit));
            let roots = perf_dwarf_unit_roots(&dwarf, &unit, &mut cache.names);
            cached_unit.segments = Some(perf_dwarf_frame_ranges_from_roots(
                &roots,
                source_line_ranges.as_slice(),
            ));
        }
        ordinal += 1;
    }
    cache.units = Some(units);
    Ok(())
}

fn perf_dwarf_unit_ranges_match_addresses(
    ranges: Option<&[PerfAddressRange]>,
    addresses: &[u64],
) -> bool {
    ranges.is_none_or(|ranges| {
        addresses
            .iter()
            .any(|address| perf_dwarf_ranges_contain(ranges, *address))
    })
}

fn perf_dwarf_source_line_ranges<R>(unit: &gimli::Unit<R>) -> Vec<PerfAddressRange>
where
    R: gimli::Reader,
{
    let Some(program) = unit.line_program.clone() else {
        return Vec::new();
    };
    let mut rows = program.rows();
    let mut ranges = Vec::new();
    let mut previous_address = None;
    while let Ok(Some((_, row))) = rows.next_row() {
        let address = row.address();
        if row.end_sequence() {
            if let Some(begin) = previous_address.take()
                && begin < address
            {
                ranges.push(PerfAddressRange {
                    begin,
                    end: address,
                });
            }
            continue;
        }
        if let Some(begin) = previous_address.replace(address)
            && begin < address
        {
            ranges.push(PerfAddressRange {
                begin,
                end: address,
            });
        }
    }
    perf_dwarf_merge_ranges(ranges)
}

fn perf_dwarf_unit_roots<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    names: &mut PerfDwarfNameInterner,
) -> Vec<PerfDwarfDieNode>
where
    R: gimli::Reader,
{
    let Ok(mut tree) = unit.entries_tree(None) else {
        return Vec::new();
    };
    let Ok(root) = tree.root() else {
        return Vec::new();
    };
    let mut roots = Vec::new();
    let mut children = root.children();
    while let Ok(Some(child)) = children.next() {
        perf_dwarf_collect_relevant_nodes(dwarf, unit, child, names, &mut roots);
    }
    roots
}

fn perf_dwarf_collect_relevant_nodes<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    node: gimli::EntriesTreeNode<'_, '_, R>,
    names: &mut PerfDwarfNameInterner,
    out: &mut Vec<PerfDwarfDieNode>,
) where
    R: gimli::Reader,
{
    let tag = node.entry().tag();
    let kind = match tag {
        gimli::DW_TAG_subprogram => Some(PerfDwarfDieKind::Subprogram),
        gimli::DW_TAG_inlined_subroutine => Some(PerfDwarfDieKind::Inline),
        _ => None,
    };
    let collect_children = match kind {
        Some(PerfDwarfDieKind::Subprogram | PerfDwarfDieKind::Inline) => {
            perf_dwarf_collect_inline_children
        }
        None => perf_dwarf_collect_relevant_nodes,
    };
    let ranges = kind
        .map(|_| perf_dwarf_ranges(dwarf.die_ranges(unit, node.entry()).ok()).unwrap_or_default());
    let name = kind.and_then(|_| {
        perf_dwarf_die_frame_name(dwarf, unit, node.entry()).map(|name| names.intern(name))
    });
    if let Some(kind) = kind {
        let mut children = Vec::new();
        let mut child_iter = node.children();
        while let Ok(Some(child)) = child_iter.next() {
            collect_children(dwarf, unit, child, names, &mut children);
        }
        out.push(PerfDwarfDieNode {
            kind,
            ranges: ranges.unwrap_or_default(),
            name,
            children,
        });
        return;
    }
    let mut child_iter = node.children();
    while let Ok(Some(child)) = child_iter.next() {
        collect_children(dwarf, unit, child, names, out);
    }
}

fn perf_dwarf_collect_inline_children<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    node: gimli::EntriesTreeNode<'_, '_, R>,
    names: &mut PerfDwarfNameInterner,
    out: &mut Vec<PerfDwarfDieNode>,
) where
    R: gimli::Reader,
{
    if node.entry().tag() == gimli::DW_TAG_subprogram {
        return;
    }
    perf_dwarf_collect_relevant_nodes(dwarf, unit, node, names, out);
}

fn perf_dwarf_ranges<R>(ranges: Option<gimli::RangeIter<R>>) -> Option<Vec<PerfAddressRange>>
where
    R: gimli::Reader,
{
    let mut ranges = ranges?;
    let mut collected = Vec::new();
    while let Ok(Some(range)) = ranges.next() {
        collected.push(PerfAddressRange {
            begin: range.begin,
            end: range.end,
        });
    }
    Some(collected)
}

fn perf_dwarf_unit_contains_address(unit: &PerfDwarfUnitIndex, address: u64) -> bool {
    unit.ranges
        .as_ref()
        .is_none_or(|ranges| perf_dwarf_ranges_contain(ranges, address))
}

fn perf_dwarf_ranges_contain(ranges: &[PerfAddressRange], address: u64) -> bool {
    ranges
        .iter()
        .any(|range| range.begin <= address && address < range.end)
}

fn perf_dwarf_frame_ranges_from_roots(
    roots: &[PerfDwarfDieNode],
    source_line_ranges: &[PerfAddressRange],
) -> Vec<PerfDwarfFrameRange> {
    let mut segments = Vec::new();
    let root_frames: Arc<[PerfDwarfNameId]> = Arc::from([]);
    let mut next_order = 0;
    for root in roots {
        perf_dwarf_collect_frame_ranges(
            root,
            &root_frames,
            false,
            source_line_ranges,
            &mut segments,
            &mut next_order,
        );
    }
    segments.sort_by_key(|segment| segment.range.begin);
    segments
}

fn perf_dwarf_collect_frame_ranges(
    node: &PerfDwarfDieNode,
    parent_frames: &Arc<[PerfDwarfNameId]>,
    parent_has_inline_frames: bool,
    source_line_ranges: &[PerfAddressRange],
    out: &mut Vec<PerfDwarfFrameRange>,
    next_order: &mut usize,
) -> Vec<PerfAddressRange> {
    let frames = perf_dwarf_node_frames(parent_frames, node.name);
    let has_inline_frames = parent_has_inline_frames || node.kind == PerfDwarfDieKind::Inline;
    let mut child_coverage = Vec::new();
    for child in &node.children {
        if child.kind == PerfDwarfDieKind::Subprogram {
            continue;
        }
        child_coverage.extend(perf_dwarf_collect_frame_ranges(
            child,
            &frames,
            has_inline_frames,
            source_line_ranges,
            out,
            next_order,
        ));
    }

    if !frames.is_empty() {
        for range in perf_dwarf_subtract_ranges(&node.ranges, &child_coverage) {
            let order = *next_order;
            *next_order += 1;
            // libdw requires a source line at the queried address, not merely
            // somewhere in this DIE. Split coverage once during preparation.
            let first_line = source_line_ranges.partition_point(|line| line.end <= range.begin);
            let covered = source_line_ranges[first_line..]
                .iter()
                .take_while(|line| line.begin < range.end)
                .map(|line| PerfAddressRange {
                    begin: line.begin.max(range.begin),
                    end: line.end.min(range.end),
                })
                .collect::<Vec<_>>();
            for (range, has_source_line) in perf_dwarf_subtract_ranges(&[range], &covered)
                .into_iter()
                .map(|range| (range, false))
                .chain(covered.into_iter().map(|range| (range, true)))
            {
                out.push(PerfDwarfFrameRange {
                    range,
                    frames: frames.clone(),
                    has_inline_frames,
                    has_source_line,
                    order,
                });
            }
        }
    }

    perf_dwarf_merge_ranges(node.ranges.clone())
}

fn perf_dwarf_node_frames(
    parent_frames: &Arc<[PerfDwarfNameId]>,
    name: Option<PerfDwarfNameId>,
) -> Arc<[PerfDwarfNameId]> {
    name.map_or(parent_frames.clone(), |name| {
        let mut frames = Vec::with_capacity(parent_frames.len() + 1);
        frames.extend(parent_frames.iter().copied());
        frames.push(name);
        Arc::from(frames)
    })
}

fn perf_dwarf_merge_ranges(mut ranges: Vec<PerfAddressRange>) -> Vec<PerfAddressRange> {
    if ranges.len() <= 1 {
        return ranges;
    }
    ranges.sort_by_key(|range| range.begin);
    let mut merged = Vec::<PerfAddressRange>::with_capacity(ranges.len());
    for range in ranges {
        if let Some(current) = merged.last_mut()
            && range.begin <= current.end
        {
            current.end = current.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    merged
}

fn perf_dwarf_subtract_ranges(
    ranges: &[PerfAddressRange],
    covered: &[PerfAddressRange],
) -> Vec<PerfAddressRange> {
    let merged_ranges = perf_dwarf_merge_ranges(ranges.to_vec());
    let merged_covered = perf_dwarf_merge_ranges(covered.to_vec());
    let mut uncovered = Vec::new();
    let mut covered_index = 0;

    for range in merged_ranges {
        let mut cursor = range.begin;
        while covered_index < merged_covered.len() && merged_covered[covered_index].end <= cursor {
            covered_index += 1;
        }

        let mut index = covered_index;
        while index < merged_covered.len() && merged_covered[index].begin < range.end {
            let overlap = merged_covered[index];
            if cursor < overlap.begin {
                uncovered.push(PerfAddressRange {
                    begin: cursor,
                    end: overlap.begin.min(range.end),
                });
            }
            cursor = cursor.max(overlap.end);
            if cursor >= range.end {
                break;
            }
            index += 1;
        }

        if cursor < range.end {
            uncovered.push(PerfAddressRange {
                begin: cursor,
                end: range.end,
            });
        }
    }

    uncovered
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PerfDwarfFrameNames {
    frames: Vec<String>,
    has_inline_frames: bool,
}

fn perf_dwarf_frame_names_from_index(
    segments: &[PerfDwarfFrameRange],
    names: &[String],
    address: u64,
    base_symbol: Option<&str>,
) -> Option<PerfDwarfFrameNames> {
    let upper_bound = segments.partition_point(|segment| segment.range.begin <= address);
    if upper_bound == 0 {
        return None;
    }
    let segment = segments[..upper_bound]
        .iter()
        .filter(|segment| segment.range.begin <= address && address < segment.range.end)
        .min_by_key(|segment| segment.order)?;
    let mut frames = segment
        .frames
        .iter()
        .filter_map(|name| names.get(usize::try_from(*name).ok()?))
        .cloned()
        .collect::<Vec<_>>();
    frames.reverse();
    let mut has_inline_frames = segment.has_inline_frames;
    if !has_inline_frames {
        let replaces_base_symbol = segment.has_source_line
            && base_symbol.is_some_and(|base_symbol| {
                frames
                    .last()
                    .is_some_and(|frame| frame.as_str() != base_symbol)
            });
        if !replaces_base_symbol {
            return None;
        }
        has_inline_frames = true;
    }
    Some(PerfDwarfFrameNames {
        frames,
        has_inline_frames,
    })
}

/// Resolves the printed frame name for one subprogram/inlined-subroutine DIE.
///
/// perf's default libdw inline path names each frame from `dwarf_diename(die)`
/// (`tools/perf/util/libdw.c` `libdw_a2l_cb`) and then passes that name through
/// `new_inline_sym` (`tools/perf/util/srcline.c`). That means Rust DIE names
/// from `DW_AT_name` / abstract origins retain their supplied spelling
/// unless the name itself is mangled and `dso__demangle_sym` can demangle it.
///
/// The installed perf-script oracle for this branch uses libdw first; tests
/// that assert perf-script output must be checked against that runtime path.
/// This helper still keeps command-backend spellings for cases where the
/// linkage name is the only perf-compatible spelling available.
fn perf_dwarf_die_frame_name<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &gimli::DebuggingInformationEntry<R>,
) -> Option<String>
where
    R: gimli::Reader,
{
    perf_dwarf_die_name(dwarf, unit, entry)
        .map(|name| perf_dwarf_function_name(&name))
        .or_else(|| {
            perf_dwarf_die_linkage_name(dwarf, unit, entry, 16)
                .map(|linkage| demangle_addr2line_name_qualified(&linkage))
        })
}

fn perf_dwarf_die_linkage_name<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &gimli::DebuggingInformationEntry<R>,
    recursion_limit: usize,
) -> Option<String>
where
    R: gimli::Reader,
{
    if recursion_limit == 0 {
        return None;
    }
    entry
        .attr(gimli::DW_AT_linkage_name)
        .and_then(|attr| dwarf.attr_string(unit, attr.value()).ok())
        .and_then(|name| name.to_string_lossy().ok().map(Cow::into_owned))
        .or_else(|| {
            entry.attr(gimli::DW_AT_abstract_origin).and_then(|attr| {
                perf_dwarf_origin_linkage_name(dwarf, unit, &attr.value(), recursion_limit - 1)
            })
        })
        .or_else(|| {
            entry.attr(gimli::DW_AT_specification).and_then(|attr| {
                perf_dwarf_origin_linkage_name(dwarf, unit, &attr.value(), recursion_limit - 1)
            })
        })
}

fn perf_dwarf_origin_linkage_name<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    value: &gimli::AttributeValue<R>,
    recursion_limit: usize,
) -> Option<String>
where
    R: gimli::Reader,
{
    let gimli::AttributeValue::UnitRef(offset) = value else {
        return None;
    };
    let mut entries = unit.entries_tree(Some(*offset)).ok()?;
    let root = entries.root().ok()?;
    perf_dwarf_die_linkage_name(dwarf, unit, root.entry(), recursion_limit)
}

fn perf_dwarf_die_name<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &gimli::DebuggingInformationEntry<R>,
) -> Option<String>
where
    R: gimli::Reader,
{
    entry
        .attr(gimli::DW_AT_name)
        .and_then(|attr| dwarf.attr_string(unit, attr.value()).ok())
        .and_then(|name| name.to_string_lossy().ok().map(Cow::into_owned))
        .or_else(|| {
            entry
                .attr(gimli::DW_AT_abstract_origin)
                .and_then(|attr| perf_dwarf_origin_name(dwarf, unit, &attr.value(), 16))
        })
        .or_else(|| {
            entry
                .attr(gimli::DW_AT_specification)
                .and_then(|attr| perf_dwarf_origin_name(dwarf, unit, &attr.value(), 16))
        })
}

fn perf_dwarf_origin_name<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    value: &gimli::AttributeValue<R>,
    recursion_limit: usize,
) -> Option<String>
where
    R: gimli::Reader,
{
    if recursion_limit == 0 {
        return None;
    }
    let gimli::AttributeValue::UnitRef(offset) = value else {
        return None;
    };
    let mut entries = unit.entries_tree(Some(*offset)).ok()?;
    let root = entries.root().ok()?;
    let entry = root.entry();
    entry
        .attr(gimli::DW_AT_name)
        .and_then(|attr| dwarf.attr_string(unit, attr.value()).ok())
        .and_then(|name| name.to_string_lossy().ok().map(Cow::into_owned))
        .or_else(|| {
            entry.attr(gimli::DW_AT_abstract_origin).and_then(|attr| {
                perf_dwarf_origin_name(dwarf, unit, &attr.value(), recursion_limit - 1)
            })
        })
        .or_else(|| {
            entry.attr(gimli::DW_AT_specification).and_then(|attr| {
                perf_dwarf_origin_name(dwarf, unit, &attr.value(), recursion_limit - 1)
            })
        })
}

#[derive(Default)]
struct PerfDwarfNameInterner {
    names: Vec<String>,
    ids_by_name: HashMap<String, PerfDwarfNameId, FxBuildHasher>,
}

impl PerfDwarfNameInterner {
    fn intern(&mut self, name: String) -> PerfDwarfNameId {
        if let Some(&id) = self.ids_by_name.get(name.as_str()) {
            return id;
        }
        let id = PerfDwarfNameId::try_from(self.names.len()).expect("dwarf name table fits in u32");
        self.ids_by_name.insert(name.clone(), id);
        self.names.push(name);
        id
    }

    fn into_names(self) -> Vec<String> {
        self.names
    }
}

#[must_use]
pub fn perf_symbol_name(name: &str) -> String {
    name.to_owned()
}

#[must_use]
pub fn perf_dwarf_function_name(name: &str) -> String {
    name.to_owned()
}

#[must_use]
pub fn perf_inline_frame_order(mut frames: Vec<String>) -> Vec<String> {
    frames.reverse();
    frames
}

type RequestIndexes = SmallVec<[usize; 16]>;

enum RequestGroups<'a> {
    Single(Option<(&'a OsStr, RequestIndexes)>),
    Multiple(hashbrown::hash_map::IntoIter<&'a OsStr, RequestIndexes>),
}

impl<'a> Iterator for RequestGroups<'a> {
    type Item = (&'a OsStr, RequestIndexes);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Single(group) => group.take(),
            Self::Multiple(groups) => groups.next(),
        }
    }
}

fn grouped_request_indexes(requests: &[SymbolRequest]) -> RequestGroups<'_> {
    let Some(first) = requests.first() else {
        return RequestGroups::Single(None);
    };
    let path = first.path.as_os_str();
    if requests
        .iter()
        .all(|request| request.path.as_os_str() == path)
    {
        return RequestGroups::Single(Some((path, (0..requests.len()).collect())));
    }
    let mut grouped = FxHashMap::<&OsStr, RequestIndexes>::default();
    for (index, request) in requests.iter().enumerate() {
        grouped
            .entry(request.path.as_os_str())
            .or_default()
            .push(index);
    }
    RequestGroups::Multiple(grouped.into_iter())
}

fn mapping_frame_key(mapping: &ResolvedMappingRef<'_>) -> MappingFrameKey {
    MappingFrameKey {
        symbol_source_id: mapping.symbol_source_id,
        relative_address: mapping.relative_address,
        kernel_mapping_range: kernel_mapping_range_from_ref(mapping),
    }
}

fn is_kernel_mapping_ref(mapping: &ResolvedMappingRef<'_>) -> bool {
    crate::perfdata::samples::is_kernel_space_frame(mapping.relative_address)
        && mapping.path.starts_with('[')
}

fn symbol_request_from_mapping_ref(mapping: &ResolvedMappingRef<'_>) -> SymbolRequest {
    let mut request = SymbolRequest {
        path: PathBuf::new(),
        relative_address: 0,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    };
    update_symbol_request_from_mapping_ref(&mut request, mapping);
    request
}

fn update_symbol_request_from_mapping_ref(
    request: &mut SymbolRequest,
    mapping: &ResolvedMappingRef<'_>,
) {
    request.path.clear();
    request.path.push(
        if is_kernel_symbol_path(Path::new(mapping.path)) && mapping.path.starts_with("[kernel") {
            "[kernel.kallsyms]"
        } else {
            mapping.path
        },
    );
    request.relative_address = mapping.relative_address;
    request.kernel_mapping_range = kernel_mapping_range_from_ref(mapping);
    if let Some(build_id) = mapping.build_id {
        let hex = request.build_id.get_or_insert_with(String::new);
        hex.clear();
        for byte in build_id {
            write!(hex, "{byte:02x}").expect("writing to a string cannot fail");
        }
    } else {
        request.build_id = None;
    }
    request.file_identity = mapping.file_identity;
    request
        .kernel_relocation
        .clone_from(&mapping.kernel_relocation);
}

fn build_id_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex, "{byte:02x}").expect("writing to a string cannot fail");
    }
    hex
}

/// Extracts the GNU build-id (lowercase hex) from a buffer of ELF notes such as
/// `/sys/kernel/notes`. Walks the note stream looking for the
/// `NT_GNU_BUILD_ID` (type 3) note with name "GNU\0" and returns its
/// descriptor. Notes are little-endian on the supported targets (`x86_64`,
/// aarch64), matching how perf stores build-ids in `HEADER_BUILD_ID`.
fn gnu_build_id_from_notes(bytes: &[u8]) -> Option<String> {
    const NT_GNU_BUILD_ID: u32 = 3;
    let mut offset = 0usize;
    while offset + 12 <= bytes.len() {
        let read_u32 = |start: usize| {
            u32::from_le_bytes([
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
            ])
        };
        let namesz = read_u32(offset) as usize;
        let descsz = read_u32(offset + 4) as usize;
        let note_type = read_u32(offset + 8);
        let name_start = offset + 12;
        let name_end = name_start.checked_add(namesz)?;
        // Notes pad name and descriptor to 4-byte boundaries.
        let name_padded = name_end.next_multiple_of(4);
        let desc_start = name_padded;
        let desc_end = desc_start.checked_add(descsz)?;
        if desc_end > bytes.len() {
            break;
        }
        if note_type == NT_GNU_BUILD_ID
            && bytes.get(name_start..name_end) == Some(b"GNU\0")
            && descsz > 0
        {
            return Some(build_id_hex(&bytes[desc_start..desc_end]));
        }
        offset = desc_end.next_multiple_of(4);
    }
    None
}

fn resolve_kernel_kallsyms(kallsyms: &Kallsyms, request: &SymbolRequest) -> Option<String> {
    // perf-script prints kernel frames as `name+0x<off>` (symbol_fprintf.c),
    // and the folded path strips the offset like every other frame.
    if let Some(relocation) = &request.kernel_relocation {
        kallsyms.resolve_relocated_with_offset(
            request.relative_address,
            &relocation.reference_symbol,
            relocation.recorded_reference_address,
        )
    } else {
        kallsyms.resolve_with_offset(request.relative_address)
    }
}

fn resolve_module_kallsyms(kallsyms: &Kallsyms, request: &SymbolRequest) -> Option<String> {
    kallsyms.resolve_module_with_offset_for_path(
        request.relative_address,
        request.kernel_mapping_range,
        request.path.to_str()?,
    )
}

fn kernel_mapping_range_from_ref(mapping: &ResolvedMappingRef<'_>) -> Option<(u64, u64)> {
    is_kernel_mapping_ref(mapping).then_some((mapping.start, mapping.end))
}

fn parse_addr2line_stdout(
    stdout: &[u8],
    expected_symbols: usize,
) -> Result<Vec<Option<String>>, String> {
    let text = String::from_utf8_lossy(stdout);
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() < expected_symbols.saturating_mul(2) {
        return Err(format!(
            "addr2line returned {} lines for {expected_symbols} symbols",
            lines.len()
        ));
    }
    Ok(lines
        .chunks(2)
        .take(expected_symbols)
        .map(|chunk| function_name(chunk[0]))
        .collect())
}

fn function_name(line: &str) -> Option<String> {
    if line == "??" || line.is_empty() {
        None
    } else {
        Some(line.to_string())
    }
}

fn is_kernel_symbol_path(path: &Path) -> bool {
    path.to_str().is_some_and(|path| {
        path.starts_with("[kernel.kallsyms]")
            || path.starts_with("[kernel]")
            || path.starts_with("[guest.kernel]")
            || is_kernel_module_symbol_path_str(path)
    })
}

fn is_kernel_module_symbol_path(path: &Path) -> bool {
    path.to_str().is_some_and(is_kernel_module_symbol_path_str)
}

fn is_kernel_module_symbol_path_str(path: &str) -> bool {
    // perf handles VDSO maps before kernel-module DSO lookup:
    // tools/perf/util/map.c: map__new() checks is_vdso_map() and calls
    // machine__findnew_vdso() instead of machine__findnew_dso_id().
    path.starts_with('[')
        && !matches!(path, "[vdso]" | "[vdso32]" | "[vdsox32]")
        && !path.starts_with("[kernel")
        && !path.starts_with("[guest.kernel]")
}

fn insert_kallsyms_symbol(
    symbols: &mut BTreeMap<u64, KallsymsSymbol>,
    addresses_by_name: Option<&mut BTreeMap<String, u64>>,
    address: u64,
    symbol: KallsymsSymbol,
) {
    #[cfg(test)]
    MODULE_KALLSYMS_SYMBOL_INSERTIONS.with(|count| count.set(count.get() + 1));
    if let Some(addresses_by_name) = addresses_by_name {
        addresses_by_name
            .entry(symbol.name.clone())
            .or_insert(address);
    }
    // Preserve the existing last-at-address selection while moving the symbol.
    symbols.insert(address, symbol);
}

fn fixup_kallsyms_symbol_ends_like_perf(symbols: &mut [BorrowedKallsymsRow<'_>]) {
    #[cfg(test)]
    MODULE_KALLSYMS_END_FIXUP_PASSES.with(|count| count.set(count.get() + 1));
    for index in 1..symbols.len() {
        let current = symbols[index];
        let previous = &mut symbols[index - 1];
        // symbol.c:246 compares the raw '[' suffix before stripping module
        // names. Losing aliases and intervening core rows still set ends.
        let previous_module = previous
            .full_name
            .find('[')
            .map(|i| &previous.full_name[i..]);
        let current_module = current.full_name.find('[').map(|i| &current.full_name[i..]);
        previous.end = if previous_module == current_module {
            current.address
        } else {
            round_up_to_page(previous.address.saturating_add(4096))
        };
    }
    if let Some(last) = symbols.last_mut() {
        last.end = round_up_to_page(last.address.saturating_add(4096));
    }
}

fn kallsyms_next_alias_is_better(
    current: &BorrowedKallsymsRow<'_>,
    next: &BorrowedKallsymsRow<'_>,
) -> bool {
    // symbol.c:152 choose_best_symbol, using the unstripped name. All accepted
    // T/W/D/B rows have FUNC/OBJECT type, never NOTYPE (tools/lib/symbol/kallsyms.c:8).
    let current_nonzero = current.end != current.address;
    let next_nonzero = next.end != next.address;
    if current_nonzero != next_nonzero {
        return next_nonzero;
    }
    // kallsyms.h:13 treats only uppercase W as STB_WEAK; lowercase w is local.
    let current_weak = current.symbol_type == 'W';
    let next_weak = next.symbol_type == 'W';
    if current_weak != next_weak {
        return !next_weak;
    }
    let current_global = current.symbol_type.is_ascii_uppercase() && !current_weak;
    let next_global = next.symbol_type.is_ascii_uppercase() && !next_weak;
    if current_global != next_global {
        return next_global;
    }
    let current_underscores = leading_underscore_count(current.full_name);
    let next_underscores = leading_underscore_count(next.full_name);
    if current_underscores != next_underscores {
        return next_underscores < current_underscores;
    }
    if current.full_name.len() != next.full_name.len() {
        return next.full_name.len() > current.full_name.len();
    }
    // symbol.c:140 arch__choose_best_symbol's generic fallback.
    current.full_name.starts_with("SyS") || current.full_name.starts_with("compat_SyS")
}

fn round_up_to_page(address: u64) -> u64 {
    address.saturating_add(4095) & !4095
}

fn perf_build_id_kallsyms_paths(debug_dir: &Path, build_id: &str) -> [PathBuf; 2] {
    let base = debug_dir.join("[kernel.kallsyms]").join(build_id);
    [base.join("kallsyms"), base]
}

fn parse_kallsyms_line(line: &str) -> Option<(u64, String)> {
    let mut fields = line.split_whitespace();
    let address = u64::from_str_radix(fields.next()?, 16).ok()?;
    let _symbol_type = fields.next()?;
    let symbol = fields.next()?;
    Some((address, symbol.to_string()))
}

fn parse_module_kallsyms_line(line: &str) -> Option<BorrowedKallsymsRow<'_>> {
    #[cfg(test)]
    MODULE_KALLSYMS_ROW_VISITS.with(|count| count.set(count.get() + 1));
    let (address, rest) = line.trim_start().split_once(char::is_whitespace)?;
    let address = u64::from_str_radix(address, 16).ok()?;
    let (symbol_type, full_name) = rest.trim_start().split_once(char::is_whitespace)?;
    let symbol_type = symbol_type.chars().next()?;
    if !perf_kallsyms_type_is_kept(symbol_type) {
        return None;
    }
    let full_name = full_name.trim_start();
    let mut fields = full_name.split_whitespace();
    let name = fields.next()?;
    // tools/perf/util/symbol.c:774 rejects these before global insertion,
    // so they must not influence end-fixup, duplicate selection, or tree shape.
    if name.starts_with('$') {
        return None;
    }
    let module = fields.next();
    if module.is_some_and(|module| !module.starts_with('[') || !module.ends_with(']')) {
        return None;
    }
    Some(BorrowedKallsymsRow {
        address,
        end: address,
        name,
        full_name,
        module,
        symbol_type,
    })
}

fn perf_kallsyms_type_is_kept(symbol_type: char) -> bool {
    matches!(symbol_type.to_ascii_uppercase(), 'T' | 'W' | 'D' | 'B')
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use object::{Object, ObjectSegment, ObjectSymbol, build, elf};

    use super::{
        CachedObjectMetadata, Kallsyms, PerfAddressRange, PerfDwarfDieKind, PerfDwarfDieNode,
        PerfDwarfFrameNames, PerfDwarfIndexCache, PerfDwarfNameInterner, PerfObjectSymbolIndex,
        PerfSymbolBinding, PerfSymbolCandidate, PerfSymbolScope, PreparedObjectMetadata,
        ResolvedMappingRef, ResolvedSymbolFrames, RustAddr2lineResolver, SymbolFrameCache,
        SymbolRequest, SymbolResolver, clean_object_symbol_request,
        demangle_addr2line_name_qualified, fixup_object_symbol_ends_like_perf,
        gnu_build_id_from_notes, perf_best_duplicate_symbol, perf_dwarf_frame_names_from_index,
        perf_dwarf_frame_ranges_from_roots, perf_frames_with_object_alias,
        perf_symbol_candidate_search_end, resolve_base_frames_from_object_metadata,
    };

    #[test]
    fn gnu_build_id_from_notes_reads_kernel_nt_gnu_build_id() {
        // Real /sys/kernel/notes bytes from the oracle recording container
        // (aarch64). Layout per note: namesz=4, descsz=20, type=3
        // (NT_GNU_BUILD_ID), name "GNU\0", then the 20-byte build-id; followed
        // by unrelated "Linux" notes that must be skipped.
        let notes = [
            0x04, 0x00, 0x00, 0x00, // namesz = 4
            0x14, 0x00, 0x00, 0x00, // descsz = 20
            0x03, 0x00, 0x00, 0x00, // type = NT_GNU_BUILD_ID
            0x47, 0x4e, 0x55, 0x00, // "GNU\0"
            0xcb, 0x97, 0xc0, 0xad, 0xd7, 0x3d, 0xc6, 0x0d, 0x73, 0xbb, 0x9a, 0xd7, 0xdc, 0x27,
            0x85, 0xd8, 0x8b, 0x36, 0x44, 0xa0, // 20-byte build-id
            0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x4c, 0x69,
            0x6e, 0x75, 0x78, 0x00, 0x00, 0x00, // a trailing "Linux" note
        ];

        assert_eq!(
            gnu_build_id_from_notes(&notes).as_deref(),
            Some("cb97c0add73dc60d73bb9ad7dc2785d88b3644a0")
        );
    }

    #[test]
    fn gnu_build_id_from_notes_skips_leading_non_build_id_note() {
        // A "Linux" version note precedes the build-id note; the walker must
        // honor 4-byte name/descriptor padding and find the later build-id.
        let notes = [
            0x06, 0x00, 0x00, 0x00, // namesz = 6 -> padded to 8
            0x04, 0x00, 0x00, 0x00, // descsz = 4
            0x00, 0x01, 0x00, 0x00, // type
            0x4c, 0x69, 0x6e, 0x75, 0x78, 0x00, 0x00, 0x00, // "Linux\0" padded
            0xde, 0xad, 0xbe, 0xef, // 4-byte desc
            0x04, 0x00, 0x00, 0x00, // namesz = 4
            0x04, 0x00, 0x00, 0x00, // descsz = 4
            0x03, 0x00, 0x00, 0x00, // NT_GNU_BUILD_ID
            0x47, 0x4e, 0x55, 0x00, // "GNU\0"
            0x01, 0x23, 0x45, 0x67, // 4-byte build-id
        ];

        assert_eq!(gnu_build_id_from_notes(&notes).as_deref(), Some("01234567"));
    }

    #[test]
    fn demangle_addr2line_name_qualified_matches_perf_external_addr2line_backend() {
        // perf's external-addr2line srcline backend names each frame from the
        // mangled symtab/DWARF linkage name and demangles it itself with the
        // Rust v0 demangler in alternate form (tools/perf/util/srcline.c
        // new_inline_sym -> tools/perf/util/symbol.c dso__demangle_sym ->
        // rust_demangle_display_demangle(..., /*alternate=*/true)), keeping the
        // fully-qualified path, dropping the trailing ::h<hash>, and preserving
        // generic arguments. These expectations are copied byte-for-byte from
        // target/oracle/dwarf.perf.script (perf 6.17.13, addr2line backend).
        //
        // Legacy `_ZN` manglings (core/std non-generic functions in symtab):
        assert_eq!(
            demangle_addr2line_name_qualified(
                "_ZN4core5slice4sort8unstable4sort17hf487fc59c5378322E"
            ),
            "core::slice::sort::unstable::sort"
        );
        assert_eq!(
            demangle_addr2line_name_qualified(
                "_ZN91_$LT$T$u20$as$u20$core..slice..sort..shared..smallsort..UnstableSmallSortFreezeTypeImpl$GT$10small_sort17ha5f9b986560cf204E"
            ),
            "<T as core::slice::sort::shared::smallsort::UnstableSmallSortFreezeTypeImpl>::small_sort"
        );
        // v0 `_R` manglings (the std::rt::lang_start_internal inline group):
        assert_eq!(
            demangle_addr2line_name_qualified("_RNvNtCsfQfHhyvAE2O_3std2rt19lang_start_internal"),
            "std::rt::lang_start_internal"
        );
        assert_eq!(
            demangle_addr2line_name_qualified(
                "_RINvNtCsfQfHhyvAE2O_3std9panicking12catch_unwindiNCNvNtB4_2rt19lang_start_internal0EB4_"
            ),
            "std::panicking::catch_unwind::<isize, std::rt::lang_start_internal::{closure#0}>"
        );
    }

    #[test]
    fn symbol_request_ignores_file_identity_when_build_id_present() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        use crate::perfdata::mappings::FileIdentity;

        let hash_of = |request: &SymbolRequest| {
            let mut hasher = DefaultHasher::new();
            request.hash(&mut hasher);
            hasher.finish()
        };

        // Same object, same build_id: the inline MMAP2-build-id form carries no
        // file_identity while the plain MMAP2 + HEADER_BUILD_ID form does.
        // perf's __dso_id__cmp makes build_id decisive, so these are one entry.
        let inline = SymbolRequest {
            path: PathBuf::from("/usr/lib/libc.so.6"),
            relative_address: 0x1234,
            kernel_mapping_range: None,
            build_id: Some("aabbccdd".to_string()),
            file_identity: None,
            kernel_relocation: None,
        };
        let with_identity = SymbolRequest {
            file_identity: Some(FileIdentity {
                major: 8,
                minor: 1,
                inode: 99,
                inode_generation: 7,
            }),
            ..inline.clone()
        };
        assert_eq!(inline, with_identity);
        assert_eq!(hash_of(&inline), hash_of(&with_identity));
        assert_eq!(inline.cmp(&with_identity), std::cmp::Ordering::Equal);

        // Different build_ids at the same path are genuinely different objects.
        let other_build_id = SymbolRequest {
            build_id: Some("11223344".to_string()),
            ..inline.clone()
        };
        assert_ne!(inline, other_build_id);

        // With no build_id, file_identity is the only backing-store
        // discriminator and must still separate distinct objects.
        let no_build_id_a = SymbolRequest {
            build_id: None,
            file_identity: Some(FileIdentity {
                major: 8,
                minor: 1,
                inode: 99,
                inode_generation: 0,
            }),
            ..inline.clone()
        };
        let no_build_id_b = SymbolRequest {
            file_identity: Some(FileIdentity {
                major: 8,
                minor: 1,
                inode: 100,
                inode_generation: 0,
            }),
            ..no_build_id_a.clone()
        };
        assert_ne!(no_build_id_a, no_build_id_b);
    }

    #[test]
    fn object_requests_use_elf_virtual_addresses_for_pie_file_offsets() {
        let path = std::env::current_exe().expect("current test binary");
        let bytes = std::fs::read(&path).expect("current test binary bytes");
        let object = object::File::parse(bytes.as_slice()).expect("current test binary object");
        let (file_offset, virtual_address) = object
            .segments()
            .find_map(|segment| {
                let (file_offset, file_size) = segment.file_range();
                let virtual_address = segment.address();
                (file_size > 8).then_some((file_offset + 8, virtual_address + 8))
            })
            .expect("current test binary has a load segment");

        let request = clean_object_symbol_request(path, file_offset);

        assert_eq!(request.relative_address, virtual_address);
    }

    #[test]
    fn perf_alias_tie_breaker_prefers_less_underscored_symbol_like_perf() {
        let internal_alias = PerfSymbolCandidate {
            name: "__read".to_string(),
            address: 0x1000,
            size: 128,
            bfd_size: 128,
            elf_type: Some(object::elf::STT_FUNC),
            scope: PerfSymbolScope::Global,
            binding: PerfSymbolBinding::Global,
            bfd_function_like: true,
            bfd_function: true,
            bfd_has_filename: false,
        };
        let public_alias = PerfSymbolCandidate {
            name: "read".to_string(),
            address: 0x1000,
            size: 128,
            bfd_size: 128,
            elf_type: Some(object::elf::STT_FUNC),
            scope: PerfSymbolScope::Global,
            binding: PerfSymbolBinding::Global,
            bfd_function_like: true,
            bfd_function: true,
            bfd_has_filename: false,
        };

        assert_eq!(
            perf_best_duplicate_symbol(&internal_alias, &public_alias).name,
            "read"
        );
    }

    #[test]
    fn perf_alias_tie_breaker_prefers_global_symbol_like_perf() {
        let local_alias = PerfSymbolCandidate {
            name: "__libc_read".to_string(),
            address: 0x1000,
            size: 128,
            bfd_size: 128,
            elf_type: Some(object::elf::STT_FUNC),
            scope: PerfSymbolScope::Local,
            binding: PerfSymbolBinding::Global,
            bfd_function_like: true,
            bfd_function: true,
            bfd_has_filename: false,
        };
        let global_alias = PerfSymbolCandidate {
            name: "read".to_string(),
            address: 0x1000,
            size: 128,
            bfd_size: 128,
            elf_type: Some(object::elf::STT_FUNC),
            scope: PerfSymbolScope::Global,
            binding: PerfSymbolBinding::Global,
            bfd_function_like: true,
            bfd_function: true,
            bfd_has_filename: false,
        };

        assert_eq!(
            perf_best_duplicate_symbol(&local_alias, &global_alias).name,
            "read"
        );
    }

    #[test]
    fn perf_alias_tie_breaker_prefers_non_weak_local_symbol_over_weak_global_like_perf() {
        // tools/perf/util/symbol.c choose_best_symbol() checks STB_WEAK
        // before STB_GLOBAL, so glibc's local symtab aliases win over weak
        // public aliases such as recv@@GLIBC_2.2.5.
        let local_non_weak_alias = PerfSymbolCandidate {
            name: "__libc_recv".to_string(),
            address: 0x1000,
            size: 47,
            bfd_size: 47,
            elf_type: Some(object::elf::STT_FUNC),
            scope: PerfSymbolScope::Local,
            binding: PerfSymbolBinding::Global,
            bfd_function_like: true,
            bfd_function: true,
            bfd_has_filename: false,
        };
        let weak_global_alias = PerfSymbolCandidate {
            name: "recv".to_string(),
            address: 0x1000,
            size: 47,
            bfd_size: 47,
            elf_type: Some(object::elf::STT_FUNC),
            scope: PerfSymbolScope::Global,
            binding: PerfSymbolBinding::Weak,
            bfd_function_like: true,
            bfd_function: true,
            bfd_has_filename: false,
        };

        assert_eq!(
            perf_best_duplicate_symbol(&local_non_weak_alias, &weak_global_alias).name,
            "__libc_recv"
        );
    }

    fn elf_with_text_symbol_fixtures(
        machine: u16,
        symbols: &[(&'static [u8], u64, u64, u8, u8)],
    ) -> Vec<u8> {
        let mut builder =
            build::elf::Builder::new(object::Endianness::Little, machine != elf::EM_ARM);
        builder.header.e_type = elf::ET_EXEC;
        builder.header.e_machine = machine;
        let section = builder.sections.add();
        section.name = b".shstrtab"[..].into();
        section.sh_type = elf::SHT_STRTAB;
        section.data = build::elf::SectionData::SectionString;
        let section = builder.sections.add();
        section.name = b".text"[..].into();
        section.sh_type = elf::SHT_PROGBITS;
        section.sh_flags = u64::from(elf::SHF_ALLOC | elf::SHF_EXECINSTR);
        section.sh_addr = 0x1000;
        section.sh_addralign = 16;
        section.data = build::elf::SectionData::Data(vec![0; 64].into());
        let text = section.id();
        let section = builder.sections.add();
        section.name = b".symtab"[..].into();
        section.sh_type = elf::SHT_SYMTAB;
        section.sh_addralign = 8;
        section.data = build::elf::SectionData::Symbol;
        let section = builder.sections.add();
        section.name = b".strtab"[..].into();
        section.sh_type = elf::SHT_STRTAB;
        section.data = build::elf::SectionData::String;
        for &(name, address, size, binding, symbol_type) in symbols {
            let symbol = builder.symbols.add();
            symbol.name = name.into();
            symbol.st_value = address;
            symbol.st_size = size;
            symbol.set_st_info(binding, symbol_type);
            symbol.section = Some(text);
        }
        builder.set_section_sizes();
        let mut bytes = Vec::new();
        builder.write(&mut bytes).expect("write symbol fixture ELF");
        bytes
    }

    #[test]
    fn symbol_parity_typed_alias_precedes_binding_and_name_ties() {
        // perf symbol.c:choose_best_symbol prefers typed symbols even when
        // they are weak, local, shorter, or more heavily underscored.
        for symbol_type in [elf::STT_FUNC, elf::STT_GNU_IFUNC, elf::STT_OBJECT] {
            for binding in [elf::STB_LOCAL, elf::STB_GLOBAL, elf::STB_WEAK] {
                let bytes = elf_with_text_symbol_fixtures(
                    elf::EM_X86_64,
                    &[
                        (b"__f", 0x1000, 16, binding, symbol_type),
                        (b"long_label", 0x1000, 16, elf::STB_GLOBAL, elf::STT_NOTYPE),
                    ],
                );
                let object = object::File::parse(bytes.as_slice()).unwrap();
                let candidates: Vec<_> = object
                    .symbols()
                    .filter_map(|symbol| {
                        super::perf_symbol_candidate_from_object_symbol(&object, &symbol)
                    })
                    .collect();
                assert_eq!(candidates.len(), 2);
                for (left, right) in [(0, 1), (1, 0)] {
                    assert_eq!(
                        perf_best_duplicate_symbol(&candidates[left], &candidates[right]).name,
                        "__f",
                        "type {symbol_type}, binding {binding}"
                    );
                }
                let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
                assert_eq!(index.symbol_name(0x1000), Some("__f"));
                assert_eq!(index.symbol_name(0x1008), Some("__f"));
            }
        }
    }

    #[test]
    fn symbol_parity_duplicate_size_precedes_type_and_equal_types_keep_tie_rules() {
        for (left_size, right_size, left_binding, right_binding, left_type, right_type, expected) in [
            (
                0,
                16,
                elf::STB_GLOBAL,
                elf::STB_GLOBAL,
                elf::STT_FUNC,
                elf::STT_NOTYPE,
                "bbb",
            ),
            (
                16,
                0,
                elf::STB_GLOBAL,
                elf::STB_GLOBAL,
                elf::STT_NOTYPE,
                elf::STT_FUNC,
                "aaa",
            ),
            (
                16,
                16,
                elf::STB_LOCAL,
                elf::STB_WEAK,
                elf::STT_FUNC,
                elf::STT_FUNC,
                "aaa",
            ),
            (
                16,
                16,
                elf::STB_LOCAL,
                elf::STB_GLOBAL,
                elf::STT_NOTYPE,
                elf::STT_NOTYPE,
                "bbb",
            ),
            (
                16,
                16,
                elf::STB_WEAK,
                elf::STB_LOCAL,
                elf::STT_NOTYPE,
                elf::STT_NOTYPE,
                "bbb",
            ),
        ] {
            let bytes = elf_with_text_symbol_fixtures(
                elf::EM_X86_64,
                &[
                    (b"aaa", 0x1000, left_size, left_binding, left_type),
                    (b"bbb", 0x1000, right_size, right_binding, right_type),
                ],
            );
            let object = object::File::parse(bytes.as_slice()).unwrap();
            let candidates: Vec<_> = object
                .symbols()
                .filter_map(|symbol| {
                    super::perf_symbol_candidate_from_object_symbol(&object, &symbol)
                })
                .collect();
            for (left, right) in [(0, 1), (1, 0)] {
                assert_eq!(
                    perf_best_duplicate_symbol(&candidates[left], &candidates[right]).name,
                    expected
                );
            }
        }
        let bytes = elf_with_text_symbol_fixtures(
            elf::EM_X86_64,
            &[
                (b"aaa", 0x1000, 16, elf::STB_GLOBAL, elf::STT_FUNC),
                (b"bbb", 0x1000, 16, elf::STB_GLOBAL, elf::STT_FUNC),
            ],
        );
        assert_eq!(
            PerfObjectSymbolIndex::from_object_bytes(&bytes).symbol_name(0x1008),
            Some("aaa")
        );
    }

    #[test]
    fn symbol_parity_duplicate_size_preference_uses_native_end_fixup_order() {
        // symbol-elf.c fixes ends before duplicates. The earlier zero-sized
        // alias stays empty; the later one extends to the next start/page.
        let function = (
            b"function".as_slice(),
            0x1000,
            0,
            elf::STB_GLOBAL,
            elf::STT_FUNC,
        );
        let label = (
            b"label".as_slice(),
            0x1000,
            16,
            elf::STB_GLOBAL,
            elf::STT_NOTYPE,
        );
        for with_next_symbol in [false, true] {
            for (aliases, expected) in [
                ([function, label], "label"),
                ([label, function], "function"),
            ] {
                let mut fixtures = aliases.to_vec();
                if with_next_symbol {
                    fixtures.push((b"next", 0x1020, 16, elf::STB_GLOBAL, elf::STT_FUNC));
                }
                let bytes = elf_with_text_symbol_fixtures(elf::EM_X86_64, &fixtures);
                let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
                for address in [0x1000, 0x1008, 0x100f] {
                    assert_eq!(
                        index.symbol_name(address),
                        Some(expected),
                        "next symbol {with_next_symbol}, address {address:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn symbol_parity_arm_mapping_markers_do_not_displace_functions() {
        for machine in [elf::EM_ARM, elf::EM_AARCH64] {
            for name in [b"$a".as_slice(), b"$d", b"$t", b"$x", b"$x.0", b"$d.123"] {
                let bytes = elf_with_text_symbol_fixtures(
                    machine,
                    &[
                        (b"function", 0x1000, 64, elf::STB_GLOBAL, elf::STT_FUNC),
                        (name, 0x1010, 0, elf::STB_LOCAL, elf::STT_NOTYPE),
                    ],
                );
                assert_eq!(
                    PerfObjectSymbolIndex::from_object_bytes(&bytes).symbol_name(0x1014),
                    Some("function"),
                    "machine {machine}, name {name:?}"
                );
            }
        }
    }

    #[test]
    fn symbol_parity_riscv_mapping_markers_do_not_displace_functions() {
        for name in [b"$d".as_slice(), b"$x", b"$d.0", b"$xrv64i", b"$data"] {
            let bytes = elf_with_text_symbol_fixtures(
                elf::EM_RISCV,
                &[
                    (b"function", 0x1000, 64, elf::STB_GLOBAL, elf::STT_FUNC),
                    (name, 0x1010, 0, elf::STB_LOCAL, elf::STT_NOTYPE),
                ],
            );
            assert_eq!(
                PerfObjectSymbolIndex::from_object_bytes(&bytes).symbol_name(0x1014),
                Some("function"),
                "name {name:?}"
            );
        }
    }

    #[test]
    fn symbol_parity_mapping_marker_filter_keeps_other_labels_and_architectures() {
        for (machine, names) in [
            (elf::EM_ARM, [b"$xLong".as_slice(), b"$aLong", b"$q", b"$"]),
            (
                elf::EM_AARCH64,
                [b"$xLong".as_slice(), b"$dLong", b"$q", b"$"],
            ),
            (elf::EM_RISCV, [b"$a".as_slice(), b"$t", b"$q", b"$"]),
            (
                elf::EM_X86_64,
                [b"$x".as_slice(), b"$d.0", b"$a", b"$xrv64i"],
            ),
        ] {
            for name in names {
                let bytes = elf_with_text_symbol_fixtures(
                    machine,
                    &[(name, 0x1000, 16, elf::STB_GLOBAL, elf::STT_NOTYPE)],
                );
                assert_eq!(
                    PerfObjectSymbolIndex::from_object_bytes(&bytes).symbol_name(0x1008),
                    Some(std::str::from_utf8(name).unwrap()),
                    "machine {machine}, name {name:?}"
                );
            }
        }
    }

    #[test]
    fn object_symbol_index_does_not_resurrect_discarded_alias_past_winner_end() {
        // perf symbol-elf.c:dso__load_sym_internal fixes ends, then
        // symbol.c:symbols__fixup_duplicate removes equal-start losers.
        let bytes = elf_with_text_symbol_fixtures(
            elf::EM_X86_64,
            &[
                (b"function", 0x1000, 16, elf::STB_GLOBAL, elf::STT_FUNC),
                (b"label", 0x1000, 0, elf::STB_GLOBAL, elf::STT_NOTYPE),
                (b"next", 0x1020, 16, elf::STB_GLOBAL, elf::STT_FUNC),
            ],
        );
        let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
        assert_eq!(index.symbol_name(0x1008), Some("function"));
        assert_eq!(index.symbol_name(0x1010), None);
        assert_eq!(index.symbol_name(0x1018), None);
        assert_eq!(index.symbol_name(0x1020), Some("next"));
    }

    #[test]
    fn discarded_perf_alias_remains_available_for_bfd_function_record_lookup() {
        // Binutils bfd/dwarf2.c:_bfd_elf_find_function retains its own
        // canonical candidates; perf's duplicate removal must not erase them.
        let bytes = elf_with_text_symbol_fixtures(
            elf::EM_X86_64,
            &[
                (b"unit.c", 0, 0, elf::STB_LOCAL, elf::STT_FILE),
                (b"global", 0x1000, 16, elf::STB_GLOBAL, elf::STT_FUNC),
                (b"local_alias", 0x1000, 48, elf::STB_LOCAL, elf::STT_FUNC),
                (b"next", 0x1030, 16, elf::STB_GLOBAL, elf::STT_FUNC),
            ],
        );
        let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
        assert_eq!(index.symbol_name(0x1008), Some("global"));
        assert_eq!(index.symbol_name(0x1018), None);
        assert_eq!(index.bfd_function_record_name(0x1018), Some("local_alias"));
    }

    #[test]
    fn bfd_function_record_lookup_uses_raw_elf_sizes_before_perf_zero_size_fixup() {
        // bfd/elf.c:_bfd_elf_maybe_function_sym reads st_size (zero means
        // one), and bfd/dwarf2.c:better_fit compares those raw extents.
        // perf symbol-elf.c:dso__load_sym_internal instead fixes zero-sized
        // ends before choosing duplicate winners. These sizes must not leak
        // into the independent BFD lookup.
        let bytes = elf_with_text_symbol_fixtures(
            elf::EM_X86_64,
            &[
                (b"unit.c", 0, 0, elf::STB_LOCAL, elf::STT_FILE),
                (b"local_function", 0x1000, 16, elf::STB_LOCAL, elf::STT_FUNC),
                (b"global_alias", 0x1000, 0, elf::STB_GLOBAL, elf::STT_FUNC),
                (b"next", 0x1020, 16, elf::STB_GLOBAL, elf::STT_FUNC),
            ],
        );
        let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
        assert_eq!(index.symbol_name(0x1018), Some("global_alias"));
        for (address, expected) in [
            (0x1018, "local_function"),
            (0x1008, "local_function"),
            (0x1000, "global_alias"),
            (0x1020, "next"),
        ] {
            assert_eq!(index.bfd_function_record_name(address), Some(expected));
        }
    }

    #[test]
    fn object_symbol_index_keeps_earlier_overlapping_symbol_candidates() {
        let symbols = PerfObjectSymbolIndex {
            symbols: vec![
                PerfSymbolCandidate {
                    name: "large".to_string(),
                    address: 0x1000,
                    size: 0x1000,
                    bfd_size: 0x1000,
                    elf_type: Some(object::elf::STT_FUNC),
                    scope: PerfSymbolScope::Global,
                    binding: PerfSymbolBinding::Global,
                    bfd_function_like: true,
                    bfd_function: true,
                    bfd_has_filename: false,
                },
                PerfSymbolCandidate {
                    name: "small".to_string(),
                    address: 0x1800,
                    size: 0x10,
                    bfd_size: 0x10,
                    elf_type: Some(object::elf::STT_FUNC),
                    scope: PerfSymbolScope::Global,
                    binding: PerfSymbolBinding::Global,
                    bfd_function_like: true,
                    bfd_function: true,
                    bfd_has_filename: false,
                },
            ],
            max_end_by_index: vec![0x2000, 0x2000],
        };

        assert_eq!(symbols.symbol_name(0x1810), Some("large"));
        let metadata = super::PreparedObjectMetadata {
            object_symbols: symbols,
        };
        for (address, expected_name, expected_offset) in [
            (0xfff, None, None),
            (0x1000, Some("large"), Some(0)),
            (0x1800, Some("small"), Some(0)),
            (0x1810, Some("large"), Some(0x810)),
            (0x2000, None, None),
        ] {
            let selected = metadata.object_symbol_names(address);
            assert_eq!(selected.bare, expected_name);
            assert_eq!(selected.offset, expected_offset);
        }
    }

    #[test]
    fn object_symbol_index_preserves_perf_duplicate_order_for_versioned_glibc_aliases() {
        let candidate = |name: &str, address| PerfSymbolCandidate {
            name: name.to_string(),
            address,
            size: 0x100,
            bfd_size: 0x100,
            elf_type: Some(object::elf::STT_FUNC),
            scope: PerfSymbolScope::Global,
            binding: PerfSymbolBinding::Global,
            bfd_function_like: true,
            bfd_function: true,
            bfd_has_filename: false,
        };
        let symbols = PerfObjectSymbolIndex {
            symbols: vec![
                candidate("pthread_create@GLIBC_2.2.5", 0x1000),
                candidate("pthread_create@@GLIBC_2.34", 0x1000),
                candidate("__libc_start_main@@GLIBC_2.34", 0x2000),
                candidate("__libc_start_main@GLIBC_2.2.5", 0x2000),
                candidate("clock_gettime@@GLIBC_2.17", 0x3000),
                candidate("clock_gettime@GLIBC_2.2.5", 0x3000),
            ],
            max_end_by_index: vec![0x1100, 0x1100, 0x2100, 0x2100, 0x3100, 0x3100],
        };

        assert_eq!(
            symbols.symbol_name_with_offset(0x1098),
            Some("pthread_create@GLIBC_2.2.5+0x98".to_string())
        );
        assert_eq!(
            symbols.symbol_name_with_offset(0x2088),
            Some("__libc_start_main@@GLIBC_2.34+0x88".to_string())
        );
        assert_eq!(
            symbols.symbol_name_with_offset(0x3004),
            Some("clock_gettime@@GLIBC_2.17+0x4".to_string())
        );
    }

    #[test]
    fn object_symbol_index_prefers_non_weak_glibc_symtab_aliases_over_weak_exports_like_perf() {
        // tools/perf/util/symbol.c symbols__fixup_duplicate() uses
        // choose_best_symbol(), whose weak check precedes the global check.
        let symbols = PerfObjectSymbolIndex {
            symbols: vec![
                PerfSymbolCandidate {
                    name: "recv".to_string(),
                    address: 0x1000,
                    size: 47,
                    bfd_size: 47,
                    elf_type: Some(object::elf::STT_FUNC),
                    scope: PerfSymbolScope::Global,
                    binding: PerfSymbolBinding::Weak,
                    bfd_function_like: true,
                    bfd_function: true,
                    bfd_has_filename: false,
                },
                PerfSymbolCandidate {
                    name: "__libc_recv".to_string(),
                    address: 0x1000,
                    size: 47,
                    bfd_size: 47,
                    elf_type: Some(object::elf::STT_FUNC),
                    scope: PerfSymbolScope::Local,
                    binding: PerfSymbolBinding::Global,
                    bfd_function_like: true,
                    bfd_function: true,
                    bfd_has_filename: false,
                },
                PerfSymbolCandidate {
                    name: "write".to_string(),
                    address: 0x2000,
                    size: 46,
                    bfd_size: 46,
                    elf_type: Some(object::elf::STT_FUNC),
                    scope: PerfSymbolScope::Global,
                    binding: PerfSymbolBinding::Weak,
                    bfd_function_like: true,
                    bfd_function: true,
                    bfd_has_filename: false,
                },
                PerfSymbolCandidate {
                    name: "__GI___libc_write".to_string(),
                    address: 0x2000,
                    size: 46,
                    bfd_size: 46,
                    elf_type: Some(object::elf::STT_FUNC),
                    scope: PerfSymbolScope::Local,
                    binding: PerfSymbolBinding::Global,
                    bfd_function_like: true,
                    bfd_function: true,
                    bfd_has_filename: false,
                },
            ],
            max_end_by_index: vec![0x102f, 0x102f, 0x202e, 0x202e],
        };

        assert_eq!(
            symbols.symbol_name_with_offset(0x101f),
            Some("__libc_recv+0x1f".to_string())
        );
        assert_eq!(
            symbols.symbol_name_with_offset(0x201e),
            Some("__GI___libc_write+0x1e".to_string())
        );
    }

    #[test]
    fn object_symbol_index_reads_dynamic_symbols_like_perf() {
        let object_bytes = elf_with_dynamic_text_symbol(b"read", 0x1000, 46);
        let symbols = super::PerfObjectSymbolIndex::from_object_bytes(&object_bytes);

        assert_eq!(symbols.symbol_name(0x1008), Some("read"));
    }

    #[test]
    fn object_symbol_index_formats_symbol_offsets_like_perf_script() {
        // tools/perf/util/symbol_fprintf.c symbol__fprintf_symname_offs()
        // prints symbol names with a hexadecimal +0x offset, including +0x0.
        let object_bytes = elf_with_dynamic_text_symbol(b"read", 0x1000, 46);
        let symbols = super::PerfObjectSymbolIndex::from_object_bytes(&object_bytes);

        assert_eq!(
            symbols.symbol_name_with_offset(0x1000),
            Some("read+0x0".to_string())
        );
        assert_eq!(
            symbols.symbol_name_with_offset(0x1008),
            Some("read+0x8".to_string())
        );
    }

    #[test]
    fn base_object_metadata_resolution_keeps_symtab_name_despite_debug_string_generics_like_perf() {
        // perf script's no-callchain event-line IP uses
        // machine__resolve() -> map__find_symbol() and
        // sample__fprintf_sym(cursor == NULL), so it prints the demangled ELF
        // symtab symbol. BFD/addr2line debug-string names are only relevant to
        // DWARF line/inline lookup, not this base symbol path.
        let mut object_bytes = elf_with_dynamic_text_symbol(
            b"alloc::collections::btree::map::IntoIter<K,V,A>::dying_next",
            0x1000,
            0x200,
        );
        object_bytes.extend_from_slice(
            b"\0alloc::collections::btree::map::IntoIter<u64, alloc::string::String, alloc::alloc::Global>::dying_next\0",
        );
        let metadata = Arc::new(CachedObjectMetadata {
            object_metadata: PreparedObjectMetadata::from_object_bytes(&object_bytes),
            object_bytes: object_bytes.into(),
            dwarf_index: Mutex::new(PerfDwarfIndexCache::default()),
        });

        let frames = resolve_base_frames_from_object_metadata(
            &[SymbolRequest {
                path: PathBuf::from("/tmp/pyroclast-generic-symbol"),
                relative_address: 0x1180,
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            }],
            |_| Some(Arc::clone(&metadata)),
        );

        assert_eq!(
            frames,
            vec![ResolvedSymbolFrames {
                frames: vec![
                    "alloc::collections::btree::map::IntoIter<K,V,A>::dying_next+0x180".to_string()
                ],
                source_state: super::SymbolSourceState::AddressDependent,
                has_base_symbol: true,
                has_inline_frames: false,
                has_non_inline_base_frame: true,
                base_offset: Some(0x180),
            }]
        );
    }

    #[test]
    fn object_symbol_index_extends_zero_sized_labels_to_next_symbol_like_perf() {
        // tools/perf/util/symbol-elf.c dso__load_sym_internal() calls
        // symbols__fixup_end(..., false), so a zero-sized label like glibc's
        // __syscall_cancel_arch_start covers IPs until the next symbol.
        let mut symbols = vec![
            PerfSymbolCandidate {
                name: "__syscall_cancel_arch".to_string(),
                address: 0xa68f0,
                size: 51,
                bfd_size: 51,
                elf_type: Some(object::elf::STT_FUNC),
                scope: PerfSymbolScope::Local,
                binding: PerfSymbolBinding::Global,
                bfd_function_like: true,
                bfd_function: true,
                bfd_has_filename: false,
            },
            PerfSymbolCandidate {
                name: "__syscall_cancel_arch_start".to_string(),
                address: 0xa68f4,
                size: 0,
                bfd_size: 0,
                elf_type: Some(object::elf::STT_NOTYPE),
                scope: PerfSymbolScope::Local,
                binding: PerfSymbolBinding::Global,
                bfd_function_like: true,
                bfd_function: true,
                bfd_has_filename: false,
            },
            PerfSymbolCandidate {
                name: "__syscall_cancel_arch_end".to_string(),
                address: 0xa6922,
                size: 0,
                bfd_size: 0,
                elf_type: Some(object::elf::STT_NOTYPE),
                scope: PerfSymbolScope::Local,
                binding: PerfSymbolBinding::Global,
                bfd_function_like: true,
                bfd_function: true,
                bfd_has_filename: false,
            },
        ];
        fixup_object_symbol_ends_like_perf(&mut symbols);
        let mut max_end = 0_u64;
        let max_end_by_index = symbols
            .iter()
            .map(|symbol| {
                max_end = max_end.max(perf_symbol_candidate_search_end(symbol));
                max_end
            })
            .collect();
        let symbols = PerfObjectSymbolIndex {
            symbols,
            max_end_by_index,
        };

        assert_eq!(
            symbols.symbol_name_with_offset(0xa691b),
            Some("__syscall_cancel_arch_start+0x27".to_string())
        );
    }

    const MULTI_MODULE_KALLSYMS: &str = "not a kallsyms row\n\
        0000000000000800 T accepted_core\n\
        0000000000000000 T zero [alpha]\n\
        0000000000000990 R excluded [alpha]\n\
        0000000000001040 T shared [alpha]\n\
        0000000000005000 T gamma_tail [gamma]\n\
        0000000000001000 T alias_first [alpha]\n\
        0000000000001000 T alias_last [alpha]\n\
        0000000000001010 W weak [alpha]\n\
        0000000000001020 t shared [alpha]\n\
        0000000000001030 D data [alpha]\n\
        0000000000001800 B gamma_head [gamma]\n\
        0000000000002010 T shared [beta]\n\
        0000000000002020 T beta_tail [beta]\n\
        0000000000004000 T alpha_tail [alpha]\n";

    fn live_module_kallsyms_fixture(text: &str) -> (tempfile::TempDir, PathBuf) {
        let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-fixtures");
        std::fs::create_dir_all(&fixtures).unwrap();
        let root = tempfile::tempdir_in(fixtures).unwrap();
        let path = root.path().join("kallsyms");
        std::fs::write(&path, text).unwrap();
        (root, path)
    }

    fn assert_multi_module_kallsyms_views(alpha: &Kallsyms, beta: &Kallsyms, gamma: &Kallsyms) {
        // tools/perf/util/symbol.c:1512-1523 fixes global ends and duplicates
        // before splitting DSOs. Same-module aliases get zero length except
        // for the last entry; module transitions end at a page boundary.
        for (view, start, end, name) in [
            (alpha, 0x1000, 0x1010, "alias_last"),
            (alpha, 0x1010, 0x1020, "weak"),
            (alpha, 0x1020, 0x1030, "shared"),
            (alpha, 0x1030, 0x1040, "data"),
            (alpha, 0x1040, 0x3000, "shared"),
            (alpha, 0x4000, 0x5000, "alpha_tail"),
            (beta, 0x2010, 0x2020, "shared"),
            (beta, 0x2020, 0x4000, "beta_tail"),
            (gamma, 0x1800, 0x3000, "gamma_head"),
            (gamma, 0x5000, 0x6000, "gamma_tail"),
        ] {
            let symbol = &view.symbols[&start];
            assert_eq!(symbol.name, name);
            assert_eq!(symbol.end, Some(end), "{name} at {start:#x}");
            assert_eq!(
                view.resolve_module_with_offset(start + 1),
                Some(format!("{name}+0x1"))
            );
        }
        for (view, end) in [(alpha, 0x3000), (beta, 0x4000), (gamma, 0x6000)] {
            assert_eq!(view.resolve_module_with_offset(end), None);
            assert_eq!(view.address_of("accepted_core"), None);
            assert_eq!(view.address_of("alias_first"), None);
            assert_eq!(view.address_of("zero"), None);
            assert_eq!(view.address_of("excluded"), None);
        }
        assert_eq!(alpha.address_of("shared"), Some(0x1020));
        assert_eq!(beta.address_of("shared"), Some(0x2010));
        assert_eq!(gamma.address_of("shared"), None);
        assert_eq!(beta.resolve_module_with_offset(0x1000), None);
        assert_eq!(
            alpha.resolve_module_with_offset_in_range(0x100f, Some((0x1000, 0x1010))),
            Some("alias_last+0xf".into())
        );
        assert_eq!(
            alpha.resolve_module_with_offset_in_range(0x100f, Some((0x1000, 0x100f))),
            None
        );
    }

    #[test]
    fn live_module_kallsyms_builds_the_global_tree_once_for_all_module_views() {
        let (_root, path) = live_module_kallsyms_fixture(MULTI_MODULE_KALLSYMS);
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        super::MODULE_KALLSYMS_TREE_BUILDS.with(|count| count.set(0));
        super::MODULE_KALLSYMS_ROW_VISITS.with(|count| count.set(0));
        super::MODULE_KALLSYMS_SYMBOL_INSERTIONS.with(|count| count.set(0));
        super::MODULE_KALLSYMS_END_FIXUP_PASSES.with(|count| count.set(0));

        let alpha = resolver.live_module_kallsyms_for_path("[alpha]").unwrap();
        // The source lifetime already retains its first successful read.
        // New module views must not reread or reparse that source snapshot.
        std::fs::write(&path, "0000000000001000 T replacement [alpha]\n").unwrap();
        let beta = resolver.live_module_kallsyms_for_path("[beta]").unwrap();
        let gamma = resolver.live_module_kallsyms_for_path("[gamma]").unwrap();
        assert_multi_module_kallsyms_views(&alpha, &beta, &gamma);
        for module in ["[missing-one]", "[missing-two]", "[missing-one]"] {
            assert!(resolver.live_module_kallsyms_for_path(module).is_none());
        }
        assert!(Arc::ptr_eq(
            &alpha,
            &resolver.live_module_kallsyms_for_path("[alpha]").unwrap()
        ));
        assert_eq!(
            (
                super::MODULE_KALLSYMS_TREE_BUILDS.with(Cell::get),
                super::MODULE_KALLSYMS_ROW_VISITS.with(Cell::get),
                super::MODULE_KALLSYMS_SYMBOL_INSERTIONS.with(Cell::get),
                super::MODULE_KALLSYMS_END_FIXUP_PASSES.with(Cell::get),
            ),
            (1, MULTI_MODULE_KALLSYMS.lines().count(), 12, 1),
            "one global build, one visit per physical row, one insertion per accepted row, one end-fixup pass"
        );
    }

    #[test]
    fn module_kallsyms_views_preserve_global_ends_aliases_and_address_ordered_names() {
        let alpha = Kallsyms::parse_modules_for_path(MULTI_MODULE_KALLSYMS, "[alpha]").unwrap();
        let beta = Kallsyms::parse_modules_for_path(MULTI_MODULE_KALLSYMS, "[beta]").unwrap();
        let gamma = Kallsyms::parse_modules_for_path(MULTI_MODULE_KALLSYMS, "[gamma]").unwrap();
        assert_multi_module_kallsyms_views(&alpha, &beta, &gamma);
    }

    #[test]
    fn live_module_kallsyms_source_snapshots_remain_isolated_between_resolvers() {
        let (_root, path) = live_module_kallsyms_fixture(MULTI_MODULE_KALLSYMS);
        let first = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        let first_alpha = first.live_module_kallsyms_for_path("[alpha]").unwrap();
        std::fs::write(&path, "0000000000001000 T replacement [alpha]\n").unwrap();
        let second = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        let second_alpha = second.live_module_kallsyms_for_path("[alpha]").unwrap();
        assert_eq!(first_alpha.address_of("alias_last"), Some(0x1000));
        assert_eq!(first_alpha.address_of("replacement"), None);
        assert_eq!(second_alpha.address_of("replacement"), Some(0x1000));
        assert_eq!(second_alpha.address_of("alias_last"), None);
        assert!(!Arc::ptr_eq(&first_alpha, &second_alpha));
        assert_eq!(
            first
                .live_module_kallsyms_for_path("[beta]")
                .unwrap()
                .address_of("shared"),
            Some(0x2010)
        );
        assert!(second.live_module_kallsyms_for_path("[beta]").is_none());
    }

    #[test]
    fn module_kallsyms_rejects_dollar_core_and_module_rows_before_global_end_fixup() {
        // map__process_kallsym_symbol (symbol.c:774) applies the same name
        // filter to core and module rows before symbols__fixup_end (1512).
        let rejected = [
            "0000000000001100 T $core",
            "0000000000001150 T $module [b]",
            "0000000000001200 T $alias [a]",
        ];
        for line in rejected {
            assert!(super::parse_module_kallsyms_line(line).is_none(), "{line}");
        }
        let text = "0000000000001000 T first [a]\n\
                    0000000000001100 T $core\n\
                    0000000000001150 T $module [b]\n\
                    0000000000001200 T next [a]\n\
                    0000000000001200 T $alias [a]\n";
        let rows = Kallsyms::parse_module_symbols(text);
        // symbol.c:305: terminal end = roundup(start, 4096) + 4096.
        assert_eq!(
            rows.iter()
                .map(|row| (row.address, row.end))
                .collect::<Vec<_>>(),
            [(0x1000, 0x1200), (0x1200, 0x3000)]
        );
        let view = Kallsyms::parse_modules_for_path(text, "[a]").unwrap();
        assert_eq!(
            view.resolve_module_with_offset(0x11ff).as_deref(),
            Some("first+0x1ff")
        );
        assert_eq!(
            view.resolve_module_with_offset(0x1200).as_deref(),
            Some("next+0x0")
        );
        assert!(Kallsyms::parse_modules_for_path(text, "[b]").is_err());
    }

    #[test]
    fn module_kallsyms_core_rows_determine_ends_before_module_views_are_split() {
        // tools/perf/util/symbol.c:1512 runs symbols__fixup_end over accepted
        // core and module rows before maps__split_kallsyms (1523). Filtering
        // the intervening core row first would incorrectly set end to 0x1200.
        let view = Kallsyms::parse_modules_for_path(
            "0000000000001000 T first [a]\n\
             0000000000001100 T core\n\
             0000000000001200 T next [a]\n",
            "[a]",
        )
        .unwrap();
        assert_eq!(view.symbols[&0x1000].end, Some(0x2000));
        assert_eq!(view.address_of("core"), None);
    }

    #[test]
    fn module_kallsyms_cross_module_aliases_prefer_nonweak_after_global_end_fixup() {
        // tools/perf/util/symbol.c:246 gives both cross-module aliases nonzero
        // ends; choose_best_symbol:173 then prefers nonweak over STB_WEAK.
        // Duplicate removal (1513) happens before the DSO split (1523).
        let text = "0000000000001000 T strong [a]\n\
                    0000000000001000 W weak [b]\n\
                    0000000000001100 T next [b]\n";
        let strong = Kallsyms::parse_modules_for_path(text, "[a]").unwrap();
        assert_eq!(strong.symbols[&0x1000].name, "strong");
        assert_eq!(strong.symbols[&0x1000].end, Some(0x2000));
        let other = Kallsyms::parse_modules_for_path(text, "[b]").unwrap();
        assert_eq!(other.address_of("weak"), None);
        assert_eq!(other.resolve_module_with_offset(0x1000), None);
        assert_eq!(other.address_of("next"), Some(0x1100));
    }

    #[test]
    fn module_kallsyms_duplicate_removal_does_not_recompute_preceding_symbol_ends() {
        // tools/perf/util/symbol.c:1512-1523 fixes ends, removes duplicates,
        // then splits without recomputing ends. The losing [b] alias still
        // establishes the preceding [a] symbol's page-boundary end.
        let view = Kallsyms::parse_modules_for_path(
            "0000000000001000 T preceding [a]\n\
             0000000000001100 W losing [b]\n\
             0000000000001100 T winner [a]\n\
             0000000000001200 T next [a]\n",
            "[a]",
        )
        .unwrap();
        assert_eq!(view.symbols[&0x1000].end, Some(0x2000));
        assert_eq!(view.symbols[&0x1100].name, "winner");
        assert_eq!(view.symbols[&0x1100].end, Some(0x1200));
        assert_eq!(view.address_of("losing"), None);
    }

    #[test]
    fn kallsyms_keeps_last_equal_address_alias_like_perf_fixup_duplicate() {
        // tools/perf/util/symbol.c __symbols__insert() inserts equal-start
        // symbols to the right, symbols__fixup_end(true) gives the last one at
        // that address the extent to the next address, then
        // symbols__fixup_duplicate() keeps that nonzero-length symbol.
        let kallsyms = Kallsyms::parse(
            "ffffffff91201850 t common_interrupt_return\n\
             ffffffff91201850 T swapgs_restore_regs_and_return_to_usermode\n\
             ffffffff91201850 T __irqentry_text_end\n\
             ffffffff91201921 T restore_regs_and_return_to_kernel\n",
        )
        .expect("parse kallsyms");

        assert_eq!(
            kallsyms.resolve_with_offset(0xffff_ffff_9120_186f),
            Some("__irqentry_text_end+0x1f".to_string())
        );
    }

    #[test]
    fn kallsyms_keeps_last_equal_address_rust_alias_like_perf_fixup_duplicate() {
        let kallsyms = Kallsyms::parse(
            "ffffffff91b8a950 T __pfx__RNvXs8_NtCs1L1xvvvYXuH_6kernel12module_paramxNtB5_11ModuleParam18try_from_param_arg\n\
             ffffffff91b8a950 T __pfx__RNvXsa_NtCs1L1xvvvYXuH_6kernel12module_paramiNtB5_11ModuleParam18try_from_param_arg\n\
             ffffffff91b8a960 T _RNvXs8_NtCs1L1xvvvYXuH_6kernel12module_paramxNtB5_11ModuleParam18try_from_param_arg\n\
             ffffffff91b8a960 T _RNvXsa_NtCs1L1xvvvYXuH_6kernel12module_paramiNtB5_11ModuleParam18try_from_param_arg\n\
             ffffffff91b8ab60 T __pfx__RNvXs8_NtCs1L1xvvvYXuH_6kernel3fmtbNtB5_7Display3fmt\n",
        )
        .expect("parse kallsyms");

        assert_eq!(
            kallsyms.resolve_with_offset(0xffff_ffff_91b8_aaa4),
            Some("_RNvXsa_NtCs1L1xvvvYXuH_6kernel12module_paramiNtB5_11ModuleParam18try_from_param_arg+0x144".to_string())
        );
    }

    #[test]
    fn object_symbol_index_keeps_notype_text_labels_like_perf() {
        // perf util/symbol-elf.c elf_sym__is_label() admits STT_NOTYPE
        // symbols with a real section, and dso__load_sym_internal() includes
        // labels alongside FUNC/OBJECT symbols. glibc's _dl_start_user is one
        // such zero-sized NOTYPE label; perf script prints `_dl_start_user+0x0`.
        let ld_linux = std::path::Path::new(
            "/nix/store/57iz36553175g3178pvxjij8z5rcsd4n-glibc-2.42-61/lib/ld-linux-x86-64.so.2",
        );
        if !ld_linux.exists() {
            return;
        }
        let object_bytes = std::fs::read(ld_linux).expect("ld-linux fixture");
        let symbols = super::PerfObjectSymbolIndex::from_object_bytes(&object_bytes);

        assert_eq!(
            symbols.symbol_name_with_offset(0x1fd48),
            Some("_dl_start_user+0x0".to_string())
        );
    }

    #[test]
    fn perf_object_alias_replaces_single_non_inline_frame_names_like_perf_script() {
        assert_eq!(
            perf_frames_with_object_alias(vec!["__read".to_string()], Some("read")),
            vec!["read".to_string()]
        );
        assert_eq!(
            perf_frames_with_object_alias(
                vec!["alloc::collections::btree::map::IntoIter<K,V,A>::dying_next".to_string()],
                Some("dying_next<u64, alloc::string::String, alloc::alloc::Global>")
            ),
            vec!["dying_next<u64, alloc::string::String, alloc::alloc::Global>".to_string()]
        );
    }

    fn elf_with_dynamic_text_symbol(name: &'static [u8], address: u64, size: usize) -> Vec<u8> {
        elf_with_dynamic_symbol(
            name,
            address,
            size,
            (elf::STT_FUNC, elf::STV_DEFAULT, false),
        )
    }

    fn elf_with_dynamic_symbol(
        name: &'static [u8],
        address: u64,
        size: usize,
        attributes: (u8, u8, bool),
    ) -> Vec<u8> {
        elf_with_dynamic_symbol_in_section(
            name,
            address,
            size,
            attributes,
            b".text",
            elf::SHF_ALLOC | elf::SHF_EXECINSTR,
        )
    }

    fn elf_with_dynamic_symbol_in_section(
        name: &'static [u8],
        address: u64,
        size: usize,
        attributes: (u8, u8, bool),
        section_name: &'static [u8],
        section_flags: u32,
    ) -> Vec<u8> {
        let mut builder = build::elf::Builder::new(object::Endianness::Little, true);
        builder.header.e_type = elf::ET_DYN;
        builder.header.e_machine = elf::EM_X86_64;
        builder.header.e_phoff = 0x40;

        let section = builder.sections.add();
        section.name = b".shstrtab"[..].into();
        section.sh_type = elf::SHT_STRTAB;
        section.data = build::elf::SectionData::SectionString;

        let section = builder.sections.add();
        section.name = section_name.into();
        section.sh_type = elf::SHT_PROGBITS;
        section.sh_flags = u64::from(section_flags);
        section.sh_addr = address;
        section.sh_addralign = 16;
        section.data = build::elf::SectionData::Data(vec![0xcc; size].into());
        let text_id = section.id();

        let section = builder.sections.add();
        section.name = b".dynsym"[..].into();
        section.sh_type = elf::SHT_DYNSYM;
        section.sh_flags = u64::from(elf::SHF_ALLOC);
        section.sh_addralign = 8;
        section.data = build::elf::SectionData::DynamicSymbol;
        let dynsym_id = section.id();

        let section = builder.sections.add();
        section.name = b".dynstr"[..].into();
        section.sh_type = elf::SHT_STRTAB;
        section.sh_flags = u64::from(elf::SHF_ALLOC);
        section.sh_addralign = 1;
        section.data = build::elf::SectionData::DynamicString;
        let dynstr_id = section.id();

        let symbol = builder.dynamic_symbols.add();
        symbol.name = name.into();
        symbol.st_value = address;
        symbol.st_size = u64::try_from(size).expect("fixture size fits in u64");
        symbol.set_st_info(elf::STB_GLOBAL, attributes.0);
        symbol.st_other = attributes.1;
        if attributes.2 {
            symbol.st_shndx = elf::SHN_ABS;
        } else {
            symbol.section = Some(text_id);
        }

        builder.set_section_sizes();

        let segment = builder.segments.add();
        segment.p_type = elf::PT_LOAD;
        segment.p_flags = elf::PF_R | elf::PF_X;
        segment.p_vaddr = address;
        segment.p_paddr = address;
        segment.p_filesz = 0x1000;
        segment.p_memsz = 0x1000;
        segment.p_align = 16;
        segment.append_section(builder.sections.get_mut(text_id));
        segment.append_section(builder.sections.get_mut(dynsym_id));
        segment.append_section(builder.sections.get_mut(dynstr_id));

        let mut bytes = Vec::new();
        builder.write(&mut bytes).expect("write dynamic-symbol ELF");
        bytes
    }

    #[test]
    fn object_symbol_index_rejects_hidden_and_internal_labels_like_perf() {
        // perf util/symbol-elf.c:elf_sym__is_label rejects STV_HIDDEN and
        // STV_INTERNAL only for STT_NOTYPE, not STT_FUNC or STT_OBJECT.
        for visibility in [elf::STV_HIDDEN, elf::STV_INTERNAL] {
            let bytes =
                elf_with_dynamic_symbol(b"label", 0x1000, 16, (elf::STT_NOTYPE, visibility, false));
            assert!(
                PerfObjectSymbolIndex::from_object_bytes(&bytes)
                    .symbols
                    .is_empty(),
                "visibility {visibility}"
            );
        }
    }

    #[test]
    fn object_symbol_index_rejects_absolute_symbols_like_perf() {
        // perf util/symbol-elf.c:dso__load_sym skips SHN_ABS after its
        // type/visibility filter, including functions and data symbols.
        for symbol_type in [elf::STT_NOTYPE, elf::STT_FUNC, elf::STT_OBJECT] {
            let bytes = elf_with_dynamic_symbol(
                b"absolute",
                0x1000,
                16,
                (symbol_type, elf::STV_DEFAULT, true),
            );
            assert!(
                PerfObjectSymbolIndex::from_object_bytes(&bytes)
                    .symbols
                    .is_empty(),
                "type {symbol_type}"
            );
        }
    }

    #[test]
    fn object_symbol_index_rejects_unrecognized_elf_types_like_perf() {
        // elf_sym__filter accepts only FUNC, GNU_IFUNC, OBJECT; the label
        // exception is specifically NOTYPE, not every object::Unknown kind.
        let bytes = elf_with_dynamic_symbol(
            b"other",
            0x1000,
            16,
            (elf::STT_LOOS + 1, elf::STV_DEFAULT, false),
        );
        assert!(
            PerfObjectSymbolIndex::from_object_bytes(&bytes)
                .symbols
                .is_empty()
        );
    }

    #[test]
    fn object_symbol_index_accepts_visible_labels_and_hidden_functions_like_perf() {
        for attributes in [
            (elf::STT_NOTYPE, elf::STV_DEFAULT, false),
            (elf::STT_NOTYPE, elf::STV_PROTECTED, false),
            (elf::STT_FUNC, elf::STV_HIDDEN, false),
            (elf::STT_OBJECT, elf::STV_INTERNAL, false),
            (elf::STT_GNU_IFUNC, elf::STV_DEFAULT, false),
        ] {
            let bytes = elf_with_dynamic_symbol(b"allowed", 0x1000, 16, attributes);
            assert_eq!(
                PerfObjectSymbolIndex::from_object_bytes(&bytes)
                    .symbols
                    .len(),
                1,
                "attributes {attributes:?}"
            );
        }
    }

    #[test]
    fn object_symbol_index_rejects_nonallocated_sections_like_perf() {
        // perf util/symbol-elf.c:dso__load_sym skips sections without SHF_ALLOC.
        let bytes = elf_with_dynamic_symbol_in_section(
            b"warning",
            0x1000,
            16,
            (elf::STT_FUNC, elf::STV_DEFAULT, false),
            b".gnu.warning",
            0,
        );
        assert!(
            PerfObjectSymbolIndex::from_object_bytes(&bytes)
                .symbols
                .is_empty()
        );
    }

    #[test]
    fn object_symbol_index_only_accepts_notype_labels_in_text_or_data_sections_like_perf() {
        // perf util/symbol-elf.c:elf_sec__filter matches section names containing
        // "text" or "data"; this extra restriction applies only to labels.
        for (section, symbol_type, accepted) in [
            (&b".bss"[..], elf::STT_NOTYPE, false),
            (&b".bss"[..], elf::STT_OBJECT, true),
            (&b".rodata"[..], elf::STT_NOTYPE, true),
            (&b".text.hot"[..], elf::STT_NOTYPE, true),
        ] {
            let bytes = elf_with_dynamic_symbol_in_section(
                b"label",
                0x1000,
                16,
                (symbol_type, elf::STV_DEFAULT, false),
                section,
                elf::SHF_ALLOC,
            );
            assert_eq!(
                !PerfObjectSymbolIndex::from_object_bytes(&bytes)
                    .symbols
                    .is_empty(),
                accepted,
                "section {section:?}, type {symbol_type}"
            );
        }
    }

    #[test]
    fn rust_inline_resolver_does_not_resurrect_a_hidden_label_like_perf() {
        // perf util/machine.c:append_inlines returns immediately when
        // ms->sym is NULL. addr2line's broader symbol map is not a fallback
        // for symbols excluded by perf's ELF loading rules.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hidden-label.so");
        let bytes = elf_with_dynamic_symbol(
            b"hidden_label",
            0x1000,
            16,
            (elf::STT_NOTYPE, elf::STV_HIDDEN, false),
        );
        std::fs::write(&path, &bytes).unwrap();
        let loader = addr2line::Loader::new(&path).unwrap();
        assert_eq!(loader.find_symbol(0x1000), Some("hidden_label"));
        let resolver = RustAddr2lineResolver::new();
        let results = resolver
            .resolve_frame_batch_with_metadata(&[test_request(path.to_str().unwrap(), 0x1000)])
            .unwrap();
        assert_eq!(
            results[0],
            ResolvedSymbolFrames {
                source_state: super::SymbolSourceState::Unavailable,
                ..ResolvedSymbolFrames::default()
            }
        );
    }

    #[test]
    fn flattened_dwarf_ranges_share_frame_slices_for_the_same_node() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(
            &[PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Subprogram,
                ranges: vec![test_range(0, 100)],
                name: Some(names.intern("outer".to_string())),
                children: vec![PerfDwarfDieNode {
                    kind: PerfDwarfDieKind::Inline,
                    ranges: vec![test_range(10, 20)],
                    name: Some(names.intern("inner".to_string())),
                    children: Vec::new(),
                }],
            }],
            &[],
        );

        assert_eq!(segments.len(), 3);
        assert_eq!(
            frame_names(&names, &segments[0].frames),
            vec!["outer".to_string()]
        );
        assert_eq!(
            frame_names(&names, &segments[1].frames),
            vec!["outer".to_string(), "inner".to_string()]
        );
        assert_eq!(
            frame_names(&names, &segments[2].frames),
            vec!["outer".to_string()]
        );
        assert!(Arc::ptr_eq(&segments[0].frames, &segments[2].frames));
        assert!(!Arc::ptr_eq(&segments[0].frames, &segments[1].frames));
    }

    #[test]
    fn flattened_dwarf_lookup_keeps_inline_and_base_symbol_rules() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(
            &[PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Subprogram,
                ranges: vec![test_range(0, 100)],
                name: Some(names.intern("outer".to_string())),
                children: vec![PerfDwarfDieNode {
                    kind: PerfDwarfDieKind::Inline,
                    ranges: vec![test_range(10, 20)],
                    name: Some(names.intern("inner".to_string())),
                    children: Vec::new(),
                }],
            }],
            &[],
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 15, Some("outer"))
                .map(|frames| frames.frames),
            Some(vec!["inner".to_string(), "outer".to_string()])
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 5, Some("outer")),
            None
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 5, Some("different_base")),
            None
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 150, None),
            None
        );
    }

    #[test]
    fn flattened_dwarf_lookup_marks_single_inline_die_as_inline_like_perf_libdw() {
        // tools/perf/util/libdw.c cu_walk_functions_at() invokes
        // libdw_a2l_cb() for each matching DW_TAG_inlined_subroutine, even
        // when there is only one printable inline DIE. srcline.c
        // new_inline_sym() then marks that symbol as inlined, so script output
        // suppresses the DSO and appends "(inlined)".
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(
            &[PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Subprogram,
                ranges: vec![test_range(0, 100)],
                name: None,
                children: vec![PerfDwarfDieNode {
                    kind: PerfDwarfDieKind::Inline,
                    ranges: vec![test_range(10, 20)],
                    name: Some(names.intern("next_remote_task".to_string())),
                    children: Vec::new(),
                }],
            }],
            &[],
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 15, Some("base_symbol")),
            Some(PerfDwarfFrameNames {
                frames: vec!["next_remote_task".to_string()],
                has_inline_frames: true,
            })
        );
    }

    #[test]
    fn flattened_dwarf_lookup_keeps_symtab_base_when_only_realfunc_name_differs_like_perf() {
        // tools/perf/util/libdw.c libdw__addr2line() returns before
        // cu_walk_functions_at() when dwfl_module_getsrc() cannot find source
        // line information. That leaves perf script printing the original
        // symtab symbol, as in the verified `float`/`f` fixture.
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(
            &[PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Subprogram,
                ranges: vec![test_range(0, 100)],
                name: Some(names.intern("next_remote_task".to_string())),
                children: Vec::new(),
            }],
            &[],
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(
                &segments,
                &names.names,
                15,
                Some(
                    "next_remote_task<impl tokio::runtime::scheduler::multi_thread::handle::Handle>"
                ),
            ),
            None
        );
    }

    #[test]
    fn flattened_dwarf_lookup_replaces_realfunc_name_when_source_line_exists_like_perf_libdw() {
        // When libdw has a source line, tools/perf/util/libdw.c calls
        // cu_walk_functions_at(). The first callback is the real function from
        // die_find_realfunc(), and srcline.c new_inline_sym() marks it inlined
        // when dwarf_diename(die) differs from the symtab base symbol.
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(
            &[PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Subprogram,
                ranges: vec![test_range(0, 100)],
                name: Some(names.intern("default_read_to_end<std::fs::File>".to_string())),
                children: vec![PerfDwarfDieNode {
                    kind: PerfDwarfDieKind::Inline,
                    ranges: vec![test_range(40, 50)],
                    name: Some(names.intern("read".to_string())),
                    children: Vec::new(),
                }],
            }],
            &[test_range(0, 100)],
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(
                &segments,
                &names.names,
                15,
                Some("std::io::default_read_to_end::<std::fs::File>"),
            ),
            Some(PerfDwarfFrameNames {
                frames: vec!["default_read_to_end<std::fs::File>".to_string()],
                has_inline_frames: true,
            })
        );
    }

    #[test]
    fn symbol_parity_single_function_die_with_line_replaces_base_without_children() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(
            &[PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Subprogram,
                ranges: vec![test_range(0, 100)],
                name: Some(names.intern("f".to_string())),
                children: Vec::new(),
            }],
            &[test_range(0, 100)],
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 15, Some("float")),
            Some(PerfDwarfFrameNames {
                frames: vec!["f".to_string()],
                has_inline_frames: true,
            })
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 15, Some("f")),
            None
        );
    }

    #[test]
    fn symbol_parity_realfunc_line_guard_checks_the_lookup_address() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(
            &[PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Subprogram,
                ranges: vec![test_range(0, 100)],
                name: Some(names.intern("f".to_string())),
                children: vec![PerfDwarfDieNode {
                    kind: PerfDwarfDieKind::Inline,
                    ranges: vec![test_range(70, 80)],
                    name: Some(names.intern("child".to_string())),
                    children: Vec::new(),
                }],
            }],
            &[test_range(20, 30), test_range(50, 60)],
        );
        for address in [0, 19, 30, 49, 60, 69, 80, 99, 100] {
            assert_eq!(
                perf_dwarf_frame_names_from_index(&segments, &names.names, address, Some("float")),
                None,
                "address {address}"
            );
        }
        for address in [20, 29, 50, 59] {
            assert_eq!(
                perf_dwarf_frame_names_from_index(&segments, &names.names, address, Some("float")),
                Some(PerfDwarfFrameNames {
                    frames: vec!["f".to_string()],
                    has_inline_frames: true,
                }),
                "address {address}"
            );
        }
    }

    #[test]
    fn flattened_dwarf_lookup_keeps_fn0_die_name_because_sentinel_is_cmd_addr2line_protocol() {
        // tools/perf/util/addr2line.c read_addr2line_record() checks the
        // address/sentinel line returned by the external GNU addr2line child.
        // A DW_AT_name value of `fn0` is not itself a sentinel, so the flattened
        // DWARF/libdw-style path must keep it. Perf parity for the
        // entropy_burn fixture requires modeling the external protocol at a
        // higher layer, not special-casing this DIE name here.
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(
            &[PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Subprogram,
                ranges: vec![test_range(0, 100)],
                name: Some(names.intern("fn0".to_string())),
                children: vec![PerfDwarfDieNode {
                    kind: PerfDwarfDieKind::Inline,
                    ranges: vec![test_range(10, 20)],
                    name: Some(names.intern("mix".to_string())),
                    children: Vec::new(),
                }],
            }],
            &[],
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 15, Some("fn0"))
                .map(|frames| frames.frames),
            Some(vec!["mix".to_string(), "fn0".to_string()])
        );
    }

    #[test]
    fn flattened_dwarf_lookup_keeps_nonfirst_short_rust_names_like_perf_libdw() {
        // tools/perf/util/libdw.c libdw_a2l_cb() passes dwarf_diename(die) to
        // srcline.c new_inline_sym(); the GNU zero-address sentinel check in
        // tools/perf/util/addr2line.c read_addr2line_record() applies only to
        // the external addr2line child protocol's address/sentinel line, not
        // to libdw DIE names. Real Rust functions named `eq` therefore remain
        // inline frames instead of terminating the chain.
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(
            &[PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Subprogram,
                ranges: vec![test_range(0, 100)],
                name: Some(names.intern("fmt".to_string())),
                children: vec![PerfDwarfDieNode {
                    kind: PerfDwarfDieKind::Inline,
                    ranges: vec![test_range(10, 90)],
                    name: Some(names.intern("eq".to_string())),
                    children: vec![PerfDwarfDieNode {
                        kind: PerfDwarfDieKind::Inline,
                        ranges: vec![test_range(20, 80)],
                        name: Some(names.intern("eq<anstyle::color::Color>".to_string())),
                        children: Vec::new(),
                    }],
                }],
            }],
            &[],
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 30, Some("outer_base"))
                .map(|frames| frames.frames),
            Some(vec![
                "eq<anstyle::color::Color>".to_string(),
                "eq".to_string(),
                "fmt".to_string(),
            ])
        );
    }

    #[test]
    fn flattened_dwarf_lookup_keeps_symtab_base_for_standalone_fn0_like_perf() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(
            &[PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Subprogram,
                ranges: vec![test_range(0, 100)],
                name: Some(names.intern("fn0".to_string())),
                children: Vec::new(),
            }],
            &[],
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 5, Some("different_base")),
            None
        );
    }

    #[test]
    fn flattened_dwarf_lookup_ignores_unnamed_intermediate_nodes() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(
            &[PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Subprogram,
                ranges: vec![test_range(0, 100)],
                name: Some(names.intern("outer".to_string())),
                children: vec![PerfDwarfDieNode {
                    kind: PerfDwarfDieKind::Inline,
                    ranges: vec![test_range(20, 80)],
                    name: None,
                    children: vec![PerfDwarfDieNode {
                        kind: PerfDwarfDieKind::Inline,
                        ranges: vec![test_range(30, 40)],
                        name: Some(names.intern("inner".to_string())),
                        children: Vec::new(),
                    }],
                }],
            }],
            &[],
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 35, Some("outer"))
                .map(|frames| frames.frames),
            Some(vec!["inner".to_string(), "outer".to_string()])
        );
    }

    #[test]
    fn flattened_dwarf_lookup_prefers_first_overlapping_inline_sibling_like_perf_die_find_child() {
        // perf util/dwarf-aux.c die_find_child walks siblings in DIE order and
        // stops at the first DW_TAG_inlined_subroutine whose range contains
        // the address. A later overlapping sibling must not win just because
        // its flattened range has the same start address.
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(
            &[PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Subprogram,
                ranges: vec![test_range(0, 100)],
                name: Some(names.intern("outer".to_string())),
                children: vec![
                    PerfDwarfDieNode {
                        kind: PerfDwarfDieKind::Inline,
                        ranges: vec![test_range(10, 30)],
                        name: Some(names.intern("first".to_string())),
                        children: Vec::new(),
                    },
                    PerfDwarfDieNode {
                        kind: PerfDwarfDieKind::Inline,
                        ranges: vec![test_range(10, 30)],
                        name: Some(names.intern("second".to_string())),
                        children: Vec::new(),
                    },
                ],
            }],
            &[],
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 20, Some("outer"))
                .map(|frames| frames.frames),
            Some(vec!["first".to_string(), "outer".to_string()])
        );
    }

    #[test]
    fn flattened_dwarf_ranges_do_not_treat_nested_subprograms_as_inline_frames_like_perf() {
        // perf util/dwarf-aux.c cu_walk_functions_at() chooses one
        // DW_TAG_subprogram with die_find_realfunc(), then subsequent
        // die_find_child() searches only accept DW_TAG_inlined_subroutine.
        // A nested DW_TAG_subprogram must not become part of the inline chain.
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(
            &[PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Subprogram,
                ranges: vec![test_range(0, 100)],
                name: Some(names.intern("outer".to_string())),
                children: vec![
                    PerfDwarfDieNode {
                        kind: PerfDwarfDieKind::Subprogram,
                        ranges: vec![test_range(10, 90)],
                        name: Some(names.intern("nested_subprogram".to_string())),
                        children: vec![PerfDwarfDieNode {
                            kind: PerfDwarfDieKind::Inline,
                            ranges: vec![test_range(20, 30)],
                            name: Some(names.intern("nested_inline".to_string())),
                            children: Vec::new(),
                        }],
                    },
                    PerfDwarfDieNode {
                        kind: PerfDwarfDieKind::Inline,
                        ranges: vec![test_range(40, 50)],
                        name: Some(names.intern("real_inline".to_string())),
                        children: Vec::new(),
                    },
                ],
            }],
            &[],
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 25, Some("outer")),
            None
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 45, Some("outer"))
                .map(|frames| frames.frames),
            Some(vec!["real_inline".to_string(), "outer".to_string()])
        );
    }

    #[test]
    fn perf_symbol_resolver_retains_loaded_address_translation_after_unlink_like_perf() {
        // perf symbol-elf.c:dso__load_sym stores the text offset in the DSO;
        // map.c:map__rip_2objdump reuses it, and symbol.c:dso__load does not
        // reload an already-loaded DSO. Translation and symbol data must
        // have the same lifetime rather than reopening the ELF every batch.
        for inline in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("library.so");
            let bytes = elf_with_dynamic_text_symbol(b"read", 0x1000, 46);
            let object = object::File::parse(bytes.as_slice()).unwrap();
            let file_offset = object.segments().next().unwrap().file_range().0;
            std::fs::write(&path, &bytes).unwrap();
            let resolver =
                super::PerfSymbolResolver::from_object_resolver(RustAddr2lineResolver::new());
            let mut request = test_request(path.to_str().unwrap(), file_offset);
            let resolve = |request| {
                if inline {
                    resolver.resolve_frame_batch_with_metadata(&[request])
                } else {
                    resolver.resolve_base_frame_batch_with_metadata(&[request])
                }
                .unwrap()
            };
            assert_eq!(resolve(request.clone())[0].frames, ["read+0x0"]);
            std::fs::remove_file(&path).unwrap();
            request.relative_address += 1;
            assert_eq!(resolve(request)[0].frames, ["read+0x1"]);
        }
    }

    #[test]
    fn rust_addr2line_resolver_reuses_cached_object_metadata_across_batches() {
        let path = std::env::current_exe().expect("current test binary");
        let bytes = std::fs::read(&path).expect("current test binary bytes");
        let object = object::File::parse(bytes.as_slice()).expect("current test binary object");
        let addresses = object
            .symbols()
            .filter(|symbol| symbol.address() != 0 && symbol.kind() == object::SymbolKind::Text)
            .map(|symbol| symbol.address())
            .take(2)
            .collect::<Vec<_>>();
        if addresses.len() < 2 {
            return;
        }

        let resolver = RustAddr2lineResolver::new();
        resolver
            .resolve_frame_batch(&[SymbolRequest {
                path: path.clone(),
                relative_address: addresses[0],
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            }])
            .expect("first resolve");
        assert_eq!(resolver.cached_object_count(), 1);

        resolver
            .resolve_frame_batch(&[SymbolRequest {
                path,
                relative_address: addresses[1],
                kernel_mapping_range: None,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            }])
            .expect("second resolve");
        assert_eq!(resolver.cached_object_count(), 1);
    }

    #[test]
    fn symbol_frame_cache_resolve_ref_reuses_cached_frame_slice() {
        let resolver = CountingFrameResolver::new(vec![vec!["one".to_string(), "two".to_string()]]);
        let mut cache = SymbolFrameCache::new(&resolver);
        let request = test_request("/bin/demo", 0x1234);

        let first_ptr = {
            let first = cache.resolve_ref(&request).expect("first resolve");
            assert_eq!(first, ["one".to_string(), "two".to_string()]);
            first.as_ptr()
        };

        let second_ptr = {
            let second = cache.resolve_ref(&request).expect("second resolve");
            assert_eq!(second, ["one".to_string(), "two".to_string()]);
            second.as_ptr()
        };

        assert_eq!(first_ptr, second_ptr);
        assert_eq!(resolver.calls.get(), 1);
    }

    #[test]
    fn symbol_frame_cache_prefetch_many_warms_cache_without_re_resolving() {
        let resolver = CountingFrameResolver::new(vec![vec!["frame".to_string()]]);
        let mut cache = SymbolFrameCache::new(&resolver);
        let request = test_request("/bin/demo", 0x1234);

        cache
            .prefetch_many(std::slice::from_ref(&request))
            .expect("prefetch frames");
        assert_eq!(resolver.calls.get(), 1);

        let frames = cache
            .resolve_ref(&request)
            .expect("resolve from prefetched cache");
        assert_eq!(frames, ["frame".to_string()]);
        assert_eq!(resolver.calls.get(), 1);
    }

    #[test]
    fn symbol_frame_cache_resolve_mapping_ref_reuses_cached_frame_slice() {
        let resolver = CountingFrameResolver::new(vec![vec!["one".to_string(), "two".to_string()]]);
        let mut cache = SymbolFrameCache::new(&resolver);
        let mapping = test_mapping_ref("/bin/demo", 0x1234);

        let first_ptr = {
            let first = cache.resolve_mapping_ref(&mapping).expect("first resolve");
            assert_eq!(first, ["one".to_string(), "two".to_string()]);
            first.as_ptr()
        };

        let second_ptr = {
            let second = cache.resolve_mapping_ref(&mapping).expect("second resolve");
            assert_eq!(second, ["one".to_string(), "two".to_string()]);
            second.as_ptr()
        };

        assert_eq!(first_ptr, second_ptr);
        assert_eq!(resolver.calls.get(), 1);
    }

    #[test]
    fn symbol_frame_cache_base_and_inline_views_borrow_unmodified_names() {
        let resolver =
            CountingFrameResolver::new(vec![vec!["handler+0x2a".into(), "inner".into()]]);
        let mut cache = SymbolFrameCache::new(&resolver);
        let mapping = test_mapping_ref("/bin/demo", 0x1234);
        assert!(!cache.mapping_ref_cached(&mapping, true));
        let first = cache.resolve_mapping_ref(&mapping).unwrap();
        assert_eq!(first, ["handler+0x2a", "inner"]);
        let pointer = first.as_ptr();
        assert!(cache.mapping_ref_cached(&mapping, true));
        assert_eq!(
            cache.resolve_mapping_ref(&mapping).unwrap().as_ptr(),
            pointer
        );
        assert_eq!(resolver.calls.get(), 1);
        // Base-only and inline resolution are distinct views of an address.
        assert!(!cache.mapping_ref_cached(&mapping, false));
        assert_eq!(
            cache.resolve_base_mapping_ref(&mapping).unwrap(),
            ["handler+0x2a", "inner"]
        );
        assert!(cache.mapping_ref_cached(&mapping, false));
    }

    #[test]
    fn symbol_frame_cache_preserves_all_inline_names_and_duplicate_hops_for_renderers() {
        let names = ["entry::call", "fn0", "mix", "fn0", "handler+0x2a"];
        let resolver =
            CountingFrameResolver::new(vec![names.iter().map(|name| (*name).into()).collect()]);
        let mut cache = SymbolFrameCache::new(&resolver);
        assert_eq!(
            cache
                .resolve_mapping_ref(&test_mapping_ref("/bin/demo", 0x1234))
                .unwrap(),
            names
        );
    }

    #[test]
    fn unresolved_symbol_cache_does_not_store_output_specific_module_labels() {
        for (path, address) in [
            ("/usr/lib/libdemo.so", 0x1234),
            ("[vdso]", 0x10),
            ("/tmp/semi;line\nname", 0x10),
            ("[unknown]", 0x10),
            ("[kernel.kallsyms]", u64::MAX - 1),
        ] {
            let resolver = CountingFrameResolver::new(vec![Vec::new()]);
            let mut cache = SymbolFrameCache::new(&resolver);
            let mapping = test_mapping_ref(path, address);
            assert!(cache.resolve_mapping_ref(&mapping).unwrap().is_empty());
            assert!(cache.mapping_ref_cached(&mapping, true));
            assert_eq!(resolver.calls.get(), 1);
            assert_eq!(cache.resolved_by_mapping.frames.capacity(), 0);
            assert_eq!(
                cache.resolve_mapping_ref_with_offset(&mapping).unwrap(),
                (&[][..], None, false, false)
            );
            assert_eq!(
                cache
                    .resolve_mapping_ref_with_base_symbol(&mapping)
                    .unwrap(),
                None
            );
            assert!(cache.resolve_base_mapping_ref(&mapping).unwrap().is_empty());
            assert_eq!(cache.resolved_base_by_mapping.frames.capacity(), 0);
            assert_eq!(resolver.calls.get(), 2);
        }
    }

    #[test]
    fn user_mapping_cache_buckets_keep_only_compact_key_and_slot_index() {
        fn bucket_bytes<K, V>(_: &super::FxHashMap<K, V>) -> usize {
            std::mem::size_of::<(K, V)>()
        }
        let resolver = CountingFrameResolver::new(vec![Vec::new()]);
        let cache = SymbolFrameCache::new(&resolver);
        assert!(
            bucket_bytes(&cache.resolved_by_mapping.user.by_source)
                <= 2 * std::mem::size_of::<u64>()
        );
        let addresses = super::FxHashMap::<u64, usize>::default();
        assert!(bucket_bytes(&addresses) <= 2 * std::mem::size_of::<u64>());
    }

    fn cached_table_frames(label: String, offset: u64) -> super::CachedMappingFrames {
        let literal_end = crate::folded::inferno_perf_raw_function_literal_end(&label);
        super::CachedMappingFrames {
            revision: 0,
            frames: vec![label],
            literal_ends: vec![literal_end],
            has_base_symbol: true,
            render_mode: super::SymbolFrameRenderMode::Direct,
            has_inline_frames: false,
            has_non_inline_base_frame: true,
            base_offset: Some(offset),
        }
    }

    fn empty_cached_table_frames() -> super::CachedMappingFrames {
        super::CachedMappingFrames {
            revision: 0,
            frames: Vec::new(),
            literal_ends: Vec::new(),
            has_base_symbol: false,
            render_mode: super::SymbolFrameRenderMode::Direct,
            has_inline_frames: false,
            has_non_inline_base_frame: false,
            base_offset: None,
        }
    }

    fn identity_test_mappings() -> crate::perfdata::mappings::MmapTable {
        let mut mappings = crate::perfdata::mappings::MmapTable::default();
        for (start, path) in [
            (0, "/bin/demo"),
            (0x1_0000, "/bin/other"),
            (0xffff_ffff_8000_0000, "[kernel.kallsyms]"),
        ] {
            mappings.insert_mmap(crate::perfdata::records::MmapRecord {
                pid: 1,
                tid: 1,
                start,
                len: 0x1_0000,
                pgoff: 0,
                path: path.into(),
            });
        }
        mappings
    }

    #[test]
    fn mapping_projection_identity_optional_result_layout() {
        assert_eq!(
            (
                std::mem::size_of::<Option<super::MappingFramesIdentity>>(),
                std::mem::size_of::<
                    Option<(
                        Option<super::MappingFramesIdentity>,
                        &super::CachedMappingFrames
                    )>,
                >(),
            ),
            (8, 16),
        );
    }

    #[test]
    fn mapping_projection_identity_survives_frame_vector_growth() {
        assert_eq!(std::mem::size_of::<super::MappingFramesIdentity>(), 8);
        let mappings = identity_test_mappings();
        let mut hint = crate::perfdata::mappings::MappingResolveCache::default();
        let resolver = CountingFrameResolver::new(Vec::new());
        for inline in [false, true] {
            let mut cache = SymbolFrameCache::new(&resolver);
            let mapping = mappings.resolve_frame_cached(1, 42, &mut hint).unwrap();
            let key = super::mapping_frame_key(&mapping.resolved_ref());
            let table = if inline {
                &mut cache.resolved_by_mapping
            } else {
                &mut cache.resolved_base_by_mapping
            };
            table.insert(key, cached_table_frames("first".into(), 1));
            let capacity = table.frames.capacity();
            let identity = cache
                .cached_mapping_frames_with_identity(&mapping, inline)
                .unwrap()
                .0
                .unwrap();
            let mut identities = super::FxHashSet::default();
            identities.insert(identity);
            for address in 43..4096 {
                let next = mappings
                    .resolve_frame_cached(1, address, &mut hint)
                    .unwrap();
                let table = if inline {
                    &mut cache.resolved_by_mapping
                } else {
                    &mut cache.resolved_base_by_mapping
                };
                table.insert(
                    super::mapping_frame_key(&next.resolved_ref()),
                    cached_table_frames("next".into(), address),
                );
                assert!(
                    identities.insert(
                        cache
                            .cached_mapping_frames_with_identity(&next, inline)
                            .unwrap()
                            .0
                            .unwrap()
                    )
                );
            }
            let table = if inline {
                &cache.resolved_by_mapping
            } else {
                &cache.resolved_base_by_mapping
            };
            assert!(table.frames.capacity() > capacity);
            let lookups = cache.mapping_frame_lookup_count();
            let (after, frames) = cache
                .cached_mapping_frames_with_identity(&mapping, inline)
                .unwrap();
            assert_eq!(after, Some(identity));
            assert_eq!(frames.frames, ["first"]);
            assert!(std::ptr::eq(
                frames,
                cache.cached_mapping_frames(&mapping, inline).unwrap()
            ));
            assert_eq!(cache.mapping_frame_lookup_count() - lookups, 2);
        }
    }

    #[test]
    fn mapping_projection_identity_separates_inline_base_and_mapping_keys() {
        let mappings = identity_test_mappings();
        let mut hint = crate::perfdata::mappings::MappingResolveCache::default();
        let resolver = CountingFrameResolver::new(Vec::new());
        let mut cache = SymbolFrameCache::new(&resolver);
        let mut identities = super::FxHashSet::default();
        for inline in [false, true] {
            for address in [42, 43, 0x1_002a, 0xffff_ffff_8000_002a] {
                let mapping = mappings
                    .resolve_frame_cached(1, address, &mut hint)
                    .unwrap();
                assert!(
                    cache
                        .cached_mapping_frames_with_identity(&mapping, inline)
                        .is_none()
                );
                let table = if inline {
                    &mut cache.resolved_by_mapping
                } else {
                    &mut cache.resolved_base_by_mapping
                };
                table.insert(
                    super::mapping_frame_key(&mapping.resolved_ref()),
                    cached_table_frames("same-label".into(), 0),
                );
                assert!(
                    identities.insert(
                        cache
                            .cached_mapping_frames_with_identity(&mapping, inline)
                            .unwrap()
                            .0
                            .unwrap()
                    )
                );
            }
        }
        assert_eq!(identities.len(), 8);
    }

    #[test]
    fn mapping_projection_identity_changes_on_overwrite_and_negative_transitions() {
        let mappings = identity_test_mappings();
        let mut hint = crate::perfdata::mappings::MappingResolveCache::default();
        let resolver = CountingFrameResolver::new(Vec::new());
        for inline in [false, true] {
            for address in [42, 0xffff_ffff_8000_002a] {
                let mut cache = SymbolFrameCache::new(&resolver);
                let mapping = mappings
                    .resolve_frame_cached(1, address, &mut hint)
                    .unwrap();
                let key = super::mapping_frame_key(&mapping.resolved_ref());
                let mut identities = super::FxHashSet::default();
                for label in ["first", "replacement", "replacement", "revived"] {
                    let table = if inline {
                        &mut cache.resolved_by_mapping
                    } else {
                        &mut cache.resolved_base_by_mapping
                    };
                    table.insert(key, cached_table_frames(label.into(), 1));
                    assert_eq!(table.frames.len(), 1);
                    let (identity, frames) = cache
                        .cached_mapping_frames_with_identity(&mapping, inline)
                        .unwrap();
                    assert!(identities.insert(identity.unwrap()));
                    assert_eq!(frames.frames, [label]);
                    if label == "first" || label == "revived" {
                        let table = if inline {
                            &mut cache.resolved_by_mapping
                        } else {
                            &mut cache.resolved_base_by_mapping
                        };
                        table.insert(key, empty_cached_table_frames());
                        let (identity, frames) = cache
                            .cached_mapping_frames_with_identity(&mapping, inline)
                            .unwrap();
                        assert_eq!(identity, None);
                        assert!(frames.is_fully_unresolved());
                    }
                }
            }
        }
    }

    #[test]
    fn mapping_projection_identity_preserves_each_empty_frame_metadata_field() {
        let mappings = identity_test_mappings();
        let mut hint = crate::perfdata::mappings::MappingResolveCache::default();
        let resolver = CountingFrameResolver::new(Vec::new());
        let mut cache = SymbolFrameCache::new(&resolver);
        for inline in [false, true] {
            for address in 0..4 {
                let mapping = mappings
                    .resolve_frame_cached(1, address, &mut hint)
                    .unwrap();
                let mut metadata = empty_cached_table_frames();
                match address {
                    0 => metadata.has_base_symbol = true,
                    1 => metadata.has_inline_frames = true,
                    2 => metadata.has_non_inline_base_frame = true,
                    _ => metadata.base_offset = Some(0),
                }
                let table = if inline {
                    &mut cache.resolved_by_mapping
                } else {
                    &mut cache.resolved_base_by_mapping
                };
                table.insert(super::mapping_frame_key(&mapping.resolved_ref()), metadata);
                let (identity, frames) = cache
                    .cached_mapping_frames_with_identity(&mapping, inline)
                    .unwrap();
                assert!(identity.is_some());
                assert!(frames.frames.is_empty());
                assert!(!std::ptr::eq(
                    frames,
                    &raw const super::UNRESOLVED_MAPPING_FRAMES
                ));
                assert_eq!(frames.has_base_symbol, address == 0);
                assert_eq!(frames.has_inline_frames, address == 1);
                assert_eq!(frames.has_non_inline_base_frame, address == 2);
                assert_eq!(frames.base_offset, (address == 3).then_some(0));
            }
        }
    }

    #[test]
    fn mapping_projection_identity_canonicalizes_terminal_sources_and_address_gaps() {
        let mappings = identity_test_mappings();
        let mut hint = crate::perfdata::mappings::MappingResolveCache::default();
        let resolver = UnavailableObjectResolver;
        let mut cache = SymbolFrameCache::new(&resolver);
        for address in [42, 0x1_002a] {
            let mapping = mappings
                .resolve_frame_cached(1, address, &mut hint)
                .unwrap();
            cache.resolve_mapping_ref(&mapping.resolved_ref()).unwrap();
        }
        for inline in [false, true] {
            for address in [0, 42, 4096, 0x1_0000, 0x1_002a, 0x1_1000] {
                let mapping = mappings
                    .resolve_frame_cached(1, address, &mut hint)
                    .unwrap();
                let (identity, frames) = cache
                    .cached_mapping_frames_with_identity(&mapping, inline)
                    .unwrap();
                assert_eq!(identity, None);
                assert!(std::ptr::eq(
                    frames,
                    &raw const super::UNRESOLVED_MAPPING_FRAMES
                ));
            }
            let table = if inline {
                &mut cache.resolved_by_mapping
            } else {
                &mut cache.resolved_base_by_mapping
            };
            assert_eq!(table.user.len(), 0);
            assert_eq!(table.frames.capacity(), 0);
            let mapping = mappings
                .resolve_frame_cached(1, 0xffff_ffff_8000_002a, &mut hint)
                .unwrap();
            table.insert(
                super::mapping_frame_key(&mapping.resolved_ref()),
                empty_cached_table_frames(),
            );
            let (identity, frames) = cache
                .cached_mapping_frames_with_identity(&mapping, inline)
                .unwrap();
            assert_eq!(identity, None);
            assert!(std::ptr::eq(
                frames,
                &raw const super::UNRESOLVED_MAPPING_FRAMES
            ));
            let unseen = mappings
                .resolve_frame_cached(1, 0xffff_ffff_8000_002b, &mut hint)
                .unwrap();
            assert!(
                cache
                    .cached_mapping_frames_with_identity(&unseen, inline)
                    .is_none()
            );
        }
        let gap_resolver = CountingFrameResolver::new(vec![Vec::new()]);
        let mut gaps = SymbolFrameCache::new(&gap_resolver);
        let mapping = mappings.resolve_frame_cached(1, 42, &mut hint).unwrap();
        gaps.resolve_mapping_ref(&mapping.resolved_ref()).unwrap();
        assert_eq!(
            gaps.cached_mapping_frames_with_identity(&mapping, true)
                .unwrap()
                .0,
            None
        );
        let unseen = mappings.resolve_frame_cached(1, 43, &mut hint).unwrap();
        assert!(
            gaps.cached_mapping_frames_with_identity(&unseen, true)
                .is_none()
        );
    }

    #[test]
    fn cached_mapping_literal_ranges_preserve_frames_and_keep_render_modes_separate() {
        let names: Vec<String> = [
            "literal",
            "literal+0x2a",
            "outer->inner",
            "with$variable",
            "with;separator",
            "with\rnewline",
            "with\nnewline",
            "crate::name::h0123456789abcdef",
            "function(param)",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let resolver = CountingFrameResolver::new(vec![names.clone()]);
        let mut cache = SymbolFrameCache::new(&resolver);
        let mapping = test_mapping_ref("/bin/demo", 0x1234);
        for inline in [true, false] {
            cache
                .prefetch_mapping_refs_with_mode([&mapping], inline)
                .unwrap();
            let table = if inline {
                &cache.resolved_by_mapping
            } else {
                &cache.resolved_base_by_mapping
            };
            let cached = table.get(&super::mapping_frame_key(&mapping)).unwrap();
            assert_eq!(cached.frames, names);
            assert_eq!(
                cached.literal_ends,
                [
                    Some(7),
                    Some(7),
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(11),
                    None
                ]
            );
        }
        assert_eq!(resolver.calls.get(), 2);
        assert!(super::UNRESOLVED_MAPPING_FRAMES.literal_ends.is_empty());
    }

    #[test]
    fn fully_unresolved_mapping_entries_need_no_frame_storage() {
        let mut table = super::MappingFrameTable::default();
        for relative_address in 0..4096 {
            for kernel_mapping_range in [None, Some((0x1000, 0x2000))] {
                let key = super::MappingFrameKey {
                    symbol_source_id: 7,
                    relative_address,
                    kernel_mapping_range,
                };
                table.insert(key, empty_cached_table_frames());
                assert!(table.get(&key).unwrap().frames.is_empty());
                assert!(!table.get(&key).unwrap().has_base_symbol);
            }
        }
        assert_eq!(table.user.len(), 4096);
        assert_eq!(table.kernel.len(), 4096);
        assert_eq!(table.frames.len(), 0);
        assert_eq!(table.frames.capacity(), 0);
    }

    #[test]
    fn empty_frame_lists_keep_metadata_and_survive_negative_positive_transitions() {
        let mut table = super::MappingFrameTable::default();
        let key = super::MappingFrameKey {
            symbol_source_id: 7,
            relative_address: 42,
            kernel_mapping_range: None,
        };
        table.insert(key, empty_cached_table_frames());
        let mut metadata = empty_cached_table_frames();
        metadata.has_base_symbol = true;
        metadata.has_inline_frames = true;
        metadata.base_offset = Some(0);
        table.insert(key, metadata);
        let cached = table.get(&key).unwrap();
        assert!(cached.frames.is_empty());
        assert!(cached.has_base_symbol);
        assert!(cached.has_inline_frames);
        assert_eq!(cached.base_offset, Some(0));
        table.insert(key, cached_table_frames("live".into(), 9));
        assert_eq!(table.get(&key).unwrap().frames, ["live"]);
        table.insert(key, empty_cached_table_frames());
        assert!(table.get(&key).unwrap().frames.is_empty());
        assert!(!table.get(&key).unwrap().has_base_symbol);
        assert_eq!(table.get(&key).unwrap().base_offset, None);
        assert!(table.frames.iter().all(|entry| entry.frames.is_empty()));
        table.insert(key, cached_table_frames("replacement".into(), 3));
        assert_eq!(table.get(&key).unwrap().frames, ["replacement"]);
        assert_eq!(table.frames.len(), 1);
    }

    #[test]
    fn each_empty_frame_metadata_field_prevents_negative_slot_canonicalization() {
        let mut table = super::MappingFrameTable::default();
        for relative_address in 0..4 {
            let mut metadata = empty_cached_table_frames();
            match relative_address {
                0 => metadata.has_base_symbol = true,
                1 => metadata.has_inline_frames = true,
                2 => metadata.has_non_inline_base_frame = true,
                _ => metadata.base_offset = Some(0),
            }
            let key = super::MappingFrameKey {
                symbol_source_id: 7,
                relative_address,
                kernel_mapping_range: None,
            };
            table.insert(key, metadata);
            assert_ne!(table.slot(&key), Some(0));
            let cached = table.get(&key).unwrap();
            assert_eq!(cached.has_base_symbol, relative_address == 0);
            assert_eq!(cached.has_inline_frames, relative_address == 1);
            assert_eq!(cached.has_non_inline_base_frame, relative_address == 2);
            assert_eq!(cached.base_offset, (relative_address == 3).then_some(0));
        }
        assert_eq!(table.frames.len(), 4);
    }

    #[test]
    fn user_cache_keeps_sparse_sources_and_addresses_separate_without_sparse_storage() {
        let mut table = super::UserFrameTable::default();
        for (source, address, slot) in [(7, 42, 1), (usize::MAX, 42, 2), (7, 43, 3)] {
            table.insert(source, address, slot);
        }
        assert_eq!(table.slot(7, 42), Some(1));
        assert_eq!(table.slot(usize::MAX, 42), Some(2));
        assert_eq!(table.slot(7, 43), Some(3));
        assert_eq!(table.slot(8, 42), None);
        assert_eq!(table.slot(7, 44), None);
        assert_eq!(table.sources.len(), 2);
        assert_eq!(table.by_source.len(), 2);
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn same_source_address_lookups_reuse_source_hint_after_a_source_switch() {
        let mut table = super::UserFrameTable::default();
        for address in 0..256 {
            table.insert(7, address, usize::try_from(address).unwrap());
        }
        table.insert(9, 0, 1);
        let searches = table.source_searches.get();
        for address in 0..256 {
            assert_eq!(
                table.slot(7, address),
                Some(usize::try_from(address).unwrap())
            );
        }
        assert_eq!(table.source_searches.get() - searches, 1);
        assert_eq!(table.slot(9, 0), Some(1));
        assert_eq!(table.slot(7, 0), Some(0));
        assert_eq!(table.source_searches.get() - searches, 3);
    }

    #[test]
    fn warm_user_frame_lookups_skip_source_state_and_duplicate_ip_checks() {
        let mut table = super::UserFrameTable::default();
        table.insert(usize::MAX, 0, 11);
        table.insert(usize::MAX, u64::MAX, 0);
        table.insert(7, 0, 22);
        assert_eq!(table.slot(usize::MAX, 0), Some(11));
        let state_checks = table.source_state_checks.get();
        let hint_checks = table.address_hint_checks.get();
        let source_searches = table.source_searches.get();
        let address_searches = table.address_searches.get();
        for (address, expected) in [(u64::MAX, Some(0)), (42, None), (0, Some(11))] {
            assert_eq!(table.slot(usize::MAX, address), expected);
        }
        assert_eq!(table.source_state_checks.get(), state_checks);
        assert_eq!(table.address_hint_checks.get(), hint_checks);
        assert_eq!(table.source_searches.get(), source_searches);
        assert_eq!(table.address_searches.get() - address_searches, 3);

        // A source switch still validates availability and reuses its saved IP.
        assert_eq!(table.slot(7, 0), Some(22));
        let address_searches = table.address_searches.get();
        assert_eq!(table.slot(usize::MAX, 0), Some(11));
        assert_eq!(table.source_state_checks.get() - state_checks, 2);
        assert_eq!(table.address_hint_checks.get() - hint_checks, 2);
        assert_eq!(table.address_searches.get(), address_searches);
    }

    #[test]
    fn warm_user_frame_lookups_invalidate_mutations_and_survive_table_growth() {
        let mut table = super::UserFrameTable::default();
        table.insert(usize::MAX, 0, 11);
        table.insert(usize::MAX, u64::MAX, 0);
        assert_eq!(table.slot(usize::MAX, 0), Some(11));
        assert_eq!(table.slot(usize::MAX, 42), None);

        // A cached miss must become visible at a different IP on the warm path.
        table.insert(usize::MAX, 42, 12);
        assert_eq!(table.slot(usize::MAX, 0), Some(11));
        assert_eq!(table.slot(usize::MAX, 42), Some(12));
        table.insert(usize::MAX, 42, 0);
        assert_eq!(table.slot(usize::MAX, u64::MAX), Some(0));
        assert_eq!(table.slot(usize::MAX, 42), Some(0));
        table.insert(usize::MAX, u64::MAX, 13);
        assert_eq!(table.slot(usize::MAX, 0), Some(11));
        assert_eq!(table.slot(usize::MAX, u64::MAX), Some(13));

        let index = table.by_source[&usize::MAX];
        let source_capacity = table.sources.capacity();
        let address_capacity = table.sources[index].by_address.capacity();
        for source in 0..256 {
            table.insert(source, 0, source + 1);
            table.insert(usize::MAX, u64::try_from(source).unwrap() + 100, source + 1);
        }
        assert!(table.sources.capacity() > source_capacity);
        assert!(table.sources[index].by_address.capacity() > address_capacity);
        assert_eq!(table.by_source[&usize::MAX], index);
        assert_eq!(table.slot(usize::MAX, 0), Some(11));
        assert_eq!(table.slot(usize::MAX, u64::MAX), Some(13));
        assert_eq!(table.slot(7, 0), Some(8));
        assert_eq!(table.slot(usize::MAX, 42), Some(0));
        assert_eq!(table.slot(usize::MAX, 100), Some(1));

        // Clearing an unavailable source drops every old IP and both hints.
        table.mark_unavailable(usize::MAX);
        assert_eq!(table.slot(usize::MAX, 0), Some(0));
        assert_eq!(table.slot(usize::MAX, u64::MAX), Some(0));
        assert_eq!(table.slot(7, 0), Some(8));
        assert_eq!(table.slot(usize::MAX, 42), Some(0));
        let source_count = table.sources.len();
        for slot in [0, 14, 15] {
            table.insert(usize::MAX, 42, slot);
            assert_eq!(table.slot(usize::MAX, 0), None);
            assert_eq!(table.slot(usize::MAX, 42), Some(slot));
            assert_eq!(table.slot(usize::MAX, u64::MAX), None);
            assert_eq!(table.slot(usize::MAX, 100), None);
            assert_eq!(table.slot(7, 0), Some(8));
            assert_eq!(table.slot(usize::MAX, 42), Some(slot));
            table.mark_unavailable(usize::MAX);
        }
        assert_eq!(table.sources.len(), source_count);
        assert_eq!(table.by_source[&usize::MAX], index);
    }

    #[test]
    fn repeated_user_frame_lookups_skip_source_storage_for_hits_negatives_and_misses() {
        // perf util/symbol.c:dso__find_symbol (575-583) reuses exact last hits.
        // Source identity and mutation invalidation must also remain explicit.
        let mut table = super::UserFrameTable::default();
        table.insert(7, 0, 11);
        table.insert(7, u64::MAX, 0);
        for (address, expected) in [(0, Some(11)), (u64::MAX, Some(0)), (42, None)] {
            assert_eq!(table.slot(7, address), expected);
            let accesses = table.source_accesses.get();
            for _ in 0..256 {
                assert_eq!(table.slot(7, address), expected);
            }
            assert_eq!(table.source_accesses.get(), accesses);
        }
    }

    #[test]
    fn repeated_user_frame_lookups_skip_address_probes_for_hits_negatives_and_misses() {
        let mut table = super::UserFrameTable::default();
        for source in [0, 7, usize::MAX] {
            table.insert(source, 0, 11);
            table.insert(source, u64::MAX, 0);
        }
        for source in [0, 7, usize::MAX] {
            for (address, expected) in [(0, Some(11)), (u64::MAX, Some(0)), (42, None)] {
                assert_eq!(table.slot(source, address), expected);
                let searches = table.address_searches.get();
                for _ in 0..256 {
                    assert_eq!(table.slot(source, address), expected);
                }
                assert_eq!(table.address_searches.get(), searches);
            }
        }
        assert_eq!(table.address_searches.get(), 9);
    }

    #[test]
    fn user_frame_lookup_hint_reuses_address_after_intervening_sources() {
        for (address, expected) in [(0, Some(11)), (u64::MAX, Some(0)), (42, None)] {
            let mut table = super::UserFrameTable::default();
            for source in [0, 7, usize::MAX] {
                table.insert(source, 0, 11);
                table.insert(source, u64::MAX, 0);
            }
            for _ in 0..256 {
                for source in [0, 7, usize::MAX] {
                    assert_eq!(table.slot(source, address), expected);
                }
            }
            assert_eq!(table.address_searches.get(), 3);
            assert_eq!(table.len(), 6);
        }
    }

    #[test]
    fn unavailable_user_frame_lookups_skip_source_storage_for_every_address() {
        let mut table = super::UserFrameTable::default();
        table.insert(7, 42, 11);
        table.mark_unavailable(usize::MAX);
        let accesses = table.source_accesses.get();
        for address in (0..256).chain([u64::MAX]) {
            assert_eq!(table.slot(usize::MAX, address), Some(0));
        }
        assert_eq!(table.source_accesses.get(), accesses);
        assert_eq!(table.address_searches.get(), 0);
        assert_eq!(table.slot(7, 42), Some(11));
        assert_eq!(table.slot(usize::MAX, 0), Some(0));
        let accesses = table.source_accesses.get();
        assert_eq!(table.slot(usize::MAX, u64::MAX), Some(0));
        assert_eq!(table.source_accesses.get(), accesses);
    }

    #[test]
    fn user_frame_lookup_hint_tracks_mutations_source_switches_and_growth() {
        let mut table = super::UserFrameTable::default();
        assert_eq!(table.slot(usize::MAX, u64::MAX), None);
        table.insert(usize::MAX, 0, 0);
        assert_eq!(table.slot(usize::MAX, u64::MAX), None);
        table.insert(usize::MAX, u64::MAX, 11);
        assert_eq!(table.slot(usize::MAX, u64::MAX), Some(11));
        table.insert(usize::MAX, u64::MAX, 12);
        assert_eq!(table.slot(usize::MAX, u64::MAX), Some(12));
        table.insert(usize::MAX, u64::MAX, 0);
        assert_eq!(table.slot(usize::MAX, u64::MAX), Some(0));
        for source in 0..4096 {
            table.insert(source, u64::MAX, source + 1);
        }
        assert_eq!(table.slot(usize::MAX, u64::MAX), Some(0));
        table.mark_unavailable(usize::MAX);
        assert_eq!(table.slot(usize::MAX, 42), Some(0));
        assert_eq!(table.slot(0, u64::MAX), Some(1));
        assert_eq!(table.slot(usize::MAX, u64::MAX), Some(0));
        table.insert(usize::MAX, 42, 13);
        assert_eq!(table.slot(usize::MAX, 42), Some(13));
        assert_eq!(table.slot(usize::MAX, 0), None);
        assert_eq!(table.slot(usize::MAX, u64::MAX), None);
        table.mark_unavailable(usize::MAX);
        assert_eq!(table.slot(usize::MAX, 42), Some(0));
    }

    #[test]
    fn warm_mapping_frame_lookups_keep_inline_base_and_kernel_namespaces_separate() {
        let mappings = identity_test_mappings();
        let mut hint = crate::perfdata::mappings::MappingResolveCache::default();
        let resolver = CountingFrameResolver::new(Vec::new());
        let mut cache = SymbolFrameCache::new(&resolver);
        let first = mappings.resolve_frame_cached(1, 42, &mut hint).unwrap();
        let negative = mappings.resolve_frame_cached(1, 43, &mut hint).unwrap();
        let kernel = mappings
            .resolve_frame_cached(1, 0xffff_ffff_8000_002a, &mut hint)
            .unwrap();
        let first_key = super::mapping_frame_key(&first.resolved_ref());
        let negative_key = super::mapping_frame_key(&negative.resolved_ref());
        let kernel_key = super::mapping_frame_key(&kernel.resolved_ref());
        for (inline, label, offset) in [(false, "base", 7), (true, "inline", 8)] {
            let table = if inline {
                &mut cache.resolved_by_mapping
            } else {
                &mut cache.resolved_base_by_mapping
            };
            let mut frames = cached_table_frames(label.into(), offset);
            frames.has_inline_frames = inline;
            frames.has_non_inline_base_frame = !inline;
            table.insert(first_key, frames);
            table.insert(negative_key, empty_cached_table_frames());
            table.insert(kernel_key, cached_table_frames("kernel".into(), 9));
        }
        let base_identity = cache
            .cached_mapping_frames_with_identity(&first, false)
            .unwrap()
            .0
            .unwrap();
        let inline_identity = cache
            .cached_mapping_frames_with_identity(&first, true)
            .unwrap()
            .0
            .unwrap();
        assert_ne!(base_identity, inline_identity);
        for (inline, label, offset, identity) in [
            (false, "base", 7, base_identity),
            (true, "inline", 8, inline_identity),
            (false, "base", 7, base_identity),
        ] {
            let (negative_identity, frames) = cache
                .cached_mapping_frames_with_identity(&negative, inline)
                .unwrap();
            assert_eq!(negative_identity, None);
            assert!(frames.is_fully_unresolved());
            let (actual, frames) = cache
                .cached_mapping_frames_with_identity(&first, inline)
                .unwrap();
            assert_eq!(actual, Some(identity));
            assert_eq!(identity.projection_index().0, usize::from(inline));
            assert_eq!(frames.frames, [label]);
            assert_eq!(frames.literal_ends, [Some(label.len())]);
            assert_eq!(frames.base_offset, Some(offset));
            assert!(frames.has_base_symbol);
            assert_eq!(frames.has_inline_frames, inline);
            assert_eq!(frames.has_non_inline_base_frame, !inline);
            assert_eq!(
                cache.cached_mapping_frames(&kernel, inline).unwrap().frames,
                ["kernel"]
            );
        }

        cache
            .resolved_by_mapping
            .user
            .mark_unavailable(first_key.symbol_source_id);
        let unavailable = cache.cached_mapping_frames(&first, true).unwrap();
        assert!(unavailable.is_fully_unresolved());
        assert_eq!(
            cache.cached_mapping_frames(&first, false).unwrap().frames,
            ["base"]
        );
        let mut metadata = empty_cached_table_frames();
        metadata.has_inline_frames = true;
        metadata.base_offset = Some(0);
        cache.resolved_by_mapping.insert(negative_key, metadata);
        assert!(cache.cached_mapping_frames(&first, true).is_none());
        let (identity, frames) = cache
            .cached_mapping_frames_with_identity(&negative, true)
            .unwrap();
        assert!(identity.is_some());
        assert!(frames.frames.is_empty());
        assert!(frames.has_inline_frames);
        assert_eq!(frames.base_offset, Some(0));
        assert!(
            cache
                .cached_mapping_frames(&negative, false)
                .unwrap()
                .is_fully_unresolved()
        );
        for inline in [false, true] {
            assert_eq!(
                cache.cached_mapping_frames(&kernel, inline).unwrap().frames,
                ["kernel"]
            );
        }
        assert_eq!(resolver.calls.get(), 0);
    }

    #[test]
    fn mapping_frame_lookup_hint_preserves_replacements_and_kernel_separation() {
        let mut table = super::MappingFrameTable::default();
        let user = super::MappingFrameKey {
            symbol_source_id: usize::MAX,
            relative_address: u64::MAX,
            kernel_mapping_range: None,
        };
        let kernel = super::MappingFrameKey {
            kernel_mapping_range: Some((0, u64::MAX)),
            ..user
        };
        table.insert(user, empty_cached_table_frames());
        table.insert(kernel, cached_table_frames("kernel".into(), 2));
        assert!(table.get(&user).unwrap().frames.is_empty());
        let searches = table.user.address_searches.get();
        for _ in 0..256 {
            assert!(table.get(&user).unwrap().frames.is_empty());
            assert_eq!(table.get(&kernel).unwrap().frames, ["kernel"]);
        }
        assert_eq!(table.user.address_searches.get(), searches);
        table.insert(user, cached_table_frames("user".into(), 3));
        assert_eq!(table.get(&user).unwrap().frames, ["user"]);
        assert_eq!(table.get(&user).unwrap().literal_ends, [Some(4)]);
        table.insert(user, cached_table_frames("replacement".into(), 4));
        assert_eq!(table.get(&user).unwrap().frames, ["replacement"]);
        assert_eq!(table.get(&user).unwrap().literal_ends, [Some(11)]);
        table.insert(user, empty_cached_table_frames());
        assert!(table.get(&user).unwrap().frames.is_empty());
        assert!(table.get(&user).unwrap().literal_ends.is_empty());
        table.user.mark_unavailable(usize::MAX);
        assert_eq!(table.get(&kernel).unwrap().frames, ["kernel"]);
        table.insert(user, cached_table_frames("revived".into(), 5));
        assert_eq!(table.get(&user).unwrap().frames, ["revived"]);
        assert_eq!(table.get(&user).unwrap().literal_ends, [Some(7)]);
        assert_eq!(table.get(&kernel).unwrap().frames, ["kernel"]);
    }

    #[test]
    fn compact_mapping_cache_keeps_source_address_and_kernel_range_identities_separate() {
        let mut table = super::MappingFrameTable::default();
        let keys = [
            super::MappingFrameKey {
                symbol_source_id: 1,
                relative_address: 42,
                kernel_mapping_range: None,
            },
            super::MappingFrameKey {
                symbol_source_id: 2,
                relative_address: 42,
                kernel_mapping_range: None,
            },
            super::MappingFrameKey {
                symbol_source_id: 1,
                relative_address: 43,
                kernel_mapping_range: None,
            },
            super::MappingFrameKey {
                symbol_source_id: 1,
                relative_address: 42,
                kernel_mapping_range: Some((0x1000, 0x2000)),
            },
            super::MappingFrameKey {
                symbol_source_id: 1,
                relative_address: 42,
                kernel_mapping_range: Some((0x1000, 0x3000)),
            },
        ];
        for (index, key) in keys.into_iter().enumerate() {
            table.insert(
                key,
                cached_table_frames(format!("symbol-{index}"), index as u64),
            );
        }
        assert_eq!(table.user.len(), 3);
        assert_eq!(table.kernel.len(), 2);
        assert_eq!(table.frames.len(), keys.len());
        for (index, key) in keys.iter().enumerate() {
            let frames = table.get(key).unwrap();
            assert_eq!(frames.frames, [format!("symbol-{index}")]);
            assert_eq!(frames.base_offset, Some(index as u64));
        }
    }

    #[test]
    fn dense_mapping_frame_slots_survive_growth_and_replace_without_retaining_old_values() {
        let mut table = super::MappingFrameTable::default();
        for relative_address in 0..4096_u64 {
            let key = super::MappingFrameKey {
                symbol_source_id: 7,
                relative_address,
                kernel_mapping_range: None,
            };
            table.insert(
                key,
                cached_table_frames(format!("symbol-{relative_address}"), relative_address),
            );
        }
        for relative_address in 0..4096_u64 {
            let key = super::MappingFrameKey {
                symbol_source_id: 7,
                relative_address,
                kernel_mapping_range: None,
            };
            assert_eq!(
                table.get(&key).unwrap().frames,
                [format!("symbol-{relative_address}")]
            );
            table.insert(
                key,
                cached_table_frames(format!("replacement-{relative_address}"), relative_address),
            );
        }
        assert_eq!(table.frames.len(), 4096);
        assert_eq!(table.user.len(), 4096);
        for relative_address in 0..4096_u64 {
            let key = super::MappingFrameKey {
                symbol_source_id: 7,
                relative_address,
                kernel_mapping_range: None,
            };
            assert_eq!(
                table.get(&key).unwrap().frames,
                [format!("replacement-{relative_address}")]
            );
        }
    }

    #[test]
    fn symbol_frame_cache_accepts_owned_mapping_iterators_and_borrowed_batches() {
        for inline in [false, true] {
            let resolver = CountingFrameResolver::new(vec![vec!["one".into()], vec!["two".into()]]);
            let mut cache = SymbolFrameCache::new(&resolver);
            let mut visits = 0;
            let mappings = std::iter::from_fn(|| {
                let address = match visits {
                    0 | 1 => 0x1234,
                    2 => 0x5678,
                    _ => return None,
                };
                visits += 1;
                Some(test_mapping_ref("/bin/demo", address))
            });
            cache
                .prefetch_mapping_refs_with_mode(mappings, inline)
                .unwrap();
            assert_eq!(visits, 3);
            let batch = [
                test_mapping_ref("/bin/demo", 0x1234),
                test_mapping_ref("/bin/demo", 0x5678),
            ];
            cache
                .prefetch_mapping_refs_with_mode(&batch, inline)
                .unwrap();
            assert_eq!(
                resolver.calls.get(),
                1,
                "borrowed batches must reuse the owned iterator's cache entries"
            );
            for (mapping, expected) in batch.iter().zip(["one", "two"]) {
                let frames = if inline {
                    cache.resolve_mapping_ref(mapping)
                } else {
                    cache.resolve_base_mapping_ref(mapping)
                }
                .unwrap();
                assert_eq!(frames, [expected]);
            }
            assert_eq!(resolver.calls.get(), 1);
        }
    }

    #[test]
    fn symbol_frame_cache_prefetch_mapping_refs_deduplicates_duplicate_batch_entries() {
        let resolver =
            CountingFrameResolver::new(vec![vec!["one".to_string()], vec!["two".to_string()]]);
        let mut cache = SymbolFrameCache::new(&resolver);
        let first = test_mapping_ref("/bin/demo", 0x1234);
        let second = test_mapping_ref("/bin/demo", 0x5678);
        let batch = [
            test_mapping_ref("/bin/demo", 0x1234),
            test_mapping_ref("/bin/demo", 0x1234),
            test_mapping_ref("/bin/demo", 0x5678),
            test_mapping_ref("/bin/demo", 0x1234),
            test_mapping_ref("/bin/demo", 0x5678),
        ];

        cache
            .prefetch_mapping_refs(&batch)
            .expect("prefetch duplicate mapping refs");

        assert_eq!(
            cache.resolve_mapping_ref(&first).expect("first mapping"),
            ["one".to_string()]
        );
        assert_eq!(
            cache.resolve_mapping_ref(&second).expect("second mapping"),
            ["two".to_string()]
        );
        assert_eq!(resolver.calls.get(), 1);
    }

    #[test]
    fn cold_mapping_requests_reuse_path_storage_across_shorter_paths_and_warm_batches() {
        let resolver = CountingFrameResolver::new(vec![Vec::new()]);
        let mut cache = SymbolFrameCache::new(&resolver);
        let first = test_mapping_ref(
            "/a/very/long/object/path/whose/request/storage/should/be/reused",
            1,
        );
        cache
            .prefetch_mapping_refs(std::slice::from_ref(&first))
            .unwrap();
        let pointer = cache.scratch_missing_requests[0]
            .path
            .as_os_str()
            .as_encoded_bytes()
            .as_ptr();
        cache
            .prefetch_mapping_refs(std::slice::from_ref(&first))
            .unwrap();
        assert_eq!(cache.scratch_missing_requests.len(), 1);
        let mut second = test_mapping_ref("/short", 2);
        second.symbol_source_id = 9;
        cache
            .prefetch_mapping_refs(std::slice::from_ref(&second))
            .unwrap();
        assert_eq!(
            cache.scratch_missing_requests[0].path,
            PathBuf::from("/short")
        );
        assert_eq!(
            cache.scratch_missing_requests[0]
                .path
                .as_os_str()
                .as_encoded_bytes()
                .as_ptr(),
            pointer
        );
        assert_eq!(resolver.calls.get(), 2);
    }

    #[test]
    fn request_groups_preserve_indices_for_empty_single_and_interleaved_objects() {
        for paths in [
            vec![],
            vec!["/a"],
            vec!["/a"; 40],
            vec!["/a", "/b", "/a", "/c", "/b"],
        ] {
            let requests: Vec<_> = paths
                .iter()
                .enumerate()
                .map(|(i, path)| SymbolRequest {
                    path: PathBuf::from(path),
                    relative_address: i as u64,
                    kernel_mapping_range: None,
                    build_id: None,
                    file_identity: None,
                    kernel_relocation: None,
                })
                .collect();
            let mut actual = std::collections::BTreeMap::new();
            for (path, indices) in super::grouped_request_indexes(&requests) {
                actual.insert(path.to_owned(), indices.into_iter().collect::<Vec<_>>());
            }
            let mut expected = std::collections::BTreeMap::<_, Vec<_>>::new();
            for (i, path) in paths.iter().enumerate() {
                expected
                    .entry(std::ffi::OsString::from(path))
                    .or_default()
                    .push(i);
            }
            assert_eq!(actual, expected);
        }
    }

    fn frame_names(names: &PerfDwarfNameInterner, frames: &[u32]) -> Vec<String> {
        frames
            .iter()
            .map(|name| names.names[*name as usize].clone())
            .collect()
    }

    fn test_range(begin: u64, end: u64) -> PerfAddressRange {
        PerfAddressRange { begin, end }
    }

    fn test_request(path: &str, relative_address: u64) -> SymbolRequest {
        SymbolRequest {
            path: path.into(),
            relative_address,
            kernel_mapping_range: None,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }
    }

    #[test]
    fn reused_symbol_request_replaces_identity_and_clears_stale_kernel_metadata() {
        let mut kernel = test_mapping_ref("[kernel.kallsyms]_text", 0xffff_ffff_8100_0010);
        kernel.build_id = Some(&[0xab, 0xcd, 0xef]);
        kernel.kernel_relocation = Some(super::KernelRelocation {
            reference_symbol: "_text".into(),
            recorded_reference_address: 42,
        });
        let mut request = super::symbol_request_from_mapping_ref(&kernel);
        assert_eq!(request.path, std::path::Path::new("[kernel.kallsyms]"));
        assert!(request.kernel_mapping_range.is_some());
        let build_id_pointer = request.build_id.as_ref().unwrap().as_ptr();
        let mut user = test_mapping_ref("/bin/app", 1);
        user.build_id = Some(&[1]);
        super::update_symbol_request_from_mapping_ref(&mut request, &user);
        assert_eq!(request.build_id.as_deref(), Some("01"));
        assert_eq!(
            request.build_id.as_ref().unwrap().as_ptr(),
            build_id_pointer
        );
        assert_eq!(request.path, std::path::Path::new("/bin/app"));
        assert_eq!(request.relative_address, 1);
        assert_eq!(request.kernel_mapping_range, None);
        assert_eq!(request.kernel_relocation, None);
        user.build_id = None;
        user.file_identity = Some(super::FileIdentity {
            major: 1,
            minor: 2,
            inode: 3,
            inode_generation: 4,
        });
        super::update_symbol_request_from_mapping_ref(&mut request, &user);
        assert_eq!(request.build_id, None);
        assert_eq!(request.file_identity, user.file_identity);
        user.file_identity = None;
        super::update_symbol_request_from_mapping_ref(&mut request, &user);
        assert_eq!(request.file_identity, None);
    }

    #[test]
    fn source_without_object_symbols_never_initializes_the_inline_dwarf_index() {
        // machine.c:append_inlines requires both a map and a base symbol.
        let file = tempfile::NamedTempFile::new().unwrap();
        let resolver = super::RustAddr2lineResolver::new();
        let request = super::clean_object_symbol_request(file.path().into(), 0x10);
        let frames = resolver
            .resolve_frame_batch_with_metadata(&[request])
            .unwrap();
        assert_eq!(
            frames[0].source_state,
            super::SymbolSourceState::Unavailable
        );
        let metadata = resolver.object_metadata(file.path()).unwrap();
        let index = metadata.dwarf_index.lock().unwrap();
        assert!(index.units.is_none());
        assert!(
            !index.failed,
            "DWARF preparation should not have run without any base symbols"
        );
    }

    #[test]
    fn routed_frame_batches_preserve_mode_and_order_before_and_after_inline_storage_spills() {
        struct ModeResolver;
        impl SymbolResolver for ModeResolver {
            fn resolve_batch(&self, _: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
                Err("frame routing must preserve metadata".into())
            }
            fn resolve_frame_batch_with_metadata(
                &self,
                requests: &[SymbolRequest],
            ) -> Result<Vec<ResolvedSymbolFrames>, String> {
                Ok(requests
                    .iter()
                    .map(|request| {
                        ResolvedSymbolFrames::from_frames(vec![format!(
                            "inline:{}:{:x}",
                            request.path.display(),
                            request.relative_address
                        )])
                    })
                    .collect())
            }
            fn resolve_base_frame_batch_with_metadata(
                &self,
                requests: &[SymbolRequest],
            ) -> Result<Vec<ResolvedSymbolFrames>, String> {
                Ok(requests
                    .iter()
                    .map(|request| {
                        ResolvedSymbolFrames::from_frames(vec![format!(
                            "base:{}:{:x}",
                            request.path.display(),
                            request.relative_address
                        )])
                    })
                    .collect())
            }
        }
        let root = tempfile::tempdir().unwrap();
        let user = root.path().join("missing-user-object");
        let kernel = root.path().join("missing-kernel-object");
        let resolver = super::PerfSymbolResolver::from_object_resolver(ModeResolver)
            .with_kernel_elf(kernel.clone())
            .with_kallsyms(super::Kallsyms::parse("0000000000001000 T known\n").unwrap());
        for size in [0_usize, 1, 16, 17, 65] {
            for inline in [true, false] {
                let mut requests: Vec<_> = (0..size)
                    .map(|address| {
                        test_request(user.to_str().unwrap(), u64::try_from(address).unwrap())
                    })
                    .collect();
                requests.insert(size / 2, test_request("[kernel.kallsyms]", 0x50));
                requests.insert(0, test_request("[kernel.kallsyms]", 0x1001));
                requests.push(test_request("[demo]", 0x55));
                let results = if inline {
                    resolver.resolve_frame_batch_with_metadata(&requests)
                } else {
                    resolver.resolve_base_frame_batch_with_metadata(&requests)
                }
                .unwrap();
                assert_eq!(results.len(), requests.len());
                for (request, frames) in requests.iter().zip(results) {
                    let expected = match request.path.to_str().unwrap() {
                        "[demo]" => Vec::new(),
                        "[kernel.kallsyms]" if request.relative_address == 0x1001 => {
                            vec!["known+0x1".into()]
                        }
                        _ => vec![format!(
                            "{}:{}:{:x}",
                            if inline { "inline" } else { "base" },
                            if request.path == std::path::Path::new("[kernel.kallsyms]") {
                                &kernel
                            } else {
                                &user
                            }
                            .display(),
                            request.relative_address
                        )],
                    };
                    assert_eq!(frames.frames, expected);
                    assert_eq!(
                        frames.source_state,
                        super::SymbolSourceState::AddressDependent
                    );
                }
            }
        }
    }

    #[test]
    fn a_symbol_gap_at_one_address_does_not_mark_its_source_unavailable() {
        struct GapResolver;
        impl SymbolResolver for GapResolver {
            fn resolve_batch(
                &self,
                requests: &[SymbolRequest],
            ) -> Result<Vec<Option<String>>, String> {
                Ok(requests
                    .iter()
                    .map(|request| (request.relative_address == 0x20).then(|| "present".into()))
                    .collect())
            }
        }
        let resolver = GapResolver;
        let mut cache = SymbolFrameCache::new(&resolver);
        let first = test_mapping_ref("/bin/gap", 0x10);
        assert!(cache.resolve_mapping_ref(&first).unwrap().is_empty());
        let second = ResolvedMappingRef {
            relative_address: 0x20,
            ..first.clone()
        };
        assert!(!cache.mapping_ref_cached(&second, true));
        assert!(!cache.mapping_ref_cached(&first, false));
        assert_eq!(cache.resolve_mapping_ref(&second).unwrap(), ["present"]);
        let other_source = ResolvedMappingRef {
            symbol_source_id: usize::MAX,
            ..first
        };
        assert!(!cache.mapping_ref_cached(&other_source, true));
    }

    struct UnavailableObjectResolver;

    #[test]
    fn user_symbol_lookups_leave_recorded_kernel_metadata_unopened() {
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_perfdata_file_kernel_cache(
                super::Path::new("/missing/perf.data"),
                super::Path::new("/missing/debug"),
            );
        let requests = [clean_object_symbol_request(
            PathBuf::from("/missing/user-object"),
            0,
        )];
        resolver.resolve_batch(&requests).unwrap();
        resolver
            .resolve_frame_batch_with_metadata(&requests)
            .unwrap();
        resolver
            .resolve_base_frame_batch_with_metadata(&requests)
            .unwrap();
        assert!(
            resolver
                .file_kernel_cache
                .as_ref()
                .unwrap()
                .loaded
                .get()
                .is_none()
        );
    }

    impl SymbolResolver for UnavailableObjectResolver {
        fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
            Ok(vec![None; requests.len()])
        }

        fn resolve_frame_batch_with_metadata(
            &self,
            requests: &[SymbolRequest],
        ) -> Result<Vec<ResolvedSymbolFrames>, String> {
            Ok(vec![
                ResolvedSymbolFrames {
                    source_state: super::SymbolSourceState::Unavailable,
                    ..ResolvedSymbolFrames::default()
                };
                requests.len()
            ])
        }
    }

    #[test]
    fn missing_module_object_does_not_hide_kallsyms_symbols_at_other_addresses() {
        // perf util/symbol.c:dso__find_kallsyms is an alternate source even
        // when an object load failed. Only the complete source can be negative.
        let root = tempfile::tempdir().unwrap();
        let build_id = "0102";
        let elf = super::perf_build_id_elf_path_for_dso(
            root.path(),
            std::path::Path::new("[demo]"),
            build_id,
        );
        std::fs::create_dir_all(elf.parent().unwrap()).unwrap();
        std::fs::write(&elf, []).unwrap();
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_debug_dir(root.path().into())
            .with_kallsyms(
                super::Kallsyms::parse_modules("0000000000001000 t handler [demo]\n").unwrap(),
            );
        for inline in [true, false] {
            let mut cache = SymbolFrameCache::new(&resolver);
            let mut first = test_mapping_ref("[demo]", 0x10);
            first.build_id = Some(&[1, 2]);
            assert!(
                cache
                    .resolve_cached_mapping(&first, inline)
                    .unwrap()
                    .frames
                    .is_empty()
            );
            let second = ResolvedMappingRef {
                relative_address: 0x1010,
                ..first
            };
            assert!(
                !cache
                    .resolve_cached_mapping(&second, inline)
                    .unwrap()
                    .frames
                    .is_empty()
            );
        }
    }

    #[test]
    fn unavailable_object_source_caches_all_addresses_and_both_inline_modes_without_ip_entries() {
        // perf util/symbol.c:dso__load exits via dso__set_loaded even after
        // object loading fails. A missing DSO is not a per-address symbol gap.
        let path = format!("/tmp/pyroclast-unavailable-source-{}", std::process::id());
        assert!(!std::path::Path::new(&path).exists());
        let resolver = super::RustAddr2lineResolver::new();
        let mut cache = SymbolFrameCache::new(&resolver);
        let mapping = test_mapping_ref(&path, 0x10);
        assert!(cache.resolve_mapping_ref(&mapping).unwrap().is_empty());
        let unseen = ResolvedMappingRef {
            relative_address: 0x20,
            ..mapping
        };
        assert!(cache.mapping_ref_cached(&unseen, true));
        assert!(cache.mapping_ref_cached(&unseen, false));
        assert!(cache.resolve_mapping_ref(&unseen).unwrap().is_empty());
        assert!(cache.resolve_base_mapping_ref(&unseen).unwrap().is_empty());
        assert_eq!(cache.resolved_by_mapping.user.len(), 0);
        assert_eq!(cache.resolved_base_by_mapping.user.len(), 0);
        assert_eq!(cache.resolved_by_mapping.frames.capacity(), 0);
        assert_eq!(resolver.cached_object_count(), 1);
    }

    #[test]
    fn unavailable_source_state_does_not_cross_source_ids_or_kernel_ranges() {
        let resolver = UnavailableObjectResolver;
        let mut cache = SymbolFrameCache::new(&resolver);
        let first = test_mapping_ref("/missing", 0x10);
        cache.resolve_mapping_ref(&first).unwrap();
        let other_source = ResolvedMappingRef {
            symbol_source_id: usize::MAX,
            ..first.clone()
        };
        assert!(!cache.mapping_ref_cached(&other_source, true));
        assert!(!cache.mapping_ref_cached(&other_source, false));

        let kernel = test_mapping_ref("[kernel.kallsyms]", 0xffff_ffff_8000_0010);
        cache.resolve_mapping_ref(&kernel).unwrap();
        let unseen = ResolvedMappingRef {
            relative_address: kernel.relative_address + 8,
            ..kernel.clone()
        };
        let another_range = ResolvedMappingRef {
            end: kernel.end + 1,
            ..kernel
        };
        assert!(!cache.mapping_ref_cached(&unseen, true));
        assert!(!cache.mapping_ref_cached(&another_range, true));
    }

    #[test]
    fn unavailable_source_marker_never_discards_positive_frame_metadata() {
        struct PositiveResolver;
        impl SymbolResolver for PositiveResolver {
            fn resolve_batch(
                &self,
                requests: &[SymbolRequest],
            ) -> Result<Vec<Option<String>>, String> {
                Ok(vec![None; requests.len()])
            }

            fn resolve_frame_batch_with_metadata(
                &self,
                requests: &[SymbolRequest],
            ) -> Result<Vec<ResolvedSymbolFrames>, String> {
                Ok(requests
                    .iter()
                    .map(|_| ResolvedSymbolFrames {
                        source_state: super::SymbolSourceState::Unavailable,
                        ..ResolvedSymbolFrames::from_frames(vec!["present".into()])
                    })
                    .collect())
            }
        }
        let resolver = PositiveResolver;
        let mut cache = SymbolFrameCache::new(&resolver);
        let first = test_mapping_ref("/contradictory-metadata", 0x10);
        assert_eq!(cache.resolve_mapping_ref(&first).unwrap(), ["present"]);
        let unseen = ResolvedMappingRef {
            relative_address: 0x20,
            ..first
        };
        assert!(!cache.mapping_ref_cached(&unseen, true));
        assert!(!cache.mapping_ref_cached(&unseen, false));
    }

    fn test_mapping_ref(path: &str, relative_address: u64) -> ResolvedMappingRef<'_> {
        ResolvedMappingRef {
            symbol_source_id: 1,
            path,
            relative_address,
            start: relative_address,
            end: relative_address.saturating_add(1),
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }
    }

    struct CountingFrameResolver {
        calls: Cell<usize>,
        response: Vec<Vec<String>>,
    }

    impl CountingFrameResolver {
        fn new(response: Vec<Vec<String>>) -> Self {
            Self {
                calls: Cell::new(0),
                response,
            }
        }
    }

    impl SymbolResolver for CountingFrameResolver {
        fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
            Ok(vec![None; requests.len()])
        }

        fn resolve_frame_batch(
            &self,
            requests: &[SymbolRequest],
        ) -> Result<Vec<Vec<String>>, String> {
            self.calls.set(self.calls.get() + 1);
            if requests.len() != self.response.len() {
                return Err(format!(
                    "expected {} frame requests, got {}",
                    self.response.len(),
                    requests.len()
                ));
            }
            Ok(self.response.clone())
        }
    }
}
