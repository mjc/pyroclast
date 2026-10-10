#[cfg(unix)]
mod gnu;
pub(crate) mod kcore;

use std::borrow::{Borrow, Cow};
use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write;
use std::hash::{Hash, Hasher};
use std::io::Read;
#[cfg(target_os = "linux")]
use std::io::{Seek, SeekFrom, Write as IoWrite};
use std::num::NonZeroU64;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use clap::ValueEnum;
use hashbrown::{HashMap, HashSet, HashTable, hash_map::RawEntryMut};
use object::{
    Object, ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable, SymbolIndex, SymbolKind,
};
use rustc_hash::FxBuildHasher;
use serde::Serialize;
use smallvec::SmallVec;

use crate::perfdata::build_id::{hex_build_id_bytes, kernel_build_id_from_perfdata};
use crate::perfdata::mappings::{FileIdentity, MappedFrame, MmapTable, ResolvedMappingRef};
use crate::process::{CommandRunner, CommandSpec};

type FxHashMap<K, V> = HashMap<K, V, FxBuildHasher>;
type FxHashSet<T> = HashSet<T, FxBuildHasher>;

const X86_64_PLT_ENTRY_SIZE: u64 = 16;
const ELF64_RELA_ENTRY_SIZE: usize = 24;
const ELF_STT_RELC: u8 = 8;
const ELF_STT_SRELC: u8 = 9;

#[cfg(test)]
thread_local! {
    static MODULE_KALLSYMS_TREE_BUILDS: Cell<usize> = const { Cell::new(0) };
    static MODULE_KALLSYMS_ROW_VISITS: Cell<usize> = const { Cell::new(0) };
    static MODULE_KALLSYMS_SYMBOL_INSERTIONS: Cell<usize> = const { Cell::new(0) };
    static MODULE_KALLSYMS_END_FIXUP_PASSES: Cell<usize> = const { Cell::new(0) };
    static KALLSYMS_REFERENCE_ROW_VISITS: Cell<usize> = const { Cell::new(0) };
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
    /// Optional perf objdump address for DWARF/inline lookup. The base-symbol
    /// VMA can differ when the mapping and .text have different ELF biases.
    pub addr2line_address: Option<u64>,
    /// Original kernel IP when an absolute module mapping supplied this request.
    pub kernel_module_address: Option<u64>,
    pub kernel_mapping_range: Option<(u64, u64)>,
    pub build_id: Option<String>,
    pub file_identity: Option<FileIdentity>,
    pub kernel_relocation: Option<KernelRelocation>,
}

impl SymbolRequest {
    fn inline_address(&self) -> u64 {
        self.addr2line_address.unwrap_or(self.relative_address)
    }

    fn recorded_build_id(&self) -> Option<&str> {
        self.build_id
            .as_deref()
            .filter(|id| build_id_is_defined(id))
    }

    /// Keep all recorded identity in cache keys. perf's missing-identity
    /// wildcard comparison is not transitive and cannot be used as `HashMap`
    /// equality; extra resolution is preferable to merging distinct files.
    fn identity_file_identity(&self) -> Option<FileIdentity> {
        self.file_identity
    }
}

impl PartialEq for SymbolRequest {
    fn eq(&self, other: &Self) -> bool {
        self.relative_address == other.relative_address
            && self.inline_address() == other.inline_address()
            && self.kernel_module_address == other.kernel_module_address
            && self.kernel_mapping_range == other.kernel_mapping_range
            && self.recorded_build_id() == other.recorded_build_id()
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
        self.inline_address().hash(state);
        self.kernel_module_address.hash(state);
        self.kernel_mapping_range.hash(state);
        self.recorded_build_id().hash(state);
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
            .then_with(|| self.inline_address().cmp(&other.inline_address()))
            .then_with(|| self.kernel_module_address.cmp(&other.kernel_module_address))
            .then_with(|| self.kernel_mapping_range.cmp(&other.kernel_mapping_range))
            .then_with(|| self.recorded_build_id().cmp(&other.recorded_build_id()))
            .then_with(|| {
                self.identity_file_identity()
                    .cmp(&other.identity_file_identity())
            })
            .then_with(|| self.kernel_relocation.cmp(&other.kernel_relocation))
    }
}

/// An additional module map created by perf's kernel ELF symbol loader.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelModuleSectionMap {
    pub section: String,
    pub start: u64,
}

/// Mapping effects and object address of the original module's text section.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KernelModuleObjectMetadata {
    pub text_address: Option<u64>,
    pub maps: Vec<KernelModuleSectionMap>,
}

pub trait SymbolResolver {
    /// Supplies the currently delivered host kernel maps before symbol loading.
    /// Direct callers must provide this context explicitly; no recording is replayed.
    fn initialize_kernel_maps(&self, _table: &MmapTable) {}

    /// Reports the live ELF's ID before a DSO's first symbol lookup, as perf's
    /// `symbol.c:dso__load` does before selecting build-ID cache candidates.
    fn object_build_id(&self, _path: &Path) -> Option<Vec<u8>> {
        None
    }

    /// Reports maps created from retained symbol and runtime ELF sources.
    /// perf `symbol-elf.c:dso__process_kernel_symbol` uses eligible symbols and
    /// section layout, not ELF type alone, to create these maps.
    /// Wrapping resolvers must forward this to the owner of the selected primary.
    fn selected_object_module_metadata(
        &self,
        _path: &Path,
        _module: &SymbolRequest,
    ) -> Option<Arc<KernelModuleObjectMetadata>> {
        None
    }

    /// Kernel map initialization can change the source between callchain nodes.
    fn requires_kernel_cursor_order(&self) -> bool {
        false
    }

    /// perf `builtin-script.c:process_sample_event` loads the event IP's map
    /// before resolving any callchain nodes (`event.c:machine__resolve`).
    fn preprocess_sample_ip(&self, _mapping: &ResolvedMappingRef<'_>) {}

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

    /// Resolves a cursor through the original module ELF after kcore replaces
    /// its map. Used only while consecutive nodes retain perf's previous map.
    ///
    /// # Errors
    /// Returns an error when the object resolver fails.
    fn resolve_original_kernel_module_frames(
        &self,
        request: &SymbolRequest,
        inline: bool,
    ) -> Result<ResolvedSymbolFrames, String> {
        let requests = std::slice::from_ref(request);
        let frames = if inline {
            self.resolve_frame_batch_with_metadata(requests)?
        } else {
            self.resolve_base_frame_batch_with_metadata(requests)?
        };
        frames
            .into_iter()
            .next()
            .ok_or_else(|| "missing original module frame result".into())
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
    /// The current cursor keeps its old module source before core map replacement.
    /// Drop its cache entry after printing this cursor so later nodes can change source.
    KernelMapReplaced,
    /// The original module ELF remains the current cursor source.
    KernelObjectMapReplaced,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SymbolDsoName {
    #[default]
    Mapping,
    KernelKallsyms,
    /// Loading/fixing the kernel map removed this address from its coverage.
    Unmapped,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResolvedSymbolFrames {
    pub frames: Vec<String>,
    pub source_state: SymbolSourceState,
    /// DSO identity after loading and fixing up the native kernel map.
    pub kernel_dso: SymbolDsoName,
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
            kernel_dso: SymbolDsoName::Mapping,
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
    replaced_kernel_entries: SmallVec<[(bool, MappingFrameKey, bool); 2]>,
    kernel_cursor_hint: Option<(MappingFrameKey, bool)>,
    preprocessed_kernel_modules: FxHashSet<usize>,
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
    pub(crate) kernel_dso: SymbolDsoName,
    pub(crate) has_inline_frames: bool,
    pub(crate) has_non_inline_base_frame: bool,
    pub(crate) base_offset: Option<u64>,
}

impl CachedMappingFrames {
    fn from_resolved(frames: ResolvedSymbolFrames) -> Self {
        Self {
            kernel_dso: frames.kernel_dso,
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
            render_mode: if matches!(
                frames.source_state,
                SymbolSourceState::KernelMapReplaced | SymbolSourceState::KernelObjectMapReplaced
            ) || frames
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
        }
    }
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
}

#[derive(Default)]
struct UserFrameTable {
    by_source: FxHashMap<usize, usize>,
    sources: Vec<UserFrameAddresses>,
    // A cached source with no index is terminal unavailable, including all IPs.
    last_source: Cell<Option<UserFrameSourceHint>>,
    // Qualified by last_source; source changes and mutations invalidate it.
    last_address: Cell<Option<(u64, Option<usize>)>>,
    #[cfg(test)]
    source_hint_publications: Cell<usize>,
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
    fn publish_source_hint(&self, hint: UserFrameSourceHint) {
        #[cfg(test)]
        self.source_hint_publications
            .set(self.source_hint_publications.get() + 1);
        self.last_source.set(Some(hint));
        self.last_address.set(None);
    }

    #[inline]
    fn slot(&self, source: usize, address: u64) -> Option<usize> {
        if let Some(hint) = self.last_source.get()
            && hint.source == source
        {
            // perf util/symbol.c:dso__find_symbol (575-583) keys a hit by IP.
            // Changing the IP result does not change the selected source.
            if let Some((cached_address, slot)) = self.last_address.get()
                && cached_address == address
            {
                return slot;
            }
            let Some(index) = hint.index else {
                return Some(0);
            };
            #[cfg(test)]
            self.source_accesses.set(self.source_accesses.get() + 1);
            return self.lookup_address(&self.sources[index], address);
        }
        self.slot_for_new_source(source, address)
    }

    #[inline(never)]
    fn slot_for_new_source(&self, source: usize, address: u64) -> Option<usize> {
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
            self.publish_source_hint(UserFrameSourceHint {
                source,
                index: None,
            });
            return Some(0);
        }
        self.publish_source_hint(UserFrameSourceHint {
            source,
            index: Some(index),
        });
        #[cfg(test)]
        self.address_hint_checks
            .set(self.address_hint_checks.get() + 1);
        if let Some((cached_address, slot)) = addresses.last_address.get()
            && cached_address == address
        {
            self.last_address.set(Some((address, slot)));
            return slot;
        }
        self.lookup_address(addresses, address)
    }

    #[inline(never)]
    fn lookup_address(&self, addresses: &UserFrameAddresses, address: u64) -> Option<usize> {
        #[cfg(test)]
        self.address_searches.set(self.address_searches.get() + 1);
        let slot = addresses.by_address.get(&address).copied();
        addresses.last_address.set(Some((address, slot)));
        self.last_address.set(Some((address, slot)));
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
        self.publish_source_hint(UserFrameSourceHint {
            source,
            index: Some(index),
        });
    }

    fn mark_unavailable(&mut self, source: usize) {
        let index = self.source_index(source);
        self.sources[index] = UserFrameAddresses {
            unavailable: true,
            ..UserFrameAddresses::default()
        };
        self.publish_source_hint(UserFrameSourceHint {
            source,
            index: None,
        });
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
    kernel_dso: SymbolDsoName::Mapping,
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
            && self.kernel_dso == SymbolDsoName::Mapping
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
    metadata_cache: OnceLock<Mutex<FxHashMap<OsString, Option<Arc<SelectedGnuObject>>>>>,
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
    segments_by_path: FxHashMap<OsString, Option<ObjectAddressMetadata>>,
}

struct ObjectAddressMetadata {
    segments: Vec<ObjectSegmentRange>,
    text_offset: u64,
    build_id: Option<String>,
}

struct ObjectSegmentRange {
    file_offset: u64,
    file_end: u64,
    virtual_address: u64,
}

struct PerfDwarfNameResolver<'a> {
    names: PerfDwarfNames<'a>,
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
    frame_index: PerfDwarfFrameIndex,
}

#[derive(Debug)]
struct PerfDwarfScope {
    depth: isize,
    ranges: Vec<PerfAddressRange>,
    frame: Option<std::num::NonZeroUsize>,
    frame_checkpoint: usize,
    segment_checkpoint: usize,
    has_inline_frames: bool,
    suppressed: bool,
    child_coverage: Vec<PerfAddressRange>,
}

#[derive(Debug)]
struct PerfDwarfFrameRange {
    range: PerfAddressRange,
    frame: std::num::NonZeroUsize,
    has_inline_frames: bool,
    has_source_line: bool,
    order: usize,
}

#[derive(Debug, Default)]
struct PerfDwarfFrameIndex {
    segments: Vec<PerfDwarfFrameRange>,
    nodes: Vec<PerfDwarfFrameNode>,
}

#[derive(Debug)]
struct PerfDwarfFrameNode {
    name: PerfDwarfNameId,
    parent: Option<std::num::NonZeroUsize>,
    kind: PerfDwarfDieKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PerfDwarfDieKind {
    Subprogram,
    Inline,
}

#[derive(Default)]
struct PreparedObjectMetadata {
    object_symbols: PerfObjectSymbolIndex,
    has_debug_line: bool,
    possibly_runtime: bool,
}

struct CachedObjectMetadata {
    object_metadata: PreparedObjectMetadata,
    object_bytes: Arc<Vec<u8>>,
    dwarf_index: Mutex<PerfDwarfIndexCache<'static>>,
    module_metadata: Mutex<FxHashMap<OsString, Arc<KernelModuleObjectMetadata>>>,
}

struct SelectedGnuObject {
    metadata: Arc<CachedObjectMetadata>,
    #[cfg(unix)]
    helper: Mutex<GnuHelperState>,
    #[cfg(unix)]
    canonical_name: PathBuf,
    #[cfg(unix)]
    input: OnceLock<Result<Arc<std::fs::File>, String>>,
}

#[cfg(unix)]
#[derive(Default)]
enum GnuHelperState {
    #[default]
    Uninitialized,
    Batched,
    Live(crate::process::CommandSession),
    Failed(String),
}

/// Per-object memo of DWARF inline-frame indexes.
///
/// Folding queries the same hot objects every round; re-parsing their DWARF
/// and re-walking the DIE trees per batch dominated fold time. Unit ranges are
/// scanned once, and each unit's frame index is built on the first batch whose
/// addresses land in it. The name interner is append-only so frame name ids
/// stay valid across incremental builds.
#[derive(Default)]
struct PerfDwarfIndexCache<'a> {
    names: PerfDwarfNameInterner<'a>,
    units: Option<Vec<PerfDwarfCachedUnit>>,
    failed: bool,
}

struct PerfDwarfCachedUnit {
    ranges: Option<Vec<PerfAddressRange>>,
    source_line_ranges: Option<Vec<PerfAddressRange>>,
    frame_index: Option<PerfDwarfFrameIndex>,
}

struct PerfDwarfPreparedUnit<R: gimli::Reader> {
    header: gimli::UnitHeader<R>,
    unit: Option<gimli::Unit<R>>,
}

struct PerfDwarfUnitDirectory<R: gimli::Reader> {
    units: Vec<PerfDwarfPreparedUnit<R>>,
}

impl<R: gimli::Reader> PerfDwarfUnitDirectory<R> {
    fn new(dwarf: &gimli::Dwarf<R>) -> Self {
        let mut units = Vec::new();
        let mut headers = dwarf.units();
        while let Ok(Some(header)) = headers.next() {
            let unit = dwarf.unit(header.clone()).ok();
            units.push(PerfDwarfPreparedUnit { header, unit });
        }
        Self { units }
    }

    fn resolve_reference(
        &self,
        offset: gimli::DebugInfoOffset<R::Offset>,
    ) -> Option<(&gimli::Unit<R>, gimli::UnitOffset<R::Offset>)> {
        // Names can refer to CUs outside queried address coverage. Locate their
        // owner without scanning units or preparing their inline frame indexes.
        let index = self
            .units
            .partition_point(|unit| unit.header.offset().0 <= offset.0)
            .checked_sub(1)?;
        let prepared = &self.units[index];
        let offset = offset.to_unit_offset(&prepared.header)?;
        Some((prepared.unit.as_ref()?, offset))
    }
}

pub(crate) struct LiveVdsoElf {
    pub(crate) path: PathBuf,
    pub(crate) architecture: object::Architecture,
    pub(crate) build_id: Option<Vec<u8>>,
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
    bfd_only_symbols: Vec<PerfSymbolCandidate>,
    bfd_sections: Vec<BfdSymbolSection>,
    bfd_function_cache: Mutex<Option<BfdFunctionRecordCache>>,
}

#[derive(Clone, Copy)]
enum BfdSymbolIndex {
    Perf(usize),
    BfdOnly(usize),
}

struct BfdSymbolSection {
    index: object::SectionIndex,
    range: PerfAddressRange,
    address_bias: u64,
    symbols: Vec<BfdSymbolIndex>,
}

struct BfdFunctionRecordCache {
    section: object::SectionIndex,
    symbol: BfdSymbolIndex,
    offset: u64,
    size: u64,
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
    live_kallsyms_cache: OnceLock<Option<LiveKallsymsSnapshot>>,
    kcore_symbols: OnceLock<Option<kcore::KcoreSymbols>>,
    ordinary_kernel_load: Mutex<OrdinaryKernelLoad>,
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

#[derive(Default)]
struct OrdinaryKernelLoad {
    core_loaded: bool,
    modules_loaded_before_core: FxHashSet<String>,
}

struct LiveKallsymsSnapshot {
    core: Option<Kallsyms>,
    modules: FxHashMap<String, Arc<Kallsyms>>,
    physical: KallsymsReferenceSource,
}

#[derive(Debug)]
struct KallsymsReferenceSource {
    source: Box<str>,
    references: Mutex<Vec<KallsymsReference>>,
}

impl PartialEq for KallsymsReferenceSource {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for KallsymsReferenceSource {}

#[derive(Debug)]
enum KallsymsReference {
    Found { name: Range<usize>, address: u64 },
    Missing(Box<str>),
}

impl KallsymsReferenceSource {
    fn new(source: Box<str>) -> Self {
        Self {
            source,
            references: Mutex::new(Vec::new()),
        }
    }

    fn reference_address(&self, reference: &str) -> Option<u64> {
        let mut references = self.references.lock().expect("kallsyms reference lock");
        for cached in references.iter() {
            match cached {
                KallsymsReference::Found { name, address }
                    if &self.source[name.clone()] == reference =>
                {
                    return Some(*address);
                }
                KallsymsReference::Missing(name) if name.as_ref() == reference => return None,
                _ => {}
            }
        }
        // perf symbol.c:kallsyms__delta -> event.c:get_function_start scans
        // the physical source independently of display-tree alias selection.
        if let Some((address, name)) = kallsyms_reference_span(&self.source, reference) {
            references.push(KallsymsReference::Found { name, address });
            Some(address)
        } else {
            // A missing name has no source span. Own only requested misses so
            // repeated failed relocation does not rescan the complete source.
            references.push(KallsymsReference::Missing(reference.into()));
            None
        }
    }
}

impl LiveKallsymsSnapshot {
    fn reference_address(&self, reference: &str) -> Option<u64> {
        self.physical.reference_address(reference)
    }

    fn relocation_delta(&self, relocation: Option<&KernelRelocation>) -> Option<u64> {
        match relocation {
            Some(relocation) => Some(
                self.reference_address(&relocation.reference_symbol)?
                    .wrapping_sub(relocation.recorded_reference_address),
            ),
            None => Some(0),
        }
    }

    fn resolve_core(&self, request: &SymbolRequest) -> Option<String> {
        let core = self.core.as_ref()?;
        let delta = self.relocation_delta(request.kernel_relocation.as_ref())?;
        core.resolve_with_offset(request.relative_address.wrapping_add(delta))
    }

    fn kernel_map_range(&self, relocation: Option<&KernelRelocation>) -> Option<(u64, u64)> {
        // perf symbol.c:maps__split_kallsyms subtracts delta before
        // map.c:map__fixup_start/end takes the first/last symbol bounds.
        let core = self.core.as_ref()?;
        let delta = self.relocation_delta(relocation)?;
        let (&start, _) = core.symbols.first_key_value()?;
        let (_, last) = core.symbols.last_key_value()?;
        Some((start.wrapping_sub(delta), last.end?.wrapping_sub(delta)))
    }
}

struct FileKernelCache {
    perfdata: PathBuf,
    debug_dir: PathBuf,
    loaded: OnceLock<CachedKernelSymbols>,
    arch: OnceLock<Option<crate::perfdata::unwind::PerfArch>>,
}

#[derive(Default)]
struct CachedKernelSymbols {
    build_id: Option<String>,
    kallsyms: Option<Kallsyms>,
    elf: Option<PathBuf>,
}

impl FileKernelCache {
    fn arch(&self) -> Option<crate::perfdata::unwind::PerfArch> {
        *self
            .arch
            .get_or_init(|| crate::perfdata::fold::perfdata_file_arch(&self.perfdata).ok())
    }

    fn initialize_symbols(&self, recorded_build_id: Option<&[u8]>) {
        self.loaded.get_or_init(|| {
            let Some(build_id) = recorded_build_id.filter(|id| id.iter().any(|byte| *byte != 0))
            else {
                return CachedKernelSymbols::default();
            };
            let build_id = build_id_hex(build_id);
            let elf = perf_build_id_elf_path(&self.debug_dir, &build_id);
            CachedKernelSymbols {
                kallsyms: Kallsyms::load_perf_build_id_cache(&self.debug_dir, &build_id),
                elf: elf.exists().then_some(elf),
                build_id: Some(build_id),
            }
        });
    }

    fn symbols(&self) -> Option<&CachedKernelSymbols> {
        self.loaded.get()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Kallsyms {
    symbols: BTreeMap<u64, KallsymsSymbol>,
    addresses_by_name: FxHashMap<Arc<str>, u64>,
    module_indexes: FxHashMap<String, ModuleKallsymsIndex>,
    physical: Option<Arc<KallsymsReferenceSource>>,
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
    name: Arc<str>,
    end: Option<u64>,
    module: Option<String>,
}

impl KallsymsSymbol {
    fn kernel(name: &str) -> Self {
        Self {
            name: Arc::from(name),
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
            name: Arc::from(self.name),
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
/// Returns an empty path for an absent or malformed hexadecimal build ID.
pub fn perf_build_id_elf_path(debug_dir: &Path, build_id: &str) -> PathBuf {
    if !valid_build_id(build_id) {
        return PathBuf::new();
    }
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
    if !valid_build_id(build_id) {
        return PathBuf::new();
    }
    if is_perf_vdso_dso_path(dso_path) {
        // perf's build-id cache uses [vdso]/<build-id>/vdso for VDSO DSOs
        // (tools/perf/util/build-id.c: build_id_cache__basename with is_vdso).
        return debug_dir.join("[vdso]").join(build_id).join("vdso");
    }

    perf_build_id_elf_path(debug_dir, build_id)
}

fn valid_build_id(build_id: &str) -> bool {
    build_id_is_defined(build_id)
        && build_id.len().is_multiple_of(2)
        && build_id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn build_id_is_defined(build_id: &str) -> bool {
    // perf's build_id__is_defined requires at least one nonzero ID byte.
    build_id.bytes().any(|byte| byte != b'0')
}

fn is_perf_vdso_dso_path(path: &Path) -> bool {
    matches!(path.to_str(), Some("[vdso]" | "[vdso32]" | "[vdsox32]"))
}

pub(crate) fn copy_live_vdso_elf_like_perf() -> Option<LiveVdsoElf> {
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

    let object = object::File::parse(bytes.as_slice()).ok()?;
    let architecture = object.architecture();
    let build_id = object.build_id().ok()?.map(<[u8]>::to_vec);
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
    Some(LiveVdsoElf {
        path,
        architecture,
        build_id,
    })
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
                let loaded = read_regular_object(path).map(|bytes| {
                    Arc::new(CachedObjectMetadata {
                        object_metadata: PreparedObjectMetadata::from_object_bytes(&bytes),
                        object_bytes: retain_object_snapshot(bytes),
                        dwarf_index: Mutex::new(PerfDwarfIndexCache::default()),
                        module_metadata: Mutex::default(),
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
        self.selected_object(path)
            .map(|selected| selected.metadata.clone())
    }

    fn selected_object(&self, path: &Path) -> Option<Arc<SelectedGnuObject>> {
        let cache = self
            .metadata_cache
            .get_or_init(|| Mutex::new(FxHashMap::default()));
        let mut cache = cache.lock().expect("addr2line metadata cache lock");
        match cache.raw_entry_mut().from_key(path.as_os_str()) {
            RawEntryMut::Occupied(entry) => entry.get().clone(),
            RawEntryMut::Vacant(entry) => {
                let loaded = (|| {
                    #[cfg(unix)]
                    let canonical_name = std::fs::canonicalize(path).ok()?;
                    let bytes = read_regular_object(path)?;
                    Some(Arc::new(SelectedGnuObject {
                        #[cfg(unix)]
                        helper: Mutex::new(GnuHelperState::Uninitialized),
                        metadata: Arc::new(CachedObjectMetadata {
                            object_metadata: PreparedObjectMetadata::from_object_bytes(&bytes),
                            object_bytes: retain_object_snapshot(bytes),
                            dwarf_index: Mutex::new(PerfDwarfIndexCache::default()),
                            module_metadata: Mutex::default(),
                        }),
                        #[cfg(unix)]
                        canonical_name,
                        #[cfg(unix)]
                        input: OnceLock::new(),
                    }))
                })();
                entry.insert(path.as_os_str().to_owned(), loaded).1.clone()
            }
        }
    }

    fn resolve_group_symbols(
        &self,
        path: &Path,
        selected: &SelectedGnuObject,
        requests: &[SymbolRequest],
        indexes: &[usize],
    ) -> Result<Vec<Option<String>>, String> {
        // Scalar resolution follows perf's base-symbol path, not append_inlines.
        let command = addr2line_command(
            path,
            indexes
                .iter()
                .map(|index| requests[*index].relative_address),
        );
        #[cfg(unix)]
        let command = selected.attach_input(path, command)?;
        #[cfg(not(unix))]
        let _ = selected;
        #[cfg(unix)]
        if let Some(stdout) = self.resolve_session_symbols(selected, &command)? {
            return parse_addr2line_stdout(&stdout, indexes.len());
        }
        let output = self
            .runner
            .run(&command)
            .map_err(|error| format!("failed to run addr2line: {error}"))?;
        if output.status_code == Some(0) {
            parse_addr2line_stdout(&output.stdout, indexes.len())
        } else {
            Ok(vec![None; indexes.len()])
        }
    }

    #[cfg(unix)]
    fn resolve_session_symbols(
        &self,
        selected: &SelectedGnuObject,
        command: &CommandSpec,
    ) -> Result<Option<Vec<u8>>, String> {
        let mut state = selected.helper.lock().expect("GNU helper lock");
        if matches!(*state, GnuHelperState::Uninitialized) {
            let mut startup = command.clone();
            startup.stdin = None;
            *state = match self.runner.start_session(&startup) {
                Ok(Some(helper)) => GnuHelperState::Live(helper),
                Ok(None) => GnuHelperState::Batched,
                Err(error) => GnuHelperState::Failed(format!("failed to start addr2line: {error}")),
            };
        }
        match &mut *state {
            GnuHelperState::Live(helper) => {
                // perf addr2line.c:300-335 retains one DSO helper and bounds
                // response reads; symbol.c:72 defaults that wait to 5 seconds.
                // GNU -f without -i emits exactly function/file lines, then
                // flushes each stdin address in translate_addresses:422-429.
                let result = (|| {
                    let mut stdout = Vec::new();
                    for address in command
                        .stdin
                        .as_deref()
                        .unwrap_or_default()
                        .split_inclusive(|byte| *byte == b'\n')
                    {
                        let response =
                            helper.exchange_lines(address, 2, std::time::Duration::from_secs(5))?;
                        stdout.extend(response);
                    }
                    Ok::<_, std::io::Error>(stdout)
                })();
                match result {
                    Ok(stdout) => Ok(Some(stdout)),
                    Err(error) => {
                        let error = format!("addr2line session failed: {error}");
                        *state = GnuHelperState::Failed(error.clone());
                        Err(error)
                    }
                }
            }
            GnuHelperState::Failed(error) => Err(error.clone()),
            GnuHelperState::Batched => Ok(None),
            GnuHelperState::Uninitialized => unreachable!("helper state was initialized"),
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
            kcore_symbols: OnceLock::new(),
            ordinary_kernel_load: Mutex::new(OrdinaryKernelLoad::default()),
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
    /// Configures lazy kernel sources for a completed recording.
    ///
    /// The perfdata replay supplies the currently delivered maps automatically.
    /// Direct symbol callers must call [`SymbolResolver::initialize_kernel_maps`]
    /// with that context before their first kernel lookup. Only architecture
    /// metadata is read from the recording; its event stream is not replayed.
    /// This follows perf `map.c:map__load` and
    /// `symbol.c:validate_kcore_addresses` at the first DSO load.
    pub fn with_perfdata_file_kernel_cache(mut self, perfdata: &Path, debug_dir: &Path) -> Self {
        // tools/perf/util/symbol.c:dso__load loads symbols on demand. A
        // user-only recording must not first be traversed to find kernel IDs.
        self.file_kernel_cache = Some(FileKernelCache {
            perfdata: perfdata.to_path_buf(),
            debug_dir: debug_dir.to_path_buf(),
            loaded: OnceLock::new(),
            arch: OnceLock::new(),
        });
        self.debug_dir = Some(debug_dir.to_path_buf());
        self
    }

    fn with_perfdata_kernel_build_id(self, build_id: &str, debug_dir: &Path) -> Self {
        let mut self_with_debug_dir = self.with_debug_dir(debug_dir.to_path_buf());
        if !build_id_is_defined(build_id) {
            return self_with_debug_dir;
        }
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
                .symbols()?
                .build_id
                .as_deref()
        })
    }

    fn kernel_elf_ref(&self) -> Option<&PathBuf> {
        self.kernel_elf
            .as_ref()
            .or_else(|| self.file_kernel_cache.as_ref()?.symbols()?.elf.as_ref())
    }

    fn kallsyms_ref(&self) -> Option<&Kallsyms> {
        self.kallsyms.as_ref().or_else(|| {
            self.file_kernel_cache
                .as_ref()?
                .symbols()?
                .kallsyms
                .as_ref()
        })
    }
}

impl Kallsyms {
    /// Parses `/proc/kallsyms`-style text.
    ///
    /// # Errors
    ///
    /// Returns an error when no valid symbols are present.
    pub fn parse(text: &str) -> Result<Self, String> {
        Self::parse_symbols(text, true)
    }

    fn parse_symbols(text: &str, index_names: bool) -> Result<Self, String> {
        let mut symbols = BTreeMap::new();
        let mut addresses_by_name = FxHashMap::default();
        for (address, symbol) in text
            .lines()
            .filter_map(parse_kallsyms_line)
            .filter(|(address, _)| *address != 0)
        {
            insert_kallsyms_symbol(
                &mut symbols,
                index_names.then_some(&mut addresses_by_name),
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
            physical: None,
        })
    }

    /// Parses only module-backed `/proc/kallsyms` lines.
    ///
    /// # Errors
    ///
    /// Returns an error when no valid module symbols are present.
    pub fn parse_modules(text: &str) -> Result<Self, String> {
        let mut addresses_by_name = FxHashMap::default();
        let symbols = Self::parse_module_symbols(text)
            .into_iter()
            .filter_map(|row| {
                let module = row.module?;
                let symbol = row.into_module_symbol(module);
                addresses_by_name
                    .entry(Arc::clone(&symbol.name))
                    .or_insert(row.address);
                Some((row.address, symbol))
            })
            .collect::<BTreeMap<_, _>>();
        if symbols.is_empty() {
            return Err("kallsyms did not contain any parseable module symbols".to_string());
        }
        let mut result = Self {
            symbols,
            addresses_by_name,
            module_indexes: FxHashMap::default(),
            physical: None,
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
        let mut addresses_by_name = FxHashMap::default();
        for (address, symbol) in &symbols {
            addresses_by_name
                .entry(Arc::clone(&symbol.name))
                .or_insert(*address);
        }
        let mut result = Self {
            symbols,
            addresses_by_name,
            module_indexes: FxHashMap::default(),
            physical: None,
        };
        result.build_module_indexes();
        Ok(result)
    }

    fn parse_module_symbols(text: &str) -> Vec<BorrowedKallsymsRow<'_>> {
        Self::parse_global_kallsyms(text)
    }

    fn parse_global_kallsyms(text: &str) -> Vec<BorrowedKallsymsRow<'_>> {
        #[cfg(test)]
        MODULE_KALLSYMS_TREE_BUILDS.with(|count| count.set(count.get() + 1));
        let mut symbols = Vec::new();
        for line in text.split_terminator('\n') {
            let Some(row) = parse_global_kallsyms_row(line) else {
                continue;
            };
            // symbol.c:dso__load_all_kallsyms filters before tree insertion;
            // event.c:find_func_symbol_cb separately accepts A references.
            if row.address == 0
                || !perf_kallsyms_type_is_kept(row.symbol_type)
                || row.name.starts_with('$')
            {
                continue;
            }
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

    fn module_views_from_symbols<'a>(
        symbols: impl IntoIterator<Item = BorrowedKallsymsRow<'a>>,
    ) -> FxHashMap<String, Arc<Self>> {
        let mut modules = FxHashMap::<String, Self>::default();
        for row in symbols {
            let Some(module) = row.module else {
                continue;
            };
            let view = match modules.raw_entry_mut().from_key(module) {
                RawEntryMut::Occupied(entry) => entry.into_mut(),
                RawEntryMut::Vacant(entry) => entry.insert(module.to_owned(), Self::default()).1,
            };
            // Ascending global addresses preserve the path API's first-by-IP
            // name index, even when the input rows were not address ordered.
            let symbol = row.into_module_symbol(module);
            view.addresses_by_name
                .entry(Arc::clone(&symbol.name))
                .or_insert(row.address);
            view.symbols.insert(row.address, symbol);
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
            .find_map(|text| {
                // perf symbol.c:1480 kallsyms__delta uses event.c:132
                // kallsyms__get_function_start on the selected cached file,
                // not a name index of its display symbols.
                let mut symbols = Self::parse_symbols(&text, false).ok()?;
                symbols.physical = Some(Arc::new(KallsymsReferenceSource::new(
                    text.into_boxed_str(),
                )));
                Some(symbols)
            })
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
            .map(|(_, symbol)| symbol.name.to_string())
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
        match &self.physical {
            Some(source) => source.reference_address(name),
            None => self.addresses_by_name.get(name).copied(),
        }
    }
}

#[must_use]
pub fn build_addr2line_command(path: &Path, requests: &[SymbolRequest]) -> CommandSpec {
    addr2line_command(path, requests.iter().map(SymbolRequest::inline_address))
}

fn addr2line_command(path: &Path, addresses: impl Iterator<Item = u64>) -> CommandSpec {
    let mut stdin = String::new();
    for address in addresses {
        writeln!(stdin, "0x{address:x}").expect("writing to a string cannot fail");
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
            replaced_kernel_entries: SmallVec::new(),
            kernel_cursor_hint: None,
            preprocessed_kernel_modules: FxHashSet::default(),
        }
    }

    pub(crate) fn requires_kernel_cursor_order(&self) -> bool {
        self.resolver.requires_kernel_cursor_order()
    }

    pub(crate) fn preprocess_sample_ip(&mut self, mapping: &ResolvedMappingRef<'_>) {
        // map.c:map__load and symbol.c:dso__load retain a module's first load,
        // including failures. Replay source IDs distinguish same-path DSOs.
        if (is_kernel_module_symbol_path_str(mapping.path)
            || mapping.kernel_module_address.is_some())
            && !self
                .preprocessed_kernel_modules
                .insert(mapping.symbol_source_id)
        {
            return;
        }
        self.resolver.preprocess_sample_ip(mapping);
    }

    pub(crate) fn finish_kernel_cursor(&mut self) {
        // Keep pre-core positive object results cached until replacement
        // actually occurs. Repeated module-only samples must not symbolize
        // the same object address again on every cursor.
        if self.kernel_cursor_hint.is_some()
            || self.replaced_kernel_entries.is_empty()
            || self.resolver.requires_kernel_cursor_order()
        {
            return;
        }
        for (inline, key, _) in self.replaced_kernel_entries.drain(..) {
            let table = if inline {
                &mut self.resolved_by_mapping
            } else {
                &mut self.resolved_base_by_mapping
            };
            // These entries are old host-kernel module cursors only. Their
            // rendered projections stay valid; later lookups get a new revision.
            table.kernel.remove(&key);
        }
    }

    pub(crate) fn finish_kernel_sample(&mut self) {
        self.kernel_cursor_hint = None;
        self.finish_kernel_cursor();
    }

    pub(crate) fn resolve_script_mapping_ref(
        &mut self,
        mapping: &ResolvedMappingRef<'_>,
        inline: bool,
    ) -> Result<&CachedMappingFrames, String> {
        let key = mapping_frame_key(mapping);
        if let Some((previous, object)) = self.kernel_cursor_hint {
            if previous.symbol_source_id == key.symbol_source_id
                && previous.kernel_mapping_range == key.kernel_mapping_range
            {
                let table = if inline {
                    &self.resolved_by_mapping
                } else {
                    &self.resolved_base_by_mapping
                };
                if table.slot(&key).is_none() {
                    let frames = if object {
                        self.resolver.resolve_original_kernel_module_frames(
                            &symbol_request_from_mapping_ref(mapping),
                            inline,
                        )?
                    } else {
                        ResolvedSymbolFrames::default()
                    };
                    self.replaced_kernel_entries.push((inline, key, object));
                    let table = if inline {
                        &mut self.resolved_by_mapping
                    } else {
                        &mut self.resolved_base_by_mapping
                    };
                    table.insert(key, CachedMappingFrames::from_resolved(frames));
                }
            } else {
                self.finish_kernel_sample();
            }
        }
        self.prefetch_mapping_refs_with_mode(std::slice::from_ref(mapping), inline)?;
        if let Some((_, _, object)) = self
            .replaced_kernel_entries
            .iter()
            .find(|(entry_inline, entry_key, _)| *entry_inline == inline && *entry_key == key)
        {
            self.kernel_cursor_hint = Some((key, *object));
        }
        self.resolve_cached_mapping(mapping, inline)
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

    pub(crate) fn resolver(&self) -> &'a R {
        self.resolver
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
                if matches!(
                    frames.source_state,
                    SymbolSourceState::KernelMapReplaced
                        | SymbolSourceState::KernelObjectMapReplaced
                ) {
                    self.replaced_kernel_entries.push((
                        inline,
                        key,
                        frames.source_state == SymbolSourceState::KernelObjectMapReplaced,
                    ));
                }
                let unavailable = frames.source_state == SymbolSourceState::Unavailable;
                let frames = CachedMappingFrames::from_resolved(frames);
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
    fn initialize_kernel_maps(&self, table: &MmapTable) {
        // A module without a delivered core map cannot load that core DSO yet.
        if self.kcore_symbols.get().is_some() {
            return;
        }
        let Some(core) = table
            .host_kernel_mappings()
            .find(|mapping| mapping.path.starts_with("[kernel.kallsyms]"))
        else {
            return;
        };
        if let Some(cache) = &self.file_kernel_cache {
            cache.initialize_symbols(core.build_id);
        }
        self.kcore_symbols.get_or_init(|| {
            // Explicit/cached sources retain their original mapping identity.
            if self.kallsyms_ref().is_some() || self.kernel_elf_ref().is_some() {
                return None;
            }
            let kallsyms_path = self.live_kallsyms_path.as_deref()?;
            if kallsyms_path.file_name()? != "kallsyms" {
                return None;
            }
            let arch = self.file_kernel_cache.as_ref()?.arch()?;
            kcore::KcoreSymbols::load(table, arch, kallsyms_path, self.live_kallsyms_snapshot()?)
        });
    }

    fn preprocess_sample_ip(&self, mapping: &ResolvedMappingRef<'_>) {
        if is_kernel_module_symbol_path_str(mapping.path) || mapping.kernel_module_address.is_some()
        {
            self.record_ordinary_module_path(mapping.path);
            if let Some(symbols) = self.kcore_symbols_ref()
                && !symbols.is_active()
            {
                let request = symbol_request_from_mapping_ref(mapping);
                let object_request = self.module_object_symbol_request(
                    &request,
                    &mut self
                        .address_cache
                        .lock()
                        .expect("object address cache lock"),
                );
                if let Some(object_request) = object_request
                    && let Some(metadata) = self
                        .object_resolver
                        .selected_object_module_metadata(&object_request.path, &request)
                {
                    // event.c:machine__resolve loads this DSO before callchain
                    // lookup. Apply its section maps without initializing core
                    // maps: the event's original module cursor still exists.
                    symbols.validate_module_maps(Path::new(mapping.path), &metadata.maps);
                }
            }
        } else if is_kernel_symbol_path(Path::new(mapping.path)) {
            if let Some(symbols) = self.kcore_symbols_ref() {
                symbols.activate(false);
            } else if self.kallsyms_ref().is_none() && self.kernel_elf_ref().is_none() {
                self.live_kallsyms_ref();
            }
            self.ordinary_kernel_load
                .lock()
                .expect("kernel DSO load lock")
                .core_loaded = true;
        }
    }
    fn selected_object_module_metadata(
        &self,
        path: &Path,
        module: &SymbolRequest,
    ) -> Option<Arc<KernelModuleObjectMetadata>> {
        self.object_resolver
            .selected_object_module_metadata(path, module)
    }

    fn object_build_id(&self, path: &Path) -> Option<Vec<u8>> {
        let mut cache = self
            .address_cache
            .lock()
            .expect("object address cache lock");
        let id = object_address_metadata(path, &mut cache)?
            .build_id
            .as_deref()?;
        Some(hex_build_id_bytes(id).expect("ELF build-ID hexadecimal"))
    }

    fn requires_kernel_cursor_order(&self) -> bool {
        if let Some(symbols) = self.kcore_symbols_ref() {
            return !symbols.is_active();
        }
        !self
            .ordinary_kernel_load
            .lock()
            .expect("kernel DSO load lock")
            .core_loaded
    }

    fn resolve_original_kernel_module_frames(
        &self,
        request: &SymbolRequest,
        inline: bool,
    ) -> Result<ResolvedSymbolFrames, String> {
        let object_request = self.module_object_symbol_request(
            request,
            &mut self
                .address_cache
                .lock()
                .expect("object address cache lock"),
        );
        let Some(object_request) = object_request else {
            return Ok(ResolvedSymbolFrames::default());
        };
        self.resolve_object_frame_batch(std::slice::from_ref(&object_request), inline)?
            .into_iter()
            .next()
            .ok_or_else(|| "missing original module frame result".into())
    }

    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        if self.requires_ordered_kernel_batch(requests) {
            return Self::resolve_ordered_kernel_batch(requests, |batch| self.resolve_batch(batch));
        }
        let mut resolved = vec![None; requests.len()];
        let mut kernel_elf_requests = Vec::new();
        let mut kernel_elf_indexes = Vec::new();
        let mut user_requests = Vec::new();
        let mut user_indexes = Vec::new();
        let mut old_module_objects = Vec::new();
        let mut address_cache = self
            .address_cache
            .lock()
            .expect("object address cache lock");

        for (index, request) in requests.iter().enumerate() {
            let kernel_address = request
                .kernel_module_address
                .unwrap_or(request.relative_address);
            if (is_kernel_symbol_path(&request.path) || request.kernel_module_address.is_some())
                && let Some(symbols) = self.kcore_symbols_ref()
                && symbols.contains(kernel_address)
            {
                let module = is_kernel_module_request(request);
                if module
                    && !symbols.is_active()
                    && let Some(object_request) =
                        self.module_object_symbol_request(request, &mut address_cache)
                {
                    old_module_objects.push(index);
                    user_indexes.push(index);
                    user_requests.push(object_request);
                } else if symbols.activate(module) {
                    resolved[index] = symbols.resolve(kernel_address);
                }
            } else if is_kernel_module_request(request) {
                self.record_ordinary_module_load(request);
                if let Some(object_request) =
                    self.module_object_symbol_request(request, &mut address_cache)
                {
                    user_indexes.push(index);
                    user_requests.push(object_request);
                } else {
                    resolved[index] = self.resolve_kernel_symbol(request);
                }
            } else if is_kernel_symbol_path(&request.path) {
                let symbol = self.resolve_kernel_symbol(request);
                if self.ordinary_kernel_address_is_unmapped(request) {
                    resolved[index] = None;
                } else if let Some(symbol) = symbol {
                    resolved[index] = Some(symbol);
                } else if let Some(kernel_elf) = self.kernel_elf_ref() {
                    if !object_build_id_matches(kernel_elf, request, &mut address_cache) {
                        continue;
                    }
                    kernel_elf_indexes.push(index);
                    kernel_elf_requests.push(clean_object_symbol_request_with_cache(
                        kernel_elf.clone(),
                        request.relative_address,
                        &mut address_cache,
                        true,
                    ));
                }
            } else {
                let object_request = self.object_symbol_request(request, &mut address_cache);
                if !object_build_id_matches(&object_request.path, request, &mut address_cache) {
                    continue;
                }
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
            for ((index, symbol), object_request) in user_indexes
                .into_iter()
                .zip(user_symbols)
                .zip(&user_requests)
            {
                if old_module_objects.contains(&index) {
                    // Loading a module also initializes the core maps, but this
                    // cursor keeps its original module source.
                    self.finish_module_object_load(&requests[index], &object_request.path);
                    resolved[index] = symbol;
                } else {
                    resolved[index] = symbol.or_else(|| {
                        is_kernel_module_request(&requests[index])
                            .then(|| self.resolve_kernel_symbol(&requests[index]))
                            .flatten()
                    });
                }
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
    fn requires_ordered_kernel_batch(&self, requests: &[SymbolRequest]) -> bool {
        requests.len() > 1
            && requests.iter().any(is_kernel_symbol_request)
            && self.requires_kernel_cursor_order()
    }

    fn resolve_ordered_kernel_batch<T>(
        mut requests: &[SymbolRequest],
        resolve: impl Fn(&[SymbolRequest]) -> Result<Vec<T>, String>,
    ) -> Result<Vec<T>, String> {
        // perf machine.c:add_callchain_ip resolves each kernel cursor before
        // the next. Complete map-changing loads in order, retaining batches
        // for adjacent user requests which cannot change kernel source state.
        let mut results = Vec::with_capacity(requests.len());
        while !requests.is_empty() {
            let count = if is_kernel_symbol_request(&requests[0]) {
                1
            } else {
                requests
                    .iter()
                    .position(is_kernel_symbol_request)
                    .unwrap_or(requests.len())
            };
            let (batch, rest) = requests.split_at(count);
            results.extend(resolve(batch)?);
            requests = rest;
        }
        Ok(results)
    }

    fn resolve_routed_frame_batch(
        &self,
        requests: &[SymbolRequest],
        inline: bool,
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        if self.requires_ordered_kernel_batch(requests) {
            return Self::resolve_ordered_kernel_batch(requests, |batch| {
                self.resolve_routed_frame_batch(batch, inline)
            });
        }
        let mut resolved = vec![ResolvedSymbolFrames::default(); requests.len()];
        let mut kernel_elf_requests = SmallVec::<[SymbolRequest; 16]>::new();
        let mut kernel_elf_indexes = RequestIndexes::new();
        let mut user_requests = SmallVec::<[SymbolRequest; 16]>::new();
        let mut user_indexes = RequestIndexes::new();
        let mut old_module_objects = SmallVec::<[usize; 4]>::new();
        let mut address_cache = self
            .address_cache
            .lock()
            .expect("object address cache lock");

        for (index, request) in requests.iter().enumerate() {
            let kernel_address = request
                .kernel_module_address
                .unwrap_or(request.relative_address);
            if (is_kernel_symbol_path(&request.path) || request.kernel_module_address.is_some())
                && let Some(symbols) = self.kcore_symbols_ref()
                && symbols.contains(kernel_address)
            {
                let module = is_kernel_module_request(request);
                if module
                    && !symbols.is_active()
                    && let Some(object_request) =
                        self.module_object_symbol_request(request, &mut address_cache)
                {
                    old_module_objects.push(index);
                    user_indexes.push(index);
                    user_requests.push(object_request);
                } else if symbols.activate(module) {
                    resolved[index] = ResolvedSymbolFrames::from_frames(
                        symbols.resolve(kernel_address).into_iter().collect(),
                    );
                    resolved[index].kernel_dso = SymbolDsoName::KernelKallsyms;
                } else {
                    resolved[index].source_state = SymbolSourceState::KernelMapReplaced;
                }
            } else if is_kernel_module_request(request) {
                self.record_ordinary_module_load(request);
                if let Some(object_request) =
                    self.module_object_symbol_request(request, &mut address_cache)
                {
                    user_indexes.push(index);
                    user_requests.push(object_request);
                } else if let Some(symbol) = self.resolve_kernel_symbol(request) {
                    resolved[index] = ResolvedSymbolFrames::from_frames(vec![symbol]);
                }
            } else if is_kernel_symbol_path(&request.path) {
                if let Some(frames) = self.resolve_kernel_frames(request) {
                    resolved[index] = frames;
                } else if let Some(kernel_elf) = self.kernel_elf_ref() {
                    if !object_build_id_matches(kernel_elf, request, &mut address_cache) {
                        resolved[index].source_state = SymbolSourceState::Unavailable;
                        continue;
                    }
                    kernel_elf_indexes.push(index);
                    kernel_elf_requests.push(clean_object_symbol_request_with_cache(
                        kernel_elf.clone(),
                        request.relative_address,
                        &mut address_cache,
                        true,
                    ));
                }
            } else {
                let object_request = self.object_symbol_request(request, &mut address_cache);
                if !object_build_id_matches(&object_request.path, request, &mut address_cache) {
                    resolved[index].source_state = SymbolSourceState::Unavailable;
                    continue;
                }
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
            for ((index, frames), object_request) in user_indexes
                .into_iter()
                .zip(user_frames)
                .zip(&user_requests)
            {
                resolved[index] = self.finish_module_frame(
                    frames,
                    &requests[index],
                    &object_request.path,
                    old_module_objects.contains(&index),
                );
            }
        }
        Ok(resolved)
    }

    fn finish_module_frame(
        &self,
        frames: ResolvedSymbolFrames,
        request: &SymbolRequest,
        path: &Path,
        old_module: bool,
    ) -> ResolvedSymbolFrames {
        let module = is_kernel_module_request(request);
        let mut frames = if frames.frames.is_empty() && module && !old_module {
            self.resolve_kernel_symbol(request)
                .map(|symbol| ResolvedSymbolFrames::from_frames(vec![symbol]))
                .unwrap_or(frames)
        } else {
            frames
        };
        // A missing module ELF does not rule out its kallsyms source.
        if module {
            frames.source_state = SymbolSourceState::AddressDependent;
        }
        if old_module {
            // Initialize core maps after resolving this cursor's original DSO.
            self.finish_module_object_load(request, path);
            frames.source_state = SymbolSourceState::KernelObjectMapReplaced;
        }
        frames
    }

    fn finish_module_object_load(&self, module: &SymbolRequest, selected: &Path) {
        if let Some(symbols) = self.kcore_symbols_ref() {
            let metadata = self
                .object_resolver
                .selected_object_module_metadata(selected, module);
            symbols.finish_module_load(
                &module.path,
                metadata.as_deref().map_or(&[], |metadata| &metadata.maps),
            );
        }
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

    fn module_object_symbol_request(
        &self,
        request: &SymbolRequest,
        address_cache: &mut ObjectAddressCache,
    ) -> Option<SymbolRequest> {
        // perf symbol.c:dso__load tries the regular system module pathname
        // after build-ID sources. Bracketed paths have no live object name.
        let mut selected = if request.kernel_module_address.is_some() {
            Some(self.object_symbol_request(request, address_cache))
        } else {
            self.cached_object_symbol_request(request, address_cache)
        }?;
        if request.kernel_module_address.is_some()
            && let Some(recorded) = request.recorded_build_id()
            && self
                .object_resolver
                .object_build_id(&selected.path)
                .as_deref()
                .map(build_id_hex)
                .as_deref()
                != Some(recorded)
        {
            // symbol-elf.c:symsrc__init rejects a missing/mismatched ID before
            // loading any symbols or section maps, including the live fallback.
            return None;
        }
        if let Some((start, _)) = request.kernel_mapping_range
            && let Some(offset) = request
                .kernel_module_address
                .unwrap_or(request.relative_address)
                .checked_sub(start)
            && let Some(text_address) = self
                .object_resolver
                .selected_object_module_metadata(&selected.path, request)
                .and_then(|metadata| metadata.text_address)
            && let Some(address) = text_address.checked_add(offset)
        {
            // symbol-elf.c:dso__process_kernel_symbol remaps .text's pgoff;
            // adjusted symbol file offsets map back to this retained text VMA.
            // Recorded module pgoff is not the post-load text-section offset.
            selected.relative_address = address;
        }
        Some(selected)
    }

    fn cached_object_symbol_request(
        &self,
        request: &SymbolRequest,
        address_cache: &mut ObjectAddressCache,
    ) -> Option<SymbolRequest> {
        let debug_dir = self.debug_dir.as_ref()?;
        let build_id = request.recorded_build_id()?;
        let elf = perf_build_id_elf_path_for_dso(debug_dir, &request.path, build_id);
        (elf.exists() && object_build_id_matches(&elf, request, address_cache)).then(|| {
            clean_object_symbol_request_with_cache(
                elf,
                request.relative_address,
                address_cache,
                is_kernel_symbol_request(request),
            )
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
            is_kernel_symbol_request(request),
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
        if request.recorded_build_id().is_some_and(|id| {
            live_vdso.build_id.as_deref().map(build_id_hex).as_deref() != Some(id)
        }) {
            return None;
        }
        Some(clean_object_symbol_request_with_cache(
            live_vdso.path.clone(),
            request.relative_address,
            address_cache,
            false,
        ))
    }

    fn live_kallsyms_ref(&self) -> Option<&Kallsyms> {
        self.live_kallsyms
            .as_ref()
            .or_else(|| self.live_kallsyms_snapshot()?.core.as_ref())
    }

    fn live_kallsyms_snapshot(&self) -> Option<&LiveKallsymsSnapshot> {
        self.live_kallsyms_cache
            .get_or_init(|| {
                let text = std::fs::read_to_string(self.live_kallsyms_path.as_ref()?)
                    .ok()?
                    .into_boxed_str();
                // perf symbol.c:__dso__load_kallsyms (1494-1523) reads and
                // splits the complete tree during core loading, not during
                // each module's later first query. Both views own one snapshot.
                let mut core = Kallsyms::default();
                let rows = Kallsyms::parse_global_kallsyms(&text);
                let mut names = FxHashMap::<&str, Arc<str>>::default();
                for row in rows.iter().filter(|row| row.module.is_none()) {
                    let name =
                        Arc::clone(names.entry(row.name).or_insert_with(|| Arc::from(row.name)));
                    core.symbols.insert(
                        row.address,
                        KallsymsSymbol {
                            name,
                            end: Some(row.end),
                            module: None,
                        },
                    );
                }
                drop(names);
                let modules = Kallsyms::module_views_from_symbols(rows);
                Some(LiveKallsymsSnapshot {
                    core: (!core.symbols.is_empty()).then_some(core),
                    modules,
                    physical: KallsymsReferenceSource::new(text),
                })
            })
            .as_ref()
    }

    fn live_module_kallsyms_for_name(&self, module_name: &str) -> Option<Arc<Kallsyms>> {
        // symbol.c:maps__split_kallsyms (914) looks up the bound DSO short
        // name. Do not reinterpret it as a raw MMAP filename here.
        self.live_kallsyms_snapshot()?
            .modules
            .get(module_name)
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

    fn kcore_symbols_ref(&self) -> Option<&kcore::KcoreSymbols> {
        self.kcore_symbols
            .get()?
            .as_ref()
            .filter(|symbols| !symbols.is_rejected())
    }

    fn resolve_kernel_frames(&self, request: &SymbolRequest) -> Option<ResolvedSymbolFrames> {
        let symbol = self.resolve_kernel_symbol(request);
        if self.ordinary_kernel_address_is_unmapped(request) {
            return Some(ResolvedSymbolFrames {
                kernel_dso: SymbolDsoName::Unmapped,
                ..ResolvedSymbolFrames::default()
            });
        }
        symbol.map(|symbol| ResolvedSymbolFrames::from_frames(vec![symbol]))
    }

    fn ordinary_kernel_address_is_unmapped(&self, request: &SymbolRequest) -> bool {
        // Only ordinary live kallsyms applies symbol.c:dso__load_kernel_sym's
        // map fixup here. Explicit objects and validated kcore own other maps.
        if self.kallsyms_ref().is_some() || self.kernel_elf_ref().is_some() {
            return false;
        }
        self.live_kallsyms_cache
            .get()
            .and_then(Option::as_ref)
            .and_then(|snapshot| snapshot.kernel_map_range(request.kernel_relocation.as_ref()))
            .is_some_and(|(start, end)| {
                request.relative_address < start || request.relative_address >= end
            })
    }

    fn resolve_kernel_symbol(&self, request: &SymbolRequest) -> Option<String> {
        if is_kernel_module_request(request) {
            let module_name = kcore::module_dso_short_name(request.path.to_str()?);
            {
                // perf symbol.c:dso__load sets loaded even on failure (1866).
                // maps__split_kallsyms (913) discards those DSO rows when the
                // core source is loaded later; a module cannot load it itself.
                let load = self
                    .ordinary_kernel_load
                    .lock()
                    .expect("kernel DSO load lock");
                if !load.core_loaded {
                    return None;
                }
                if load
                    .modules_loaded_before_core
                    .contains(module_name.as_ref())
                {
                    return None;
                }
            }
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
                    self.live_module_kallsyms_for_name(&module_name)
                        .and_then(|kallsyms| resolve_module_kallsyms(kallsyms.as_ref(), request))
                })
        } else {
            self.ordinary_kernel_load
                .lock()
                .expect("kernel DSO load lock")
                .core_loaded = true;
            self.kallsyms_ref()
                .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request))
                .or_else(|| {
                    // tools/perf/util/symbol.c dso__find_kallsyms() tries the
                    // host/root /proc/kallsyms path before the final cached
                    // kallsyms fallback for host kernel maps.
                    match self.live_kallsyms.as_ref() {
                        Some(kallsyms) => resolve_kernel_kallsyms(kallsyms, request),
                        None => self.live_kallsyms_snapshot()?.resolve_core(request),
                    }
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

    fn record_ordinary_module_load(&self, request: &SymbolRequest) {
        if let Some(path) = request.path.to_str() {
            self.record_ordinary_module_path(path);
        }
    }

    fn record_ordinary_module_path(&self, path: &str) {
        let mut load = self
            .ordinary_kernel_load
            .lock()
            .expect("kernel DSO load lock");
        if !load.core_loaded {
            let name = kcore::module_dso_short_name(path);
            // Both successful and failed dso__load attempts set loaded; a
            // selected ELF must not gain kallsyms symbols in its address gaps.
            load.modules_loaded_before_core.insert(name.into_owned());
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
    clean_object_symbol_request_with_cache(path, relative_address, &mut address_cache, false)
}

fn clean_object_symbol_request_with_cache(
    path: PathBuf,
    relative_address: u64,
    address_cache: &mut ObjectAddressCache,
    kernel: bool,
) -> SymbolRequest {
    // perf machine.c:2110 -> map.c:529 uses a user DSO's global .text bias
    // for inline lookup, independently of its symbol's PT_LOAD bias.
    // Kernel objects/modules use their kernel relocation instead (map.c:559).
    let metadata = object_address_metadata(&path, address_cache);
    let addr2line_address = metadata
        .filter(|_| !kernel)
        .map(|metadata| relative_address.wrapping_add(metadata.text_offset));
    let relative_address = metadata
        .and_then(|metadata| {
            metadata.segments.iter().find_map(|segment| {
                (relative_address >= segment.file_offset && relative_address < segment.file_end)
                    .then(|| segment.virtual_address + (relative_address - segment.file_offset))
            })
        })
        .unwrap_or(relative_address);
    SymbolRequest {
        addr2line_address,
        kernel_module_address: None,
        path,
        relative_address,
        kernel_mapping_range: None,
        build_id: None,
        file_identity: None,
        kernel_relocation: None,
    }
}

fn object_address_metadata<'a>(
    path: &Path,
    address_cache: &'a mut ObjectAddressCache,
) -> Option<&'a ObjectAddressMetadata> {
    let metadata = match address_cache
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
    metadata.as_ref()
}

fn object_build_id_matches(
    path: &Path,
    request: &SymbolRequest,
    address_cache: &mut ObjectAddressCache,
) -> bool {
    let Some(recorded) = request.recorded_build_id() else {
        return true;
    };
    object_address_metadata(path, address_cache)
        .and_then(|metadata| metadata.build_id.as_deref())
        .is_some_and(|actual| actual.eq_ignore_ascii_case(recorded))
}

fn object_load_segment_ranges(path: &Path) -> Option<ObjectAddressMetadata> {
    let file = open_regular_object(path)?;
    let len = file.metadata().ok()?.len();
    // ReadCache fetches ELF headers, notes and tables on demand, not the image.
    // Restrict its view to the opened file's size even if the file grows.
    let cache = object::read::ReadCache::new(file);
    let range = cache.range(0, len);
    let object = object::File::parse(range).ok()?;
    if object.format() != object::BinaryFormat::Elf {
        return None;
    }
    let build_id = object
        .build_id()
        .ok()?
        .filter(|id| !id.is_empty())
        .map(build_id_hex);
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
    Some(ObjectAddressMetadata {
        segments,
        text_offset: object_text_offset(&object),
        build_id,
    })
}

fn object_text_offset<'data, R: object::read::ReadRef<'data>>(
    object: &object::File<'data, R>,
) -> u64 {
    use object::read::elf::SectionHeader;
    // symbol-elf.c:1508 reads sh_offset even for NOBITS .text in debug files.
    let (address, offset) = match object {
        object::File::Elf32(file) => file.section_by_name(".text").map(|section| {
            (
                section.address(),
                u64::from(section.elf_section_header().sh_offset(file.endian())),
            )
        }),
        object::File::Elf64(file) => file.section_by_name(".text").map(|section| {
            (
                section.address(),
                section.elf_section_header().sh_offset(file.endian()),
            )
        }),
        _ => None,
    }
    .unwrap_or_default();
    address.wrapping_sub(offset)
}

fn open_regular_object(path: &Path) -> Option<std::fs::File> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A replacement FIFO between stat and open must not block at open.
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = options.open(path).ok()?;
    file.metadata().ok()?.is_file().then_some(file)
}

fn read_regular_object(path: &Path) -> Option<Vec<u8>> {
    let file = open_regular_object(path)?;
    let len = file.metadata().ok()?.len();
    read_object_with_size(file, len)
}

fn read_regular_snapshot(path: &Path) -> Option<Arc<Vec<u8>>> {
    let file = open_regular_object(path)?;
    let len = file.metadata().ok()?.len();
    read_snapshot_with_size(file, len).map(retain_object_snapshot)
}

fn retain_object_snapshot(bytes: Vec<u8>) -> Arc<Vec<u8>> {
    Arc::new(bytes)
}

fn read_snapshot_with_size(reader: impl Read, len: u64) -> Option<Vec<u8>> {
    let size = usize::try_from(len).ok()?;
    let mut bytes = Vec::new();
    // Reserve the frozen extent, not a geometrically grown read buffer.
    bytes.try_reserve_exact(size).ok()?;
    // Like elfutils lib/system.h:pread_retry, read_to_end retries interrupted
    // reads; Take excludes growth and the length check rejects truncation.
    reader.take(len).read_to_end(&mut bytes).ok()?;
    (bytes.len() == size).then_some(bytes)
}

fn read_object_with_size(mut reader: impl Read + std::io::Seek, len: u64) -> Option<Vec<u8>> {
    // Classify through a bounded view before allocating the whole image. PE
    // recognition may seek beyond the initial magic to its optional header.
    let kind = {
        let cache = object::read::ReadCache::new(&mut reader);
        object::FileKind::parse(cache.range(0, len)).ok()?
    };
    if !matches!(
        kind,
        object::FileKind::Elf32
            | object::FileKind::Elf64
            | object::FileKind::MachO32
            | object::FileKind::MachO64
            | object::FileKind::Pe32
            | object::FileKind::Pe64
            | object::FileKind::Coff
            | object::FileKind::CoffBig
            | object::FileKind::Xcoff32
            | object::FileKind::Xcoff64
    ) {
        return None;
    }
    reader.rewind().ok()?;
    let bytes = read_snapshot_with_size(reader, len)?;
    object::File::parse(bytes.as_slice()).ok()?;
    Some(bytes)
}

impl<R> SymbolResolver for Addr2lineResolver<'_, R>
where
    R: CommandRunner,
{
    fn object_build_id(&self, path: &Path) -> Option<Vec<u8>> {
        self.object_metadata(path)?.build_id()
    }

    fn selected_object_module_metadata(
        &self,
        path: &Path,
        module: &SymbolRequest,
    ) -> Option<Arc<KernelModuleObjectMetadata>> {
        self.object_metadata(path)
            .map(|metadata| metadata.module_metadata(module, |path| self.object_metadata(path)))
    }

    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        let mut resolved = vec![None; requests.len()];
        for (path, indexes) in grouped_request_indexes(requests) {
            let path = Path::new(path);
            let Some(selected) = self.selected_object(path) else {
                continue;
            };
            let symbols = self.resolve_group_symbols(path, &selected, requests, &indexes)?;
            for (index, symbol) in indexes.into_iter().zip(symbols) {
                let request = &requests[index];
                let object_symbol = selected
                    .metadata
                    .object_metadata
                    .object_symbol(request.relative_address);
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
                                    request.inline_address(),
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
                    kernel_dso: SymbolDsoName::Mapping,
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
    fn object_build_id(&self, path: &Path) -> Option<Vec<u8>> {
        match self {
            Self::Addr2line(resolver) => resolver.object_build_id(path),
            Self::RustAddr2line(resolver) => resolver.object_build_id(path),
        }
    }

    fn selected_object_module_metadata(
        &self,
        path: &Path,
        module: &SymbolRequest,
    ) -> Option<Arc<KernelModuleObjectMetadata>> {
        match self {
            Self::Addr2line(resolver) => resolver.selected_object_module_metadata(path, module),
            Self::RustAddr2line(resolver) => resolver.selected_object_module_metadata(path, module),
        }
    }

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
    fn object_build_id(&self, path: &Path) -> Option<Vec<u8>> {
        self.object_metadata(path)?.build_id()
    }

    fn selected_object_module_metadata(
        &self,
        path: &Path,
        module: &SymbolRequest,
    ) -> Option<Arc<KernelModuleObjectMetadata>> {
        self.object_metadata(path)
            .map(|metadata| metadata.module_metadata(module, |path| self.object_metadata(path)))
    }

    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        let mut resolved = vec![None; requests.len()];
        for (path, indexes) in grouped_request_indexes(requests) {
            let path = Path::new(path);
            let Some(object_metadata) = self.object_metadata(path) else {
                continue;
            };
            let main_path = path.to_path_buf();
            let main_bytes = Arc::clone(&object_metadata.object_bytes);
            let Ok(loader) = addr2line::Loader::new_with_opener(path, move |requested| {
                if requested == main_path {
                    return Ok(Arc::clone(&main_bytes));
                }
                read_regular_snapshot(requested).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "cannot snapshot regular auxiliary file {}",
                            requested.display()
                        ),
                    )
                    .into()
                })
            }) else {
                continue;
            };
            for index in indexes {
                let request = &requests[index];
                let object_symbol = object_metadata
                    .object_metadata
                    .object_symbol(request.relative_address);
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
                let address = request.inline_address();
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
                // already follow perf's libdw attribute/demangling path. Rewriting
                // them again can invent spellings perf never printed.
                resolved[index] = ResolvedSymbolFrames {
                    frames,
                    source_state: SymbolSourceState::AddressDependent,
                    kernel_dso: SymbolDsoName::Mapping,
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
        .filter_map(|(&index, symbol)| symbol.bare.map(|_| requests[index].inline_address()))
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
                kernel_dso: SymbolDsoName::Mapping,
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
    if !perf_symbol_is_allocated_candidate(object, symbol) {
        return false;
    }
    if !elf_symbol_is_label(symbol) {
        return true;
    }
    symbol
        .section_index()
        .and_then(|index| object.section_by_index(index).ok())
        .and_then(|section| section.name().ok())
        .is_some_and(|name| name.contains("text") || name.contains("data"))
}

fn elf_symbol_is_label(symbol: &object::Symbol<'_, '_>) -> bool {
    matches!(symbol.flags(), object::SymbolFlags::Elf { st_info, .. }
        if st_info & 0xf == object::elf::STT_NOTYPE)
}

fn perf_symbol_is_allocated_candidate(
    object: &object::File<'_>,
    symbol: &object::Symbol<'_, '_>,
) -> bool {
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
            object::Architecture::Arm
            | object::Architecture::Aarch64
            | object::Architecture::Aarch64_Ilp32 => {
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
    // an allocated original section. Label section-name filtering follows
    // any NOBITS runtime-header substitution in the module loader.
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
}

fn elf_section_layout(
    object: &object::File<'_>,
    index: object::SectionIndex,
) -> Option<(u32, u64)> {
    use object::read::elf::SectionHeader as _;
    match object {
        object::File::Elf32(elf) => {
            let header = elf.section_by_index(index).ok()?.elf_section_header();
            Some((
                header.sh_type(elf.endian()),
                header.sh_offset(elf.endian()).into(),
            ))
        }
        object::File::Elf64(elf) => {
            let header = elf.section_by_index(index).ok()?.elf_section_header();
            Some((header.sh_type(elf.endian()), header.sh_offset(elf.endian())))
        }
        _ => None,
    }
}

fn elf_possibly_runtime(object: &object::File<'_>) -> bool {
    // symbol-elf.c:symsrc__possibly_runtime (1038) requires an actual dynsym
    // or .opd. A debug-only NOBITS section with either name does not qualify.
    [
        (".dynsym", object::elf::SHT_DYNSYM),
        (".opd", object::elf::SHT_PROGBITS),
    ]
    .iter()
    .any(|(name, kind)| {
        object
            .section_by_name(name)
            .and_then(|section| elf_section_layout(object, section.index()))
            .is_some_and(|(section_type, _)| section_type == *kind)
    })
}

fn elf_section_is_executable(section: &object::Section<'_, '_>) -> bool {
    matches!(section.flags(), object::SectionFlags::Elf { sh_flags }
        if sh_flags & u64::from(object::elf::SHF_ALLOC | object::elf::SHF_EXECINSTR)
            == u64::from(object::elf::SHF_ALLOC | object::elf::SHF_EXECINSTR))
}

fn kernel_module_max_text_offset(runtime: &object::File<'_>) -> u64 {
    // symbol-elf.c:max_text_section stops at init/exit or a noncontiguous
    // executable section. Its offsets are file offsets, not section VMAs.
    let mut max_text_offset = 0_u64;
    if !matches!(
        runtime.architecture(),
        object::Architecture::Alpha | object::Architecture::Hppa
    ) {
        for section in runtime.sections().filter(elf_section_is_executable) {
            let Ok(name) = section.name() else {
                break;
            };
            if name.starts_with(".init") || name.starts_with(".exit") {
                break;
            }
            let Some((_, offset)) = elf_section_layout(runtime, section.index()) else {
                break;
            };
            let align = section.align().max(1);
            let aligned = max_text_offset
                .checked_add(align - 1)
                .map(|end| end & !(align - 1));
            if max_text_offset != 0 && aligned != Some(offset) {
                break;
            }
            max_text_offset = offset.saturating_add(section.size());
        }
    }
    max_text_offset
}

fn kernel_module_object_metadata(bytes: &[u8], runtime_bytes: &[u8]) -> KernelModuleObjectMetadata {
    let Ok(object) = object::File::parse(bytes) else {
        return KernelModuleObjectMetadata::default();
    };
    let Ok(runtime) = object::File::parse(runtime_bytes) else {
        return KernelModuleObjectMetadata::default();
    };
    // symbol-elf.c:dso__load_sym requires a kernel symtab before dynsym,
    // and elf__needs_adjust_symbols accepts all three ordinary ELF kinds.
    if object.format() != object::BinaryFormat::Elf
        || object.symbol_table().is_none()
        || !matches!(
            object.kind(),
            object::ObjectKind::Executable
                | object::ObjectKind::Dynamic
                | object::ObjectKind::Relocatable
        )
    {
        return KernelModuleObjectMetadata::default();
    }
    let max_text_offset = kernel_module_max_text_offset(&runtime);
    let mut maps = Vec::new();
    let mut seen = FxHashSet::default();
    let mut text_address = None;
    for table in [object.symbols(), object.dynamic_symbols()] {
        // dso__load_sym_internal resets remap_kernel for each table pass.
        let mut text_remapped = false;
        for symbol in table {
            if !perf_symbol_is_allocated_candidate(&object, &symbol) {
                continue;
            }
            let Some(index) = symbol.section_index() else {
                continue;
            };
            let Ok(symbol_section) = object.section_by_index(index) else {
                continue;
            };
            // symbol-elf.c:1656 replaces a NOBITS symbol-section header with
            // the runtime source's header at the same index, not by name.
            let use_runtime = elf_section_layout(&object, index)
                .is_some_and(|(kind, _)| kind == object::elf::SHT_NOBITS);
            let section_owner = if use_runtime { &runtime } else { &object };
            let section = if use_runtime {
                let Ok(section) = runtime.section_by_index(index) else {
                    continue;
                };
                section
            } else {
                symbol_section
            };
            let Ok(name) = section.name() else {
                continue;
            };
            // symbol-elf.c:1665 filters labels after runtime substitution.
            if elf_symbol_is_label(&symbol) && !name.contains("text") && !name.contains("data") {
                continue;
            }
            if name == ".text" {
                if !text_remapped {
                    text_address = Some(if object.kind() == object::ObjectKind::Relocatable {
                        0
                    } else {
                        section.address()
                    });
                    text_remapped = true;
                }
                continue;
            }
            if (elf_section_is_executable(&section)
                && elf_section_layout(section_owner, index)
                    .is_some_and(|(_, offset)| offset <= max_text_offset))
                || !seen.insert(name)
            {
                continue;
            }
            // dso__process_kernel_symbol: additional module DSOs use the section
            // suffix and sh_addr as their adjusted map start (module reloc is 0).
            maps.push(KernelModuleSectionMap {
                section: name.to_owned(),
                start: section.address(),
            });
        }
    }
    KernelModuleObjectMetadata { text_address, maps }
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
        let object = object::File::parse(object_bytes).ok();
        Self {
            object_symbols: PerfObjectSymbolIndex::from_object_bytes(object_bytes),
            // perf addr2line.c:cmd__addr2line checks this literal section
            // before launching GNU's command fallback, not STT_FILE symbols.
            has_debug_line: object
                .as_ref()
                .is_some_and(|object| object.section_by_name(".debug_line").is_some()),
            possibly_runtime: object.as_ref().is_some_and(elf_possibly_runtime),
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
        self.has_debug_line
            .then(|| self.object_symbols.bfd_function_record_name(address))
            .flatten()
    }
}

impl PerfObjectSymbolIndex {
    fn from_object_bytes(object_bytes: &[u8]) -> Self {
        let Ok(object) = object::File::parse(object_bytes) else {
            return Self::default();
        };
        let mut bfd_sections = bfd_symbol_sections(&object);
        let (mut symbols, bfd_only_symbols) = object_symbol_candidates(&object, &mut bfd_sections);
        symbols.extend(perf_synthesized_plt_symbols(&object, &symbols));
        // Remap BFD's references after perf sorting without sorting BFD's
        // canonical per-section order or duplicating candidate metadata.
        let mut sorted_symbols: Vec<_> = symbols.into_iter().enumerate().collect();
        sorted_symbols.sort_by_key(|(_, symbol)| symbol.address);
        let mut sorted_indexes = vec![0; sorted_symbols.len()];
        let mut symbols: Vec<_> = sorted_symbols
            .into_iter()
            .enumerate()
            .map(|(sorted, (original, symbol))| {
                sorted_indexes[original] = sorted;
                symbol
            })
            .collect();
        for section in &mut bfd_sections {
            for index in &mut section.symbols {
                if let BfdSymbolIndex::Perf(index) = index {
                    *index = sorted_indexes[*index];
                }
            }
        }
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
            bfd_only_symbols,
            bfd_sections,
            bfd_function_cache: Mutex::default(),
        }
    }

    fn symbol_name(&self, address: u64) -> Option<&str> {
        self.symbol(address)
            .map(|candidate| candidate.name.as_str())
    }

    fn bfd_function_record_name(&self, address: u64) -> Option<&str> {
        // dwarf2.c:_bfd_elf_find_function returns a selected function even
        // without a filename. GNU addr2line prints ??:? for that success;
        // perf addr2line.c:filename_split rejects only the ??:0 sentinel.
        self.bfd_function_record_symbol(address)
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
        let mut cache = self
            .bfd_function_cache
            .lock()
            .expect("BFD function cache lock");
        // addr2line.c:find_address_in_section walks allocated sections in
        // object order. Function candidates must belong to that exact section.
        for section in &self.bfd_sections {
            if address < section.range.begin || address >= section.range.end {
                continue;
            }
            let offset = address - section.range.begin;
            if let Some(current) = cache.as_ref()
                && current.section == section.index
                && offset >= current.offset
                && offset < current.offset.saturating_add(current.size)
            {
                return Some(self.bfd_symbol(current.symbol));
            }
            *cache = None;
            // elfcode.h preserves canonical symtab order. Even starts beyond
            // the query can shorten the best extent before a later alias wins.
            for &index in &section.symbols {
                let candidate = self.bfd_symbol(index);
                let code_off = candidate.address.wrapping_sub(section.address_bias);
                let better = cache.as_ref().map_or(code_off <= offset, |current| {
                    bfd_function_record_better_fit(
                        self.bfd_symbol(current.symbol),
                        current.offset,
                        current.size,
                        candidate,
                        code_off,
                        offset,
                    )
                });
                if better {
                    *cache = Some(BfdFunctionRecordCache {
                        section: section.index,
                        symbol: index,
                        offset: code_off,
                        size: bfd_function_record_size(candidate),
                    });
                } else if let Some(current) = cache.as_mut()
                    && code_off > offset
                    && code_off > current.offset
                    && code_off < current.offset.saturating_add(current.size)
                {
                    current.size = code_off - current.offset;
                }
            }
            if let Some(current) = cache.as_ref() {
                return Some(self.bfd_symbol(current.symbol));
            }
        }
        None
    }

    fn bfd_symbol(&self, index: BfdSymbolIndex) -> &PerfSymbolCandidate {
        match index {
            BfdSymbolIndex::Perf(index) => &self.symbols[index],
            BfdSymbolIndex::BfdOnly(index) => &self.bfd_only_symbols[index],
        }
    }
}

fn bfd_symbol_sections(object: &object::File<'_>) -> Vec<BfdSymbolSection> {
    object
        .sections()
        .filter(|section| {
            matches!(section.flags(), object::SectionFlags::Elf { sh_flags }
                if sh_flags & u64::from(object::elf::SHF_ALLOC) != 0)
        })
        .map(|section| BfdSymbolSection {
            index: section.index(),
            range: PerfAddressRange {
                begin: section.address(),
                end: section.address().saturating_add(section.size()),
            },
            address_bias: if object.kind() == object::ObjectKind::Relocatable {
                0
            } else {
                section.address()
            },
            symbols: Vec::new(),
        })
        .collect()
}

fn object_symbol_candidates(
    object: &object::File<'_>,
    bfd_sections: &mut [BfdSymbolSection],
) -> (Vec<PerfSymbolCandidate>, Vec<PerfSymbolCandidate>) {
    let mut symbols =
        Vec::with_capacity(object.symbols().count() + object.dynamic_symbols().count());
    let mut bfd_only_symbols = Vec::new();
    let bfd_section_by_index: FxHashMap<_, _> = bfd_sections
        .iter()
        .enumerate()
        .map(|(index, section)| (section.index, index))
        .collect();
    // addr2line.c:slurp_symtab selects dynsym only when canonical symtab
    // has no entries, not when its entries fail candidate filtering.
    let bfd_dynamic = object.symbols().next().is_none();
    for (dynamic, table) in [(false, object.symbols()), (true, object.dynamic_symbols())] {
        for symbol in table {
            let perf_candidate = perf_symbol_candidate_from_object_symbol(object, &symbol);
            let bfd_function_like = perf_candidate.as_ref().map_or_else(
                || bfd_symbol_is_function_like(object.architecture(), &symbol),
                |candidate| candidate.bfd_function_like,
            );
            let bfd_section = (dynamic == bfd_dynamic && bfd_function_like)
                .then(|| {
                    symbol
                        .section_index()
                        .and_then(|index| bfd_section_by_index.get(&index).copied())
                })
                .flatten();
            if perf_candidate.is_none() && bfd_section.is_none() {
                continue;
            }
            let is_perf_candidate = perf_candidate.is_some();
            let candidate = perf_candidate.unwrap_or_else(|| {
                symbol_candidate_from_object_symbol(object.architecture(), &symbol)
            });
            let index = if is_perf_candidate {
                let index = BfdSymbolIndex::Perf(symbols.len());
                symbols.push(candidate);
                index
            } else {
                let index = BfdSymbolIndex::BfdOnly(bfd_only_symbols.len());
                bfd_only_symbols.push(candidate);
                index
            };
            if let Some(section) = bfd_section {
                bfd_sections[section].symbols.push(index);
            }
        }
    }
    (symbols, bfd_only_symbols)
}

fn bfd_function_record_size(candidate: &PerfSymbolCandidate) -> u64 {
    // bfd/elf.c:_bfd_elf_maybe_function_sym reads the unmodified ELF size,
    // treating zero (including synthetic symbols) as one. Perf's end fixup
    // must affect only candidate.size, not BFD's independent lookup extent.
    candidate.bfd_size.max(1)
}

fn bfd_function_record_better_fit(
    current: &PerfSymbolCandidate,
    current_offset: u64,
    current_size: u64,
    candidate: &PerfSymbolCandidate,
    candidate_offset: u64,
    offset: u64,
) -> bool {
    // dwarf2.c:better_fit uses the mutable cached size, not the winner's raw
    // st_size. Equal fits preserve the earlier canonical symbol.
    if candidate_offset > offset {
        return false;
    }
    if candidate_offset < current_offset {
        return false;
    }
    if candidate_offset > current_offset {
        return true;
    }

    let candidate_size = bfd_function_record_size(candidate);
    if current_offset.saturating_add(current_size) <= offset {
        return candidate_size > current_size;
    }
    if candidate_offset.saturating_add(candidate_size) <= offset {
        return false;
    }
    if current.bfd_function && !candidate.bfd_function {
        return false;
    }
    if candidate.bfd_function && !current.bfd_function {
        return true;
    }
    if current.elf_type == Some(object::elf::STT_NOTYPE)
        && candidate.elf_type != Some(object::elf::STT_NOTYPE)
    {
        return true;
    }
    if current.elf_type != Some(object::elf::STT_NOTYPE)
        && candidate.elf_type == Some(object::elf::STT_NOTYPE)
    {
        return false;
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
        .map(|section| (section.address(), false))
        .or_else(|| {
            let size = plt.size();
            let has_header = perf_x86_64_plt_relocations(object).is_none_or(|relocations| {
                u64::try_from(relocations.len())
                    .map_or(true, |len| len * X86_64_PLT_ENTRY_SIZE != size)
            });
            Some((
                plt.address()
                    .checked_add(u64::from(has_header) * X86_64_PLT_ENTRY_SIZE)?,
                true,
            ))
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
            address: plt.address(),
            size: X86_64_PLT_ENTRY_SIZE,
            bfd_size: 0,
            elf_type: Some(object::elf::STT_FUNC),
            scope: PerfSymbolScope::Global,
            binding: PerfSymbolBinding::Global,
            bfd_function_like: true,
            bfd_function: true,
        });
    }
    for relocation in relocations {
        let Some(next_offset) = plt_offset.checked_add(X86_64_PLT_ENTRY_SIZE) else {
            break;
        };
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
        });
        plt_offset = next_offset;
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
    perf_symbol_is_candidate(object, symbol)
        .then(|| symbol_candidate_from_object_symbol(object.architecture(), symbol))
}

fn bfd_symbol_is_function_like(
    architecture: object::Architecture,
    symbol: &object::Symbol<'_, '_>,
) -> bool {
    let object::SymbolFlags::Elf { st_info, st_other } = symbol.flags() else {
        return false;
    };
    let symbol_type = st_info & 0xf;
    // elfcode.h assigns the flags excluded by elf.c:maybe_function_sym for
    // these types. Generic ELF accepts IFUNC without BSF_FUNCTION; target
    // hooks below may reject it entirely.
    if matches!(
        symbol_type,
        object::elf::STT_SECTION
            | object::elf::STT_FILE
            | object::elf::STT_OBJECT
            | object::elf::STT_COMMON
            | object::elf::STT_TLS
            | ELF_STT_RELC
            | ELF_STT_SRELC
    ) {
        return false;
    }
    let local = st_info >> 4 == object::elf::STB_LOCAL;
    if symbol.size() == 0
        && local
        && symbol_type == object::elf::STT_NOTYPE
        && st_other & 3 == object::elf::STV_HIDDEN
    {
        return false;
    }
    // elf32-arm.c/elfnn-aarch64.c:maybe_function_sym have explicit type
    // whitelists, then reject local special names using cpu-*.c's TYPE_ANY.
    match architecture {
        object::Architecture::Arm
            if !matches!(
                symbol_type,
                object::elf::STT_NOTYPE | object::elf::STT_FUNC | object::elf::STT_ARM_TFUNC
            ) =>
        {
            return false;
        }
        object::Architecture::Aarch64 | object::Architecture::Aarch64_Ilp32
            if !matches!(symbol_type, object::elf::STT_NOTYPE | object::elf::STT_FUNC) =>
        {
            return false;
        }
        _ => {}
    }
    if !local {
        return true;
    }
    let name = symbol.name().unwrap_or_default().as_bytes();
    let special = match architecture {
        object::Architecture::Arm => {
            matches!(name, [b'$', letter, suffix @ ..]
                if letter.is_ascii_lowercase() && (suffix.is_empty() || suffix[0] == b'.'))
        }
        object::Architecture::Aarch64 | object::Architecture::Aarch64_Ilp32 => {
            matches!(name, [b'$', b'x' | b'd' | b'm' | b'f' | b'p', suffix @ ..]
                if suffix.is_empty() || suffix[0] == b'.')
        }
        // cpu-riscv.c accepts exact $d/$x and the $xrv prefix; unlike perf
        // it does not classify $d.0 or $x.0 as mapping symbols.
        object::Architecture::Riscv32 | object::Architecture::Riscv64 => {
            matches!(name, b"$d" | b"$x")
                || name.starts_with(b"$xrv")
                || bfd_elf_is_local_label_name(name)
        }
        _ => false,
    };
    !special
}

fn bfd_elf_is_local_label_name(name: &[u8]) -> bool {
    // elf.c:_bfd_elf_is_local_label_name recognizes these prefixes and
    // L<digit>\x01 fake symbols. Its numeric-label loop rejects other
    // control-character forms when its non-digit check runs.
    name.starts_with(b".L")
        || name.starts_with(b"..")
        || name.starts_with(b"_.L_")
        || matches!(name, [b'L', digit, 1, ..] if digit.is_ascii_digit())
}

fn symbol_candidate_from_object_symbol(
    architecture: object::Architecture,
    symbol: &object::Symbol<'_, '_>,
) -> PerfSymbolCandidate {
    let elf_type = match symbol.flags() {
        object::SymbolFlags::Elf { st_info, .. } => Some(st_info & 0xf),
        _ => None,
    };
    // perf util/symbol-elf.c:dso__load_sym_internal and BFD
    // elf32-arm.c:elf32_arm_swap_symbol_in both clear Thumb's STT_FUNC bit.
    // Perf keeps IFUNC's raw address; ARM BFD's maybe_function_sym rejects it.
    let address =
        if architecture == object::Architecture::Arm && elf_type == Some(object::elf::STT_FUNC) {
            symbol.address() & !1
        } else {
            symbol.address()
        };
    PerfSymbolCandidate {
        name: perf_symbol_name(&addr2line::demangle_auto(
            Cow::Borrowed(symbol.name().unwrap_or_default()),
            None,
        )),
        address,
        size: symbol.size(),
        bfd_size: symbol.size(),
        elf_type,
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
        bfd_function_like: bfd_symbol_is_function_like(architecture, symbol),
        // BFD's ARM swap-in hook promotes TFUNC before elfcode.h assigns
        // BSF_FUNCTION. Keep perf's independent raw ELF type unchanged.
        bfd_function: elf_type == Some(object::elf::STT_FUNC)
            || (architecture == object::Architecture::Arm
                && elf_type == Some(object::elf::STT_ARM_TFUNC)),
    }
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
    let bytes = read_regular_object(path)?;
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

impl<'a> PerfDwarfNameResolver<'a> {
    fn from_object_bytes_for_addresses(
        bytes: &'a [u8],
        addresses: &[u64],
    ) -> Result<Self, gimli::Error> {
        Self::from_object_bytes_matching_addresses(bytes, Some(addresses))
    }

    fn from_object_bytes_matching_addresses(
        bytes: &'a [u8],
        addresses: Option<&[u64]>,
    ) -> Result<Self, gimli::Error> {
        let backing = Arc::new(PerfDwarfBacking::load(PerfDwarfObjectBytes::Borrowed(
            bytes,
        ))?);
        let mut names = PerfDwarfNameInterner::with_backing(Arc::clone(&backing));
        let dwarf = backing.dwarf();
        let mut units = Vec::new();
        let directory = PerfDwarfUnitDirectory::new(&dwarf);
        for prepared in &directory.units {
            let Some(unit) = &prepared.unit else {
                continue;
            };
            let ranges = perf_dwarf_ranges(dwarf.unit_ranges(unit).ok());
            if let Some(addresses) = addresses
                && !perf_dwarf_unit_ranges_match_addresses(ranges.as_deref(), addresses)
            {
                continue;
            }
            let source_line_ranges = perf_dwarf_source_line_ranges(unit);
            units.push(PerfDwarfUnitIndex {
                ranges,
                frame_index: perf_dwarf_unit_frame_index(
                    &dwarf,
                    unit,
                    &directory,
                    &mut names,
                    &source_line_ranges,
                ),
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
            if let Some(frames) = perf_dwarf_frame_names_from_index(
                &unit.frame_index,
                &self.names,
                address,
                base_symbol,
            ) {
                return Some(frames);
            }
        }
        None
    }
}

impl CachedObjectMetadata {
    fn module_metadata(
        &self,
        module: &SymbolRequest,
        load: impl FnOnce(&Path) -> Option<Arc<Self>>,
    ) -> Arc<KernelModuleObjectMetadata> {
        // symbol.c:1809 selects syms_ss and runtime_ss independently. Cache
        // by the runtime candidate as distinct DSOs can share a debug file.
        let candidate = if self.object_metadata.possibly_runtime {
            OsStr::new("")
        } else {
            module.path.as_os_str()
        };
        let mut cache = self
            .module_metadata
            .lock()
            .expect("module metadata cache lock");
        match cache.raw_entry_mut().from_key(candidate) {
            RawEntryMut::Occupied(entry) => Arc::clone(entry.get()),
            RawEntryMut::Vacant(entry) => {
                let runtime = (!candidate.is_empty())
                    .then(|| load(Path::new(candidate)))
                    .flatten()
                    .filter(|runtime| {
                        runtime.object_metadata.possibly_runtime
                            && module.recorded_build_id().is_none_or(|recorded| {
                                runtime.build_id().as_deref().map(build_id_hex).as_deref()
                                    == Some(recorded)
                            })
                    });
                // symbol.c falls back to syms_ss if no eligible runtime source
                // exists; symsrc__init (symbol-elf.c:1193) checks each source ID.
                let runtime_bytes = runtime
                    .as_ref()
                    .map_or(self.object_bytes.as_slice(), |runtime| {
                        runtime.object_bytes.as_slice()
                    });
                let metadata = Arc::new(kernel_module_object_metadata(
                    &self.object_bytes,
                    runtime_bytes,
                ));
                entry.insert(candidate.to_owned(), Arc::clone(&metadata));
                metadata
            }
        }
    }

    fn build_id(&self) -> Option<Vec<u8>> {
        let object = object::File::parse(self.object_bytes.as_slice()).ok()?;
        object.build_id().ok()?.map(<[u8]>::to_vec)
    }

    /// Builds frame indexes for every DWARF unit covering `addresses` that has
    /// not been indexed by an earlier batch.
    fn prepare_dwarf_frames_for_addresses(&self, addresses: &[u64]) {
        let mut cache = self.dwarf_index.lock().expect("dwarf index cache lock");
        if cache.failed {
            return;
        }
        if let Some(units) = &cache.units {
            let needs_build = units.iter().any(|unit| {
                unit.frame_index.is_none()
                    && perf_dwarf_unit_ranges_match_addresses(unit.ranges.as_deref(), addresses)
            });
            if !needs_build {
                return;
            }
        }
        if build_dwarf_index_cache_for_addresses(
            &mut cache,
            PerfDwarfObjectBytes::Shared(Arc::clone(&self.object_bytes)),
            addresses,
        )
        .is_err()
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
            let Some(frame_index) = &unit.frame_index else {
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
                frame_index,
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

fn build_dwarf_index_cache_for_addresses<'a>(
    cache: &mut PerfDwarfIndexCache<'a>,
    bytes: PerfDwarfObjectBytes<'a>,
    addresses: &[u64],
) -> Result<(), gimli::Error> {
    if cache.names.names.backing.is_none() {
        cache.names.names.backing = Some(Arc::new(PerfDwarfBacking::load(bytes)?));
    }
    let backing = Arc::clone(
        cache
            .names
            .names
            .backing
            .as_ref()
            .expect("DWARF backing loaded"),
    );
    let dwarf = backing.dwarf();

    let scanning = cache.units.is_none();
    let mut units = cache.units.take().unwrap_or_default();
    let directory = PerfDwarfUnitDirectory::new(&dwarf);
    for (ordinal, prepared) in directory.units.iter().enumerate() {
        let Some(unit) = &prepared.unit else {
            if scanning {
                units.push(PerfDwarfCachedUnit {
                    ranges: Some(Vec::new()),
                    source_line_ranges: Some(Vec::new()),
                    frame_index: Some(PerfDwarfFrameIndex::default()),
                });
            }
            continue;
        };
        if scanning {
            units.push(PerfDwarfCachedUnit {
                ranges: perf_dwarf_ranges(dwarf.unit_ranges(unit).ok()),
                source_line_ranges: Some(perf_dwarf_source_line_ranges(unit)),
                frame_index: None,
            });
        }
        let Some(cached_unit) = units.get_mut(ordinal) else {
            break;
        };
        if cached_unit.frame_index.is_none()
            && perf_dwarf_unit_ranges_match_addresses(cached_unit.ranges.as_deref(), addresses)
        {
            let source_line_ranges = cached_unit
                .source_line_ranges
                .get_or_insert_with(|| perf_dwarf_source_line_ranges(unit));
            cached_unit.frame_index = Some(perf_dwarf_unit_frame_index(
                &dwarf,
                unit,
                &directory,
                &mut cache.names,
                source_line_ranges.as_slice(),
            ));
        }
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

fn perf_dwarf_unit_frame_index<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    directory: &PerfDwarfUnitDirectory<R>,
    names: &mut PerfDwarfNameInterner<'_>,
    source_line_ranges: &[PerfAddressRange],
) -> PerfDwarfFrameIndex
where
    R: gimli::Reader,
{
    let mut entries = unit.entries();
    let Ok(true) = entries.next_entry() else {
        return PerfDwarfFrameIndex::default();
    };
    let Some(root) = entries.current() else {
        return PerfDwarfFrameIndex::default();
    };
    if !root.has_children() {
        return PerfDwarfFrameIndex::default();
    }
    let root_depth = root.depth();
    let mut scopes = Vec::<PerfDwarfScope>::new();
    let mut index = PerfDwarfFrameIndex::default();
    let mut next_order = 0;
    let mut skip_subtree = false;
    loop {
        // Retain the sibling fast path when pruning a direct subprogram child.
        // A null sibling terminator must be consumed before resuming DFS.
        let skipping = std::mem::take(&mut skip_subtree);
        let next = if skipping {
            entries.next_sibling().map(|entry| entry.is_some())
        } else {
            entries.next_dfs().map(|entry| entry.is_some())
        };
        let entry = match next {
            Ok(true) => entries
                .current()
                .expect("cursor advanced to a non-null DIE"),
            Ok(false) if skipping => continue,
            _ => break,
        };
        let depth = entry.depth();
        if depth <= root_depth {
            break;
        }
        while scopes.last().is_some_and(|scope| scope.depth >= depth) {
            perf_dwarf_finish_scope(&mut scopes, source_line_ranges, &mut index, &mut next_order);
        }
        let kind = match entry.tag() {
            gimli::DW_TAG_subprogram => PerfDwarfDieKind::Subprogram,
            gimli::DW_TAG_inlined_subroutine => PerfDwarfDieKind::Inline,
            _ => continue,
        };
        let parent = scopes.last();
        if kind == PerfDwarfDieKind::Subprogram
            && parent.is_some_and(|scope| scope.depth + 1 == depth)
        {
            skip_subtree = true;
            continue;
        }
        let ranges = perf_dwarf_ranges(dwarf.die_ranges(unit, entry).ok()).unwrap_or_default();
        let name = perf_dwarf_die_frame_name(dwarf, unit, directory, entry)
            .and_then(|name| names.intern(&name));
        // A subprogram behind a transparent wrapper was previously collected
        // (including its names), but flattening excluded its entire subtree.
        let suppressed =
            parent.is_some_and(|scope| scope.suppressed || kind == PerfDwarfDieKind::Subprogram);
        let frame_checkpoint = index.nodes.len();
        let parent_frame = parent.and_then(|scope| scope.frame);
        let frame = if suppressed {
            None
        } else if let Some(name) = name {
            index.nodes.push(PerfDwarfFrameNode {
                name,
                parent: parent_frame,
                kind,
            });
            std::num::NonZeroUsize::new(index.nodes.len())
        } else {
            parent_frame
        };
        scopes.push(PerfDwarfScope {
            depth,
            ranges,
            frame,
            frame_checkpoint,
            segment_checkpoint: index.segments.len(),
            has_inline_frames: kind == PerfDwarfDieKind::Inline
                || parent.is_some_and(|scope| scope.has_inline_frames),
            suppressed,
            child_coverage: Vec::new(),
        });
    }
    // Parsing errors previously retained partial nodes. Finalize them too.
    while !scopes.is_empty() {
        perf_dwarf_finish_scope(&mut scopes, source_line_ranges, &mut index, &mut next_order);
    }
    index.segments.sort_by_key(|segment| segment.range.begin);
    index
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

fn perf_dwarf_finish_scope(
    scopes: &mut Vec<PerfDwarfScope>,
    source_line_ranges: &[PerfAddressRange],
    index: &mut PerfDwarfFrameIndex,
    next_order: &mut usize,
) {
    let Some(scope) = scopes.pop() else {
        return;
    };
    if scope.suppressed {
        return;
    }
    if let Some(frame) = scope.frame {
        for range in perf_dwarf_subtract_ranges(&scope.ranges, &scope.child_coverage) {
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
                index.segments.push(PerfDwarfFrameRange {
                    range,
                    frame,
                    has_inline_frames: scope.has_inline_frames,
                    has_source_line,
                    order,
                });
            }
        }
    }

    // A subtree that emitted no intervals has no surviving chain references.
    if index.segments.len() == scope.segment_checkpoint {
        index.nodes.truncate(scope.frame_checkpoint);
    }

    if let Some(parent) = scopes.last_mut() {
        parent
            .child_coverage
            .extend(perf_dwarf_merge_ranges(scope.ranges));
    }
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
    index: &PerfDwarfFrameIndex,
    names: &PerfDwarfNames<'_>,
    address: u64,
    base_symbol: Option<&str>,
) -> Option<PerfDwarfFrameNames> {
    let segments = &index.segments;
    let upper_bound = segments.partition_point(|segment| segment.range.begin <= address);
    if upper_bound == 0 {
        return None;
    }
    let segment = segments[..upper_bound]
        .iter()
        .filter(|segment| segment.range.begin <= address && address < segment.range.end)
        .min_by_key(|segment| segment.order)?;
    // libdw__addr2line (Linux v7.2.9 util/libdw.c:183-185) cannot walk
    // inline DIEs unless dwfl_module_getsrc resolves this address.
    if !segment.has_inline_frames || !segment.has_source_line {
        return None;
    }
    let mut frames = Vec::new();
    let mut frame = Some(segment.frame);
    let mut has_outer_frame = false;
    while let Some(id) = frame {
        let node = &index.nodes[id.get() - 1];
        let name_index = usize::try_from(node.name).ok()?;
        let name = if node.kind == PerfDwarfDieKind::Subprogram {
            has_outer_frame = true;
            base_symbol.or_else(|| names.get(name_index))
        } else {
            names.get(name_index)
        };
        if let Some(name) = name {
            frames.push(name.to_owned());
        }
        frame = node.parent;
    }
    // Linux v7.2.9 tools/perf/util/libdw.c:85-108 always emits args->sym
    // for the outer subprogram, including a DIE without a printable name.
    if !has_outer_frame && let Some(base_symbol) = base_symbol {
        frames.push(base_symbol.to_owned());
    }
    Some(PerfDwarfFrameNames {
        frames,
        has_inline_frames: true,
    })
}

/// Resolves the printed frame name for one subprogram/inlined-subroutine DIE.
///
/// Linux v7.2.9 tools/perf/util/libdw.c:90-114 selects linkage/name or the
/// outer ELF symbol; srcline.c:94-108 `new_inline_sym()` demangles either spelling.
/// <https://github.com/gregkh/linux/blob/v7.2.9/tools/perf/util/libdw.c#L90-L114>
/// <https://github.com/gregkh/linux/blob/v7.2.9/tools/perf/util/srcline.c#L94-L108>
fn perf_dwarf_die_frame_name<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    directory: &PerfDwarfUnitDirectory<R>,
    entry: &gimli::DebuggingInformationEntry<R>,
) -> Option<R>
where
    R: gimli::Reader,
{
    perf_dwarf_inherited_string(dwarf, unit, directory, entry, gimli::DW_AT_linkage_name, 17)
        .or_else(|| perf_dwarf_die_name(dwarf, unit, directory, entry))
}

fn perf_dwarf_die_name<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    directory: &PerfDwarfUnitDirectory<R>,
    entry: &gimli::DebuggingInformationEntry<R>,
) -> Option<R>
where
    R: gimli::Reader,
{
    // Keep the existing root plus sixteen referenced DIEs for DW_AT_name.
    perf_dwarf_inherited_string(dwarf, unit, directory, entry, gimli::DW_AT_name, 17)
}

fn perf_dwarf_inherited_string<'a, R>(
    dwarf: &gimli::Dwarf<R>,
    mut unit: &'a gimli::Unit<R>,
    directory: &'a PerfDwarfUnitDirectory<R>,
    entry: &gimli::DebuggingInformationEntry<R>,
    attribute: gimli::DwAt,
    entry_limit: usize,
) -> Option<R>
where
    R: gimli::Reader,
{
    let mut offset = entry.offset();
    for _ in 0..entry_limit {
        let attr = |name| perf_dwarf_raw_attribute(unit, offset, name);
        if let Some(value) = attr(attribute) {
            let name = dwarf.attr_string(unit, value.ok()?.value()).ok()?;
            return name.to_string_lossy().is_ok().then_some(name);
        }
        // libdw dwarf_attr_integrate.c:43-63 uses specification only when
        // abstract_origin is absent, never after that reference fails.
        let reference = attr(gimli::DW_AT_abstract_origin)
            .or_else(|| attr(gimli::DW_AT_specification))?
            .ok()?
            .value();
        let (owner, reference_offset) = match reference {
            gimli::AttributeValue::UnitRef(offset) => (unit, offset),
            gimli::AttributeValue::DebugInfoRef(offset) => directory.resolve_reference(offset)?,
            _ => return None,
        };
        unit = owner;
        offset = reference_offset;
    }
    None
}

fn perf_dwarf_raw_attribute<R: gimli::Reader>(
    unit: &gimli::Unit<R>,
    offset: gimli::UnitOffset<R::Offset>,
    name: gimli::DwAt,
) -> Option<Result<gimli::Attribute<R>, gimli::Error>> {
    let mut entries = unit.entries_raw(Some(offset)).ok()?;
    let abbreviation = entries.read_abbreviation().ok()??;
    for &spec in abbreviation.attributes() {
        let mut spec = spec;
        if spec.form() == gimli::DW_FORM_indirect {
            let offset = entries.next_offset();
            let mut value = unit.header.range_from(offset..).ok()?;
            if value.is_empty() {
                return None;
            }
            let length = value.len();
            let form = match perf_dwarf_uleb128(&mut value) {
                Ok(form) => form & u64::from(u32::MAX),
                Err(error) => return (spec.name() == name).then_some(Err(error)),
            };
            // dwarf_child.c resolves one indirect form before the name match.
            // Gimli permits nesting, but libdw rejects indirect/implicit_const.
            if form == u64::from(gimli::DW_FORM_indirect.0)
                || form == u64::from(gimli::DW_FORM_implicit_const.0)
            {
                return None;
            }
            let form = match u16::try_from(form) {
                Ok(form) => gimli::DwForm(form),
                Err(_) => {
                    return (spec.name() == name).then_some(Err(gimli::Error::BadUnsignedLeb128));
                }
            };
            let offset = gimli::UnitOffset(offset.0 + (length - value.len()));
            entries =
                gimli::EntriesRaw::new(value, unit.header.encoding(), &unit.abbreviations, offset);
            spec = gimli::AttributeSpecification::new(spec.name(), form, None);
        }
        if spec.name() == name {
            // libdw dwarf_child.c:__libdw_find_attr stops at the match.
            // A present invalid value is distinct from an absent attribute.
            return Some(entries.read_attribute(spec));
        }
        if matches!(
            spec.form(),
            gimli::DW_FORM_udata
                | gimli::DW_FORM_sdata
                | gimli::DW_FORM_ref_udata
                | gimli::DW_FORM_addrx
                | gimli::DW_FORM_loclistx
                | gimli::DW_FORM_rnglistx
                | gimli::DW_FORM_strx
                | gimli::DW_FORM_GNU_addr_index
                | gimli::DW_FORM_GNU_str_index
        ) {
            // libdw_form.c uses the bounded unsigned decoder to skip these,
            // even for signed values; do not consume beyond ten bytes.
            let offset = entries.next_offset();
            let mut value = unit.header.range_from(offset..).ok()?;
            if value.is_empty() {
                return None;
            }
            let length = value.len();
            perf_dwarf_uleb128(&mut value).ok()?;
            let offset = gimli::UnitOffset(offset.0 + (length - value.len()));
            entries =
                gimli::EntriesRaw::new(value, unit.header.encoding(), &unit.abbreviations, offset);
        } else if spec.form().0 != 0 {
            // dwarf_child.c skips a value only when attr_form is nonzero.
            entries.skip_attributes(std::slice::from_ref(&spec)).ok()?;
        }
    }
    None
}

fn perf_dwarf_uleb128<R: gimli::Reader>(value: &mut R) -> Result<u64, gimli::Error> {
    // libdw memory-access.h consumes at most ten bytes, accepting any
    // terminating tenth byte and returning UINT64_MAX if none terminates.
    let mut result = 0;
    for index in 0..10 {
        if value.is_empty() {
            break;
        }
        let byte = value.read_u8()?;
        result |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok(result);
        }
    }
    Ok(u64::MAX)
}

enum PerfDwarfObjectBytes<'a> {
    Borrowed(&'a [u8]),
    Shared(Arc<Vec<u8>>),
}

impl PerfDwarfObjectBytes<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Shared(bytes) => bytes,
        }
    }
}

#[derive(Clone, Copy)]
struct PerfDwarfNameSpan {
    buffer: usize,
    offset: usize,
    len: usize,
}

// Readers are temporary views; persisted names hold ranges into this shared
// owner, including decompressed sections needed by later CU index builds.
struct PerfDwarfBacking<'a> {
    object: PerfDwarfObjectBytes<'a>,
    decompressed: Vec<Vec<u8>>,
    sections: gimli::DwarfSections<PerfDwarfNameSpan>,
    endian: gimli::RunTimeEndian,
}

impl<'a> PerfDwarfBacking<'a> {
    fn load(bytes: PerfDwarfObjectBytes<'a>) -> Result<Self, gimli::Error> {
        let slice = bytes.as_slice();
        let object = object::File::parse(slice).map_err(|_| gimli::Error::Io)?;
        let endian = if object.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };
        let base = gimli::EndianSlice::new(slice, endian);
        let mut decompressed = Vec::new();
        let sections = gimli::DwarfSections::load(|id| {
            let data = object
                .section_by_name(id.name())
                .and_then(|section| section.uncompressed_data().ok())
                .unwrap_or(Cow::Borrowed(&[]));
            let len = data.len();
            let (buffer, offset) = match data {
                Cow::Borrowed([]) => (0, 0),
                Cow::Borrowed(data) => {
                    let reader = gimli::EndianSlice::new(data, endian);
                    let offset =
                        gimli::Reader::lookup_offset_id(&base, gimli::Reader::offset_id(&reader))
                            .ok_or(gimli::Error::Io)?;
                    (0, offset)
                }
                Cow::Owned(data) => {
                    decompressed.push(data);
                    (decompressed.len(), 0)
                }
            };
            Ok::<_, gimli::Error>(PerfDwarfNameSpan {
                buffer,
                offset,
                len,
            })
        })?;
        Ok(Self {
            object: bytes,
            decompressed,
            sections,
            endian,
        })
    }

    fn buffer(&self, index: usize) -> Option<&[u8]> {
        if index == 0 {
            Some(self.object.as_slice())
        } else {
            self.decompressed.get(index - 1).map(Vec::as_slice)
        }
    }

    fn bytes(&self, span: PerfDwarfNameSpan) -> Option<&[u8]> {
        self.buffer(span.buffer)?
            .get(span.offset..span.offset.checked_add(span.len)?)
    }

    fn dwarf(&self) -> gimli::Dwarf<gimli::EndianSlice<'_, gimli::RunTimeEndian>> {
        self.sections.borrow(|span| {
            gimli::EndianSlice::new(
                self.bytes(*span).expect("valid DWARF section range"),
                self.endian,
            )
        })
    }

    fn name_span<R: gimli::Reader>(&self, reader: &R) -> Option<PerfDwarfNameSpan> {
        let len = usize::try_from(gimli::ReaderOffset::into_u64(reader.len())).ok()?;
        for buffer in 0..=self.decompressed.len() {
            let bytes = self.buffer(buffer)?;
            let base = gimli::EndianSlice::new(bytes, self.endian);
            if let Some(offset) = gimli::Reader::lookup_offset_id(&base, reader.offset_id())
                && offset.checked_add(len)? <= bytes.len()
            {
                return Some(PerfDwarfNameSpan {
                    buffer,
                    offset,
                    len,
                });
            }
        }
        None
    }
}

enum PerfDwarfStoredName {
    Source(PerfDwarfNameSpan),
    Rendered(String),
    Function(PerfDwarfNameId),
}

struct PerfDwarfFunctionName {
    raw: PerfDwarfStoredName,
    rendered: OnceLock<Option<String>>,
}

#[derive(Default)]
struct PerfDwarfNames<'a> {
    backing: Option<Arc<PerfDwarfBacking<'a>>>,
    entries: Vec<PerfDwarfStoredName>,
    function_names: Vec<PerfDwarfFunctionName>,
}

impl PerfDwarfNames<'_> {
    fn get(&self, index: usize) -> Option<&str> {
        let raw = self.raw_name(index)?;
        let PerfDwarfStoredName::Function(id) = self.entries.get(index)? else {
            return Some(raw);
        };
        let name = self.function_names.get(*id as usize)?;
        let rendered = name.rendered.get_or_init(|| {
            match addr2line::demangle_auto(Cow::Borrowed(raw), None) {
                Cow::Borrowed(_) => None,
                Cow::Owned(rendered) => Some(rendered),
            }
        });
        Some(rendered.as_deref().unwrap_or(raw))
    }

    fn raw_name(&self, index: usize) -> Option<&str> {
        let entry = match self.entries.get(index)? {
            PerfDwarfStoredName::Function(id) => &self.function_names.get(*id as usize)?.raw,
            entry => entry,
        };
        match entry {
            PerfDwarfStoredName::Source(span) => {
                std::str::from_utf8(self.backing.as_ref()?.bytes(*span)?).ok()
            }
            PerfDwarfStoredName::Rendered(name) => Some(name),
            PerfDwarfStoredName::Function(_) => None,
        }
    }

    fn is_function(&self, index: usize) -> bool {
        matches!(
            self.entries.get(index),
            Some(PerfDwarfStoredName::Function(_))
        )
    }

    #[cfg(test)]
    fn iter(&self) -> impl Iterator<Item = &str> {
        (0..self.entries.len()).map(|index| self.get(index).expect("valid DWARF name ID"))
    }
}

#[cfg(test)]
impl std::ops::Index<usize> for PerfDwarfNames<'_> {
    type Output = str;

    fn index(&self, index: usize) -> &str {
        self.get(index).expect("valid DWARF name ID")
    }
}

#[derive(Default)]
struct PerfDwarfNameInterner<'a> {
    names: PerfDwarfNames<'a>,
    ids_by_name: HashTable<PerfDwarfNameId>,
}

fn perf_dwarf_name_hash(name: &str) -> u64 {
    let mut hasher = rustc_hash::FxHasher::default();
    name.hash(&mut hasher);
    hasher.finish()
}

impl<'a> PerfDwarfNameInterner<'a> {
    fn with_backing(backing: Arc<PerfDwarfBacking<'a>>) -> Self {
        Self {
            names: PerfDwarfNames {
                backing: Some(backing),
                entries: Vec::new(),
                function_names: Vec::new(),
            },
            ids_by_name: HashTable::new(),
        }
    }

    fn intern<R: gimli::Reader>(&mut self, reader: &R) -> Option<PerfDwarfNameId> {
        let text = reader.to_string_lossy().ok()?;
        let span = self
            .names
            .backing
            .as_ref()
            .and_then(|backing| backing.name_span(reader));
        Some(self.intern_text(text, span, true))
    }

    fn intern_text(
        &mut self,
        name: Cow<'_, str>,
        span: Option<PerfDwarfNameSpan>,
        function: bool,
    ) -> PerfDwarfNameId {
        let hash = perf_dwarf_name_hash(&name);
        // Rehashing and duplicate detection must not render unused DIE names.
        if let Some(&id) = self.ids_by_name.find(hash, |&id| {
            self.names.is_function(id as usize) == function
                && self.names.raw_name(id as usize) == Some(name.as_ref())
        }) {
            return id;
        }
        let id = PerfDwarfNameId::try_from(self.names.entries.len())
            .expect("dwarf name table fits in u32");
        let stored = match name {
            Cow::Borrowed(name) => span.map_or_else(
                || PerfDwarfStoredName::Rendered(name.to_owned()),
                PerfDwarfStoredName::Source,
            ),
            Cow::Owned(name) => PerfDwarfStoredName::Rendered(name),
        };
        let stored = if function {
            let id = PerfDwarfNameId::try_from(self.names.function_names.len())
                .expect("dwarf function name table fits in u32");
            self.names.function_names.push(PerfDwarfFunctionName {
                raw: stored,
                rendered: OnceLock::new(),
            });
            PerfDwarfStoredName::Function(id)
        } else {
            stored
        };
        self.names.entries.push(stored);
        self.ids_by_name.insert_unique(hash, id, |&id| {
            perf_dwarf_name_hash(
                self.names
                    .raw_name(id as usize)
                    .expect("valid DWARF name ID"),
            )
        });
        id
    }

    fn into_names(self) -> PerfDwarfNames<'a> {
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
    mapping.kernel_module_address.is_some()
        || crate::perfdata::samples::is_kernel_space_frame(mapping.relative_address)
            && mapping.path.starts_with('[')
}

fn symbol_request_from_mapping_ref(mapping: &ResolvedMappingRef<'_>) -> SymbolRequest {
    let mut request = SymbolRequest {
        addr2line_address: None,
        kernel_module_address: None,
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
    request.kernel_module_address = mapping.kernel_module_address;
    request.kernel_mapping_range = kernel_mapping_range_from_ref(mapping);
    if let Some(build_id) = mapping
        .build_id
        .filter(|id| id.iter().any(|byte| *byte != 0))
    {
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

pub(crate) fn build_id_hex(bytes: &[u8]) -> String {
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
    let module_name = kcore::module_dso_short_name(request.path.to_str()?);
    kallsyms.resolve_module_with_offset_for_path(
        request
            .kernel_module_address
            .unwrap_or(request.relative_address),
        request.kernel_mapping_range,
        &module_name,
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

fn is_kernel_module_request(request: &SymbolRequest) -> bool {
    is_kernel_module_symbol_path(&request.path) || request.kernel_module_address.is_some()
}

fn is_kernel_symbol_request(request: &SymbolRequest) -> bool {
    is_kernel_symbol_path(&request.path) || request.kernel_module_address.is_some()
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
    addresses_by_name: Option<&mut FxHashMap<Arc<str>, u64>>,
    address: u64,
    symbol: KallsymsSymbol,
) {
    #[cfg(test)]
    MODULE_KALLSYMS_SYMBOL_INSERTIONS.with(|count| count.set(count.get() + 1));
    if let Some(addresses_by_name) = addresses_by_name {
        addresses_by_name
            .entry(Arc::clone(&symbol.name))
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

fn parse_kallsyms_line(line: &str) -> Option<(u64, &str)> {
    let mut fields = line.split_whitespace();
    let address = u64::from_str_radix(fields.next()?, 16).ok()?;
    let _symbol_type = fields.next()?;
    let symbol = fields.next()?;
    Some((address, symbol))
}

fn parse_kallsyms_function_line(line: &str) -> Option<(u64, &str)> {
    // tools/lib/symbol/kallsyms.c:31-77 and api/io.h:io__get_hex require
    // literal separators and accumulate hex modulo u64, without a sign.
    let (hex, row) = line.split_once(' ')?;
    if hex.is_empty() {
        return None;
    }
    let address = hex.bytes().try_fold(0_u64, |value, byte| {
        let digit = char::from(byte).to_digit(16)?;
        Some((value << 4) | u64::from(digit))
    })?;
    let (kind, name) = row.split_once(' ')?;
    // event.c:find_func_symbol_cb accepts only functions or uppercase A;
    // strcmp sees the full name (including module suffix) up to the first NUL.
    matches!(kind, "T" | "t" | "W" | "w" | "A").then_some((address, name.split('\0').next()?))
}

fn kallsyms_reference_span(text: &str, reference: &str) -> Option<(u64, Range<usize>)> {
    let mut offset = 0;
    for line in text.split_terminator('\n') {
        #[cfg(test)]
        KALLSYMS_REFERENCE_ROW_VISITS.with(|count| count.set(count.get() + 1));
        if let Some((address, name)) = parse_kallsyms_function_line(line)
            && name == reference
        {
            // The accepted parser requires one ASCII type byte between spaces.
            let start = offset + line.find(' ')? + 3;
            return Some((address, start..start + name.len()));
        }
        offset += line.len() + 1;
    }
    None
}

fn parse_global_kallsyms_row(line: &str) -> Option<BorrowedKallsymsRow<'_>> {
    #[cfg(test)]
    MODULE_KALLSYMS_ROW_VISITS.with(|count| count.set(count.get() + 1));
    let (address, rest) = line.trim_start().split_once(char::is_whitespace)?;
    let address = u64::from_str_radix(address, 16).ok()?;
    let (symbol_type, full_name) = rest.trim_start().split_once(char::is_whitespace)?;
    let symbol_type = symbol_type.chars().next()?;
    let full_name = full_name.trim_start();
    let mut fields = full_name.split_whitespace();
    let name = fields.next()?;
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

    use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, build, elf};

    use super::{
        CachedObjectMetadata, Kallsyms, PerfAddressRange, PerfDwarfFrameNames, PerfDwarfIndexCache,
        PerfDwarfNameInterner, PerfObjectSymbolIndex, PerfSymbolBinding, PerfSymbolCandidate,
        PerfSymbolScope, PreparedObjectMetadata, ResolvedMappingRef, ResolvedSymbolFrames,
        RustAddr2lineResolver, SymbolDsoName, SymbolFrameCache, SymbolRequest, SymbolResolver,
        clean_object_symbol_request, demangle_addr2line_name_qualified,
        fixup_object_symbol_ends_like_perf, gnu_build_id_from_notes, perf_best_duplicate_symbol,
        perf_dwarf_frame_names_from_index, perf_frames_with_object_alias,
        perf_symbol_candidate_search_end, resolve_base_frames_from_object_metadata,
    };

    fn regression_elf_with_build_id() -> Vec<u8> {
        let bytes = elf_with_dynamic_text_symbol(b"recorded_function", 0x1000, 16);
        let mut builder = build::elf::Builder::read(bytes.as_slice()).unwrap();
        let note = builder.sections.add();
        note.name = b".note.gnu.build-id"[..].into();
        note.sh_type = elf::SHT_NOTE;
        note.sh_addralign = 4;
        note.data = build::elf::SectionData::Data(
            vec![
                4, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, b'G', b'N', b'U', 0, 0xaa, 0xbb, 0xcc, 0xdd,
            ]
            .into(),
        );
        builder.set_section_sizes();
        let mut output = Vec::new();
        builder.write(&mut output).unwrap();
        assert_eq!(
            object::File::parse(output.as_slice())
                .unwrap()
                .build_id()
                .unwrap(),
            Some(&[0xaa, 0xbb, 0xcc, 0xdd][..])
        );
        output
    }

    fn module_metadata_retention_fixture(separate_map: bool) -> Vec<u8> {
        let bytes = regression_elf_with_build_id();
        let mut builder = build::elf::Builder::read(bytes.as_slice()).unwrap();
        let section = builder
            .sections
            .iter_mut()
            .find(|section| section.name.as_slice() == b".text")
            .unwrap();
        let text = section.id();
        if separate_map {
            section.name = b".data"[..].into();
            section.sh_flags = u64::from(elf::SHF_ALLOC | elf::SHF_WRITE);
        }
        let section = builder.sections.add();
        section.name = b".symtab"[..].into();
        section.sh_type = elf::SHT_SYMTAB;
        section.sh_addralign = 8;
        section.data = build::elf::SectionData::Symbol;
        let section = builder.sections.add();
        section.name = b".strtab"[..].into();
        section.sh_type = elf::SHT_STRTAB;
        section.sh_addralign = 1;
        section.data = build::elf::SectionData::String;
        let symbol = builder.symbols.add();
        symbol.name = b"recorded_function"[..].into();
        symbol.section = Some(text);
        symbol.set_st_info(elf::STB_GLOBAL, elf::STT_FUNC);
        symbol.st_value = 0x1000;
        symbol.st_size = 16;
        builder.set_section_sizes();
        let mut output = Vec::new();
        builder.write(&mut output).unwrap();
        output
    }

    #[test]
    fn selected_module_maps_use_retained_primary_after_rewrite_and_unlink() {
        struct NoCommands;
        impl crate::process::CommandRunner for NoCommands {
            fn run(
                &self,
                _: &crate::process::CommandSpec,
            ) -> std::io::Result<crate::process::CommandOutput> {
                panic!("selected module maps and base metadata must not launch a helper");
            }
        }

        // perf symbol-elf.c:symsrc__init retains ss->ehdr with ss->elf/fd,
        // just as libdwfl/offline.c retains the primary fd in mod->main.fd.
        for kind in [
            super::SymbolizerKind::Addr2line,
            super::SymbolizerKind::RustAddr2line,
        ] {
            for separate_map in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let path = root.path().join("selected.elf");
                let selected = module_metadata_retention_fixture(separate_map);
                let elf = object::File::parse(selected.as_slice()).unwrap();
                let expected = elf
                    .section_by_name(".data")
                    .map(|section| {
                        vec![super::KernelModuleSectionMap {
                            section: ".data".into(),
                            start: section.address(),
                        }]
                    })
                    .unwrap_or_default();
                assert_eq!(!expected.is_empty(), separate_map);
                std::fs::write(&path, selected).unwrap();
                let runner = NoCommands;
                let resolver = super::SelectedObjectResolver::new(&runner, kind);
                let request = test_request(path.to_str().unwrap(), 0x1001);
                assert!(
                    !resolver
                        .resolve_base_frame_batch_with_metadata(std::slice::from_ref(&request))
                        .unwrap()[0]
                        .frames
                        .is_empty()
                );
                assert_eq!(
                    resolver
                        .selected_object_module_metadata(&path, &request)
                        .unwrap()
                        .maps,
                    expected
                );
                std::fs::write(&path, module_metadata_retention_fixture(!separate_map)).unwrap();
                assert_eq!(
                    resolver
                        .selected_object_module_metadata(&path, &request)
                        .unwrap()
                        .maps,
                    expected
                );
                std::fs::remove_file(&path).unwrap();
                assert_eq!(
                    resolver
                        .selected_object_module_metadata(&path, &request)
                        .unwrap()
                        .maps,
                    expected
                );
                let missing = root.path().join("missing.elf");
                assert_eq!(
                    resolver.selected_object_module_metadata(&missing, &request),
                    None
                );
                std::fs::write(&missing, regression_elf_with_build_id()).unwrap();
                assert!(
                    resolver
                        .selected_object_module_metadata(&missing, &request)
                        .is_none(),
                    "failed selection is retained"
                );
            }
        }
    }

    #[test]
    fn module_text_remapping_keeps_the_first_eligible_text_section() {
        // symbol-elf.c:1397 clears remap_kernel after the first .text symbol,
        // including when later dynsym rows refer to a different .text section.
        let bytes = module_metadata_retention_fixture(false);
        let elf = object::File::parse(bytes.as_slice()).unwrap();
        let first = elf.section_by_name(".text").unwrap().address();
        let mut builder = build::elf::Builder::read(bytes.as_slice()).unwrap();
        let section = builder.sections.add();
        section.name = b".text"[..].into();
        section.sh_type = elf::SHT_NOBITS;
        section.sh_flags = u64::from(elf::SHF_ALLOC | elf::SHF_EXECINSTR);
        section.sh_addr = first + 0x4000;
        section.sh_addralign = 16;
        section.data = build::elf::SectionData::UninitializedData(16);
        let index = section.id();
        for symbol in &mut builder.dynamic_symbols {
            symbol.set_st_info(elf::STB_GLOBAL, elf::STT_FILE);
        }
        let symbol = builder.symbols.add();
        symbol.name = b"second_text"[..].into();
        symbol.section = Some(index);
        symbol.set_st_info(elf::STB_GLOBAL, elf::STT_FUNC);
        symbol.st_value = first + 0x4000;
        symbol.st_size = 16;
        builder.set_section_sizes();
        let mut selected = Vec::new();
        builder.write(&mut selected).unwrap();
        assert_eq!(
            super::kernel_module_object_metadata(&selected, &selected).text_address,
            Some(first)
        );
    }

    #[test]
    fn module_text_remapping_requires_an_eligible_text_symbol_not_just_a_header() {
        // symbol-elf.c:dso__process_kernel_symbol changes .text's pgoff only
        // after dso__load_sym_internal accepts a symbol from that section.
        let bytes = elf_with_text_symbol_fixtures(
            elf::EM_X86_64,
            &[(
                b"initialization",
                0x1000,
                16,
                elf::STB_GLOBAL,
                elf::STT_FUNC,
            )],
        );
        let mut builder = build::elf::Builder::read(bytes.as_slice()).unwrap();
        let section = builder
            .sections
            .iter_mut()
            .find(|section| section.name.as_slice() == b".text")
            .unwrap();
        section.name = b".init.text"[..].into();
        let section = builder.sections.add();
        section.name = b".text"[..].into();
        section.sh_type = elf::SHT_PROGBITS;
        section.sh_flags = u64::from(elf::SHF_ALLOC | elf::SHF_EXECINSTR);
        section.sh_addr = 0x2000;
        section.sh_addralign = 16;
        section.data = build::elf::SectionData::Data(Vec::new().into());
        builder.set_section_sizes();
        let mut selected = Vec::new();
        builder.write(&mut selected).unwrap();
        let metadata = super::kernel_module_object_metadata(&selected, &selected);
        assert_eq!(metadata.text_address, None);
        assert_eq!(metadata.maps.len(), 1);
        assert_eq!(metadata.maps[0].section, ".init.text");
    }

    #[test]
    fn module_event_ip_preprocessing_loads_each_dso_once_without_skipping_core_lookups() {
        // perf map.c:map__load returns immediately once dso__loaded is set;
        // symbol.c:dso__load sets it even when loading fails. A new source ID
        // still represents an independent DSO, even with the same pathname.
        struct CountingPreprocess {
            calls: Cell<usize>,
        }
        impl SymbolResolver for CountingPreprocess {
            fn preprocess_sample_ip(&self, _: &ResolvedMappingRef<'_>) {
                self.calls.set(self.calls.get() + 1);
            }
            fn resolve_batch(&self, _: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
                panic!("event-IP preprocessing must not render symbols");
            }
        }
        let resolver = CountingPreprocess {
            calls: Cell::new(0),
        };
        let mut cache = SymbolFrameCache::new(&resolver);
        let mut module = test_mapping_ref("[a]", 0x10);
        module.symbol_source_id = 7;
        for _ in 0..100 {
            cache.preprocess_sample_ip(&module);
        }
        assert_eq!(resolver.calls.get(), 1);
        module.relative_address = 0x20;
        cache.preprocess_sample_ip(&module);
        assert_eq!(resolver.calls.get(), 1);
        module.symbol_source_id = 8;
        cache.preprocess_sample_ip(&module);
        assert_eq!(resolver.calls.get(), 2);
        let mut core = test_mapping_ref("[kernel.kallsyms]", 0x10);
        core.symbol_source_id = 9;
        cache.preprocess_sample_ip(&core);
        cache.preprocess_sample_ip(&core);
        assert_eq!(resolver.calls.get(), 4);
    }

    #[test]
    fn module_section_maps_reuse_the_first_map_with_the_same_section_name() {
        // perf symbol-elf.c:dso__process_kernel_symbol calls maps__find_by_name
        // before creating a section map, even when ELF section indexes differ.
        let mut builder = build::elf::Builder::new(object::Endianness::Little, true);
        builder.header.e_type = elf::ET_REL;
        builder.header.e_machine = elf::EM_X86_64;
        for (name, kind, data) in [
            (
                b".shstrtab".as_slice(),
                elf::SHT_STRTAB,
                build::elf::SectionData::SectionString,
            ),
            (
                b".symtab".as_slice(),
                elf::SHT_SYMTAB,
                build::elf::SectionData::Symbol,
            ),
            (
                b".strtab".as_slice(),
                elf::SHT_STRTAB,
                build::elf::SectionData::String,
            ),
        ] {
            let section = builder.sections.add();
            section.name = name.into();
            section.sh_type = kind;
            section.sh_addralign = 8;
            section.data = data;
        }
        for (name, address) in [
            (b"first".as_slice(), 0x2000),
            (b"second".as_slice(), 0x3000),
        ] {
            let section = builder.sections.add();
            section.name = b".data"[..].into();
            section.sh_type = elf::SHT_PROGBITS;
            section.sh_flags = u64::from(elf::SHF_ALLOC | elf::SHF_WRITE);
            section.sh_addr = address;
            section.sh_addralign = 8;
            section.data = build::elf::SectionData::Data(vec![0; 8].into());
            let index = section.id();
            let symbol = builder.symbols.add();
            symbol.name = name.into();
            symbol.section = Some(index);
            symbol.set_st_info(elf::STB_GLOBAL, elf::STT_OBJECT);
            symbol.st_size = 8;
        }
        builder.set_section_sizes();
        let mut bytes = Vec::new();
        builder.write(&mut bytes).unwrap();
        assert_eq!(
            super::kernel_module_object_metadata(&bytes, &bytes).maps,
            [super::KernelModuleSectionMap {
                section: ".data".into(),
                start: 0x2000,
            }]
        );
    }

    #[cfg(unix)]
    #[test]
    fn gnu_primary_transport_is_lazy_and_dropped_with_its_resolver() {
        struct NoCommands;
        impl crate::process::CommandRunner for NoCommands {
            fn run(
                &self,
                _: &crate::process::CommandSpec,
            ) -> std::io::Result<crate::process::CommandOutput> {
                panic!("transport preparation must not spawn a helper");
            }
        }

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("selected.elf");
        std::fs::write(&path, regression_elf_with_build_id()).unwrap();
        let runner = NoCommands;
        let resolver = super::Addr2lineResolver::new(&runner);
        assert!(resolver.object_metadata(&path).is_some());
        let selected = resolver.selected_object(&path).unwrap();
        assert!(selected.input.get().is_none());
        let command = selected
            .attach_input(&path, crate::process::CommandSpec::new("addr2line"))
            .unwrap();
        let file = Arc::downgrade(selected.input.get().unwrap().as_ref().unwrap());
        drop(command);
        drop(selected);
        assert!(file.upgrade().is_some(), "DSO retains its selected input");
        drop(resolver);
        assert!(file.upgrade().is_none(), "resolver drop releases its input");
    }

    #[test]
    fn pyroc34_rejects_live_and_cached_build_id_mismatches_in_both_symbolizers() {
        struct NoCommands;
        impl crate::process::CommandRunner for NoCommands {
            fn run(
                &self,
                _: &crate::process::CommandSpec,
            ) -> std::io::Result<crate::process::CommandOutput> {
                panic!("base symbol lookup must not spawn addr2line");
            }
        }
        let bytes = regression_elf_with_build_id();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let offset = object.segments().next().unwrap().file_range().0;
        for kind in [
            super::SymbolizerKind::Addr2line,
            super::SymbolizerKind::RustAddr2line,
        ] {
            for cached in [false, true] {
                for inline in [false, true] {
                    let dir = tempfile::tempdir().unwrap();
                    let path = dir.path().join("library.so");
                    std::fs::write(&path, &bytes).unwrap();
                    let mut request = test_request(path.to_str().unwrap(), offset);
                    request.build_id = Some("11223344".into());
                    let cache = super::perf_build_id_elf_path(dir.path(), "11223344");
                    if cached {
                        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
                        std::fs::write(&cache, &bytes).unwrap();
                    }
                    let resolver = super::PerfSymbolResolver::from_object_resolver(
                        super::SelectedObjectResolver::new(&NoCommands, kind),
                    )
                    .with_debug_dir(dir.path().into());
                    let frames = if inline {
                        resolver.resolve_frame_batch_with_metadata(&[request])
                    } else {
                        resolver.resolve_base_frame_batch_with_metadata(&[request])
                    }
                    .unwrap();
                    assert!(
                        frames[0].frames.is_empty(),
                        "{kind:?}, cached={cached}, inline={inline}: {:?}",
                        frames[0]
                    );
                }
            }
        }
    }

    #[test]
    fn pyroc35_empty_build_id_uses_live_object_like_absent_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("library.so");
        let bytes = regression_elf_with_build_id();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let offset = object.segments().next().unwrap().file_range().0;
        std::fs::write(&path, &bytes).unwrap();
        let resolver =
            super::PerfSymbolResolver::from_object_resolver(RustAddr2lineResolver::new())
                .with_debug_dir(dir.path().into());
        for id in [None, Some(String::new())] {
            let mut request = test_request(path.to_str().unwrap(), offset);
            request.build_id = id;
            assert_eq!(
                resolver
                    .resolve_base_frame_batch_with_metadata(&[request])
                    .unwrap()[0]
                    .frames,
                ["recorded_function+0x0"]
            );
        }
    }

    #[test]
    fn pyroc35_public_cache_helpers_reject_invalid_ids_without_panicking() {
        for id in [
            "",
            "a",
            "abc",
            "../escape",
            "a/../../escape",
            "\u{e9}aa",
            "zzzz",
        ] {
            assert!(
                super::perf_build_id_elf_path(std::path::Path::new("/cache"), id)
                    .as_os_str()
                    .is_empty()
            );
            assert!(
                super::perf_build_id_elf_path_for_dso(
                    std::path::Path::new("/cache"),
                    std::path::Path::new("[vdso]"),
                    id
                )
                .as_os_str()
                .is_empty()
            );
        }
    }

    #[test]
    fn absolute_kernel_mapping_requests_keep_object_offsets_and_original_ips_separate() {
        // perf machine.c:machine__process_kernel_mmap_event distinguishes the
        // kernel module map from map.h:map__map_ip's object-relative offset.
        let start = 0xffff_ffff_c100_0000;
        let mut mapping = test_mapping_ref("/lib/modules/a.ko", 0x10);
        mapping.start = start;
        mapping.end = start + 0x4000;
        mapping.kernel_module_address = Some(start + 0x10);
        let mut request = super::symbol_request_from_mapping_ref(&mapping);
        assert_eq!(request.relative_address, 0x10);
        assert_eq!(request.kernel_module_address, Some(start + 0x10));
        assert_eq!(request.kernel_mapping_range, Some((start, start + 0x4000)));
        let mut object_only = request.clone();
        object_only.kernel_module_address = None;
        assert_ne!(request, object_only);
        assert_ne!(request.cmp(&object_only), std::cmp::Ordering::Equal);
        assert_eq!(
            std::collections::HashSet::from([request.clone(), object_only]).len(),
            2
        );
        mapping.kernel_module_address = None;
        super::update_symbol_request_from_mapping_ref(&mut request, &mapping);
        assert_eq!(request.relative_address, 0x10);
        assert_eq!(request.kernel_module_address, None);
        assert_eq!(request.kernel_mapping_range, None);
    }

    #[test]
    fn pyroc35_empty_mapping_build_id_normalizes_to_absent_request_identity() {
        use std::hash::{Hash, Hasher};
        let mut mapping = test_mapping_ref("/bin/object", 0x10);
        let absent = super::symbol_request_from_mapping_ref(&mapping);
        mapping.build_id = Some(&[]);
        let empty = super::symbol_request_from_mapping_ref(&mapping);
        assert_eq!(empty.build_id, None);
        let mut reused = absent.clone();
        reused.build_id = Some("aabbccdd".into());
        super::update_symbol_request_from_mapping_ref(&mut reused, &mapping);
        assert_eq!(reused.build_id, None);
        let direct_empty = SymbolRequest {
            build_id: Some(String::new()),
            ..absent.clone()
        };
        assert_eq!(direct_empty, absent);
        assert_eq!(direct_empty.cmp(&absent), std::cmp::Ordering::Equal);
        let hash = |request: &SymbolRequest| {
            let mut state = std::hash::DefaultHasher::new();
            request.hash(&mut state);
            state.finish()
        };
        assert_eq!(hash(&direct_empty), hash(&absent));
    }

    #[test]
    fn pyroc35_zero_mapping_build_id_normalizes_to_absent_request_identity() {
        use std::hash::{Hash, Hasher};
        let mut mapping = test_mapping_ref("/bin/object", 0x10);
        let absent = super::symbol_request_from_mapping_ref(&mapping);
        mapping.build_id = Some(&[0; 20]);
        let zero = super::symbol_request_from_mapping_ref(&mapping);
        assert_eq!(zero.build_id, None);
        let mut reused = absent.clone();
        reused.build_id = Some("aabbccdd".into());
        super::update_symbol_request_from_mapping_ref(&mut reused, &mapping);
        assert_eq!(reused.build_id, None);
        let direct_zero = SymbolRequest {
            build_id: Some("00".repeat(20)),
            ..absent.clone()
        };
        assert_eq!(direct_zero, absent);
        assert_eq!(direct_zero.cmp(&absent), std::cmp::Ordering::Equal);
        let hash = |request: &SymbolRequest| {
            let mut state = std::hash::DefaultHasher::new();
            request.hash(&mut state);
            state.finish()
        };
        assert_eq!(hash(&direct_zero), hash(&absent));
    }

    #[test]
    fn pyroc35_zero_recorded_id_allows_live_elf_without_build_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("library.so");
        let bytes = elf_with_dynamic_text_symbol(b"recorded_function", 0x1000, 16);
        let offset = object::File::parse(bytes.as_slice())
            .unwrap()
            .segments()
            .next()
            .unwrap()
            .file_range()
            .0;
        std::fs::write(&path, &bytes).unwrap();
        let resolver =
            super::PerfSymbolResolver::from_object_resolver(RustAddr2lineResolver::new())
                .with_debug_dir(dir.path().into());
        let mut request = test_request(path.to_str().unwrap(), offset);
        request.build_id = Some("00".repeat(20));
        assert_eq!(
            resolver
                .resolve_base_frame_batch_with_metadata(&[request])
                .unwrap()[0]
                .frames,
            ["recorded_function+0x0"]
        );
    }

    #[test]
    fn pyroc34_enforces_recorded_id_and_preserves_no_recorded_id_behavior() {
        for bytes in [
            regression_elf_with_build_id(),
            elf_with_dynamic_text_symbol(b"recorded_function", 0x1000, 16),
        ] {
            let object = object::File::parse(bytes.as_slice()).unwrap();
            let has_elf_id = object.build_id().unwrap().is_some();
            let offset = object.segments().next().unwrap().file_range().0;
            for id in [None, Some(String::new()), Some("aabbccdd".into())] {
                for cached in [false, true] {
                    let dir = tempfile::tempdir().unwrap();
                    let path = dir.path().join("library.so");
                    std::fs::write(&path, &bytes).unwrap();
                    let cache = super::perf_build_id_elf_path(dir.path(), "aabbccdd");
                    if cached {
                        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
                        std::fs::write(&cache, &bytes).unwrap();
                        std::fs::remove_file(&path).unwrap();
                    }
                    if cached && id.as_ref().is_none_or(String::is_empty) {
                        continue;
                    }
                    let mut request = test_request(path.to_str().unwrap(), offset);
                    request.build_id = id.clone();
                    request.file_identity = Some(super::FileIdentity {
                        major: u32::MAX,
                        minor: u32::MAX,
                        inode: u64::MAX,
                        inode_generation: u64::MAX,
                    });
                    let resolver = super::PerfSymbolResolver::from_object_resolver(
                        RustAddr2lineResolver::new(),
                    )
                    .with_debug_dir(dir.path().into());
                    for inline in [false, true] {
                        let frames = if inline {
                            resolver.resolve_frame_batch_with_metadata(&[request.clone()])
                        } else {
                            resolver.resolve_base_frame_batch_with_metadata(&[request.clone()])
                        }
                        .unwrap();
                        if !has_elf_id && id.as_ref().is_some_and(|id| !id.is_empty()) {
                            assert!(
                                frames[0].frames.is_empty(),
                                "recorded ID requires a readable ELF ID"
                            );
                        } else {
                            assert_eq!(frames[0].frames, ["recorded_function+0x0"]);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn pyroc34_unreadable_cache_falls_back_to_matching_live_elf() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("library.so");
        let bytes = regression_elf_with_build_id();
        let offset = object::File::parse(bytes.as_slice())
            .unwrap()
            .segments()
            .next()
            .unwrap()
            .file_range()
            .0;
        std::fs::write(&path, &bytes).unwrap();
        let cache = super::perf_build_id_elf_path(dir.path(), "aabbccdd");
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
        std::fs::write(&cache, b"not an ELF").unwrap();
        let mut request = test_request(path.to_str().unwrap(), offset);
        request.build_id = Some("aabbccdd".into());
        let resolver =
            super::PerfSymbolResolver::from_object_resolver(RustAddr2lineResolver::new())
                .with_debug_dir(dir.path().into());
        assert_eq!(
            resolver
                .resolve_base_frame_batch_with_metadata(&[request])
                .unwrap()[0]
                .frames,
            ["recorded_function+0x0"]
        );
    }

    #[test]
    fn generic_symbolizers_accept_macho_with_text_symbol() {
        struct NoCommands;
        impl crate::process::CommandRunner for NoCommands {
            fn run(
                &self,
                _: &crate::process::CommandSpec,
            ) -> std::io::Result<crate::process::CommandOutput> {
                panic!("symbol-table lookup must not spawn addr2line");
            }
        }
        let mut object = object::write::Object::new(
            object::BinaryFormat::MachO,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let text = object.section_id(object::write::StandardSection::Text);
        object.append_section_data(text, &[0x90; 32], 1);
        object.add_symbol(object::write::Symbol {
            name: b"macho_function".to_vec(),
            value: 16,
            size: 16,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: object::write::SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });
        let bytes = object.write().unwrap();
        let parsed = object::File::parse(bytes.as_slice()).unwrap();
        assert_eq!(parsed.format(), object::BinaryFormat::MachO);
        let symbol = parsed
            .symbols()
            .find(|symbol| symbol.kind() == object::SymbolKind::Text)
            .unwrap();
        let address = symbol.address();
        assert_eq!(symbol.name().unwrap(), "_macho_function");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.macho");
        std::fs::write(&path, &bytes).unwrap();
        let request = test_request(path.to_str().unwrap(), address);
        let rust = RustAddr2lineResolver::new();
        assert!(
            rust.object_metadata(&path).is_some(),
            "generic metadata must accept Mach-O"
        );
        let runner = NoCommands;
        let external = super::Addr2lineResolver::new(&runner);
        assert!(external.object_metadata(&path).is_some());
        assert_eq!(
            rust.resolve_batch(std::slice::from_ref(&request)).unwrap(),
            [Some("_macho_function".into())]
        );
        for resolver in [&rust as &dyn SymbolResolver, &external] {
            assert_eq!(
                resolver
                    .resolve_base_frame_batch_with_metadata(std::slice::from_ref(&request))
                    .unwrap()[0]
                    .frames,
                ["_macho_function+0x0"]
            );
        }
    }

    #[test]
    fn pyroc48_object_reader_stops_at_snapshot_size_and_rejects_truncation() {
        let bytes = regression_elf_with_build_id();
        let mut grown = bytes.clone();
        grown.extend_from_slice(b"unrecorded growth must not be consumed");
        let mut reader = std::io::Cursor::new(grown);
        assert_eq!(
            super::read_object_with_size(&mut reader, bytes.len() as u64),
            Some(bytes.clone())
        );
        assert_eq!(reader.position(), bytes.len() as u64);
        assert!(
            super::read_object_with_size(std::io::Cursor::new(&bytes), bytes.len() as u64 + 1)
                .is_none()
        );
        assert!(super::read_object_with_size(std::io::Cursor::new(b"not ELF"), 7).is_none());
    }

    #[test]
    fn object_snapshot_retains_only_the_known_extent_capacity() {
        for len in [0, 1, 8191, 8192, 8193, 65537, 1_048_577] {
            let bytes = vec![0x5a; len];
            let snapshot = super::read_snapshot_with_size(bytes.as_slice(), len as u64).unwrap();
            assert_eq!(snapshot, bytes);
            assert_eq!(
                snapshot.capacity(),
                len,
                "a known-size snapshot must not retain geometric growth slack"
            );
        }
    }

    #[test]
    fn classified_object_snapshot_retains_only_the_known_extent_capacity() {
        let mut bytes = regression_elf_with_build_id();
        bytes.resize(1_048_577, 0);
        let snapshot =
            super::read_object_with_size(std::io::Cursor::new(&bytes), bytes.len() as u64).unwrap();
        assert_eq!(snapshot, bytes);
        assert_eq!(snapshot.capacity(), bytes.len());
    }

    #[test]
    fn short_snapshot_reads_preserve_bytes_and_exact_capacity() {
        struct ShortReader<'a> {
            bytes: &'a [u8],
            chunk: usize,
        }
        impl std::io::Read for ShortReader<'_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                let len = self.chunk.min(output.len());
                self.bytes.read(&mut output[..len])
            }
        }
        let bytes = vec![0xa5; 65537];
        for chunk in [1, 3, 8191, 8192, 8193, 65537] {
            let mut reader = ShortReader {
                bytes: &bytes,
                chunk,
            };
            let snapshot = super::read_snapshot_with_size(&mut reader, bytes.len() as u64).unwrap();
            assert_eq!(snapshot, bytes);
            assert_eq!(snapshot.capacity(), bytes.len());
            assert!(reader.bytes.is_empty());
        }
    }

    #[test]
    fn empty_and_unrepresentable_snapshots_do_not_read_the_source() {
        struct MustNotRead;
        impl std::io::Read for MustNotRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("empty or unrepresentable snapshots must not consume input");
            }
        }
        let empty = super::read_snapshot_with_size(MustNotRead, 0).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.capacity(), 0);
        for len in [u64::MAX, isize::MAX as u64 + 1] {
            assert!(super::read_snapshot_with_size(MustNotRead, len).is_none());
        }
    }

    #[test]
    fn truncated_snapshot_rejects_early_eof_after_short_reads() {
        let bytes = b"short";
        assert!(super::read_snapshot_with_size(bytes.as_slice(), 8193).is_none());
    }

    #[test]
    fn object_snapshot_retries_interrupted_reads_without_consuming_growth() {
        assert_interrupted_snapshot_preserves_extent(false);
    }

    #[test]
    fn classified_object_reader_retries_interrupted_reads_without_consuming_growth() {
        assert_interrupted_snapshot_preserves_extent(true);
    }

    fn assert_interrupted_snapshot_preserves_extent(classify: bool) {
        struct InterruptedReader {
            cursor: std::io::Cursor<Vec<u8>>,
            interrupt_next: bool,
        }
        impl std::io::Read for InterruptedReader {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                let interrupt = self.interrupt_next;
                self.interrupt_next = !interrupt;
                if interrupt {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                let len = bytes.len().min(3);
                self.cursor.read(&mut bytes[..len])
            }
        }
        impl std::io::Seek for InterruptedReader {
            fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
                self.cursor.seek(position)
            }
        }

        // elfutils lib/system.h:pread_retry wraps every pread in
        // TEMP_FAILURE_RETRY; interruption is not EOF or a corrupt object.
        let expected = regression_elf_with_build_id();
        let mut bytes = expected.clone();
        bytes.extend_from_slice(b"unrecorded growth");
        let mut reader = InterruptedReader {
            cursor: std::io::Cursor::new(bytes),
            interrupt_next: true,
        };
        let result = if classify {
            super::read_object_with_size(&mut reader, expected.len() as u64)
        } else {
            super::read_snapshot_with_size(&mut reader, expected.len() as u64)
        };
        assert_eq!(result.as_deref(), Some(expected.as_slice()));
        assert_eq!(reader.cursor.position(), expected.len() as u64);
    }

    #[test]
    fn object_snapshot_rejects_non_interrupted_errors_without_retry() {
        struct FailingReader {
            error: std::io::ErrorKind,
            calls: usize,
        }
        impl std::io::Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                self.calls += 1;
                Err(self.error.into())
            }
        }
        for error in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::UnexpectedEof,
            std::io::ErrorKind::WouldBlock,
        ] {
            let mut reader = FailingReader { error, calls: 0 };
            assert!(super::read_snapshot_with_size(&mut reader, 1).is_none());
            assert_eq!(reader.calls, 1);
        }
    }

    #[test]
    fn pyroc48_auxiliary_snapshot_is_finite_and_accepts_archives() {
        let bytes = b"!<arch>\n";
        object::read::archive::ArchiveFile::parse(bytes.as_slice()).unwrap();
        assert!(object::File::parse(bytes.as_slice()).is_err());
        let mut grown = bytes.to_vec();
        grown.extend_from_slice(b"later growth");
        let mut reader = std::io::Cursor::new(grown);
        assert_eq!(
            super::read_snapshot_with_size(&mut reader, bytes.len() as u64),
            Some(bytes.to_vec())
        );
        assert_eq!(reader.position(), bytes.len() as u64);
        assert!(super::read_snapshot_with_size(bytes.as_slice(), bytes.len() as u64 + 1).is_none());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("objects.a");
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(super::read_regular_snapshot(&path).unwrap().as_ref(), bytes);
        assert!(super::read_regular_snapshot(dir.path()).is_none());
    }

    #[test]
    fn pyroc48_resolve_batch_uses_cached_main_after_replacement_and_unlink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("library.so");
        std::fs::write(&path, regression_elf_with_build_id()).unwrap();
        let resolver = RustAddr2lineResolver::new();
        let metadata = resolver.object_metadata(&path).unwrap();
        let request = test_request(path.to_str().unwrap(), 0x1001);
        std::fs::write(
            &path,
            elf_with_dynamic_text_symbol(b"replacement", 0x1000, 16),
        )
        .unwrap();
        for unlink in [false, true] {
            if unlink {
                std::fs::remove_file(&path).unwrap();
            }
            assert_eq!(
                resolver
                    .resolve_batch(std::slice::from_ref(&request))
                    .unwrap(),
                [Some("recorded_function".into())]
            );
            assert!(Arc::ptr_eq(
                &metadata.object_bytes,
                &resolver.object_metadata(&path).unwrap().object_bytes,
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pyroc48_recording_selected_fifo_is_rejected_before_object_read() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("object.fifo");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        // A finite ELF and finite writer lifetime make the old read safe to exercise.
        let mut writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        let bytes = regression_elf_with_build_id();
        let capacity =
            usize::try_from(unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETPIPE_SZ) })
                .expect("FIFO capacity must be nonnegative");
        assert!(capacity > 0 && bytes.len() <= capacity);
        let offset = object::File::parse(bytes.as_slice())
            .unwrap()
            .segments()
            .next()
            .unwrap()
            .file_range()
            .0;
        writer.write_all(&bytes).unwrap();
        let close = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(writer);
        });
        let resolver =
            super::PerfSymbolResolver::from_object_resolver(RustAddr2lineResolver::new());
        let request = test_request(path.to_str().unwrap(), offset);
        let selected =
            resolver.object_symbol_request(&request, &mut super::ObjectAddressCache::default());
        close.join().unwrap();
        assert_eq!(
            selected.relative_address, offset,
            "FIFO bytes must not translate a recorded offset"
        );
        assert!(super::object_load_segment_ranges(dir.path()).is_none());
    }

    #[cfg(target_os = "linux")]
    struct Pyroc48LoaderWorker(Option<std::process::Child>);

    #[cfg(target_os = "linux")]
    impl Drop for Pyroc48LoaderWorker {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                // The unreaped owned child cannot have its PID reused.
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn pyroc48_loader_child(root: std::path::PathBuf) {
        let path = super::perf_build_id_elf_path(&root, "aabbccdd");
        let bytes = std::fs::read(&path).expect("regular main ELF fixture");
        let object = object::File::parse(bytes.as_slice()).unwrap();
        assert_eq!(
            object.build_id().unwrap(),
            Some(&[0xaa, 0xbb, 0xcc, 0xdd][..])
        );
        let offset = object.segments().next().unwrap().file_range().0;
        let recorded_path = root.join("recorded/library.so");
        assert!(!recorded_path.exists());
        let mut request = test_request(recorded_path.to_str().unwrap(), offset);
        request.build_id = Some("aabbccdd".into());
        let resolver =
            super::PerfSymbolResolver::from_object_resolver(RustAddr2lineResolver::new())
                .with_debug_dir(root);
        let selected =
            resolver.object_symbol_request(&request, &mut super::ObjectAddressCache::default());
        assert_eq!(selected.path, path, "select the recorded build-ID image");
        assert_eq!(selected.relative_address, 0x1000);
        assert!(resolver.object_resolver.object_metadata(&path).is_some());
        assert_eq!(resolver.object_resolver.cached_object_count(), 1);
        // Unlike the metadata-only frame path, resolve_batch constructs Loader.
        assert_eq!(
            resolver.object_resolver.resolve_batch(&[selected]).unwrap(),
            [Some("recorded_function".into())]
        );
    }

    #[cfg(target_os = "linux")]
    fn pyroc48_loader_snapshot_subprocess(test: &str, fifo: bool) {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;

        const WORKER: &str = "PYROCLAST_PYROC48_LOADER_WORKER";
        const ROOT: &str = "PYROCLAST_PYROC48_LOADER_ROOT";
        if std::env::var(WORKER).as_deref() == Ok(test) {
            pyroc48_loader_child(std::path::PathBuf::from(std::env::var_os(ROOT).unwrap()));
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let path = super::perf_build_id_elf_path(root.path(), "aabbccdd");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, regression_elf_with_build_id()).unwrap();
        // The cache image is named "elf", so Loader derives exactly "elf.dwp".
        let dwp = path.with_extension("dwp");
        if fifo {
            let name = std::ffi::CString::new(dwp.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        } else {
            // Optional parse errors must not hide a valid main-file symbol.
            std::fs::write(&dwp, b"not a DWARF package").unwrap();
        }

        let mut worker = Pyroc48LoaderWorker(Some(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &format!("symbols::tests::{test}"), "--nocapture"])
                .env(WORKER, test)
                .env(ROOT, root.path())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("isolated Loader worker"),
        ));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut fifo_writer = None;
        let timed_out = loop {
            if fifo && fifo_writer.is_none() {
                // ENXIO means no reader. Success proves Loader opened this FIFO,
                // and releases its blocking open without writing or reading bytes.
                match std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
                    .open(&dwp)
                {
                    Ok(writer) => fifo_writer = Some(writer),
                    Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
                    Err(error) => panic!("FIFO writer handshake: {error}"),
                }
            }
            let child = worker.0.as_mut().unwrap();
            if child.try_wait().expect("poll Loader worker").is_some() {
                break false;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().expect("stop timed-out Loader worker");
                break true;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let fifo_opened = fifo_writer.is_some();
        drop(fifo_writer);
        let output = worker.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            !timed_out && output.status.success(),
            "{test}: timeout={timed_out}, fifo_opened={fifo_opened}, status={}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed;"),
            "worker must execute exactly one test: {}",
            String::from_utf8_lossy(&output.stdout),
        );
        assert!(
            !fifo_opened,
            "Loader opened the derived .dwp FIFO after selecting a valid recorded ELF"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pyroc48_loader_derived_dwp_fifo_is_not_opened() {
        pyroc48_loader_snapshot_subprocess("pyroc48_loader_derived_dwp_fifo_is_not_opened", true);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pyroc48_loader_regular_object_control() {
        pyroc48_loader_snapshot_subprocess("pyroc48_loader_regular_object_control", false);
    }

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
    fn symbol_request_preserves_file_identity_when_build_id_present() {
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
        // Conservatively keep these separate rather than introducing a
        // non-transitive missing-identity wildcard into cache equality.
        let inline = SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
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
        assert_ne!(inline, with_identity);
        assert_ne!(hash_of(&inline), hash_of(&with_identity));
        assert_ne!(inline.cmp(&with_identity), std::cmp::Ordering::Equal);
        let different_inode = SymbolRequest {
            file_identity: with_identity.file_identity.map(|mut identity| {
                identity.inode += 1;
                identity
            }),
            ..with_identity.clone()
        };
        assert_ne!(with_identity, different_inode);

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
    fn object_requests_keep_the_containing_segment_vma_for_base_symbols() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        let bytes = elf_with_dynamic_text_symbol(b"pie_function", 0x5000, 32);
        std::fs::write(&path, &bytes).unwrap();
        let object = object::File::parse(bytes.as_slice()).expect("fixture ELF");
        assert_eq!(object.kind(), object::ObjectKind::Dynamic);
        let (file_offset, virtual_address) = object
            .segments()
            .find_map(|segment| {
                let (file_offset, file_size) = segment.file_range();
                let virtual_address = segment.address();
                (file_size > 8).then_some((file_offset + 8, virtual_address + 8))
            })
            .expect("fixture ELF has a load segment");
        assert_ne!(file_offset, virtual_address);

        let request = clean_object_symbol_request(path, file_offset);

        assert_eq!(request.relative_address, virtual_address);
    }

    fn elf_with_distinct_text_and_data_biases() -> Vec<u8> {
        let mut builder = build::elf::Builder::new(object::Endianness::Little, true);
        builder.header.e_type = elf::ET_DYN;
        builder.header.e_machine = elf::EM_X86_64;
        builder.header.e_phoff = 0x40;
        let section = builder.sections.add();
        section.name = b".shstrtab"[..].into();
        section.sh_type = elf::SHT_STRTAB;
        section.data = build::elf::SectionData::SectionString;
        let mut sections = Vec::new();
        for (name, address, flags) in [
            (
                b".text".as_slice(),
                0x1000,
                elf::SHF_ALLOC | elf::SHF_EXECINSTR,
            ),
            (b".data".as_slice(), 0x4000, elf::SHF_ALLOC | elf::SHF_WRITE),
        ] {
            let section = builder.sections.add();
            section.name = name.into();
            section.sh_type = elf::SHT_PROGBITS;
            section.sh_flags = u64::from(flags);
            section.sh_addr = address;
            section.sh_addralign = 16;
            section.data = build::elf::SectionData::Data(vec![0; 64].into());
            sections.push((section.id(), address, flags));
        }
        builder.set_section_sizes();
        for (index, (section, address, flags)) in sections.into_iter().enumerate() {
            let segment = builder.segments.add();
            segment.p_type = elf::PT_LOAD;
            segment.p_flags = elf::PF_R
                | if flags & elf::SHF_EXECINSTR == 0 {
                    elf::PF_W
                } else {
                    elf::PF_X
                };
            segment.p_vaddr = address;
            segment.p_paddr = address;
            segment.p_offset = (u64::try_from(index).unwrap() + 1) * 0x1000;
            segment.p_align = 16;
            segment.append_section(builder.sections.get_mut(section));
        }
        let mut bytes = Vec::new();
        builder.write(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn object_requests_keep_symbol_vma_separate_from_text_biased_inline_address() {
        // perf symbol-elf.c:dso__load_sym_internal converts symbols using
        // their PT_LOAD bias, whereas machine.c:append_inlines passes
        // file offset + .text's bias through map.c:map__rip_2objdump.
        let file = tempfile::NamedTempFile::new().unwrap();
        let bytes = elf_with_distinct_text_and_data_biases();
        std::fs::write(file.path(), &bytes).unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let text = object.section_by_name(".text").unwrap();
        let text_bias = text.address() - text.file_range().unwrap().0;
        let data = object.section_by_name(".data").unwrap();
        let file_offset = data.file_range().unwrap().0 + 15;
        let symbol_address = data.address() + 15;
        let inline_address = file_offset + text_bias;
        assert_ne!(symbol_address, inline_address);
        let request = clean_object_symbol_request(file.path().to_path_buf(), file_offset);
        assert_eq!(request.relative_address, symbol_address);
        let command = super::build_addr2line_command(file.path(), &[request]);
        assert_eq!(
            command.stdin,
            Some(format!("0x{inline_address:x}\n").into_bytes())
        );
    }

    #[test]
    fn object_requests_without_text_keep_zero_objdump_bias_like_perf() {
        // dso__text_offset defaults to zero when .text is absent; do not
        // substitute the queried data segment's bias.
        let file = tempfile::NamedTempFile::new().unwrap();
        let bytes = elf_with_dynamic_symbol_in_section(
            b"data_symbol",
            0x4000,
            32,
            (elf::STT_OBJECT, elf::STV_DEFAULT, false),
            b".data",
            elf::SHF_ALLOC | elf::SHF_WRITE,
        );
        std::fs::write(file.path(), &bytes).unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        assert!(object.section_by_name(".text").is_none());
        let data = object.section_by_name(".data").unwrap();
        let file_offset = data.file_range().unwrap().0 + 7;
        let request = clean_object_symbol_request(file.path().to_path_buf(), file_offset);
        assert_eq!(request.relative_address, data.address() + 7);
        let command = super::build_addr2line_command(file.path(), &[request]);
        assert_eq!(
            command.stdin,
            Some(format!("0x{file_offset:x}\n").into_bytes())
        );
    }

    #[test]
    fn kernel_object_requests_do_not_apply_the_user_text_bias() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let bytes = elf_with_distinct_text_and_data_biases();
        std::fs::write(file.path(), &bytes).unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let data = object.section_by_name(".data").unwrap();
        let mut cache = super::ObjectAddressCache::default();
        let request = super::clean_object_symbol_request_with_cache(
            file.path().to_path_buf(),
            data.file_range().unwrap().0 + 15,
            &mut cache,
            true,
        );
        // map.c:map__rip_2objdump's kernel branch uses kernel relocation,
        // not the user DSO .text offset. Keep the already translated VMA.
        assert_eq!(request.relative_address, data.address() + 15);
        assert_eq!(request.addr2line_address, None);
        let command = super::build_addr2line_command(file.path(), &[request]);
        assert_eq!(
            command.stdin,
            Some(format!("0x{:x}\n", data.address() + 15).into_bytes())
        );
    }

    #[test]
    fn objdump_text_bias_reads_nobits_section_offsets_for_both_elf_classes() {
        // symbol-elf.c:dso__load_sym_internal uses the raw section header,
        // even when .text's bytes are absent from a separate debug file.
        for is_64 in [false, true] {
            for address in [0_u64, 0x5000] {
                let mut builder = build::elf::Builder::new(object::Endianness::Little, is_64);
                builder.header.e_type = elf::ET_EXEC;
                builder.header.e_machine = if is_64 { elf::EM_X86_64 } else { elf::EM_386 };
                let section = builder.sections.add();
                section.name = b".shstrtab"[..].into();
                section.sh_type = elf::SHT_STRTAB;
                section.data = build::elf::SectionData::SectionString;
                let section = builder.sections.add();
                section.name = b".text"[..].into();
                section.sh_type = elf::SHT_NOBITS;
                section.sh_addr = address;
                section.sh_addralign = 1;
                section.data = build::elf::SectionData::UninitializedData(64);
                builder.set_section_sizes();
                let mut bytes = Vec::new();
                builder.write(&mut bytes).unwrap();
                let object = object::File::parse(bytes.as_slice()).unwrap();
                assert!(
                    object
                        .section_by_name(".text")
                        .unwrap()
                        .file_range()
                        .is_none()
                );
                let offset = if is_64 { 64 } else { 52 };
                assert_eq!(
                    super::object_text_offset(&object),
                    address.wrapping_sub(offset)
                );
            }
        }
    }

    #[test]
    fn symbol_request_identity_distinguishes_inline_queries_and_normalizes_default_address() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let hash = |request: &super::SymbolRequest| {
            let mut hasher = DefaultHasher::new();
            request.hash(&mut hasher);
            hasher.finish()
        };
        let direct = test_request("/fixture", 0x400f);
        let same = super::SymbolRequest {
            addr2line_address: Some(direct.relative_address),
            ..direct.clone()
        };
        assert_eq!(direct, same);
        assert_eq!(direct.cmp(&same), std::cmp::Ordering::Equal);
        assert_eq!(hash(&direct), hash(&same));
        let translated = super::SymbolRequest {
            addr2line_address: Some(0x200f),
            ..direct.clone()
        };
        assert_ne!(direct, translated);
        assert_ne!(direct.cmp(&translated), std::cmp::Ordering::Equal);
        assert_ne!(hash(&direct), hash(&translated));
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
        elf_with_text_symbol_fixtures_for_class(machine, machine != elf::EM_ARM, symbols)
    }

    fn elf_with_text_symbol_fixtures_for_class(
        machine: u16,
        is_64: bool,
        symbols: &[(&'static [u8], u64, u64, u8, u8)],
    ) -> Vec<u8> {
        let mut builder = build::elf::Builder::new(object::Endianness::Little, is_64);
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
    fn bfd_lookup_rejects_local_target_special_symbols_like_binutils() {
        // Native maybe_function_sym hooks use cpu-arm.c/cpu-aarch64.c's
        // SPECIAL_SYM_TYPE_ANY, and cpu-riscv.c's exact mapping predicate
        // plus elf.c:_bfd_elf_is_local_label_name. These differ from perf.
        for (machine, names) in [
            (
                elf::EM_ARM,
                vec![b"$a".as_slice(), b"$t", b"$d", b"$x", b"$q", b"$f.1"],
            ),
            (
                elf::EM_AARCH64,
                vec![b"$x".as_slice(), b"$d", b"$m", b"$p", b"$f.1"],
            ),
            (
                elf::EM_RISCV,
                vec![
                    b"$x".as_slice(),
                    b"$d",
                    b"$xrv64i",
                    b".Linternal",
                    b"..internal",
                    b"_.L_internal",
                    b"L0\x01symbol",
                ],
            ),
        ] {
            for name in names {
                let bytes = elf_with_text_symbol_fixtures(
                    machine,
                    &[
                        (b"fixture.c", 0, 0, elf::STB_LOCAL, elf::STT_FILE),
                        (b"function", 0x1000, 64, elf::STB_LOCAL, elf::STT_FUNC),
                        (name, 0x1010, 0, elf::STB_LOCAL, elf::STT_NOTYPE),
                    ],
                );
                assert_eq!(
                    PerfObjectSymbolIndex::from_object_bytes(&bytes)
                        .bfd_function_record_name(0x1014),
                    Some("function"),
                    "machine {machine}, name {name:?}"
                );
            }
        }
    }

    #[test]
    fn bfd_lookup_rejects_aarch64_local_mapping_symbols_like_binutils() {
        // elfnn-aarch64.c:elfNN_aarch64_maybe_function_sym delegates to
        // cpu-aarch64.c:bfd_is_aarch64_special_symbol_name with TYPE_ANY.
        let bytes = elf_with_text_symbol_fixtures(
            elf::EM_AARCH64,
            &[
                (b"fixture.c", 0, 0, elf::STB_LOCAL, elf::STT_FILE),
                (b"function", 0x1000, 64, elf::STB_LOCAL, elf::STT_FUNC),
                (b"$x", 0x1010, 0, elf::STB_LOCAL, elf::STT_NOTYPE),
            ],
        );
        assert_eq!(
            PerfObjectSymbolIndex::from_object_bytes(&bytes).bfd_function_record_name(0x1014),
            Some("function")
        );
    }

    #[test]
    fn bfd_lookup_clears_arm_thumb_function_address_bit_like_binutils() {
        // bfd/elf32-arm.c:elf32_arm_swap_symbol_in clears STT_FUNC's low bit
        // before dwarf2.c:better_fit compares canonical symbol offsets.
        let bytes = elf_with_text_symbol_fixtures(
            elf::EM_ARM,
            &[
                (b"fixture.c", 0, 0, elf::STB_LOCAL, elf::STT_FILE),
                (b"thumb", 0x1001, 16, elf::STB_LOCAL, elf::STT_FUNC),
                (b"base", 0x1000, 32, elf::STB_GLOBAL, elf::STT_FUNC),
            ],
        );
        assert_eq!(
            PerfObjectSymbolIndex::from_object_bytes(&bytes).bfd_function_record_name(0x1000),
            Some("thumb")
        );
    }

    #[test]
    fn bfd_lookup_treats_arm_tfunc_as_function_like_binutils() {
        // elf32_arm_swap_symbol_in converts STT_ARM_TFUNC to STT_FUNC;
        // elfcode.h:elf_slurp_symbol_table then assigns BSF_FUNCTION.
        let bytes = elf_with_text_symbol_fixtures(
            elf::EM_ARM,
            &[
                (b"fixture.c", 0, 0, elf::STB_LOCAL, elf::STT_FILE),
                (b"ordinary", 0x1000, 32, elf::STB_LOCAL, elf::STT_FUNC),
                (
                    b"thumb_alias",
                    0x1000,
                    16,
                    elf::STB_LOCAL,
                    elf::STT_ARM_TFUNC,
                ),
            ],
        );
        assert_eq!(
            PerfObjectSymbolIndex::from_object_bytes(&bytes).bfd_function_record_name(0x1008),
            Some("thumb_alias")
        );
    }

    #[test]
    fn perf_lookup_clears_arm_thumb_function_address_bit() {
        // tools/perf/util/symbol-elf.c:dso__load_sym_internal removes the
        // low address bit only for EM_ARM STT_FUNC, before symbol insertion.
        let bytes = elf_with_text_symbol_fixtures(
            elf::EM_ARM,
            &[(b"thumb", 0x1001, 16, elf::STB_LOCAL, elf::STT_FUNC)],
        );
        assert_eq!(
            PerfObjectSymbolIndex::from_object_bytes(&bytes).symbol_name(0x1000),
            Some("thumb")
        );
    }

    #[test]
    fn perf_lookup_rejects_aarch64_ilp32_mapping_symbols() {
        // dso__load_sym_internal filters EM_AARCH64 mapping symbols without
        // an ELFCLASS restriction, so ELF32 follows the same rule as ELF64.
        let bytes = elf_with_text_symbol_fixtures_for_class(
            elf::EM_AARCH64,
            false,
            &[
                (b"function", 0x1000, 64, elf::STB_LOCAL, elf::STT_FUNC),
                (b"$x", 0x1010, 0, elf::STB_LOCAL, elf::STT_NOTYPE),
            ],
        );
        assert_eq!(
            object::File::parse(bytes.as_slice())
                .unwrap()
                .architecture(),
            object::Architecture::Aarch64_Ilp32
        );
        assert_eq!(
            PerfObjectSymbolIndex::from_object_bytes(&bytes).symbol_name(0x1014),
            Some("function")
        );
    }

    #[test]
    fn arm_symbol_normalization_preserves_non_func_addresses() {
        // Perf strips the low bit only on FUNC; BFD's TFUNC branch changes
        // its type but not its address (elf32_arm_swap_symbol_in).
        for symbol_type in [elf::STT_NOTYPE, elf::STT_GNU_IFUNC] {
            let bytes = elf_with_text_symbol_fixtures(
                elf::EM_ARM,
                &[(b"symbol", 0x1001, 16, elf::STB_LOCAL, symbol_type)],
            );
            let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
            assert_eq!(index.symbol_name(0x1000), None);
            assert_eq!(index.symbol_name(0x1001), Some("symbol"));
        }
        let bytes = elf_with_text_symbol_fixtures(
            elf::EM_ARM,
            &[
                (b"fixture.c", 0, 0, elf::STB_LOCAL, elf::STT_FILE),
                (b"thumb", 0x1001, 16, elf::STB_LOCAL, elf::STT_ARM_TFUNC),
            ],
        );
        let index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
        assert_eq!(index.bfd_function_record_name(0x1000), None);
        assert_eq!(index.bfd_function_record_name(0x1001), Some("thumb"));
    }

    #[test]
    fn bfd_lookup_rejects_riscv_local_mapping_symbols_like_binutils() {
        // elfnn-riscv.c:riscv_maybe_function_sym rejects the exact $x/$d
        // names and $xrv prefix recognized by cpu-riscv.c.
        let bytes = elf_with_text_symbol_fixtures(
            elf::EM_RISCV,
            &[
                (b"fixture.c", 0, 0, elf::STB_LOCAL, elf::STT_FILE),
                (b"function", 0x1000, 64, elf::STB_LOCAL, elf::STT_FUNC),
                (b"$x", 0x1010, 0, elf::STB_LOCAL, elf::STT_NOTYPE),
            ],
        );
        assert_eq!(
            PerfObjectSymbolIndex::from_object_bytes(&bytes).bfd_function_record_name(0x1014),
            Some("function")
        );
    }

    #[test]
    fn bfd_lookup_rejects_aarch64_ifunc_records_like_binutils() {
        // elfnn-aarch64.c:elfNN_aarch64_maybe_function_sym accepts only
        // NOTYPE/FUNC for nonsynthetic symbols, explicitly excluding IFUNC.
        let bytes = elf_with_text_symbol_fixtures(
            elf::EM_AARCH64,
            &[
                (b"fixture.c", 0, 0, elf::STB_LOCAL, elf::STT_FILE),
                (b"function", 0x1000, 64, elf::STB_LOCAL, elf::STT_FUNC),
                (b"ifunc", 0x1008, 16, elf::STB_LOCAL, elf::STT_GNU_IFUNC),
            ],
        );
        assert_eq!(
            PerfObjectSymbolIndex::from_object_bytes(&bytes).bfd_function_record_name(0x100c),
            Some("function")
        );
    }

    #[test]
    fn bfd_lookup_preserves_global_special_symbols_and_nonmapping_labels() {
        for (machine, name, binding) in [
            (elf::EM_ARM, b"$a".as_slice(), elf::STB_GLOBAL),
            (elf::EM_AARCH64, b"$x".as_slice(), elf::STB_GLOBAL),
            (elf::EM_RISCV, b"$d".as_slice(), elf::STB_GLOBAL),
            (elf::EM_ARM, b"$aLong".as_slice(), elf::STB_LOCAL),
            (elf::EM_AARCH64, b"$xLong".as_slice(), elf::STB_LOCAL),
            (elf::EM_RISCV, b"$d.0".as_slice(), elf::STB_LOCAL),
            (elf::EM_RISCV, b"$x.0".as_slice(), elf::STB_LOCAL),
            (elf::EM_RISCV, b"L12\x01suffix".as_slice(), elf::STB_LOCAL),
            (elf::EM_X86_64, b"$x".as_slice(), elf::STB_LOCAL),
            (elf::EM_X86_64, b".Linternal".as_slice(), elf::STB_LOCAL),
        ] {
            let bytes = elf_with_text_symbol_fixtures(
                machine,
                &[
                    (b"fixture.c", 0, 0, elf::STB_LOCAL, elf::STT_FILE),
                    (b"function", 0x1000, 64, elf::STB_LOCAL, elf::STT_FUNC),
                    (name, 0x1010, 0, binding, elf::STT_NOTYPE),
                ],
            );
            assert_eq!(
                PerfObjectSymbolIndex::from_object_bytes(&bytes).bfd_function_record_name(0x1014),
                Some(std::str::from_utf8(name).unwrap()),
                "machine {machine}, name {name:?}"
            );
        }
    }

    #[test]
    fn bfd_lookup_applies_arm_type_whitelists_without_restricting_x86() {
        // elf32-arm.c/elfnn-aarch64.c:maybe_function_sym explicitly reject
        // IFUNC, unlike the generic hook used by x86 and RISC-V.
        for (machine, expected) in [
            (elf::EM_ARM, "function"),
            (elf::EM_AARCH64, "function"),
            (elf::EM_X86_64, "ifunc"),
            (elf::EM_RISCV, "ifunc"),
        ] {
            let bytes = elf_with_text_symbol_fixtures(
                machine,
                &[
                    (b"fixture.c", 0, 0, elf::STB_LOCAL, elf::STT_FILE),
                    (b"function", 0x1000, 64, elf::STB_LOCAL, elf::STT_FUNC),
                    (b"ifunc", 0x1008, 16, elf::STB_LOCAL, elf::STT_GNU_IFUNC),
                ],
            );
            assert_eq!(
                PerfObjectSymbolIndex::from_object_bytes(&bytes).bfd_function_record_name(0x100c),
                Some(expected),
                "machine {machine}"
            );
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
    fn bfd_function_record_lookup_preserves_raw_extents_and_native_cached_alias() {
        // bfd/elf.c:_bfd_elf_maybe_function_sym reads st_size (zero means
        // one), and bfd/dwarf2.c:better_fit compares those raw extents.
        // perf symbol-elf.c:dso__load_sym_internal instead fixes zero-sized
        // ends before choosing duplicate winners. These sizes must not leak
        // into the independent BFD lookup. Queries inside the cached raw
        // extent reuse the winner, even when a fresh scan would pick an alias.
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
            (0x1000, "local_function"),
            (0x1020, "next"),
        ] {
            assert_eq!(index.bfd_function_record_name(address), Some(expected));
        }
        let fresh_index = PerfObjectSymbolIndex::from_object_bytes(&bytes);
        assert_eq!(
            fresh_index.bfd_function_record_name(0x1000),
            Some("global_alias")
        );
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
                },
            ],
            max_end_by_index: vec![0x2000, 0x2000],
            ..PerfObjectSymbolIndex::default()
        };

        assert_eq!(symbols.symbol_name(0x1810), Some("large"));
        let metadata = super::PreparedObjectMetadata {
            object_symbols: symbols,
            ..super::PreparedObjectMetadata::default()
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
            ..PerfObjectSymbolIndex::default()
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
                },
            ],
            max_end_by_index: vec![0x102f, 0x102f, 0x202e, 0x202e],
            ..PerfObjectSymbolIndex::default()
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
            module_metadata: Mutex::default(),
        });

        let frames = resolve_base_frames_from_object_metadata(
            &[SymbolRequest {
                addr2line_address: None,
                kernel_module_address: None,
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
                kernel_dso: SymbolDsoName::Mapping,
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
            ..PerfObjectSymbolIndex::default()
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
            assert_eq!(symbol.name.as_ref(), name);
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
    fn kallsyms_function_rows_preserve_native_separators_names_and_hex_accumulation() {
        // tools/lib/symbol/kallsyms.c, api/io.h:io__get_hex, and
        // perf util/event.c:find_func_symbol_cb define the physical row parser.
        for (row, expected) in [
            ("", None),
            ("1 T function", Some((1, "function"))),
            ("0 w function", Some((0, "function"))),
            ("1 A alias", Some((1, "alias"))),
            ("1 a alias", None),
            ("1 D object", None),
            ("1 TT function", None),
            ("1\tT function", None),
            ("1 T\tfunction", None),
            (" 1 T function", None),
            ("+1 T function", None),
            ("1 T function\t[module]", Some((1, "function\t[module]"))),
            ("1 T function ", Some((1, "function "))),
            ("1 T function\r", Some((1, "function\r"))),
            ("1 T function\0ignored", Some((1, "function"))),
            ("10000000000000001 T function", Some((1, "function"))),
        ] {
            let parsed = super::parse_kallsyms_function_line(row);
            assert_eq!(parsed, expected, "{row:?}");
            if let Some((_, name)) = parsed {
                assert!(row.as_bytes().as_ptr_range().contains(&name.as_ptr()));
            }
        }
    }

    #[test]
    fn live_kallsyms_relocation_ignores_noncanonical_zero_reference_rows() {
        // tools/lib/symbol/kallsyms.c requires one type byte and literal spaces;
        // event.c:find_func_symbol_cb compares the complete remaining name.
        for row in [
            "0000000000000000\tT reference",
            " 0000000000000000 T reference",
            "0000000000000000 TT reference",
            "0000000000000000 T reference ",
        ] {
            let text = format!("{row}\n0000000000001000 T reference\n0000000000001010 T next\n");
            let (_root, path) = live_module_kallsyms_fixture(&text);
            let resolver =
                super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
                    .with_system_kallsyms_from_path(&path);
            let snapshot = resolver.live_kallsyms_snapshot().unwrap();
            assert_eq!(
                snapshot.reference_address("reference"),
                Some(0x1000),
                "{row:?}"
            );
            let mut request = test_request("[kernel.kallsyms]", 0x2010);
            request.kernel_relocation = Some(super::KernelRelocation {
                reference_symbol: "reference".into(),
                recorded_reference_address: 0x2000,
            });
            assert_eq!(snapshot.resolve_core(&request), Some("next+0x0".into()));
        }
    }

    #[test]
    fn live_kallsyms_loaded_kernel_map_excludes_addresses_outside_symbol_extent() {
        // perf symbol.c:dso__load_kernel_sym calls map.c:map__fixup_start/end
        // after loading ordinary kallsyms; later map lookups use these bounds.
        let (_root, path) =
            live_module_kallsyms_fixture("0000000000001000 T first\n0000000000001100 T last\n");
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        let mut request = test_request("[kernel.kallsyms]", 0x3000);
        request.kernel_mapping_range = Some((0x1000, 0x10000));
        let frames = resolver
            .resolve_frame_batch_with_metadata(&[request])
            .unwrap();
        assert_eq!(frames[0].kernel_dso, super::SymbolDsoName::Unmapped);
        assert!(frames[0].frames.is_empty());
    }

    #[test]
    fn live_kallsyms_relocation_keeps_the_first_eligible_zero_reference() {
        // perf symbol.c:kallsyms__delta uses event.c:find_func_symbol_cb,
        // which stops at the first eligible physical match, including zero.
        let (_root, path) = live_module_kallsyms_fixture(
            "0000000000000000 T reference\n\
             0000000000001000 T reference\n\
             0000000000001010 T next\n",
        );
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        let snapshot = resolver.live_kallsyms_snapshot().unwrap();
        assert_eq!(snapshot.reference_address("reference"), Some(0));
        let mut request = test_request("[kernel.kallsyms]", 0x2010);
        request.kernel_relocation = Some(super::KernelRelocation {
            reference_symbol: "reference".into(),
            recorded_reference_address: 0x2000,
        });
        assert_eq!(snapshot.resolve_core(&request), None);
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

        let alpha = resolver.live_module_kallsyms_for_name("[alpha]").unwrap();
        // The source lifetime already retains its first successful read.
        // New module views must not reread or reparse that source snapshot.
        std::fs::write(&path, "0000000000001000 T replacement [alpha]\n").unwrap();
        let beta = resolver.live_module_kallsyms_for_name("[beta]").unwrap();
        let gamma = resolver.live_module_kallsyms_for_name("[gamma]").unwrap();
        assert_multi_module_kallsyms_views(&alpha, &beta, &gamma);
        for module in ["[missing-one]", "[missing-two]", "[missing-one]"] {
            assert!(resolver.live_module_kallsyms_for_name(module).is_none());
        }
        assert!(Arc::ptr_eq(
            &alpha,
            &resolver.live_module_kallsyms_for_name("[alpha]").unwrap()
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
    fn live_kernel_symbol_fallback_does_not_resurrect_module_rows_without_a_map() {
        // perf v7.2.9 symbol.c:1034-1041 discards a module row without a
        // named map; maps.c:731-738 searches only the selected address map.
        let (_root, path) = live_module_kallsyms_fixture(
            "0000000000001000 T core_entry\n\
             0000000000005000 t bpf_prog_abc [bpf]\n\
             0000000000005020 t bpf_prog_def [bpf]\n\
             0000000000003000 T core_tail\n",
        );
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        assert!(!path.with_file_name("modules").exists());
        let snapshot = resolver.live_kallsyms_snapshot().unwrap();
        assert_eq!(
            snapshot.modules["[bpf]"]
                .resolve_module_with_offset(0x5008)
                .as_deref(),
            Some("bpf_prog_abc+0x8"),
            "the module row is present in the source, but has no module map"
        );
        resolver.ordinary_kernel_load.lock().unwrap().core_loaded = true;
        let requests = [
            test_request("[unknown]", 0x5008),
            test_request("[kernel.kallsyms]", 0x5008),
        ];
        assert_eq!(
            requests.map(|request| resolver
                .resolve_kernel_frames(&request)
                .map(|resolved| resolved.frames)),
            [Some(Vec::new()), Some(Vec::new())],
            "module symbol ranges must not substitute for an absent module map"
        );
        let request = test_request("[kernel.kallsyms]", 0x7000);
        assert_eq!(
            resolver.resolve_kernel_frames(&request).unwrap().frames,
            Vec::<String>::new()
        );
        assert!(resolver.ordinary_kernel_address_is_unmapped(&request));
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
        let first_alpha = first.live_module_kallsyms_for_name("[alpha]").unwrap();
        std::fs::write(&path, "0000000000001000 T replacement [alpha]\n").unwrap();
        let second = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        let second_alpha = second.live_module_kallsyms_for_name("[alpha]").unwrap();
        assert_eq!(first_alpha.address_of("alias_last"), Some(0x1000));
        assert_eq!(first_alpha.address_of("replacement"), None);
        assert_eq!(second_alpha.address_of("replacement"), Some(0x1000));
        assert_eq!(second_alpha.address_of("alias_last"), None);
        assert!(!Arc::ptr_eq(&first_alpha, &second_alpha));
        assert_eq!(
            first
                .live_module_kallsyms_for_name("[beta]")
                .unwrap()
                .address_of("shared"),
            Some(0x2010)
        );
        assert!(second.live_module_kallsyms_for_name("[beta]").is_none());
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
            assert!(Kallsyms::parse_module_symbols(line).is_empty(), "{line}");
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
        assert_eq!(strong.symbols[&0x1000].name.as_ref(), "strong");
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
        assert_eq!(view.symbols[&0x1100].name.as_ref(), "winner");
        assert_eq!(view.symbols[&0x1100].end, Some(0x1200));
        assert_eq!(view.address_of("losing"), None);
    }

    #[test]
    fn kallsyms_core_name_index_shares_symbol_storage() {
        // perf symbol.c:symbol__new retains one name in the symbol;
        // __symbols__insert indexes that symbol, not a second name copy.
        let symbols = Kallsyms::parse("1000 T retained\n2000 T next\n").unwrap();
        let name = &symbols.symbols[&0x1000].name;
        let indexed = symbols
            .addresses_by_name
            .get_key_value("retained")
            .unwrap()
            .0;
        assert_eq!(name.as_ptr(), indexed.as_ptr());
    }

    #[test]
    fn kallsyms_module_name_index_shares_symbol_storage() {
        let symbols =
            Kallsyms::parse_modules("1000 T retained [alpha]\n2000 T next [alpha]\n").unwrap();
        let name = &symbols.symbols[&0x1000].name;
        let indexed = symbols
            .addresses_by_name
            .get_key_value("retained")
            .unwrap()
            .0;
        assert_eq!(name.as_ptr(), indexed.as_ptr());
    }

    #[test]
    fn kallsyms_module_path_name_index_shares_symbol_storage() {
        let symbols = Kallsyms::parse_modules_for_path(
            "1000 T retained [alpha]\n2000 T next [alpha]\n",
            "[alpha]",
        )
        .unwrap();
        let name = &symbols.symbols[&0x1000].name;
        let indexed = symbols
            .addresses_by_name
            .get_key_value("retained")
            .unwrap()
            .0;
        assert_eq!(name.as_ptr(), indexed.as_ptr());
    }

    #[test]
    fn kallsyms_live_core_reference_lookup_does_not_own_a_second_name_index() {
        let (_root, path) = live_module_kallsyms_fixture("1000 T retained\n2000 T next\n");
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        let symbols = resolver
            .live_kallsyms_snapshot()
            .unwrap()
            .core
            .as_ref()
            .unwrap();
        assert_eq!(symbols.symbols[&0x1000].name.as_ref(), "retained");
        assert_eq!(
            symbols.resolve_with_offset(0x1001),
            Some("retained+0x1".into())
        );
        // perf symbol.c:kallsyms__delta requests one physical reference via
        // event.c:get_function_start, not a second index of every input name.
        assert!(symbols.addresses_by_name.is_empty());
        assert_eq!(
            resolver
                .live_kallsyms_snapshot()
                .unwrap()
                .reference_address("retained"),
            Some(0x1000)
        );
    }

    #[test]
    fn kallsyms_live_core_does_not_index_unrequested_absolute_references() {
        use std::fmt::Write;

        let mut text = String::from("1000 T retained\n2000 T next\n");
        for i in 0..4096 {
            writeln!(text, "{:x} A reference_{i}", 0x3000 + i).unwrap();
        }
        let (_root, path) = live_module_kallsyms_fixture(&text);
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        let core = resolver
            .live_kallsyms_snapshot()
            .unwrap()
            .core
            .as_ref()
            .unwrap();
        assert_eq!(core.symbols.len(), 2);
        assert_eq!(
            core.resolve_with_offset(0x1001),
            Some("retained+0x1".into())
        );
        assert!(
            core.addresses_by_name.is_empty(),
            "{} owned reference names",
            core.addresses_by_name.len()
        );
        let snapshot = resolver.live_kallsyms_snapshot().unwrap();
        assert!(snapshot.physical.references.lock().unwrap().is_empty());
        assert_eq!(snapshot.reference_address("reference_4095"), Some(0x3fff));
        assert_eq!(snapshot.physical.references.lock().unwrap().len(), 1);
    }

    #[test]
    fn kallsyms_live_module_name_index_shares_symbol_storage() {
        let (_root, path) =
            live_module_kallsyms_fixture("1000 T retained [alpha]\n2000 T next [alpha]\n");
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        let symbols = resolver.live_module_kallsyms_for_name("[alpha]").unwrap();
        let name = &symbols.symbols[&0x1000].name;
        let indexed = symbols
            .addresses_by_name
            .get_key_value("retained")
            .unwrap()
            .0;
        assert_eq!(name.as_ptr(), indexed.as_ptr());
    }

    #[test]
    fn kallsyms_shared_names_outlive_input_and_release_with_final_view() {
        let text = "1000 T retained\n2000 T next\n".to_owned();
        let symbols = Kallsyms::parse(&text).unwrap();
        let name = Arc::downgrade(&symbols.symbols[&0x1000].name);
        let clone = symbols.clone();
        assert!(Arc::ptr_eq(
            &symbols.symbols[&0x1000].name,
            &clone.symbols[&0x1000].name,
        ));
        drop(text);
        drop(symbols);
        assert!(name.upgrade().is_some());
        assert_eq!(clone.address_of("retained"), Some(0x1000));
        assert_eq!(
            clone.resolve_with_offset(0x1003).as_deref(),
            Some("retained+0x3")
        );
        drop(clone);
        assert!(name.upgrade().is_none());
    }

    #[test]
    fn kallsyms_name_index_growth_keeps_shared_storage_and_exact_names() {
        use std::fmt::Write;

        let mut text = String::new();
        for i in 0..2048 {
            writeln!(text, "{:x} T name_{i}", 0x1000 + i * 16).unwrap();
        }
        let symbols = Kallsyms::parse(&text).unwrap();
        drop(text);
        for i in 0..2048 {
            let name = format!("name_{i}");
            let address = 0x1000 + i * 16;
            let (indexed, &indexed_address) = symbols
                .addresses_by_name
                .get_key_value(name.as_str())
                .unwrap();
            assert_eq!(indexed_address, address);
            assert_eq!(indexed.as_ptr(), symbols.symbols[&address].name.as_ptr());
        }
        for missing in ["name", "name_2048", "name_0_suffix", "Name_0", ""] {
            assert_eq!(symbols.address_of(missing), None);
        }
    }

    #[test]
    fn kallsyms_live_relocation_names_keep_physical_order_and_losing_aliases() {
        // perf symbol.c:kallsyms__delta uses event.c:find_func_symbol_cb,
        // before the symbol tree sorts, fixes ends, and removes aliases.
        let (_root, path) = live_module_kallsyms_fixture(
            "2000 T repeat\n1000 T repeat\n3000 W losing\n3000 T winner\n4000 A absolute\n5000 D data\n",
        );
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        let snapshot = resolver.live_kallsyms_snapshot().unwrap();
        std::fs::remove_file(path).unwrap();
        let core = snapshot.core.as_ref().unwrap();
        assert_eq!(snapshot.reference_address("repeat"), Some(0x2000));
        assert_eq!(snapshot.reference_address("losing"), Some(0x3000));
        assert_eq!(snapshot.reference_address("absolute"), Some(0x4000));
        assert_eq!(snapshot.reference_address("data"), None);
        assert_eq!(core.symbols[&0x3000].name.as_ref(), "winner");
        assert!(!core.symbols.contains_key(&0x4000));
        assert_eq!(core.symbols[&0x5000].name.as_ref(), "data");
        assert!(Arc::ptr_eq(
            &core.symbols[&0x1000].name,
            &core.symbols[&0x2000].name
        ));
    }

    #[test]
    fn kallsyms_live_reference_cache_retains_source_spans_not_requested_names() {
        let text = "0 T zero\n1000 T displayed\n2000 A physical\t[module]\0ignored\n";
        let (_root, path) = live_module_kallsyms_fixture(text);
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        let snapshot = resolver.live_kallsyms_snapshot().unwrap();
        assert!(snapshot.physical.references.lock().unwrap().is_empty());
        // Look up only after the file and the caller's name storage disappear.
        std::fs::remove_file(path).unwrap();
        for (name, address) in [("zero", 0), ("physical\t[module]", 0x2000)] {
            let requested = name.to_owned();
            assert_eq!(snapshot.reference_address(&requested), Some(address));
            drop(requested);
        }
        let references = snapshot.physical.references.lock().unwrap();
        assert_eq!(references.len(), 2);
        for (cached, expected) in references
            .iter()
            .zip([("zero", 0), ("physical\t[module]", 0x2000)])
        {
            let super::KallsymsReference::Found { name, address } = cached else {
                panic!("successful physical reference owns a copied name");
            };
            assert_eq!(
                (&snapshot.physical.source[name.clone()], *address),
                expected
            );
        }
    }

    #[test]
    fn cached_kallsyms_relocations_retain_source_and_share_requested_memo_across_clones() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("[kernel.kallsyms]/fixture");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("kallsyms");
        std::fs::write(
            &path,
            "1000 D reference\n2000 T reference\n3000 T displayed\n",
        )
        .unwrap();
        let symbols = Kallsyms::load_perf_build_id_cache(root.path(), "fixture").unwrap();
        let cloned = symbols.clone();
        assert!(symbols.addresses_by_name.is_empty());
        let physical = symbols.physical.as_ref().unwrap();
        assert!(Arc::ptr_eq(physical, cloned.physical.as_ref().unwrap()));
        assert!(physical.references.lock().unwrap().is_empty());
        std::fs::remove_file(path).unwrap();
        super::KALLSYMS_REFERENCE_ROW_VISITS.with(|count| count.set(0));
        let requested = "reference".to_owned();
        assert_eq!(
            symbols.resolve_relocated_with_offset(0x5001, &requested, 0x4000),
            Some("displayed+0x1".into())
        );
        drop(requested);
        assert_eq!(symbols.address_of("absent"), None);
        super::KALLSYMS_REFERENCE_ROW_VISITS.with(|count| assert_eq!(count.get(), 5));
        for _ in 0..100 {
            assert_eq!(cloned.address_of("reference"), Some(0x2000));
            assert_eq!(cloned.address_of("absent"), None);
        }
        super::KALLSYMS_REFERENCE_ROW_VISITS.with(|count| assert_eq!(count.get(), 5));
        let references = physical.references.lock().unwrap();
        assert_eq!(references.len(), 2);
        let super::KallsymsReference::Found { name, address } = &references[0] else {
            panic!("successful physical reference owns a copied name");
        };
        assert_eq!(
            (&physical.source[name.clone()], *address),
            ("reference", 0x2000)
        );
    }

    #[test]
    fn cached_kallsyms_equality_depends_on_physical_source_not_query_cache() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("[kernel.kallsyms]/fixture");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("kallsyms");
        std::fs::write(&path, "1000 D reference\n2000 T reference\n").unwrap();
        let first = Kallsyms::load_perf_build_id_cache(root.path(), "fixture").unwrap();
        let second = Kallsyms::load_perf_build_id_cache(root.path(), "fixture").unwrap();
        assert_eq!(first.address_of("reference"), Some(0x2000));
        assert_eq!(first.address_of("missing"), None);
        assert_eq!(first, second);
        // event.c:find_func_symbol_cb accepts A but not D. Identical display
        // trees can have different physical relocation references.
        std::fs::write(&path, "1000 A reference\n2000 T reference\n").unwrap();
        let third = Kallsyms::load_perf_build_id_cache(root.path(), "fixture").unwrap();
        assert_eq!(first.symbols, third.symbols);
        assert_eq!(third.address_of("reference"), Some(0x1000));
        assert_ne!(first, third);
    }

    #[test]
    fn kallsyms_live_reference_cache_does_not_rescan_hits_or_misses() {
        let (_root, path) = live_module_kallsyms_fixture("1000 T first\n2000 T last\n");
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        let snapshot = resolver.live_kallsyms_snapshot().unwrap();
        super::KALLSYMS_REFERENCE_ROW_VISITS.with(|count| count.set(0));
        assert_eq!(snapshot.reference_address("last"), Some(0x2000));
        assert_eq!(snapshot.reference_address("absent"), None);
        super::KALLSYMS_REFERENCE_ROW_VISITS.with(|count| assert_eq!(count.get(), 4));
        let (storage, capacity) = {
            let references = snapshot.physical.references.lock().unwrap();
            (references.as_ptr(), references.capacity())
        };
        for _ in 0..100 {
            assert_eq!(snapshot.reference_address("last"), Some(0x2000));
            assert_eq!(snapshot.reference_address("absent"), None);
        }
        super::KALLSYMS_REFERENCE_ROW_VISITS.with(|count| assert_eq!(count.get(), 4));
        let references = snapshot.physical.references.lock().unwrap();
        assert_eq!(references.len(), 2);
        assert_eq!(
            (references.as_ptr(), references.capacity()),
            (storage, capacity)
        );
        drop(references);
        // A cached miss must not match a different exact name.
        assert_eq!(snapshot.reference_address("absent_suffix"), None);
        assert_eq!(snapshot.physical.references.lock().unwrap().len(), 3);
    }

    #[test]
    fn kallsyms_reference_spans_preserve_physical_byte_boundaries() {
        // event.c:find_func_symbol_cb compares the full physical C name;
        // kallsyms.c strips only newline and strcmp stops at the first NUL.
        for (text, name, address) in [
            ("1000 D same\n2000 T same\n", "same", 0x2000),
            ("0 A same\n2000 T same", "same", 0),
            ("1 T first\r\n2 T last\r\n", "last\r", 2),
            ("1 T first\n2 w last ", "last ", 2),
            ("1 T first\n2 W last\0suffix", "last", 2),
            (
                "1 T before_\u{00e9}\n2 T matched_\u{00e9}\t[module]\n",
                "matched_\u{00e9}\t[module]",
                2,
            ),
            ("fffffffffffffffff A overflow", "overflow", u64::MAX),
            ("1\tT same\n2 TT same\n3 T same", "same", 3),
        ] {
            let (found, span) = super::kallsyms_reference_span(text, name).unwrap();
            assert_eq!(found, address);
            assert_eq!(&text[span], name);
        }
        assert_eq!(
            super::kallsyms_reference_span("1 T name [module]", "name"),
            None
        );
        assert_eq!(super::kallsyms_reference_span("1 T name\r\n", "name"), None);
        assert_eq!(super::kallsyms_reference_span("+1 T name", "name"), None);
    }

    #[test]
    fn kallsyms_live_reference_cache_is_snapshot_local_and_concurrent() {
        let (_root, path) = live_module_kallsyms_fixture("1000 T shared\n2000 T next\n");
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        let old = resolver.live_kallsyms_snapshot().unwrap();
        std::fs::write(&path, "3000 T shared\n4000 T next\n").unwrap();
        let replacement =
            super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
                .with_system_kallsyms_from_path(&path);
        assert_eq!(
            replacement
                .live_kallsyms_snapshot()
                .unwrap()
                .reference_address("shared"),
            Some(0x3000)
        );
        let barrier = std::sync::Barrier::new(8);
        let visits = std::thread::scope(|scope| {
            let threads = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        super::KALLSYMS_REFERENCE_ROW_VISITS.with(|count| count.set(0));
                        barrier.wait();
                        assert_eq!(old.reference_address("shared"), Some(0x1000));
                        barrier.wait();
                        assert_eq!(old.reference_address("missing"), None);
                        super::KALLSYMS_REFERENCE_ROW_VISITS.with(Cell::get)
                    })
                })
                .collect::<Vec<_>>();
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .sum::<usize>()
        });
        assert_eq!(
            visits, 3,
            "cold hit and miss must each scan once under contention"
        );
        assert_eq!(old.physical.references.lock().unwrap().len(), 2);
    }

    #[test]
    fn kallsyms_live_reference_relocates_resolution_and_map_bounds_identically() {
        let (_root, path) =
            live_module_kallsyms_fixture("4000 A reference\n1000 T first\n2000 T last\n");
        let resolver = super::PerfSymbolResolver::from_object_resolver(UnavailableObjectResolver)
            .with_system_kallsyms_from_path(&path);
        let snapshot = resolver.live_kallsyms_snapshot().unwrap();
        let mut request = test_request("[kernel.kallsyms]", 0x5001);
        request.kernel_relocation = Some(super::KernelRelocation {
            reference_symbol: "reference".into(),
            recorded_reference_address: 0x8000,
        });
        assert_eq!(snapshot.resolve_core(&request), Some("first+0x1".into()));
        assert_eq!(
            snapshot.kernel_map_range(request.kernel_relocation.as_ref()),
            Some((0x5000, 0x7000))
        );
        assert_eq!(snapshot.physical.references.lock().unwrap().len(), 1);
        request.kernel_relocation.as_mut().unwrap().reference_symbol = "missing".into();
        assert_eq!(snapshot.resolve_core(&request), None);
        assert_eq!(
            snapshot.kernel_map_range(request.kernel_relocation.as_ref()),
            None
        );
    }

    #[test]
    fn kallsyms_line_parser_borrows_names_before_address_acceptance() {
        // tools/lib/symbol/kallsyms.c:kallsyms__parse supplies the parsed
        // name to its callback before symbol.c:map__process_kallsym_symbol
        // allocates an accepted symbol. Parsing alone need not own the token.
        for address in ["0000000000000000", "ffffffff91201850"] {
            let line = format!("{address} T borrowed_symbol [module]");
            let (_, name) = super::parse_kallsyms_line(&line).unwrap();
            let original = line.split_whitespace().nth(2).unwrap();
            assert_eq!(name, original);
            assert_eq!(name.as_ptr(), original.as_ptr(), "parser copied {address}");
        }
    }

    #[test]
    fn kallsyms_line_parser_keeps_token_and_malformed_input_behavior() {
        for line in ["", "nothex T name", "1000", "1000 T", "1000 T   "] {
            assert!(super::parse_kallsyms_line(line).is_none(), "{line:?}");
        }
        for line in [
            "1000 T name",
            " 1000\tT\tname [module]\r\n",
            "1000 arbitrary_type name ignored trailing fields",
        ] {
            assert_eq!(super::parse_kallsyms_line(line), Some((0x1000, "name")));
        }
        let name = "x".repeat(4096);
        let line = format!("1000 T {name}");
        let (_, parsed) = super::parse_kallsyms_line(&line).unwrap();
        assert_eq!(parsed, name);
        assert_eq!(parsed.as_ptr(), line[7..].as_ptr());
    }

    #[test]
    fn kallsyms_owns_only_accepted_names_after_input_is_dropped() {
        let text = "0000 T masked\n1000 T first\n1000 T winner\n2000 T first\n".to_owned();
        let symbols = Kallsyms::parse(&text).unwrap();
        drop(text);
        assert_eq!(symbols.address_of("masked"), None);
        assert_eq!(symbols.address_of("first"), Some(0x1000));
        assert_eq!(
            symbols.resolve_with_offset(0x1001),
            Some("winner+0x1".into())
        );
        assert_eq!(
            symbols.resolve_with_offset(0x2001),
            Some("first+0x1".into())
        );
        assert!(Kallsyms::parse("0000 T masked\n").is_err());
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
                kernel_dso: SymbolDsoName::Mapping,
                ..ResolvedSymbolFrames::default()
            }
        );
    }

    type TestDwarfDie<'a> = (usize, gimli::DwTag, Option<&'a str>, &'a [PerfAddressRange]);

    fn test_dwarf_frame_index(
        dies: &[TestDwarfDie<'_>],
        source_line_ranges: &[PerfAddressRange],
        names: &mut PerfDwarfNameInterner,
    ) -> super::PerfDwarfFrameIndex {
        let (abbrev, info, ranges) = test_dwarf_sections(dies);
        // These are function-walk fixtures, with source coverage unless a
        // narrower line table is supplied. Line-less cases use raw sections.
        let default_lines = [test_range(0, u64::MAX)];
        let lines = if source_line_ranges.is_empty() {
            &default_lines[..]
        } else {
            source_line_ranges
        };
        test_dwarf_frame_index_from_sections(&abbrev, &info, &ranges, lines, names)
    }

    fn test_dwarf_sections(dies: &[TestDwarfDie<'_>]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut abbrev = vec![1, 0x11, 1, 0, 0];
        let mut info = vec![0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, 1];
        let mut ranges = Vec::new();
        let mut open_depth = 0;
        for (index, &(depth, tag, name, die_ranges)) in dies.iter().enumerate() {
            assert!(depth > 0 && depth <= open_depth + 1);
            while open_depth >= depth {
                info.push(0);
                open_depth -= 1;
            }
            let code = u8::try_from(index + 2).unwrap();
            assert!(code < 128 && tag.0 < 128);
            abbrev.extend_from_slice(&[code, u8::try_from(tag.0).unwrap(), 1]);
            if name.is_some() {
                abbrev.extend_from_slice(&[0x03, 0x08]); // name: string
            }
            abbrev.extend_from_slice(&[0x55, 0x17, 0, 0]); // ranges: sec_offset
            info.push(code);
            if let Some(name) = name {
                info.extend_from_slice(name.as_bytes());
                info.push(0);
            }
            info.extend_from_slice(&u32::try_from(ranges.len()).unwrap().to_le_bytes());
            for range in die_ranges {
                ranges.extend_from_slice(&range.begin.to_le_bytes());
                ranges.extend_from_slice(&range.end.to_le_bytes());
            }
            ranges.extend_from_slice(&[0; 16]);
            open_depth = depth;
        }
        info.extend(std::iter::repeat_n(0, open_depth + 1));
        abbrev.push(0);
        let length = u32::try_from(info.len() - 4).unwrap();
        info[..4].copy_from_slice(&length.to_le_bytes());
        (abbrev, info, ranges)
    }

    fn test_dwarf_frame_index_from_sections(
        abbrev: &[u8],
        info: &[u8],
        ranges: &[u8],
        source_line_ranges: &[PerfAddressRange],
        names: &mut PerfDwarfNameInterner,
    ) -> super::PerfDwarfFrameIndex {
        let dwarf = gimli::Dwarf::load(|id| {
            let bytes = match id {
                gimli::SectionId::DebugAbbrev => abbrev,
                gimli::SectionId::DebugInfo => info,
                gimli::SectionId::DebugRanges => ranges,
                _ => &[],
            };
            Ok::<_, gimli::Error>(gimli::EndianSlice::new(bytes, gimli::LittleEndian))
        })
        .unwrap();
        let directory = super::PerfDwarfUnitDirectory::new(&dwarf);
        let unit = directory.units[0].unit.as_ref().unwrap();
        super::perf_dwarf_unit_frame_index(&dwarf, unit, &directory, names, source_line_ranges)
    }

    #[test]
    fn inline_function_names_stay_raw_until_lookup_and_keep_the_outer_elf_symbol_like_perf() {
        // Linux v7.2.9 tools/perf/util/libdw.c:85-108: the subprogram uses
        // args->sym; inline DIEs prefer die_get_linkage_name() over die_name().
        let abbrev = [
            1, 0x11, 1, 0, 0, 2, 0x2e, 1, 0x03, 0x08, 0x6e, 0x08, 0x11, 0x01, 0x12, 0x06, 0, 0, 3,
            0x1d, 0, 0x03, 0x08, 0x6e, 0x08, 0x11, 0x01, 0x12, 0x06, 0, 0, 0,
        ];
        let mut info = vec![0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, 1];
        info.extend_from_slice(b"\x02outer\0_ZN2ns5outerEv\0");
        info.extend_from_slice(&0_u64.to_le_bytes());
        info.extend_from_slice(&100_u32.to_le_bytes());
        info.extend_from_slice(b"\x03inner\0_ZN2ns5innerEv\0");
        info.extend_from_slice(&10_u64.to_le_bytes());
        info.extend_from_slice(&10_u32.to_le_bytes());
        info.extend_from_slice(&[0, 0]);
        let length = u32::try_from(info.len() - 4).unwrap();
        info[..4].copy_from_slice(&length.to_le_bytes());
        let mut names = PerfDwarfNameInterner::default();
        let index = test_dwarf_frame_index_from_sections(
            &abbrev,
            &info,
            &[],
            &[test_range(0, 100)],
            &mut names,
        );
        assert_eq!(names.names.raw_name(0), Some("_ZN2ns5outerEv"));
        assert_eq!(names.names.raw_name(1), Some("_ZN2ns5innerEv"));
        assert!(
            names
                .names
                .function_names
                .iter()
                .all(|name| name.rendered.get().is_none())
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&index, &names.names, 15, Some("outer.constprop.0")),
            Some(PerfDwarfFrameNames {
                frames: vec!["ns::inner()".into(), "outer.constprop.0".into()],
                has_inline_frames: true,
            })
        );
        assert!(names.names.function_names[0].rendered.get().is_none());
        assert_eq!(
            names.names.function_names[1]
                .rendered
                .get()
                .unwrap()
                .as_deref(),
            Some("ns::inner()")
        );
    }

    #[test]
    fn inline_fallback_names_demangle_once_and_leave_outer_elf_name_unrendered() {
        let mut names = PerfDwarfNameInterner::default();
        let index = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("_ZN2ns5outerEv"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("_ZN2ns5innerEv"),
                    &[test_range(10, 20)],
                ),
            ],
            &[test_range(0, 100)],
            &mut names,
        );
        assert_eq!(names.names.raw_name(0), Some("_ZN2ns5outerEv"));
        assert_eq!(names.names.raw_name(1), Some("_ZN2ns5innerEv"));
        assert!(
            names
                .names
                .function_names
                .iter()
                .all(|name| name.rendered.get().is_none())
        );
        let expected = Some(PerfDwarfFrameNames {
            frames: vec!["ns::inner()".into(), "outer.constprop.0".into()],
            has_inline_frames: true,
        });
        assert_eq!(
            perf_dwarf_frame_names_from_index(&index, &names.names, 15, Some("outer.constprop.0")),
            expected,
        );
        assert!(names.names.function_names[0].rendered.get().is_none());
        let rendered = names.names.function_names[1].rendered.get().unwrap();
        assert_eq!(rendered.as_deref(), Some("ns::inner()"));
        let pointer = rendered.as_ref().unwrap().as_ptr();
        assert_eq!(
            perf_dwarf_frame_names_from_index(&index, &names.names, 15, Some("outer.constprop.0")),
            expected,
        );
        assert_eq!(names.names.get(1).unwrap().as_ptr(), pointer);
        assert!(names.names.function_names[0].rendered.get().is_none());
        assert_eq!(names.names.raw_name(1), Some("_ZN2ns5innerEv"));
    }

    #[derive(Clone, Copy, Debug)]
    enum CrossCuInlineName {
        Direct,
        LocalReference,
        IndexedString,
    }

    fn identity_map_fixture_text(builder: &mut build::elf::Builder<'_>) {
        let text = builder
            .sections
            .iter()
            .find(|section| section.name.as_slice() == b".text")
            .unwrap()
            .id();
        let address = builder.sections.get(text).sh_addr;
        // Keep both perf's PT_LOAD base bias and global .text inline bias zero.
        let segment = builder.segments.add();
        segment.p_type = elf::PT_LOAD;
        segment.p_flags = elf::PF_R | elf::PF_X;
        segment.p_offset = address;
        segment.p_vaddr = address;
        segment.p_paddr = address;
        segment.p_align = 0x1000;
        segment.append_section(builder.sections.get_mut(text));
        builder.header.e_phoff = 64;
    }

    fn cross_cu_inline_fixture(kind: CrossCuInlineName) -> Vec<u8> {
        let abbrev = vec![
            // CU: low/high PC, str_offsets_base, stmt_list.
            1, 0x11, 1, 0x11, 0x01, 0x12, 0x06, 0x72, 0x17, 0x10, 0x17, 0, 0,
            // Concrete subprogram: name, low/high PC.
            2, 0x2e, 1, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0, 0,
            // Inline: abstract_origin ref_addr, low/high PC.
            3, 0x1d, 1, 0x31, 0x10, 0x11, 0x01, 0x12, 0x06, 0, 0, 4, 0x2e, 0, 0x03, 0x08, 0,
            0, // Abstract subprogram: name string.
            5, 0x2e, 0, 0x31, 0x13, 0, 0, // Abstract subprogram: origin ref4.
            6, 0x2e, 0, 0x03, 0x25, 0, 0, // Abstract subprogram: name strx1.
            0,
        ];
        let unit = |start: u64, string_base: u32| {
            let mut info = vec![0, 0, 0, 0, 5, 0, 1, 8, 0, 0, 0, 0];
            info.push(1);
            info.extend_from_slice(&start.to_le_bytes());
            info.extend_from_slice(&0x40_u32.to_le_bytes());
            info.extend_from_slice(&string_base.to_le_bytes());
            info.extend_from_slice(&0_u32.to_le_bytes());
            info
        };
        let finish = |info: &mut Vec<u8>| {
            info.push(0);
            let length = u32::try_from(info.len() - 4).unwrap();
            info[..4].copy_from_slice(&length.to_le_bytes());
        };
        let mut first = unit(0x1000, 8);
        first.extend_from_slice(b"\x02outer\0");
        first.extend_from_slice(&0x1000_u64.to_le_bytes());
        first.extend_from_slice(&0x40_u32.to_le_bytes());
        let mut references = Vec::new();
        for _ in 0..3 {
            first.push(3);
            references.push(first.len());
            first.extend_from_slice(&0_u32.to_le_bytes());
            first.extend_from_slice(&0x1010_u64.to_le_bytes());
            first.extend_from_slice(&0x10_u32.to_le_bytes());
        }
        first.extend_from_slice(&[0; 4]);
        let decoy_offset = u32::try_from(first.len()).unwrap();
        first.extend_from_slice(b"\x04wrong_unit\0");
        finish(&mut first);

        // This CU has no code at the queried PC. Its names must still resolve.
        let mut second = unit(0x2000, 20);
        for reference in references {
            let offset = u32::try_from(first.len() + second.len()).unwrap();
            first[reference..reference + 4].copy_from_slice(&offset.to_le_bytes());
            match kind {
                CrossCuInlineName::Direct => second.extend_from_slice(b"\x04read_at\0"),
                CrossCuInlineName::LocalReference => {
                    second.push(5);
                    second.extend_from_slice(&decoy_offset.to_le_bytes());
                }
                CrossCuInlineName::IndexedString => second.extend_from_slice(&[6, 0]),
            }
        }
        if matches!(kind, CrossCuInlineName::LocalReference) {
            // The same CU-local offset names wrong_unit in the originating CU.
            let padding = usize::try_from(decoy_offset).unwrap() - second.len() - 2;
            second.push(4);
            second.extend(std::iter::repeat_n(b'p', padding));
            second.push(0);
            assert_eq!(second.len(), usize::try_from(decoy_offset).unwrap());
            second.extend_from_slice(b"\x04read_at\0");
        }
        finish(&mut second);
        first.extend(second);

        let mut string_offsets = Vec::new();
        for offset in [0_u32, 11] {
            string_offsets.extend_from_slice(&8_u32.to_le_bytes());
            string_offsets.extend_from_slice(&5_u16.to_le_bytes());
            string_offsets.extend_from_slice(&0_u16.to_le_bytes());
            string_offsets.extend_from_slice(&offset.to_le_bytes());
        }
        let base = elf_with_text_symbol_fixtures(
            elf::EM_X86_64,
            &[(b"base_symbol", 0x1000, 0x40, elf::STB_GLOBAL, elf::STT_FUNC)],
        );
        let mut builder = build::elf::Builder::read(base.as_slice()).unwrap();
        for (name, data) in [
            (b".debug_abbrev".as_slice(), abbrev),
            (b".debug_info", first),
            (b".debug_str", b"wrong_unit\0read_at\0".to_vec()),
            (b".debug_str_offsets", string_offsets),
            (b".debug_line", cross_cu_line_fixture(0x1000)),
        ] {
            let section = builder.sections.add();
            section.name = name.into();
            section.sh_type = elf::SHT_PROGBITS;
            section.sh_addralign = 1;
            section.data = build::elf::SectionData::Data(data.into());
        }
        builder.set_section_sizes();
        identity_map_fixture_text(&mut builder);
        let mut bytes = Vec::new();
        builder.write(&mut bytes).unwrap();
        bytes
    }

    fn cross_cu_line_fixture(address: u64) -> Vec<u8> {
        let header = b"\x01\x01\x01\xfb\x0e\x0d\x00\x01\x01\x01\x01\x00\x00\x00\x01\x00\x00\x01\x00cross-cu.c\0\x00\x00\x00\x00";
        let mut line = vec![0; 4];
        line.extend_from_slice(&4_u16.to_le_bytes());
        line.extend_from_slice(&u32::try_from(header.len()).unwrap().to_le_bytes());
        line.extend_from_slice(header);
        line.extend_from_slice(&[0, 9, 2]); // DW_LNE_set_address.
        line.extend_from_slice(&address.to_le_bytes());
        line.extend_from_slice(&[1, 2, 0x40, 0, 1, 1]); // copy, advance_pc, end_sequence.
        let length = u32::try_from(line.len() - 4).unwrap();
        line[..4].copy_from_slice(&length.to_le_bytes());
        line
    }

    #[derive(Clone, Copy, Debug)]
    enum InheritedNameOrigin {
        Absent,
        Invalid,
        Cyclic,
        Nameless,
        InvalidLocalString,
        NamedWithMalformedTail,
        OriginBeforeMalformedTail,
        InvalidInheritedString,
        NameAfterBlock,
        ImplicitConstOrigin,
        NestedIndirectOrigin,
        MissingIndirectOrigin,
        ValidIndirectOrigin,
        NestedIndirectLocalName,
        ValidIndirectLocalName,
        WideNestedIndirectOrigin,
        WideImplicitConstOrigin,
        WideValidIndirectOrigin,
        WideIndirectName,
        ZeroIndirectBeforeName,
        OverflowIndirectOrigin,
        OverflowIndirectName,
        LebBeforeName(gimli::DwForm, &'static [u8]),
    }

    fn inherited_name_fixture(kind: InheritedNameOrigin) -> (Vec<u8>, usize) {
        let mut abbrev = vec![
            1, 0x11, 1, 0x11, 1, 0x12, 6, 0x10, 0x17, 0, 0, // CU ranges/stmt_list.
            2, 0x2e, 0, 0x03, 8, 0x11, 1, 0x12, 6, 0, 0, // Named preceding subprogram.
            3, 0x2e, 0, 0x31, 0x13, 0x47, 0x13, 0x11, 1, 0x12, 6, 0, 0, 4, 0x2e, 0, 0x03, 8, 0,
            0, // Named specification.
            5, 0x2e, 0, 0, 0, // Nameless abstract origin.
            6, 0x2e, 0, 0x47, 0x13, 0x11, 1, 0x12, 6, 0, 0, // Specification only.
            7, 0x2e, 0, 0x03, 0x0e, 0x31, 0x13, 0x47, 0x13, 0x11, 1, 0x12, 6, 0, 0,
            // Invalid local name (strp), origin, specification, range.
            8, 0x2e, 0, 0x03, 8, 0x1c, 0x0a, 0, 0, // Name before malformed block1.
            9, 0x2e, 0, 0x31, 0x13, 0x1c, 0x0a, 0, 0, // Origin before malformed block1.
            10, 0x2e, 0, 0x03, 0x0e, 0x31, 0x13, 0, 0, // Invalid strp before origin.
            11, 0x2e, 0, 0x1c, 0x0a, 0x03, 8, 0, 0, // Name after valid block1.
            12, 0x2e, 0, 0x47, 0x13, 0x31, 0x16, 0, 0, // Specification, indirect origin.
            13, 0x2e, 0, 0x11, 1, 0x12, 6, 0x03, 0x16, 0x31, 0x13, 0x47, 0x13, 0, 0,
            // Range before indirect local name, origin, specification.
            14, 0x2e, 0, 0x03, 0x16, 0, 0, // Indirect name only.
            15, 0x2e, 0, 0x1c, 0x16, 0x03, 8, 0, 0, // Zero indirect form before name.
            0,
        ];
        if let InheritedNameOrigin::LebBeforeName(form, _) = kind {
            abbrev.pop();
            abbrev.extend_from_slice(&[16, 0x2e, 0, 0x1c]);
            let mut encoded = gimli::write::EndianVec::new(gimli::LittleEndian);
            gimli::write::Writer::write_uleb128(&mut encoded, u64::from(form.0)).unwrap();
            abbrev.extend_from_slice(encoded.slice());
            abbrev.extend_from_slice(&[0x03, 8, 0, 0, 0]);
        }
        let mut info = vec![0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8];
        info.push(1);
        info.extend_from_slice(&0x1000_u64.to_le_bytes());
        info.extend_from_slice(&0x40_u32.to_le_bytes());
        info.extend_from_slice(&0_u32.to_le_bytes());
        info.extend_from_slice(b"\x02outer\0");
        info.extend_from_slice(&0x1000_u64.to_le_bytes());
        info.extend_from_slice(&0x10_u32.to_le_bytes());
        // A concrete subprogram exercises naming without dwarf_getscopes'
        // separate requirement that inline scopes have a valid abstract origin.
        let function_offset = info.len();
        info.push(match kind {
            InheritedNameOrigin::Absent => 6,
            InheritedNameOrigin::InvalidLocalString => 7,
            InheritedNameOrigin::NestedIndirectLocalName
            | InheritedNameOrigin::ValidIndirectLocalName => 13,
            _ => 3,
        });
        let indirect_local_name = matches!(
            kind,
            InheritedNameOrigin::NestedIndirectLocalName
                | InheritedNameOrigin::ValidIndirectLocalName
        );
        if indirect_local_name {
            info.extend_from_slice(&0x1010_u64.to_le_bytes());
            info.extend_from_slice(&0x10_u32.to_le_bytes());
        }
        if matches!(kind, InheritedNameOrigin::InvalidLocalString) {
            info.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        if indirect_local_name {
            if matches!(kind, InheritedNameOrigin::NestedIndirectLocalName) {
                info.push(0x16);
            }
            info.extend_from_slice(b"\x08local_name\0");
        }
        let origin_reference = if matches!(kind, InheritedNameOrigin::Absent) {
            None
        } else {
            let offset = info.len();
            info.extend_from_slice(&0_u32.to_le_bytes());
            Some(offset)
        };
        let specification_reference = info.len();
        info.extend_from_slice(&0_u32.to_le_bytes());
        if !indirect_local_name {
            info.extend_from_slice(&0x1010_u64.to_le_bytes());
            info.extend_from_slice(&0x10_u32.to_le_bytes());
        }
        let specification = u32::try_from(info.len()).unwrap();
        info.extend_from_slice(b"\x04spec_name\0");
        let origin_entry = inherited_origin_entry(&mut info, kind, specification);
        info[specification_reference..specification_reference + 4]
            .copy_from_slice(&specification.to_le_bytes());
        if let Some(reference) = origin_reference {
            let origin = match kind {
                InheritedNameOrigin::Invalid => u32::MAX,
                InheritedNameOrigin::Cyclic => u32::try_from(function_offset).unwrap(),
                InheritedNameOrigin::InvalidLocalString
                | InheritedNameOrigin::NestedIndirectLocalName
                | InheritedNameOrigin::ValidIndirectLocalName => specification,
                InheritedNameOrigin::Absent => unreachable!(),
                _ => origin_entry,
            };
            info[reference..reference + 4].copy_from_slice(&origin.to_le_bytes());
        }
        let length = u32::try_from(info.len() - 4).unwrap();
        info[..4].copy_from_slice(&length.to_le_bytes());
        (inherited_name_elf(info, abbrev), function_offset)
    }

    fn inherited_origin_entry(
        info: &mut Vec<u8>,
        kind: InheritedNameOrigin,
        specification: u32,
    ) -> u32 {
        let offset = u32::try_from(info.len()).unwrap();
        match kind {
            InheritedNameOrigin::NamedWithMalformedTail => {
                info.extend_from_slice(b"\x08origin_name\0\xff\x00");
            }
            InheritedNameOrigin::OriginBeforeMalformedTail => {
                info.push(9);
                info.extend_from_slice(&specification.to_le_bytes());
                info.extend_from_slice(&[0xff, 0]);
            }
            InheritedNameOrigin::InvalidInheritedString => {
                info.push(10);
                info.extend_from_slice(&u32::MAX.to_le_bytes());
                info.extend_from_slice(&specification.to_le_bytes());
                info.push(0);
            }
            InheritedNameOrigin::NameAfterBlock => {
                info.extend_from_slice(b"\x0b\x03\x01\x02\x03origin_name\0\x00");
            }
            InheritedNameOrigin::WideIndirectName => {
                info.extend_from_slice(b"\x0e\x88\x80\x80\x80\x10origin_name\0\x00");
            }
            InheritedNameOrigin::OverflowIndirectName => {
                info.extend_from_slice(
                    b"\x0e\x88\x80\x80\x80\x80\x80\x80\x80\x80\x02origin_name\0\x00",
                );
            }
            InheritedNameOrigin::ZeroIndirectBeforeName => {
                info.extend_from_slice(b"\x0f\x00origin_name\0\x00");
            }
            InheritedNameOrigin::LebBeforeName(_, value) => {
                info.push(16);
                info.extend_from_slice(value);
                info.extend_from_slice(b"Xname\0\x00");
            }
            InheritedNameOrigin::ImplicitConstOrigin
            | InheritedNameOrigin::NestedIndirectOrigin
            | InheritedNameOrigin::MissingIndirectOrigin
            | InheritedNameOrigin::ValidIndirectOrigin
            | InheritedNameOrigin::WideNestedIndirectOrigin
            | InheritedNameOrigin::WideImplicitConstOrigin
            | InheritedNameOrigin::WideValidIndirectOrigin
            | InheritedNameOrigin::OverflowIndirectOrigin => {
                info.extend_from_slice(b"\x04origin_name\0");
                let origin = u32::try_from(info.len()).unwrap();
                info.push(12);
                info.extend_from_slice(&specification.to_le_bytes());
                match kind {
                    InheritedNameOrigin::ImplicitConstOrigin => info.extend_from_slice(&[0x21, 0]),
                    InheritedNameOrigin::MissingIndirectOrigin => info.push(0x80),
                    InheritedNameOrigin::WideNestedIndirectOrigin => {
                        info.extend_from_slice(&[0x96, 0x80, 0x80, 0x80, 0x10, 0]);
                    }
                    InheritedNameOrigin::WideImplicitConstOrigin => {
                        info.extend_from_slice(&[0xa1, 0x80, 0x80, 0x80, 0x10, 0]);
                    }
                    InheritedNameOrigin::WideValidIndirectOrigin => {
                        info.extend_from_slice(&[0x93, 0x80, 0x80, 0x80, 0x10]);
                        info.extend_from_slice(&offset.to_le_bytes());
                        info.push(0);
                    }
                    InheritedNameOrigin::OverflowIndirectOrigin => {
                        info.extend_from_slice(&[
                            0x93, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02,
                        ]);
                        info.extend_from_slice(&offset.to_le_bytes());
                        info.push(0);
                    }
                    _ => {
                        if matches!(kind, InheritedNameOrigin::NestedIndirectOrigin) {
                            info.push(0x16);
                        }
                        info.push(0x13);
                        info.extend_from_slice(&offset.to_le_bytes());
                        info.push(0);
                    }
                }
                return origin;
            }
            _ => info.extend_from_slice(&[5, 0]),
        }
        offset
    }

    fn inherited_name_elf(info: Vec<u8>, abbrev: Vec<u8>) -> Vec<u8> {
        let base = elf_with_text_symbol_fixtures(
            elf::EM_X86_64,
            &[(b"base_symbol", 0x1000, 0x40, elf::STB_GLOBAL, elf::STT_FUNC)],
        );
        let mut builder = build::elf::Builder::read(base.as_slice()).unwrap();
        for (name, data) in [
            (b".debug_abbrev".as_slice(), abbrev),
            (b".debug_info", info),
            (b".debug_line", cross_cu_line_fixture(0x1000)),
        ] {
            let section = builder.sections.add();
            section.name = name.into();
            section.sh_type = elf::SHT_PROGBITS;
            section.sh_addralign = 1;
            section.data = build::elf::SectionData::Data(data.into());
        }
        builder.set_section_sizes();
        let text = builder
            .sections
            .iter()
            .find(|section| section.sh_flags & u64::from(elf::SHF_EXECINSTR) != 0)
            .unwrap()
            .id();
        let segment = builder.segments.add();
        segment.p_type = elf::PT_LOAD;
        segment.p_flags = elf::PF_R | elf::PF_X;
        segment.p_vaddr = 0x1000;
        segment.p_paddr = 0x1000;
        segment.p_filesz = 0x1000;
        segment.p_memsz = 0x1000;
        segment.p_align = 16;
        segment.append_section(builder.sections.get_mut(text));
        builder.header.e_phoff = 64;
        let mut bytes = Vec::new();
        builder.write(&mut bytes).unwrap();
        bytes
    }

    fn assert_inherited_name_origin(kind: InheritedNameOrigin, expected: Option<&str>) {
        let (bytes, offset) = inherited_name_fixture(kind);
        #[cfg(target_os = "linux")]
        {
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), &bytes).unwrap();
            let output = std::process::Command::new("eu-addr2line")
                .args(["-f", "--pretty-print", "-e"])
                .arg(file.path())
                .arg("0x1018")
                .output()
                .expect("native libdw name oracle");
            assert!(output.status.success(), "{output:?}");
            let text = String::from_utf8(output.stdout).unwrap();
            assert_eq!(
                text.split_whitespace().next(),
                Some(expected.unwrap_or("??")),
                "{text}"
            );
        }
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let dwarf = gimli::Dwarf::load(|section| {
            let bytes = object
                .section_by_name(section.name())
                .map_or(&[][..], |section| section.data().unwrap());
            Ok::<_, gimli::Error>(gimli::EndianSlice::new(bytes, gimli::LittleEndian))
        })
        .unwrap();
        let directory = super::PerfDwarfUnitDirectory::new(&dwarf);
        let unit = directory.units[0].unit.as_ref().unwrap();
        let entry = unit.entry(gimli::UnitOffset(offset)).unwrap();
        // Linux v7.2.9 libdw_a2l_cb uses die_name when linkage is absent. libdw's
        // dwarf_attr_integrate.c:43-63 follows one selected reference chain,
        // not a backtracking search through both attributes.
        assert_eq!(
            super::perf_dwarf_die_frame_name(&dwarf, unit, &directory, &entry)
                .map(|reader| {
                    addr2line::demangle_auto(reader.to_string_lossy(), None).into_owned()
                })
                .as_deref(),
            expected,
            "{kind:?}"
        );
        assert_eq!(
            super::perf_dwarf_frame_names_from_object_bytes(&bytes, 0x1018),
            Some(vec!["base_symbol".to_owned()]),
            "production frame index: {kind:?}"
        );
    }

    #[test]
    fn present_invalid_dwarf_name_does_not_inherit_like_libdw() {
        // dwarf_attr_integrate returns a present attribute before
        // dwarf_formstring validates it; invalid text is not absence.
        assert_inherited_name_origin(InheritedNameOrigin::InvalidLocalString, None);
    }

    #[test]
    fn inherited_dwarf_name_ignores_malformed_later_attributes_like_libdw() {
        // dwarf_child.c:__libdw_find_attr returns the matched attribute
        // before consuming later values in the DIE.
        assert_inherited_name_origin(
            InheritedNameOrigin::NamedWithMalformedTail,
            Some("origin_name"),
        );
    }

    #[test]
    fn absent_dwarf_name_can_follow_origin_before_malformed_tail_like_libdw() {
        assert_inherited_name_origin(
            InheritedNameOrigin::OriginBeforeMalformedTail,
            Some("spec_name"),
        );
    }

    #[test]
    fn present_invalid_inherited_dwarf_name_stops_reference_chain_like_libdw() {
        assert_inherited_name_origin(InheritedNameOrigin::InvalidInheritedString, None);
    }

    #[test]
    fn inherited_dwarf_name_skips_preceding_block_value_like_libdw() {
        assert_inherited_name_origin(InheritedNameOrigin::NameAfterBlock, Some("origin_name"));
    }

    #[test]
    fn implicit_const_indirect_origin_uses_specification_like_libdw() {
        assert_inherited_name_origin(InheritedNameOrigin::ImplicitConstOrigin, Some("spec_name"));
    }

    #[test]
    fn nested_indirect_origin_uses_specification_like_libdw() {
        assert_inherited_name_origin(InheritedNameOrigin::NestedIndirectOrigin, Some("spec_name"));
    }

    #[test]
    fn truncated_indirect_origin_value_does_not_use_specification_like_libdw() {
        // libdw memory-access.h:get_uleb128 returns UINT64_MAX for this
        // unterminated encoding; the selected unsupported form is present.
        assert_inherited_name_origin(InheritedNameOrigin::MissingIndirectOrigin, None);
    }

    #[test]
    fn valid_indirect_origin_takes_precedence_over_specification_like_libdw() {
        assert_inherited_name_origin(
            InheritedNameOrigin::ValidIndirectOrigin,
            Some("origin_name"),
        );
    }

    #[test]
    fn nested_indirect_local_name_is_not_accepted_like_libdw() {
        assert_inherited_name_origin(InheritedNameOrigin::NestedIndirectLocalName, None);
    }

    #[test]
    fn valid_indirect_local_name_precedes_origin_like_libdw() {
        assert_inherited_name_origin(
            InheritedNameOrigin::ValidIndirectLocalName,
            Some("local_name"),
        );
    }

    #[test]
    fn wide_indirect_origin_form_uses_native_u32_restrictions() {
        assert_inherited_name_origin(
            InheritedNameOrigin::WideNestedIndirectOrigin,
            Some("spec_name"),
        );
    }

    #[test]
    fn wide_implicit_const_origin_form_uses_native_u32_restrictions() {
        assert_inherited_name_origin(
            InheritedNameOrigin::WideImplicitConstOrigin,
            Some("spec_name"),
        );
    }

    #[test]
    fn wide_valid_indirect_origin_is_decoded_like_libdw() {
        assert_inherited_name_origin(
            InheritedNameOrigin::WideValidIndirectOrigin,
            Some("origin_name"),
        );
    }

    #[test]
    fn wide_indirect_name_is_decoded_like_libdw() {
        assert_inherited_name_origin(InheritedNameOrigin::WideIndirectName, Some("origin_name"));
    }

    #[test]
    fn zero_indirect_form_before_name_consumes_no_value_like_libdw() {
        assert_inherited_name_origin(
            InheritedNameOrigin::ZeroIndirectBeforeName,
            Some("origin_name"),
        );
    }

    #[test]
    fn terminating_overflow_indirect_origin_uses_native_u32_form() {
        // libdw memory-access.h:get_uleb128_step accepts a terminating tenth
        // byte; dwarf_child.c then narrows the accumulated form to unsigned int.
        assert_inherited_name_origin(
            InheritedNameOrigin::OverflowIndirectOrigin,
            Some("origin_name"),
        );
    }

    #[test]
    fn terminating_overflow_indirect_name_uses_native_u32_form() {
        assert_inherited_name_origin(
            InheritedNameOrigin::OverflowIndirectName,
            Some("origin_name"),
        );
    }

    #[test]
    fn preceding_leb_values_stop_after_ten_bytes_like_libdw() {
        // libdw_form.c:__libdw_form_val_len uses the bounded unsigned decoder
        // even for sdata; skipping must not consume the next name's first byte.
        for form in [
            gimli::DW_FORM_udata,
            gimli::DW_FORM_sdata,
            gimli::DW_FORM_ref_udata,
            gimli::DW_FORM_addrx,
            gimli::DW_FORM_loclistx,
            gimli::DW_FORM_rnglistx,
            gimli::DW_FORM_strx,
            gimli::DW_FORM_GNU_addr_index,
            gimli::DW_FORM_GNU_str_index,
        ] {
            assert_inherited_name_origin(
                InheritedNameOrigin::LebBeforeName(form, &[0x80; 10]),
                Some("Xname"),
            );
        }
    }

    #[test]
    fn preceding_leb_values_consume_only_their_encoding_like_libdw() {
        for value in [&[0x01][..], &[0x81, 0x80, 0x80, 0x80, 0x01][..]] {
            for form in [gimli::DW_FORM_udata, gimli::DW_FORM_sdata] {
                assert_inherited_name_origin(
                    InheritedNameOrigin::LebBeforeName(form, value),
                    Some("Xname"),
                );
            }
        }
        for (form, value) in [
            (
                gimli::DW_FORM_udata,
                &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
            ),
            (
                gimli::DW_FORM_sdata,
                &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f],
            ),
        ] {
            assert_inherited_name_origin(
                InheritedNameOrigin::LebBeforeName(form, value),
                Some("Xname"),
            );
        }
    }

    #[test]
    fn invalid_abstract_origin_does_not_fall_back_to_specification_like_libdw() {
        assert_inherited_name_origin(InheritedNameOrigin::Invalid, None);
    }

    #[test]
    fn cyclic_abstract_origin_does_not_fall_back_to_specification_like_libdw() {
        assert_inherited_name_origin(InheritedNameOrigin::Cyclic, None);
    }

    #[test]
    fn nameless_abstract_origin_does_not_fall_back_to_specification_like_libdw() {
        assert_inherited_name_origin(InheritedNameOrigin::Nameless, None);
    }

    #[test]
    fn absent_abstract_origin_uses_specification_like_libdw() {
        assert_inherited_name_origin(InheritedNameOrigin::Absent, Some("spec_name"));
    }

    fn cross_cu_reference_file(bytes: &[u8]) -> tempfile::NamedTempFile {
        let object = object::File::parse(bytes).unwrap();
        let text = object.section_by_name(".text").unwrap();
        assert_eq!(text.file_range().unwrap().0, text.address());
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), bytes).unwrap();
        let loader = addr2line::Loader::new(file.path()).unwrap();
        let mut frames = loader.find_frames(0x1018).unwrap();
        let mut names = Vec::new();
        while let Some(frame) = frames.next().unwrap() {
            names.push(frame.function.unwrap().raw_name().unwrap().into_owned());
        }
        // Upstream function.rs:name_attr carries the target CU across ref_addr.
        assert_eq!(names, ["read_at", "read_at", "read_at", "outer"]);
        file
    }

    #[test]
    fn standalone_dwarf_names_borrow_original_object_bytes() {
        for kind in [
            CrossCuInlineName::Direct,
            CrossCuInlineName::LocalReference,
            CrossCuInlineName::IndexedString,
        ] {
            let bytes = cross_cu_inline_fixture(kind);
            let resolver =
                super::PerfDwarfNameResolver::from_object_bytes_for_addresses(&bytes, &[0x1018])
                    .unwrap();
            assert_eq!(
                resolver
                    .names
                    .iter()
                    .filter(|name| name.as_bytes() == b"read_at")
                    .count(),
                1,
                "duplicate DIE names share an ID"
            );
            let object_range = bytes.as_ptr_range();
            for name in resolver.names.iter() {
                assert!(
                    object_range.contains(&name.as_ptr()),
                    "{kind:?}: {name:?} was copied instead of borrowing ELF/DWARF bytes"
                );
            }
        }
    }

    #[test]
    fn shared_object_snapshot_keeps_the_read_buffer_allocation() {
        let mut bytes = cross_cu_inline_fixture(CrossCuInlineName::Direct);
        bytes.reserve(8192);
        let pointer = bytes.as_ptr();
        let len = bytes.len();
        let capacity = bytes.capacity();
        let snapshot = super::retain_object_snapshot(bytes);
        assert_eq!(snapshot.len(), len);
        assert_eq!(snapshot.capacity(), capacity);
        assert!(object::File::parse(snapshot.as_slice()).is_ok());
        assert_eq!(
            snapshot.as_ptr(),
            pointer,
            "sharing an already-read snapshot must move its allocation, not copy the whole object"
        );
        let weak = Arc::downgrade(&snapshot);
        let clone = Arc::clone(&snapshot);
        drop(snapshot);
        assert_eq!(clone.as_ptr(), pointer);
        drop(clone);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn shared_empty_snapshot_does_not_allocate_a_byte_buffer() {
        let bytes = Vec::new();
        let pointer = bytes.as_ptr();
        let snapshot = super::retain_object_snapshot(bytes);
        assert!(snapshot.is_empty());
        assert_eq!(snapshot.capacity(), 0);
        assert_eq!(snapshot.as_ptr(), pointer);
    }

    #[test]
    fn cached_dwarf_names_borrow_retained_object_bytes() {
        for kind in [
            CrossCuInlineName::Direct,
            CrossCuInlineName::LocalReference,
            CrossCuInlineName::IndexedString,
        ] {
            let bytes = cross_cu_inline_fixture(kind);
            let file = cross_cu_reference_file(&bytes);
            let resolver = RustAddr2lineResolver::new();
            let metadata = resolver.object_metadata(file.path()).unwrap();
            metadata.prepare_dwarf_frames_for_addresses(&[0x1018]);
            std::fs::remove_file(file.path()).unwrap();
            let cache = metadata.dwarf_index.lock().unwrap();
            assert_eq!(
                cache
                    .names
                    .names
                    .iter()
                    .filter(|name| name.as_bytes() == b"read_at")
                    .count(),
                1
            );
            let object_range = metadata.object_bytes.as_ptr_range();
            for name in cache.names.names.iter() {
                assert!(
                    object_range.contains(&name.as_ptr()),
                    "{kind:?}: {name:?} was copied instead of borrowing cached ELF/DWARF bytes"
                );
            }
            assert_eq!(
                perf_dwarf_frame_names_from_index(
                    cache.units.as_ref().unwrap()[0]
                        .frame_index
                        .as_ref()
                        .unwrap(),
                    &cache.names.names,
                    0x1018,
                    Some("base_symbol"),
                )
                .unwrap()
                .frames,
                ["read_at", "read_at", "read_at", "base_symbol"]
            );
        }
    }

    #[test]
    fn incremental_dwarf_indexes_keep_unit_local_chains_and_shared_names_distinct() {
        let abbrev = vec![
            1, 0x11, 1, 0x11, 0x01, 0x12, 0x06, 0x10, 0x17, 0, 0, 2, 0x2e, 1, 0x03, 0x08, 0x11,
            0x01, 0x12, 0x06, 0, 0, 3, 0x1d, 1, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0, 0, 0,
        ];
        let mut info = Vec::new();
        let mut lines = Vec::new();
        for (address, name) in [(0x1000, "alpha"), (0x2000, "beta")] {
            let mut unit = vec![0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8];
            pyroc50_push_die(&mut unit, 1, None, Some((address, 0x40)));
            unit.extend_from_slice(&u32::try_from(lines.len()).unwrap().to_le_bytes());
            pyroc50_push_die(&mut unit, 2, Some(name), Some((address, 0x40)));
            pyroc50_push_die(&mut unit, 3, Some("shared"), Some((address + 0x10, 8)));
            unit.extend_from_slice(&[0, 0, 0]);
            let length = u32::try_from(unit.len() - 4).unwrap();
            unit[..4].copy_from_slice(&length.to_le_bytes());
            info.extend(unit);
            lines.extend(cross_cu_line_fixture(address));
        }
        let base = elf_with_text_symbol_fixtures(
            elf::EM_X86_64,
            &[
                (b"alpha", 0x1000, 0x40, elf::STB_GLOBAL, elf::STT_FUNC),
                (b"beta", 0x2000, 0x40, elf::STB_GLOBAL, elf::STT_FUNC),
            ],
        );
        let mut builder = build::elf::Builder::read(base.as_slice()).unwrap();
        for section in &mut builder.sections {
            if section.name.as_slice() == b".text" {
                section.data = build::elf::SectionData::Data(vec![0; 0x1040].into());
            }
        }
        for (name, data) in [
            (b".debug_abbrev".as_slice(), abbrev),
            (b".debug_info", info),
            (b".debug_line", lines),
        ] {
            let section = builder.sections.add();
            section.name = name.into();
            section.sh_type = elf::SHT_PROGBITS;
            section.sh_addralign = 1;
            section.data = build::elf::SectionData::Data(data.into());
        }
        builder.set_section_sizes();
        let mut bytes = Vec::new();
        builder.write(&mut bytes).unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        let resolver = RustAddr2lineResolver::new();
        let metadata = resolver.object_metadata(file.path()).unwrap();
        metadata.prepare_dwarf_frames_for_addresses(&[0x1011]);
        let (nodes, segments) = {
            let cache = metadata.dwarf_index.lock().unwrap();
            let units = cache.units.as_ref().unwrap();
            assert_eq!(units.len(), 2);
            assert!(units[1].frame_index.is_none());
            let first = units[0].frame_index.as_ref().unwrap();
            (first.nodes.as_ptr(), first.segments.as_ptr())
        };
        metadata.prepare_dwarf_frames_for_addresses(&[0x2011]);
        {
            let cache = metadata.dwarf_index.lock().unwrap();
            let units = cache.units.as_ref().unwrap();
            let first = units[0].frame_index.as_ref().unwrap();
            let second = units[1].frame_index.as_ref().unwrap();
            assert_eq!(first.nodes.as_ptr(), nodes);
            assert_eq!(first.segments.as_ptr(), segments);
            assert_eq!(first.nodes.len(), 2);
            assert_eq!(second.nodes.len(), 2);
            assert_eq!(first.nodes[1].parent, second.nodes[1].parent);
            assert_eq!(first.nodes[1].name, second.nodes[1].name);
            assert_ne!(first.nodes[0].name, second.nodes[0].name);
        }
        for (address, name) in [(0x1011, "alpha"), (0x2011, "beta"), (0x1011, "alpha")] {
            let frames = metadata
                .dwarf_frame_names_for_base_symbol(address, Some(name))
                .unwrap();
            assert!(frames.has_inline_frames);
            assert_eq!(frames.frames, ["shared", name]);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn compressed_dwarf_names_keep_section_backing_across_incremental_indexes() {
        for format in ["zlib", "zlib-gnu"] {
            let bytes = cross_cu_inline_fixture(CrossCuInlineName::Direct);
            let file = cross_cu_reference_file(&bytes);
            let output = std::process::Command::new("objcopy")
                .arg(format!("--compress-debug-sections={format}"))
                .arg(file.path())
                .output()
                .expect("binutils compressed DWARF fixture");
            assert!(output.status.success(), "{output:?}");
            let resolver = RustAddr2lineResolver::new();
            let metadata = resolver.object_metadata(file.path()).unwrap();
            metadata.prepare_dwarf_frames_for_addresses(&[0x1018]);
            let (backing, name_pointer) =
                {
                    let cache = metadata.dwarf_index.lock().unwrap();
                    let backing = Arc::clone(cache.names.names.backing.as_ref().unwrap());
                    assert!(
                        !backing.decompressed.is_empty(),
                        "{format} fixture must be compressed"
                    );
                    assert!(!cache.names.names.function_names.is_empty());
                    assert_eq!(
                        cache.names.names.function_names.len(),
                        cache.names.names.entries.len()
                    );
                    assert!(
                        cache.names.names.function_names.iter().all(|name| {
                            matches!(name.raw, super::PerfDwarfStoredName::Source(_))
                        })
                    );
                    let name = cache
                        .names
                        .names
                        .iter()
                        .find(|name| *name == "read_at")
                        .unwrap();
                    assert!(
                        backing
                            .decompressed
                            .iter()
                            .any(|bytes| bytes.as_ptr_range().contains(&name.as_ptr()))
                    );
                    (backing, name.as_ptr())
                };
            std::fs::remove_file(file.path()).unwrap();
            metadata.prepare_dwarf_frames_for_addresses(&[0x2000]);
            let cache = metadata.dwarf_index.lock().unwrap();
            assert!(cache.units.as_ref().unwrap()[1].frame_index.is_some());
            assert!(Arc::ptr_eq(
                &backing,
                cache.names.names.backing.as_ref().unwrap()
            ));
            assert_eq!(
                cache
                    .names
                    .names
                    .iter()
                    .find(|name| *name == "read_at")
                    .unwrap()
                    .as_ptr(),
                name_pointer
            );
            assert_eq!(
                perf_dwarf_frame_names_from_index(
                    cache.units.as_ref().unwrap()[0]
                        .frame_index
                        .as_ref()
                        .unwrap(),
                    &cache.names.names,
                    0x1018,
                    Some("base_symbol"),
                )
                .unwrap()
                .frames,
                ["read_at", "read_at", "read_at", "base_symbol"]
            );
        }
    }

    #[test]
    fn function_name_interning_and_rehashing_do_not_render_unused_names() {
        let mut names = PerfDwarfNameInterner::default();
        let reader = gimli::EndianSlice::new(b"_ZN2ns5innerEv", gimli::LittleEndian);
        let id = names.intern(&reader).unwrap();
        let literal = names.intern_text(std::borrow::Cow::Borrowed("_ZN2ns5innerEv"), None, false);
        assert_ne!(id, literal);
        assert_eq!(names.names.get(literal as usize), Some("_ZN2ns5innerEv"));
        for index in 0..1024 {
            names.intern_text(
                std::borrow::Cow::Owned(format!("literal_{index}")),
                None,
                false,
            );
        }
        assert_eq!(names.intern(&reader), Some(id));
        assert_eq!(names.names.entries.len(), 1026);
        assert_eq!(names.names.function_names.len(), 1);
        assert!(names.names.function_names[0].rendered.get().is_none());
        assert_eq!(names.names.get(id as usize), Some("ns::inner()"));
        let pointer = names.names.get(id as usize).unwrap().as_ptr();
        for index in 1024..4096 {
            names.intern_text(
                std::borrow::Cow::Owned(format!("literal_{index}")),
                None,
                false,
            );
        }
        assert_eq!(names.intern(&reader), Some(id));
        let names = names.into_names();
        assert_eq!(names.get(id as usize).unwrap().as_ptr(), pointer);
        assert_eq!(names.raw_name(id as usize), Some("_ZN2ns5innerEv"));
    }

    #[test]
    fn unmangled_fallback_function_names_keep_source_backing_without_owned_rendered_text() {
        let bytes = cross_cu_inline_fixture(CrossCuInlineName::IndexedString);
        let backing = Arc::new(
            super::PerfDwarfBacking::load(super::PerfDwarfObjectBytes::Shared(bytes.into()))
                .unwrap(),
        );
        let weak = Arc::downgrade(&backing);
        let mut names = PerfDwarfNameInterner::with_backing(Arc::clone(&backing));
        let (id, pointer) = {
            let dwarf = backing.dwarf();
            let directory = super::PerfDwarfUnitDirectory::new(&dwarf);
            let unit = directory.units[1].unit.as_ref().unwrap();
            let mut entries = unit.entries();
            let entry = loop {
                let entry = entries.next_dfs().unwrap().unwrap();
                if entry.tag() == gimli::DW_TAG_subprogram {
                    break entry;
                }
            };
            assert!(entry.attr(gimli::DW_AT_linkage_name).is_none());
            let reader = super::perf_dwarf_die_frame_name(&dwarf, unit, &directory, entry).unwrap();
            let pointer = reader.slice().as_ptr();
            let id = names.intern(&reader).unwrap();
            (id, pointer)
        };
        drop(backing);
        assert!(weak.upgrade().is_some());
        assert!(matches!(
            names.names.function_names[0].raw,
            super::PerfDwarfStoredName::Source(_)
        ));
        assert!(names.names.function_names[0].rendered.get().is_none());
        assert_eq!(names.names.get(id as usize), Some("read_at"));
        assert_eq!(names.names.get(id as usize).unwrap().as_ptr(), pointer);
        assert_eq!(names.names.function_names[0].rendered.get(), Some(&None));
        drop(names);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn function_name_ids_and_backing_survive_interner_growth() {
        let bytes = cross_cu_inline_fixture(CrossCuInlineName::IndexedString);
        let backing = Arc::new(
            super::PerfDwarfBacking::load(super::PerfDwarfObjectBytes::Shared(bytes.into()))
                .unwrap(),
        );
        let weak = Arc::downgrade(&backing);
        let mut names = PerfDwarfNameInterner::with_backing(Arc::clone(&backing));
        let (id, pointer) = {
            let dwarf = backing.dwarf();
            let reader = dwarf.debug_str.get_str(gimli::DebugStrOffset(11)).unwrap();
            let pointer = reader.slice().as_ptr();
            let id = names.intern(&reader).unwrap();
            for index in 0..1024 {
                names.intern_text(
                    std::borrow::Cow::Owned(format!("rendered_{index}")),
                    None,
                    false,
                );
            }
            let repeated = dwarf.debug_str.get_str(gimli::DebugStrOffset(11)).unwrap();
            assert_eq!(names.intern(&repeated), Some(id));
            assert_eq!(names.names.entries.len(), 1025);
            (id, pointer)
        };
        drop(backing);
        assert!(
            weak.upgrade().is_some(),
            "name store owns the backing, not the names"
        );
        assert_eq!(names.names.get(id as usize), Some("read_at"));
        assert_eq!(names.names.get(id as usize).unwrap().as_ptr(), pointer);
        drop(names);
        assert!(
            weak.upgrade().is_none(),
            "backing is released with its name store"
        );
    }

    #[test]
    fn rendered_dwarf_names_transfer_storage_once_and_deduplicate_by_text() {
        let mut names = PerfDwarfNameInterner::default();
        let rendered = "demangled_name".to_owned();
        let pointer = rendered.as_ptr();
        let id = names.intern_text(std::borrow::Cow::Owned(rendered), None, false);
        assert_eq!(names.names.get(id as usize).unwrap().as_ptr(), pointer);
        assert_eq!(
            names.intern_text(std::borrow::Cow::Borrowed("demangled_name"), None, false),
            id
        );
        let reader = gimli::EndianSlice::new(b"invalid_\xff", gimli::LittleEndian);
        let lossy = names.intern(&reader).unwrap();
        assert_eq!(names.names.get(lossy as usize), Some("invalid_\u{fffd}"));
        let empty = names.intern_text(std::borrow::Cow::Borrowed(""), None, false);
        assert_eq!(names.names.get(empty as usize), Some(""));
        assert_eq!(names.names.entries.len(), 3);
    }

    #[test]
    fn cross_cu_inline_names_preserve_three_nested_duplicates() {
        let bytes = cross_cu_inline_fixture(CrossCuInlineName::Direct);
        let _reference = cross_cu_reference_file(&bytes);
        assert_eq!(
            super::perf_dwarf_frame_names_from_object_bytes(&bytes, 0x1018),
            Some(vec![
                "read_at".into(),
                "read_at".into(),
                "read_at".into(),
                "base_symbol".into()
            ])
        );
    }

    #[test]
    fn cross_cu_inline_names_keep_target_cu_for_local_references() {
        let bytes = cross_cu_inline_fixture(CrossCuInlineName::LocalReference);
        let _reference = cross_cu_reference_file(&bytes);
        assert_eq!(
            super::perf_dwarf_frame_names_from_object_bytes(&bytes, 0x1018),
            Some(vec![
                "read_at".into(),
                "read_at".into(),
                "read_at".into(),
                "base_symbol".into()
            ])
        );
    }

    #[test]
    fn cross_cu_inline_names_keep_target_cu_for_indexed_strings() {
        let bytes = cross_cu_inline_fixture(CrossCuInlineName::IndexedString);
        let _reference = cross_cu_reference_file(&bytes);
        assert_eq!(
            super::perf_dwarf_frame_names_from_object_bytes(&bytes, 0x1018),
            Some(vec![
                "read_at".into(),
                "read_at".into(),
                "read_at".into(),
                "base_symbol".into()
            ])
        );
    }

    #[test]
    fn cross_cu_inline_names_survive_cold_and_warm_production_indexes() {
        for kind in [
            CrossCuInlineName::Direct,
            CrossCuInlineName::LocalReference,
            CrossCuInlineName::IndexedString,
        ] {
            let bytes = cross_cu_inline_fixture(kind);
            let file = cross_cu_reference_file(&bytes);
            let resolver = RustAddr2lineResolver::new();
            let request = super::clean_object_symbol_request(file.path().into(), 0x1018);
            let first = resolver
                .resolve_frame_batch_with_metadata(&[request])
                .unwrap();
            assert_eq!(
                first[0].frames,
                ["base_symbol", "read_at", "read_at", "read_at"],
                "{kind:?}"
            );
            assert!(first[0].has_base_symbol && first[0].has_inline_frames);
            assert_eq!(first[0].base_offset, Some(0x18));
            let metadata = resolver.object_metadata(file.path()).unwrap();
            let segments = {
                let cache = metadata.dwarf_index.lock().unwrap();
                let units = cache.units.as_ref().unwrap();
                assert_eq!(units.len(), 2);
                assert!(
                    units[1].frame_index.is_none(),
                    "origin CU has no queried code"
                );
                units[0].frame_index.as_ref().unwrap().segments.as_ptr()
            };
            std::fs::remove_file(file.path()).unwrap();
            let requests = [0x1019, 0x101f]
                .map(|address| super::clean_object_symbol_request(file.path().into(), address));
            let warm = resolver
                .resolve_frame_batch_with_metadata(&requests)
                .unwrap();
            for frames in warm {
                assert_eq!(
                    frames.frames,
                    ["base_symbol", "read_at", "read_at", "read_at"],
                    "{kind:?}"
                );
                assert!(frames.has_base_symbol && frames.has_inline_frames);
            }
            assert!(Arc::ptr_eq(
                &metadata,
                &resolver.object_metadata(file.path()).unwrap()
            ));
            let cache = metadata.dwarf_index.lock().unwrap();
            let units = cache.units.as_ref().unwrap();
            assert_eq!(
                units[0].frame_index.as_ref().unwrap().segments.as_ptr(),
                segments
            );
            assert!(units[1].frame_index.is_none());
        }
    }

    fn pyroc50_raw_nested_dwarf(depth: usize, unnamed_inline: bool) -> Vec<u8> {
        // DWARF32 v4, 8-byte addresses. Every DIE has children; null records
        // close them iteratively, including the named leaves and CU.
        let abbrev = vec![
            1, 0x11, 1, 0x11, 0x01, 0x12, 0x06, 0x10, 0x17, 0, 0, // CU: PCs, stmt_list
            2, 0x2e, 1, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0, 0, // named function
            3, 0x0b, 1, 0, 0, // lexical block
            4, 0x1d, 1, 0x11, 0x01, 0x12, 0x06, 0, 0, // unnamed inline
            5, 0x1d, 1, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0, 0, // named inline
            0,
        ];
        let mut info = vec![0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8];
        pyroc50_push_die(&mut info, 1, None, Some((0x1000, 0x40)));
        info.extend_from_slice(&0_u32.to_le_bytes());
        pyroc50_push_die(&mut info, 2, Some("outer"), Some((0x1000, 0x40)));
        for _ in 0..depth {
            if unnamed_inline {
                pyroc50_push_die(&mut info, 4, None, Some((0x1010, 0x10)));
            } else {
                pyroc50_push_die(&mut info, 3, None, None);
            }
        }
        pyroc50_push_die(&mut info, 5, Some("leaf"), Some((0x1018, 4)));
        info.extend(std::iter::repeat_n(0, depth + 1));
        for name in ["trailing", "later"] {
            pyroc50_push_die(&mut info, 5, Some(name), Some((0x1028, 8)));
            info.push(0);
        }
        info.extend_from_slice(&[0, 0]);
        let length = u32::try_from(info.len() - 4).expect("fixture unit length");
        info[..4].copy_from_slice(&length.to_le_bytes());

        let base = elf_with_text_symbol_fixtures(
            elf::EM_X86_64,
            &[(b"base_symbol", 0x1000, 0x40, elf::STB_GLOBAL, elf::STT_FUNC)],
        );
        let mut builder = build::elf::Builder::read(base.as_slice()).expect("fixture ELF");
        for (name, data) in [
            (b".debug_abbrev".as_slice(), abbrev),
            (b".debug_info", info),
            (b".debug_line", cross_cu_line_fixture(0x1000)),
        ] {
            let section = builder.sections.add();
            section.name = name.into();
            section.sh_type = elf::SHT_PROGBITS;
            section.sh_addralign = 1;
            section.data = build::elf::SectionData::Data(data.into());
        }
        builder.set_section_sizes();
        identity_map_fixture_text(&mut builder);
        let mut bytes = Vec::new();
        builder.write(&mut bytes).expect("raw nested DWARF ELF");
        bytes
    }

    fn pyroc50_push_die(
        info: &mut Vec<u8>,
        code: u8,
        name: Option<&str>,
        range: Option<(u64, u32)>,
    ) {
        info.push(code);
        if let Some(name) = name {
            info.extend_from_slice(name.as_bytes());
            info.push(0);
        }
        if let Some((begin, size)) = range {
            info.extend_from_slice(&begin.to_le_bytes());
            info.extend_from_slice(&size.to_le_bytes());
        }
    }

    fn pyroc50_assert_raw_layout(bytes: &[u8], depth: usize, unnamed_inline: bool) {
        use object::ObjectSection as _;

        let object = object::File::parse(bytes).expect("parse raw fixture ELF");
        let text = object.section_by_name(".text").unwrap();
        assert_eq!(text.file_range().unwrap().0, text.address());
        let dwarf = gimli::Dwarf::load(|id| {
            let data = object
                .section_by_name(id.name())
                .map_or(&[][..], |section| {
                    section.data().expect("raw DWARF section")
                });
            Ok::<_, gimli::Error>(gimli::EndianSlice::new(data, gimli::LittleEndian))
        })
        .expect("load raw DWARF");
        let mut headers = dwarf.units();
        let header = headers.next().expect("unit header").expect("one CU");
        assert!(headers.next().expect("end of units").is_none());
        let unit = dwarf.unit(header).expect("valid fixture CU");
        assert!(unit.line_program.is_some());
        let mut cursor = unit.entries();
        let mut dies = 0;
        let mut nulls = 0;
        let mut lexical = 0;
        let mut inlines = 0;
        let mut max_depth = 0;
        let mut names = Vec::new();
        while cursor.next_entry().expect("iteratively parse every DIE") {
            let Some(entry) = cursor.current() else {
                nulls += 1;
                continue;
            };
            dies += 1;
            max_depth = max_depth.max(entry.depth());
            lexical += usize::from(entry.tag() == gimli::DW_TAG_lexical_block);
            inlines += usize::from(entry.tag() == gimli::DW_TAG_inlined_subroutine);
            assert!(entry.has_children());
            if let Some(attr) = entry.attr(gimli::DW_AT_name) {
                names.push(
                    dwarf
                        .attr_string(&unit, attr.value())
                        .expect("fixture name")
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
        assert_eq!(dies, depth + 5);
        assert_eq!(nulls, dies);
        assert_eq!(cursor.next_depth(), 0);
        assert_eq!(max_depth, isize::try_from(depth + 2).unwrap());
        assert_eq!(lexical, if unnamed_inline { 0 } else { depth });
        assert_eq!(inlines, 3 + if unnamed_inline { depth } else { 0 });
        assert_eq!(names, ["outer", "leaf", "trailing", "later"]);
    }

    fn pyroc50_assert_product_frames(bytes: &[u8], unnamed_inline: bool) {
        let addresses = [
            0x1000, 0x100f, 0x1010, 0x1017, 0x1018, 0x101b, 0x101c, 0x101f, 0x1020, 0x1028, 0x102f,
            0x1030, 0x103f, 0x1040,
        ];
        let resolver =
            super::PerfDwarfNameResolver::from_object_bytes_for_addresses(bytes, &addresses)
                .expect("prepare standalone DWARF index");
        assert_eq!(resolver.units.len(), 1);
        assert!(
            resolver.units[0]
                .frame_index
                .segments
                .iter()
                .all(|segment| segment.has_source_line)
        );
        let mut cache = PerfDwarfIndexCache::default();
        super::build_dwarf_index_cache_for_addresses(
            &mut cache,
            super::PerfDwarfObjectBytes::Borrowed(bytes),
            &addresses,
        )
        .expect("prepare cached DWARF index");
        let units = cache.units.as_ref().expect("cached units");
        assert_eq!(units.len(), 1);
        let segments = units[0].frame_index.as_ref().expect("cached segments");
        for address in addresses {
            let names: Option<Vec<String>> = match address {
                0x1018 | 0x101b => Some(vec!["leaf".into(), "base_symbol".into()]),
                0x1028 | 0x102f => Some(vec!["trailing".into(), "base_symbol".into()]),
                0x1010 | 0x1017 | 0x101c | 0x101f if unnamed_inline => {
                    Some(vec!["base_symbol".into()])
                }
                _ => None,
            };
            let expected = names.map(|frames| PerfDwarfFrameNames {
                frames,
                has_inline_frames: true,
            });
            assert_eq!(
                resolver.frame_names_for_base_symbol(address, Some("base_symbol")),
                expected,
                "standalone lookup at {address:#x}"
            );
            assert_eq!(
                perf_dwarf_frame_names_from_index(
                    segments,
                    &cache.names.names,
                    address,
                    Some("base_symbol"),
                ),
                expected,
                "cached lookup at {address:#x}"
            );
        }
        assert_eq!(
            super::perf_dwarf_frame_names_from_object_bytes(bytes, 0x1018),
            Some(vec!["leaf".into(), "base_symbol".into()])
        );
        assert_eq!(
            super::perf_dwarf_frame_names_from_object_bytes(bytes, 0x100f),
            Some(vec!["base_symbol".into()])
        );
        // All indexes must be destroyed on the small product thread.
        drop(cache);
        drop(resolver);
    }

    fn pyroc50_assert_file_resolver_frames(path: &std::path::Path, unnamed_inline: bool) {
        let resolver = RustAddr2lineResolver::new();
        let leaf = super::clean_object_symbol_request(path.to_path_buf(), 0x1018);
        let first = resolver
            .resolve_frame_batch_with_metadata(&[leaf])
            .expect("resolve deep DWARF from file");
        assert_eq!(first[0].frames, ["base_symbol", "leaf"]);
        assert!(first[0].has_base_symbol && first[0].has_inline_frames);
        assert!(first[0].has_non_inline_base_frame);
        assert_eq!(first[0].base_offset, Some(0x18));
        let metadata = resolver
            .object_metadata(path)
            .expect("cached file metadata");
        let segment_pointer = {
            let cache = metadata.dwarf_index.lock().unwrap();
            let units = cache.units.as_ref().expect("file resolver prepared units");
            assert_eq!(units.len(), 1);
            assert_eq!(
                cache.names.names.iter().collect::<Vec<_>>(),
                ["outer", "leaf", "trailing", "later"]
            );
            units[0]
                .frame_index
                .as_ref()
                .expect("prepared CU")
                .segments
                .as_ptr()
        };
        // Different addresses must reuse the loaded file and prepared CU.
        std::fs::remove_file(path).expect("unlink deep fixture after loading");
        let requests = [0x101b, 0x1010, 0x1028, 0x100f]
            .map(|address| super::clean_object_symbol_request(path.to_path_buf(), address));
        let second = resolver
            .resolve_frame_batch_with_metadata(&requests)
            .expect("resolve cached deep DWARF after unlink");
        assert_eq!(second[0].frames, ["base_symbol", "leaf"]);
        if unnamed_inline {
            assert_eq!(second[1].frames, ["base_symbol"]);
            assert!(second[1].has_inline_frames);
        } else {
            assert_eq!(second[1].frames, ["base_symbol+0x10"]);
            assert!(!second[1].has_inline_frames);
        }
        assert_eq!(second[2].frames, ["base_symbol", "trailing"]);
        assert!(second[2].has_inline_frames);
        assert_eq!(second[3].frames, ["base_symbol+0xf"]);
        assert!(!second[3].has_inline_frames);
        assert!(second[3].has_non_inline_base_frame);
        assert!(second.iter().all(|frames| {
            frames.has_base_symbol
                && frames.source_state == super::SymbolSourceState::AddressDependent
        }));
        assert_eq!(resolver.cached_object_count(), 1);
        assert!(Arc::ptr_eq(
            &metadata,
            &resolver.object_metadata(path).unwrap()
        ));
        {
            let cache = metadata.dwarf_index.lock().unwrap();
            assert_eq!(
                cache.units.as_ref().unwrap()[0]
                    .frame_index
                    .as_ref()
                    .unwrap()
                    .segments
                    .as_ptr(),
                segment_pointer,
            );
        }
        drop(metadata);
        drop(resolver);
    }

    fn pyroc50_nested_dwarf_subprocess(test: &str, depth: usize, unnamed_inline: bool) {
        const WORKER: &str = "PYROCLAST_PYROC50_WORKER";
        if std::env::var(WORKER).as_deref() == Ok(test) {
            #[cfg(unix)]
            {
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                // This process is an isolated worker; suppress abort core files.
                assert_eq!(
                    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) },
                    0
                );
            }
            let bytes = pyroc50_raw_nested_dwarf(depth, unnamed_inline);
            pyroc50_assert_raw_layout(&bytes, depth, unnamed_inline);
            let file = tempfile::NamedTempFile::new().expect("deep DWARF fixture file");
            std::fs::write(file.path(), &bytes).expect("write raw deep DWARF fixture");
            std::thread::Builder::new()
                .name("pyroc50-product".into())
                .stack_size(256 * 1024)
                .spawn(move || {
                    pyroc50_assert_product_frames(&bytes, unnamed_inline);
                    pyroc50_assert_file_resolver_frames(file.path(), unnamed_inline);
                    drop(file);
                    drop(bytes);
                })
                .expect("small-stack product thread")
                .join()
                .expect("small-stack product assertions");
            return;
        }

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &format!("symbols::tests::{test}"), "--nocapture"])
            .env(WORKER, test)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("isolated DWARF worker");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let timed_out = loop {
            if child.try_wait().expect("poll DWARF worker").is_some() {
                break false;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().expect("stop timed-out DWARF worker");
                break true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        let output = child.wait_with_output().expect("reap DWARF worker");
        assert!(
            !timed_out && output.status.success(),
            "{test}: timeout={timed_out}, status={}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed;"),
            "worker must execute exactly one test: {}",
            String::from_utf8_lossy(&output.stdout),
        );
    }

    #[test]
    fn pyroc50_deep_lexical_dwarf_is_stack_safe() {
        pyroc50_nested_dwarf_subprocess("pyroc50_deep_lexical_dwarf_is_stack_safe", 16_384, false);
    }

    #[test]
    fn pyroc50_deep_unnamed_inline_dwarf_is_stack_safe() {
        pyroc50_nested_dwarf_subprocess(
            "pyroc50_deep_unnamed_inline_dwarf_is_stack_safe",
            16_384,
            true,
        );
    }

    #[test]
    fn pyroc50_shallow_lexical_dwarf_control() {
        pyroc50_nested_dwarf_subprocess("pyroc50_shallow_lexical_dwarf_control", 8, false);
    }

    #[test]
    fn pyroc50_shallow_unnamed_inline_dwarf_control() {
        pyroc50_nested_dwarf_subprocess("pyroc50_shallow_unnamed_inline_dwarf_control", 8, true);
    }

    #[test]
    fn named_dwarf_scope_storage_grows_linearly_with_depth() {
        let depth = 64;
        let labels: Vec<_> = (0..depth).map(|index| format!("scope_{index}")).collect();
        let ranges: Vec<_> = (0..depth)
            .map(|index| [test_range(index as u64, (2 * depth - index) as u64)])
            .collect();
        let dies: Vec<_> = (0..depth)
            .map(|index| {
                (
                    index + 1,
                    if index == 0 {
                        gimli::DW_TAG_subprogram
                    } else {
                        gimli::DW_TAG_inlined_subroutine
                    },
                    Some(labels[index].as_str()),
                    ranges[index].as_slice(),
                )
            })
            .collect();
        let mut names = PerfDwarfNameInterner::default();
        let index = test_dwarf_frame_index(&dies, &[], &mut names);
        assert_eq!(index.segments.len(), 2 * depth - 1);
        let frames =
            perf_dwarf_frame_names_from_index(&index, &names.names, depth as u64, None).unwrap();
        assert_eq!(
            frames.frames,
            labels.iter().rev().cloned().collect::<Vec<_>>()
        );
        // Each arena node stores exactly one identifier, shared by its descendants.
        let retained_ids = index.nodes.len();
        assert!(
            retained_ids <= depth,
            "{depth} named scopes retained {retained_ids} frame identifiers"
        );
    }

    #[test]
    fn dwarf_frame_chains_keep_range_less_and_fully_covered_ancestors() {
        for parent_ranges in [Vec::new(), vec![test_range(10, 20)]] {
            let mut names = PerfDwarfNameInterner::default();
            let index = test_dwarf_frame_index(
                &[
                    (1, gimli::DW_TAG_subprogram, Some("outer"), &parent_ranges),
                    (
                        2,
                        gimli::DW_TAG_inlined_subroutine,
                        Some("inner"),
                        &[test_range(10, 20)],
                    ),
                ],
                &[],
                &mut names,
            );
            assert_eq!(index.nodes.len(), 2);
            assert_eq!(index.segments.len(), 1);
            assert_eq!(
                perf_dwarf_frame_names_from_index(&index, &names.names, 15, None)
                    .unwrap()
                    .frames,
                ["inner", "outer"]
            );
        }
    }

    #[test]
    fn dwarf_frame_chains_reclaim_dead_suffixes_without_changing_live_siblings() {
        let mut names = PerfDwarfNameInterner::default();
        let index = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("outer"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("same"),
                    &[test_range(10, 20)],
                ),
                (2, gimli::DW_TAG_inlined_subroutine, Some("dead"), &[]),
                (3, gimli::DW_TAG_inlined_subroutine, Some("dead_child"), &[]),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("same"),
                    &[test_range(30, 40)],
                ),
            ],
            &[],
            &mut names,
        );
        assert_eq!(index.nodes.len(), 3);
        assert_eq!(index.nodes[1].name, index.nodes[2].name);
        assert_eq!(index.nodes[1].parent, index.nodes[2].parent);
        for address in [15, 35] {
            assert_eq!(
                perf_dwarf_frame_names_from_index(&index, &names.names, address, None)
                    .unwrap()
                    .frames,
                ["same", "outer"]
            );
        }
        let first = index
            .segments
            .iter()
            .find(|segment| segment.range.begin == 10)
            .unwrap();
        let second = index
            .segments
            .iter()
            .find(|segment| segment.range.begin == 30)
            .unwrap();
        assert_ne!(first.frame, second.frame);
    }

    #[test]
    fn dwarf_frame_chains_preserve_repeated_names_in_recursive_scopes() {
        let mut names = PerfDwarfNameInterner::default();
        let index = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("same"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("same"),
                    &[test_range(10, 20)],
                ),
            ],
            &[],
            &mut names,
        );
        assert_eq!(names.names.entries.len(), 1);
        assert_eq!(index.nodes.len(), 2);
        assert_eq!(
            perf_dwarf_frame_names_from_index(&index, &names.names, 15, None)
                .unwrap()
                .frames,
            ["same", "same"]
        );
    }

    #[test]
    fn dwarf_frame_chains_preserve_live_ancestry_after_malformed_tail() {
        let cases: &[&[TestDwarfDie<'_>]] = &[
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("outer"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("first"),
                    &[test_range(10, 20)],
                ),
                (2, gimli::DW_TAG_inlined_subroutine, Some("dead"), &[]),
                (3, gimli::DW_TAG_inlined_subroutine, Some("dead_child"), &[]),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("last"),
                    &[test_range(30, 40)],
                ),
            ],
            &[
                (1, gimli::DW_TAG_subprogram, Some("outer"), &[]),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("last"),
                    &[test_range(30, 40)],
                ),
            ],
        ];
        for dies in cases {
            let (abbrev, mut info, ranges) = test_dwarf_sections(dies);
            // Interrupt before closing the last inline scope, which is still
            // awaiting range emission when the unknown abbreviation fails.
            let tail = info.len() - 3;
            info[tail] = 127;
            let mut names = PerfDwarfNameInterner::default();
            let index = test_dwarf_frame_index_from_sections(
                &abbrev,
                &info,
                &ranges,
                &[test_range(0, 100)],
                &mut names,
            );
            assert_eq!(
                perf_dwarf_frame_names_from_index(&index, &names.names, 35, None)
                    .unwrap()
                    .frames,
                ["last", "outer"]
            );
            if dies.len() == 5 {
                assert_eq!(
                    perf_dwarf_frame_names_from_index(&index, &names.names, 15, None)
                        .unwrap()
                        .frames,
                    ["first", "outer"]
                );
                assert_eq!(index.nodes.len(), 3);
            } else {
                assert_eq!(index.nodes.len(), 2);
            }
        }
    }

    #[test]
    fn deep_named_dwarf_index_and_drop_are_stack_safe() {
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let depth = 8192;
                let abbrev = [
                    1, 0x11, 1, 0, 0, 2, 0x2e, 1, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0, 0, 3,
                    0x1d, 1, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0, 0, 0,
                ];
                let mut info = vec![0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, 1];
                pyroc50_push_die(&mut info, 2, Some("same"), Some((0x1000, 0x40)));
                for _ in 0..depth {
                    pyroc50_push_die(&mut info, 3, Some("same"), Some((0x1000, 0x40)));
                }
                info.extend(std::iter::repeat_n(0, depth + 2));
                let length = u32::try_from(info.len() - 4).unwrap();
                info[..4].copy_from_slice(&length.to_le_bytes());
                let dwarf = gimli::Dwarf::load(|id| {
                    let bytes = match id {
                        gimli::SectionId::DebugAbbrev => abbrev.as_slice(),
                        gimli::SectionId::DebugInfo => info.as_slice(),
                        _ => &[],
                    };
                    Ok::<_, gimli::Error>(gimli::EndianSlice::new(bytes, gimli::LittleEndian))
                })
                .unwrap();
                let directory = super::PerfDwarfUnitDirectory::new(&dwarf);
                let unit = directory.units[0].unit.as_ref().unwrap();
                let mut names = PerfDwarfNameInterner::default();
                let index = super::perf_dwarf_unit_frame_index(
                    &dwarf,
                    unit,
                    &directory,
                    &mut names,
                    &[test_range(0x1000, 0x1040)],
                );
                assert_eq!(index.nodes.len(), depth + 1);
                assert_eq!(index.segments.len(), 1);
                let frames =
                    perf_dwarf_frame_names_from_index(&index, &names.names, 0x1018, None).unwrap();
                assert_eq!(frames.frames.len(), depth + 1);
                assert!(frames.frames.iter().all(|name| name == "same"));
                drop(frames);
                drop(index);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn flattened_dwarf_ranges_share_the_same_scope_chain() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("outer"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("inner"),
                    &[test_range(10, 20)],
                ),
            ],
            &[],
            &mut names,
        );

        assert_eq!(segments.segments.len(), 3);
        assert_eq!(
            frame_names(&names, &segments, segments.segments[0].frame),
            vec!["outer".to_string()]
        );
        assert_eq!(
            frame_names(&names, &segments, segments.segments[1].frame),
            vec!["outer".to_string(), "inner".to_string()]
        );
        assert_eq!(
            frame_names(&names, &segments, segments.segments[2].frame),
            vec!["outer".to_string()]
        );
        assert_eq!(segments.segments[0].frame, segments.segments[2].frame);
        assert_ne!(segments.segments[0].frame, segments.segments[1].frame);
    }

    #[test]
    fn pyroc50_wrapped_subprogram_interns_names_without_frames_or_coverage() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("outer"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_subprogram,
                    Some("direct_skipped"),
                    &[test_range(10, 20)],
                ),
                (
                    3,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("direct_inline_skipped"),
                    &[test_range(10, 20)],
                ),
                (2, gimli::DW_TAG_lexical_block, None, &[]),
                (
                    3,
                    gimli::DW_TAG_subprogram,
                    Some("wrapped"),
                    &[test_range(20, 30)],
                ),
                (
                    4,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("wrapped_inline"),
                    &[test_range(20, 30)],
                ),
                (
                    4,
                    gimli::DW_TAG_subprogram,
                    Some("wrapped_direct_skipped"),
                    &[test_range(20, 30)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("real_inline"),
                    &[test_range(40, 50)],
                ),
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("second_root"),
                    &[test_range(100, 200)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("root_inline"),
                    &[test_range(110, 120)],
                ),
            ],
            &[],
            &mut names,
        );
        assert_eq!(
            names.names.iter().collect::<Vec<_>>(),
            [
                "outer",
                "wrapped",
                "wrapped_inline",
                "real_inline",
                "second_root",
                "root_inline"
            ]
        );
        assert!(segments.segments.iter().any(|segment| {
            segment.range.begin <= 25
                && 25 < segment.range.end
                && frame_names(&names, &segments, segment.frame) == ["outer"]
        }));
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 25, Some("outer")),
            None
        );
        for (address, expected) in [
            (45, ["real_inline", "outer"]),
            (115, ["root_inline", "second_root"]),
        ] {
            assert_eq!(
                perf_dwarf_frame_names_from_index(&segments, &names.names, address, None)
                    .unwrap()
                    .frames,
                expected,
            );
        }
    }

    #[test]
    fn pyroc50_pruned_last_child_resumes_at_parent_sibling() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("first"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("early"),
                    &[test_range(10, 20)],
                ),
                (
                    2,
                    gimli::DW_TAG_subprogram,
                    Some("skipped"),
                    &[test_range(40, 50)],
                ),
                (
                    3,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("skipped_inline"),
                    &[test_range(40, 50)],
                ),
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("second"),
                    &[test_range(100, 200)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("last"),
                    &[test_range(110, 120)],
                ),
            ],
            &[],
            &mut names,
        );
        assert_eq!(
            names.names.iter().collect::<Vec<_>>(),
            ["first", "early", "second", "last"]
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 115, None)
                .unwrap()
                .frames,
            ["last", "second"],
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 45, Some("first")),
            None
        );
    }

    #[test]
    fn pyroc50_own_coverage_and_postorder_survive_missing_and_external_ranges() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("outer"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    None,
                    &[test_range(20, 40)],
                ),
                (
                    3,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("leaf"),
                    &[test_range(30, 50)],
                ),
                (2, gimli::DW_TAG_inlined_subroutine, Some("range_less"), &[]),
                (
                    3,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("outside"),
                    &[test_range(110, 120)],
                ),
            ],
            &[test_range(0, 5), test_range(42, 46), test_range(115, 118)],
            &mut names,
        );
        for (address, expected) in [
            (45, Some(vec!["leaf", "outer"])),
            (25, None),
            (115, Some(vec!["outside", "range_less", "outer"])),
        ] {
            assert_eq!(
                perf_dwarf_frame_names_from_index(&segments, &names.names, address, None)
                    .map(|frames| frames.frames),
                expected.map(|frames| frames.into_iter().map(str::to_owned).collect()),
            );
        }
        // Descendant coverage is neither clipped to the parent nor promoted
        // into the parent's own coverage when returning to its caller.
        assert!(segments.segments.iter().any(|segment| {
            segment.range.begin <= 45
                && 45 < segment.range.end
                && frame_names(&names, &segments, segment.frame) == ["outer"]
        }));
        for segment in &segments.segments {
            let expected_order = match frame_names(&names, &segments, segment.frame).as_slice() {
                [_, leaf] if leaf == "leaf" => 0,
                [_, _, outside] if outside == "outside" => 2,
                [_] if segment.range.begin >= 20 && segment.range.end <= 30 => 1,
                [_] if segment.range.end <= 20 => 3,
                [_] => 4,
                frames => panic!("unexpected frames: {frames:?}"),
            };
            assert_eq!(segment.order, expected_order);
            assert_eq!(
                segment.has_source_line,
                [test_range(0, 5), test_range(42, 46), test_range(115, 118)]
                    .iter()
                    .any(|line| {
                        line.begin <= segment.range.begin && segment.range.end <= line.end
                    })
            );
        }
    }

    #[test]
    fn flattened_dwarf_lookup_keeps_inline_and_base_symbol_rules() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("outer"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("inner"),
                    &[test_range(10, 20)],
                ),
            ],
            &[],
            &mut names,
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
        let segments = test_dwarf_frame_index(
            &[
                (1, gimli::DW_TAG_subprogram, None, &[test_range(0, 100)]),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("next_remote_task"),
                    &[test_range(10, 20)],
                ),
            ],
            &[],
            &mut names,
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 15, Some("base_symbol")),
            Some(PerfDwarfFrameNames {
                frames: vec!["next_remote_task".to_string(), "base_symbol".to_string()],
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
        let dies = [(
            1,
            gimli::DW_TAG_subprogram,
            Some("next_remote_task"),
            &[test_range(0, 100)][..],
        )];
        let (abbrev, info, ranges) = test_dwarf_sections(&dies);
        let segments =
            test_dwarf_frame_index_from_sections(&abbrev, &info, &ranges, &[], &mut names);

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
    fn flattened_dwarf_lookup_keeps_outer_elf_symbol_when_source_line_exists_like_perf_libdw() {
        // Linux v7.2.9 tools/perf/util/libdw.c:85-96 reuses args->sym for
        // DW_TAG_subprogram instead of manufacturing an inlined outer frame.
        let mut names = PerfDwarfNameInterner::default();
        let segments = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("default_read_to_end<std::fs::File>"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("read"),
                    &[test_range(40, 50)],
                ),
            ],
            &[test_range(0, 100)],
            &mut names,
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(
                &segments,
                &names.names,
                15,
                Some("std::io::default_read_to_end::<std::fs::File>"),
            ),
            None
        );
    }

    #[test]
    fn symbol_parity_single_function_die_with_line_keeps_base_without_children() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = test_dwarf_frame_index(
            &[(
                1,
                gimli::DW_TAG_subprogram,
                Some("f"),
                &[test_range(0, 100)],
            )],
            &[test_range(0, 100)],
            &mut names,
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 15, Some("float")),
            None
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 15, Some("f")),
            None
        );
    }

    #[test]
    fn symbol_parity_inline_line_guard_checks_the_lookup_address() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("f"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("child"),
                    &[test_range(10, 90)],
                ),
            ],
            &[test_range(20, 30), test_range(50, 60)],
            &mut names,
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
                    frames: vec!["child".to_string(), "float".to_string()],
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
        let segments = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("fn0"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("mix"),
                    &[test_range(10, 20)],
                ),
            ],
            &[],
            &mut names,
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 15, Some("fn0"))
                .map(|frames| frames.frames),
            Some(vec!["mix".to_string(), "fn0".to_string()])
        );
    }

    #[test]
    fn flattened_dwarf_lookup_keeps_nonfirst_short_rust_names_like_perf_libdw() {
        // Linux v7.2.9 libdw_a2l_cb() falls back to die_name() without linkage;
        // srcline.c new_inline_sym(); the GNU zero-address sentinel check in
        // tools/perf/util/addr2line.c read_addr2line_record() applies only to
        // the external addr2line child protocol's address/sentinel line, not
        // to libdw DIE names. Real Rust functions named `eq` therefore remain
        // inline frames instead of terminating the chain.
        let mut names = PerfDwarfNameInterner::default();
        let segments = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("fmt"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("eq"),
                    &[test_range(10, 90)],
                ),
                (
                    3,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("eq<anstyle::color::Color>"),
                    &[test_range(20, 80)],
                ),
            ],
            &[],
            &mut names,
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 30, Some("outer_base"))
                .map(|frames| frames.frames),
            Some(vec![
                "eq<anstyle::color::Color>".to_string(),
                "eq".to_string(),
                "outer_base".to_string(),
            ])
        );
    }

    #[test]
    fn flattened_dwarf_lookup_keeps_symtab_base_for_standalone_fn0_like_perf() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = test_dwarf_frame_index(
            &[(
                1,
                gimli::DW_TAG_subprogram,
                Some("fn0"),
                &[test_range(0, 100)],
            )],
            &[],
            &mut names,
        );

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 5, Some("different_base")),
            None
        );
    }

    #[test]
    fn flattened_dwarf_lookup_ignores_unnamed_intermediate_nodes() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("outer"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    None,
                    &[test_range(20, 80)],
                ),
                (
                    3,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("inner"),
                    &[test_range(30, 40)],
                ),
            ],
            &[],
            &mut names,
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
        let segments = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("outer"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("first"),
                    &[test_range(10, 30)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("second"),
                    &[test_range(10, 30)],
                ),
            ],
            &[],
            &mut names,
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
        let segments = test_dwarf_frame_index(
            &[
                (
                    1,
                    gimli::DW_TAG_subprogram,
                    Some("outer"),
                    &[test_range(0, 100)],
                ),
                (
                    2,
                    gimli::DW_TAG_subprogram,
                    Some("nested_subprogram"),
                    &[test_range(10, 90)],
                ),
                (
                    3,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("nested_inline"),
                    &[test_range(20, 30)],
                ),
                (
                    2,
                    gimli::DW_TAG_inlined_subroutine,
                    Some("real_inline"),
                    &[test_range(40, 50)],
                ),
            ],
            &[],
            &mut names,
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
                addr2line_address: None,
                kernel_module_address: None,
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
                addr2line_address: None,
                kernel_module_address: None,
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
            kernel_dso: SymbolDsoName::Mapping,
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
            kernel_dso: SymbolDsoName::Mapping,
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
    fn source_selection_stays_published_while_warm_ips_change() {
        for source in [7, usize::MAX] {
            let mut table = super::UserFrameTable::default();
            for address in 0..64 {
                match address % 3 {
                    0 => table.insert(source, address, usize::try_from(address).unwrap() + 1),
                    1 => table.insert(source, address, 0),
                    _ => {}
                }
            }
            assert_eq!(table.slot(source, 0), Some(1));
            let publications = table.source_hint_publications.get();
            let searches = table.source_searches.get();
            for _ in 0..3 {
                for address in 0..64 {
                    let expected = match address % 3 {
                        0 => Some(usize::try_from(address).unwrap() + 1),
                        1 => Some(0),
                        _ => None,
                    };
                    assert_eq!(table.slot(source, address), expected);
                }
            }
            assert_eq!(table.source_searches.get(), searches);
            assert_eq!(
                table.source_hint_publications.get() - publications,
                0,
                "changing IP results must not republish the unchanged source selection"
            );
        }
    }

    #[test]
    fn source_selection_is_published_once_per_source_switch() {
        let mut table = super::UserFrameTable::default();
        for source in [7, usize::MAX] {
            for address in 0..32 {
                table.insert(source, address, usize::try_from(address).unwrap());
            }
        }
        assert_eq!(table.slot(7, 0), Some(0));
        let publications = table.source_hint_publications.get();
        let searches = table.source_searches.get();
        for source in [usize::MAX, 7, usize::MAX, 7] {
            for address in 0..32 {
                assert_eq!(
                    table.slot(source, address),
                    Some(usize::try_from(address).unwrap())
                );
            }
        }
        assert_eq!(table.source_searches.get() - searches, 4);
        assert_eq!(
            table.source_hint_publications.get() - publications,
            4,
            "only the four actual source switches need source selection publication"
        );
    }

    #[test]
    fn source_hint_publications_include_insertion_replacement_and_unavailability() {
        let mut table = super::UserFrameTable::default();
        table.insert(7, 42, 11);
        assert_eq!(table.source_hint_publications.get(), 1);
        table.insert(7, 42, 12);
        assert_eq!(table.source_hint_publications.get(), 2);
        table.mark_unavailable(7);
        assert_eq!(table.source_hint_publications.get(), 3);
        for address in [0, 42, u64::MAX] {
            assert_eq!(table.slot(7, address), Some(0));
        }
        assert_eq!(table.source_hint_publications.get(), 3);
        table.insert(7, 42, 13);
        assert_eq!(table.source_hint_publications.get(), 4);
        assert_eq!(table.slot(7, 42), Some(13));
        assert_eq!(table.slot(7, 0), None);
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
                    addr2line_address: None,
                    kernel_module_address: None,
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

    fn frame_names(
        names: &PerfDwarfNameInterner,
        index: &super::PerfDwarfFrameIndex,
        frame: std::num::NonZeroUsize,
    ) -> Vec<String> {
        let mut frames = Vec::new();
        let mut frame = Some(frame);
        while let Some(id) = frame {
            let node = &index.nodes[id.get() - 1];
            frames.push(names.names[node.name as usize].to_owned());
            frame = node.parent;
        }
        frames.reverse();
        frames
    }

    fn test_range(begin: u64, end: u64) -> PerfAddressRange {
        PerfAddressRange { begin, end }
    }

    #[test]
    fn closing_dwarf_scope_preserves_child_subtraction_and_source_line_segment_order() {
        // dwarf-aux.c:cu_walk_functions_at follows the containing child chain;
        // libdw.c:libdw__addr2line requires source coverage at the queried PC.
        let mut scopes = vec![super::PerfDwarfScope {
            depth: 1,
            ranges: vec![test_range(0, 100)],
            frame: std::num::NonZeroUsize::new(1),
            frame_checkpoint: 0,
            segment_checkpoint: 0,
            has_inline_frames: true,
            suppressed: false,
            child_coverage: vec![test_range(40, 50), test_range(20, 30)],
        }];
        let mut index = super::PerfDwarfFrameIndex::default();
        index.nodes.push(super::PerfDwarfFrameNode {
            name: 0,
            parent: None,
            kind: super::PerfDwarfDieKind::Inline,
        });
        let lines = [test_range(10, 25), test_range(45, 60), test_range(70, 80)];
        let mut order = 5;
        super::perf_dwarf_finish_scope(&mut scopes, &lines, &mut index, &mut order);
        assert_eq!(
            index
                .segments
                .iter()
                .map(|segment| (segment.range, segment.has_source_line, segment.order))
                .collect::<Vec<_>>(),
            [
                (test_range(0, 10), false, 5),
                (test_range(10, 20), true, 5),
                (test_range(30, 40), false, 6),
                (test_range(60, 70), false, 7),
                (test_range(80, 100), false, 7),
                (test_range(50, 60), true, 7),
                (test_range(70, 80), true, 7),
            ]
        );
        assert!(
            index
                .segments
                .iter()
                .all(|segment| segment.has_inline_frames)
        );
        assert_eq!(index.nodes.len(), 1);
        assert!(scopes.is_empty());
        assert_eq!(order, 8);
    }

    #[test]
    fn dwarf_range_subtraction_preserves_half_open_extreme_and_empty_intervals() {
        // elfutils libdw/dwarf_haspc.c:48-53 uses begin <= pc && pc < end.
        for (ranges, covered, expected) in [
            (vec![], vec![], vec![]),
            (vec![test_range(2, 2)], vec![], vec![]),
            (vec![test_range(8, 2)], vec![], vec![]),
            (
                vec![test_range(0, u64::MAX)],
                vec![test_range(1, u64::MAX - 1)],
                vec![test_range(0, 1), test_range(u64::MAX - 1, u64::MAX)],
            ),
            (
                vec![test_range(5, 10), test_range(10, 15)],
                vec![test_range(0, 5), test_range(15, 20)],
                vec![test_range(5, 15)],
            ),
            (vec![test_range(0, 10)], vec![test_range(0, 20)], vec![]),
        ] {
            assert_eq!(
                super::perf_dwarf_subtract_ranges(&ranges, &covered),
                expected
            );
        }
    }

    proptest::proptest! {
        #[test]
        fn dwarf_range_merge_preserves_half_open_union_and_is_idempotent(
            ranges in proptest::collection::vec((0_u64..64, 0_u64..64), 0..32),
        ) {
            let ranges = ranges.into_iter()
                .map(|(a, b)| test_range(a.min(b), a.max(b)))
                .collect::<Vec<_>>();
            let actual = super::perf_dwarf_merge_ranges(ranges.clone());
            proptest::prop_assert!(actual.windows(2).all(|pair| pair[0].end < pair[1].begin));
            for address in 0..64 {
                let contains = |ranges: &[PerfAddressRange]| {
                    ranges.iter().any(|range| range.begin <= address && address < range.end)
                };
                proptest::prop_assert_eq!(contains(&actual), contains(&ranges));
            }
            proptest::prop_assert_eq!(super::perf_dwarf_merge_ranges(actual.clone()), actual);
        }

        #[test]
        fn dwarf_range_subtraction_matches_half_open_set_difference(
            ranges in proptest::collection::vec((0_u64..64, 0_u64..64), 0..12),
            covered in proptest::collection::vec((0_u64..64, 0_u64..64), 0..12),
        ) {
            let normalize = |ranges: Vec<(u64, u64)>| {
                ranges.into_iter().map(|(a, b)| test_range(a.min(b), a.max(b)))
                    .collect::<Vec<_>>()
            };
            let ranges = normalize(ranges);
            let covered = normalize(covered);
            let actual = super::perf_dwarf_subtract_ranges(&ranges, &covered);
            proptest::prop_assert!(actual.iter().all(|range| range.begin < range.end));
            proptest::prop_assert!(actual.windows(2).all(|pair| pair[0].end <= pair[1].begin));
            for address in 0..64 {
                let contains = |ranges: &[PerfAddressRange]| {
                    ranges.iter().any(|range| range.begin <= address && address < range.end)
                };
                proptest::prop_assert_eq!(contains(&actual), contains(&ranges) && !contains(&covered));
            }
        }
    }

    fn test_request(path: &str, relative_address: u64) -> SymbolRequest {
        SymbolRequest {
            addr2line_address: None,
            kernel_module_address: None,
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
        let mut builder = build::elf::Builder::new(object::Endianness::Little, true);
        builder.header.e_type = elf::ET_DYN;
        builder.header.e_machine = elf::EM_X86_64;
        let mut bytes = Vec::new();
        builder.write(&mut bytes).unwrap();
        std::fs::write(file.path(), bytes).unwrap();
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
                    kernel_dso: SymbolDsoName::Mapping,
                    ..ResolvedSymbolFrames::default()
                };
                requests.len()
            ])
        }
    }

    #[test]
    fn module_first_object_failure_stays_unknown_after_core_load_at_other_addresses() {
        // perf symbol.c:dso__load (1866) marks failed module sources loaded;
        // maps__split_kallsyms (913) then discards their module rows, not just
        // the first queried address. Core-first loading is a separate case.
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
            cache
                .resolve_cached_mapping(
                    &test_mapping_ref("[kernel.kallsyms]", 0xffff_ffff_8100_0010),
                    inline,
                )
                .unwrap();
            assert!(
                cache
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
                        kernel_dso: SymbolDsoName::Mapping,
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
            kernel_module_address: None,
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
