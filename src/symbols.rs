use std::borrow::Cow;
use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write;
use std::hash::{Hash, Hasher};
use std::io::{Read, Seek, SeekFrom, Write as IoWrite};
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResolvedSymbolFrames {
    pub frames: Vec<String>,
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

struct CachedMappingFrames {
    frames: Vec<String>,
    has_base_symbol: bool,
    has_inline_frames: bool,
    has_non_inline_base_frame: bool,
    base_offset: Option<u64>,
}

#[derive(Default)]
struct UserFrameTable {
    by_source: FxHashMap<usize, usize>,
    sources: Vec<FxHashMap<u64, usize>>,
    last_source: Cell<Option<(usize, usize)>>,
    #[cfg(test)]
    source_searches: Cell<usize>,
}

impl UserFrameTable {
    fn slot(&self, source: usize, address: u64) -> Option<usize> {
        let index = if let Some((cached_source, index)) = self.last_source.get()
            && cached_source == source
        {
            index
        } else {
            #[cfg(test)]
            self.source_searches.set(self.source_searches.get() + 1);
            let index = *self.by_source.get(&source)?;
            self.last_source.set(Some((source, index)));
            index
        };
        self.sources[index].get(&address).copied()
    }

    fn insert(&mut self, source: usize, address: u64, slot: usize) {
        let index = *self.by_source.entry(source).or_insert_with(|| {
            let index = self.sources.len();
            self.sources.push(FxHashMap::default());
            index
        });
        self.last_source.set(Some((source, index)));
        self.sources[index].insert(address, slot);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.sources.iter().map(FxHashMap::len).sum()
    }
}

static UNRESOLVED_MAPPING_FRAMES: CachedMappingFrames = CachedMappingFrames {
    frames: Vec::new(),
    has_base_symbol: false,
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
}

impl MappingFrameTable {
    fn user_slot(&self, symbol_source_id: usize, relative_address: u64) -> Option<usize> {
        self.user.slot(symbol_source_id, relative_address)
    }

    fn slot(&self, key: &MappingFrameKey) -> Option<usize> {
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

    fn at_slot(&self, slot: usize) -> &CachedMappingFrames {
        // Zero represents a resolved negative result, not a cache miss.
        if slot == 0 {
            &UNRESOLVED_MAPPING_FRAMES
        } else {
            &self.frames[slot - 1]
        }
    }

    fn get_frame(&self, mapping: &MappedFrame<'_>) -> Option<&CachedMappingFrames> {
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

    fn insert(&mut self, key: MappingFrameKey, frames: CachedMappingFrames) {
        if let Some(slot) = self.slot(&key) {
            if slot != 0 {
                self.frames[slot - 1] = frames;
                return;
            }
            if frames.is_fully_unresolved() {
                return;
            }
        }
        let slot = if frames.is_fully_unresolved() {
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
    has_inline_children: bool,
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
    kallsyms: Option<Kallsyms>,
    live_kallsyms: Option<Kallsyms>,
    live_kallsyms_path: Option<PathBuf>,
    live_kallsyms_cache: OnceLock<Option<Kallsyms>>,
    live_module_kallsyms_text_cache: OnceLock<Option<Arc<String>>>,
    live_module_kallsyms_cache: Mutex<FxHashMap<String, Option<Arc<Kallsyms>>>>,
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Kallsyms {
    symbols: BTreeMap<u64, KallsymsSymbol>,
    addresses_by_name: BTreeMap<String, u64>,
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

    fn module(name: String, _symbol_type: char, module: String) -> Self {
        Self {
            name,
            end: None,
            module: Some(module),
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
            kallsyms: None,
            live_kallsyms: None,
            live_kallsyms_path: None,
            live_kallsyms_cache: OnceLock::new(),
            live_module_kallsyms_text_cache: OnceLock::new(),
            live_module_kallsyms_cache: Mutex::new(FxHashMap::default()),
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
    pub fn with_perfdata_file_kernel_cache(self, perfdata: &Path, debug_dir: &Path) -> Self {
        match kernel_build_id_from_perfdata_file(perfdata) {
            Ok(Some(build_id)) => self.with_perfdata_kernel_build_id(&build_id, debug_dir),
            Ok(None) | Err(_) => self,
        }
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
        match &self.recorded_kernel_build_id {
            Some(recorded) => self
                .live_kernel_build_id()
                .is_some_and(|live| live == recorded),
            None => false,
        }
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
                &mut addresses_by_name,
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
        })
    }

    /// Parses only module-backed `/proc/kallsyms` lines.
    ///
    /// # Errors
    ///
    /// Returns an error when no valid module symbols are present.
    pub fn parse_modules(text: &str) -> Result<Self, String> {
        let mut symbols = BTreeMap::new();
        let mut addresses_by_name = BTreeMap::new();
        for (address, symbol, symbol_type, module) in text
            .lines()
            .filter_map(parse_module_kallsyms_line)
            .filter(|(address, _, _, _)| *address != 0)
        {
            insert_kallsyms_symbol(
                &mut symbols,
                &mut addresses_by_name,
                address,
                KallsymsSymbol::module(symbol, symbol_type, module),
            );
        }
        if symbols.is_empty() {
            return Err("kallsyms did not contain any parseable module symbols".to_string());
        }
        fixup_kallsyms_symbol_ends_like_perf(&mut symbols);
        Ok(Self {
            symbols,
            addresses_by_name,
        })
    }

    /// Parses only `/proc/kallsyms` lines for a specific module path like `[zfs]`.
    ///
    /// # Errors
    ///
    /// Returns an error when no valid module symbols are present for that module.
    pub fn parse_modules_for_path(text: &str, module_path: &str) -> Result<Self, String> {
        let mut symbols = BTreeMap::new();
        let mut addresses_by_name = BTreeMap::new();
        for (address, symbol, symbol_type, module) in text
            .lines()
            .filter_map(parse_module_kallsyms_line)
            .filter(|(address, _, _, _)| *address != 0)
        {
            insert_kallsyms_symbol(
                &mut symbols,
                &mut addresses_by_name,
                address,
                KallsymsSymbol::module(symbol, symbol_type, module),
            );
        }
        if symbols.is_empty() {
            return Err(format!(
                "kallsyms did not contain any parseable module symbols for {module_path}"
            ));
        }
        // perf runs symbols__fixup_end() on the full kallsyms tree before
        // maps__split_kallsyms() moves symbols into per-module DSOs, so symbols
        // can be capped by the next global kallsyms entry from another module.
        fixup_kallsyms_symbol_ends_like_perf(&mut symbols);
        symbols.retain(|_, symbol| symbol.module.as_deref() == Some(module_path));
        if symbols.is_empty() {
            return Err(format!(
                "kallsyms did not contain any parseable module symbols for {module_path}"
            ));
        }
        addresses_by_name.clear();
        for (address, symbol) in &symbols {
            addresses_by_name
                .entry(symbol.name.clone())
                .or_insert(*address);
        }
        Ok(Self {
            symbols,
            addresses_by_name,
        })
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
        self.symbols
            .range(..=address)
            .next_back()
            .and_then(|(start, symbol)| {
                let mut end = symbol.end?;
                if let Some((range_start, range_end)) = range {
                    if *start < range_start || range_end <= address {
                        return None;
                    }
                    end = end.min(range_end);
                }
                // perf's map__find_symbol() calls symbols__find(), which
                // requires start <= ip < end. kallsyms keeps T/W/D/B symbols
                // before maps__split_kallsyms(), so data/BSS module symbols
                // are valid anchors too.
                (address < end).then(|| format!("{}+0x{:x}", symbol.name, address - start))
            })
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

    pub(crate) fn cached_mapping_frames(
        &self,
        mapping: &MappedFrame<'_>,
        inline: bool,
    ) -> Option<(&[String], bool)> {
        let table = if inline {
            &self.resolved_by_mapping
        } else {
            &self.resolved_base_by_mapping
        };
        table
            .get_frame(mapping)
            .map(|cached| (cached.frames.as_slice(), cached.has_base_symbol))
    }

    fn prefetch_mapping_refs_with_mode(
        &mut self,
        mappings: &[ResolvedMappingRef<'_>],
        inline: bool,
    ) -> Result<(), String> {
        let mut seen = std::mem::take(&mut self.scratch_seen_mapping);
        let mut keys = std::mem::take(&mut self.scratch_missing_keys);
        let mut requests = std::mem::take(&mut self.scratch_missing_requests);
        seen.clear();
        keys.clear();
        let result = (|| {
            for mapping in mappings {
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
            let table = if inline {
                &mut self.resolved_by_mapping
            } else {
                &mut self.resolved_base_by_mapping
            };
            for (key, frames) in keys.drain(..).zip(resolved) {
                table.insert(
                    key,
                    CachedMappingFrames {
                        frames: frames.frames,
                        has_base_symbol: frames.has_base_symbol,
                        has_inline_frames: frames.has_inline_frames,
                        has_non_inline_base_frame: frames.has_non_inline_base_frame,
                        base_offset: frames.base_offset,
                    },
                );
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
                } else if let Some(kernel_elf) = &self.kernel_elf {
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
        let mut resolved = vec![ResolvedSymbolFrames::default(); requests.len()];
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
                } else if let Some(symbol) = self.resolve_kernel_symbol(request) {
                    resolved[index] = ResolvedSymbolFrames::from_frames(vec![symbol]);
                }
            } else if is_kernel_symbol_path(&request.path) {
                if let Some(symbol) = self.resolve_kernel_symbol(request) {
                    resolved[index] = ResolvedSymbolFrames::from_frames(vec![symbol]);
                } else if let Some(kernel_elf) = &self.kernel_elf {
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
            let kernel_frames = self
                .object_resolver
                .resolve_frame_batch_with_metadata(&kernel_elf_requests)?;
            for (index, frames) in kernel_elf_indexes.into_iter().zip(kernel_frames) {
                resolved[index] = frames;
            }
        }

        if !user_requests.is_empty() {
            let user_frames = self
                .object_resolver
                .resolve_frame_batch_with_metadata(&user_requests)?;
            for (index, frames) in user_indexes.into_iter().zip(user_frames) {
                resolved[index] = if frames.frames.is_empty()
                    && is_kernel_module_symbol_path(&requests[index].path)
                {
                    self.resolve_kernel_symbol(&requests[index])
                        .map(|symbol| ResolvedSymbolFrames::from_frames(vec![symbol]))
                        .unwrap_or(frames)
                } else {
                    frames
                };
            }
        }
        Ok(resolved)
    }

    fn resolve_base_frame_batch_with_metadata(
        &self,
        requests: &[SymbolRequest],
    ) -> Result<Vec<ResolvedSymbolFrames>, String> {
        let mut resolved = vec![ResolvedSymbolFrames::default(); requests.len()];
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
                } else if let Some(symbol) = self.resolve_kernel_symbol(request) {
                    resolved[index] = ResolvedSymbolFrames::from_frames(vec![symbol]);
                }
            } else if is_kernel_symbol_path(&request.path) {
                if let Some(symbol) = self.resolve_kernel_symbol(request) {
                    resolved[index] = ResolvedSymbolFrames::from_frames(vec![symbol]);
                } else if let Some(kernel_elf) = &self.kernel_elf {
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
            let kernel_frames = self
                .object_resolver
                .resolve_base_frame_batch_with_metadata(&kernel_elf_requests)?;
            for (index, frames) in kernel_elf_indexes.into_iter().zip(kernel_frames) {
                resolved[index] = frames;
            }
        }

        if !user_requests.is_empty() {
            let user_frames = self
                .object_resolver
                .resolve_base_frame_batch_with_metadata(&user_requests)?;
            for (index, frames) in user_indexes.into_iter().zip(user_frames) {
                resolved[index] = if frames.frames.is_empty()
                    && is_kernel_module_symbol_path(&requests[index].path)
                {
                    self.resolve_kernel_symbol(&requests[index])
                        .map(|symbol| ResolvedSymbolFrames::from_frames(vec![symbol]))
                        .unwrap_or(frames)
                } else {
                    frames
                };
            }
        }
        Ok(resolved)
    }
}

impl<O> PerfSymbolResolver<O>
where
    O: SymbolResolver,
{
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
        if !is_perf_vdso_dso_path(&request.path) {
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
        if let Some(cached) = self
            .live_module_kallsyms_cache
            .lock()
            .expect("live module kallsyms cache lock")
            .get(module_path)
            .cloned()
        {
            return cached;
        }

        let text = self
            .live_module_kallsyms_text_cache
            .get_or_init(|| {
                self.live_kallsyms_path
                    .as_ref()
                    .and_then(|path| std::fs::read_to_string(path).ok())
                    .map(Arc::new)
            })
            .clone();
        let parsed = text.and_then(|text| {
            Kallsyms::parse_modules_for_path(text.as_ref(), module_path)
                .ok()
                .map(Arc::new)
        });
        self.live_module_kallsyms_cache
            .lock()
            .expect("live module kallsyms cache lock")
            .insert(module_path.to_string(), parsed.clone());
        parsed
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
            self.kallsyms
                .as_ref()
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
            self.kallsyms
                .as_ref()
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
        self.recorded_kernel_build_id.is_none()
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
            if let Some(metadata) = object_metadata.as_ref() {
                let addresses = indexes
                    .iter()
                    .map(|&i| requests[i].relative_address)
                    .collect::<Vec<_>>();
                metadata.prepare_dwarf_frames_for_addresses(&addresses);
            }
            for index in indexes {
                let request = &requests[index];
                let object_symbols =
                    object_symbols_for_frame(object_metadata.as_ref(), request.relative_address);
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
            if let Some(metadata) = object_metadata.as_ref() {
                let addresses: Vec<_> = indexes
                    .iter()
                    .map(|&i| requests[i].relative_address)
                    .collect();
                metadata.prepare_dwarf_frames_for_addresses(&addresses);
            }
            for index in indexes {
                let request = &requests[index];
                let address = request.relative_address;
                let object_symbols = object_symbols_for_frame(object_metadata.as_ref(), address);
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

fn resolve_base_frames_from_object_metadata(
    requests: &[SymbolRequest],
    object_metadata: impl Fn(&Path) -> Option<Arc<CachedObjectMetadata>>,
) -> Vec<ResolvedSymbolFrames> {
    let mut resolved = vec![ResolvedSymbolFrames::default(); requests.len()];
    for (path, indexes) in grouped_request_indexes(requests) {
        let path = Path::new(path);
        let metadata = object_metadata(path);
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
    // tools/perf/util/symbol.c choose_best_symbol(): size, non-weak, global,
    // fewer leading underscores, then longest name.
    if current.size == 0 && candidate.size > 0 {
        return candidate;
    }
    if candidate.size == 0 && current.size > 0 {
        return current;
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
        PerfObjectSymbolNames {
            bare: self.object_symbol(address),
            offset: self.object_symbols.symbol_offset(address),
        }
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

    fn symbol_offset(&self, address: u64) -> Option<u64> {
        let candidate = self.symbol(address)?;
        Some(address.saturating_sub(candidate.address))
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
            let candidate = &self.symbols[index];
            if !perf_symbol_candidate_contains_address(candidate, address) {
                continue;
            }
            best = Some(match best {
                Some(current) if current.address > candidate.address => current,
                Some(current) if current.address == candidate.address => {
                    // perf inserts equal-start symbols to the right side of the
                    // rb-tree and symbols__fixup_duplicate() walks in-order, so
                    // the earlier inserted symbol is syma. This reverse scan
                    // sees the later symbol first; pass the earlier candidate as
                    // the first argument to preserve perf's final arch fallback.
                    perf_best_duplicate_symbol(candidate, current)
                }
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
    if candidate.size == 0 {
        1
    } else {
        candidate.size
    }
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

fn perf_dwarf_ranges_overlap(ranges: &[PerfAddressRange], range: &PerfAddressRange) -> bool {
    ranges
        .iter()
        .any(|other| other.begin < range.end && range.begin < other.end)
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
    let has_inline_children = node
        .children
        .iter()
        .any(|child| child.kind == PerfDwarfDieKind::Inline);
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
            out.push(PerfDwarfFrameRange {
                range,
                frames: frames.clone(),
                has_inline_frames,
                has_source_line: perf_dwarf_ranges_overlap(source_line_ranges, &range),
                has_inline_children,
                order,
            });
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
            && segment.has_inline_children
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
    kallsyms
        .resolve_module_with_offset_in_range(request.relative_address, request.kernel_mapping_range)
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
    addresses_by_name: &mut BTreeMap<String, u64>,
    address: u64,
    symbol: KallsymsSymbol,
) {
    match symbols.entry(address) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(symbol.clone());
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            // tools/perf/util/symbol.c __symbols__insert() inserts equal-start
            // symbols to the rb-tree's right side. After symbols__fixup_end(),
            // the last symbol at an address is the one with nonzero length to
            // the next address, so symbols__fixup_duplicate() keeps it.
            entry.insert(symbol.clone());
        }
    }
    addresses_by_name.entry(symbol.name).or_insert(address);
}

fn fixup_kallsyms_symbol_ends_like_perf(symbols: &mut BTreeMap<u64, KallsymsSymbol>) {
    let addresses = symbols.keys().copied().collect::<Vec<_>>();
    for pair in addresses.windows(2) {
        let [prev_addr, curr_addr] = pair else {
            continue;
        };
        let curr_module = symbols
            .get(curr_addr)
            .and_then(|symbol| symbol.module.clone());
        let Some(prev) = symbols.get_mut(prev_addr) else {
            continue;
        };
        if prev.end.is_some() {
            continue;
        }
        prev.end = if prev.module == curr_module {
            Some(*curr_addr)
        } else {
            Some(round_up_to_page(prev_addr.saturating_add(4096)))
        };
    }
    if let Some((addr, symbol)) = symbols.iter_mut().next_back()
        && symbol.end.is_none()
    {
        symbol.end = Some(round_up_to_page(addr.saturating_add(4096)));
    }
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

fn parse_module_kallsyms_line(line: &str) -> Option<(u64, String, char, String)> {
    let mut fields = line.split_whitespace();
    let address = u64::from_str_radix(fields.next()?, 16).ok()?;
    let symbol_type = fields.next()?.chars().next()?;
    if !perf_kallsyms_type_is_kept(symbol_type) {
        return None;
    }
    let symbol = fields.next()?;
    let module = fields.next()?;
    (module.starts_with('[') && module.ends_with(']'))
        .then(|| (address, symbol.to_string(), symbol_type, module.to_string()))
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

    #[test]
    fn object_symbol_index_keeps_earlier_overlapping_symbol_candidates() {
        let symbols = PerfObjectSymbolIndex {
            symbols: vec![
                PerfSymbolCandidate {
                    name: "large".to_string(),
                    address: 0x1000,
                    size: 0x1000,
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
    }

    #[test]
    fn object_symbol_index_preserves_perf_duplicate_order_for_versioned_glibc_aliases() {
        let candidate = |name: &str, address| PerfSymbolCandidate {
            name: name.to_string(),
            address,
            size: 0x100,
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
        assert_eq!(results[0], ResolvedSymbolFrames::default());
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
        super::CachedMappingFrames {
            frames: vec![label],
            has_base_symbol: true,
            has_inline_frames: false,
            has_non_inline_base_frame: true,
            base_offset: Some(offset),
        }
    }

    fn empty_cached_table_frames() -> super::CachedMappingFrames {
        super::CachedMappingFrames {
            frames: Vec::new(),
            has_base_symbol: false,
            has_inline_frames: false,
            has_non_inline_base_frame: false,
            base_offset: None,
        }
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

    fn test_mapping_ref(path: &'static str, relative_address: u64) -> ResolvedMappingRef<'static> {
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
