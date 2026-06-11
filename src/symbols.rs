use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use clap::ValueEnum;
use hashbrown::{HashMap, HashSet};
use object::{
    Object, ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable, SymbolIndex, SymbolKind,
};
use rustc_hash::FxBuildHasher;
use serde::Serialize;

use crate::folded::{render_inferno_perf_folded_label, render_inferno_perf_raw_stack};
use crate::perfdata::build_id::{
    kernel_build_id_from_perfdata, kernel_build_id_from_perfdata_file,
};
use crate::perfdata::mappings::{FileIdentity, ResolvedMappingRef};
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
    pub build_id: Option<String>,
    pub file_identity: Option<FileIdentity>,
    pub kernel_relocation: Option<KernelRelocation>,
}

impl PartialEq for SymbolRequest {
    fn eq(&self, other: &Self) -> bool {
        self.relative_address == other.relative_address
            && self.build_id == other.build_id
            && self.file_identity == other.file_identity
            && self.kernel_relocation == other.kernel_relocation
            && self.path.as_os_str() == other.path.as_os_str()
    }
}

impl Eq for SymbolRequest {}

impl Hash for SymbolRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.as_os_str().hash(state);
        self.relative_address.hash(state);
        self.build_id.hash(state);
        self.file_identity.hash(state);
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
            .then_with(|| self.build_id.cmp(&other.build_id))
            .then_with(|| self.file_identity.cmp(&other.file_identity))
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
    /// The `+0x<off>` suffix (relative to the containing symtab symbol) that
    /// perf prints on every inline AND base frame for this address.
    /// `tools/perf/util/symbol_fprintf.c __symbol__fprintf_symname_offs` uses
    /// `al->addr - sym->start`, and an inline frame's fake symbol reuses
    /// `base_sym->start` (`tools/perf/util/srcline.c new_inline_sym`), so the
    /// whole group shares one offset.
    pub base_offset: Option<String>,
}

impl ResolvedSymbolFrames {
    #[must_use]
    pub fn from_frames(frames: Vec<String>) -> Self {
        let has_base_symbol = !frames.is_empty();
        Self {
            frames,
            has_base_symbol,
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
    resolved_by_mapping: FxHashMap<MappingFrameKey, CachedMappingFrames>,
    resolved_base_by_mapping: FxHashMap<MappingFrameKey, CachedMappingFrames>,
    scratch_seen_mapping: FxHashSet<MappingFrameKey>,
    scratch_missing_keys: Vec<MappingFrameKey>,
    scratch_missing_requests: Vec<SymbolRequest>,
    scratch_missing_fallbacks: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MappingFrameKey {
    symbol_source_id: usize,
    relative_address: u64,
}

struct CachedMappingFrames {
    frames: Vec<String>,
    folded_rendered: String,
    has_base_symbol: bool,
    base_offset: Option<String>,
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
    base_symbol_sensitive: bool,
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
    debug_names: DebugStringNameIndex,
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
    segments: Option<Vec<PerfDwarfFrameRange>>,
}

#[derive(Default)]
struct PerfObjectSymbolNames<'a> {
    bare: Option<&'a str>,
    with_offset: Option<String>,
    /// Just the `+0x<off>` suffix of `with_offset`, shared by every inline and
    /// base frame at this address in perf-script output.
    offset_suffix: Option<String>,
}

#[derive(Default)]
struct PerfObjectSymbolIndex {
    symbols: Vec<PerfSymbolCandidate>,
    max_end_by_index: Vec<u64>,
}

pub struct PerfSymbolResolver<O> {
    object_resolver: O,
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
    /// `/sys/kernel/notes` (or a test override) — the live kernel's GNU
    /// build-id note. Used to confirm the running kernel matches the build-id
    /// recorded in the perf.data before trusting live `/proc/kallsyms` for
    /// `[kernel.kallsyms]` frames.
    live_kernel_notes_path: Option<PathBuf>,
    live_kernel_build_id_cache: OnceLock<Option<String>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Kallsyms {
    symbols: BTreeMap<u64, String>,
    addresses_by_name: BTreeMap<String, u64>,
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
        let path_key = path.as_os_str().to_owned();
        if let Some(cached) = cache
            .lock()
            .expect("rust addr2line metadata cache lock")
            .get(&path_key)
            .cloned()
        {
            return cached;
        }

        let loaded = std::fs::read(path).ok().map(|bytes| {
            Arc::new(CachedObjectMetadata {
                object_metadata: PreparedObjectMetadata::from_object_bytes(&bytes),
                object_bytes: bytes.into(),
                dwarf_index: Mutex::new(PerfDwarfIndexCache::default()),
            })
        });

        let mut cache = cache.lock().expect("rust addr2line metadata cache lock");
        cache
            .entry(path_key)
            .or_insert_with(|| loaded.clone())
            .clone()
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
        let path_key = path.as_os_str().to_owned();
        if let Some(cached) = cache
            .lock()
            .expect("addr2line metadata cache lock")
            .get(&path_key)
            .cloned()
        {
            return cached;
        }

        let loaded = std::fs::read(path).ok().map(|bytes| {
            Arc::new(CachedObjectMetadata {
                object_metadata: PreparedObjectMetadata::from_object_bytes(&bytes),
                object_bytes: bytes.into(),
                dwarf_index: Mutex::new(PerfDwarfIndexCache::default()),
            })
        });

        let mut cache = cache.lock().expect("addr2line metadata cache lock");
        cache
            .entry(path_key)
            .or_insert_with(|| loaded.clone())
            .clone()
    }

    fn resolve_group_symbols(
        &self,
        path: &Path,
        grouped_requests: &[SymbolRequest],
    ) -> Result<Vec<Option<String>>, String> {
        let output = self
            .runner
            .run(&build_addr2line_command(path, grouped_requests))
            .map_err(|error| format!("failed to run addr2line: {error}"))?;
        if output.status_code == Some(0) {
            parse_addr2line_stdout(&output.stdout, grouped_requests.len())
        } else {
            Ok(vec![None; grouped_requests.len()])
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
            insert_kallsyms_symbol(&mut symbols, &mut addresses_by_name, address, symbol);
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
        for (address, symbol) in text
            .lines()
            .filter_map(|line| {
                parse_module_kallsyms_line(line).map(|(address, symbol, _)| (address, symbol))
            })
            .filter(|(address, _)| *address != 0)
        {
            insert_kallsyms_symbol(&mut symbols, &mut addresses_by_name, address, symbol);
        }
        if symbols.is_empty() {
            return Err("kallsyms did not contain any parseable module symbols".to_string());
        }
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
        for (address, symbol) in text
            .lines()
            .filter_map(parse_module_kallsyms_line)
            .filter(|(_, _, module)| *module == module_path)
            .map(|(address, symbol, _)| (address, symbol))
            .filter(|(address, _)| *address != 0)
        {
            insert_kallsyms_symbol(&mut symbols, &mut addresses_by_name, address, symbol);
        }
        if symbols.is_empty() {
            return Err(format!(
                "kallsyms did not contain any parseable module symbols for {module_path}"
            ));
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
            .map(|(_, symbol)| symbol.clone())
    }

    /// Resolves an address to `name+0x<off>`, matching perf-script kernel
    /// frames (`tools/perf/util/symbol_fprintf.c __symbol__fprintf_symname_offs`
    /// prints the offset from the containing symbol, including `+0x0`).
    #[must_use]
    pub fn resolve_with_offset(&self, address: u64) -> Option<String> {
        self.symbols
            .range(..=address)
            .next_back()
            .map(|(start, symbol)| format!("{symbol}+0x{:x}", address - start))
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
            resolved_by_mapping: FxHashMap::default(),
            resolved_base_by_mapping: FxHashMap::default(),
            scratch_seen_mapping: FxHashSet::default(),
            scratch_missing_keys: Vec::new(),
            scratch_missing_requests: Vec::new(),
            scratch_missing_fallbacks: Vec::new(),
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
        let key = mapping_frame_key(mapping);
        if !self.resolved_by_mapping.contains_key(&key) {
            self.prefetch_mapping_refs(std::slice::from_ref(mapping))?;
        }
        self.resolved_by_mapping
            .get(&key)
            .map(|cached| cached.frames.as_slice())
            .ok_or_else(|| "symbol frame cache lookup missed after resolution".to_string())
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
    ) -> Result<(&[String], Option<&str>), String> {
        let key = mapping_frame_key(mapping);
        if !self.resolved_by_mapping.contains_key(&key) {
            self.prefetch_mapping_refs(std::slice::from_ref(mapping))?;
        }
        self.resolved_by_mapping
            .get(&key)
            .map(|cached| (cached.frames.as_slice(), cached.base_offset.as_deref()))
            .ok_or_else(|| "symbol frame cache lookup missed after resolution".to_string())
    }

    /// Resolves one borrowed perfdata mapping through the cache and returns the
    /// pre-rendered folded fragment for its symbolized inline frames.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails.
    pub fn resolve_folded_mapping_ref(
        &mut self,
        mapping: &ResolvedMappingRef<'_>,
    ) -> Result<Option<&str>, String> {
        let key = mapping_frame_key(mapping);
        if !self.resolved_by_mapping.contains_key(&key) {
            self.prefetch_mapping_refs(std::slice::from_ref(mapping))?;
        }
        self.resolved_by_mapping
            .get(&key)
            .map(|cached| {
                (!cached.folded_rendered.is_empty()).then_some(cached.folded_rendered.as_str())
            })
            .ok_or_else(|| "symbol frame cache lookup missed after resolution".to_string())
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
        let key = mapping_frame_key(mapping);
        if !self.resolved_base_by_mapping.contains_key(&key) {
            self.prefetch_base_mapping_refs(std::slice::from_ref(mapping))?;
        }
        self.resolved_base_by_mapping
            .get(&key)
            .map(|cached| cached.has_base_symbol.then_some(cached.frames.as_slice()))
            .ok_or_else(|| "symbol frame cache lookup missed after resolution".to_string())
    }

    /// Resolves one borrowed perfdata mapping to the pre-rendered folded
    /// fragment for its single base object symbol (no DWARF inline expansion).
    ///
    /// This is the default `perf script`/folded path: plain `perf` prints one
    /// frame per callchain entry named from the ELF symtab.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails.
    pub fn resolve_base_folded_mapping_ref(
        &mut self,
        mapping: &ResolvedMappingRef<'_>,
    ) -> Result<Option<&str>, String> {
        let key = mapping_frame_key(mapping);
        if !self.resolved_base_by_mapping.contains_key(&key) {
            self.prefetch_base_mapping_refs(std::slice::from_ref(mapping))?;
        }
        self.resolved_base_by_mapping
            .get(&key)
            .map(|cached| {
                (!cached.folded_rendered.is_empty()).then_some(cached.folded_rendered.as_str())
            })
            .ok_or_else(|| "symbol frame cache lookup missed after resolution".to_string())
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
        let mut seen = std::mem::take(&mut self.scratch_seen_mapping);
        let mut missing_keys = std::mem::take(&mut self.scratch_missing_keys);
        let mut missing_requests = std::mem::take(&mut self.scratch_missing_requests);
        let mut missing_fallbacks = std::mem::take(&mut self.scratch_missing_fallbacks);
        seen.clear();
        missing_keys.clear();
        missing_requests.clear();
        missing_fallbacks.clear();

        let result = (|| {
            seen.reserve(mappings.len());
            missing_keys.reserve(mappings.len());
            missing_requests.reserve(mappings.len());
            missing_fallbacks.reserve(mappings.len());
            for mapping in mappings {
                let key = mapping_frame_key(mapping);
                if self.resolved_base_by_mapping.contains_key(&key) || !seen.insert(key) {
                    continue;
                }
                missing_keys.push(key);
                missing_requests.push(symbol_request_from_mapping_ref(mapping));
                let fallback_frame = mapping_fallback_frame(mapping);
                missing_fallbacks.push(render_inferno_perf_folded_label(fallback_frame.as_str()));
            }
            if missing_requests.is_empty() {
                return Ok(());
            }
            let resolved = self
                .resolver
                .resolve_base_frame_batch_with_metadata(&missing_requests)?;
            if resolved.len() != missing_requests.len() {
                return Err(format!(
                    "symbol resolver returned {} base frame results for {} requests",
                    resolved.len(),
                    missing_requests.len()
                ));
            }
            self.resolved_base_by_mapping.reserve(missing_keys.len());
            for ((key, fallback_rendered), resolved_frames) in missing_keys
                .drain(..)
                .zip(missing_fallbacks.drain(..))
                .zip(resolved)
            {
                let folded_rendered = if resolved_frames.frames.is_empty() {
                    fallback_rendered
                } else {
                    render_inferno_perf_raw_stack(resolved_frames.frames.iter().map(String::as_str))
                };
                self.resolved_base_by_mapping.insert(
                    key,
                    CachedMappingFrames {
                        frames: resolved_frames.frames,
                        folded_rendered,
                        has_base_symbol: resolved_frames.has_base_symbol,
                        base_offset: resolved_frames.base_offset,
                    },
                );
            }
            Ok(())
        })();

        self.scratch_seen_mapping = seen;
        self.scratch_missing_keys = missing_keys;
        self.scratch_missing_requests = missing_requests;
        self.scratch_missing_fallbacks = missing_fallbacks;
        result
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
        let mut seen = std::mem::take(&mut self.scratch_seen_mapping);
        let mut missing_keys = std::mem::take(&mut self.scratch_missing_keys);
        let mut missing_requests = std::mem::take(&mut self.scratch_missing_requests);
        let mut missing_fallbacks = std::mem::take(&mut self.scratch_missing_fallbacks);
        seen.clear();
        missing_keys.clear();
        missing_requests.clear();
        missing_fallbacks.clear();

        let result = (|| {
            seen.reserve(mappings.len());
            missing_keys.reserve(mappings.len());
            missing_requests.reserve(mappings.len());
            missing_fallbacks.reserve(mappings.len());
            for mapping in mappings {
                let key = mapping_frame_key(mapping);
                if self.resolved_by_mapping.contains_key(&key) || !seen.insert(key) {
                    continue;
                }
                missing_keys.push(key);
                missing_requests.push(symbol_request_from_mapping_ref(mapping));
                let fallback_frame = mapping_fallback_frame(mapping);
                missing_fallbacks.push(render_inferno_perf_folded_label(fallback_frame.as_str()));
            }
            if missing_requests.is_empty() {
                return Ok(());
            }
            let resolved = self
                .resolver
                .resolve_frame_batch_with_metadata(&missing_requests)?;
            if resolved.len() != missing_requests.len() {
                return Err(format!(
                    "symbol resolver returned {} frame results for {} requests",
                    resolved.len(),
                    missing_requests.len()
                ));
            }
            self.resolved_by_mapping.reserve(missing_keys.len());
            for ((key, fallback_rendered), resolved_frames) in missing_keys
                .drain(..)
                .zip(missing_fallbacks.drain(..))
                .zip(resolved)
            {
                let folded_rendered = if resolved_frames.frames.is_empty() {
                    fallback_rendered
                } else {
                    render_inferno_perf_raw_stack(resolved_frames.frames.iter().map(String::as_str))
                };
                self.resolved_by_mapping.insert(
                    key,
                    CachedMappingFrames {
                        frames: resolved_frames.frames,
                        folded_rendered,
                        has_base_symbol: resolved_frames.has_base_symbol,
                        base_offset: resolved_frames.base_offset,
                    },
                );
            }
            Ok(())
        })();

        self.scratch_seen_mapping = seen;
        self.scratch_missing_keys = missing_keys;
        self.scratch_missing_requests = missing_requests;
        self.scratch_missing_fallbacks = missing_fallbacks;
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
        let mut address_cache = ObjectAddressCache::default();

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

        if !kernel_elf_requests.is_empty() {
            let kernel_symbols = self.object_resolver.resolve_batch(&kernel_elf_requests)?;
            for (index, symbol) in kernel_elf_indexes.into_iter().zip(kernel_symbols) {
                resolved[index] = symbol;
            }
        }

        if !user_requests.is_empty() {
            let user_symbols = self.object_resolver.resolve_batch(&user_requests)?;
            for (index, symbol) in user_indexes.into_iter().zip(user_symbols) {
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
        let mut kernel_elf_requests = Vec::new();
        let mut kernel_elf_indexes = Vec::new();
        let mut user_requests = Vec::new();
        let mut user_indexes = Vec::new();
        let mut address_cache = ObjectAddressCache::default();

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
                resolved[index] = frames;
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
        let mut address_cache = ObjectAddressCache::default();

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
                resolved[index] = frames;
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
            .unwrap_or_else(|| Self::live_object_symbol_request(request, address_cache))
    }

    fn cached_object_symbol_request(
        &self,
        request: &SymbolRequest,
        address_cache: &mut ObjectAddressCache,
    ) -> Option<SymbolRequest> {
        let debug_dir = self.debug_dir.as_ref()?;
        let build_id = request.build_id.as_ref()?;
        let elf = perf_build_id_elf_path(debug_dir, build_id);
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
            self.live_kallsyms
                .as_ref()
                .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request))
                .or_else(|| {
                    request
                        .path
                        .to_str()
                        .and_then(|module_path| self.live_module_kallsyms_for_path(module_path))
                        .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms.as_ref(), request))
                })
                .or_else(|| {
                    self.kallsyms
                        .as_ref()
                        .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request))
                })
        } else {
            self.kallsyms
                .as_ref()
                .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request))
                .or_else(|| {
                    if !self.can_use_system_kernel_symbols(request) {
                        return None;
                    }
                    self.system_map_kallsyms_ref()
                        .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request))
                })
                .or_else(|| {
                    if !self.can_use_system_kernel_symbols(request) {
                        return None;
                    }
                    self.live_kallsyms_ref()
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
    let segments = address_cache
        .segments_by_path
        .entry(path.as_os_str().to_owned())
        .or_insert_with(|| object_load_segment_ranges(path));
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
        let mut resolved_by_request = BTreeMap::<SymbolRequest, Option<String>>::new();
        for (path, indexes) in grouped_request_indexes(requests) {
            let path = Path::new(path);
            let grouped_requests = indexes
                .iter()
                .map(|index| requests[*index].clone())
                .collect::<Vec<_>>();
            let symbols = self.resolve_group_symbols(path, &grouped_requests)?;
            let object_metadata = self.object_metadata(path);
            for (request, symbol) in grouped_requests.into_iter().zip(symbols) {
                let object_symbol = object_metadata.as_ref().and_then(|metadata| {
                    metadata
                        .object_metadata
                        .object_symbol(request.relative_address)
                });
                let symbol = perf_name_with_object_alias(symbol, object_symbol);
                resolved_by_request.insert(request, symbol);
            }
        }

        requests
            .iter()
            .map(|request| {
                resolved_by_request
                    .get(request)
                    .cloned()
                    .ok_or_else(|| "missing addr2line result for request".to_string())
            })
            .collect()
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
            let grouped_requests = indexes
                .iter()
                .map(|index| requests[*index].clone())
                .collect::<Vec<_>>();
            let symbols = self.resolve_group_symbols(path, &grouped_requests)?;
            let object_metadata = self.object_metadata(path);
            if let Some(metadata) = object_metadata.as_ref() {
                let addresses = grouped_requests
                    .iter()
                    .map(|request| request.relative_address)
                    .collect::<Vec<_>>();
                metadata.prepare_dwarf_frames_for_addresses(&addresses);
            }
            for ((index, request), symbol) in indexes.into_iter().zip(grouped_requests).zip(symbols)
            {
                let object_symbols =
                    object_symbols_for_frame(object_metadata.as_ref(), request.relative_address);
                let object_symbol = object_symbols.bare;
                let has_base_symbol = object_symbol.is_some();
                let mut frames = if let Some(object_symbol) = object_symbol {
                    object_metadata
                        .as_ref()
                        .and_then(|metadata| {
                            metadata.dwarf_frame_names_for_base_symbol(
                                request.relative_address,
                                Some(object_symbol),
                            )
                        })
                        .map_or_else(|| vec![object_symbol.to_string()], perf_inline_frame_order)
                } else {
                    symbol.map_or_else(Vec::new, |name| vec![name])
                };
                frames = perf_frames_with_object_alias_and_offset(
                    frames,
                    object_symbol,
                    object_symbols.with_offset.as_deref(),
                );
                resolved[index] = ResolvedSymbolFrames {
                    frames,
                    has_base_symbol,
                    base_offset: object_symbols.offset_suffix,
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
                    .map(demangle_addr2line_name)
                    .or_else(|| rust_addr2line_frame_name(&loader, request.relative_address));
                let mut symbol = perf_name_with_object_alias(symbol, object_symbol);
                if let Some(metadata) = &object_metadata {
                    specialize_symbol_from_debug_strings(
                        &mut symbol,
                        &metadata.object_metadata.debug_names,
                    );
                }
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
                    .map(|index| requests[*index].relative_address)
                    .collect::<Vec<_>>();
                metadata.prepare_dwarf_frames_for_addresses(&addresses);
            }
            let mut loader = None;
            let mut loader_attempted = false;
            for index in indexes {
                let request = &requests[index];
                let object_symbols =
                    object_symbols_for_frame(object_metadata.as_ref(), request.relative_address);
                let object_symbol = object_symbols.bare;
                let has_base_symbol = object_symbol.is_some();
                let mut frames = if let Some(object_symbol) = object_symbol {
                    object_metadata
                        .as_ref()
                        .and_then(|metadata| {
                            metadata.dwarf_frame_names_for_base_symbol(
                                request.relative_address,
                                Some(object_symbol),
                            )
                        })
                        .map_or_else(|| vec![object_symbol.to_string()], perf_inline_frame_order)
                } else {
                    rust_addr2line_loader(path, &mut loader, &mut loader_attempted)
                        .and_then(|loader| {
                            loader
                                .find_symbol(request.relative_address)
                                .map(|name| vec![demangle_addr2line_name(name)])
                                .or_else(|| {
                                    rust_addr2line_frame_names(loader, request.relative_address)
                                })
                        })
                        .unwrap_or_default()
                };
                frames = perf_frames_with_object_alias_and_offset(
                    frames,
                    object_symbol,
                    object_symbols.with_offset.as_deref(),
                );
                // No .debug_str generic specialization here: inline-frame names
                // now come from the DWARF linkage name demangled like perf's
                // external-addr2line backend (fully qualified, perf-faithful).
                // Re-specializing from .debug_str would rewrite e.g.
                // `core::slice::<impl [T]>::sort_unstable` to `sort_unstable<u64>`,
                // which perf never prints (verified against
                // target/oracle/dwarf.perf.script).
                resolved[index] = ResolvedSymbolFrames {
                    frames,
                    has_base_symbol,
                    base_offset: object_symbols.offset_suffix,
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
                object_symbols.with_offset.as_deref(),
            );
            if let Some(metadata) = &metadata {
                specialize_frames_from_debug_strings(
                    &mut frames,
                    &metadata.object_metadata.debug_names,
                );
            }
            resolved[index] = ResolvedSymbolFrames {
                frames,
                has_base_symbol: true,
                // The no-inline base path bakes +0x<off> into the single frame
                // name via with_offset, so no separate per-line offset is used.
                base_offset: None,
            };
        }
    }
    resolved
}

fn demangle_addr2line_name(name: &str) -> String {
    perf_dwarf_function_name(&addr2line::demangle_auto(Cow::Borrowed(name), None))
}

/// Demangles a mangled (linkage) symbol the way perf's external-addr2line
/// srcline backend does: fully qualified, no trailing `::h<hash>`, generic
/// args preserved (`dso__demangle_sym` ->
/// `rust_demangle_display_demangle(..., /*alternate=*/true)`). Unlike
/// [`demangle_addr2line_name`] it does NOT collapse to the unqualified leaf.
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
    object_alias_with_offset: Option<&str>,
) -> Vec<String> {
    let mut frames = perf_frames_with_object_alias(frames, object_alias);
    if frames.len() == 1
        && let Some(alias) = object_alias_with_offset
    {
        frames[0] = alias.to_string();
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

fn perf_symbol_is_candidate(symbol: &object::Symbol<'_, '_>) -> bool {
    !symbol.is_undefined()
        && !symbol.name().unwrap_or_default().is_empty()
        && matches!(
            symbol.kind(),
            SymbolKind::Text | SymbolKind::Data | SymbolKind::Label
        )
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
    if current.size == 0 && candidate.size > 0 {
        return candidate;
    }
    if candidate.size == 0 && current.size > 0 {
        return current;
    }
    if current.scope == PerfSymbolScope::Global && candidate.scope != PerfSymbolScope::Global {
        return current;
    }
    if candidate.scope == PerfSymbolScope::Global && current.scope != PerfSymbolScope::Global {
        return candidate;
    }
    if candidate.binding == PerfSymbolBinding::Weak && current.binding != PerfSymbolBinding::Weak {
        return current;
    }
    if current.binding == PerfSymbolBinding::Weak && candidate.binding != PerfSymbolBinding::Weak {
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
            debug_names: DebugStringNameIndex::from_object_bytes(object_bytes),
        }
    }

    fn object_symbol(&self, address: u64) -> Option<&str> {
        self.object_symbols.symbol_name(address)
    }

    fn object_symbol_with_offset(&self, address: u64) -> Option<String> {
        self.object_symbols.symbol_name_with_offset(address)
    }

    fn object_symbol_names(&self, address: u64) -> PerfObjectSymbolNames<'_> {
        PerfObjectSymbolNames {
            bare: self.object_symbol(address),
            with_offset: self.object_symbol_with_offset(address),
            offset_suffix: self.object_symbols.symbol_offset_suffix(address),
        }
    }
}

impl PerfObjectSymbolIndex {
    fn from_object_bytes(object_bytes: &[u8]) -> Self {
        let Ok(object) = object::File::parse(object_bytes) else {
            return Self::default();
        };
        let mut symbols = object
            .symbols()
            .chain(object.dynamic_symbols())
            .filter_map(|symbol| perf_symbol_candidate_from_object_symbol(&symbol))
            .collect::<Vec<_>>();
        symbols.extend(perf_synthesized_plt_symbols(&object, &symbols));
        symbols.sort_by_key(|symbol| symbol.address);
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

    fn symbol_name_with_offset(&self, address: u64) -> Option<String> {
        let candidate = self.symbol(address)?;
        let offset = address.saturating_sub(candidate.address);
        Some(format!("{}+0x{offset:x}", candidate.name))
    }

    fn symbol_offset_suffix(&self, address: u64) -> Option<String> {
        let candidate = self.symbol(address)?;
        let offset = address.saturating_sub(candidate.address);
        Some(format!("+0x{offset:x}"))
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
                    perf_best_duplicate_symbol(current, candidate)
                }
                _ => candidate,
            });
        }
        best
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
        .chunks_exact(ELF64_RELA_ENTRY_SIZE)
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

fn parse_elf64_rela_entry(entry: &[u8]) -> Option<Elf64RelaEntry> {
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
    symbol: &object::Symbol<'_, '_>,
) -> Option<PerfSymbolCandidate> {
    perf_symbol_is_candidate(symbol).then(|| PerfSymbolCandidate {
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
    })
}

fn rust_addr2line_loader<'a>(
    path: &Path,
    loader: &'a mut Option<addr2line::Loader>,
    loader_attempted: &mut bool,
) -> Option<&'a addr2line::Loader> {
    if !*loader_attempted {
        *loader = addr2line::Loader::new(path).ok();
        *loader_attempted = true;
    }
    loader.as_ref()
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
    PerfDwarfNameResolver::from_object_bytes_for_addresses(&bytes, &[address])
        .ok()?
        .frame_names(address)
}

#[must_use]
pub fn perf_dwarf_frame_names_from_object_bytes(bytes: &[u8], address: u64) -> Option<Vec<String>> {
    PerfDwarfNameResolver::from_object_bytes_for_addresses(bytes, &[address])
        .ok()?
        .frame_names(address)
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
            let roots = perf_dwarf_unit_roots(&dwarf, &unit, &mut names);
            units.push(PerfDwarfUnitIndex {
                ranges,
                segments: perf_dwarf_frame_ranges_from_roots(&roots),
            });
        }
        Ok(Self {
            names: names.into_names(),
            units,
        })
    }

    fn frame_names(&self, address: u64) -> Option<Vec<String>> {
        self.frame_names_for_base_symbol(address, None)
    }

    fn frame_names_for_base_symbol(
        &self,
        address: u64,
        base_symbol: Option<&str>,
    ) -> Option<Vec<String>> {
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
    ) -> Option<Vec<String>> {
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
                    segments: Some(Vec::new()),
                });
            }
            ordinal += 1;
            continue;
        };
        if scanning {
            units.push(PerfDwarfCachedUnit {
                ranges: perf_dwarf_ranges(dwarf.unit_ranges(&unit).ok()),
                segments: None,
            });
        }
        let Some(cached_unit) = units.get_mut(ordinal) else {
            break;
        };
        if cached_unit.segments.is_none()
            && perf_dwarf_unit_ranges_match_addresses(cached_unit.ranges.as_deref(), addresses)
        {
            let roots = perf_dwarf_unit_roots(&dwarf, &unit, &mut cache.names);
            cached_unit.segments = Some(perf_dwarf_frame_ranges_from_roots(&roots));
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

fn perf_dwarf_frame_ranges_from_roots(roots: &[PerfDwarfDieNode]) -> Vec<PerfDwarfFrameRange> {
    let mut segments = Vec::new();
    let root_frames: Arc<[PerfDwarfNameId]> = Arc::from([]);
    let mut next_order = 0;
    for root in roots {
        perf_dwarf_collect_frame_ranges(root, &root_frames, &mut segments, &mut next_order);
    }
    segments.sort_by_key(|segment| segment.range.begin);
    segments
}

fn perf_dwarf_collect_frame_ranges(
    node: &PerfDwarfDieNode,
    parent_frames: &Arc<[PerfDwarfNameId]>,
    out: &mut Vec<PerfDwarfFrameRange>,
    next_order: &mut usize,
) -> Vec<PerfAddressRange> {
    let frames = perf_dwarf_node_frames(parent_frames, node.name);

    let mut child_coverage = Vec::new();
    for child in &node.children {
        if child.kind == PerfDwarfDieKind::Subprogram {
            continue;
        }
        child_coverage.extend(perf_dwarf_collect_frame_ranges(
            child, &frames, out, next_order,
        ));
    }

    if !frames.is_empty() {
        let base_symbol_sensitive = node.kind == PerfDwarfDieKind::Subprogram && frames.len() == 1;
        for range in perf_dwarf_subtract_ranges(&node.ranges, &child_coverage) {
            let order = *next_order;
            *next_order += 1;
            out.push(PerfDwarfFrameRange {
                range,
                frames: frames.clone(),
                base_symbol_sensitive,
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

fn perf_dwarf_frame_names_from_index(
    segments: &[PerfDwarfFrameRange],
    names: &[String],
    address: u64,
    base_symbol: Option<&str>,
) -> Option<Vec<String>> {
    let upper_bound = segments.partition_point(|segment| segment.range.begin <= address);
    if upper_bound == 0 {
        return None;
    }
    let segment = segments[..upper_bound]
        .iter()
        .filter(|segment| segment.range.begin <= address && address < segment.range.end)
        .min_by_key(|segment| segment.order)?;
    if segment.base_symbol_sensitive
        && !segment
            .frames
            .first()
            .and_then(|name| names.get(usize::try_from(*name).ok()?))
            .is_some_and(|name| perf_realfunc_name_replaces_base_symbol(name, base_symbol))
    {
        return None;
    }
    let mut frames = segment
        .frames
        .iter()
        .filter_map(|name| names.get(usize::try_from(*name).ok()?))
        .cloned()
        .collect::<Vec<_>>();
    frames.reverse();
    Some(frames)
}

fn perf_realfunc_name_replaces_base_symbol(name: &str, base_symbol: Option<&str>) -> bool {
    base_symbol.is_some_and(|base_symbol| name != base_symbol)
}

/// Resolves the printed frame name for one subprogram/inlined-subroutine DIE.
///
/// perf's external-addr2line srcline backend (the modern oracle build) names
/// each frame from the ELF symtab / DWARF *linkage* (mangled) name and then
/// demangles it itself with the Rust v0 demangler in alternate form
/// (`tools/perf/util/srcline.c` `new_inline_sym` -> `dso__demangle_sym` ->
/// `rust_demangle_display_demangle(..., /*alternate=*/true)` in
/// `tools/perf/util/symbol.c`), which yields fully-qualified names without the
/// trailing `::h<hash>` and with generic arguments preserved.
/// `addr2line::demangle_auto` produces byte-identical output to perf's alternate
/// Rust demangle for both legacy `_ZN` and v0 `_R` manglings, so the linkage
/// name is demangled with it directly (NOT run through
/// [`perf_dwarf_function_name`], which strips to the unqualified leaf and only
/// applies to the bare `DW_AT_name` fallback).
///
/// Falls back to the bare `DW_AT_name` (perf's libdw backend spelling) when no
/// linkage name is present, e.g. closures and shim DIEs.
fn perf_dwarf_die_frame_name<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &gimli::DebuggingInformationEntry<R>,
) -> Option<String>
where
    R: gimli::Reader,
{
    if let Some(linkage) = perf_dwarf_die_linkage_name(dwarf, unit, entry, 16) {
        return Some(demangle_addr2line_name_qualified(&linkage));
    }
    perf_dwarf_die_name(dwarf, unit, entry).map(|name| perf_dwarf_function_name(&name))
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

fn specialize_symbol_from_debug_strings(
    symbol: &mut Option<String>,
    debug_names: &DebugStringNameIndex,
) {
    if let Some(symbol) = symbol
        && let Some(specialized) = debug_names.get(symbol)
        && specialized != symbol
    {
        *symbol = specialized.to_string();
    }
}

fn specialize_frames_from_debug_strings(frames: &mut [String], debug_names: &DebugStringNameIndex) {
    for frame in frames {
        if let Some(specialized) = debug_names.get(frame)
            && specialized != frame
        {
            *frame = specialized.to_string();
        }
    }
}

#[derive(Default)]
struct DebugStringNameIndex {
    names_by_leaf: BTreeMap<String, Option<String>>,
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

impl DebugStringNameIndex {
    fn from_object_bytes(object_bytes: &[u8]) -> Self {
        let mut index = Self::default();
        for raw in object_bytes.split(|byte| *byte == 0) {
            if raw.len() < 4 || raw.len() > 4096 {
                continue;
            }
            let Ok(candidate) = std::str::from_utf8(raw) else {
                continue;
            };
            if !candidate.contains('<') {
                continue;
            }
            let normalized = perf_dwarf_function_name(candidate);
            let Some(leaf) = generic_function_leaf(&normalized) else {
                continue;
            };
            if let Some(existing) = index.names_by_leaf.get_mut(leaf) {
                if existing
                    .as_ref()
                    .is_some_and(|current| current != &normalized)
                {
                    *existing = None;
                }
            } else {
                index
                    .names_by_leaf
                    .insert(leaf.to_string(), Some(normalized));
            }
        }
        index
    }

    fn get(&self, function_leaf: &str) -> Option<&str> {
        if function_leaf.is_empty() {
            return None;
        }
        let normalized = perf_dwarf_function_name(function_leaf);
        let lookup_leaf = generic_function_leaf(&normalized).unwrap_or(&normalized);
        self.names_by_leaf
            .get(lookup_leaf)
            .and_then(Option::as_deref)
    }
}

#[must_use]
pub fn more_specific_dwarf_name_from_debug_strings(
    function_leaf: &str,
    object_bytes: &[u8],
) -> Option<String> {
    DebugStringNameIndex::from_object_bytes(object_bytes)
        .get(function_leaf)
        .map(str::to_string)
}

fn generic_function_leaf(name: &str) -> Option<&str> {
    let generic_start = name.find('<')?;
    let leaf = &name[..generic_start];
    (!leaf.is_empty() && !leaf.contains(' ') && !leaf.contains('(')).then_some(leaf)
}

#[must_use]
pub fn perf_symbol_name(name: &str) -> String {
    if !looks_like_cpp_qualified_name(name)
        && let Some(name) = rust_receiver_generic_leaf(name)
    {
        return name;
    }
    name.to_owned()
}

#[must_use]
pub fn perf_dwarf_function_name(name: &str) -> String {
    if looks_like_cpp_qualified_name(name) || perf_script_keeps_rust_qualified_name(name) {
        return name.to_owned();
    }
    rust_leaf_with_receiver_generics(name).unwrap_or_else(|| name.to_owned())
}

fn looks_like_cpp_qualified_name(name: &str) -> bool {
    name.starts_with("std::vector")
        || name.starts_with("std::allocator")
        || (name.contains("std::vector") && name.contains("::"))
}

fn perf_script_keeps_rust_qualified_name(name: &str) -> bool {
    name.starts_with("std::fs::") || name.starts_with("std::io::") || name.starts_with("std::sys::")
}

fn rust_leaf_with_receiver_generics(name: &str) -> Option<String> {
    let separator = last_namespace_separator(name)?;
    let leaf = name.get(separator + 2..)?;
    if leaf.contains('<') {
        return Some(leaf.to_owned());
    }

    let receiver = name.get(..separator)?;
    if receiver.starts_with('<') {
        return Some(leaf.to_owned());
    }
    if let Some(generic_arguments) = trailing_generic_arguments(receiver)
        && perf_script_receiver_generics_are_specific(generic_arguments)
    {
        Some(format!("{leaf}{generic_arguments}"))
    } else {
        Some(leaf.to_owned())
    }
}

fn rust_receiver_generic_leaf(name: &str) -> Option<String> {
    let separator = last_namespace_separator(name)?;
    let leaf = name.get(separator + 2..)?;
    let receiver = name.get(..separator)?;
    if receiver.starts_with('<') {
        return None;
    }
    let generic_arguments = trailing_generic_arguments(receiver)?;
    perf_script_receiver_generics_are_specific(generic_arguments)
        .then(|| format!("{leaf}{generic_arguments}"))
}

fn perf_script_receiver_generics_are_specific(generic_arguments: &str) -> bool {
    generic_arguments.contains(',') || generic_arguments.contains("::")
}

fn last_namespace_separator(name: &str) -> Option<usize> {
    let mut angle_depth = 0_u32;
    let mut last_namespace_separator = None;
    for (index, character) in name.char_indices() {
        match character {
            '<' => angle_depth = angle_depth.saturating_add(1),
            '>' => angle_depth = angle_depth.saturating_sub(1),
            ':' if angle_depth == 0 && name[index..].starts_with("::") => {
                last_namespace_separator = Some(index);
            }
            _ => {}
        }
    }
    last_namespace_separator
}

fn trailing_generic_arguments(name: &str) -> Option<&str> {
    let mut angle_depth = 0_u32;
    let mut generic_start = None;
    for (index, character) in name.char_indices().rev() {
        match character {
            '>' => angle_depth = angle_depth.saturating_add(1),
            '<' => {
                angle_depth = angle_depth.checked_sub(1)?;
                if angle_depth == 0 {
                    generic_start = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    name.get(generic_start?..)
}

#[must_use]
pub fn perf_inline_frame_order(mut frames: Vec<String>) -> Vec<String> {
    frames.reverse();
    frames
}

fn grouped_request_indexes(requests: &[SymbolRequest]) -> FxHashMap<&OsStr, Vec<usize>> {
    let mut grouped = FxHashMap::<&OsStr, Vec<usize>>::default();
    for (index, request) in requests.iter().enumerate() {
        grouped
            .entry(request.path.as_os_str())
            .or_default()
            .push(index);
    }
    grouped
}

fn mapping_frame_key(mapping: &ResolvedMappingRef<'_>) -> MappingFrameKey {
    MappingFrameKey {
        symbol_source_id: mapping.symbol_source_id,
        relative_address: mapping.relative_address,
    }
}

fn mapping_fallback_frame(mapping: &ResolvedMappingRef<'_>) -> String {
    if is_kernel_mapping_ref(mapping) {
        kernel_module_fallback_frame(mapping.path)
    } else if mapping.path == "[unknown]" {
        mapping.path.to_string()
    } else {
        let name = Path::new(mapping.path)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or(mapping.path);
        format!("[{name}]")
    }
}

fn kernel_module_fallback_frame(path: &str) -> String {
    if path.starts_with("[kernel.kallsyms]") {
        "[[kernel.kallsyms]]".to_string()
    } else {
        let name = Path::new(path)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or(path);
        format!("[{name}]")
    }
}

fn is_kernel_mapping_ref(mapping: &ResolvedMappingRef<'_>) -> bool {
    crate::perfdata::samples::is_kernel_space_frame(mapping.relative_address)
        && mapping.path.starts_with('[')
}

fn symbol_request_from_mapping_ref(mapping: &ResolvedMappingRef<'_>) -> SymbolRequest {
    SymbolRequest {
        path: if is_kernel_symbol_path(Path::new(mapping.path))
            && mapping.path.starts_with("[kernel")
        {
            PathBuf::from("[kernel.kallsyms]")
        } else {
            PathBuf::from(mapping.path)
        },
        relative_address: mapping.relative_address,
        build_id: mapping.build_id.map(build_id_hex),
        file_identity: mapping.file_identity,
        kernel_relocation: mapping.kernel_relocation.clone(),
    }
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
/// descriptor. Notes are little-endian on the supported targets (x86_64,
/// aarch64), matching how perf stores build-ids in HEADER_BUILD_ID.
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
    path.starts_with('[') && !path.starts_with("[kernel") && !path.starts_with("[guest.kernel]")
}

fn prefer_kernel_alias(candidate: &str, current: &str) -> bool {
    candidate.starts_with("__pi_") && !current.starts_with("__pi_")
}

fn insert_kallsyms_symbol(
    symbols: &mut BTreeMap<u64, String>,
    addresses_by_name: &mut BTreeMap<String, u64>,
    address: u64,
    symbol: String,
) {
    match symbols.entry(address) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(symbol.clone());
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            if prefer_kernel_alias(&symbol, entry.get()) {
                entry.insert(symbol.clone());
            }
        }
    }
    addresses_by_name.entry(symbol).or_insert(address);
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

fn parse_module_kallsyms_line(line: &str) -> Option<(u64, String, String)> {
    let mut fields = line.split_whitespace();
    let address = u64::from_str_radix(fields.next()?, 16).ok()?;
    let _symbol_type = fields.next()?;
    let symbol = fields.next()?;
    let module = fields.next()?;
    (module.starts_with('[') && module.ends_with(']'))
        .then(|| (address, symbol.to_string(), module.to_string()))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Arc;

    use object::{Object, ObjectSegment, ObjectSymbol, build, elf};

    use super::{
        PerfAddressRange, PerfDwarfDieKind, PerfDwarfDieNode, PerfDwarfNameInterner,
        PerfObjectSymbolIndex, PerfSymbolBinding, PerfSymbolCandidate, PerfSymbolScope,
        ResolvedMappingRef, RustAddr2lineResolver, SymbolFrameCache, SymbolRequest, SymbolResolver,
        clean_object_symbol_request, demangle_addr2line_name_qualified, gnu_build_id_from_notes,
        perf_best_duplicate_symbol, perf_dwarf_frame_names_from_index,
        perf_dwarf_frame_ranges_from_roots, perf_frames_with_object_alias,
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
        };
        let public_alias = PerfSymbolCandidate {
            name: "read".to_string(),
            address: 0x1000,
            size: 128,
            scope: PerfSymbolScope::Global,
            binding: PerfSymbolBinding::Global,
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
        };
        let global_alias = PerfSymbolCandidate {
            name: "read".to_string(),
            address: 0x1000,
            size: 128,
            scope: PerfSymbolScope::Global,
            binding: PerfSymbolBinding::Global,
        };

        assert_eq!(
            perf_best_duplicate_symbol(&local_alias, &global_alias).name,
            "read"
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
                },
                PerfSymbolCandidate {
                    name: "small".to_string(),
                    address: 0x1800,
                    size: 0x10,
                    scope: PerfSymbolScope::Global,
                    binding: PerfSymbolBinding::Global,
                },
            ],
            max_end_by_index: vec![0x2000, 0x2000],
        };

        assert_eq!(symbols.symbol_name(0x1810), Some("large"));
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
        let mut builder = build::elf::Builder::new(object::Endianness::Little, true);
        builder.header.e_type = elf::ET_DYN;
        builder.header.e_machine = elf::EM_X86_64;
        builder.header.e_phoff = 0x40;

        let section = builder.sections.add();
        section.name = b".shstrtab"[..].into();
        section.sh_type = elf::SHT_STRTAB;
        section.data = build::elf::SectionData::SectionString;

        let section = builder.sections.add();
        section.name = b".text"[..].into();
        section.sh_type = elf::SHT_PROGBITS;
        section.sh_flags = u64::from(elf::SHF_ALLOC | elf::SHF_EXECINSTR);
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
        symbol.set_st_info(elf::STB_GLOBAL, elf::STT_FUNC);
        symbol.section = Some(text_id);

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
    fn flattened_dwarf_ranges_share_frame_slices_for_the_same_node() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(&[PerfDwarfDieNode {
            kind: PerfDwarfDieKind::Subprogram,
            ranges: vec![test_range(0, 100)],
            name: Some(names.intern("outer".to_string())),
            children: vec![PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Inline,
                ranges: vec![test_range(10, 20)],
                name: Some(names.intern("inner".to_string())),
                children: Vec::new(),
            }],
        }]);

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
        let segments = perf_dwarf_frame_ranges_from_roots(&[PerfDwarfDieNode {
            kind: PerfDwarfDieKind::Subprogram,
            ranges: vec![test_range(0, 100)],
            name: Some(names.intern("outer".to_string())),
            children: vec![PerfDwarfDieNode {
                kind: PerfDwarfDieKind::Inline,
                ranges: vec![test_range(10, 20)],
                name: Some(names.intern("inner".to_string())),
                children: Vec::new(),
            }],
        }]);

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 15, Some("outer")),
            Some(vec!["inner".to_string(), "outer".to_string()])
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 5, Some("outer")),
            None
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 5, Some("different_base")),
            Some(vec!["outer".to_string()])
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 150, None),
            None
        );
    }

    #[test]
    fn flattened_dwarf_lookup_ignores_unnamed_intermediate_nodes() {
        let mut names = PerfDwarfNameInterner::default();
        let segments = perf_dwarf_frame_ranges_from_roots(&[PerfDwarfDieNode {
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
        }]);

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 35, Some("outer")),
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
        let segments = perf_dwarf_frame_ranges_from_roots(&[PerfDwarfDieNode {
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
        }]);

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 20, Some("outer")),
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
        let segments = perf_dwarf_frame_ranges_from_roots(&[PerfDwarfDieNode {
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
        }]);

        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 25, Some("outer")),
            None
        );
        assert_eq!(
            perf_dwarf_frame_names_from_index(&segments, &names.names, 45, Some("outer")),
            Some(vec!["real_inline".to_string(), "outer".to_string()])
        );
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
    fn symbol_frame_cache_resolve_folded_mapping_ref_reuses_cached_rendered_stack() {
        let resolver = CountingFrameResolver::new(vec![vec!["one".to_string(), "two".to_string()]]);
        let mut cache = SymbolFrameCache::new(&resolver);
        let mapping = test_mapping_ref("/bin/demo", 0x1234);

        let first_ptr = {
            let first = cache
                .resolve_folded_mapping_ref(&mapping)
                .expect("first resolve")
                .expect("folded render");
            assert_eq!(first, "one;two");
            first.as_ptr()
        };

        let second_ptr = {
            let second = cache
                .resolve_folded_mapping_ref(&mapping)
                .expect("second resolve")
                .expect("folded render");
            assert_eq!(second, "one;two");
            second.as_ptr()
        };

        assert_eq!(first_ptr, second_ptr);
        assert_eq!(resolver.calls.get(), 1);
    }

    #[test]
    fn symbol_frame_cache_resolve_folded_mapping_ref_strips_symbol_offsets_like_inferno_perf() {
        let resolver = CountingFrameResolver::new(vec![vec!["handler+0x2a".to_string()]]);
        let mut cache = SymbolFrameCache::new(&resolver);
        let mapping = test_mapping_ref("/bin/demo", 0x1234);

        let folded = cache
            .resolve_folded_mapping_ref(&mapping)
            .expect("resolve")
            .expect("folded render");

        assert_eq!(folded, "handler");
    }

    #[test]
    fn symbol_frame_cache_resolve_folded_mapping_ref_caches_fallback_rendering() {
        let resolver = CountingFrameResolver::new(vec![Vec::new()]);
        let mut cache = SymbolFrameCache::new(&resolver);
        let mapping = test_mapping_ref("/usr/lib/libdemo.so", 0x1234);

        let first_ptr = {
            let first = cache
                .resolve_folded_mapping_ref(&mapping)
                .expect("first resolve")
                .expect("folded fallback render");
            assert_eq!(first, "[libdemo.so]");
            first.as_ptr()
        };

        let second_ptr = {
            let second = cache
                .resolve_folded_mapping_ref(&mapping)
                .expect("second resolve")
                .expect("folded fallback render");
            assert_eq!(second, "[libdemo.so]");
            second.as_ptr()
        };

        assert_eq!(first_ptr, second_ptr);
        assert_eq!(resolver.calls.get(), 1);
    }

    #[test]
    fn symbol_frame_cache_resolve_folded_mapping_ref_wraps_bracket_dso_like_inferno_perf() {
        let resolver = CountingFrameResolver::new(vec![Vec::new()]);
        let mut cache = SymbolFrameCache::new(&resolver);
        let mapping = test_mapping_ref("[vdso]", 0x10);

        let folded = cache
            .resolve_folded_mapping_ref(&mapping)
            .expect("resolve")
            .expect("folded fallback render");

        assert_eq!(folded, "[[vdso]]");
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
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        }
    }

    fn test_mapping_ref(path: &'static str, relative_address: u64) -> ResolvedMappingRef<'static> {
        ResolvedMappingRef {
            symbol_source_id: 1,
            path,
            relative_address,
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
