use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use clap::ValueEnum;
use hashbrown::HashMap;
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SymbolKind};
use rustc_hash::FxBuildHasher;
use serde::Serialize;

use crate::perfdata::build_id::kernel_build_id_from_perfdata;
use crate::perfdata::mappings::{FileIdentity, file_matches_recorded_identity};
use crate::process::{CommandRunner, CommandSpec};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KernelRelocation {
    pub reference_symbol: String,
    pub recorded_reference_address: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SymbolRequest {
    pub path: PathBuf,
    pub relative_address: u64,
    pub build_id: Option<String>,
    pub file_identity: Option<FileIdentity>,
    pub kernel_relocation: Option<KernelRelocation>,
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
}

pub struct SymbolCache<'a, R> {
    resolver: &'a R,
    resolved: BTreeMap<SymbolRequest, Option<String>>,
}

pub struct SymbolFrameCache<'a, R> {
    resolver: &'a R,
    resolved: BTreeMap<SymbolRequest, Vec<String>>,
}

pub struct Addr2lineResolver<'a, R> {
    runner: &'a R,
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
    metadata_cache: OnceLock<Mutex<BTreeMap<PathBuf, Option<Arc<CachedObjectMetadata>>>>>,
}

#[derive(Default)]
struct ObjectAddressCache {
    segments_by_path: BTreeMap<PathBuf, Option<Vec<ObjectSegmentRange>>>,
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
    perf_dwarf: Option<PerfDwarfNameResolver>,
}

#[derive(Default)]
struct PerfObjectSymbolIndex {
    symbols: Vec<PerfSymbolCandidate>,
}

pub struct PerfSymbolResolver<O> {
    object_resolver: O,
    debug_dir: Option<PathBuf>,
    kernel_elf: Option<PathBuf>,
    kallsyms: Option<Kallsyms>,
    live_kallsyms: Option<Kallsyms>,
    live_kallsyms_path: Option<PathBuf>,
    live_kallsyms_cache: OnceLock<Option<Kallsyms>>,
    live_module_kallsyms_text_cache: OnceLock<Option<Arc<String>>>,
    live_module_kallsyms_cache: Mutex<BTreeMap<String, Option<Arc<Kallsyms>>>>,
    system_map_kallsyms: Option<Kallsyms>,
    system_map_candidates: Vec<PathBuf>,
    system_map_kallsyms_cache: OnceLock<Option<Kallsyms>>,
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
            .get_or_init(|| Mutex::new(BTreeMap::new()));
        if let Some(cached) = cache
            .lock()
            .expect("rust addr2line metadata cache lock")
            .get(path)
            .cloned()
        {
            return cached;
        }

        let loaded = std::fs::read(path).ok().map(|bytes| {
            Arc::new(CachedObjectMetadata {
                object_metadata: PreparedObjectMetadata::from_object_bytes(&bytes),
                perf_dwarf: PerfDwarfNameResolver::from_object_bytes(&bytes).ok(),
            })
        });

        let mut cache = cache.lock().expect("rust addr2line metadata cache lock");
        cache
            .entry(path.to_path_buf())
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
        Self { runner }
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
            kallsyms: None,
            live_kallsyms: None,
            live_kallsyms_path: None,
            live_kallsyms_cache: OnceLock::new(),
            live_module_kallsyms_text_cache: OnceLock::new(),
            live_module_kallsyms_cache: Mutex::new(BTreeMap::new()),
            system_map_kallsyms: None,
            system_map_candidates: Vec::new(),
            system_map_kallsyms_cache: OnceLock::new(),
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
        let self_with_debug_dir = self.with_debug_dir(debug_dir.to_path_buf());
        let kernel_elf = perf_build_id_elf_path(debug_dir, &build_id);
        let self_with_kallsyms = match Kallsyms::load_perf_build_id_cache(debug_dir, &build_id) {
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
    pub fn with_perfdata_file_kernel_cache(self, perfdata: &Path, debug_dir: &Path) -> Self {
        match std::fs::read(perfdata) {
            Ok(bytes) => self.with_perfdata_kernel_cache(&bytes, debug_dir),
            Err(_) => self,
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
        }
        this
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
            resolved: BTreeMap::new(),
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
        requests
            .iter()
            .filter(|request| !self.resolved.contains_key(*request))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
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
            resolved: BTreeMap::new(),
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

    /// Resolves many object-relative addresses to frame lists, batching cache misses.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing resolver fails or returns the wrong
    /// number of results.
    pub fn resolve_many(&mut self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
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
                    .ok_or_else(|| "symbol frame cache lookup missed after resolution".to_string())
            })
            .collect()
    }

    fn unique_misses(&self, requests: &[SymbolRequest]) -> Vec<SymbolRequest> {
        requests
            .iter()
            .filter(|request| !self.resolved.contains_key(*request))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
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
            } else if let Some(object_request) =
                self.object_symbol_request(request, &mut address_cache)
            {
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
        let mut resolved = vec![Vec::new(); requests.len()];
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
                    resolved[index] = vec![symbol];
                }
            } else if is_kernel_symbol_path(&request.path) {
                if let Some(symbol) = self.resolve_kernel_symbol(request) {
                    resolved[index] = vec![symbol];
                } else if let Some(kernel_elf) = &self.kernel_elf {
                    kernel_elf_indexes.push(index);
                    kernel_elf_requests.push(clean_object_symbol_request_with_cache(
                        kernel_elf.clone(),
                        request.relative_address,
                        &mut address_cache,
                    ));
                }
            } else if let Some(object_request) =
                self.object_symbol_request(request, &mut address_cache)
            {
                user_indexes.push(index);
                user_requests.push(object_request);
            }
        }

        if !kernel_elf_requests.is_empty() {
            let kernel_frames = self
                .object_resolver
                .resolve_frame_batch(&kernel_elf_requests)?;
            for (index, frames) in kernel_elf_indexes.into_iter().zip(kernel_frames) {
                resolved[index] = frames;
            }
        }

        if !user_requests.is_empty() {
            let user_frames = self.object_resolver.resolve_frame_batch(&user_requests)?;
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
    ) -> Option<SymbolRequest> {
        self.cached_object_symbol_request(request, address_cache)
            .or_else(|| Self::live_object_symbol_request(request, address_cache))
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
    ) -> Option<SymbolRequest> {
        if request
            .file_identity
            .is_some_and(|identity| !file_matches_recorded_identity(&request.path, identity))
        {
            return None;
        }
        Some(clean_object_symbol_request_with_cache(
            request.path.clone(),
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
                    self.system_map_kallsyms_ref()
                        .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request))
                })
                .or_else(|| {
                    self.live_kallsyms_ref()
                        .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request))
                })
        }
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
        .entry(path.to_path_buf())
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
            let grouped_requests = indexes
                .iter()
                .map(|index| requests[*index].clone())
                .collect::<Vec<_>>();
            let output = self
                .runner
                .run(&build_addr2line_command(&path, &grouped_requests))
                .map_err(|error| format!("failed to run addr2line: {error}"))?;
            let symbols = if output.status_code == Some(0) {
                parse_addr2line_stdout(&output.stdout, grouped_requests.len())?
            } else {
                vec![None; grouped_requests.len()]
            };
            for (request, symbol) in grouped_requests.into_iter().zip(symbols) {
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
}

impl SymbolResolver for RustAddr2lineResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        let mut resolved_by_request = BTreeMap::<SymbolRequest, Option<String>>::new();
        for (path, indexes) in grouped_request_indexes(requests) {
            let Ok(loader) = addr2line::Loader::new(&path) else {
                for index in indexes {
                    resolved_by_request.insert(requests[index].clone(), None);
                }
                continue;
            };
            let object_metadata = self.object_metadata(&path);
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
                resolved_by_request.insert(request.clone(), symbol);
            }
        }

        requests
            .iter()
            .map(|request| {
                resolved_by_request
                    .get(request)
                    .cloned()
                    .ok_or_else(|| "missing rust addr2line result for request".to_string())
            })
            .collect()
    }

    fn resolve_frame_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
        let mut resolved_by_request = BTreeMap::<SymbolRequest, Vec<String>>::new();
        for (path, indexes) in grouped_request_indexes(requests) {
            let Ok(loader) = addr2line::Loader::new(&path) else {
                for index in indexes {
                    resolved_by_request.insert(requests[index].clone(), Vec::new());
                }
                continue;
            };
            let object_metadata = self.object_metadata(&path);
            for index in indexes {
                let request = &requests[index];
                let object_symbol = object_metadata.as_ref().and_then(|metadata| {
                    metadata
                        .object_metadata
                        .object_symbol(request.relative_address)
                });
                let mut frames = object_metadata
                    .as_ref()
                    .and_then(|resolver| {
                        resolver.perf_dwarf.as_ref()?.frame_names_for_base_symbol(
                            request.relative_address,
                            object_symbol.as_deref(),
                        )
                    })
                    .map(perf_inline_frame_order)
                    .or_else(|| object_symbol.clone().map(|name| vec![name]))
                    .or_else(|| {
                        loader
                            .find_symbol(request.relative_address)
                            .map(|name| vec![demangle_addr2line_name(name)])
                    })
                    .or_else(|| rust_addr2line_frame_names(&loader, request.relative_address))
                    .unwrap_or_default();
                frames = perf_frames_with_object_alias(frames, object_symbol);
                if let Some(metadata) = &object_metadata {
                    specialize_frames_from_debug_strings(
                        &mut frames,
                        &metadata.object_metadata.debug_names,
                    );
                }
                resolved_by_request.insert(request.clone(), frames);
            }
        }

        requests
            .iter()
            .map(|request| {
                resolved_by_request
                    .get(request)
                    .cloned()
                    .ok_or_else(|| "missing rust addr2line frame result for request".to_string())
            })
            .collect()
    }
}

fn demangle_addr2line_name(name: &str) -> String {
    perf_dwarf_function_name(&addr2line::demangle_auto(Cow::Borrowed(name), None))
}

fn perf_name_with_object_alias(
    name: Option<String>,
    object_alias: Option<String>,
) -> Option<String> {
    match (name, object_alias) {
        (Some(name), Some(object_alias))
            if perf_object_alias_improves_name(&name, &object_alias) =>
        {
            Some(object_alias)
        }
        (Some(name), _) => Some(name),
        (None, object_alias) => object_alias,
    }
}

fn perf_frames_with_object_alias(
    mut frames: Vec<String>,
    object_alias: Option<String>,
) -> Vec<String> {
    if frames.len() == 1
        && let Some(alias) = object_alias
        && perf_object_alias_improves_name(&frames[0], &alias)
    {
        frames[0] = alias;
    }
    frames
}

fn perf_object_alias_improves_name(name: &str, object_alias: &str) -> bool {
    leading_underscore_count(object_alias) < leading_underscore_count(name)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PerfSymbolCandidate {
    name: String,
    address: u64,
    size: u64,
    binding: PerfSymbolBinding,
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

    fn object_symbol(&self, address: u64) -> Option<String> {
        self.object_symbols.symbol_name(address)
    }
}

impl PerfObjectSymbolIndex {
    fn from_object_bytes(object_bytes: &[u8]) -> Self {
        let Ok(object) = object::File::parse(object_bytes) else {
            return Self::default();
        };
        let mut symbols = object
            .symbols()
            .filter(perf_symbol_is_candidate)
            .map(|symbol| PerfSymbolCandidate {
                name: perf_symbol_name(&addr2line::demangle_auto(
                    Cow::Borrowed(symbol.name().unwrap_or_default()),
                    None,
                )),
                address: symbol.address(),
                size: symbol.size(),
                binding: if symbol.is_weak() {
                    PerfSymbolBinding::Weak
                } else {
                    PerfSymbolBinding::Global
                },
            })
            .collect::<Vec<_>>();
        symbols.sort_by_key(|symbol| symbol.address);
        Self { symbols }
    }

    fn symbol_name(&self, address: u64) -> Option<String> {
        let mut best = None::<&PerfSymbolCandidate>;
        for candidate in &self.symbols {
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
        best.map(|candidate| candidate.name.clone())
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
    PerfDwarfNameResolver::from_object(path)
        .ok()?
        .frame_names(address)
}

#[must_use]
pub fn perf_dwarf_frame_names_from_object_bytes(bytes: &[u8], address: u64) -> Option<Vec<String>> {
    PerfDwarfNameResolver::from_object_bytes(bytes)
        .ok()?
        .frame_names(address)
}

impl PerfDwarfNameResolver {
    fn from_object(path: &Path) -> Result<Self, gimli::Error> {
        let bytes = std::fs::read(path).map_err(|_| gimli::Error::Io)?;
        Self::from_object_bytes(&bytes)
    }

    fn from_object_bytes(bytes: &[u8]) -> Result<Self, gimli::Error> {
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
            let roots = perf_dwarf_unit_roots(&dwarf, &unit, &mut names);
            units.push(PerfDwarfUnitIndex {
                ranges: perf_dwarf_ranges(dwarf.unit_ranges(&unit).ok()),
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
    let ranges = kind
        .map(|_| perf_dwarf_ranges(dwarf.die_ranges(unit, node.entry()).ok()).unwrap_or_default());
    let name = kind.and_then(|_| {
        perf_dwarf_die_name(dwarf, unit, node.entry())
            .map(|name| names.intern(perf_dwarf_function_name(&name)))
    });
    if let Some(kind) = kind {
        let mut children = Vec::new();
        let mut child_iter = node.children();
        while let Ok(Some(child)) = child_iter.next() {
            perf_dwarf_collect_relevant_nodes(dwarf, unit, child, names, &mut children);
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
        perf_dwarf_collect_relevant_nodes(dwarf, unit, child, names, out);
    }
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
    for root in roots {
        perf_dwarf_collect_frame_ranges(root, &root_frames, &mut segments);
    }
    segments.sort_by_key(|segment| segment.range.begin);
    segments
}

fn perf_dwarf_collect_frame_ranges(
    node: &PerfDwarfDieNode,
    parent_frames: &Arc<[PerfDwarfNameId]>,
    out: &mut Vec<PerfDwarfFrameRange>,
) -> Vec<PerfAddressRange> {
    let frames = perf_dwarf_node_frames(parent_frames, node.name);

    let mut child_coverage = Vec::new();
    for child in &node.children {
        child_coverage.extend(perf_dwarf_collect_frame_ranges(child, &frames, out));
    }

    if !frames.is_empty() {
        let base_symbol_sensitive = node.kind == PerfDwarfDieKind::Subprogram && frames.len() == 1;
        for range in perf_dwarf_subtract_ranges(&node.ranges, &child_coverage) {
            out.push(PerfDwarfFrameRange {
                range,
                frames: frames.clone(),
                base_symbol_sensitive,
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
    let segment = &segments[upper_bound - 1];
    if !(segment.range.begin <= address && address < segment.range.end) {
        return None;
    }
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
    {
        *symbol = specialized;
    }
}

fn specialize_frames_from_debug_strings(frames: &mut [String], debug_names: &DebugStringNameIndex) {
    for frame in frames {
        if let Some(specialized) = debug_names.get(frame) {
            *frame = specialized;
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

    fn get(&self, function_leaf: &str) -> Option<String> {
        if function_leaf.is_empty() {
            return None;
        }
        let normalized = perf_dwarf_function_name(function_leaf);
        let lookup_leaf = generic_function_leaf(&normalized).unwrap_or(&normalized);
        self.names_by_leaf.get(lookup_leaf).cloned().flatten()
    }
}

#[must_use]
pub fn more_specific_dwarf_name_from_debug_strings(
    function_leaf: &str,
    object_bytes: &[u8],
) -> Option<String> {
    DebugStringNameIndex::from_object_bytes(object_bytes).get(function_leaf)
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

fn grouped_request_indexes(requests: &[SymbolRequest]) -> BTreeMap<PathBuf, Vec<usize>> {
    let mut grouped = BTreeMap::<PathBuf, Vec<usize>>::new();
    for (index, request) in requests.iter().enumerate() {
        grouped.entry(request.path.clone()).or_default().push(index);
    }
    grouped
}

fn resolve_kernel_kallsyms(kallsyms: &Kallsyms, request: &SymbolRequest) -> Option<String> {
    if let Some(relocation) = &request.kernel_relocation {
        kallsyms.resolve_relocated(
            request.relative_address,
            &relocation.reference_symbol,
            relocation.recorded_reference_address,
        )
    } else {
        kallsyms.resolve(request.relative_address)
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
    use std::sync::Arc;

    use object::{Object, ObjectSegment, ObjectSymbol};

    use super::{
        PerfAddressRange, PerfDwarfDieKind, PerfDwarfDieNode, PerfDwarfNameInterner,
        PerfSymbolBinding, PerfSymbolCandidate, RustAddr2lineResolver, SymbolRequest,
        SymbolResolver, clean_object_symbol_request, perf_best_duplicate_symbol,
        perf_dwarf_frame_names_from_index, perf_dwarf_frame_ranges_from_roots,
        perf_frames_with_object_alias,
    };

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
                (file_size > 8 && virtual_address != file_offset)
                    .then_some((file_offset + 8, virtual_address + 8))
            })
            .expect("current test binary has a biased load segment");

        let request = clean_object_symbol_request(path, file_offset);

        assert_eq!(request.relative_address, virtual_address);
    }

    #[test]
    fn perf_alias_tie_breaker_prefers_less_underscored_symbol_like_perf() {
        let internal_alias = PerfSymbolCandidate {
            name: "__read".to_string(),
            address: 0x1000,
            size: 128,
            binding: PerfSymbolBinding::Global,
        };
        let public_alias = PerfSymbolCandidate {
            name: "read".to_string(),
            address: 0x1000,
            size: 128,
            binding: PerfSymbolBinding::Global,
        };

        assert_eq!(
            perf_best_duplicate_symbol(&internal_alias, &public_alias).name,
            "read"
        );
    }

    #[test]
    fn perf_object_alias_only_replaces_more_underscored_frame_names() {
        assert_eq!(
            perf_frames_with_object_alias(vec!["__read".to_string()], Some("read".to_string())),
            vec!["read".to_string()]
        );
        assert_eq!(
            perf_frames_with_object_alias(
                vec!["alloc::collections::btree::map::IntoIter<K,V,A>::dying_next".to_string()],
                Some("dying_next<u64, alloc::string::String, alloc::alloc::Global>".to_string())
            ),
            vec!["alloc::collections::btree::map::IntoIter<K,V,A>::dying_next".to_string()]
        );
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

    fn frame_names(names: &PerfDwarfNameInterner, frames: &[u32]) -> Vec<String> {
        frames
            .iter()
            .map(|name| names.names[*name as usize].clone())
            .collect()
    }

    fn test_range(begin: u64, end: u64) -> PerfAddressRange {
        PerfAddressRange { begin, end }
    }
}
