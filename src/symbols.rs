use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use object::{Object, ObjectSection, ObjectSegment};
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

#[derive(Clone, Copy, Debug, Default)]
pub struct RustAddr2lineResolver;

type PerfDwarfReader = gimli::EndianArcSlice<gimli::RunTimeEndian>;

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
    dwarf: gimli::Dwarf<PerfDwarfReader>,
}

pub struct PerfSymbolResolver<O> {
    object_resolver: O,
    debug_dir: Option<PathBuf>,
    kernel_elf: Option<PathBuf>,
    kallsyms: Option<Kallsyms>,
    live_kallsyms: Option<Kallsyms>,
    system_map_kallsyms: Option<Kallsyms>,
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
        Self
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
            system_map_kallsyms: None,
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
        self
    }

    #[must_use]
    pub fn with_system_map_kallsyms(mut self, kallsyms: Kallsyms) -> Self {
        self.system_map_kallsyms = Some(kallsyms);
        self
    }

    #[must_use]
    pub fn with_system_map_candidates(self, candidates: impl IntoIterator<Item = PathBuf>) -> Self {
        if self.kernel_elf.is_some() {
            return self;
        }
        match Kallsyms::load_first_system_map_candidate(candidates) {
            Some(kallsyms) => self.with_system_map_kallsyms(kallsyms),
            None => self,
        }
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
        if self.live_kallsyms.is_some() {
            return self;
        }
        match std::fs::read_to_string(path)
            .ok()
            .and_then(|text| Kallsyms::parse(&text).ok())
        {
            Some(kallsyms) => self.with_live_kallsyms(kallsyms),
            None => self,
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
        if symbols.is_empty() {
            return Err("kallsyms did not contain any parseable symbols".to_string());
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

    fn resolve_kernel_symbol(&self, request: &SymbolRequest) -> Option<String> {
        if is_kernel_module_symbol_path(&request.path) {
            self.live_kallsyms
                .as_ref()
                .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request))
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
                    self.system_map_kallsyms
                        .as_ref()
                        .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request))
                })
                .or_else(|| {
                    self.live_kallsyms
                        .as_ref()
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
            let debug_names = std::fs::read(&path)
                .map(|bytes| DebugStringNameIndex::from_object_bytes(&bytes))
                .unwrap_or_default();
            for index in indexes {
                let request = &requests[index];
                let mut symbol = loader
                    .find_symbol(request.relative_address)
                    .map(demangle_addr2line_name)
                    .or_else(|| rust_addr2line_frame_name(&loader, request.relative_address));
                specialize_symbol_from_debug_strings(&mut symbol, &debug_names);
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
            let object_bytes = std::fs::read(&path).ok();
            let debug_names = object_bytes
                .as_deref()
                .map(DebugStringNameIndex::from_object_bytes)
                .unwrap_or_default();
            let perf_dwarf = object_bytes
                .as_deref()
                .and_then(|bytes| PerfDwarfNameResolver::from_object_bytes(bytes).ok());
            for index in indexes {
                let request = &requests[index];
                let mut frames = perf_dwarf
                    .as_ref()
                    .and_then(|resolver| resolver.frame_names(request.relative_address))
                    .map(perf_inline_frame_order)
                    .or_else(|| rust_addr2line_frame_names(&loader, request.relative_address))
                    .or_else(|| {
                        loader
                            .find_symbol(request.relative_address)
                            .map(|name| vec![demangle_addr2line_name(name)])
                    })
                    .unwrap_or_default();
                specialize_frames_from_debug_strings(&mut frames, &debug_names);
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
        let load_section = |id: gimli::SectionId| {
            let data = object
                .section_by_name(id.name())
                .and_then(|section| section.uncompressed_data().ok())
                .unwrap_or(Cow::Borrowed(&[][..]));
            Ok::<_, gimli::Error>(gimli::EndianArcSlice::new(
                std::sync::Arc::<[u8]>::from(data.as_ref()),
                endian,
            ))
        };
        let dwarf = gimli::Dwarf::load(load_section)?;
        Ok(Self { dwarf })
    }

    fn frame_names(&self, address: u64) -> Option<Vec<String>> {
        perf_dwarf_frame_names(&self.dwarf, address)
    }
}

fn perf_dwarf_frame_names<R>(dwarf: &gimli::Dwarf<R>, address: u64) -> Option<Vec<String>>
where
    R: gimli::Reader,
{
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        if !unit_contains_address(dwarf, &unit, address) {
            continue;
        }
        if let Some(frames) = perf_dwarf_frame_names_from_unit(dwarf, &unit, address) {
            return Some(frames);
        }
    }
    None
}

fn unit_contains_address<R>(dwarf: &gimli::Dwarf<R>, unit: &gimli::Unit<R>, address: u64) -> bool
where
    R: gimli::Reader,
{
    let Ok(mut ranges) = dwarf.unit_ranges(unit) else {
        return true;
    };
    while let Ok(Some(range)) = ranges.next() {
        if range.begin <= address && address < range.end {
            return true;
        }
    }
    false
}

fn perf_dwarf_frame_names_from_unit<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    address: u64,
) -> Option<Vec<String>>
where
    R: gimli::Reader,
{
    let mut tree = unit.entries_tree(None).ok()?;
    let root = tree.root().ok()?;
    let mut children = root.children();
    while let Ok(Some(child)) = children.next() {
        if let Some(mut frames) = perf_dwarf_frames_from_node(dwarf, unit, child, address, false) {
            frames.reverse();
            return Some(frames);
        }
    }
    None
}

fn perf_dwarf_frames_from_node<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    node: gimli::EntriesTreeNode<'_, '_, '_, R>,
    address: u64,
    looking_for_inline: bool,
) -> Option<Vec<String>>
where
    R: gimli::Reader,
{
    let entry = node.entry();
    let expected_tag = if looking_for_inline {
        gimli::DW_TAG_inlined_subroutine
    } else {
        gimli::DW_TAG_subprogram
    };
    if entry.tag() == expected_tag && die_contains_address(dwarf, unit, entry, address) {
        let mut frames = Vec::new();
        if let Some(name) = perf_dwarf_die_name(dwarf, unit, entry) {
            frames.push(perf_dwarf_function_name(&name));
        }
        let mut children = node.children();
        while let Ok(Some(child)) = children.next() {
            if let Some(mut child_frames) =
                perf_dwarf_frames_from_node(dwarf, unit, child, address, true)
            {
                frames.append(&mut child_frames);
                break;
            }
        }
        return (!frames.is_empty()).then_some(frames);
    }

    let mut children = node.children();
    while let Ok(Some(child)) = children.next() {
        if let Some(frames) =
            perf_dwarf_frames_from_node(dwarf, unit, child, address, looking_for_inline)
        {
            return Some(frames);
        }
    }
    None
}

fn die_contains_address<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, R>,
    address: u64,
) -> bool
where
    R: gimli::Reader,
{
    let Ok(mut ranges) = dwarf.die_ranges(unit, entry) else {
        return false;
    };
    while let Ok(Some(range)) = ranges.next() {
        if range.begin <= address && address < range.end {
            return true;
        }
    }
    false
}

fn perf_dwarf_die_name<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, R>,
) -> Option<String>
where
    R: gimli::Reader,
{
    entry
        .attr(gimli::DW_AT_name)
        .ok()
        .flatten()
        .and_then(|attr| dwarf.attr_string(unit, attr.value()).ok())
        .and_then(|name| name.to_string_lossy().ok().map(Cow::into_owned))
        .or_else(|| {
            entry
                .attr(gimli::DW_AT_abstract_origin)
                .ok()
                .flatten()
                .and_then(|attr| perf_dwarf_origin_name(dwarf, unit, &attr.value(), 16))
        })
        .or_else(|| {
            entry
                .attr(gimli::DW_AT_specification)
                .ok()
                .flatten()
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
        .ok()
        .flatten()
        .and_then(|attr| dwarf.attr_string(unit, attr.value()).ok())
        .and_then(|name| name.to_string_lossy().ok().map(Cow::into_owned))
        .or_else(|| {
            entry
                .attr(gimli::DW_AT_abstract_origin)
                .ok()
                .flatten()
                .and_then(|attr| {
                    perf_dwarf_origin_name(dwarf, unit, &attr.value(), recursion_limit - 1)
                })
        })
        .or_else(|| {
            entry
                .attr(gimli::DW_AT_specification)
                .ok()
                .flatten()
                .and_then(|attr| {
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
        let lookup_leaf = generic_function_leaf(function_leaf).unwrap_or(function_leaf);
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
    name.starts_with("std::fs::") || name.starts_with("std::io::")
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

#[cfg(test)]
mod tests {
    use object::{Object, ObjectSegment};

    use super::clean_object_symbol_request;

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
}
