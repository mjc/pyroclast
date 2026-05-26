use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use serde::Serialize;

use crate::perfdata::build_id::kernel_build_id_from_perfdata;
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

pub struct PerfSymbolResolver<O> {
    object_resolver: O,
    debug_dir: Option<PathBuf>,
    kernel_elf: Option<PathBuf>,
    kallsyms: Option<Kallsyms>,
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
    PerfSymbolResolver::new(runner)
        .with_perfdata_file_kernel_cache(perfdata, &perf_debug_dir(home))
        .with_system_kallsyms()
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
        .with_system_kallsyms()
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
        Some(home) => perf_symbol_resolver_for_perfdata_file_with_object(
            object_resolver,
            perfdata,
            Path::new(&home),
        )
        .with_system_map_candidates(current_linux_system_map_candidates()),
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
    pub fn with_system_map_candidates(self, candidates: impl IntoIterator<Item = PathBuf>) -> Self {
        if self.kernel_elf.is_some() {
            return self;
        }
        match Kallsyms::load_first_system_map_candidate(candidates) {
            Some(kallsyms) => self.with_kallsyms(kallsyms),
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
        if kernel_elf.exists() {
            return self_with_debug_dir.with_kernel_elf(kernel_elf);
        }
        match Kallsyms::load_perf_build_id_cache(debug_dir, &build_id) {
            Some(kallsyms) => self_with_debug_dir.with_kallsyms(kallsyms),
            None => self_with_debug_dir,
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
        if self.kernel_elf.is_some() || self.kallsyms.is_some() {
            return self;
        }
        match std::fs::read_to_string("/proc/kallsyms")
            .ok()
            .and_then(|text| Kallsyms::parse(&text).ok())
        {
            Some(kallsyms) => self.with_kallsyms(kallsyms),
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
            symbols.insert(address, symbol.clone());
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

        for (index, request) in requests.iter().enumerate() {
            if is_kernel_symbol_path(&request.path) {
                if let Some(kernel_elf) = &self.kernel_elf {
                    kernel_elf_indexes.push(index);
                    kernel_elf_requests.push(SymbolRequest {
                        path: kernel_elf.clone(),
                        relative_address: request.relative_address,
                        build_id: None,
                        kernel_relocation: None,
                    });
                } else {
                    resolved[index] = self
                        .kallsyms
                        .as_ref()
                        .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request));
                }
            } else {
                user_indexes.push(index);
                user_requests.push(self.object_symbol_request(request));
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

        for (index, request) in requests.iter().enumerate() {
            if is_kernel_symbol_path(&request.path) {
                if let Some(kernel_elf) = &self.kernel_elf {
                    kernel_elf_indexes.push(index);
                    kernel_elf_requests.push(SymbolRequest {
                        path: kernel_elf.clone(),
                        relative_address: request.relative_address,
                        build_id: None,
                        kernel_relocation: None,
                    });
                } else if let Some(symbol) = self
                    .kallsyms
                    .as_ref()
                    .and_then(|kallsyms| resolve_kernel_kallsyms(kallsyms, request))
                {
                    resolved[index] = vec![symbol];
                }
            } else {
                user_indexes.push(index);
                user_requests.push(self.object_symbol_request(request));
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
    fn object_symbol_request(&self, request: &SymbolRequest) -> SymbolRequest {
        let Some(debug_dir) = &self.debug_dir else {
            return request.clone();
        };
        let Some(build_id) = &request.build_id else {
            return request.clone();
        };
        let elf = perf_build_id_elf_path(debug_dir, build_id);
        if !elf.exists() {
            return request.clone();
        }
        SymbolRequest {
            path: elf,
            relative_address: request.relative_address,
            build_id: None,
            kernel_relocation: None,
        }
    }
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
            for index in indexes {
                let request = &requests[index];
                let symbol = loader
                    .find_symbol(request.relative_address)
                    .map(demangle_addr2line_name)
                    .or_else(|| rust_addr2line_frame_name(&loader, request.relative_address));
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
            for index in indexes {
                let request = &requests[index];
                let frames = rust_addr2line_frame_names(&loader, request.relative_address)
                    .or_else(|| {
                        loader
                            .find_symbol(request.relative_address)
                            .map(|name| vec![demangle_addr2line_name(name)])
                    })
                    .unwrap_or_default();
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
    perf_symbol_name(&addr2line::demangle_auto(Cow::Borrowed(name), None))
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
            names.push(perf_symbol_name(&name));
        }
    }
    (!names.is_empty()).then_some(names)
}

#[must_use]
pub fn perf_symbol_name(name: &str) -> String {
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
        .and_then(|index| name.get(index + 2..))
        .filter(|part| !part.is_empty())
        .unwrap_or(name)
        .to_string()
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
    })
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
