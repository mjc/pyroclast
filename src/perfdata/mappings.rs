use crate::perfdata::records::{
    Mmap2BuildIdRecord, Mmap2Record, MmapRecord, PERF_RECORD_MISC_CPUMODE_MASK,
    PERF_RECORD_MISC_CPUMODE_USER,
};
use crate::symbols::KernelRelocation;
use hashbrown::{HashMap, HashSet};
use rustc_hash::FxBuildHasher;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const PROT_EXEC: u32 = 4;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MmapTable {
    mappings: Vec<Mapping>,
    mappings_by_pid: HashMap<u32, Vec<IndexedMapping>, FxBuildHasher>,
    symbol_source_ids: HashMap<SymbolSourceKey, usize, FxBuildHasher>,
    pids_with_mappings: HashSet<u32, FxBuildHasher>,
    executable_pids: HashSet<u32, FxBuildHasher>,
    has_global_mappings: bool,
    has_global_executable_mappings: bool,
    #[cfg(test)]
    index_searches: std::cell::Cell<usize>,
    #[cfg(test)]
    bucket_searches: std::cell::Cell<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMapping {
    pub path: String,
    pub relative_address: u64,
    pub start: u64,
    pub end: u64,
    pub build_id: Option<Vec<u8>>,
    pub file_identity: Option<FileIdentity>,
    pub kernel_relocation: Option<KernelRelocation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMappingRef<'a> {
    pub symbol_source_id: usize,
    pub path: &'a str,
    pub relative_address: u64,
    pub start: u64,
    pub end: u64,
    pub build_id: Option<&'a [u8]>,
    pub file_identity: Option<FileIdentity>,
    pub kernel_relocation: Option<KernelRelocation>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MappedFrame<'a> {
    mapping: &'a Mapping,
    pub(crate) relative_address: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum ModuleFallbackKind {
    #[default]
    Literal,
    Escaped,
    Normalized,
    RawFunction,
    Skip,
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MappingPathLayout {
    pub(crate) basename_start: usize,
    pub(crate) last_space: Option<usize>,
    pub(crate) basename_has_parentheses: bool,
    pub(crate) basename_needs_escaping: bool,
    pub(crate) fallback: ModuleFallbackKind,
    bracketed: bool,
}

impl MappingPathLayout {
    pub(crate) fn new(path: &str) -> Self {
        let basename_start = memchr::memrchr(b'/', path.as_bytes()).map_or(0, |index| index + 1);
        let mut layout = Self {
            bracketed: path.starts_with('['),
            basename_start,
            last_space: memchr::memrchr(b' ', path.as_bytes()),
            basename_has_parentheses: path[basename_start..].contains('('),
            basename_needs_escaping: memchr::memchr3(
                b';',
                b'\r',
                b'\n',
                &path.as_bytes()[basename_start..],
            )
            .is_some(),
            fallback: ModuleFallbackKind::Literal,
        };
        // Inferno perf.rs:stack_line_parts and with_module_fallback. Store
        // path classification, never an output-specific rendered label.
        layout.fallback = if path == "[unknown]" {
            ModuleFallbackKind::Unknown
        } else if let Some(index) = layout.last_space {
            if path.as_bytes().get(index + 1) == Some(&b'(') {
                ModuleFallbackKind::RawFunction
            } else {
                ModuleFallbackKind::Skip
            }
        } else if layout.basename_has_parentheses {
            ModuleFallbackKind::Normalized
        } else if layout.basename_needs_escaping {
            ModuleFallbackKind::Escaped
        } else {
            ModuleFallbackKind::Literal
        };
        layout
    }
}

impl<'a> MappedFrame<'a> {
    fn new(mapping: &'a Mapping, ip: u64) -> Self {
        let relative_address = mapping.relative_address(ip);
        Self {
            mapping,
            relative_address,
        }
    }

    pub(crate) fn symbol_source_id(self) -> usize {
        self.mapping.symbol_source_id
    }
    pub(crate) fn path(self) -> &'a str {
        &self.mapping.path
    }
    pub(crate) fn kernel_range(self) -> Option<(u64, u64)> {
        self.is_kernel()
            .then(|| (self.mapping.start, self.mapping.end()))
    }
    pub(crate) fn is_kernel(self) -> bool {
        crate::perfdata::samples::is_kernel_space_frame(self.relative_address)
            && self.mapping.path_layout.bracketed
    }
    pub(crate) fn path_layout(self) -> &'a MappingPathLayout {
        &self.mapping.path_layout
    }
    pub(crate) fn resolved_ref(self) -> ResolvedMappingRef<'a> {
        ResolvedMappingRef {
            symbol_source_id: self.mapping.symbol_source_id,
            path: &self.mapping.path,
            relative_address: self.relative_address,
            start: self.mapping.start,
            end: self.mapping.end(),
            build_id: self.mapping.build_id.as_deref(),
            file_identity: self.mapping.file_identity,
            kernel_relocation: self.mapping.kernel_relocation(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MappingResolveCache {
    pid: Option<u32>,
    pid_index: Option<usize>,
    global_index: Option<usize>,
}

pub(crate) struct FrameMappingContext<'a> {
    table: &'a MmapTable,
    pid: u32,
    user: &'a [IndexedMapping],
    global: &'a [IndexedMapping],
}

impl<'a> FrameMappingContext<'a> {
    pub(crate) fn resolve_user(
        &self,
        ip: u64,
        cache: &mut MappingResolveCache,
    ) -> Option<MappedFrame<'a>> {
        let index = self.table.resolve_bucket_with_cache(
            self.pid,
            self.user,
            ip,
            &mut cache.pid_index,
            Mapping::is_user_cpumode,
        )?;
        Some(MappedFrame::new(&self.table.mappings[index], ip))
    }

    pub(crate) fn resolve(
        &self,
        ip: u64,
        cache: &mut MappingResolveCache,
    ) -> Option<MappedFrame<'a>> {
        let global = self.table.resolve_bucket_with_cache(
            u32::MAX,
            self.global,
            ip,
            &mut cache.global_index,
            |_| true,
        );
        let index = if self.pid == u32::MAX {
            global?
        } else {
            let user = self.table.resolve_bucket_with_cache(
                self.pid,
                self.user,
                ip,
                &mut cache.pid_index,
                |_| true,
            );
            match (user, global) {
                (Some(left), Some(right)) => {
                    if self.table.mappings[left].start >= self.table.mappings[right].start {
                        left
                    } else {
                        right
                    }
                }
                (Some(index), None) | (None, Some(index)) => index,
                (None, None) => return None,
            }
        };
        Some(MappedFrame::new(&self.table.mappings[index], ip))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FileIdentity {
    pub major: u32,
    pub minor: u32,
    pub inode: u64,
    pub inode_generation: u64,
}

/// Reports whether the on-disk file at `path` carries the same backing-storage
/// identity (device major/minor + inode, and inode generation when recorded)
/// that perf captured in the `PERF_RECORD_MMAP2` event.
///
/// This mirrors perf's `__dso_id__cmp` (tools/perf/util/dso.c), which compares
/// `maj`/`min`/`ino` together — never the inode alone — so two files sharing an
/// inode number on different filesystems are not treated as the same backing
/// store. Inode numbers are unique only within a single device, so comparing
/// `ino` without the device would admit cross-filesystem false matches.
///
/// Note: perf does not use this device/inode identity to *reject* an on-disk
/// file before symbolizing or unwinding from it (`dso__load` and
/// `do_open`/`__open_dso` trust the path and only validate build-ids when both
/// the recorded and on-disk build-ids are defined). This helper exists for the
/// dso-instance identity comparison perf performs in `__dso_id__cmp`, and must
/// match that semantics: device-aware, with absent generation skipped.
#[must_use]
#[cfg(unix)]
pub fn file_matches_recorded_identity(path: &Path, identity: FileIdentity) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| {
        let device = metadata.dev();
        // PERF_RECORD_MMAP2 records maj/min as MAJOR(dev)/MINOR(dev); decompose
        // the on-disk st_dev with the matching macros before comparing.
        major(device) == identity.major
            && minor(device) == identity.minor
            && metadata.ino() == identity.inode
    })
}

#[cfg(not(unix))]
pub fn file_matches_recorded_identity(_path: &Path, _identity: FileIdentity) -> bool {
    false
}

/// Extracts the device major number from a `st_dev` value using the glibc
/// encoding userspace `stat` reports, matching the kernel `MAJOR()` macro perf
/// records in `PERF_RECORD_MMAP2`.
#[cfg(unix)]
fn major(device: u64) -> u32 {
    u32::try_from(((device >> 8) & 0xfff) | ((device >> 32) & 0xffff_f000))
        .expect("masked device major fits u32")
}

/// Extracts the device minor number from a `st_dev` value, matching the kernel
/// `MINOR()` macro perf records in `PERF_RECORD_MMAP2`.
#[cfg(unix)]
fn minor(device: u64) -> u32 {
    u32::try_from((device & 0xff) | ((device >> 12) & 0xffff_ff00))
        .expect("masked device minor fits u32")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserMapping<'a> {
    pub pid: u32,
    pub start: u64,
    pub len: u64,
    pub pgoff: u64,
    pub prot: Option<u32>,
    pub path: &'a str,
    pub build_id: Option<&'a [u8]>,
    pub file_identity: Option<FileIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Mapping {
    pid: u32,
    start: u64,
    len: u64,
    pgoff: u64,
    symbol_source_id: usize,
    path: String,
    path_layout: MappingPathLayout,
    build_id: Option<Vec<u8>>,
    file_identity: Option<FileIdentity>,
    prot: Option<u32>,
    cpumode: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IndexedMapping {
    start: u64,
    max_end: u64,
    index: usize,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SymbolSourceKey {
    path: String,
    build_id: Option<Vec<u8>>,
    file_identity: Option<FileIdentity>,
    kernel_relocation: Option<KernelRelocation>,
}

impl MmapTable {
    #[cfg(test)]
    pub(crate) fn index_search_count(&self) -> usize {
        self.index_searches.get()
    }

    #[cfg(test)]
    pub(crate) fn bucket_search_count(&self) -> usize {
        self.bucket_searches.get()
    }

    fn bucket(&self, pid: u32) -> &[IndexedMapping] {
        #[cfg(test)]
        self.bucket_searches.set(self.bucket_searches.get() + 1);
        self.mappings_by_pid.get(&pid).map_or(&[], Vec::as_slice)
    }

    pub(crate) fn frame_context(
        &self,
        pid: u32,
        cache: &mut MappingResolveCache,
    ) -> FrameMappingContext<'_> {
        if cache.pid != Some(pid) {
            cache.pid = Some(pid);
            cache.pid_index = None;
        }
        let user = self.bucket(pid);
        let global = if pid == u32::MAX {
            user
        } else {
            self.bucket(u32::MAX)
        };
        FrameMappingContext {
            table: self,
            pid,
            user,
            global,
        }
    }

    pub fn insert_mmap(&mut self, record: MmapRecord) {
        self.insert_mapping(Mapping {
            pid: record.pid,
            start: record.start,
            len: record.len,
            pgoff: record.pgoff,
            symbol_source_id: 0,
            path: record.path,
            path_layout: MappingPathLayout::default(),
            build_id: None,
            file_identity: None,
            prot: None,
            cpumode: PERF_RECORD_MISC_CPUMODE_USER,
        });
    }

    pub(crate) fn insert_mmap_with_misc(&mut self, record: MmapRecord, misc: u16) {
        self.insert_mapping(Mapping {
            pid: record.pid,
            start: record.start,
            len: record.len,
            pgoff: record.pgoff,
            symbol_source_id: 0,
            path: record.path,
            path_layout: MappingPathLayout::default(),
            build_id: None,
            file_identity: None,
            prot: None,
            cpumode: mapping_cpumode_from_misc(misc),
        });
    }

    pub fn insert_mmap2(&mut self, record: Mmap2Record) {
        self.insert_mmap2_with_build_id(record, None);
    }

    pub fn insert_mmap2_with_build_id(&mut self, record: Mmap2Record, build_id: Option<Vec<u8>>) {
        self.insert_mmap2_with_build_id_and_misc(record, build_id, PERF_RECORD_MISC_CPUMODE_USER);
    }

    pub(crate) fn insert_mmap2_with_misc(&mut self, record: Mmap2Record, misc: u16) {
        self.insert_mmap2_with_build_id_and_misc(record, None, mapping_cpumode_from_misc(misc));
    }

    pub(crate) fn insert_mmap2_with_build_id_and_misc(
        &mut self,
        record: Mmap2Record,
        build_id: Option<Vec<u8>>,
        misc: u16,
    ) {
        self.insert_mapping(Mapping {
            pid: record.pid,
            start: record.start,
            len: record.len,
            pgoff: record.pgoff,
            symbol_source_id: 0,
            path: record.path,
            path_layout: MappingPathLayout::default(),
            build_id,
            file_identity: Some(FileIdentity {
                major: record.major,
                minor: record.minor,
                inode: record.inode,
                inode_generation: record.inode_generation,
            }),
            prot: Some(record.prot),
            cpumode: mapping_cpumode_from_misc(misc),
        });
    }

    pub fn insert_mmap2_build_id(&mut self, record: Mmap2BuildIdRecord) {
        self.insert_mmap2_build_id_with_misc(record, PERF_RECORD_MISC_CPUMODE_USER);
    }

    pub(crate) fn insert_mmap2_build_id_with_misc(
        &mut self,
        record: Mmap2BuildIdRecord,
        misc: u16,
    ) {
        self.insert_mapping(Mapping {
            pid: record.pid,
            start: record.start,
            len: record.len,
            pgoff: record.pgoff,
            symbol_source_id: 0,
            path: record.path,
            path_layout: MappingPathLayout::default(),
            build_id: Some(record.build_id),
            file_identity: None,
            prot: Some(record.prot),
            cpumode: mapping_cpumode_from_misc(misc),
        });
    }

    pub fn clone_pid_mappings(&mut self, parent_pid: u32, child_pid: u32) {
        if parent_pid == child_pid {
            return;
        }

        self.mappings.retain(|mapping| mapping.pid != child_pid);
        let cloned_mappings = self
            .mappings
            .iter()
            .filter(|mapping| mapping.pid == parent_pid)
            .cloned()
            .map(|mut mapping| {
                mapping.pid = child_pid;
                mapping.symbol_source_id = 0;
                mapping
            })
            .collect::<Vec<_>>();
        self.rebuild_pid_indexes();
        for mapping in cloned_mappings {
            self.insert_mapping(mapping);
        }
    }

    fn insert_mapping(&mut self, mut mapping: Mapping) {
        mapping.path_layout = MappingPathLayout::new(&mapping.path);
        // Common case: the new mapping does not overlap any existing mapping for
        // its pid. Detect this in O(log n + matches) using the per-pid interval
        // index and take a pure incremental insert, skipping the whole-table
        // `mem::take` and global index rebuild. Only an actual overlap (a split)
        // falls back to the rebuild-based path, which preserves perf's exact
        // retained-mapping ordering and split semantics.
        if !self.has_overlapping_mapping_for_pid(mapping.pid, mapping.start, mapping.end()) {
            self.insert_mapping_without_overlap_fix(mapping);
            return;
        }
        let split_mappings = self.remove_overlapping_mappings_like_perf(&mapping);
        for split in split_mappings {
            self.insert_mapping_without_overlap_fix(split);
        }
        self.insert_mapping_without_overlap_fix(mapping);
    }

    fn remove_overlapping_mappings_like_perf(&mut self, new_mapping: &Mapping) -> Vec<Mapping> {
        let mut kept = Vec::with_capacity(self.mappings.len());
        let mut split_mappings = Vec::new();
        for mapping in std::mem::take(&mut self.mappings) {
            if mapping.pid != new_mapping.pid || !mapping.overlaps(new_mapping) {
                kept.push(mapping);
                continue;
            }
            if mapping.start < new_mapping.start {
                let mut before = mapping.clone();
                before.len = new_mapping.start - mapping.start;
                split_mappings.push(before);
            }
            if mapping.end() > new_mapping.end() {
                let mut after = mapping;
                let old_start = after.start;
                let old_end = after.end();
                after.start = new_mapping.end();
                after.pgoff = after.pgoff.saturating_add(after.start - old_start);
                after.len = old_end - after.start;
                split_mappings.push(after);
            }
        }
        self.mappings = kept;
        self.rebuild_pid_indexes();
        split_mappings
    }

    /// Returns whether any existing mapping for `pid` overlaps the half-open
    /// range `[start, end)`, using the per-pid interval index so the common
    /// no-overlap case is `O(log n + matches)` rather than a full scan.
    fn has_overlapping_mapping_for_pid(&self, pid: u32, start: u64, end: u64) -> bool {
        self.any_indexed_mapping_in_range(pid, start, end, |_mapping| true)
    }

    /// Walks the per-pid interval index for mappings whose `[start, end)` range
    /// intersects `[start, end)` and reports whether any matching mapping also
    /// satisfies `predicate`. Mirrors the `max_end`-augmented descent used by
    /// `resolve_mapping_index_for_pid`, but tests interval intersection instead
    /// of point containment.
    fn any_indexed_mapping_in_range(
        &self,
        pid: u32,
        start: u64,
        end: u64,
        mut predicate: impl FnMut(&Mapping) -> bool,
    ) -> bool {
        let Some(bucket) = self.mappings_by_pid.get(&pid) else {
            return false;
        };
        // Mappings are sorted by `start`; only those with `start < end` can
        // overlap, so descend from the last such entry. The augmented `max_end`
        // lets us stop once no earlier mapping can reach past `start`.
        let mut upper_bound = bucket.partition_point(|indexed| indexed.start < end);
        while upper_bound > 0 {
            upper_bound -= 1;
            let indexed = &bucket[upper_bound];
            if indexed.max_end <= start {
                break;
            }
            let mapping = &self.mappings[indexed.index];
            if start < mapping.end() && mapping.start < end && predicate(mapping) {
                return true;
            }
        }
        false
    }

    fn insert_mapping_without_overlap_fix(&mut self, mut mapping: Mapping) {
        let pid = mapping.pid;
        let start = mapping.start;
        let may_execute = mapping.may_execute();
        mapping.symbol_source_id = self.intern_symbol_source(&mapping);
        let index = self.mappings.len();
        let end = mapping.end();
        self.mappings.push(mapping);
        let bucket = self.mappings_by_pid.entry(pid).or_default();
        let position = bucket.partition_point(|indexed| indexed.start <= start);
        let max_end = if position == 0 {
            end
        } else {
            bucket[position - 1].max_end.max(end)
        };
        bucket.insert(
            position,
            IndexedMapping {
                start,
                max_end,
                index,
            },
        );
        for bucket_index in position + 1..bucket.len() {
            let mapping_end = self.mappings[bucket[bucket_index].index].end();
            let updated_max_end = bucket[bucket_index - 1].max_end.max(mapping_end);
            if bucket[bucket_index].max_end == updated_max_end {
                break;
            }
            bucket[bucket_index].max_end = updated_max_end;
        }
        if pid == u32::MAX {
            self.has_global_mappings = true;
            self.has_global_executable_mappings |= may_execute;
        } else {
            self.pids_with_mappings.insert(pid);
            if may_execute {
                self.executable_pids.insert(pid);
            }
        }
    }

    fn rebuild_pid_indexes(&mut self) {
        self.mappings_by_pid.clear();
        self.pids_with_mappings.clear();
        self.executable_pids.clear();
        self.has_global_mappings = false;
        self.has_global_executable_mappings = false;

        let indexed_mappings = self
            .mappings
            .iter()
            .enumerate()
            .map(|(index, mapping)| (index, mapping.pid, mapping.start, mapping.end()))
            .collect::<Vec<_>>();
        for (index, pid, start, end) in indexed_mappings {
            let bucket = self.mappings_by_pid.entry(pid).or_default();
            let position = bucket.partition_point(|indexed| indexed.start <= start);
            let max_end = if position == 0 {
                end
            } else {
                bucket[position - 1].max_end.max(end)
            };
            bucket.insert(
                position,
                IndexedMapping {
                    start,
                    max_end,
                    index,
                },
            );
            for bucket_index in position + 1..bucket.len() {
                let mapping_end = self.mappings[bucket[bucket_index].index].end();
                let updated_max_end = bucket[bucket_index - 1].max_end.max(mapping_end);
                if bucket[bucket_index].max_end == updated_max_end {
                    break;
                }
                bucket[bucket_index].max_end = updated_max_end;
            }

            let may_execute = self.mappings[index].may_execute();
            if pid == u32::MAX {
                self.has_global_mappings = true;
                self.has_global_executable_mappings |= may_execute;
            } else {
                self.pids_with_mappings.insert(pid);
                if may_execute {
                    self.executable_pids.insert(pid);
                }
            }
        }
    }

    #[must_use]
    pub fn resolve(&self, pid: u32, ip: u64) -> Option<ResolvedMapping> {
        self.resolve_ref(pid, ip).map(|mapping| ResolvedMapping {
            path: mapping.path.to_string(),
            relative_address: mapping.relative_address,
            start: mapping.start,
            end: mapping.end,
            build_id: mapping.build_id.map(<[u8]>::to_vec),
            file_identity: mapping.file_identity,
            kernel_relocation: mapping.kernel_relocation,
        })
    }

    #[must_use]
    pub fn resolve_ref(&self, pid: u32, ip: u64) -> Option<ResolvedMappingRef<'_>> {
        self.resolve_mapping_with_index(pid, ip)
            .map(|(_, mapping)| ResolvedMappingRef {
                symbol_source_id: mapping.symbol_source_id,
                path: mapping.path.as_str(),
                relative_address: mapping.relative_address(ip),
                start: mapping.start,
                end: mapping.end(),
                build_id: mapping.build_id.as_deref(),
                file_identity: mapping.file_identity,
                kernel_relocation: mapping.kernel_relocation(),
            })
    }

    #[must_use]
    pub(crate) fn resolve_ref_cached(
        &self,
        pid: u32,
        ip: u64,
        cache: &mut MappingResolveCache,
    ) -> Option<ResolvedMappingRef<'_>> {
        self.resolve_frame_cached(pid, ip, cache)
            .map(MappedFrame::resolved_ref)
    }

    pub(crate) fn resolve_frame_cached(
        &self,
        pid: u32,
        ip: u64,
        cache: &mut MappingResolveCache,
    ) -> Option<MappedFrame<'_>> {
        self.resolve_mapping_with_index_cached(pid, ip, cache)
            .map(|(_, mapping)| MappedFrame::new(mapping, ip))
    }

    #[must_use]
    pub(crate) fn resolve_user_pid_ref_cached(
        &self,
        pid: u32,
        ip: u64,
        cache: &mut MappingResolveCache,
    ) -> Option<ResolvedMappingRef<'_>> {
        self.resolve_user_frame_cached(pid, ip, cache)
            .map(MappedFrame::resolved_ref)
    }

    pub(crate) fn resolve_user_frame_cached(
        &self,
        pid: u32,
        ip: u64,
        cache: &mut MappingResolveCache,
    ) -> Option<MappedFrame<'_>> {
        if cache.pid != Some(pid) {
            cache.pid = Some(pid);
            cache.pid_index = None;
        }
        self.resolve_mapping_index_for_pid_with_cache_and_predicate(
            pid,
            ip,
            &mut cache.pid_index,
            Mapping::is_user_cpumode,
        )
        .map(|index| MappedFrame::new(&self.mappings[index], ip))
    }

    #[must_use]
    pub fn has_mapping_for_pid(&self, pid: u32, ip: u64) -> bool {
        self.resolve_mapping(pid, ip).is_some()
    }

    #[must_use]
    pub(crate) fn has_overlapping_user_mapping_for_pid(
        &self,
        pid: u32,
        start: u64,
        len: u64,
    ) -> bool {
        let end = start.saturating_add(len);
        self.any_indexed_mapping_in_range(pid, start, end, Mapping::is_user_file_mapping)
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn has_mapping_for_pid_cached(
        &self,
        pid: u32,
        ip: u64,
        cache: &mut MappingResolveCache,
    ) -> bool {
        self.resolve_mapping_with_index_cached(pid, ip, cache)
            .is_some()
    }

    #[must_use]
    pub fn mapping_path(&self, pid: u32, ip: u64) -> Option<&str> {
        self.resolve_mapping(pid, ip)
            .map(|mapping| mapping.path.as_str())
    }

    pub fn user_mappings(&self) -> impl Iterator<Item = UserMapping<'_>> {
        self.mappings
            .iter()
            .filter(|mapping| mapping.is_user_file_mapping())
            .map(|mapping| UserMapping {
                pid: mapping.pid,
                start: mapping.start,
                len: mapping.len,
                pgoff: mapping.pgoff,
                prot: mapping.prot,
                path: &mapping.path,
                build_id: mapping.build_id.as_deref(),
                file_identity: mapping.file_identity,
            })
    }

    pub(crate) fn user_mapping_for_pid_ip(&self, pid: u32, ip: u64) -> Option<UserMapping<'_>> {
        self.resolve_mapping(pid, ip).map(|mapping| UserMapping {
            pid: mapping.pid,
            start: mapping.start,
            len: mapping.len,
            pgoff: mapping.pgoff,
            prot: mapping.prot,
            path: &mapping.path,
            build_id: mapping.build_id.as_deref(),
            file_identity: mapping.file_identity,
        })
    }

    #[must_use]
    pub fn has_mappings_for_pid(&self, pid: u32) -> bool {
        self.has_global_mappings || self.pids_with_mappings.contains(&pid)
    }

    #[must_use]
    pub fn has_executable_mappings_for_pid(&self, pid: u32) -> bool {
        self.has_global_executable_mappings || self.executable_pids.contains(&pid)
    }

    #[must_use]
    pub fn is_known_non_executable(&self, pid: u32, ip: u64) -> bool {
        self.resolve_mapping(pid, ip)
            .is_some_and(Mapping::is_known_non_executable)
    }

    fn resolve_mapping(&self, pid: u32, ip: u64) -> Option<&Mapping> {
        self.resolve_mapping_with_index(pid, ip)
            .map(|(_, mapping)| mapping)
    }

    fn resolve_mapping_with_index(&self, pid: u32, ip: u64) -> Option<(usize, &Mapping)> {
        if pid == u32::MAX {
            let index = self.resolve_mapping_index_for_pid(pid, ip)?;
            return Some((index, &self.mappings[index]));
        }
        match (
            self.resolve_mapping_index_for_pid(pid, ip),
            self.resolve_mapping_index_for_pid(u32::MAX, ip),
        ) {
            (Some(left), Some(right)) => {
                let left_mapping = &self.mappings[left];
                let right_mapping = &self.mappings[right];
                Some(if left_mapping.start >= right_mapping.start {
                    (left, left_mapping)
                } else {
                    (right, right_mapping)
                })
            }
            (Some(index), None) | (None, Some(index)) => Some((index, &self.mappings[index])),
            (None, None) => None,
        }
    }

    fn resolve_mapping_with_index_cached(
        &self,
        pid: u32,
        ip: u64,
        cache: &mut MappingResolveCache,
    ) -> Option<(usize, &Mapping)> {
        if pid == u32::MAX {
            let index =
                self.resolve_mapping_index_for_pid_with_cache(pid, ip, &mut cache.global_index)?;
            return Some((index, &self.mappings[index]));
        }
        if cache.pid != Some(pid) {
            cache.pid = Some(pid);
            cache.pid_index = None;
        }
        match (
            self.resolve_mapping_index_for_pid_with_cache(pid, ip, &mut cache.pid_index),
            self.resolve_mapping_index_for_pid_with_cache(u32::MAX, ip, &mut cache.global_index),
        ) {
            (Some(left), Some(right)) => {
                let left_mapping = &self.mappings[left];
                let right_mapping = &self.mappings[right];
                Some(if left_mapping.start >= right_mapping.start {
                    (left, left_mapping)
                } else {
                    (right, right_mapping)
                })
            }
            (Some(index), None) | (None, Some(index)) => Some((index, &self.mappings[index])),
            (None, None) => None,
        }
    }

    fn resolve_mapping_index_for_pid(&self, pid: u32, ip: u64) -> Option<usize> {
        #[cfg(test)]
        self.index_searches.set(self.index_searches.get() + 1);
        let bucket = self.bucket(pid);
        let mut upper_bound = bucket.partition_point(|indexed| indexed.start <= ip);
        let mut latest_matching_index = None;
        while upper_bound > 0 {
            upper_bound -= 1;
            let indexed = &bucket[upper_bound];
            if indexed.max_end <= ip {
                break;
            }
            let index = indexed.index;
            let mapping = &self.mappings[index];
            if ip < mapping.end() {
                latest_matching_index = latest_matching_index.max(Some(index));
            }
        }
        latest_matching_index
    }

    fn resolve_mapping_index_for_pid_with_cache(
        &self,
        pid: u32,
        ip: u64,
        cached_index: &mut Option<usize>,
    ) -> Option<usize> {
        self.resolve_mapping_index_for_pid_with_cache_and_predicate(pid, ip, cached_index, |_| true)
    }

    fn resolve_mapping_index_for_pid_with_cache_and_predicate(
        &self,
        pid: u32,
        ip: u64,
        cached_index: &mut Option<usize>,
        predicate: impl Fn(&Mapping) -> bool,
    ) -> Option<usize> {
        if let Some(index) = self.cached_mapping_index(pid, ip, *cached_index, &predicate) {
            return Some(index);
        }
        let resolved = self.resolve_bucket_with_predicate(self.bucket(pid), ip, predicate);
        *cached_index = resolved;
        resolved
    }

    fn resolve_bucket_with_cache(
        &self,
        pid: u32,
        bucket: &[IndexedMapping],
        ip: u64,
        cached_index: &mut Option<usize>,
        predicate: impl Fn(&Mapping) -> bool,
    ) -> Option<usize> {
        if let Some(index) = self.cached_mapping_index(pid, ip, *cached_index, &predicate) {
            return Some(index);
        }
        let resolved = self.resolve_bucket_with_predicate(bucket, ip, predicate);
        *cached_index = resolved;
        resolved
    }

    fn cached_mapping_index(
        &self,
        pid: u32,
        ip: u64,
        cached_index: Option<usize>,
        predicate: &impl Fn(&Mapping) -> bool,
    ) -> Option<usize> {
        // maps.c:__maps__fixup_overlap_and_insert leaves disjoint ranges per
        // PID. Check the current entry, not a stored mapping: splits and fork
        // rebuilds can move indices, and callers share a cache across modes.
        if let Some(index) = cached_index
            && self.mappings.get(index).is_some_and(|mapping| {
                mapping.pid == pid
                    && mapping.start <= ip
                    && ip < mapping.end()
                    && predicate(mapping)
            })
        {
            return Some(index);
        }
        None
    }

    fn resolve_bucket_with_predicate(
        &self,
        bucket: &[IndexedMapping],
        ip: u64,
        predicate: impl Fn(&Mapping) -> bool,
    ) -> Option<usize> {
        #[cfg(test)]
        self.index_searches.set(self.index_searches.get() + 1);
        let mut upper_bound = bucket.partition_point(|indexed| indexed.start <= ip);
        let mut latest_matching_index = None;
        while upper_bound > 0 {
            upper_bound -= 1;
            let indexed = &bucket[upper_bound];
            if indexed.max_end <= ip {
                break;
            }
            let index = indexed.index;
            let mapping = &self.mappings[index];
            if ip < mapping.end() && predicate(mapping) {
                latest_matching_index = latest_matching_index.max(Some(index));
            }
        }
        latest_matching_index
    }

    fn intern_symbol_source(&mut self, mapping: &Mapping) -> usize {
        let key = mapping.symbol_source_key();
        let next_id = self.symbol_source_ids.len();
        *self.symbol_source_ids.entry(key).or_insert(next_id)
    }
}

fn mapping_cpumode_from_misc(misc: u16) -> u16 {
    match misc & PERF_RECORD_MISC_CPUMODE_MASK {
        crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL => {
            crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL
        }
        _ => PERF_RECORD_MISC_CPUMODE_USER,
    }
}

impl Mapping {
    fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    fn relative_address(&self, ip: u64) -> u64 {
        if self.is_kernel_symbol_mapping() {
            ip
        } else {
            ip - self.start + self.pgoff
        }
    }

    fn kernel_relocation(&self) -> Option<KernelRelocation> {
        self.path
            .strip_prefix("[kernel.kallsyms]")
            .filter(|reference_symbol| !reference_symbol.is_empty())
            .map(|reference_symbol| KernelRelocation {
                reference_symbol: reference_symbol.to_string(),
                recorded_reference_address: self.pgoff,
            })
    }

    fn is_user_file_mapping(&self) -> bool {
        !self.path.starts_with('[') && self.pid != u32::MAX
    }

    fn is_user_cpumode(&self) -> bool {
        self.cpumode == PERF_RECORD_MISC_CPUMODE_USER
    }

    fn is_known_non_executable(&self) -> bool {
        self.prot.is_some_and(|prot| prot & PROT_EXEC == 0) || is_perf_data_path(&self.path)
    }

    fn may_execute(&self) -> bool {
        !self.is_known_non_executable()
    }

    fn is_kernel_symbol_mapping(&self) -> bool {
        self.pid == u32::MAX && self.path.starts_with('[')
    }

    fn symbol_source_key(&self) -> SymbolSourceKey {
        // perf identifies a dso backing store via __dso_id__cmp
        // (tools/perf/util/dso.c): once both sides carry a defined build_id it
        // is the decisive comparison, and the mmap2 maj/min/ino are only
        // weighed when both sides recorded them. The same on-disk object can
        // therefore reach us as an inline MMAP2-build-id record (build_id, no
        // file_identity) or as a plain MMAP2 plus a HEADER_BUILD_ID entry
        // (build_id and file_identity). Keying on file_identity alongside the
        // build_id would split those into two symbol sources, so when a
        // build_id is present we drop file_identity from the key and rely on
        // (path, build_id) — preserving distinct build_ids at the same path,
        // and falling back to file_identity only when no build_id exists.
        let build_id = self.build_id.clone();
        let file_identity = if build_id.is_some() {
            None
        } else {
            self.file_identity
        };
        SymbolSourceKey {
            path: if self.is_kernel_symbol_mapping() && self.path.starts_with("[kernel") {
                "[kernel.kallsyms]".to_string()
            } else {
                self.path.clone()
            },
            build_id,
            file_identity,
            kernel_relocation: self.kernel_relocation(),
        }
    }
}

fn is_perf_data_path(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|file_name| file_name == "perf.data" || file_name.starts_with("perf.data."))
}

#[cfg(test)]
mod tests {
    #[test]
    fn mapped_frame_views_borrow_paths_and_preserve_resolved_metadata() {
        assert!(std::mem::size_of::<super::MappedFrame<'_>>() <= 2 * std::mem::size_of::<usize>());
        for (pid, start, path) in [
            (7, 0x1000, "/tmp/demo.so"),
            (7, 0x1000, "/tmp/\u{e9};demo(args).so"),
            (u32::MAX, 0xffff_ffff_8100_0000, "[kernel.kallsyms]_text"),
        ] {
            let mut table = super::MmapTable::default();
            table.insert_mmap(super::MmapRecord {
                pid,
                tid: pid,
                start,
                len: 0x100,
                pgoff: 0,
                path: path.into(),
            });
            let mut hint = super::MappingResolveCache::default();
            let frame = table
                .resolve_frame_cached(pid, start + 0x10, &mut hint)
                .unwrap();
            let reference = table.resolve_ref(pid, start + 0x10).unwrap();
            assert_eq!(frame.resolved_ref(), reference);
            assert_eq!(frame.path().as_ptr(), table.mappings[0].path.as_ptr());
            assert_eq!(*frame.path_layout(), super::MappingPathLayout::new(path));
            assert_eq!(frame.is_kernel(), pid == u32::MAX);
            assert_eq!(
                frame.kernel_range(),
                (pid == u32::MAX).then_some((start, start + 0x100))
            );
        }
    }

    #[test]
    fn mapping_path_layout_preserves_literal_utf8_boundaries_and_escape_requirements() {
        for path in [
            "/",
            "/tmp/demo///",
            "/tmp/\u{e9}.so",
            "/tmp/a;b.so",
            "/tmp/a\r\nb.so",
            "/tmp/a (b).so",
            "[vdso]",
        ] {
            let layout = super::MappingPathLayout::new(path);
            let basename = &path[path.rfind('/').map_or(0, |index| index + 1)..];
            assert_eq!(&path[layout.basename_start..], basename);
            assert_eq!(layout.last_space, path.rfind(' '));
            assert_eq!(layout.basename_has_parentheses, basename.contains('('));
            assert_eq!(
                layout.basename_needs_escaping,
                basename.contains([';', '\r', '\n'])
            );
        }
    }

    use super::{MappingResolveCache, MmapTable};
    use crate::perfdata::records::MmapRecord;

    #[test]
    fn broad_new_mapping_replaces_covered_old_mapping_like_perf_maps_fixup() {
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x3000,
            len: 0x100,
            pgoff: 0,
            path: "/later".to_string(),
        });
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x4000,
            pgoff: 0,
            path: "/earlier".to_string(),
        });

        let bucket = table.mappings_by_pid.get(&7).expect("bucket");
        assert_eq!(bucket.len(), 1);
        assert_eq!(bucket[0].max_end, 0x5000);
        assert_eq!(table.resolve(7, 0x3000).expect("mapping").path, "/earlier");
    }

    #[test]
    fn new_mapping_replaces_fully_overlapped_old_mapping_like_perf_maps_fixup() {
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x1000,
            pgoff: 0,
            path: "/bin/sh".to_string(),
        });
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x1000,
            pgoff: 0,
            path: "/pyroclast".to_string(),
        });

        let paths = table
            .user_mappings()
            .map(|mapping| mapping.path)
            .collect::<Vec<_>>();
        assert_eq!(paths, ["/pyroclast"]);
        assert_eq!(
            table.resolve(7, 0x1000).expect("mapping").path,
            "/pyroclast"
        );
    }

    #[test]
    fn cached_lookup_tracks_pid_specific_and_global_mappings() {
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x100,
            pgoff: 0,
            path: "/app".to_string(),
        });
        table.insert_mmap(MmapRecord {
            pid: u32::MAX,
            tid: u32::MAX,
            start: 0xffff_ffff_8100_0000,
            len: 0x1000,
            pgoff: 0,
            path: "[kernel.kallsyms]".to_string(),
        });

        let mut cache = MappingResolveCache::default();
        let local = table
            .resolve_ref_cached(7, 0x1010, &mut cache)
            .expect("local mapping");
        assert_eq!(local.path, "/app");
        assert_eq!(cache.pid, Some(7));
        assert_eq!(cache.pid_index, Some(0));
        assert_eq!(cache.global_index, None);

        let global = table
            .resolve_ref_cached(42, 0xffff_ffff_8100_0010, &mut cache)
            .expect("global mapping");
        assert_eq!(global.path, "[kernel.kallsyms]");
        assert_eq!(cache.pid, Some(42));
        assert_eq!(cache.pid_index, None);
        assert_eq!(cache.global_index, Some(1));
    }

    #[test]
    fn cached_lookup_clears_stale_pid_mapping_after_miss() {
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x100,
            pgoff: 0,
            path: "/app".to_string(),
        });

        let mut cache = MappingResolveCache::default();
        assert!(table.has_mapping_for_pid_cached(7, 0x1010, &mut cache));
        assert_eq!(cache.pid_index, Some(0));

        assert!(!table.has_mapping_for_pid_cached(7, 0x5000, &mut cache));
        assert_eq!(cache.pid_index, None);
    }

    #[test]
    fn cached_lookup_reuses_a_containing_mapping_without_researching_the_pid_index() {
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x100,
            pgoff: 0,
            path: "/app".into(),
        });
        let mut cache = MappingResolveCache::default();
        table
            .resolve_user_pid_ref_cached(7, 0x1000, &mut cache)
            .unwrap();
        let searches = table.index_searches.get();
        for ip in 0x1001..0x1100 {
            let mapping = table
                .resolve_user_pid_ref_cached(7, ip, &mut cache)
                .unwrap();
            assert_eq!(mapping.relative_address, ip - 0x1000);
        }
        assert_eq!(table.index_searches.get(), searches);
    }

    #[test]
    fn cached_lookup_checks_the_current_cpu_mode_before_reusing_an_index() {
        let mut table = MmapTable::default();
        table.insert_mmap_with_misc(
            MmapRecord {
                pid: 7,
                tid: 7,
                start: 0x1000,
                len: 0x100,
                pgoff: 0,
                path: "[kernel]".into(),
            },
            crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
        );
        let mut cache = MappingResolveCache::default();
        assert!(table.resolve_ref_cached(7, 0x1010, &mut cache).is_some());
        assert!(
            table
                .resolve_user_pid_ref_cached(7, 0x1010, &mut cache)
                .is_none()
        );
        assert_eq!(cache.pid_index, None);
    }

    #[test]
    fn cached_lookups_match_current_maps_after_splits_reindexing_and_pid_switches() {
        let mut table = MmapTable::default();
        for (pid, path) in [(7, "/first"), (8, "/other"), (u32::MAX, "[global]")] {
            table.insert_mmap(MmapRecord {
                pid,
                tid: pid,
                start: 0x1000,
                len: 0x1000,
                pgoff: u64::from(pid),
                path: path.into(),
            });
        }
        let mut cache = MappingResolveCache::default();
        let mut user_cache = MappingResolveCache::default();
        assert!(table.resolve_ref_cached(7, 0x1800, &mut cache).is_some());
        assert!(
            table
                .resolve_user_pid_ref_cached(7, 0x1800, &mut user_cache)
                .is_some()
        );
        // Removing a middle interval shifts entries belonging to other PIDs
        // and creates both old-map fragments with adjusted file offsets.
        for (start, len) in [(0x1700, 0x200), (0x1000, 0x1000), (0x1800, 0x100)] {
            table.insert_mmap(MmapRecord {
                pid: 7,
                tid: 7,
                start,
                len,
                pgoff: start,
                path: format!("/replacement-{start:x}"),
            });
            for pid in [7, 8, 9, u32::MAX] {
                for ip in [
                    0xfff, 0x1000, 0x16ff, 0x1700, 0x1800, 0x18ff, 0x1900, 0x1fff, 0x2000,
                ] {
                    assert_eq!(
                        table.resolve_ref_cached(pid, ip, &mut cache),
                        table.resolve_ref(pid, ip)
                    );
                    let context = table.frame_context(pid, &mut cache);
                    assert_eq!(
                        context
                            .resolve(ip, &mut cache)
                            .map(super::MappedFrame::resolved_ref),
                        table.resolve_ref(pid, ip)
                    );
                    let expected = table
                        .mappings
                        .iter()
                        .find(|mapping| {
                            mapping.pid == pid
                                && mapping.start <= ip
                                && ip < mapping.end()
                                && mapping.is_user_cpumode()
                        })
                        .map(|mapping| {
                            (
                                mapping.path.as_str(),
                                mapping.relative_address(ip),
                                mapping.start,
                                mapping.end(),
                            )
                        });
                    let actual = table
                        .resolve_user_pid_ref_cached(pid, ip, &mut user_cache)
                        .map(|mapping| {
                            (
                                mapping.path,
                                mapping.relative_address,
                                mapping.start,
                                mapping.end,
                            )
                        });
                    assert_eq!(actual, expected);
                    let context = table.frame_context(pid, &mut user_cache);
                    let actual = context.resolve_user(ip, &mut user_cache).map(|mapping| {
                        let mapping = mapping.resolved_ref();
                        (
                            mapping.path,
                            mapping.relative_address,
                            mapping.start,
                            mapping.end,
                        )
                    });
                    assert_eq!(actual, expected);
                }
            }
        }
    }

    #[test]
    fn incremental_insert_splits_multiple_overlapping_mappings_like_perf() {
        // Two adjacent mappings, then a third that straddles both: the overlap
        // path must remove both originals, emit before/after fragments in the
        // perf-source order, and let the newest mapping win the shared interior.
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x1000,
            pgoff: 0,
            path: "/first".to_string(),
        });
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x2000,
            len: 0x1000,
            pgoff: 0,
            path: "/second".to_string(),
        });
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1800,
            len: 0x1000,
            pgoff: 0x100,
            path: "/straddle".to_string(),
        });

        // /first head survives below the straddle, /second tail above it.
        assert_eq!(table.resolve(7, 0x1400).expect("first head").path, "/first");
        assert_eq!(
            table.resolve(7, 0x1900).expect("straddle body").path,
            "/straddle"
        );
        assert_eq!(
            table.resolve(7, 0x2900).expect("second tail").path,
            "/second"
        );
        let straddle = table.resolve(7, 0x1900).expect("straddle relative");
        assert_eq!(straddle.relative_address, 0x100 + 0x100);
    }

    #[test]
    fn non_overlapping_insert_takes_fast_path_and_indexes_correctly() {
        // Disjoint mappings (and a different pid) must not be treated as
        // overlapping, so each insert takes the incremental fast path while
        // still resolving and pruning correctly.
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x100,
            pgoff: 0,
            path: "/a".to_string(),
        });
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x3000,
            len: 0x100,
            pgoff: 0,
            path: "/b".to_string(),
        });
        table.insert_mmap(MmapRecord {
            pid: 9,
            tid: 9,
            start: 0x1000,
            len: 0x100,
            pgoff: 0,
            path: "/other-pid".to_string(),
        });

        assert!(!table.has_overlapping_user_mapping_for_pid(7, 0x1100, 0x100));
        assert!(!table.has_overlapping_user_mapping_for_pid(7, 0x2000, 0x800));
        assert!(table.has_overlapping_user_mapping_for_pid(7, 0x10ff, 0x100));
        assert!(table.has_overlapping_user_mapping_for_pid(7, 0x3080, 0x100));
        // Adjacency is not overlap (half-open ranges).
        assert!(!table.has_overlapping_user_mapping_for_pid(7, 0x1100, 0x10));
        // Different pid's mapping must not count.
        assert!(!table.has_overlapping_user_mapping_for_pid(8, 0x1000, 0x100));
        assert_eq!(table.resolve(7, 0x1050).expect("/a").path, "/a");
        assert_eq!(table.resolve(7, 0x3050).expect("/b").path, "/b");
    }

    #[test]
    fn has_overlapping_user_mapping_matches_linear_scan_oracle() {
        // The index-based overlap query must agree with an exhaustive linear
        // scan across a dense, multi-pid set of mappings (including bracket
        // paths that are not user-file mappings).
        let segments: &[(u32, u64, u64, &str)] = &[
            (7, 0x1000, 0x400, "/bin/a"),
            (7, 0x1400, 0x400, "/bin/b"),
            (7, 0x2000, 0x100, "/bin/c"),
            (7, 0x2500, 0x800, "/bin/d"),
            (7, 0x3000, 0x200, "[anon]"),
            (9, 0x1200, 0x600, "/bin/e"),
            (9, 0x4000, 0x100, "/bin/f"),
        ];
        let mut table = MmapTable::default();
        for &(pid, start, len, path) in segments {
            table.insert_mmap(MmapRecord {
                pid,
                tid: pid,
                start,
                len,
                pgoff: 0,
                path: path.to_string(),
            });
        }

        for pid in [7_u32, 8, 9] {
            for start in (0x0u64..0x5000).step_by(0x80) {
                for len in [0u64, 0x40, 0x100, 0x900] {
                    let end = start.saturating_add(len);
                    let expected = segments.iter().any(|&(seg_pid, seg_start, seg_len, path)| {
                        let seg_end = seg_start + seg_len;
                        let is_user = !path.starts_with('[');
                        seg_pid == pid && is_user && start < seg_end && seg_start < end
                    });
                    assert_eq!(
                        table.has_overlapping_user_mapping_for_pid(pid, start, len),
                        expected,
                        "pid={pid} start={start:#x} len={len:#x}"
                    );
                }
            }
        }
    }
}
