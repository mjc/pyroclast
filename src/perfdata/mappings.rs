use crate::perfdata::records::{
    Mmap2BuildIdRecord, Mmap2Record, MmapRecord, PERF_RECORD_MISC_CPUMODE_MASK,
    PERF_RECORD_MISC_CPUMODE_USER,
};
use crate::symbols::{KernelRelocation, SymbolResolver};
use hashbrown::{HashMap, HashSet};
use rustc_hash::FxBuildHasher;
use std::cell::{Cell, OnceCell};
use std::cmp::Ordering;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

const PROT_EXEC: u32 = 4;

#[cfg(test)]
thread_local! {
    static MAPPED_FRAME_KERNEL_CLASSIFICATIONS: Cell<usize> = const { Cell::new(0) };
    static FRAME_MAPPING_TRANSLATION_CLASSIFICATIONS: Cell<usize> = const { Cell::new(0) };
    static FRAME_MAPPING_USER_CLASSIFICATIONS: Cell<usize> = const { Cell::new(0) };
    static FRAME_MAPPING_HINT_LOADS: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct MappingMutationRowWork {
    overlap_rows: usize,
    rebuild_rows: usize,
    index_writes: usize,
    index_tail_moves: usize,
    fork_remove_rows: usize,
    fork_select_rows: usize,
    fork_cloned_rows: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MmapTable {
    mappings: MappingArena,
    mappings_by_pid: HashMap<u32, Vec<IndexedMapping>, FxBuildHasher>,
    symbol_source_ids: HashMap<SymbolSourceKey, usize, FxBuildHasher>,
    native_dsos: NativeDsoRegistry,
    display_path_ids: HashMap<String, usize, FxBuildHasher>,
    pids_with_mappings: HashSet<u32, FxBuildHasher>,
    executable_pids: HashSet<u32, FxBuildHasher>,
    has_global_mappings: bool,
    has_global_executable_mappings: bool,
    #[cfg(test)]
    index_searches: std::cell::Cell<usize>,
    #[cfg(test)]
    bucket_searches: std::cell::Cell<usize>,
    #[cfg(test)]
    cache_index_probes: std::cell::Cell<usize>,
    #[cfg(test)]
    gap_computations: std::cell::Cell<usize>,
    #[cfg(test)]
    mutation_row_work: std::cell::RefCell<HashMap<u32, MappingMutationRowWork, FxBuildHasher>>,
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
    /// Original IP for an absolute module path recorded in kernel CPU mode.
    pub kernel_module_address: Option<u64>,
    pub start: u64,
    pub end: u64,
    pub build_id: Option<&'a [u8]>,
    pub file_identity: Option<FileIdentity>,
    pub kernel_relocation: Option<KernelRelocation>,
}

pub(super) struct DsoMemoryMapping<'a> {
    pub(super) source_id: usize,
    pub(super) path: &'a str,
    pub(super) relative_address: u64,
    pub(super) build_id: Option<&'a [u8]>,
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
    display_path_id: usize,
    pub(crate) basename_start: usize,
    pub(crate) last_space: Option<usize>,
    pub(crate) text_row_boundary: Option<usize>,
    pub(crate) basename_needs_escaping: bool,
    pub(crate) fallback: ModuleFallbackKind,
    bracketed: bool,
}

impl MappingPathLayout {
    pub(crate) fn new(path: &str) -> Self {
        let basename_start = memchr::memrchr(b'/', path.as_bytes()).map_or(0, |index| index + 1);
        let mut layout = Self {
            display_path_id: 0,
            bracketed: path.starts_with('['),
            basename_start,
            last_space: memchr::memrchr(b' ', path.as_bytes()),
            text_row_boundary: memchr::memchr3(b' ', b'\r', b'\n', path.as_bytes()),
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
        } else if path[basename_start..].contains('(') {
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
    pub(crate) fn display_path_id(self) -> usize {
        self.mapping.path_layout.display_path_id
    }
    #[cfg(test)]
    pub(crate) fn path(self) -> &'a str {
        &self.mapping.path
    }
    pub(crate) fn display_path(self) -> &'a str {
        self.mapping.display_path()
    }
    pub(crate) fn kernel_range(self) -> Option<(u64, u64)> {
        self.is_kernel()
            .then(|| (self.mapping.start, self.mapping.end()))
    }
    pub(crate) fn is_kernel(self) -> bool {
        self.kernel_module_address().is_some()
            || self.mapping.path_layout.bracketed && {
                #[cfg(test)]
                MAPPED_FRAME_KERNEL_CLASSIFICATIONS.with(|count| count.set(count.get() + 1));
                crate::perfdata::samples::is_kernel_space_frame(self.relative_address)
            }
    }
    fn kernel_module_address(self) -> Option<u64> {
        self.mapping.kernel_module_address(
            self.relative_address
                .wrapping_sub(self.mapping.translation_bias()),
        )
    }
    pub(crate) fn path_layout(self) -> &'a MappingPathLayout {
        &self.mapping.path_layout
    }
    pub(crate) fn resolved_ref(self) -> ResolvedMappingRef<'a> {
        ResolvedMappingRef {
            symbol_source_id: self.mapping.symbol_source_id,
            path: &self.mapping.path,
            relative_address: self.relative_address,
            kernel_module_address: self.kernel_module_address(),
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
    user_hint: Cell<Option<FrameMappingHint<'a>>>,
    global_hint: Cell<Option<FrameMappingHint<'a>>>,
    user_miss: Cell<Option<FrameMappingMiss>>,
    global_miss: Cell<Option<FrameMappingMiss>>,
}

#[derive(Clone, Copy)]
struct FrameMappingMiss {
    start: u64,
    last: u64,
}

impl FrameMappingMiss {
    fn contains(self, ip: u64) -> bool {
        self.start <= ip && ip <= self.last
    }
}

#[derive(Clone, Copy)]
struct FrameMappingHint<'a> {
    mapping: &'a Mapping,
    index: usize,
    start: u64,
    end: u64,
    translation_bias: u64,
    user_cpumode: bool,
}

impl<'a> FrameMappingHint<'a> {
    #[inline]
    fn load(hint: &Cell<Option<Self>>) -> Option<Self> {
        #[cfg(test)]
        FRAME_MAPPING_HINT_LOADS.with(|count| count.set(count.get() + 1));
        hint.get()
    }

    fn new(index: usize, mapping: &'a Mapping) -> Self {
        Self {
            mapping,
            index,
            start: mapping.start,
            end: mapping.end(),
            translation_bias: mapping.translation_bias(),
            user_cpumode: mapping.is_user_cpumode(),
        }
    }

    fn mapped_frame(self, ip: u64) -> MappedFrame<'a> {
        // Perf map__map_ip: reuse translation metadata for this borrowed map.
        MappedFrame {
            mapping: self.mapping,
            relative_address: ip.wrapping_add(self.translation_bias),
        }
    }
}

impl<'a> FrameMappingContext<'a> {
    #[inline]
    pub(crate) fn resolve_user(
        &self,
        ip: u64,
        cache: &mut MappingResolveCache,
    ) -> Option<MappedFrame<'a>> {
        self.resolve_bucket::<true>(
            self.user,
            ip,
            &mut cache.pid_index,
            &self.user_hint,
            &self.user_miss,
        )
    }

    #[inline]
    pub(crate) fn resolve(
        &self,
        ip: u64,
        cache: &mut MappingResolveCache,
    ) -> Option<MappedFrame<'a>> {
        let global = self.resolve_bucket::<false>(
            self.global,
            ip,
            &mut cache.global_index,
            &self.global_hint,
            &self.global_miss,
        );
        if self.pid == u32::MAX {
            global
        } else {
            let user = self.resolve_bucket::<false>(
                self.user,
                ip,
                &mut cache.pid_index,
                &self.user_hint,
                &self.user_miss,
            );
            match (user, global) {
                (Some(left), Some(right)) => {
                    if left.mapping.start >= right.mapping.start {
                        Some(left)
                    } else {
                        Some(right)
                    }
                }
                (Some(found), None) | (None, Some(found)) => Some(found),
                (None, None) => None,
            }
        }
    }

    #[inline]
    fn resolve_bucket<const USER_ONLY: bool>(
        &self,
        bucket: &[IndexedMapping],
        ip: u64,
        cached_index: &mut Option<usize>,
        hint: &Cell<Option<FrameMappingHint<'a>>>,
        miss: &Cell<Option<FrameMappingMiss>>,
    ) -> Option<MappedFrame<'a>> {
        if bucket.is_empty() {
            *cached_index = None;
            return None;
        }
        // The context borrows the table for one delivered sample: map edits
        // cannot invalidate these references until that sample is finished.
        if let Some(found) = FrameMappingHint::load(hint)
            && found.start <= ip
            && ip < found.end
        {
            // Perf overlap fixup leaves disjoint ranges per PID, so this
            // containing non-USER map also proves that USER lookup misses.
            if USER_ONLY && !found.user_cpumode {
                *cached_index = None;
                return None;
            }
            *cached_index = Some(found.index);
            return Some(found.mapped_frame(ip));
        }
        if miss.get().is_some_and(|range| range.contains(ip)) {
            *cached_index = None;
            return None;
        }
        self.resolve_bucket_miss::<USER_ONLY>(bucket, ip, cached_index, hint, miss)
    }

    #[inline(never)]
    fn resolve_bucket_miss<const USER_ONLY: bool>(
        &self,
        bucket: &[IndexedMapping],
        ip: u64,
        cached_index: &mut Option<usize>,
        hint: &Cell<Option<FrameMappingHint<'a>>>,
        miss: &Cell<Option<FrameMappingMiss>>,
    ) -> Option<MappedFrame<'a>> {
        let index = match self.table.search_bucket(bucket, ip) {
            Ok(index) => index,
            Err(insertion) => {
                // Only this immutable context retains interval proofs.
                // Ordinary lookups need neither their bounds nor storage.
                #[cfg(test)]
                self.table
                    .gap_computations
                    .set(self.table.gap_computations.get() + 1);
                miss.set(Some(MmapTable::bucket_gap(bucket, insertion)));
                *cached_index = None;
                return None;
            }
        };
        *cached_index = Some(index);
        let found = FrameMappingHint::new(index, &self.table.mappings[index]);
        hint.set(Some(found));
        if USER_ONLY && !found.user_cpumode {
            *cached_index = None;
            return None;
        }
        Some(found.mapped_frame(ip))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FileIdentity {
    pub major: u32,
    pub minor: u32,
    pub inode: u64,
    pub inode_generation: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct NativeDsoRegistry {
    entries: Vec<NativeDso>,
    order: Vec<usize>,
    sorted: bool,
    header_paths: HashSet<String, FxBuildHasher>,
    headers_initialized: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeDso {
    id: usize,
    path: String,
    build_id: OnceCell<Vec<u8>>,
    symbol_build_id: OnceCell<Option<Vec<u8>>>,
    file_identity: Option<FileIdentity>,
}

impl NativeDso {
    fn build_id(&self) -> Option<&[u8]> {
        self.build_id.get().map(Vec::as_slice)
    }

    fn set_build_id(&mut self, build_id: &[u8]) {
        self.build_id.take();
        if build_id.iter().any(|byte| *byte != 0) {
            self.build_id
                .set(build_id.to_vec())
                .expect("DSO build ID was cleared");
        }
    }

    fn compare(
        &self,
        path: &str,
        file_identity: Option<FileIdentity>,
        build_id: Option<&[u8]>,
    ) -> Ordering {
        // dso.c:__dso_id__cmp skips fields missing from either identity.
        // Inode fields sort descending; build IDs sort by size, then bytes.
        self.path.as_str().cmp(path).then_with(|| {
            let file_order = self
                .file_identity
                .zip(file_identity)
                .map_or(Ordering::Equal, |(a, b)| b.cmp(&a));
            file_order.then_with(|| {
                self.build_id()
                    .zip(build_id)
                    .map_or(Ordering::Equal, |(a, b)| {
                        a.len().cmp(&b.len()).then_with(|| a.cmp(b))
                    })
            })
        })
    }

    fn enrich(&mut self, file_identity: Option<FileIdentity>, build_id: Option<&[u8]>) -> bool {
        let mut changed = false;
        if self.file_identity.is_none() && file_identity.is_some() {
            self.file_identity = file_identity;
            changed = true;
        }
        if self.build_id.get().is_none()
            && let Some(build_id) = build_id
        {
            self.set_build_id(build_id);
            changed = true;
        }
        changed
    }
}

impl NativeDsoRegistry {
    fn register_header(&mut self, path: &str, build_id: &[u8]) {
        if build_id.iter().all(|byte| *byte == 0) || !self.header_paths.insert(path.to_string()) {
            return;
        }
        // header.c:__event_process_build_id finds by empty identity, then
        // sets the DSO build ID before mapping records are processed.
        let id = self.intern(path, None, None);
        self.entries[id].set_build_id(build_id);
    }

    fn intern(
        &mut self,
        path: &str,
        file_identity: Option<FileIdentity>,
        build_id: Option<&[u8]>,
    ) -> usize {
        let build_id = build_id.filter(|id| id.iter().any(|byte| *byte != 0));
        if !self.sorted {
            self.sort();
        }
        // dsos.c uses bsearch: stop at the first equal midpoint. Wildcards
        // are non-transitive, so neither hash interning nor Rust's duplicate
        // selection in binary_search_by implements this lookup.
        let (mut low, mut high) = (0, self.order.len());
        while low < high {
            let mid = low + (high - low) / 2;
            let id = self.order[mid];
            match self.entries[id]
                .compare(path, file_identity, build_id)
                .reverse()
            {
                Ordering::Less => high = mid,
                Ordering::Greater => low = mid + 1,
                Ordering::Equal => {
                    if self.entries[id].enrich(file_identity, build_id) {
                        self.sorted = false;
                    }
                    return id;
                }
            }
        }
        // __dsos__add uses a lower-bound search with an inclusive high end,
        // whose midpoint differs from bsearch for even-length arrays.
        let (mut low, mut high) = (0, self.order.len());
        while low < high {
            let mid = low + (high - low - 1) / 2;
            if self.entries[self.order[mid]]
                .compare(path, file_identity, build_id)
                .is_lt()
            {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        let id = self.entries.len();
        self.entries.push(NativeDso {
            id,
            path: path.to_string(),
            build_id: build_id.map_or_else(OnceCell::new, |id| OnceCell::from(id.to_vec())),
            symbol_build_id: OnceCell::new(),
            file_identity,
        });
        self.order.insert(low, id);
        id
    }

    fn sort(&mut self) {
        let mut ordered = self
            .order
            .iter()
            .map(|&id| &self.entries[id])
            .collect::<Vec<_>>();
        // Match perf's pointer-array qsort on Unix. The wildcard comparator
        // is not a total order, which Rust's slice sorting APIs require.
        #[cfg(unix)]
        unsafe {
            // SAFETY: qsort only rearranges initialized references in this
            // exclusive buffer. Their referents remain live and immutable;
            // compare_native_dsos uses this exact element type and cannot panic.
            libc::qsort(
                ordered.as_mut_ptr().cast(),
                ordered.len(),
                std::mem::size_of::<&NativeDso>(),
                Some(compare_native_dsos),
            );
        }
        #[cfg(not(unix))]
        for index in 1..ordered.len() {
            let mut position = index;
            while position > 0
                && ordered[position]
                    .compare(
                        &ordered[position - 1].path,
                        ordered[position - 1].file_identity,
                        ordered[position - 1].build_id(),
                    )
                    .is_lt()
            {
                ordered.swap(position - 1, position);
                position -= 1;
            }
        }
        self.order = ordered.iter().map(|dso| dso.id).collect();
        self.sorted = true;
    }
}

#[cfg(unix)]
unsafe extern "C" fn compare_native_dsos(
    a: *const libc::c_void,
    b: *const libc::c_void,
) -> libc::c_int {
    // SAFETY: only NativeDsoRegistry::sort calls this with pointers to live
    // elements of its Vec<&NativeDso>.
    let (a, b) = unsafe { (*a.cast::<&NativeDso>(), *b.cast::<&NativeDso>()) };
    match a.compare(&b.path, b.file_identity, b.build_id()) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
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
    native_dso_id: usize,
    path: String,
    path_layout: MappingPathLayout,
    module_display: Option<Arc<str>>,
    build_id: Option<Vec<u8>>,
    mmap_build_id: bool,
    file_identity: Option<FileIdentity>,
    prot: Option<u32>,
    cpumode: u16,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct MappingArena {
    slots: Vec<MappingSlot>,
    free: Vec<usize>,
    first: Option<usize>,
    last: Option<usize>,
    next_insertion_id: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MappingSlot {
    mapping: Option<Mapping>,
    previous: Option<usize>,
    next: Option<usize>,
    insertion_id: usize,
}

impl MappingArena {
    fn insert(&mut self, mapping: Mapping) -> usize {
        let insertion_id = self.next_insertion_id;
        self.next_insertion_id = insertion_id
            .checked_add(1)
            .expect("mapping insertion ID overflow");
        let slot = MappingSlot {
            mapping: Some(mapping),
            previous: self.last,
            next: None,
            insertion_id,
        };
        let index = if let Some(index) = self.free.pop() {
            self.slots[index] = slot;
            index
        } else {
            let index = self.slots.len();
            self.slots.push(slot);
            index
        };
        if let Some(previous) = self.last {
            self.slots[previous].next = Some(index);
        } else {
            self.first = Some(index);
        }
        self.last = Some(index);
        index
    }

    fn remove(&mut self, index: usize) -> Mapping {
        let slot = &mut self.slots[index];
        let mapping = slot.mapping.take().expect("indexed mapping slot is live");
        let previous = slot.previous.take();
        let next = slot.next.take();
        if let Some(previous) = previous {
            self.slots[previous].next = next;
        } else {
            self.first = next;
        }
        if let Some(next) = next {
            self.slots[next].previous = previous;
        } else {
            self.last = previous;
        }
        self.free.push(index);
        mapping
    }

    fn get(&self, index: usize) -> Option<&Mapping> {
        self.slots.get(index)?.mapping.as_ref()
    }

    fn insertion_id(&self, index: usize) -> usize {
        self.slots[index].insertion_id
    }

    // Preserve the flat table's insertion order without moving live mappings
    // or allocating an ordering node for each map. Free slots are not visited.
    fn iter(&self) -> impl Iterator<Item = &Mapping> {
        std::iter::successors(self.first, move |&index| self.slots[index].next)
            .map(move |index| &self[index])
    }
}

impl std::ops::Index<usize> for MappingArena {
    type Output = Mapping;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("indexed mapping slot is live")
    }
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
        } else if !self.has_global_mappings {
            &[]
        } else {
            self.bucket(u32::MAX)
        };
        FrameMappingContext {
            table: self,
            pid,
            user,
            global,
            user_hint: Cell::new(self.frame_mapping_hint(pid, cache.pid_index)),
            global_hint: Cell::new(self.frame_mapping_hint(u32::MAX, cache.global_index)),
            user_miss: Cell::new(None),
            global_miss: Cell::new(None),
        }
    }

    fn frame_mapping_hint(&self, pid: u32, index: Option<usize>) -> Option<FrameMappingHint<'_>> {
        #[cfg(test)]
        self.cache_index_probes
            .set(self.cache_index_probes.get() + 1);
        let index = index?;
        self.mappings
            .get(index)
            .filter(|mapping| mapping.pid == pid)
            .map(|mapping| FrameMappingHint::new(index, mapping))
    }

    pub fn insert_mmap(&mut self, record: MmapRecord) {
        self.insert_mmap_with_misc(record, PERF_RECORD_MISC_CPUMODE_USER);
    }

    pub(crate) fn insert_mmap_with_misc(&mut self, record: MmapRecord, misc: u16) {
        self.insert_mmap_with_build_id_and_misc(record, None, misc);
    }

    pub(crate) fn insert_mmap_with_build_id_and_misc(
        &mut self,
        record: MmapRecord,
        build_id: Option<Vec<u8>>,
        misc: u16,
    ) {
        if let Some(id) = build_id.as_deref() {
            self.native_dsos.register_header(&record.path, id);
        }
        self.insert_mapping(Mapping {
            pid: record.pid,
            start: record.start,
            len: record.len,
            pgoff: record.pgoff,
            symbol_source_id: 0,
            native_dso_id: 0,
            path: record.path,
            path_layout: MappingPathLayout::default(),
            module_display: None,
            build_id,
            mmap_build_id: false,
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
        if let Some(id) = build_id.as_deref() {
            self.native_dsos.register_header(&record.path, id);
        }
        self.insert_mapping(Mapping {
            pid: record.pid,
            start: record.start,
            len: record.len,
            pgoff: record.pgoff,
            symbol_source_id: 0,
            native_dso_id: 0,
            path: record.path,
            path_layout: MappingPathLayout::default(),
            module_display: None,
            build_id,
            mmap_build_id: false,
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
            native_dso_id: 0,
            path: record.path,
            path_layout: MappingPathLayout::default(),
            module_display: None,
            build_id: Some(record.build_id),
            mmap_build_id: true,
            file_identity: None,
            prot: Some(record.prot),
            cpumode: mapping_cpumode_from_misc(misc),
        });
    }

    pub fn clone_pid_mappings(&mut self, parent_pid: u32, child_pid: u32) {
        if parent_pid == child_pid {
            return;
        }

        let mut child_bucket = self.bucket(parent_pid).to_vec();
        // perf maps.c:maps__copy_from copies the already sorted parent arrays.
        // Keep their interval augmentation while cloning arena entries in
        // insertion order, then replace each copied slot index exactly once.
        let mut parent_slots = child_bucket
            .iter()
            .enumerate()
            .map(|(position, indexed)| {
                #[cfg(test)]
                {
                    self.mutation_row_work
                        .borrow_mut()
                        .entry(self.mappings[indexed.index].pid)
                        .or_default()
                        .fork_select_rows += 1;
                }
                (position, indexed.index)
            })
            .collect::<Vec<_>>();
        parent_slots.sort_unstable_by_key(|&(_, index)| self.mappings.insertion_id(index));
        if let Some(child) = self.mappings_by_pid.remove(&child_pid) {
            for indexed in child {
                #[cfg(test)]
                {
                    self.mutation_row_work
                        .get_mut()
                        .entry(self.mappings[indexed.index].pid)
                        .or_default()
                        .fork_remove_rows += 1;
                }
                self.mappings.remove(indexed.index);
            }
        }
        self.update_pid_presence(child_pid, false, false);
        let mut may_execute = false;
        for (position, index) in parent_slots {
            #[cfg(test)]
            {
                self.mutation_row_work
                    .get_mut()
                    .entry(self.mappings[index].pid)
                    .or_default()
                    .fork_cloned_rows += 1;
            }
            let mut mapping = self.mappings[index].clone();
            mapping.pid = child_pid;
            mapping.symbol_source_id = self.intern_symbol_source(&mapping);
            may_execute |= mapping.may_execute();
            child_bucket[position].index = self.mappings.insert(mapping);
            #[cfg(test)]
            {
                self.mutation_row_work
                    .get_mut()
                    .entry(child_pid)
                    .or_default()
                    .index_writes += 1;
            }
        }
        if !child_bucket.is_empty() {
            self.mappings_by_pid.insert(child_pid, child_bucket);
            self.update_pid_presence(child_pid, true, may_execute);
        }
    }

    fn insert_mapping(&mut self, mut mapping: Mapping) {
        // map.c:map__new binds a DSO before inserting/splitting maps. Splits
        // and fork copies retain that ID without repeating wildcard lookup.
        mapping.native_dso_id = self.native_dsos.intern(
            &mapping.path,
            mapping.file_identity,
            if mapping.mmap_build_id {
                mapping.build_id.as_deref()
            } else {
                None
            },
        );
        // perf util/machine.c:870 and util/dsos.c:420-449 register the
        // util/dso.c:412-475 short name while retaining the long ELF path.
        // addr2line.c:444 opens file_name; libdwfl/dwfl_module_getdwarf.c:55
        // opens the selected file too. Neither should receive display metadata.
        if mapping.kernel_module_address(mapping.start).is_some() {
            mapping.module_display = crate::symbols::kcore::module_short_name(&mapping.path)
                .map(|name| Arc::from(name.as_ref()));
        }
        mapping.path_layout = MappingPathLayout::new(mapping.display_path());
        let next_id = self.display_path_ids.len();
        mapping.path_layout.display_path_id = *self
            .display_path_ids
            .entry_ref(mapping.display_path())
            .or_insert(next_id);
        // Common case: the new mapping does not overlap any existing mapping for
        // its pid. Detect this in O(log n + matches) using the per-pid interval
        // index and take a pure incremental insert. Splitting an overlap
        // updates only this PID's index and leaves foreign slots unchanged.
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
        let pid = new_mapping.pid;
        let mut bucket = self.mappings_by_pid.remove(&pid).unwrap_or_default();
        let mut removed = Vec::new();
        bucket.retain(|indexed| {
            #[cfg(test)]
            {
                self.mutation_row_work
                    .get_mut()
                    .entry(self.mappings[indexed.index].pid)
                    .or_default()
                    .overlap_rows += 1;
            }
            if self.mappings[indexed.index].overlaps(new_mapping) {
                removed.push(indexed.index);
                false
            } else {
                true
            }
        });
        removed.sort_unstable_by_key(|&index| self.mappings.insertion_id(index));
        let mut split_mappings = Vec::new();
        for index in removed {
            let mapping = self.mappings.remove(index);
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
                // perf util/maps.c:909 and util/map.h:280-282 use unsigned addition.
                after.pgoff = after.pgoff.wrapping_add(after.start - old_start);
                after.len = old_end - after.start;
                split_mappings.push(after);
            }
        }
        self.mappings_by_pid.insert(pid, bucket);
        self.rebuild_pid_index(pid);
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
        let end = mapping.end();
        let index = self.mappings.insert(mapping);
        let bucket = self.mappings_by_pid.entry(pid).or_default();
        let position = bucket.partition_point(|indexed| indexed.start <= start);
        let max_end = if position == 0 {
            end
        } else {
            bucket[position - 1].max_end.max(end)
        };
        #[cfg(test)]
        {
            let work = self.mutation_row_work.get_mut().entry(pid).or_default();
            work.index_writes += 1;
            work.index_tail_moves += bucket.len() - position;
        }
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

    fn rebuild_pid_index(&mut self, pid: u32) {
        let bucket = self
            .mappings_by_pid
            .get_mut(&pid)
            .expect("PID bucket exists");
        let mut max_end = 0;
        let mut may_execute = false;
        for indexed in bucket.iter_mut() {
            let mapping = &self.mappings[indexed.index];
            #[cfg(test)]
            {
                let work = self
                    .mutation_row_work
                    .get_mut()
                    .entry(mapping.pid)
                    .or_default();
                work.rebuild_rows += 1;
                work.index_writes += 1;
            }
            max_end = max_end.max(mapping.end());
            indexed.max_end = max_end;
            may_execute |= mapping.may_execute();
        }
        let has_mappings = !bucket.is_empty();
        if !has_mappings {
            self.mappings_by_pid.remove(&pid);
        }
        self.update_pid_presence(pid, has_mappings, may_execute);
    }

    fn update_pid_presence(&mut self, pid: u32, has_mappings: bool, may_execute: bool) {
        if pid == u32::MAX {
            self.has_global_mappings = has_mappings;
            self.has_global_executable_mappings = may_execute;
        } else {
            if has_mappings {
                self.pids_with_mappings.insert(pid);
            } else {
                self.pids_with_mappings.remove(&pid);
            }
            if may_execute {
                self.executable_pids.insert(pid);
            } else {
                self.executable_pids.remove(&pid);
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
                kernel_module_address: mapping.kernel_module_address(ip),
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

    pub(super) fn resolve_user_memory_cached(
        &self,
        pid: u32,
        ip: u64,
        cache: &mut MappingResolveCache,
    ) -> Option<DsoMemoryMapping<'_>> {
        let frame = self.resolve_user_frame_cached(pid, ip, cache)?;
        let dso = &self.native_dsos.entries[frame.mapping.native_dso_id];
        Some(DsoMemoryMapping {
            source_id: dso.id,
            path: &dso.path,
            relative_address: frame.relative_address,
            build_id: dso.build_id(),
        })
    }

    pub(super) fn initialize_native_dso_headers<'a>(
        &mut self,
        headers: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    ) {
        if self.native_dsos.headers_initialized {
            return;
        }
        for (path, id) in headers {
            self.native_dsos.register_header(path, id);
        }
        self.native_dsos.headers_initialized = true;
    }

    pub(super) fn update_native_dso_build_id(&mut self, path: &str, build_id: &[u8]) {
        // header.c:__event_process_build_id finds with empty file/build identity,
        // then sets the ID on the existing DSO; maps keep their DSO binding.
        let id = self.native_dsos.intern(path, None, None);
        self.native_dsos.entries[id].set_build_id(build_id);
        self.native_dsos.header_paths.insert(path.to_owned());
        // dso.c:dso__set_build_id does not change dsos->sorted. Only identity
        // enrichment through __dso__improve_id invalidates lookup order.
    }

    pub(crate) fn symbol_mapping_ref<'a, R: SymbolResolver>(
        &'a self,
        frame: MappedFrame<'a>,
        resolver: Option<&R>,
    ) -> ResolvedMappingRef<'a> {
        let Some(resolver) = resolver else {
            return frame.resolved_ref();
        };
        // symbol.c:1705/1866 loads a DSO once, including failed loads. Later
        // stream metadata changes the current DSO ID, not its loaded symbols.
        let dso = &self.native_dsos.entries[frame.mapping.native_dso_id];
        let mut mapping = frame.resolved_ref();
        mapping.build_id = dso
            .symbol_build_id
            .get_or_init(|| {
                // symbol.c:dso__load fills an undefined ID from the live ELF
                // before cache selection. Later MMAP2 comparisons see that ID.
                if dso.build_id.get().is_none()
                    && let Some(id) = resolver.object_build_id(std::path::Path::new(&dso.path))
                    && id.iter().any(|byte| *byte != 0)
                {
                    dso.build_id.set(id).expect("undefined DSO build ID");
                }
                dso.build_id.get().cloned()
            })
            .as_deref();
        mapping
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
                latest_matching_index = Some(latest_matching_index.map_or(index, |latest| {
                    if self.mappings.insertion_id(index) > self.mappings.insertion_id(latest) {
                        index
                    } else {
                        latest
                    }
                }));
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

    fn cached_mapping_index(
        &self,
        pid: u32,
        ip: u64,
        cached_index: Option<usize>,
        predicate: &impl Fn(&Mapping) -> bool,
    ) -> Option<usize> {
        #[cfg(test)]
        self.cache_index_probes
            .set(self.cache_index_probes.get() + 1);
        // maps.c:__maps__fixup_overlap_and_insert leaves disjoint ranges per
        // PID. Check the live entry, not a stored mapping: a released slot can
        // belong to a new PID, range, or CPU mode, with new translation data.
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
        // maps.c:844 overlap fixup leaves disjoint ranges, so CPU-mode
        // filtering can happen after the containing map has been found.
        self.search_bucket(bucket, ip)
            .ok()
            .filter(|&index| predicate(&self.mappings[index]))
    }

    #[inline]
    fn search_bucket(&self, bucket: &[IndexedMapping], ip: u64) -> Result<usize, usize> {
        #[cfg(test)]
        self.index_searches.set(self.index_searches.get() + 1);
        let insertion = bucket.partition_point(|indexed| indexed.start <= ip);
        let mut upper_bound = insertion;
        while upper_bound > 0 {
            upper_bound -= 1;
            let indexed = &bucket[upper_bound];
            if indexed.max_end <= ip {
                break;
            }
            let index = indexed.index;
            let mapping = &self.mappings[index];
            if ip < mapping.end() {
                // Perf maps.c:844 removes overlapping ranges per PID. Keep
                // walking past zero-length entries, but only one map can hit.
                return Ok(index);
            }
        }
        Err(insertion)
    }

    fn bucket_gap(bucket: &[IndexedMapping], insertion: usize) -> FrameMappingMiss {
        // maps.c:1110 map__addr_cmp uses [start, end). The prefix maximum
        // also handles zero-length entries when deriving the surrounding gap.
        // An inclusive last address represents the unmapped u64::MAX itself.
        let start = insertion
            .checked_sub(1)
            .map_or(0, |index| bucket[index].max_end);
        let last = bucket
            .get(insertion)
            .map_or(u64::MAX, |next| next.start - 1);
        FrameMappingMiss { start, last }
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
    fn display_path(&self) -> &str {
        self.module_display.as_deref().unwrap_or(&self.path)
    }

    fn kernel_module_address(&self, ip: u64) -> Option<u64> {
        // machine.c:machine__process_kernel_mmap_event creates a module map
        // for an absolute kernel path even when its name has no .ko suffix.
        (self.cpumode == crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL
            && self.path.starts_with('/'))
        .then_some(ip)
    }

    fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    fn relative_address(&self, ip: u64) -> u64 {
        ip.wrapping_add(self.translation_bias())
    }

    fn translation_bias(&self) -> u64 {
        // perf util/map.h:107-125: unsigned DSO translation, identity otherwise.
        if self.is_kernel_symbol_mapping() {
            0
        } else {
            self.pgoff.wrapping_sub(self.start)
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
        #[cfg(test)]
        FRAME_MAPPING_USER_CLASSIFICATIONS.with(|count| count.set(count.get() + 1));
        self.cpumode == PERF_RECORD_MISC_CPUMODE_USER
    }

    fn is_known_non_executable(&self) -> bool {
        self.prot.is_some_and(|prot| prot & PROT_EXEC == 0) || is_perf_data_path(&self.path)
    }

    fn may_execute(&self) -> bool {
        !self.is_known_non_executable()
    }

    fn is_kernel_symbol_mapping(&self) -> bool {
        #[cfg(test)]
        FRAME_MAPPING_TRANSLATION_CLASSIFICATIONS.with(|count| count.set(count.get() + 1));
        self.pid == u32::MAX && self.path.starts_with('[')
    }

    fn symbol_source_key(&self) -> SymbolSourceKey {
        // perf compares known device/inode identities before build IDs. Its
        // missing-identity wildcard is not transitive, so retain all recorded
        // identity in hash keys. Mixed mmap forms may resolve separately.
        SymbolSourceKey {
            path: if self.is_kernel_symbol_mapping() && self.path.starts_with("[kernel") {
                "[kernel.kallsyms]".to_string()
            } else {
                self.path.clone()
            },
            build_id: self.build_id.clone(),
            file_identity: self.file_identity,
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
    use proptest::prelude::*;

    struct BuildIdProbe {
        calls: std::cell::Cell<usize>,
        id: Option<Vec<u8>>,
    }

    impl crate::symbols::SymbolResolver for BuildIdProbe {
        fn object_build_id(&self, _path: &std::path::Path) -> Option<Vec<u8>> {
            self.calls.set(self.calls.get() + 1);
            self.id.clone()
        }

        fn resolve_batch(
            &self,
            _requests: &[crate::symbols::SymbolRequest],
        ) -> Result<Vec<Option<String>>, String> {
            unreachable!("this test only initializes DSO identity")
        }
    }

    #[test]
    fn dso_identity_discovery_runs_once_and_metadata_does_not_reload_symbols() {
        // symbol.c:dso__load fills a missing ID, then sets loaded even on
        // failure. header.c can update/clear that ID without reloading symbols.
        for id in [None, Some(vec![0x11; 20])] {
            let mut table = super::MmapTable::default();
            table.insert_mmap(mutation_record(7, 0x1000, 0x100, 0, "/object"));
            let resolver = BuildIdProbe {
                calls: std::cell::Cell::new(0),
                id: id.clone(),
            };
            let mut cache = super::MappingResolveCache::default();
            let frame = table
                .resolve_user_frame_cached(7, 0x1000, &mut cache)
                .unwrap();
            assert_eq!(
                table
                    .symbol_mapping_ref::<BuildIdProbe>(frame, None)
                    .build_id,
                None
            );
            assert_eq!(resolver.calls.get(), 0, "no-symbols must not load the ELF");
            for address in 0x1000..0x1020 {
                let frame = table
                    .resolve_user_frame_cached(7, address, &mut cache)
                    .unwrap();
                assert_eq!(
                    table.symbol_mapping_ref(frame, Some(&resolver)).build_id,
                    id.as_deref()
                );
            }
            assert_eq!(resolver.calls.get(), 1, "probe only the first DSO lookup");
            assert_eq!(
                table
                    .resolve_user_memory_cached(7, 0x1000, &mut cache)
                    .unwrap()
                    .build_id,
                id.as_deref(),
                "the discovered ID must be published to the native DSO"
            );
            table.clone_pid_mappings(7, 8);
            for replacement in [&[0x22; 20], &[0; 20]] {
                table.update_native_dso_build_id("/object", replacement);
                for pid in [7, 8] {
                    let frame = table
                        .resolve_user_frame_cached(pid, 0x1000, &mut cache)
                        .unwrap();
                    assert_eq!(
                        table.symbol_mapping_ref(frame, Some(&resolver)).build_id,
                        id.as_deref(),
                        "forked maps retain the same loaded symbol source"
                    );
                }
            }
            assert_eq!(resolver.calls.get(), 1);
            assert_eq!(
                table
                    .resolve_user_memory_cached(7, 0x1000, &mut cache)
                    .unwrap()
                    .build_id,
                None
            );
        }
    }

    #[test]
    fn native_dso_enrichment_resorts_lookup_without_rebinding_forks_or_splits() {
        let mut table = super::MmapTable::default();
        let mut first = churn_mapping(7, 0x1000, 0x100, 0, "/object");
        first.file_identity.inode = 1;
        first.insert_into(&mut table);
        // Enrich the first entry's build ID, then add a distinct build-ID
        // entry with no inode: initial order is [inode 1/id 11, id 22].
        let build_map = |pid, byte| super::Mmap2BuildIdRecord {
            pid,
            tid: pid,
            start: 0x1000,
            len: 0x100,
            pgoff: 0,
            build_id_size: 20,
            build_id: vec![byte; 20],
            prot: 5,
            flags: 2,
            path: "/object".into(),
        };
        table.insert_mmap2_build_id(build_map(7, 0x11));
        table.insert_mmap2_build_id(build_map(8, 0x22));
        let second_id = table
            .resolve_user_memory_cached(8, 0x1000, &mut super::MappingResolveCache::default())
            .unwrap()
            .source_id;
        let mut enriched = first.clone();
        enriched.pid = 9;
        enriched.file_identity.inode = 2;
        table.insert_mmap2_with_build_id(
            super::Mmap2Record {
                pid: 9,
                tid: 9,
                start: enriched.start,
                len: enriched.len,
                pgoff: enriched.pgoff,
                major: enriched.file_identity.major,
                minor: enriched.file_identity.minor,
                inode: enriched.file_identity.inode,
                inode_generation: enriched.file_identity.inode_generation,
                prot: enriched.prot,
                flags: 2,
                path: enriched.path,
            },
            Some(vec![0x22; 20]),
        );
        assert!(!table.native_dsos.sorted);
        table.insert_mmap(mutation_record(10, 0x1000, 0x100, 0, "/object"));
        // Enrichment changes order to [inode 2/id 22, inode 1/id 11].
        let wildcard = table
            .resolve_user_memory_cached(10, 0x1000, &mut super::MappingResolveCache::default())
            .unwrap();
        assert_eq!(wildcard.build_id, Some([0x11; 20].as_slice()));
        assert_ne!(wildcard.source_id, second_id);
        table.clone_pid_mappings(8, 11);
        table.insert_mmap(mutation_record(8, 0x1040, 0x20, 0, "/replacement"));
        for (pid, address) in [(8, 0x1000), (8, 0x1060), (9, 0x1000), (11, 0x1000)] {
            let bound = table
                .resolve_user_memory_cached(
                    pid,
                    address,
                    &mut super::MappingResolveCache::default(),
                )
                .unwrap();
            assert_eq!(bound.source_id, second_id);
            assert_eq!(bound.build_id, Some([0x22; 20].as_slice()));
        }
        // Enriched memory metadata must not rewrite recorded symbol identity.
        assert_eq!(table.resolve_ref(8, 0x1000).unwrap().file_identity, None);
    }

    #[test]
    fn native_dso_identity_wildcards_are_non_transitive_and_zero_inodes_are_known() {
        let file = |inode| super::FileIdentity {
            major: 0,
            minor: 0,
            inode,
            inode_generation: 0,
        };
        let dso = |inode: Option<u64>, byte| super::NativeDso {
            id: 0,
            path: "/object".into(),
            file_identity: inode.map(file),
            build_id: std::cell::OnceCell::from(vec![byte; 20]),
            symbol_build_id: std::cell::OnceCell::new(),
        };
        let a = dso(Some(2), 0x33);
        let b = dso(Some(1), 0x11);
        let c = dso(None, 0x22);
        for (left, right) in [(&a, &b), (&b, &c), (&c, &a)] {
            assert!(
                left.compare(&right.path, right.file_identity, right.build_id())
                    .is_lt()
            );
        }
        let mut registry = super::NativeDsoRegistry::default();
        let zero = registry.intern("/object", Some(file(0)), Some(&[0; 20]));
        assert_eq!(registry.entries[zero].build_id.get(), None);
        assert_ne!(zero, registry.intern("/object", Some(file(1)), None));
        // An absent build ID is compatible, but known zero inode fields
        // still distinguish a source from nonzero inode fields.
        assert_eq!(zero, registry.intern("/object", Some(file(0)), Some(&[])));
        let known = registry.intern("/other", None, Some(&[0x11; 20]));
        assert_eq!(known, registry.intern("/other", None, Some(&[0; 20])));
        assert_ne!(known, registry.intern("/other", None, Some(&[0x11; 19])));
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ChurnMapping {
        pid: u32,
        start: u64,
        len: u64,
        pgoff: u64,
        path: String,
        cpumode: u16,
        prot: u32,
        file_identity: super::FileIdentity,
    }

    impl ChurnMapping {
        fn end(&self) -> u64 {
            self.start.saturating_add(self.len)
        }

        fn resolved(&self, ip: u64) -> super::ResolvedMapping {
            super::ResolvedMapping {
                path: self.path.clone(),
                relative_address: if self.pid == u32::MAX && self.path.starts_with('[') {
                    ip
                } else {
                    ip.wrapping_sub(self.start).wrapping_add(self.pgoff)
                },
                start: self.start,
                end: self.end(),
                build_id: None,
                file_identity: Some(self.file_identity),
                kernel_relocation: None,
            }
        }

        fn insert_into(&self, table: &mut super::MmapTable) {
            table.insert_mmap2_with_misc(
                super::Mmap2Record {
                    pid: self.pid,
                    tid: self.pid,
                    start: self.start,
                    len: self.len,
                    pgoff: self.pgoff,
                    major: self.file_identity.major,
                    minor: self.file_identity.minor,
                    inode: self.file_identity.inode,
                    inode_generation: self.file_identity.inode_generation,
                    prot: self.prot,
                    flags: 2,
                    path: self.path.clone(),
                },
                self.cpumode,
            );
        }
    }

    fn churn_mapping(pid: u32, start: u64, len: u64, pgoff: u64, path: &str) -> ChurnMapping {
        ChurnMapping {
            pid,
            start,
            len,
            pgoff,
            path: path.into(),
            cpumode: super::PERF_RECORD_MISC_CPUMODE_USER,
            prot: 5,
            file_identity: super::FileIdentity {
                major: 8,
                minor: 1,
                inode: 99,
                inode_generation: 7,
            },
        }
    }

    #[derive(Debug)]
    enum ChurnOperation {
        Insert(ChurnMapping),
        Fork(u32, u32),
    }

    // Independent flat-vector model: perf maps.c:844 clones uncovered pieces
    // and adjusts the right piece's pgoff; maps.c:1032 clones parent values.
    // No arena, index, cache, or production overlap/translation helpers.
    #[derive(Default)]
    struct FlatMappingOracle {
        rows: Vec<ChurnMapping>,
    }

    impl FlatMappingOracle {
        fn apply(&mut self, operation: &ChurnOperation) {
            match operation {
                ChurnOperation::Insert(new) => {
                    let mut survivors = Vec::new();
                    let mut fragments = Vec::new();
                    for old in std::mem::take(&mut self.rows) {
                        if old.pid != new.pid || old.end() <= new.start || new.end() <= old.start {
                            survivors.push(old);
                            continue;
                        }
                        if old.start < new.start {
                            let mut left = old.clone();
                            left.len = new.start - old.start;
                            fragments.push(left);
                        }
                        if new.end() < old.end() {
                            let mut right = old.clone();
                            right.start = new.end();
                            right.len = old.end() - right.start;
                            right.pgoff = right.pgoff.wrapping_add(right.start - old.start);
                            fragments.push(right);
                        }
                    }
                    survivors.extend(fragments);
                    survivors.push(new.clone());
                    self.rows = survivors;
                }
                ChurnOperation::Fork(parent, child) if parent != child => {
                    let inherited = self
                        .rows
                        .iter()
                        .filter(|row| row.pid == *parent)
                        .cloned()
                        .map(|mut row| {
                            row.pid = *child;
                            row
                        })
                        .collect::<Vec<_>>();
                    self.rows.retain(|row| row.pid != *child);
                    self.rows.extend(inherited);
                }
                ChurnOperation::Fork(_, _) => {}
            }
        }

        fn resolve(&self, pid: u32, ip: u64, user_only: bool) -> Option<super::ResolvedMapping> {
            let containing = |wanted_pid| {
                self.rows.iter().rev().find(|row| {
                    row.pid == wanted_pid
                        && row.start <= ip
                        && ip < row.end()
                        && (!user_only || row.cpumode == super::PERF_RECORD_MISC_CPUMODE_USER)
                })
            };
            let local = containing(pid);
            let winner = if user_only || pid == u32::MAX {
                local
            } else {
                match (local, containing(u32::MAX)) {
                    (Some(left), Some(right)) if left.start >= right.start => Some(left),
                    (_, Some(right)) => Some(right),
                    (Some(left), None) => Some(left),
                    (None, None) => None,
                }
            };
            winner.map(|row| row.resolved(ip))
        }
    }

    fn owned_frame_metadata(frame: super::MappedFrame<'_>) -> super::ResolvedMapping {
        let resolved = frame.resolved_ref();
        super::ResolvedMapping {
            path: resolved.path.into(),
            relative_address: resolved.relative_address,
            start: resolved.start,
            end: resolved.end,
            build_id: resolved.build_id.map(<[u8]>::to_vec),
            file_identity: resolved.file_identity,
            kernel_relocation: resolved.kernel_relocation,
        }
    }

    fn apply_churn_operation(
        table: &mut super::MmapTable,
        oracle: &mut FlatMappingOracle,
        operation: &ChurnOperation,
    ) {
        match operation {
            ChurnOperation::Insert(mapping) => mapping.insert_into(table),
            ChurnOperation::Fork(parent, child) => table.clone_pid_mappings(*parent, *child),
        }
        oracle.apply(operation);
    }

    fn assert_churn_state(
        table: &super::MmapTable,
        oracle: &FlatMappingOracle,
        cache: &mut super::MappingResolveCache,
        user_cache: &mut super::MappingResolveCache,
    ) {
        assert_mapping_arena_invariants(table);
        let actual = table
            .mappings
            .iter()
            .map(|row| ChurnMapping {
                pid: row.pid,
                start: row.start,
                len: row.len,
                pgoff: row.pgoff,
                path: row.path.clone(),
                cpumode: row.cpumode,
                prot: row.prot.expect("churn uses MMAP2"),
                file_identity: row.file_identity.expect("churn uses inode-form MMAP2"),
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, oracle.rows, "live rows or insertion order differ");
        let expected_user = oracle
            .rows
            .iter()
            .filter(|row| row.pid != u32::MAX && !row.path.starts_with('['))
            .map(|row| super::UserMapping {
                pid: row.pid,
                start: row.start,
                len: row.len,
                pgoff: row.pgoff,
                prot: Some(row.prot),
                path: &row.path,
                build_id: None,
                file_identity: Some(row.file_identity),
            })
            .collect::<Vec<_>>();
        assert_eq!(table.user_mappings().collect::<Vec<_>>(), expected_user);
        let mut addresses = vec![0, 0xfff, 0x1000, 0x1800, u64::MAX - 1, u64::MAX];
        for row in &oracle.rows {
            addresses.extend([
                row.start.saturating_sub(1),
                row.start,
                row.start.saturating_add(1),
                row.end().saturating_sub(1),
                row.end(),
            ]);
        }
        addresses.sort_unstable();
        addresses.dedup();
        for pid in [7, 8, 9, 101, 404, u32::MAX] {
            let present = oracle
                .rows
                .iter()
                .any(|row| row.pid == pid || row.pid == u32::MAX);
            let executable = oracle
                .rows
                .iter()
                .any(|row| (row.pid == pid || row.pid == u32::MAX) && row.prot & 4 != 0);
            assert_eq!(table.has_mappings_for_pid(pid), present);
            assert_eq!(table.has_executable_mappings_for_pid(pid), executable);
            let context = table.frame_context(pid, cache);
            let user_context = table.frame_context(pid, user_cache);
            // Alternate ascending and descending probes to exercise warm hints
            // and cached gap proofs in both directions within a sample.
            for &ip in addresses.iter().chain(addresses.iter().rev()) {
                let expected = oracle.resolve(pid, ip, false);
                assert_eq!(
                    table.resolve(pid, ip),
                    expected,
                    "uncached PID {pid} IP {ip:x}"
                );
                assert_eq!(
                    table
                        .resolve_frame_cached(pid, ip, cache)
                        .map(owned_frame_metadata),
                    expected,
                    "cached PID {pid} IP {ip:x}"
                );
                assert_eq!(
                    context.resolve(ip, cache).map(owned_frame_metadata),
                    expected,
                    "context PID {pid} IP {ip:x}"
                );
                let expected_user = oracle.resolve(pid, ip, true);
                assert_eq!(
                    table
                        .resolve_user_frame_cached(pid, ip, user_cache)
                        .map(owned_frame_metadata),
                    expected_user,
                    "USER cached PID {pid} IP {ip:x}"
                );
                assert_eq!(
                    user_context
                        .resolve_user(ip, user_cache)
                        .map(owned_frame_metadata),
                    expected_user,
                    "USER context PID {pid} IP {ip:x}"
                );
            }
        }
    }

    fn churn_operation_strategy() -> impl Strategy<Value = ChurnOperation> {
        let pid = prop::sample::select(vec![7_u32, 8, 9, 101, u32::MAX]);
        let insert = (
            pid.clone(),
            0_u64..16,
            0_u64..12,
            0_u64..16,
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            0_u8..4,
        )
            .prop_map(
                |(pid, address, len, offset, high, user, executable, path)| {
                    let start = if high {
                        u64::MAX - 0x200 + address * 0x20
                    } else {
                        0x1000 + address * 0x20
                    };
                    let path = match path {
                        0 => "/first",
                        1 => "/second",
                        2 => "[module]",
                        _ => "/third",
                    };
                    let mut mapping = churn_mapping(pid, start, len * 0x20, offset * 0x20, path);
                    mapping.cpumode = if user {
                        super::PERF_RECORD_MISC_CPUMODE_USER
                    } else {
                        crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL
                    };
                    mapping.prot = if executable { 5 } else { 1 };
                    ChurnOperation::Insert(mapping)
                },
            );
        prop_oneof![3 => insert, 1 => (pid.clone(), pid).prop_map(|(parent, child)| ChurnOperation::Fork(parent, child))]
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        #[test]
        fn arena_churn_cached_frames_match_independent_flat_vector_oracle(
            operations in prop::collection::vec(churn_operation_strategy(), 1..65),
        ) {
            let mut table = super::MmapTable::default();
            let mut oracle = FlatMappingOracle::default();
            let mut cache = super::MappingResolveCache::default();
            let mut user_cache = super::MappingResolveCache::default();
            for operation in &operations {
                let pid = match operation {
                    ChurnOperation::Insert(mapping) => mapping.pid,
                    ChurnOperation::Fork(_, child) => *child,
                };
                let warm_address = oracle.rows.iter().rev().find(|row| {
                    (row.pid == pid || row.pid == u32::MAX) && row.start < row.end()
                }).map(|row| row.start);
                if let Some(ip) = warm_address {
                    prop_assert_eq!(
                        table.resolve_frame_cached(pid, ip, &mut cache).map(owned_frame_metadata),
                        oracle.resolve(pid, ip, false)
                    );
                    prop_assert_eq!(
                        table.resolve_user_frame_cached(pid, ip, &mut user_cache).map(owned_frame_metadata),
                        oracle.resolve(pid, ip, true)
                    );
                }
                apply_churn_operation(&mut table, &mut oracle, operation);
                if let Some(ip) = warm_address {
                    prop_assert_eq!(
                        table.resolve_frame_cached(pid, ip, &mut cache).map(owned_frame_metadata),
                        oracle.resolve(pid, ip, false),
                        "warm cache after {:?}", operation
                    );
                    prop_assert_eq!(
                        table.resolve_user_frame_cached(pid, ip, &mut user_cache).map(owned_frame_metadata),
                        oracle.resolve(pid, ip, true),
                        "warm USER cache after {:?}", operation
                    );
                }
                assert_churn_state(&table, &oracle, &mut cache, &mut user_cache);
            }
        }
    }

    #[test]
    fn warm_child_fork_chains_preserve_inherited_identity_after_parent_churn() {
        let mut table = super::MmapTable::default();
        let mut oracle = FlatMappingOracle::default();
        let mut cache = super::MappingResolveCache::default();
        let mut user_cache = super::MappingResolveCache::default();
        for mapping in [
            churn_mapping(7, 0x1000, 0x1000, 0x100, "/parent-a"),
            churn_mapping(7, 0x3000, 0x100, 0x300, "/parent-tail"),
            churn_mapping(101, 0x1000, 0x1000, 0x900, "/parent-b"),
            churn_mapping(8, 0x1000, 0x1000, 0x700, "/old-child"),
        ] {
            apply_churn_operation(&mut table, &mut oracle, &ChurnOperation::Insert(mapping));
        }
        let mut child_cache = super::MappingResolveCache::default();
        let mut grandchild_cache = super::MappingResolveCache::default();
        let old_child = mapping_identity_snapshot(&table, 8, 0x1010, &mut child_cache);
        for (generation, parent) in [7, 101, 7, 101, 7, 101].into_iter().enumerate() {
            let mut parent_cache = super::MappingResolveCache::default();
            let inherited = mapping_identity_snapshot(&table, parent, 0x1010, &mut parent_cache);
            apply_churn_operation(&mut table, &mut oracle, &ChurnOperation::Fork(parent, 8));
            let child = mapping_identity_snapshot(&table, 8, 0x1010, &mut child_cache);
            assert_eq!(child, inherited);
            assert_ne!(child.source_id, old_child.source_id);
            apply_churn_operation(&mut table, &mut oracle, &ChurnOperation::Fork(8, 9));
            assert_eq!(
                mapping_identity_snapshot(&table, 9, 0x1010, &mut grandchild_cache),
                inherited
            );
            let offset = u64::try_from(generation).unwrap() * 0x100 + 0x2000;
            apply_churn_operation(
                &mut table,
                &mut oracle,
                &ChurnOperation::Insert(churn_mapping(
                    parent,
                    0x1000,
                    0x1000,
                    offset,
                    "/replaced-parent",
                )),
            );
            for (pid, hint) in [(8, &mut child_cache), (9, &mut grandchild_cache)] {
                assert_eq!(
                    mapping_identity_snapshot(&table, pid, 0x1010, hint),
                    inherited
                );
            }
            apply_churn_operation(&mut table, &mut oracle, &ChurnOperation::Fork(8, 8));
            assert_eq!(
                mapping_identity_snapshot(&table, 8, 0x1010, &mut child_cache),
                inherited
            );
            assert_churn_state(&table, &oracle, &mut cache, &mut user_cache);

            let mut vacant_cache = child_cache;
            apply_churn_operation(&mut table, &mut oracle, &ChurnOperation::Fork(505, 8));
            assert!(
                table
                    .resolve_frame_cached(8, 0x1010, &mut vacant_cache)
                    .is_none()
            );
            apply_churn_operation(
                &mut table,
                &mut oracle,
                &ChurnOperation::Insert(churn_mapping(404, 0x1000, 0x1000, offset, "/foreign")),
            );
            assert!(
                table
                    .resolve_frame_cached(8, 0x1010, &mut child_cache)
                    .is_none()
            );
            assert_eq!(
                mapping_identity_snapshot(&table, 9, 0x1010, &mut grandchild_cache),
                inherited
            );
            assert_churn_state(&table, &oracle, &mut cache, &mut user_cache);
        }
    }

    #[test]
    fn global_precedence_churn_revalidates_warm_slots_ties_modes_and_boundaries() {
        let mut table = super::MmapTable::default();
        let mut oracle = FlatMappingOracle::default();
        let mut cache = super::MappingResolveCache::default();
        let mut user_cache = super::MappingResolveCache::default();
        let mut warm = super::MappingResolveCache::default();
        let mut local = churn_mapping(7, 0x1000, 0x1000, 0x100, "/local");
        let global = churn_mapping(u32::MAX, 0x1800, 0x800, 0x900, "[module]");
        for mapping in [local.clone(), global] {
            apply_churn_operation(&mut table, &mut oracle, &ChurnOperation::Insert(mapping));
        }
        assert_eq!(
            mapping_identity_snapshot(&table, 7, 0x1810, &mut warm)
                .resolved
                .path,
            "[module]"
        );
        let removed_global = warm.global_index.unwrap();
        apply_churn_operation(
            &mut table,
            &mut oracle,
            &ChurnOperation::Fork(505, u32::MAX),
        );
        apply_churn_operation(
            &mut table,
            &mut oracle,
            &ChurnOperation::Insert(churn_mapping(101, 0x1800, 0x800, 0x500, "/foreign")),
        );
        assert_eq!(
            table.mappings[removed_global].pid, 101,
            "must exercise actual slot reuse"
        );
        assert_eq!(
            mapping_identity_snapshot(&table, 7, 0x1810, &mut warm)
                .resolved
                .path,
            "/local"
        );
        assert_churn_state(&table, &oracle, &mut cache, &mut user_cache);

        for path in ["[global-tie]", "/global-file"] {
            apply_churn_operation(
                &mut table,
                &mut oracle,
                &ChurnOperation::Insert(churn_mapping(u32::MAX, 0x1000, 0x1000, 0x700, path)),
            );
            assert_eq!(
                mapping_identity_snapshot(&table, 7, 0x1010, &mut warm)
                    .resolved
                    .path,
                "/local"
            );
            local.cpumode = crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL;
            apply_churn_operation(
                &mut table,
                &mut oracle,
                &ChurnOperation::Insert(local.clone()),
            );
            assert!(
                table
                    .resolve_user_frame_cached(7, 0x1010, &mut user_cache)
                    .is_none()
            );
            assert_churn_state(&table, &oracle, &mut cache, &mut user_cache);
            apply_churn_operation(&mut table, &mut oracle, &ChurnOperation::Fork(505, 7));
            assert_eq!(
                mapping_identity_snapshot(&table, 7, 0x1010, &mut warm)
                    .resolved
                    .path,
                path
            );
            assert_churn_state(&table, &oracle, &mut cache, &mut user_cache);
            local.cpumode = super::PERF_RECORD_MISC_CPUMODE_USER;
            apply_churn_operation(
                &mut table,
                &mut oracle,
                &ChurnOperation::Insert(local.clone()),
            );
        }
        for mapping in [
            churn_mapping(u32::MAX, 0x1400, 0x100, 0x200, "[split]"),
            churn_mapping(7, 0x1400, 0x100, 0x300, "/equal-split"),
            churn_mapping(7, 0x1450, 0, 0x400, "/zero"),
            churn_mapping(u32::MAX, u64::MAX - 0x30, 0x100, 0x500, "[saturated]"),
            churn_mapping(7, u64::MAX - 0x20, 0x100, 0x600, "/saturated-local"),
        ] {
            apply_churn_operation(&mut table, &mut oracle, &ChurnOperation::Insert(mapping));
            assert_churn_state(&table, &oracle, &mut cache, &mut user_cache);
        }
    }

    #[test]
    fn bulk_fork_preserves_sorted_prefix_bounds_for_zero_lengths_and_saturated_ends() {
        let mut table = super::MmapTable::default();
        for (start, len, path) in [
            (u64::MAX - 0x30, 0x100, "/saturated"),
            (0x3000, 0, "/empty"),
            (0x1000, 0x100, "/first"),
            (0, 0, "/zero"),
        ] {
            table.insert_mmap(mutation_record(7, start, len, 0x20, path));
        }
        table.insert_mmap(mutation_record(8, 0x1000, 0x100, 0x900, "/old-child"));
        let mut parent_cache = super::MappingResolveCache::default();
        let mut child_cache = super::MappingResolveCache::default();
        table
            .resolve_frame_cached(8, 0x1010, &mut child_cache)
            .unwrap();
        table.clone_pid_mappings(7, 8);
        assert_mapping_arena_invariants(&table);
        for address in [
            0,
            0xfff,
            0x1000,
            0x10ff,
            0x1100,
            0x3000,
            u64::MAX - 1,
            u64::MAX,
        ] {
            assert_eq!(table.resolve(8, address), table.resolve(7, address));
            assert_eq!(
                table
                    .resolve_frame_cached(8, address, &mut child_cache)
                    .map(super::MappedFrame::resolved_ref),
                table
                    .resolve_frame_cached(7, address, &mut parent_cache)
                    .map(super::MappedFrame::resolved_ref)
            );
        }
        let before = table
            .user_mappings()
            .map(|mapping| (mapping.pid, mapping.start))
            .collect::<Vec<_>>();
        table.clone_pid_mappings(7, 7);
        assert_eq!(
            table
                .user_mappings()
                .map(|mapping| (mapping.pid, mapping.start))
                .collect::<Vec<_>>(),
            before
        );
        assert_mapping_arena_invariants(&table);
    }

    #[test]
    fn bulk_fork_reinterns_source_identity_when_cloning_between_pid_domains() {
        let mut table = super::MmapTable::default();
        let start = 0xffff_ffff_8100_0000;
        let address = start + 0x10;
        table.insert_mmap(mutation_record(
            7,
            start,
            0x100,
            0x500,
            "[kernel.kallsyms]_text",
        ));
        let mut cache = super::MappingResolveCache::default();
        let local = mapping_identity_snapshot(&table, 7, address, &mut cache);
        assert_eq!(local.resolved.relative_address, 0x510);
        table.clone_pid_mappings(7, u32::MAX);
        let global = mapping_identity_snapshot(&table, u32::MAX, address, &mut cache);
        assert_eq!(global.resolved.relative_address, address);
        assert_ne!(global.source_id, local.source_id);
        assert_eq!(global.display_id, local.display_id);
        assert_eq!(
            global.resolved.kernel_relocation,
            local.resolved.kernel_relocation
        );
        assert_mapping_arena_invariants(&table);
        table.clone_pid_mappings(u32::MAX, 8);
        let child = mapping_identity_snapshot(&table, 8, address, &mut cache);
        assert_eq!(child, local);
        assert_mapping_arena_invariants(&table);
    }

    #[test]
    fn reverse_address_insertions_count_actual_pid_index_tail_moves() {
        let mut table = super::MmapTable::default();
        for index in (0..8).rev() {
            table.insert_mmap(mutation_record(
                7,
                0x1000 + index * 0x100,
                0x80,
                index * 0x10,
                "/reverse",
            ));
        }
        let work = table.mutation_row_work.borrow();
        assert_eq!(work[&7].index_writes, 8);
        assert_eq!(work[&7].index_tail_moves, 8 * 7 / 2);
        assert_mapping_arena_invariants(&table);
    }

    #[test]
    fn fork_bulk_clones_reverse_address_parent_without_child_index_tail_moves() {
        // perf maps.c:maps__copy_from's empty-dest branch clones the parent
        // arrays directly and preserves their sorted flag, without inserting
        // each child map into a growing sorted vector.
        let mut table = super::MmapTable::default();
        for index in (0..64).rev() {
            table.insert_mmap(mutation_record(
                7,
                0x1000 + index * 0x100,
                0x80,
                index * 0x10,
                &format!("/reverse-{index}"),
            ));
        }
        let expected_order = table
            .user_mappings()
            .map(|mapping| mapping.start)
            .collect::<Vec<_>>();
        table.mutation_row_work.get_mut().clear();
        table.clone_pid_mappings(7, 8);
        assert_mapping_arena_invariants(&table);
        assert_eq!(
            table
                .user_mappings()
                .filter(|mapping| mapping.pid == 8)
                .map(|mapping| mapping.start)
                .collect::<Vec<_>>(),
            expected_order
        );
        let mut parent_cache = super::MappingResolveCache::default();
        let mut child_cache = super::MappingResolveCache::default();
        for index in 0..64 {
            let address = 0x1010 + index * 0x100;
            assert_eq!(
                mapping_identity_snapshot(&table, 8, address, &mut child_cache),
                mapping_identity_snapshot(&table, 7, address, &mut parent_cache)
            );
        }
        let work = table.mutation_row_work.borrow();
        assert_eq!(work[&7].fork_select_rows, 64);
        assert_eq!(work[&7].fork_cloned_rows, 64);
        assert_eq!(work[&8].index_writes, 64);
        assert_eq!(
            work[&8].index_tail_moves, 0,
            "fork inserted child maps one at a time"
        );
    }

    fn assert_mapping_arena_invariants(table: &super::MmapTable) {
        let arena = &table.mappings;
        let mut live = super::HashSet::<_, super::FxBuildHasher>::default();
        let mut next = arena.first;
        let mut previous = None;
        while let Some(index) = next {
            assert!(live.insert(index), "arena order contains a cycle");
            let slot = &arena.slots[index];
            assert!(slot.mapping.is_some());
            assert_eq!(slot.previous, previous);
            previous = Some(index);
            next = slot.next;
        }
        assert_eq!(previous, arena.last);
        let free = arena
            .free
            .iter()
            .copied()
            .collect::<super::HashSet<_, super::FxBuildHasher>>();
        assert_eq!(free.len(), arena.free.len(), "a slot was freed twice");
        assert_eq!(free.len() + live.len(), arena.slots.len());
        assert!(free.is_disjoint(&live));
        assert!(free.iter().all(|&index| arena.get(index).is_none()));
        let mut indexed_slots = super::HashSet::<_, super::FxBuildHasher>::default();
        for (&pid, bucket) in &table.mappings_by_pid {
            let mut max_end = 0;
            let mut last_start = 0;
            assert!(!bucket.is_empty());
            for indexed in bucket {
                assert!(indexed_slots.insert(indexed.index), "slot indexed twice");
                let mapping = &arena[indexed.index];
                assert_eq!(mapping.pid, pid);
                assert_eq!(mapping.start, indexed.start);
                assert!(indexed.start >= last_start);
                last_start = indexed.start;
                max_end = max_end.max(mapping.end());
                assert_eq!(indexed.max_end, max_end);
            }
        }
        assert_eq!(indexed_slots, live);
        let mut present = super::HashSet::<_, super::FxBuildHasher>::default();
        let mut executable = super::HashSet::<_, super::FxBuildHasher>::default();
        let mut global_present = false;
        let mut global_executable = false;
        for mapping in arena.iter() {
            if mapping.pid == u32::MAX {
                global_present = true;
                global_executable |= mapping.may_execute();
            } else {
                present.insert(mapping.pid);
                if mapping.may_execute() {
                    executable.insert(mapping.pid);
                }
            }
        }
        assert_eq!(table.pids_with_mappings, present);
        assert_eq!(table.executable_pids, executable);
        assert_eq!(table.has_global_mappings, global_present);
        assert_eq!(table.has_global_executable_mappings, global_executable);
    }

    #[test]
    fn arena_reuse_preserves_insertion_order_and_storage_tracks_peak_live_maps() {
        let mut table = super::MmapTable::default();
        for (pid, start, path) in [
            (7, 0x3000, "/late-address"),
            (7, 0x1000, "/early-address"),
            (8, 0x1000, "/foreign"),
            (7, 0x1000, "/patch"),
        ] {
            table.insert_mmap(mutation_record(pid, start, 0x100, 0, path));
            assert_mapping_arena_invariants(&table);
        }
        assert_eq!(
            table
                .user_mappings()
                .map(|mapping| mapping.path)
                .collect::<Vec<_>>(),
            ["/late-address", "/foreign", "/patch"]
        );
        table.clone_pid_mappings(7, 9);
        assert_mapping_arena_invariants(&table);
        assert_eq!(
            table
                .user_mappings()
                .filter(|mapping| mapping.pid == 9)
                .map(|mapping| mapping.path)
                .collect::<Vec<_>>(),
            ["/late-address", "/patch"]
        );
        let peak_slots = table.mappings.slots.len();
        assert_eq!(peak_slots, 5);
        for pid in [8, 7] {
            table.clone_pid_mappings(999, pid);
            assert_mapping_arena_invariants(&table);
            assert!(!table.has_mappings_for_pid(pid));
            assert!(!table.has_executable_mappings_for_pid(pid));
        }
        for pgoff in 0..128 {
            table.insert_mmap(mutation_record(9, 0x1000, 0x3000, pgoff, "/replacement"));
            assert_mapping_arena_invariants(&table);
            assert_eq!(table.mappings.slots.len(), peak_slots);
            assert_eq!(table.user_mappings().count(), 1);
            assert_eq!(
                table.resolve(9, 0x1010).unwrap().relative_address,
                pgoff + 0x10
            );
        }
    }

    #[test]
    fn cached_slots_revalidate_vacancy_foreign_pid_and_new_range_after_reuse() {
        let mut table = super::MmapTable::default();
        let mut cache = super::MappingResolveCache::default();
        table.insert_mmap(mutation_record(7, 0x1000, 0x100, 0x50, "/first"));
        table.resolve_frame_cached(7, 0x1010, &mut cache).unwrap();
        let old_slot = cache.pid_index.unwrap();
        let mut vacant_cache = cache;
        table.clone_pid_mappings(999, 7);
        assert_mapping_arena_invariants(&table);
        assert!(table.mappings.get(old_slot).is_none());
        assert!(
            table
                .resolve_frame_cached(7, 0x1010, &mut vacant_cache)
                .is_none()
        );
        assert!(vacant_cache.pid_index.is_none());
        table.insert_mmap(mutation_record(8, 0x1000, 0x100, 0x900, "/foreign-reuse"));
        assert_eq!(table.bucket(8)[0].index, old_slot);
        assert!(table.resolve_frame_cached(7, 0x1010, &mut cache).is_none());
        let context = table.frame_context(7, &mut vacant_cache);
        assert!(context.resolve_user(0x1010, &mut vacant_cache).is_none());
        table.clone_pid_mappings(999, 8);
        table.insert_mmap(mutation_record(7, 0x2000, 0x100, 0x500, "/new-range"));
        assert_eq!(table.bucket(7)[0].index, old_slot);
        cache.pid_index = Some(old_slot);
        assert!(table.resolve_frame_cached(7, 0x1010, &mut cache).is_none());
        let frame = table.resolve_frame_cached(7, 0x2010, &mut cache).unwrap();
        assert_eq!(
            (frame.path(), frame.relative_address),
            ("/new-range", 0x510)
        );
        assert_mapping_arena_invariants(&table);
    }

    #[test]
    fn reused_global_slot_does_not_leak_mapping_or_executable_presence() {
        let mut table = super::MmapTable::default();
        let mut cache = super::MappingResolveCache::default();
        table.insert_mmap(mutation_record(u32::MAX, 0x1000, 0x100, 0x50, "/code"));
        table.resolve_frame_cached(7, 0x1010, &mut cache).unwrap();
        let global_slot = cache.global_index.unwrap();
        table.clone_pid_mappings(999, u32::MAX);
        table.insert_mmap(mutation_record(8, 0x1000, 0x100, 0x90, "/foreign"));
        assert_eq!(table.bucket(8)[0].index, global_slot);
        assert!(!table.has_mappings_for_pid(7));
        assert!(!table.has_executable_mappings_for_pid(7));
        assert!(table.resolve_frame_cached(7, 0x1010, &mut cache).is_none());
        assert!(cache.global_index.is_none());
        table.insert_mmap(mutation_record(u32::MAX, 0x1000, 0x100, 0x70, "/perf.data"));
        assert!(table.has_mappings_for_pid(7));
        assert!(!table.has_executable_mappings_for_pid(7));
        let frame = table.resolve_frame_cached(7, 0x1010, &mut cache).unwrap();
        assert_eq!((frame.path(), frame.relative_address), ("/perf.data", 0x80));
        table.insert_mmap(mutation_record(u32::MAX, 0x1040, 0x20, 0x900, "/new-code"));
        assert_mapping_arena_invariants(&table);
        assert!(table.has_executable_mappings_for_pid(7));
        assert_eq!(table.resolve(7, 0x1030).unwrap().path, "/perf.data");
        assert_eq!(table.resolve(7, 0x1040).unwrap().path, "/new-code");
        assert_eq!(table.resolve(7, 0x1060).unwrap().relative_address, 0xd0);
    }

    fn mutation_record(
        pid: u32,
        start: u64,
        len: u64,
        pgoff: u64,
        path: &str,
    ) -> super::MmapRecord {
        super::MmapRecord {
            pid,
            tid: pid,
            start,
            len,
            pgoff,
            path: path.into(),
        }
    }

    fn mapping_mutation_locality_fixture() -> super::MmapTable {
        let mut table = super::MmapTable::default();
        for (pid, start, len, path) in [
            (7, 0x1000, 0x1000, "/parent"),
            (7, 0x4000, 0x200, "/parent-tail"),
            (8, 0x1000, 0x1000, "/old-child"),
            (8, 0x9000, 0x100, "/child-only"),
        ] {
            table.insert_mmap(mutation_record(pid, start, len, 0x100, path));
        }
        for pid in 100..132 {
            table.insert_mmap(mutation_record(
                pid,
                0x1000,
                0x1000,
                u64::from(pid),
                &format!("/foreign-{pid}"),
            ));
        }
        table.insert_mmap(mutation_record(u32::MAX, 0x8000, 0x100, 0, "/global"));
        table.mutation_row_work.get_mut().clear();
        table
    }

    #[test]
    fn nonoverlapping_insert_records_only_its_actual_pid_index_write() {
        let mut table = mapping_mutation_locality_fixture();
        table.insert_mmap(mutation_record(7, 0x6000, 0x100, 0, "/disjoint"));
        let work = table.mutation_row_work.borrow();
        assert_eq!(work.len(), 1);
        assert_eq!(
            work[&7],
            super::MappingMutationRowWork {
                index_writes: 1,
                ..Default::default()
            }
        );
        assert_eq!(table.resolve(7, 0x6010).unwrap().path, "/disjoint");
    }

    #[test]
    fn overlap_split_visits_and_reindexes_only_the_affected_pid() {
        // perf maps.c:__maps__fixup_overlap_and_insert visits one maps object,
        // clones its surviving fragments, and never rebuilds other processes.
        let mut table = mapping_mutation_locality_fixture();
        table.insert_mmap(mutation_record(7, 0x1400, 0x100, 0x900, "/patch"));
        for (address, path, offset) in [
            (0x1010, "/parent", 0x110),
            (0x1410, "/patch", 0x910),
            (0x1510, "/parent", 0x610),
            (0x4010, "/parent-tail", 0x110),
        ] {
            let mapping = table.resolve(7, address).unwrap();
            assert_eq!(
                (mapping.path.as_str(), mapping.relative_address),
                (path, offset)
            );
        }
        let work = table.mutation_row_work.borrow();
        assert!(
            work[&7].overlap_rows > 0,
            "real overlap traversal was not counted"
        );
        assert!(
            work[&7].index_writes >= 3,
            "fragment index writes were not counted"
        );
        let foreign = work.iter().filter(|(pid, _)| **pid != 7).fold(
            (0, 0, 0),
            |(overlap, rebuild, writes), (_, row)| {
                (
                    overlap + row.overlap_rows,
                    rebuild + row.rebuild_rows,
                    writes + row.index_writes,
                )
            },
        );
        assert_eq!(
            foreign,
            (0, 0, 0),
            "overlap removal touched foreign mapping rows"
        );
    }

    #[test]
    fn fork_removal_selection_and_indexing_touch_only_parent_and_child_rows() {
        // perf maps.c:maps__copy_from clones parent_maps_by_address[0..n],
        // not a global array filtered across every process in the recording.
        let mut table = mapping_mutation_locality_fixture();
        table.clone_pid_mappings(7, 8);
        assert!(table.resolve(8, 0x9000).is_none());
        for address in [0x1010, 0x4010] {
            assert_eq!(table.resolve(8, address), table.resolve(7, address));
        }
        let work = table.mutation_row_work.borrow();
        assert_eq!(work[&7].fork_select_rows, 2);
        assert_eq!(
            work[&7].fork_cloned_rows, 2,
            "actual parent clones were not counted"
        );
        assert_eq!(
            work[&8].fork_remove_rows, 2,
            "actual child removals were not counted"
        );
        assert_eq!(work[&8].index_writes, 2);
        let foreign = work
            .iter()
            .filter(|(pid, _)| **pid != 7 && **pid != 8)
            .fold(
                (0, 0, 0, 0),
                |(remove, select, rebuild, writes), (_, row)| {
                    (
                        remove + row.fork_remove_rows,
                        select + row.fork_select_rows,
                        rebuild + row.rebuild_rows,
                        writes + row.index_writes,
                    )
                },
            );
        assert_eq!(
            foreign,
            (0, 0, 0, 0),
            "fork scanned or rebuilt unrelated processes"
        );
    }

    #[derive(Debug, Eq, PartialEq)]
    struct MappingIdentitySnapshot {
        source_id: usize,
        display_id: usize,
        resolved: super::ResolvedMapping,
    }

    fn mapping_identity_snapshot(
        table: &super::MmapTable,
        pid: u32,
        address: u64,
        cache: &mut super::MappingResolveCache,
    ) -> MappingIdentitySnapshot {
        let frame = table.resolve_frame_cached(pid, address, cache).unwrap();
        MappingIdentitySnapshot {
            source_id: frame.symbol_source_id(),
            display_id: frame.display_path_id(),
            resolved: owned_frame_metadata(frame),
        }
    }

    #[test]
    fn foreign_mapping_slots_and_cache_identity_survive_other_pid_splits_and_forks() {
        let mut table = mapping_mutation_locality_fixture();
        let mut cache = super::MappingResolveCache::default();
        let before = mapping_identity_snapshot(&table, 100, 0x1010, &mut cache);
        let foreign_slot = cache.pid_index;
        table.insert_mmap(mutation_record(7, 0x1400, 0x100, 0x900, "/patch"));
        assert_eq!(
            mapping_identity_snapshot(&table, 100, 0x1010, &mut cache),
            before
        );
        assert_eq!(
            cache.pid_index, foreign_slot,
            "overlap removal relocated a foreign slot"
        );
        table.clone_pid_mappings(7, 8);
        assert_eq!(
            mapping_identity_snapshot(&table, 100, 0x1010, &mut cache),
            before
        );
        assert_eq!(
            cache.pid_index, foreign_slot,
            "fork removal relocated a foreign slot"
        );
    }

    #[test]
    fn reused_same_pid_mapping_slot_revalidates_source_display_offset_and_mode() {
        let mut table = super::MmapTable::default();
        let mut cache = super::MappingResolveCache::default();
        let mut user_cache = super::MappingResolveCache::default();
        table.insert_mmap(mutation_record(7, 0x1000, 0x1000, 0x100, "/old"));
        let old = mapping_identity_snapshot(&table, 7, 0x1010, &mut cache);
        assert!(
            table
                .resolve_user_frame_cached(7, 0x1010, &mut user_cache)
                .is_some()
        );
        for (path, pgoff, mode) in [
            (
                "/kernel",
                0x900,
                crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
            ),
            ("/new", 0x500, super::PERF_RECORD_MISC_CPUMODE_USER),
            ("/old", 0x100, super::PERF_RECORD_MISC_CPUMODE_USER),
        ] {
            table.insert_mmap_with_misc(mutation_record(7, 0x1000, 0x1000, pgoff, path), mode);
            let current = mapping_identity_snapshot(&table, 7, 0x1010, &mut cache);
            assert_eq!(current.resolved.path, path);
            assert_eq!(current.resolved.relative_address, pgoff + 0x10);
            if path == "/old" {
                assert_eq!(current, old);
            } else {
                assert_ne!(current.source_id, old.source_id);
                assert_ne!(current.display_id, old.display_id);
            }
            let context = table.frame_context(7, &mut user_cache);
            let user = context.resolve_user(0x1010, &mut user_cache);
            assert_eq!(user.is_some(), mode == super::PERF_RECORD_MISC_CPUMODE_USER);
            if let Some(frame) = user {
                assert_eq!(frame.resolved_ref(), table.resolve_ref(7, 0x1010).unwrap());
            }
        }
    }

    #[test]
    fn split_projection_identity_and_cached_offsets_survive_foreign_slot_replacement() {
        let mut table = mapping_mutation_locality_fixture();
        let mut cache = super::MappingResolveCache::default();
        let parent = mapping_identity_snapshot(&table, 7, 0x1010, &mut cache);
        table.insert_mmap(mutation_record(7, 0x1400, 0x100, 0x900, "/patch"));
        for (address, offset) in [(0x1010, 0x110), (0x1510, 0x610)] {
            let fragment = mapping_identity_snapshot(&table, 7, address, &mut cache);
            assert_eq!(fragment.source_id, parent.source_id);
            assert_eq!(fragment.display_id, parent.display_id);
            assert_eq!(fragment.resolved.relative_address, offset);
        }
        let old_foreign = mapping_identity_snapshot(&table, 100, 0x1010, &mut cache);
        table.clone_pid_mappings(7, 100);
        let inherited = mapping_identity_snapshot(&table, 100, 0x1510, &mut cache);
        assert_ne!(inherited.source_id, old_foreign.source_id);
        assert_eq!(inherited.source_id, parent.source_id);
        assert_eq!(inherited.display_id, parent.display_id);
        assert_eq!(inherited.resolved.relative_address, 0x610);
        assert_eq!(
            mapping_identity_snapshot(&table, 100, 0x1410, &mut cache),
            mapping_identity_snapshot(&table, 7, 0x1410, &mut cache)
        );
    }

    #[test]
    fn absolute_kernel_module_frames_preserve_kernel_range_but_user_paths_do_not() {
        // perf machine.c:machine__process_kernel_mmap_event recognizes absolute
        // kernel paths independently of their extension or bracket spelling.
        let start = 0xffff_ffff_c100_0000;
        for (misc, expected) in [
            (
                crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
                true,
            ),
            (super::PERF_RECORD_MISC_CPUMODE_USER, false),
        ] {
            let mut table = super::MmapTable::default();
            table.insert_mmap_with_misc(
                super::MmapRecord {
                    pid: u32::MAX,
                    tid: u32::MAX,
                    start,
                    len: 0x4000,
                    pgoff: 0,
                    path: "/lib/modules/a.ko".into(),
                },
                misc,
            );
            let frame = super::MappedFrame::new(&table.mappings[0], start + 0x10);
            assert_eq!(frame.resolved_ref().path, "/lib/modules/a.ko");
            assert_eq!(
                frame.display_path(),
                if expected { "[a]" } else { "/lib/modules/a.ko" }
            );
            assert_eq!(
                frame.display_path().as_ptr(),
                table.mappings[0].display_path().as_ptr()
            );
            assert_eq!(
                frame.path_layout().basename_start,
                if expected { 0 } else { 13 }
            );
            assert_eq!(frame.relative_address, 0x10);
            assert_eq!(
                frame.resolved_ref().kernel_module_address,
                expected.then_some(start + 0x10)
            );
            assert_eq!(
                table
                    .resolve_ref(u32::MAX, start + 0x10)
                    .unwrap()
                    .kernel_module_address,
                expected.then_some(start + 0x10)
            );
            assert_eq!(frame.is_kernel(), expected);
            assert_eq!(
                frame.kernel_range(),
                expected.then_some((start, start + 0x4000))
            );
        }
    }

    #[test]
    fn mapped_frame_unbracketed_paths_skip_numeric_kernel_classification() {
        for path in ["", "/usr/bin/demo", "/tmp/[kernel]", "demo.so", " /[vdso]"] {
            for relative_address in [
                0,
                0x1000,
                0xffff_7fff_ffff_ffff,
                0xffff_8000_0000_0000,
                0xffff_8000_0000_0001,
                0xffff_ffff_ffff_efff,
                0xffff_ffff_ffff_f000,
                0xffff_ffff_ffff_fe00,
                u64::MAX,
            ] {
                let mut table = super::MmapTable::default();
                table.insert_mmap(super::MmapRecord {
                    pid: 7,
                    tid: 7,
                    start: 0x1000,
                    len: 1,
                    pgoff: relative_address,
                    path: path.into(),
                });
                let frame = super::MappedFrame::new(&table.mappings[0], 0x1000);
                assert_eq!(frame.relative_address, relative_address);
                super::MAPPED_FRAME_KERNEL_CLASSIFICATIONS.with(|count| count.set(0));
                assert!(!frame.is_kernel(), "{path:?} at {relative_address:#x}");
                super::MAPPED_FRAME_KERNEL_CLASSIFICATIONS.with(|count| {
                    assert_eq!(
                        count.get(),
                        0,
                        "unbracketed {path:?} at {relative_address:#x} must skip numeric classification"
                    );
                });
            }
        }
    }

    #[test]
    fn mapped_frame_bracketed_paths_keep_kernel_ips_below_perf_context_max() {
        // linux/include/uapi/linux/perf_event.h defines PERF_CONTEXT_MAX as
        // -4095. The preceding address (-4096) is not a context marker.
        for path in ["[", "[vdso]", "[kernel].0", "[unknown]"] {
            for (relative_address, expected) in [
                (0, false),
                (0xffff_7fff_ffff_ffff, false),
                (0xffff_8000_0000_0000, true),
                (0xffff_8000_0000_0001, true),
                (0xffff_ffff_ffff_efff, true),
                (0xffff_ffff_ffff_f000, true),
                (0xffff_ffff_ffff_f001, false),
                (0xffff_ffff_ffff_fd80, false),
                (0xffff_ffff_ffff_fe00, false),
                (u64::MAX, false),
            ] {
                let mut table = super::MmapTable::default();
                table.insert_mmap(super::MmapRecord {
                    pid: 7,
                    tid: 7,
                    start: 0x1000,
                    len: 1,
                    pgoff: relative_address,
                    path: path.into(),
                });
                let frame = super::MappedFrame::new(&table.mappings[0], 0x1000);
                assert_eq!(frame.relative_address, relative_address);
                super::MAPPED_FRAME_KERNEL_CLASSIFICATIONS.with(|count| count.set(0));
                assert_eq!(
                    frame.is_kernel(),
                    expected,
                    "{path} at {relative_address:#x}"
                );
                super::MAPPED_FRAME_KERNEL_CLASSIFICATIONS.with(|count| {
                    assert_eq!(count.get(), 1, "bracketed paths still classify numerically");
                });
            }
        }
    }

    #[test]
    fn mapped_frame_kernel_classification_uses_relative_not_absolute_addresses() {
        for (pid, start, pgoff, relative_address, expected) in [
            (7, 0xffff_8000_0000_0000, 0x20, 0x30, false),
            (
                7,
                0x1000,
                0xffff_8000_0000_0000,
                0xffff_8000_0000_0010,
                true,
            ),
            (
                u32::MAX,
                0xffff_8000_0000_0000,
                0,
                0xffff_8000_0000_0010,
                true,
            ),
            (u32::MAX, 0x1000, 0xffff_8000_0000_0000, 0x1010, false),
        ] {
            let mut table = super::MmapTable::default();
            table.insert_mmap(super::MmapRecord {
                pid,
                tid: pid,
                start,
                len: 0x100,
                pgoff,
                path: "[kernel]".into(),
            });
            let frame = super::MappedFrame::new(&table.mappings[0], start + 0x10);
            assert_eq!(frame.relative_address, relative_address);
            assert_eq!(frame.is_kernel(), expected, "pid {pid}, start {start:#x}");
            assert_eq!(
                frame.kernel_range(),
                expected.then_some((start, start + 0x100))
            );
        }
    }

    #[test]
    fn display_path_identity_preserves_names_aliased_by_symbol_source_identity() {
        // perf symbol.c:maps__split_kallsyms names individual maps [kernel].N.
        let mut table = super::MmapTable::default();
        for (start, path) in [
            (0xffff_ffff_8100_0000, "[kernel].0"),
            (0xffff_ffff_8200_0000, "[kernel].1"),
        ] {
            table.insert_mmap(super::MmapRecord {
                pid: u32::MAX,
                tid: u32::MAX,
                start,
                len: 0x1000,
                pgoff: 0,
                path: path.into(),
            });
        }
        let mut hint = super::MappingResolveCache::default();
        let first = table
            .resolve_frame_cached(7, 0xffff_ffff_8100_0010, &mut hint)
            .unwrap();
        let second = table
            .resolve_frame_cached(7, 0xffff_ffff_8200_0010, &mut hint)
            .unwrap();
        assert_eq!(first.symbol_source_id(), second.symbol_source_id());
        assert_ne!(first.display_path_id(), second.display_path_id());
    }

    #[test]
    fn display_path_identity_survives_overlap_splits_forks_and_replacement() {
        let mut table = super::MmapTable::default();
        let insert = |table: &mut super::MmapTable, start, len, path: &str| {
            table.insert_mmap(super::MmapRecord {
                pid: 7,
                tid: 7,
                start,
                len,
                pgoff: 0,
                path: path.into(),
            });
        };
        insert(&mut table, 0x1000, 0x1000, "/bin/old");
        let mut hint = super::MappingResolveCache::default();
        let old = table
            .resolve_frame_cached(7, 0x1010, &mut hint)
            .unwrap()
            .display_path_id();
        insert(&mut table, 0x1400, 0x100, "/bin/new");
        hint = super::MappingResolveCache::default();
        for address in [0x1010, 0x1510] {
            assert_eq!(
                table
                    .resolve_frame_cached(7, address, &mut hint)
                    .unwrap()
                    .display_path_id(),
                old
            );
        }
        let new = table
            .resolve_frame_cached(7, 0x1410, &mut hint)
            .unwrap()
            .display_path_id();
        assert_ne!(new, old);
        table.clone_pid_mappings(7, 8);
        hint = super::MappingResolveCache::default();
        assert_eq!(
            table
                .resolve_frame_cached(8, 0x1410, &mut hint)
                .unwrap()
                .display_path_id(),
            new
        );
        insert(&mut table, 0x1000, 0x1000, "/bin/new");
        insert(&mut table, 0x3000, 0x1000, "/bin/old");
        hint = super::MappingResolveCache::default();
        assert_eq!(
            table
                .resolve_frame_cached(7, 0x1010, &mut hint)
                .unwrap()
                .display_path_id(),
            new
        );
        assert_eq!(
            table
                .resolve_frame_cached(7, 0x3010, &mut hint)
                .unwrap()
                .display_path_id(),
            old
        );
        assert_eq!(table.display_path_ids.len(), 2);
    }

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
            assert_eq!(layout.text_row_boundary, path.find([' ', '\r', '\n']));
            assert_eq!(
                layout.basename_needs_escaping,
                basename.contains([';', '\r', '\n'])
            );
        }
    }

    use super::{MappingResolveCache, MmapTable};
    use crate::perfdata::records::{
        MmapRecord, PERF_RECORD_MISC_CPUMODE_KERNEL, PERF_RECORD_MISC_CPUMODE_USER,
    };
    use std::cell::Cell;

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
    fn ordinary_mapping_translation_wraps_like_perf_dso_map_ip() {
        // perf util/map.h:107-110 uses unsigned u64 subtract/add, not saturation.
        let mut table = MmapTable::default();
        table.insert_mmap(mutation_record(7, 0x1000, 0x100, u64::MAX - 0xf, "/user"));
        let mut cache = MappingResolveCache::default();
        let mut user_cache = MappingResolveCache::default();
        for (ip, expected) in [(0x1000, u64::MAX - 0xf), (0x1020, 0x10), (0x10ff, 0xef)] {
            assert_eq!(table.resolve_ref(7, ip).unwrap().relative_address, expected);
            assert_eq!(table.resolve(7, ip).unwrap().relative_address, expected);
            assert_eq!(
                table
                    .resolve_frame_cached(7, ip, &mut cache)
                    .unwrap()
                    .relative_address,
                expected
            );
            assert_eq!(
                table
                    .resolve_ref_cached(7, ip, &mut cache)
                    .unwrap()
                    .relative_address,
                expected
            );
            assert_eq!(
                table
                    .resolve_user_frame_cached(7, ip, &mut user_cache)
                    .unwrap()
                    .relative_address,
                expected
            );
            assert_eq!(
                table
                    .resolve_user_pid_ref_cached(7, ip, &mut user_cache)
                    .unwrap()
                    .relative_address,
                expected
            );
        }
    }

    #[test]
    fn sample_context_cold_user_translation_wraps_like_perf_dso_map_ip() {
        let mut table = MmapTable::default();
        table.insert_mmap(mutation_record(7, 0x1000, 0x100, u64::MAX - 0xf, "/user"));
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        assert_eq!(
            context
                .resolve_user(0x1020, &mut cache)
                .unwrap()
                .relative_address,
            0x10
        );
    }

    #[test]
    fn sample_context_warm_user_translation_wraps_like_perf_dso_map_ip() {
        let mut table = MmapTable::default();
        table.insert_mmap(mutation_record(7, 0x1000, 0x100, u64::MAX - 0xf, "/user"));
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        context.resolve_user(0x1000, &mut cache).unwrap();
        let searches = table.index_search_count();
        for _ in 0..2 {
            assert_eq!(
                context
                    .resolve_user(0x1020, &mut cache)
                    .unwrap()
                    .relative_address,
                0x10
            );
        }
        assert_eq!(table.index_search_count(), searches);
    }

    #[test]
    fn sample_context_overlapping_maps_preserve_wrapped_winner_translation() {
        for (local_start, global_start, global_path, expected_path, expected) in [
            (0x1080, 0x1000, "/global", "/user", 0xf),
            (0x1000, 0x1080, "/global", "/global", 0xf),
            (0x1000, 0x1080, "[global]", "[global]", 0x1090),
        ] {
            let mut table = MmapTable::default();
            for (pid, start, path) in [
                (7, local_start, "/user"),
                (u32::MAX, global_start, global_path),
            ] {
                table.insert_mmap(mutation_record(pid, start, 0x100, u64::MAX, path));
            }
            let mut cache = MappingResolveCache::default();
            let context = table.frame_context(7, &mut cache);
            for _ in 0..2 {
                let frame = context.resolve(0x1090, &mut cache).unwrap();
                assert_eq!(
                    (frame.path(), frame.relative_address),
                    (expected_path, expected)
                );
            }
            let resolved = table.resolve_ref(7, 0x1090).unwrap();
            assert_eq!(
                (resolved.path, resolved.relative_address),
                (expected_path, expected)
            );
        }
    }

    #[test]
    fn sample_context_non_user_translation_wraps_after_user_filter_rejection() {
        let mut table = MmapTable::default();
        table.insert_mmap_with_misc(
            mutation_record(7, 0x1000, 0x100, u64::MAX, "/non-user"),
            crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
        );
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        assert!(context.resolve_user(0x1010, &mut cache).is_none());
        assert_eq!(cache.pid_index, None);
        let searches = table.index_search_count();
        let frame = context.resolve(0x1010, &mut cache).unwrap();
        assert_eq!((frame.path(), frame.relative_address), ("/non-user", 0xf));
        assert!(context.resolve_user(0x1010, &mut cache).is_none());
        assert_eq!(cache.pid_index, None);
        assert_eq!(table.index_search_count(), searches);
    }

    #[test]
    fn mapping_right_split_wraps_pgoff_like_perf_maps_fixup_overlappings() {
        // perf util/maps.c:908-911 and util/map.h:280-282 preserve unsigned offset arithmetic.
        let mut table = MmapTable::default();
        table.insert_mmap(mutation_record(7, 0x1000, 0x300, u64::MAX - 0xff, "/old"));
        table.insert_mmap(mutation_record(7, 0x1080, 0x100, 0, "/replacement"));
        let after = table
            .mappings
            .iter()
            .find(|mapping| mapping.start == 0x1180)
            .unwrap();
        assert_eq!(after.pgoff, 0x80);
        assert_eq!(table.resolve_ref(7, 0x1190).unwrap().relative_address, 0x90);
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        assert_eq!(
            context
                .resolve_user(0x1190, &mut cache)
                .unwrap()
                .relative_address,
            0x90
        );
    }

    #[test]
    fn sample_context_preserves_precedence_with_overflowing_loser_translation() {
        for (loser_pid, loser_path, winner_pid, winner_path, expected) in [
            (u32::MAX, "/global-file", 7, "/user", 0x510),
            (7, "/user", u32::MAX, "[global]", 0x1090),
        ] {
            let mut table = MmapTable::default();
            for (pid, start, pgoff, path) in [
                (loser_pid, 0x1000, u64::MAX, loser_path),
                (winner_pid, 0x1080, 0x500, winner_path),
            ] {
                table.insert_mmap(MmapRecord {
                    pid,
                    tid: pid,
                    start,
                    len: 0x100,
                    pgoff,
                    path: path.into(),
                });
            }
            assert_eq!(
                table.resolve_ref(7, 0x1090).unwrap().relative_address,
                expected
            );
            let mut cache = MappingResolveCache::default();
            let context = table.frame_context(7, &mut cache);
            for _ in 0..2 {
                assert_eq!(
                    context
                        .resolve(0x1090, &mut cache)
                        .unwrap()
                        .relative_address,
                    expected
                );
            }
        }
    }

    #[test]
    fn sample_context_bucket_returns_the_translated_borrowed_frame() {
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x100,
            pgoff: 0x500,
            path: "/user".into(),
        });
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        for ip in [0x1000, 0x1010, 0x1100] {
            let result = context.resolve_bucket::<true>(
                context.user,
                ip,
                &mut cache.pid_index,
                &context.user_hint,
                &context.user_miss,
            );
            assert_eq!(result.is_some(), ip < 0x1100);
            assert_eq!(
                std::mem::size_of_val(&result),
                2 * std::mem::size_of::<usize>()
            );
            if let Some(frame) = result {
                assert_eq!(frame.mapping.start, 0x1000);
                assert_eq!(frame.mapping.end(), 0x1100);
                assert_eq!(frame.mapping.pgoff, 0x500);
                assert!(frame.mapping.is_user_cpumode());
                assert!(!frame.mapping.is_kernel_symbol_mapping());
                assert_eq!(cache.pid_index, Some(table.bucket(7)[0].index));
                assert_eq!(frame.path(), "/user");
                assert_eq!(frame.relative_address, ip - 0x1000 + 0x500);
            } else {
                assert_eq!(cache.pid_index, None);
            }
        }
        assert_eq!(
            std::mem::size_of::<Option<super::MappedFrame<'_>>>(),
            std::mem::size_of::<super::MappedFrame<'_>>(),
            "the borrowed mapping provides the Option niche"
        );
    }

    #[test]
    fn sample_context_user_hit_loads_the_validated_hint_once() {
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x100,
            pgoff: 0x800,
            path: "/user".into(),
        });
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        context.resolve_user(0x1000, &mut cache).unwrap();
        let searches = table.index_search_count();
        super::FRAME_MAPPING_HINT_LOADS.with(|count| count.set(0));
        for offset in 0..64 {
            let frame = context.resolve_user(0x1000 + offset, &mut cache).unwrap();
            assert_eq!(frame.path(), "/user");
            assert_eq!(frame.relative_address, 0x800 + offset);
        }
        assert_eq!(table.index_search_count(), searches);
        assert_eq!(
            super::FRAME_MAPPING_HINT_LOADS.with(Cell::get),
            64,
            "one validated hint load must provide both containment and translation"
        );
    }

    #[test]
    fn sample_context_general_hits_do_not_reload_the_selected_hint() {
        let mut table = MmapTable::default();
        for (pid, start, len, pgoff, path) in [
            (7, 0x1000, 0x200, 0x800, "/user"),
            (u32::MAX, 0x1080, 0x100, 0, "[global]"),
        ] {
            table.insert_mmap(MmapRecord {
                pid,
                tid: pid,
                start,
                len,
                pgoff,
                path: path.into(),
            });
        }
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        context.resolve(0x1080, &mut cache).unwrap();
        context.resolve(0x1000, &mut cache).unwrap();
        let searches = table.index_search_count();
        super::FRAME_MAPPING_HINT_LOADS.with(|count| count.set(0));
        for offset in 0..64 {
            let global = context.resolve(0x1080 + offset, &mut cache).unwrap();
            assert_eq!(global.path(), "[global]");
            assert_eq!(global.relative_address, 0x1080 + offset);
            let user = context.resolve(0x1000 + offset, &mut cache).unwrap();
            assert_eq!(user.path(), "/user");
            assert_eq!(user.relative_address, 0x800 + offset);
            assert_eq!(cache.global_index, None);
        }
        assert_eq!(table.index_search_count(), searches);
        assert_eq!(
            super::FRAME_MAPPING_HINT_LOADS.with(Cell::get),
            256,
            "two participating buckets need two hint loads, not a third selected-hint reload"
        );
    }

    #[test]
    fn sample_context_general_hits_skip_absent_global_hint_reads() {
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x100,
            pgoff: 0x800,
            path: "/user".into(),
        });
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        context.resolve(0x1000, &mut cache).unwrap();
        let searches = table.index_search_count();
        super::FRAME_MAPPING_HINT_LOADS.with(|count| count.set(0));
        for offset in 0..64 {
            let frame = context.resolve(0x1000 + offset, &mut cache).unwrap();
            assert_eq!(frame.path(), "/user");
            assert_eq!(frame.relative_address, 0x800 + offset);
            assert_eq!(cache.global_index, None);
        }
        assert_eq!(table.index_search_count(), searches);
        assert_eq!(
            super::FRAME_MAPPING_HINT_LOADS.with(Cell::get),
            64,
            "an absent global bucket needs no hint load, and the USER result needs no reload"
        );
    }

    #[test]
    fn sample_context_hint_hits_skip_translation_and_user_reclassification() {
        let mut table = MmapTable::default();
        for (pid, start, pgoff, path, mode) in [
            (7, 0x1000, 0x500, "/user", PERF_RECORD_MISC_CPUMODE_USER),
            (
                u32::MAX,
                0x2000,
                0x900,
                "[global]",
                PERF_RECORD_MISC_CPUMODE_KERNEL,
            ),
            (7, 0x3000, 0x700, "[local]", PERF_RECORD_MISC_CPUMODE_KERNEL),
        ] {
            table.insert_mmap_with_misc(
                MmapRecord {
                    pid,
                    tid: pid,
                    start,
                    len: 0x100,
                    pgoff,
                    path: path.into(),
                },
                mode,
            );
        }
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        context.resolve_user(0x1000, &mut cache).unwrap();
        context.resolve(0x2000, &mut cache).unwrap();
        super::FRAME_MAPPING_TRANSLATION_CLASSIFICATIONS.with(|count| count.set(0));
        super::FRAME_MAPPING_USER_CLASSIFICATIONS.with(|count| count.set(0));
        for offset in 0..0x100 {
            assert_eq!(
                context
                    .resolve_user(0x1000 + offset, &mut cache)
                    .unwrap()
                    .relative_address,
                0x500 + offset
            );
            assert_eq!(
                context
                    .resolve(0x2000 + offset, &mut cache)
                    .unwrap()
                    .relative_address,
                0x2000 + offset
            );
        }
        let translations = super::FRAME_MAPPING_TRANSLATION_CLASSIFICATIONS.with(Cell::get);
        let user_checks = super::FRAME_MAPPING_USER_CLASSIFICATIONS.with(Cell::get);
        assert_eq!(
            (translations, user_checks),
            (0, 0),
            "validated hint hits must skip mapping translation and USER classification"
        );

        assert!(context.resolve_user(0x3000, &mut cache).is_none());
        super::FRAME_MAPPING_TRANSLATION_CLASSIFICATIONS.with(|count| count.set(0));
        super::FRAME_MAPPING_USER_CLASSIFICATIONS.with(|count| count.set(0));
        for offset in 0..0x100 {
            assert!(context.resolve_user(0x3000 + offset, &mut cache).is_none());
            assert_eq!(cache.pid_index, None);
            assert_eq!(
                context
                    .resolve(0x3000 + offset, &mut cache)
                    .unwrap()
                    .relative_address,
                0x700 + offset
            );
        }
        let translations = super::FRAME_MAPPING_TRANSLATION_CLASSIFICATIONS.with(Cell::get);
        let user_checks = super::FRAME_MAPPING_USER_CLASSIFICATIONS.with(Cell::get);
        assert_eq!(
            (translations, user_checks),
            (0, 0),
            "non-USER hints must retain their validated rejection and translation"
        );
    }

    #[test]
    fn sample_context_reuses_borrowed_maps_without_probing_table_indices_on_hits() {
        let mut table = MmapTable::default();
        for (pid, start, path) in [(7, 0x1000, "/user"), (u32::MAX, 0x2000, "[global]")] {
            table.insert_mmap(MmapRecord {
                pid,
                tid: pid,
                start,
                len: 0x100,
                pgoff: 0,
                path: path.into(),
            });
        }
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        assert!(context.resolve_user(0x1000, &mut cache).is_some());
        assert!(context.resolve(0x2000, &mut cache).is_some());
        let probes = table.cache_index_probes.get();
        for offset in 0..0x100 {
            let user = context.resolve_user(0x1000 + offset, &mut cache).unwrap();
            assert_eq!(user.path(), "/user");
            assert_eq!(user.relative_address, offset);
            assert_eq!(
                context.resolve(0x2000 + offset, &mut cache).unwrap().path(),
                "[global]"
            );
        }
        assert_eq!(
            table.cache_index_probes.get(),
            probes,
            "an immutable sample context must reuse borrowed maps, not revalidate global vector indices"
        );
    }

    #[test]
    fn sample_context_reuses_gap_misses_for_alternating_user_and_global_frames() {
        let mut table = MmapTable::default();
        for (pid, start, path) in [(7, 0x1000, "/user"), (u32::MAX, 0x2000, "[global]")] {
            table.insert_mmap(MmapRecord {
                pid,
                tid: pid,
                start,
                len: 0x100,
                pgoff: 0,
                path: path.into(),
            });
        }
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        assert_eq!(context.resolve(0x1010, &mut cache).unwrap().path(), "/user");
        assert_eq!(
            context.resolve(0x2010, &mut cache).unwrap().path(),
            "[global]"
        );
        let searches = table.index_search_count();
        for _ in 0..32 {
            assert_eq!(context.resolve(0x1010, &mut cache).unwrap().path(), "/user");
            assert_eq!(cache.global_index, None);
            assert_eq!(
                context.resolve(0x2010, &mut cache).unwrap().path(),
                "[global]"
            );
        }
        assert_eq!(
            table.index_search_count(),
            searches,
            "retain positive hint across misses"
        );
        assert_eq!(
            context
                .resolve(0x1020, &mut cache)
                .unwrap()
                .relative_address,
            0x20
        );
        assert_eq!(
            table.index_search_count(),
            searches,
            "different IP in the same global gap needs no search"
        );
    }

    #[test]
    fn sample_context_reuses_unmapped_intervals_for_distinct_frame_addresses() {
        let mut table = MmapTable::default();
        for (pid, start, path) in [
            (7, 0x1000, "/before"),
            (7, 0x3000, "/after"),
            (u32::MAX, 0x2000, "[global]"),
        ] {
            table.insert_mmap(MmapRecord {
                pid,
                tid: pid,
                start,
                len: 0x100,
                pgoff: 0,
                path: path.into(),
            });
        }
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        assert!(context.resolve(0x1100, &mut cache).is_none());
        let searches = table.index_search_count();
        for ip in 0x1101..0x1201 {
            assert!(context.resolve(ip, &mut cache).is_none());
            assert!(context.resolve_user(ip, &mut cache).is_none());
        }
        assert_eq!(
            table.index_search_count(),
            searches,
            "distinct addresses in the same immutable mapping gap need no new binary search"
        );
        // The global gap ends where its map starts, not where the PID gap ends.
        assert_eq!(
            context.resolve(0x2000, &mut cache).unwrap().path(),
            "[global]"
        );
        assert!(context.resolve_user(0x2000, &mut cache).is_none());
        assert_eq!(
            context.resolve(0x10ff, &mut cache).unwrap().path(),
            "/before"
        );
        assert_eq!(
            context.resolve(0x3000, &mut cache).unwrap().path(),
            "/after"
        );
    }

    #[test]
    fn ordinary_mapping_lookups_do_not_compute_unused_gap_bounds() {
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x100,
            pgoff: 0,
            path: "/mapped".into(),
        });
        let mut cache = MappingResolveCache::default();
        for ip in 0x2000..0x2100 {
            assert!(table.resolve_ref(7, ip).is_none());
            assert!(table.resolve_ref_cached(7, ip, &mut cache).is_none());
        }
        assert_eq!(
            table.gap_computations.get(),
            0,
            "ordinary lookups do not retain gap proofs and must not construct their bounds"
        );
        let context = table.frame_context(7, &mut cache);
        assert!(context.resolve(0x2000, &mut cache).is_none());
        assert_eq!(table.gap_computations.get(), 1);
        assert!(context.resolve(0x20ff, &mut cache).is_none());
        assert_eq!(table.gap_computations.get(), 1);
    }

    #[test]
    fn sample_context_cold_user_rejection_retains_the_containing_non_user_map() {
        let mut table = MmapTable::default();
        table.insert_mmap_with_misc(
            MmapRecord {
                pid: 7,
                tid: 7,
                start: 0x1000,
                len: 0x100,
                pgoff: 0,
                path: "[local-kernel]".into(),
            },
            crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
        );
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        assert!(context.resolve_user(0x1000, &mut cache).is_none());
        let searches = table.index_search_count();
        for ip in 0x1001..0x1100 {
            assert!(context.resolve_user(ip, &mut cache).is_none());
            assert_eq!(cache.pid_index, None);
        }
        assert_eq!(
            table.index_search_count(),
            searches,
            "a cold USER rejection must retain the containing map, not search again for each IP"
        );
        assert_eq!(
            context.resolve(0x1010, &mut cache).unwrap().path(),
            "[local-kernel]"
        );
        assert_eq!(table.index_search_count(), searches);
    }

    #[test]
    fn sample_context_gap_proofs_preserve_boundaries_zero_lengths_and_cpu_modes() {
        let mut table = MmapTable::default();
        for (pid, start, len, mode) in [
            (7, 0x10, 0x10, PERF_RECORD_MISC_CPUMODE_USER),
            (7, 0x30, 0x10, PERF_RECORD_MISC_CPUMODE_KERNEL),
            (7, 0x18, 0, PERF_RECORD_MISC_CPUMODE_USER),
            (7, 0, 0, PERF_RECORD_MISC_CPUMODE_USER),
            (u32::MAX, 0x25, 0x20, PERF_RECORD_MISC_CPUMODE_KERNEL),
            (u32::MAX, 0x60, 0, PERF_RECORD_MISC_CPUMODE_KERNEL),
            (7, u64::MAX - 4, 16, PERF_RECORD_MISC_CPUMODE_USER),
            (u32::MAX, u64::MAX - 8, 4, PERF_RECORD_MISC_CPUMODE_KERNEL),
        ] {
            table.insert_mmap_with_misc(
                MmapRecord {
                    pid,
                    tid: pid,
                    start,
                    len,
                    pgoff: 0,
                    path: format!("/map-{pid}-{start}"),
                },
                mode,
            );
        }
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        let addresses = (0..0x80).chain(u64::MAX - 9..=u64::MAX).collect::<Vec<_>>();
        for ip in addresses.iter().chain(addresses.iter().rev()).copied() {
            assert_eq!(
                context
                    .resolve(ip, &mut cache)
                    .map(super::MappedFrame::resolved_ref),
                table.resolve_ref(7, ip),
                "general lookup at {ip:#x}"
            );
            let expected_user = table.mappings.iter().find(|mapping| {
                mapping.pid == 7
                    && mapping.start <= ip
                    && ip < mapping.end()
                    && mapping.is_user_cpumode()
            });
            assert_eq!(
                context
                    .resolve_user(ip, &mut cache)
                    .map(super::MappedFrame::path),
                expected_user.map(|mapping| mapping.path.as_str()),
                "USER lookup at {ip:#x}"
            );
        }
    }

    #[test]
    fn sample_context_gap_proofs_are_discarded_after_map_insertions_and_fork() {
        let mut table = MmapTable::default();
        let mut cache = MappingResolveCache::default();
        for (pid, start, len, path, mode) in [
            (7, 0x1000, 0x100, "/before", PERF_RECORD_MISC_CPUMODE_USER),
            (7, 0x3000, 0x100, "/after", PERF_RECORD_MISC_CPUMODE_USER),
            (7, 0x1800, 0x80, "[kernel]", PERF_RECORD_MISC_CPUMODE_KERNEL),
            (
                7,
                0x1820,
                0x20,
                "/replacement",
                PERF_RECORD_MISC_CPUMODE_USER,
            ),
            (8, 0x1500, 0x500, "/parent", PERF_RECORD_MISC_CPUMODE_USER),
        ] {
            {
                let context = table.frame_context(7, &mut cache);
                for ip in [0x1100, 0x1810, 0x1820, 0x1880, 0x2fff] {
                    assert_eq!(
                        context
                            .resolve(ip, &mut cache)
                            .map(super::MappedFrame::resolved_ref),
                        table.resolve_ref(7, ip)
                    );
                }
            }
            table.insert_mmap_with_misc(
                MmapRecord {
                    pid,
                    tid: pid,
                    start,
                    len,
                    pgoff: 0,
                    path: path.into(),
                },
                mode,
            );
        }
        table.clone_pid_mappings(8, 7);
        let context = table.frame_context(7, &mut cache);
        for ip in 0x1500..0x1a00 {
            assert_eq!(
                context.resolve_user(ip, &mut cache).unwrap().path(),
                "/parent"
            );
        }
        assert!(context.resolve(0x1000, &mut cache).is_none());
        assert!(context.resolve(0x3000, &mut cache).is_none());
    }

    #[test]
    fn sample_context_rejects_non_user_hint_without_researching_or_losing_it() {
        let mut table = MmapTable::default();
        table.insert_mmap_with_misc(
            MmapRecord {
                pid: 7,
                tid: 7,
                start: 0x1000,
                len: 0x100,
                pgoff: 0,
                path: "[local-kernel]".into(),
            },
            crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
        );
        let mut cache = MappingResolveCache::default();
        table.resolve_ref_cached(7, 0x1000, &mut cache).unwrap();
        let context = table.frame_context(7, &mut cache);
        let searches = table.index_search_count();
        let probes = table.cache_index_probes.get();
        for offset in 0..0x100 {
            assert!(context.resolve_user(0x1000 + offset, &mut cache).is_none());
            assert_eq!(cache.pid_index, None);
            assert_eq!(
                context.resolve(0x1000 + offset, &mut cache).unwrap().path(),
                "[local-kernel]"
            );
        }
        assert_eq!(
            table.index_search_count(),
            searches,
            "containing non-USER hint proves a USER miss"
        );
        assert_eq!(table.cache_index_probes.get(), probes);
    }

    #[test]
    fn sample_context_misses_reset_after_mutations_and_do_not_cross_modes() {
        let mut table = MmapTable::default();
        let mut cache = MappingResolveCache::default();
        for (pid, start, path, mode) in [
            (
                7,
                0x1000,
                "/user",
                crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_USER,
            ),
            (
                u32::MAX,
                0x2000,
                "[global]",
                crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
            ),
            (
                u32::MAX,
                0x1000,
                "[global-overlap]",
                crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
            ),
            (
                7,
                0x1000,
                "[local-kernel]",
                crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
            ),
            (
                8,
                0x3000,
                "/parent",
                crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_USER,
            ),
        ] {
            // Each old context observes misses before the next map edit.
            {
                let context = table.frame_context(7, &mut cache);
                let mut user_oracle_cache = MappingResolveCache::default();
                for ip in [0x1010, 0x2010, 0x3010] {
                    assert_eq!(
                        context
                            .resolve(ip, &mut cache)
                            .map(super::MappedFrame::resolved_ref),
                        table.resolve_ref(7, ip)
                    );
                    assert_eq!(
                        context
                            .resolve_user(ip, &mut cache)
                            .map(super::MappedFrame::resolved_ref),
                        table.resolve_user_pid_ref_cached(7, ip, &mut user_oracle_cache)
                    );
                }
            }
            table.insert_mmap_with_misc(
                MmapRecord {
                    pid,
                    tid: pid,
                    start,
                    len: 0x100,
                    pgoff: 0,
                    path: path.into(),
                },
                mode,
            );
        }
        table.clone_pid_mappings(8, 7);
        let context = table.frame_context(7, &mut cache);
        assert_eq!(
            context.resolve_user(0x3010, &mut cache).unwrap().path(),
            "/parent"
        );
        assert!(context.resolve_user(0x1010, &mut cache).is_none());
        assert_eq!(
            context.resolve(0x1010, &mut cache).unwrap().path(),
            "[global-overlap]"
        );
        let searches = table.index_search_count();
        for _ in 0..8 {
            assert_eq!(
                context.resolve_user(0x3010, &mut cache).unwrap().path(),
                "/parent"
            );
            assert!(context.resolve_user(0x1010, &mut cache).is_none());
            assert_eq!(
                context.resolve(0x1010, &mut cache).unwrap().path(),
                "[global-overlap]"
            );
        }
        assert_eq!(table.index_search_count(), searches);
    }

    #[test]
    fn sample_context_skips_absent_global_buckets() {
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: 0x1000,
            len: 0x100,
            pgoff: 0,
            path: "/user".into(),
        });
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        assert_eq!(
            table.bucket_searches.get(),
            1,
            "no global bucket exists to fetch"
        );
        context.resolve(0x1000, &mut cache).unwrap();
        let searches = table.index_searches.get();
        for offset in 0..0x100 {
            assert!(context.resolve(0x1000 + offset, &mut cache).is_some());
        }
        assert_eq!(
            table.index_searches.get(),
            searches,
            "an empty global index must not be searched on every hit"
        );
    }

    #[test]
    fn sample_context_hints_preserve_cpu_mode_and_global_precedence() {
        let mut table = MmapTable::default();
        for (pid, start, path, mode) in [
            (
                7,
                0x1000,
                "/user",
                crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_USER,
            ),
            (
                7,
                0x2000,
                "[local-kernel]",
                crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
            ),
            (
                u32::MAX,
                0x1080,
                "[global]",
                crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
            ),
            (
                u32::MAX,
                0x2000,
                "[global-tie]",
                crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
            ),
            (
                u32::MAX,
                0x3000,
                "/global-file",
                crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_KERNEL,
            ),
            (
                7,
                0x4000,
                "[local-user]",
                crate::perfdata::records::PERF_RECORD_MISC_CPUMODE_USER,
            ),
        ] {
            table.insert_mmap_with_misc(
                MmapRecord {
                    pid,
                    tid: pid,
                    start,
                    len: 0x100,
                    pgoff: 0x500,
                    path: path.into(),
                },
                mode,
            );
        }
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        for _ in 0..3 {
            let global = context.resolve(0x1090, &mut cache).unwrap();
            assert_eq!(
                (global.path(), global.relative_address),
                ("[global]", 0x1090)
            );
            let user = context.resolve_user(0x1090, &mut cache).unwrap();
            assert_eq!((user.path(), user.relative_address), ("/user", 0x590));
            let local = context.resolve(0x2010, &mut cache).unwrap();
            assert_eq!(
                (local.path(), local.relative_address),
                ("[local-kernel]", 0x510)
            );
            assert_eq!(
                context
                    .resolve(0x3010, &mut cache)
                    .unwrap()
                    .relative_address,
                0x510
            );
            assert!(context.resolve_user(0x3010, &mut cache).is_none());
            assert_eq!(
                context
                    .resolve_user(0x4010, &mut cache)
                    .unwrap()
                    .relative_address,
                0x510
            );
            assert!(context.resolve_user(0x2010, &mut cache).is_none());
            assert_eq!(cache.pid_index, None);
            assert_eq!(
                context.resolve(0x2010, &mut cache).unwrap().path(),
                "[local-kernel]"
            );
        }
    }

    #[test]
    fn sample_context_hints_keep_exclusive_saturating_bounds_after_misses() {
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: 7,
            tid: 7,
            start: u64::MAX - 0x100,
            len: 0x200,
            pgoff: u64::MAX - 0xff,
            path: "/end".into(),
        });
        let mut cache = MappingResolveCache::default();
        let context = table.frame_context(7, &mut cache);
        for ip in [
            u64::MAX - 1,
            u64::MAX,
            0,
            u64::MAX - 0x101,
            u64::MAX - 0x100,
            u64::MAX - 1,
        ] {
            assert_eq!(
                context
                    .resolve(ip, &mut cache)
                    .map(super::MappedFrame::resolved_ref),
                table.resolve_ref(7, ip)
            );
            assert_eq!(
                context
                    .resolve_user(ip, &mut cache)
                    .map(super::MappedFrame::resolved_ref),
                table.resolve_ref(7, ip)
            );
        }
        assert_eq!(
            context
                .resolve_user(u64::MAX - 1, &mut cache)
                .unwrap()
                .relative_address,
            u64::MAX
        );
        assert!(context.resolve_user(u64::MAX, &mut cache).is_none());
    }

    fn assert_context_translation_matches_table(
        table: &MmapTable,
        cache: &mut MappingResolveCache,
        user_cache: &mut MappingResolveCache,
    ) {
        for pid in [8, 9, u32::MAX, 7] {
            let context = table.frame_context(pid, cache);
            // Repeat the endpoint to exercise freshly validated metadata and hint hits.
            for ip in [
                0xfff, 0x1000, 0x16ff, 0x1700, 0x18ff, 0x1900, 0x1fff, 0x2000, 0x1fff, 0x1fff,
            ] {
                assert_eq!(
                    context
                        .resolve(ip, cache)
                        .map(super::MappedFrame::resolved_ref),
                    table.resolve_ref(pid, ip)
                );
                assert_eq!(
                    context
                        .resolve_user(ip, cache)
                        .map(super::MappedFrame::resolved_ref),
                    table.resolve_user_pid_ref_cached(pid, ip, user_cache)
                );
            }
        }
    }

    fn assert_split_translation(table: &MmapTable, pid: u32, cache: &mut MappingResolveCache) {
        let context = table.frame_context(pid, cache);
        assert_eq!(
            context
                .resolve_user(0x16ff, cache)
                .unwrap()
                .relative_address,
            0xbff
        );
        assert!(context.resolve_user(0x1700, cache).is_none());
        assert!(context.resolve_user(0x18ff, cache).is_none());
        assert_eq!(
            context.resolve(0x1700, cache).unwrap().relative_address,
            0x2000
        );
        assert_eq!(
            context
                .resolve_user(0x1900, cache)
                .unwrap()
                .relative_address,
            0xe00
        );
    }

    #[test]
    fn sample_context_translation_metadata_revalidates_after_splits_replacement_and_fork() {
        let mut table = MmapTable::default();
        for (pid, pgoff, path) in [
            (7, 0x500, "/old"),
            (8, 0x900, "/other"),
            (9, 0x100, "/old-child"),
            (u32::MAX, 0x600, "[global]"),
        ] {
            table.insert_mmap(MmapRecord {
                pid,
                tid: pid,
                start: 0x1000,
                len: 0x1000,
                pgoff,
                path: path.into(),
            });
        }
        let mut cache = MappingResolveCache::default();
        let mut user_cache = MappingResolveCache::default();
        assert_context_translation_matches_table(&table, &mut cache, &mut user_cache);
        for (step, (pid, start, len, pgoff, path, mode)) in [
            (
                7,
                0x1700,
                0x200,
                0x2000,
                "/patch",
                PERF_RECORD_MISC_CPUMODE_KERNEL,
            ),
            (
                u32::MAX,
                0x1000,
                0x1000,
                0x700,
                "/global-file",
                PERF_RECORD_MISC_CPUMODE_KERNEL,
            ),
            (
                7,
                0x1000,
                0x1000,
                0x900,
                "[local-user]",
                PERF_RECORD_MISC_CPUMODE_USER,
            ),
            (
                u32::MAX,
                0x1000,
                0x1000,
                0x300,
                "[global-new]",
                PERF_RECORD_MISC_CPUMODE_KERNEL,
            ),
            (
                7,
                0x1000,
                0x1000,
                0xa00,
                "[local-kernel]",
                PERF_RECORD_MISC_CPUMODE_KERNEL,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            table.insert_mmap_with_misc(
                MmapRecord {
                    pid,
                    tid: pid,
                    start,
                    len,
                    pgoff,
                    path: path.into(),
                },
                mode,
            );
            assert_context_translation_matches_table(&table, &mut cache, &mut user_cache);
            if step == 0 {
                assert_split_translation(&table, 7, &mut cache);
            }
            table.clone_pid_mappings(7, 9);
            assert_context_translation_matches_table(&table, &mut cache, &mut user_cache);
            if step == 0 {
                assert_split_translation(&table, 9, &mut cache);
            }
        }
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
                let context = table.frame_context(pid, &mut cache);
                let user_context = table.frame_context(pid, &mut user_cache);
                for ip in [
                    0xfff, 0x1000, 0x16ff, 0x1700, 0x1800, 0x18ff, 0x1900, 0x1fff, 0x2000,
                ] {
                    assert_eq!(
                        table.resolve_ref_cached(pid, ip, &mut cache),
                        table.resolve_ref(pid, ip)
                    );
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
                    let actual = user_context
                        .resolve_user(ip, &mut user_cache)
                        .map(|mapping| {
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

        let overlaps = |pid, start, end| {
            table.any_indexed_mapping_in_range(
                pid,
                start,
                end,
                super::Mapping::is_user_file_mapping,
            )
        };
        assert!(!overlaps(7, 0x1100, 0x1200));
        assert!(!overlaps(7, 0x2000, 0x2800));
        assert!(overlaps(7, 0x10ff, 0x11ff));
        assert!(overlaps(7, 0x3080, 0x3180));
        // Adjacency is not overlap (half-open ranges).
        assert!(!overlaps(7, 0x1100, 0x1110));
        // Different pid's mapping must not count.
        assert!(!overlaps(8, 0x1000, 0x1100));
        assert_eq!(table.resolve(7, 0x1050).expect("/a").path, "/a");
        assert_eq!(table.resolve(7, 0x3050).expect("/b").path, "/b");
    }

    #[test]
    fn indexed_user_mapping_overlap_matches_linear_scan_oracle() {
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
                        table.any_indexed_mapping_in_range(
                            pid,
                            start,
                            end,
                            super::Mapping::is_user_file_mapping,
                        ),
                        expected,
                        "pid={pid} start={start:#x} len={len:#x}"
                    );
                }
            }
        }
    }
}
