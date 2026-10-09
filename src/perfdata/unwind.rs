use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fs::File;
#[cfg(not(unix))]
use std::io::{Read, Seek, SeekFrom};
use std::ops::{Deref, Range};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use framehop::aarch64::{CacheAarch64, UnwindRegsAarch64, UnwinderAarch64};
use framehop::x86_64::{CacheX86_64, Reg, UnwindRegsX86_64, UnwinderX86_64};
use framehop::{ExplicitModuleSectionInfo, FrameAddress, Module, Unwinder};
use gimli::{BaseAddresses, CieOrFde, DebugFrame, EhFrame, LittleEndian, UnwindSection};
use object::read::{Object, ObjectSection, ObjectSegment};
use rustc_hash::FxBuildHasher;

use super::memory::open_regular_object;

#[cfg(target_os = "linux")]
mod dwarf;

// The gap-2 skip gate queries `has_unwind_info_for_ip` once per sampled IP,
// and the same hot leaves (libc `malloc`/`memmove`/`memcmp`) recur across
// millions of samples. Memoizing collapses the otherwise-linear FDE-range scan
// (`.ace-review-findings.md` PERF-6) into an O(1) lookup. The memo is keyed by
// the EXACT ip, not `ip >> 12`: FDE pc-ranges are function-granular and two
// functions (one covered, one not) can share a 4 KiB page, so a page-granular
// memo could return a stale answer for a second IP in the page and perturb the
// skip-gate decision. Exact-ip keying keeps the answer byte-identical to the
// linear scan while still collapsing the dominant repeated-leaf query pattern.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfX86_64Regs {
    pub ip: u64,
    pub sp: u64,
    pub bp: u64,
    pub registers: [u64; 16],
}

/// The architecture a perf.data file's user register samples were recorded on,
/// from the `HEADER_ARCH` feature string.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PerfArch {
    #[default]
    X86_64,
    Aarch64,
}

impl PerfArch {
    pub(crate) const fn instruction_pointer_register(self) -> u32 {
        match self {
            Self::X86_64 => 8,
            Self::Aarch64 => 32,
        }
    }

    #[must_use]
    pub fn from_header_arch(arch: &str) -> Option<Self> {
        match arch {
            "x86_64" | "amd64" => Some(Self::X86_64),
            "aarch64" | "arm64" => Some(Self::Aarch64),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfAarch64Regs {
    pub pc: u64,
    pub sp: u64,
    pub fp: u64,
    pub lr: u64,
}

/// Architecture-neutral user register sample, decoded from a perf `REGS_USER`
/// payload according to the recording machine's arch.
///
/// The fold path threads this through every unwind site so the `x86_64` and
/// aarch64 register layouts and frame-pointer fallbacks stay byte-faithful to
/// perf/elfutils without forcing a fake bp/sp onto aarch64.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PerfUserRegs {
    X86_64(PerfX86_64Regs),
    Aarch64(PerfAarch64Regs),
}

impl PerfUserRegs {
    /// Decodes the minimal user register set for `arch` from perf's ascending
    /// register-mask encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when the value slice does not match the mask or a
    /// register required for unwinding is missing.
    pub fn from_perf_masked_values(
        arch: PerfArch,
        mask: u64,
        values: &[u64],
    ) -> Result<Self, String> {
        match arch {
            PerfArch::X86_64 => {
                PerfX86_64Regs::from_perf_masked_values(mask, values).map(Self::X86_64)
            }
            PerfArch::Aarch64 => {
                PerfAarch64Regs::from_perf_masked_values(mask, values).map(Self::Aarch64)
            }
        }
    }

    #[must_use]
    pub fn arch(self) -> PerfArch {
        match self {
            Self::X86_64(_) => PerfArch::X86_64,
            Self::Aarch64(_) => PerfArch::Aarch64,
        }
    }

    /// The sampled instruction pointer (`x86_64` IP / aarch64 PC).
    #[must_use]
    pub fn ip(self) -> u64 {
        match self {
            Self::X86_64(regs) => regs.ip,
            Self::Aarch64(regs) => regs.pc,
        }
    }

    /// The sampled stack pointer.
    #[must_use]
    pub fn sp(self) -> u64 {
        match self {
            Self::X86_64(regs) => regs.sp,
            Self::Aarch64(regs) => regs.sp,
        }
    }

    /// Whether the sample looks like an `x86_64` syscall-return state, which perf
    /// truncates after the first executable frame. aarch64 has no analogue, so
    /// this is always `false` there.
    #[must_use]
    pub fn is_syscall_return_state(self) -> bool {
        match self {
            Self::X86_64(regs) => regs.is_syscall_return_state(),
            Self::Aarch64(_) => false,
        }
    }

    /// The `x86_64` `ebl_unwind` frame-pointer precondition `bp >= sp`.
    ///
    /// elfutils' `x86_64` backend only walks the rbp chain when the frame pointer
    /// sits at or above the stack pointer. aarch64's backend has no such
    /// precondition (its accept condition is internal to the walk), so this
    /// returns `false` there and the fallback is gated differently.
    #[must_use]
    pub fn frame_pointer_at_or_above_stack_pointer(self) -> bool {
        match self {
            Self::X86_64(regs) => regs.bp >= regs.sp,
            Self::Aarch64(_) => false,
        }
    }
}

pub struct PerfStackReader<'a> {
    sp: u64,
    bytes: &'a [u8],
}

pub struct PerfUserMemoryReader<'a, F> {
    sp: u64,
    stack: &'a [u8],
    mapped_read: F,
}

pub struct FramehopUnwinder {
    arch: ArchUnwinder,
    module_count: usize,
    reported_modules: Vec<ReportedModule>,
    module_order: Vec<usize>,
    segment_lookup: RefCell<DwflSegmentLookup>,
    segment_lookup_dirty: Cell<bool>,
    framehop_dirty: bool,
    /// Exact-ip memo for `has_unwind_info_for_ip`. Interior-mutable so the
    /// predicate stays `&self`; cleared on module addition or GC, since either
    /// can change which retained module supplies CFI at an ip.
    unwind_info_memo: RefCell<HashMap<u64, bool, FxBuildHasher>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectMappingResult {
    Added(usize),
    Reused(usize),
    Rejected,
}

impl ObjectMappingResult {
    pub(crate) fn module(self) -> Option<usize> {
        match self {
            Self::Added(module) | Self::Reused(module) => Some(module),
            Self::Rejected => None,
        }
    }
}

#[derive(Default)]
struct DwflSegmentLookup {
    slots: Vec<DwflSegmentSlot>,
}

#[derive(Clone, Copy)]
struct DwflSegmentSlot {
    address: u64,
    module: Option<usize>,
}

impl DwflSegmentLookup {
    fn lookup(&self, address: u64, hint: Option<usize>) -> Option<usize> {
        if let Some(index) = hint
            && address >= self.slots[index].address
            && self
                .slots
                .get(index + 1)
                .is_none_or(|slot| address < slot.address)
        {
            return Some(index);
        }
        let (mut low, mut high) = (0, self.slots.len());
        while low < high {
            let index = usize::midpoint(low, high);
            if address < self.slots[index].address {
                high = index;
            } else {
                low = index + 1;
                if self
                    .slots
                    .get(low)
                    .is_none_or(|slot| address < slot.address)
                {
                    return Some(index);
                }
            }
        }
        None
    }

    fn insert(&mut self, mut index: usize, start: u64, end: u64) {
        let need_start = index == 0 || self.slots[index - 1].address != start;
        let need_end = self
            .slots
            .get(index + 1)
            .is_none_or(|slot| slot.address != end);
        if need_start {
            self.slots.insert(
                index,
                DwflSegmentSlot {
                    address: start,
                    module: None,
                },
            );
            index += 1;
        }
        if need_end {
            self.slots.insert(
                index,
                DwflSegmentSlot {
                    address: end,
                    module: None,
                },
            );
        }
    }

    fn reify(&mut self, modules: impl IntoIterator<Item = (usize, Range<u64>)>) {
        // elfutils 0.195 segment.c:158-245 retains lookup_addr across reports.
        // Preserve its insertion/hint behavior, including reverse-order overlaps.
        for slot in &mut self.slots {
            slot.module = None;
        }
        let mut hint = None;
        for (module, range) in modules {
            let mut index = if let Some(index) = self.lookup(range.start, hint) {
                if self.slots[index].address == range.start {
                    index
                } else {
                    self.insert(index + 1, range.start, range.end);
                    index + 1
                }
            } else {
                self.insert(0, range.start, range.end);
                0
            };
            if let Some(next) = self.slots.get(index + 1)
                && range.end < next.address
            {
                self.insert(index + 1, range.end, next.address);
            }
            loop {
                self.slots[index].module = Some(module);
                index += 1;
                if self
                    .slots
                    .get(index)
                    .is_none_or(|slot| slot.address >= range.end)
                {
                    break;
                }
            }
            hint = (index < self.slots.len()).then_some(index);
        }
    }

    fn module_for_ip(&self, ip: u64, module_end: impl Fn(usize) -> u64) -> Option<usize> {
        let index = self.lookup(ip, None)?;
        self.slots[index].module.or_else(|| {
            // segment.c:267-274 only accepts a preceding high endpoint when
            // this exact boundary has no owner of its own.
            if index > 0 && self.slots[index].address == ip {
                self.slots[index - 1]
                    .module
                    .filter(|&module| module_end(module) == ip)
            } else {
                None
            }
        })
    }
}

/// Per-architecture framehop unwinder and cache. Module registration is shared
/// (both arches register `framehop::Module<ModuleBytes>` from the same
/// `ExplicitModuleSectionInfo`); only the seeded registers and `iter_frames`
/// differ, so the regs handed to `unwind` must match the active arch.
enum ArchUnwinder {
    X86_64 {
        unwinder: Box<UnwinderX86_64<ModuleBytes>>,
        cache: CacheX86_64,
        #[cfg(target_os = "linux")]
        dwarf_cache: dwarf::Cache,
    },
    Aarch64 {
        unwinder: Box<UnwinderAarch64<ModuleBytes>>,
        cache: CacheAarch64,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserStackUnwindResult {
    pub accepted_frames: Vec<u64>,
    pub framehop_frame_count: usize,
}

pub trait UserStackUnwinder {
    fn unwind_user_stack(
        &mut self,
        regs: PerfUserRegs,
        stack: &[u8],
        max_frames: usize,
    ) -> UserStackUnwindResult;
}

#[derive(Clone)]
struct ReportedModule {
    name: String,
    source: PathBuf,
    range: Range<u64>,
    gc: bool,
    template: Module<ModuleBytes>,
    sections: ExplicitModuleSectionInfo<ModuleBytes>,
    memory_segments: Vec<ModuleMemorySegment>,
    unwind_ranges: Vec<Range<u64>>,
    #[cfg(target_os = "linux")]
    dwarf: Option<dwarf::Module>,
}

#[derive(Clone, Copy, Debug)]
struct ModuleAddresses {
    base_svma: u64,
    base_avma: u64,
}

impl ModuleAddresses {
    fn svma_to_avma(self, address: u64) -> Option<u64> {
        if let Some(offset) = address.checked_sub(self.base_svma) {
            self.base_avma.checked_add(offset)
        } else {
            self.base_avma.checked_sub(self.base_svma - address)
        }
    }

    fn svma_range_to_avma(self, range: Range<u64>) -> Option<Range<u64>> {
        Some(self.svma_to_avma(range.start)?..self.svma_to_avma(range.end)?)
    }
}

#[derive(Clone, Debug)]
struct ModuleMemorySegment {
    range: Range<u64>,
    file: Arc<File>,
    file_offset: u64,
    file_len: u64,
}

#[derive(Clone, Debug)]
struct ModuleBytes(Arc<[u8]>);

#[must_use]
pub fn unwind_x86_64_stack(regs: PerfX86_64Regs, stack: &[u8], max_frames: usize) -> Vec<u64> {
    let mut memory_reader = PerfUserMemoryReader::new(regs.sp, stack, |_| None);
    let mut read_stack = |address| memory_reader.read_u64(address).ok_or(());
    let mut cache = CacheX86_64::new();
    let unwinder = UnwinderX86_64::<Vec<u8>>::new();
    let ip = regs.ip;
    let regs = regs.to_framehop_regs();
    let mut iter = unwinder.iter_frames(ip, regs, &mut cache, &mut read_stack);
    let mut frames = Vec::new();
    while frames.len() < max_frames {
        let Ok(Some(frame)) = iter.next() else {
            break;
        };
        push_perf_unwind_address(&mut frames, frame.address());
    }
    frames
}

#[must_use]
pub fn unwind_x86_64_frame_pointer_stack_like_elfutils(
    regs: PerfX86_64Regs,
    stack: &[u8],
    max_frames: usize,
) -> Vec<u64> {
    let memory_reader = PerfStackReader::new(regs.sp, stack);
    let mut frames = Vec::new();
    if max_frames == 0 || regs.bp == 0 {
        return frames;
    }

    frames.push(regs.ip);
    let mut fp = regs.bp;
    let mut sp = regs.sp;
    while frames.len() < max_frames {
        let prev_fp = memory_reader.read_u64(fp).unwrap_or(0);
        let Some(ret) = memory_reader.read_u64(fp.saturating_add(8)) else {
            break;
        };
        let next_sp = fp.saturating_add(16);
        if sp >= next_sp {
            break;
        }
        push_perf_unwind_address(&mut frames, ret);
        fp = prev_fp;
        sp = next_sp;
        if fp == 0 {
            break;
        }
    }
    frames
}

impl Default for FramehopUnwinder {
    fn default() -> Self {
        Self::new()
    }
}

impl FramehopUnwinder {
    #[must_use]
    pub fn new() -> Self {
        Self::with_arch(PerfArch::X86_64)
    }

    #[must_use]
    pub fn with_arch(arch: PerfArch) -> Self {
        let arch = match arch {
            PerfArch::X86_64 => ArchUnwinder::X86_64 {
                unwinder: Box::new(UnwinderX86_64::new()),
                cache: CacheX86_64::new(),
                #[cfg(target_os = "linux")]
                dwarf_cache: dwarf::Cache::new(),
            },
            PerfArch::Aarch64 => ArchUnwinder::Aarch64 {
                unwinder: Box::new(UnwinderAarch64::new()),
                cache: CacheAarch64::new(),
            },
        };
        Self {
            arch,
            module_count: 0,
            reported_modules: Vec::new(),
            module_order: Vec::new(),
            segment_lookup: RefCell::new(DwflSegmentLookup::default()),
            segment_lookup_dirty: Cell::new(false),
            framehop_dirty: false,
            unwind_info_memo: RefCell::new(HashMap::with_hasher(FxBuildHasher)),
        }
    }

    /// Loads unwind sections for a mapped object file.
    ///
    /// # Errors
    ///
    /// Returns an error when the object file cannot be read or parsed.
    pub fn add_object_mapping(
        &mut self,
        path: &Path,
        start: u64,
        len: u64,
        pgoff: u64,
    ) -> Result<bool, String> {
        let name = path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy();
        self.report_object_mapping(path, &name, start, len, pgoff)
            .map(|result| matches!(result, ObjectMappingResult::Added(_)))
    }

    pub(crate) fn report_object_mapping(
        &mut self,
        path: &Path,
        name: &str,
        start: u64,
        len: u64,
        pgoff: u64,
    ) -> Result<ObjectMappingResult, String> {
        if len == 0 || start.checked_add(len).is_none() {
            return Ok(ObjectMappingResult::Rejected);
        }
        let file = open_regular_object(path)
            .map_err(|error| format!("failed to open unwind object {}: {error}", path.display()))?;
        let file_len = file.metadata().map_err(|error| error.to_string())?.len();
        let file = Arc::new(file);
        let cache = object::read::ReadCache::new(&*file);
        let object = object::File::parse(cache.range(0, file_len)).map_err(|error| {
            format!("failed to parse unwind object {}: {error}", path.display())
        })?;
        let Some(addresses) = object_mapping_addresses(&object, path, start, pgoff) else {
            return Ok(ObjectMappingResult::Rejected);
        };
        let Some(module_range) =
            object_load_range(&object).and_then(|range| addresses.svma_range_to_avma(range))
        else {
            return Ok(ObjectMappingResult::Rejected);
        };
        if self.reject_existing_elf_report(name, &module_range) {
            return Ok(ObjectMappingResult::Rejected);
        }
        let sections = explicit_module_section_info(&object, addresses.base_svma);
        let memory_segments = module_memory_segments(&file, file_len, &object, addresses);
        let unwind_ranges = object_unwind_ranges(&object, addresses);
        #[cfg(target_os = "linux")]
        let dwarf = (object.format() == object::BinaryFormat::Elf)
            .then(|| dwarf::Module::new(&sections, addresses, object_cfi_base_addresses(&object)));
        let module = Module::<ModuleBytes>::new(
            path.to_string_lossy().into_owned(),
            module_range.clone(),
            addresses.base_avma,
            sections.clone(),
        );
        let module_id = self.reported_modules.len();
        self.reported_modules.push(ReportedModule {
            name: name.to_owned(),
            source: path.to_path_buf(),
            range: module_range,
            gc: false,
            template: module,
            sections,
            memory_segments,
            unwind_ranges,
            #[cfg(target_os = "linux")]
            dwarf,
        });
        let position = self
            .module_order
            .iter()
            .rposition(|&id| !self.reported_modules[id].gc)
            .map_or(0, |position| position + 1);
        self.module_order.insert(position, module_id);
        self.module_count += 1;
        self.invalidate_module_lookups();
        Ok(ObjectMappingResult::Added(module_id))
    }

    fn reject_existing_elf_report(&mut self, name: &str, range: &Range<u64>) -> bool {
        let Some(position) = self.module_order.iter().position(|&id| {
            let module = &self.reported_modules[id];
            module.name == name && module.range == *range
        }) else {
            return false;
        };
        let insertion = self.module_order[..position]
            .iter()
            .rposition(|&id| !self.reported_modules[id].gc)
            .map_or(0, |index| index + 1);
        let id = self.module_order.remove(position);
        self.module_order.insert(insertion, id);
        // dwfl_report_module reuses (name, low, high), but public report_elf(-1)
        // opens a fresh FD. The old main FD is retained, so even the same path
        // fails at dwfl_report_elf.c:259-265 and marks this identity GC.
        self.reported_modules[id].gc = true;
        self.invalidate_module_lookups();
        true
    }

    fn invalidate_module_lookups(&mut self) {
        self.segment_lookup_dirty.set(true);
        self.framehop_dirty = true;
        self.unwind_info_memo.borrow_mut().clear();
    }

    fn refresh_segment_lookup(&self) {
        if self.segment_lookup_dirty.replace(false) {
            self.segment_lookup.borrow_mut().reify(
                self.module_order
                    .iter()
                    .copied()
                    .filter(|&id| !self.reported_modules[id].gc)
                    .map(|id| (id, self.reported_modules[id].range.clone())),
            );
        }
    }

    fn refresh_framehop_modules(&mut self) {
        if !self.framehop_dirty {
            return;
        }
        self.refresh_segment_lookup();
        let mut boundaries = self
            .segment_lookup
            .borrow()
            .slots
            .iter()
            .map(|slot| slot.address)
            .collect::<Vec<_>>();
        for module in self.reported_modules.iter().filter(|module| !module.gc) {
            if let Some(end) = module.range.end.checked_add(1) {
                boundaries.push(end);
            }
        }
        boundaries.sort_unstable();
        boundaries.dedup();
        let mut spans: Vec<(usize, Range<u64>)> = Vec::new();
        for pair in boundaries.windows(2) {
            let Some(id) = self.reported_module_for_ip(pair[0]) else {
                continue;
            };
            if let Some((previous, range)) = spans.last_mut()
                && *previous == id
                && range.end == pair[0]
            {
                range.end = pair[1];
            } else {
                spans.push((id, pair[0]..pair[1]));
            }
        }
        self.arch.clear_modules();
        for (id, range) in spans {
            let module = &self.reported_modules[id];
            let registration = if module.range == range {
                module.template.clone()
            } else {
                Module::new(
                    module.source.to_string_lossy().into_owned(),
                    range,
                    module.template.base_avma(),
                    module.sections.clone(),
                )
            };
            self.arch.add_module(registration);
        }
        self.framehop_dirty = false;
    }

    #[must_use]
    pub fn module_count(&self) -> usize {
        self.module_count
    }

    #[must_use]
    pub fn has_reported_module_for_ip(&self, ip: u64) -> bool {
        self.reported_module_for_ip(ip).is_some()
    }

    pub(crate) fn reported_module_for_ip(&self, ip: u64) -> Option<usize> {
        self.refresh_segment_lookup();
        self.segment_lookup
            .borrow()
            .module_for_ip(ip, |id| self.reported_modules[id].range.end)
    }

    pub(crate) fn reported_module_start(&self, module: usize) -> u64 {
        self.reported_modules[module].range.start
    }

    #[must_use]
    pub fn has_rejected_mapping_for_ip(&self, ip: u64) -> bool {
        self.reported_modules
            .iter()
            .any(|module| module.gc && module.range.contains(&ip))
    }

    #[must_use]
    pub fn has_unwind_info_for_ip(&self, ip: u64) -> bool {
        if let Some(&cached) = self.unwind_info_memo.borrow().get(&ip) {
            return cached;
        }
        let covered = self.reported_module_for_ip(ip).is_some_and(|module| {
            self.reported_modules[module]
                .unwind_ranges
                .iter()
                .any(|range| range.contains(&ip))
        });
        self.unwind_info_memo.borrow_mut().insert(ip, covered);
        covered
    }

    #[must_use]
    pub fn read_process_u64(&self, address: u64) -> Option<u64> {
        read_reported_module_u64(&self.reported_modules, address)
    }

    #[must_use]
    pub fn unwind_stack(
        &mut self,
        regs: PerfUserRegs,
        stack: &[u8],
        max_frames: usize,
    ) -> Vec<u64> {
        self.unwind_stack_with_diagnostics(regs, stack, max_frames)
            .accepted_frames
    }

    #[must_use]
    pub fn unwind_stack_with_diagnostics(
        &mut self,
        regs: PerfUserRegs,
        stack: &[u8],
        max_frames: usize,
    ) -> UserStackUnwindResult {
        self.refresh_framehop_modules();
        let reported_modules = &self.reported_modules;
        let lookup = self.segment_lookup.borrow();
        self.arch.unwind_stack(
            regs,
            stack,
            max_frames,
            reported_modules,
            &lookup,
            |address| read_reported_module_u64(reported_modules, address),
        )
    }

    pub(crate) fn unwind_stack_with_diagnostics_and_memory(
        &mut self,
        regs: PerfUserRegs,
        stack: &[u8],
        max_frames: usize,
        memory: impl FnMut(u64) -> Option<u64>,
    ) -> UserStackUnwindResult {
        self.refresh_framehop_modules();
        let modules = &self.reported_modules;
        let lookup = self.segment_lookup.borrow();
        self.arch
            .unwind_stack(regs, stack, max_frames, modules, &lookup, memory)
    }
}

fn module_has_unwind_info(modules: &[ReportedModule], lookup: &DwflSegmentLookup, ip: u64) -> bool {
    lookup
        .module_for_ip(ip, |id| modules[id].range.end)
        .is_some_and(|id| {
            modules[id]
                .unwind_ranges
                .iter()
                .any(|range| range.contains(&ip))
        })
}

impl ArchUnwinder {
    fn unwind_stack(
        &mut self,
        regs: PerfUserRegs,
        stack: &[u8],
        max_frames: usize,
        modules: &[ReportedModule],
        lookup: &DwflSegmentLookup,
        memory: impl FnMut(u64) -> Option<u64>,
    ) -> UserStackUnwindResult {
        let mut memory_reader = PerfUserMemoryReader::new(regs.sp(), stack, memory);
        let mut read_stack = |address| memory_reader.read_u64(address).ok_or(());
        let frames = self.iter_addresses(
            regs.ip(),
            regs,
            &mut read_stack,
            max_frames,
            modules,
            lookup,
        );
        let framehop_frame_count = frames.len();
        UserStackUnwindResult {
            accepted_frames: frames,
            framehop_frame_count,
        }
    }

    fn clear_modules(&mut self) {
        match self {
            Self::X86_64 {
                unwinder, cache, ..
            } => {
                **unwinder = UnwinderX86_64::new();
                *cache = CacheX86_64::new();
            }
            Self::Aarch64 { unwinder, cache } => {
                **unwinder = UnwinderAarch64::new();
                *cache = CacheAarch64::new();
            }
        }
    }
    fn add_module(&mut self, module: Module<ModuleBytes>) {
        match self {
            Self::X86_64 { unwinder, .. } => unwinder.add_module(module),
            Self::Aarch64 { unwinder, .. } => unwinder.add_module(module),
        }
    }

    fn iter_addresses(
        &mut self,
        ip: u64,
        regs: PerfUserRegs,
        read_stack: &mut impl FnMut(u64) -> Result<u64, ()>,
        max_frames: usize,
        modules: &[ReportedModule],
        lookup: &DwflSegmentLookup,
    ) -> Vec<u64> {
        #[cfg(target_os = "linux")]
        if matches!(self, Self::X86_64 { .. })
            && let PerfUserRegs::X86_64(regs) = regs
        {
            return self.iter_dwarf_addresses(regs, modules, lookup, read_stack, max_frames);
        }
        let mut frames = Vec::new();
        // The seeded register file must match the active arch; a mismatch means
        // the file header arch and the regs decode disagreed, which cannot
        // happen because both flow from the same PerfArch.
        match (self, regs) {
            (
                Self::X86_64 {
                    unwinder, cache, ..
                },
                PerfUserRegs::X86_64(regs),
            ) => {
                let mut regs = regs.to_framehop_regs();
                let mut address = FrameAddress::from_instruction_pointer(ip);
                while frames.len() < max_frames {
                    push_perf_unwind_address(&mut frames, address.address());
                    // libdwfl/frame_unwind.c:738-788 falls back to ebl_unwind
                    // when no FDE covers this PC. Framehop's uncovered-FDE rule
                    // instead pops SP on the initial frame (x86_64/dwarf.rs:87).
                    let next =
                        if module_has_unwind_info(modules, lookup, address.address_for_lookup()) {
                            unwinder
                                .unwind_frame(address, &mut regs, cache, read_stack)
                                .ok()
                                .flatten()
                        } else {
                            unwind_x86_64_frame_pointer(&mut regs, read_stack)
                        };
                    let Some(next) = next.and_then(FrameAddress::from_return_address) else {
                        break;
                    };
                    address = next;
                }
            }
            (Self::Aarch64 { unwinder, cache }, PerfUserRegs::Aarch64(regs)) => {
                let mut iter = unwinder.iter_frames(ip, regs.to_framehop_regs(), cache, read_stack);
                while frames.len() < max_frames {
                    let Ok(Some(frame)) = iter.next() else {
                        break;
                    };
                    push_perf_unwind_address(&mut frames, frame.address());
                }
            }
            _ => {}
        }
        frames
    }

    #[cfg(target_os = "linux")]
    fn iter_dwarf_addresses(
        &mut self,
        regs: PerfX86_64Regs,
        modules: &[ReportedModule],
        lookup: &DwflSegmentLookup,
        read: &mut impl FnMut(u64) -> Result<u64, ()>,
        max_frames: usize,
    ) -> Vec<u64> {
        let Self::X86_64 {
            unwinder,
            cache,
            dwarf_cache,
        } = self
        else {
            unreachable!()
        };
        let mut regs = dwarf::Registers::new(regs);
        let mut signal = false;
        let mut frames = Vec::new();
        while frames.len() < max_frames {
            let Some(pc) = regs.pc() else {
                break;
            };
            let initial = frames.is_empty();
            let address = if initial || signal {
                pc
            } else {
                pc.wrapping_sub(1)
            };
            let module = lookup
                .module_for_ip(address, |id| modules[id].range.end)
                .map(|id| &modules[id]);
            let step = if let Some(module) = module {
                if let Some(dwarf) = &module.dwarf {
                    dwarf.step(address, regs, dwarf_cache, read)
                } else {
                    // Keep Framehop for non-ELF platform unwind formats.
                    let mut platform_regs = regs.framehop_regs();
                    let address = if initial || signal {
                        Some(FrameAddress::from_instruction_pointer(pc))
                    } else {
                        FrameAddress::from_return_address(pc)
                    };
                    match address.and_then(|address| {
                        unwinder
                            .unwind_frame(address, &mut platform_regs, cache, read)
                            .ok()
                            .flatten()
                    }) {
                        Some(_) => dwarf::Step::Caller(
                            dwarf::Registers::from_framehop(platform_regs),
                            false,
                        ),
                        None => dwarf::Step::Stop,
                    }
                }
            } else {
                dwarf::Step::NoRow
            };
            let step = if matches!(step, dwarf::Step::NoRow) {
                regs.frame_pointer_step(read)
            } else {
                step
            };
            // dwfl_frame_pc.c:43-59: either adjacent frame being a signal
            // frame makes this PC an activation address (no return adjustment).
            let next_signal = matches!(step, dwarf::Step::Caller(_, true));
            frames.push(if initial || signal || next_signal {
                pc
            } else {
                pc.wrapping_sub(1)
            });
            match step {
                dwarf::Step::Caller(caller, is_signal) => {
                    regs = caller;
                    signal = is_signal;
                }
                dwarf::Step::NoRow | dwarf::Step::Stop => break,
            }
        }
        frames
    }
}

fn unwind_x86_64_frame_pointer(
    regs: &mut UnwindRegsX86_64,
    read: &mut impl FnMut(u64) -> Result<u64, ()>,
) -> Option<u64> {
    // elfutils 0.195 backends/x86_64_unwind.c:48-91: missing previous FP
    // is nonfatal; only the return-slot read and forward SP movement are required.
    let fp = regs.bp();
    if fp == 0 {
        return None;
    }
    let previous_fp = read(fp).unwrap_or(0);
    let return_address = read(fp.wrapping_add(8)).ok()?;
    let next_sp = fp.wrapping_add(16);
    if regs.sp() >= next_sp {
        return None;
    }
    regs.set_bp(previous_fp);
    regs.set_sp(next_sp);
    regs.set_ip(return_address);
    Some(return_address)
}

impl UserStackUnwinder for FramehopUnwinder {
    fn unwind_user_stack(
        &mut self,
        regs: PerfUserRegs,
        stack: &[u8],
        max_frames: usize,
    ) -> UserStackUnwindResult {
        self.unwind_stack_with_diagnostics(regs, stack, max_frames)
    }
}

impl Deref for ModuleBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn explicit_module_section_info<'a>(
    object: &object::File<'a, impl object::read::ReadRef<'a>>,
    base_svma: u64,
) -> ExplicitModuleSectionInfo<ModuleBytes> {
    ExplicitModuleSectionInfo {
        base_svma,
        text_svma: first_section_svma_range(object, &[b"__text", b".text"]),
        // Only Mach-O compact unwinding needs instruction bytes. ELF DWARF
        // needs the text address as a decoding base, not the full code section.
        text: if object.format() == object::BinaryFormat::MachO {
            first_section_data(object, &[b"__text", b".text"])
        } else {
            None
        },
        stubs_svma: first_section_svma_range(object, &[b"__stubs"]),
        stub_helper_svma: first_section_svma_range(object, &[b"__stub_helper"]),
        got_svma: first_section_svma_range(object, &[b"__got", b".got"]),
        unwind_info: first_section_data(object, &[b"__unwind_info"]),
        eh_frame_svma: first_section_svma_range(object, &[b"__eh_frame", b".eh_frame"]),
        eh_frame: first_section_data(object, &[b"__eh_frame", b".eh_frame"]),
        eh_frame_hdr_svma: first_section_svma_range(object, &[b"__eh_frame_hdr", b".eh_frame_hdr"]),
        eh_frame_hdr: first_section_data(object, &[b"__eh_frame_hdr", b".eh_frame_hdr"]),
        debug_frame: first_section_data(object, &[b".debug_frame"]),
        text_segment_svma: segment_svma_range(object, b"__TEXT"),
        text_segment: segment_data(object, b"__TEXT"),
    }
}

fn object_base_svma<'a>(object: &object::File<'a, impl object::read::ReadRef<'a>>) -> u64 {
    if object.format() == object::BinaryFormat::Elf {
        // object 0.39's ELF segment iterator yields PT_LOADs in header order.
        // Match libdwfl's p_vaddr & -p_align anchor, including p_align == 0.
        return object.segments().next().map_or(0, |segment| {
            segment.address() & segment.align().wrapping_neg()
        });
    }
    object
        .segments()
        .find(|segment| segment.name() == Ok(Some("__TEXT")))
        .map_or_else(
            || object.relative_address_base(),
            |segment| segment.address(),
        )
}

fn object_load_range<'a>(
    object: &object::File<'a, impl object::read::ReadRef<'a>>,
) -> Option<Range<u64>> {
    let mut range: Option<Range<u64>> = None;
    for segment in object.segments().filter(|segment| segment.size() != 0) {
        let start = segment.address();
        let end = start.checked_add(segment.size())?;
        range = Some(match range {
            Some(range) => range.start.min(start)..range.end.max(end),
            None => start..end,
        });
    }
    let mut range = range?;
    if object.format() == object::BinaryFormat::Elf {
        range.start = object_base_svma(object);
    }
    Some(range)
}

fn object_unwind_ranges<'a>(
    object: &impl Object<'a>,
    addresses: ModuleAddresses,
) -> Vec<Range<u64>> {
    let bases = object_cfi_base_addresses(object);
    let mut ranges = Vec::new();
    append_eh_frame_unwind_ranges(object, addresses, &bases, &mut ranges);
    append_debug_frame_unwind_ranges(object, addresses, &bases, &mut ranges);
    normalize_ranges(&mut ranges);
    ranges
}

fn append_eh_frame_unwind_ranges<'a>(
    object: &impl Object<'a>,
    addresses: ModuleAddresses,
    bases: &BaseAddresses,
    ranges: &mut Vec<Range<u64>>,
) {
    let Some(section) = object.section_by_name_bytes(b".eh_frame") else {
        return;
    };
    let Ok(data) = section.data() else {
        return;
    };
    let eh_frame = EhFrame::new(data, LittleEndian);
    let mut entries = eh_frame.entries(bases);
    while let Ok(Some(entry)) = entries.next() {
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) = partial.parse(EhFrame::cie_from_offset) else {
            continue;
        };
        push_unwind_range(ranges, addresses, fde.initial_address(), fde.end_address());
    }
}

fn append_debug_frame_unwind_ranges<'a>(
    object: &impl Object<'a>,
    addresses: ModuleAddresses,
    bases: &BaseAddresses,
    ranges: &mut Vec<Range<u64>>,
) {
    let Some(section) = object.section_by_name_bytes(b".debug_frame") else {
        return;
    };
    let Ok(data) = section.data() else {
        return;
    };
    let debug_frame = DebugFrame::new(data, LittleEndian);
    let mut entries = debug_frame.entries(bases);
    while let Ok(Some(entry)) = entries.next() {
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) = partial.parse(DebugFrame::cie_from_offset) else {
            continue;
        };
        push_unwind_range(ranges, addresses, fde.initial_address(), fde.end_address());
    }
}

fn object_cfi_base_addresses<'a>(object: &impl Object<'a>) -> BaseAddresses {
    let mut bases = BaseAddresses::default();
    if let Some(address) = section_address(object, b".eh_frame_hdr") {
        bases = bases.set_eh_frame_hdr(address);
    }
    if let Some(address) = section_address(object, b".eh_frame") {
        bases = bases.set_eh_frame(address);
    }
    if let Some(address) = first_section_address(object, &[b"__text", b".text"]) {
        bases = bases.set_text(address);
    }
    if let Some(address) = first_section_address(object, &[b"__got", b".got"]) {
        bases = bases.set_got(address);
    }
    bases
}

fn section_address<'a>(object: &impl Object<'a>, name: &[u8]) -> Option<u64> {
    object
        .section_by_name_bytes(name)
        .map(|section| section.address())
}

fn first_section_address<'a>(object: &impl Object<'a>, names: &[&[u8]]) -> Option<u64> {
    names.iter().find_map(|name| section_address(object, name))
}

fn push_unwind_range(
    ranges: &mut Vec<Range<u64>>,
    addresses: ModuleAddresses,
    start: u64,
    end: u64,
) {
    let Some(range) = addresses.svma_range_to_avma(start..end) else {
        return;
    };
    if range.start < range.end {
        ranges.push(range);
    }
}

#[cfg(test)]
thread_local! {
    static CFI_RANGE_ROWS_MOVED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn normalize_ranges(ranges: &mut Vec<Range<u64>>) {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    if ranges.is_empty() {
        return;
    }

    let mut write = 0;
    for read in 1..ranges.len() {
        if ranges[write].end >= ranges[read].start {
            ranges[write].end = ranges[write].end.max(ranges[read].end);
        } else {
            write += 1;
            if write != read {
                #[cfg(test)]
                CFI_RANGE_ROWS_MOVED.with(|rows| rows.set(rows.get() + 1));
                ranges[write] = ranges[read].clone();
            }
        }
    }
    ranges.truncate(write + 1);
}

fn module_memory_segments<'a>(
    file: &Arc<File>,
    file_len: u64,
    object: &impl Object<'a>,
    addresses: ModuleAddresses,
) -> Vec<ModuleMemorySegment> {
    object
        .segments()
        .filter_map(|segment| {
            let (file_offset, len) = segment.file_range();
            if file_offset.checked_add(len)? > file_len {
                return None;
            }
            let start = addresses.svma_to_avma(segment.address())?;
            Some(ModuleMemorySegment {
                range: start..start.checked_add(len)?,
                file: Arc::clone(file),
                file_offset,
                file_len,
            })
        })
        .collect()
}

fn object_mapping_addresses<'a>(
    object: &object::File<'a, impl object::read::ReadRef<'a>>,
    path: &Path,
    start: u64,
    pgoff: u64,
) -> Option<ModuleAddresses> {
    // perf reports start-pgoff (start for JIT). elfutils 0.195
    // dwfl_report_elf.c:170-201 ignores that base for ET_EXEC/ET_CORE.
    let linked_base = object_base_svma(object);
    let fixed_elf = object.format() == object::BinaryFormat::Elf
        && matches!(
            object.kind(),
            object::ObjectKind::Executable | object::ObjectKind::Core
        );
    let base = if fixed_elf {
        linked_base
    } else if path
        .to_str()
        .is_some_and(|path| path.starts_with("/tmp/jitted-"))
    {
        start
    } else {
        start.checked_sub(pgoff)?
    };
    let runtime_base = if object.format() == object::BinaryFormat::Elf {
        base
    } else {
        base.checked_add(linked_base)?
    };
    Some(ModuleAddresses {
        base_svma: linked_base,
        base_avma: runtime_base,
    })
}

fn read_reported_module_u64(modules: &[ReportedModule], address: u64) -> Option<u64> {
    modules
        .iter()
        .flat_map(|module| module.memory_segments.iter())
        .find_map(|segment| {
            let offset = address.checked_sub(segment.range.start)?;
            if address.checked_add(8)? > segment.range.end {
                return None;
            }
            let offset = segment.file_offset.checked_add(offset)?;
            if offset.checked_add(8)? > segment.file_len {
                return None;
            }
            let mut bytes = [0; 8];
            read_file_word(&segment.file, offset, &mut bytes).ok()?;
            Some(u64::from_le_bytes(bytes))
        })
}

fn first_section_svma_range<'a>(object: &impl Object<'a>, names: &[&[u8]]) -> Option<Range<u64>> {
    names.iter().find_map(|name| {
        let section = object.section_by_name_bytes(name)?;
        Some(section.address()..section.address().checked_add(section.size())?)
    })
}

fn first_section_data<'a>(object: &impl Object<'a>, names: &[&[u8]]) -> Option<ModuleBytes> {
    names.iter().find_map(|name| {
        let section = object.section_by_name_bytes(name)?;
        section.data().ok().map(|bytes| ModuleBytes(bytes.into()))
    })
}

fn segment_svma_range<'a>(object: &impl Object<'a>, name: &[u8]) -> Option<Range<u64>> {
    let segment = object
        .segments()
        .find(|segment| segment.name_bytes() == Ok(Some(name)))?;
    Some(segment.address()..segment.address().checked_add(segment.size())?)
}

fn segment_data<'a>(object: &impl Object<'a>, name: &[u8]) -> Option<ModuleBytes> {
    let segment = object
        .segments()
        .find(|segment| segment.name_bytes() == Ok(Some(name)))?;
    segment.data().ok().map(|bytes| ModuleBytes(bytes.into()))
}

fn read_file_word(file: &File, offset: u64, bytes: &mut [u8; 8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(bytes, offset)
    }
    #[cfg(not(unix))]
    {
        let mut file = file;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(bytes)
    }
}

fn push_perf_unwind_address(frames: &mut Vec<u64>, address: u64) {
    let address = if frames.is_empty() {
        address
    } else {
        address.saturating_sub(1)
    };
    frames.push(address);
}

#[cfg(test)]
fn truncate_at_first_uncovered_unwind_frame(
    _frames: &mut Vec<u64>,
    _has_unwind_info: impl FnMut(u64) -> bool,
) {
}

impl PerfX86_64Regs {
    #[must_use]
    pub fn is_syscall_return_state(self) -> bool {
        self.registers[Reg::RCX as usize] == self.ip && self.registers[Reg::R11 as usize] != 0
    }

    /// Builds the minimal `x86_64` register set needed for stack unwinding from
    /// perf's ascending register-mask encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when the value slice does not match the number of set
    /// bits in `mask`.
    pub fn from_perf_masked_values(mask: u64, values: &[u64]) -> Result<Self, String> {
        if mask.count_ones() as usize != values.len() {
            return Err("perf register mask and value count differ".to_string());
        }

        let mut ip = None;
        let mut sp = None;
        let mut bp = None;
        let mut registers = [0_u64; 16];
        let mut values = values.iter().copied();
        for register in 0..64 {
            if mask & (1 << register) == 0 {
                continue;
            }
            let value = values
                .next()
                .ok_or_else(|| "perf register value is missing".to_string())?;
            match register {
                0 => registers[Reg::RAX as usize] = value,
                1 => registers[Reg::RBX as usize] = value,
                2 => registers[Reg::RCX as usize] = value,
                3 => registers[Reg::RDX as usize] = value,
                4 => registers[Reg::RSI as usize] = value,
                5 => registers[Reg::RDI as usize] = value,
                6 => {
                    registers[Reg::RBP as usize] = value;
                    bp = Some(value);
                }
                7 => {
                    registers[Reg::RSP as usize] = value;
                    sp = Some(value);
                }
                register if register == PerfArch::X86_64.instruction_pointer_register() => {
                    ip = Some(value);
                }
                16 => registers[Reg::R8 as usize] = value,
                17 => registers[Reg::R9 as usize] = value,
                18 => registers[Reg::R10 as usize] = value,
                19 => registers[Reg::R11 as usize] = value,
                20 => registers[Reg::R12 as usize] = value,
                21 => registers[Reg::R13 as usize] = value,
                22 => registers[Reg::R14 as usize] = value,
                23 => registers[Reg::R15 as usize] = value,
                _ => {}
            }
        }

        Ok(Self {
            ip: ip.ok_or_else(|| "perf sample is missing x86_64 IP register".to_string())?,
            sp: sp.ok_or_else(|| "perf sample is missing x86_64 SP register".to_string())?,
            // perf unwind-libdw.c:252-302 zero-fills omitted BP through RIP.
            bp: bp.unwrap_or(0),
            registers,
        })
    }

    #[must_use]
    pub fn to_framehop_regs(self) -> UnwindRegsX86_64 {
        let mut regs = UnwindRegsX86_64::new(self.ip, self.sp, self.bp);
        regs.set(Reg::RAX, self.registers[Reg::RAX as usize]);
        regs.set(Reg::RDX, self.registers[Reg::RDX as usize]);
        regs.set(Reg::RCX, self.registers[Reg::RCX as usize]);
        regs.set(Reg::RBX, self.registers[Reg::RBX as usize]);
        regs.set(Reg::RSI, self.registers[Reg::RSI as usize]);
        regs.set(Reg::RDI, self.registers[Reg::RDI as usize]);
        regs.set(Reg::RBP, self.registers[Reg::RBP as usize]);
        regs.set(Reg::RSP, self.registers[Reg::RSP as usize]);
        regs.set(Reg::R8, self.registers[Reg::R8 as usize]);
        regs.set(Reg::R9, self.registers[Reg::R9 as usize]);
        regs.set(Reg::R10, self.registers[Reg::R10 as usize]);
        regs.set(Reg::R11, self.registers[Reg::R11 as usize]);
        regs.set(Reg::R12, self.registers[Reg::R12 as usize]);
        regs.set(Reg::R13, self.registers[Reg::R13 as usize]);
        regs.set(Reg::R14, self.registers[Reg::R14 as usize]);
        regs.set(Reg::R15, self.registers[Reg::R15 as usize]);
        regs
    }
}

impl PerfAarch64Regs {
    /// Builds the minimal aarch64 register set needed for stack unwinding from
    /// perf's ascending register-mask encoding (`PERF_REG_ARM64_*`: x29/fp=29,
    /// lr=30, sp=31, pc=32).
    ///
    /// # Errors
    ///
    /// Returns an error when the value slice does not match the number of set
    /// bits in `mask` or a required register is missing.
    pub fn from_perf_masked_values(mask: u64, values: &[u64]) -> Result<Self, String> {
        const FP: u32 = 29;
        const LR: u32 = 30;
        const SP: u32 = 31;

        if mask.count_ones() as usize != values.len() {
            return Err("perf register mask and value count differ".to_string());
        }

        let masked = |register: u32| -> Option<u64> {
            if mask & (1_u64 << register) == 0 {
                return None;
            }
            let index = (mask & ((1_u64 << register) - 1)).count_ones() as usize;
            values.get(index).copied()
        };

        Ok(Self {
            pc: masked(PerfArch::Aarch64.instruction_pointer_register())
                .ok_or_else(|| "perf sample is missing aarch64 PC register".to_string())?,
            sp: masked(SP)
                .ok_or_else(|| "perf sample is missing aarch64 SP register".to_string())?,
            fp: masked(FP)
                .ok_or_else(|| "perf sample is missing aarch64 FP register".to_string())?,
            lr: masked(LR)
                .ok_or_else(|| "perf sample is missing aarch64 LR register".to_string())?,
        })
    }

    #[must_use]
    pub fn to_framehop_regs(self) -> UnwindRegsAarch64 {
        UnwindRegsAarch64::new(self.lr, self.sp, self.fp)
    }
}

/// Walks an aarch64 frame-pointer chain the way elfutils' `ebl_unwind` backend
/// does when no CFI covers the program counter.
///
/// Faithful to elfutils `backends/aarch64_unwind.c`: the caller's pc is the
/// current lr (zero lr ends the walk before any caller is accepted), the next
/// lr/fp load from `fp+8`/`fp+0` (zero on failed reads), the next sp is
/// `fp+16`, and a step is accepted iff `fp == 0 || new_sp > sp`. Unlike the
/// `x86_64` backend there is no `fp >= sp` precondition, so a zero frame pointer
/// still yields one lr-based caller.
#[must_use]
pub fn unwind_aarch64_frame_pointer_stack_like_elfutils(
    regs: PerfAarch64Regs,
    stack: &[u8],
    max_frames: usize,
) -> Vec<u64> {
    let memory_reader = PerfStackReader::new(regs.sp, stack);
    let mut frames = Vec::new();
    if max_frames == 0 {
        return frames;
    }

    frames.push(regs.pc);
    let mut lr = regs.lr;
    let mut fp = regs.fp;
    let mut sp = regs.sp;
    while frames.len() < max_frames {
        if lr == 0 {
            break;
        }
        let new_lr = memory_reader.read_u64(fp.saturating_add(8)).unwrap_or(0);
        let new_fp = memory_reader.read_u64(fp).unwrap_or(0);
        let caller_sp = fp.saturating_add(16);
        if fp != 0 && caller_sp <= sp {
            break;
        }
        push_perf_unwind_address(&mut frames, lr);
        lr = new_lr;
        fp = new_fp;
        sp = caller_sp;
    }
    frames
}

impl<'a> PerfStackReader<'a> {
    #[must_use]
    pub fn new(sp: u64, bytes: &'a [u8]) -> Self {
        Self { sp, bytes }
    }

    #[must_use]
    pub fn read_u64(&self, address: u64) -> Option<u64> {
        let offset = usize::try_from(address.checked_sub(self.sp)?).ok()?;
        let bytes = self.bytes.get(offset..offset.checked_add(8)?)?;
        let bytes: [u8; 8] = bytes.try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }
}

impl<'a, F> PerfUserMemoryReader<'a, F>
where
    F: FnMut(u64) -> Option<u64>,
{
    #[must_use]
    pub fn new(sp: u64, stack: &'a [u8], mapped_read: F) -> Self {
        Self {
            sp,
            stack,
            mapped_read,
        }
    }

    #[must_use]
    pub fn read_u64(&mut self, address: u64) -> Option<u64> {
        // Matches perf tools/perf/util/unwind-libdw.c memory_read(): reject
        // overflowing words, read inside the captured user stack, otherwise
        // fall back to mapped object memory through access_dso_mem().
        let word_end = address.checked_add(8)?;
        let stack_end = self.sp.checked_add(u64::try_from(self.stack.len()).ok()?)?;
        if address < self.sp || word_end > stack_end {
            return (self.mapped_read)(address);
        }
        let offset = usize::try_from(address - self.sp).ok()?;
        let bytes = self.stack.get(offset..offset.checked_add(8)?)?;
        let bytes: [u8; 8] = bytes.try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use framehop::x86_64::Reg;
    use object::read::{Object, ObjectSegment};

    #[test]
    fn dwfl_segment_lookup_matches_four_native_pie_report_and_gc_observations() {
        // elfutils 0.195 segment.c:158-274 preserves boundary history across
        // dwfl_module.c:145-155 owner invalidation; report_elf.c:259-265 GCs
        // the identity whose fresh-FD re-report fails. Native captures:
        // target/native-replacement-20261008/GC-ORDERS.md and
        // out/pie-gc-orders/{forward,reverse}-gc-{next,first}.stdout.
        let ranges = [
            0x5555_5555_4000..0x5555_566f_525d,
            0x5555_5555_5000..0x5555_566f_625d,
        ];
        let ip = 0x5555_5567_66de;
        for (order, collected, expected) in [
            ([0, 1], 1, Some(0)),
            ([0, 1], 0, Some(1)),
            ([1, 0], 0, Some(1)),
            ([1, 0], 1, None),
        ] {
            let mut lookup = super::DwflSegmentLookup::default();
            lookup.reify([(order[0], ranges[order[0]].clone())]);
            lookup.reify(order.map(|id| (id, ranges[id].clone())));
            assert_eq!(lookup.module_for_ip(ip, |id| ranges[id].end), Some(1));
            // Re-report moves the collected identity after the surviving one
            // before setting gc; reify visits only that surviving identity.
            let retained = 1 - collected;
            lookup.reify([(retained, ranges[retained].clone())]);
            assert_eq!(
                lookup.module_for_ip(ip, |id| ranges[id].end),
                expected,
                "order={order:?} collected={collected}"
            );
        }
    }

    #[test]
    fn dwfl_segment_lookup_restores_same_range_owner_after_gc() {
        let ranges = [0x0040_0000..0x0040_20d0, 0x0040_0000..0x0040_20d0];
        let mut lookup = super::DwflSegmentLookup::default();
        lookup.reify([(0, ranges[0].clone())]);
        lookup.reify(ranges.iter().cloned().enumerate());
        assert_eq!(
            lookup.module_for_ip(0x0040_1001, |id| ranges[id].end),
            Some(1)
        );
        lookup.reify([(0, ranges[0].clone())]);
        assert_eq!(
            lookup.module_for_ip(0x0040_1001, |id| ranges[id].end),
            Some(0)
        );
        assert_eq!(
            lookup.module_for_ip(0x0040_20d0, |id| ranges[id].end),
            Some(0)
        );
        assert_eq!(lookup.module_for_ip(0x0040_20d1, |id| ranges[id].end), None);
    }

    #[test]
    fn dwfl_segment_lookup_endpoint_does_not_override_another_owner() {
        let ranges = [0x1000..0x2000, 0x2000..0x3000];
        let mut lookup = super::DwflSegmentLookup::default();
        lookup.reify(ranges.iter().cloned().enumerate());
        assert_eq!(lookup.module_for_ip(0x2000, |id| ranges[id].end), Some(1));
    }

    fn normalize_cfi_ranges_with_work_count(ranges: &mut Vec<std::ops::Range<u64>>) -> usize {
        super::CFI_RANGE_ROWS_MOVED.with(|rows| rows.set(0));
        super::normalize_ranges(ranges);
        super::CFI_RANGE_ROWS_MOVED.with(std::cell::Cell::get)
    }

    #[test]
    fn cfi_range_normalization_merges_touching_ranges() {
        let mut ranges = vec![30..40, 10..20, 20..30, 0..10];
        normalize_cfi_ranges_with_work_count(&mut ranges);
        assert_eq!(ranges, vec![0..40]);
    }

    #[test]
    fn cfi_range_normalization_preserves_outer_extent_of_nested_ranges() {
        let mut ranges = vec![20..30, 0..100, 10..90, 0..80, 50..60];
        normalize_cfi_ranges_with_work_count(&mut ranges);
        assert_eq!(ranges, vec![0..100]);
    }

    #[test]
    fn cfi_range_normalization_coalesces_duplicate_ranges() {
        let mut ranges = vec![10..20, 0..5, 10..20, 0..5, 10..20];
        normalize_cfi_ranges_with_work_count(&mut ranges);
        assert_eq!(ranges, vec![0..5, 10..20]);
    }

    #[test]
    fn cfi_range_normalization_preserves_disjoint_ranges_without_moving_rows() {
        let mut ranges = vec![30..40, 0..10, 15..20];
        let rows_moved = normalize_cfi_ranges_with_work_count(&mut ranges);
        assert_eq!(ranges, vec![0..10, 15..20, 30..40]);
        assert_eq!(rows_moved, 0);
    }

    #[test]
    fn cfi_range_normalization_preserves_half_open_coverage_and_gaps() {
        // This is our auxiliary CFI coverage index, not perf's unwind algorithm.
        let original = vec![12..16, 0..4, 2..6, 6..8, 13..15, 12..16];
        let mut ranges = original.clone();
        let rows_moved = normalize_cfi_ranges_with_work_count(&mut ranges);
        assert_eq!(ranges, vec![0..8, 12..16]);
        assert_eq!(rows_moved, 1);
        for ip in 0..=17 {
            assert_eq!(
                ranges.iter().any(|range| range.contains(&ip)),
                original.iter().any(|range| range.contains(&ip)),
                "coverage changed at {ip}"
            );
        }

        let mut ranges = vec![u64::MAX - 2..u64::MAX, u64::MAX - 4..u64::MAX - 2];
        normalize_cfi_ranges_with_work_count(&mut ranges);
        assert_eq!(ranges, vec![u64::MAX - 4..u64::MAX]);
        assert!(!ranges[0].contains(&u64::MAX));
    }

    #[test]
    fn cfi_range_normalization_merging_moves_at_most_linear_range_rows() {
        for len in [0_usize, 1, 2, 16, 64, 512] {
            for shape in ["touching", "nested", "duplicate", "disjoint"] {
                let mut ranges: Vec<_> = (0..len as u64)
                    .rev()
                    .map(|index| match shape {
                        "touching" => index..index + 1,
                        "nested" => index..2 * len as u64 - index,
                        "duplicate" => 0..1,
                        "disjoint" => 2 * index..2 * index + 1,
                        _ => unreachable!(),
                    })
                    .collect();
                let rows_moved = normalize_cfi_ranges_with_work_count(&mut ranges);
                let expected = if len == 0 {
                    Vec::new()
                } else {
                    match shape {
                        "touching" => std::iter::once(0..len as u64).collect(),
                        "nested" => std::iter::once(0..2 * len as u64).collect(),
                        "duplicate" => std::iter::once(0..1).collect(),
                        "disjoint" => (0..len as u64)
                            .map(|index| 2 * index..2 * index + 1)
                            .collect(),
                        _ => unreachable!(),
                    }
                };
                assert_eq!(ranges, expected, "{shape}, {len} input ranges");
                assert!(
                    rows_moved <= len,
                    "{shape}, {len} input ranges moved {rows_moved} range rows; linear bound is {len}"
                );
            }
        }
    }

    #[test]
    fn object_mapping_range_matches_dwfl_report_elf_load_span() {
        // perf tools/perf/util/unwind-libdw.c reports modules with
        // dwfl_report_elf(..., map__start(map) - map__pgoff(map), false).
        // libdwfl then exposes a module range spanning the ELF PT_LOAD
        // p_vaddr+p_memsz extent shifted by that base.
        let current_exe = std::env::current_exe().expect("current exe");
        let bytes = std::fs::read(&current_exe).expect("read current exe");
        let object = object::File::parse(&bytes[..]).expect("parse current exe");
        let load_range = super::object_load_range(&object).expect("load range");
        let executable_segment = object
            .segments()
            .find(|segment| segment.permissions().executable())
            .expect("executable segment");
        let load_address = 0x5555_5555_5000;
        let pgoff = executable_segment.file_range().0;
        let start = load_address + executable_segment.address();
        let len = executable_segment.size();
        let perf_dwfl_base = start - pgoff;

        let mut unwinder = super::FramehopUnwinder::new();
        assert!(
            unwinder
                .add_object_mapping(&current_exe, start, len, pgoff)
                .expect("add object mapping")
        );

        assert_eq!(
            unwinder.reported_modules[0].range,
            perf_dwfl_base + load_range.start..perf_dwfl_base + load_range.end
        );
        assert!(unwinder.has_reported_module_for_ip(perf_dwfl_base + load_range.start));
        // segment.c:267-274 accepts an exact high boundary only when its
        // lookup slot is unowned and the preceding module ends here.
        assert!(unwinder.has_reported_module_for_ip(perf_dwfl_base + load_range.end));
        assert!(!unwinder.has_reported_module_for_ip(perf_dwfl_base + load_range.end + 1));
    }

    #[test]
    fn jitted_object_mapping_uses_map_start_as_dwfl_base_like_perf_libdw() {
        // tools/perf/util/unwind-libdw.c special-cases generated JIT DSOs:
        // paths starting with /tmp/jitted- use map__start(al->map) as the
        // DWFL base instead of map__start(al->map) - map__pgoff(al->map).
        let current_exe = std::env::current_exe().expect("current exe");
        let jitted_path = std::path::PathBuf::from(format!(
            "/tmp/jitted-pyroclast-test-{}.so",
            std::process::id()
        ));
        std::fs::copy(&current_exe, &jitted_path).expect("copy test object");
        let bytes = std::fs::read(&jitted_path).expect("read jitted object");
        let object = object::File::parse(&bytes[..]).expect("parse jitted object");
        let load_range = super::object_load_range(&object).expect("load range");

        let start = 0x7000_0000_0000;
        let pgoff = 0x2000;
        let mut unwinder = super::FramehopUnwinder::new();
        assert!(
            unwinder
                .add_object_mapping(&jitted_path, start, 0x1000_0000, pgoff)
                .expect("add jitted object mapping")
        );
        let _ = std::fs::remove_file(&jitted_path);

        assert_eq!(
            unwinder.reported_modules[0].range,
            start + load_range.start..start + load_range.end
        );
    }

    #[test]
    fn detects_syscall_return_state_with_normal_frame_pointer_like_perf_libdw() {
        let ip = 0x7fff_f7e9_a23e;
        let mut registers = [0; 16];
        registers[Reg::RCX as usize] = ip;
        registers[Reg::R11 as usize] = 0x206;
        let regs = super::PerfX86_64Regs {
            ip,
            sp: 0x7fff_ffff_88b8,
            bp: 0x7fff_ffff_89e0,
            registers,
        };

        assert!(regs.is_syscall_return_state());
    }

    #[test]
    fn keeps_ebl_fallback_tail_after_cfi_runs_out_like_elfutils_libdwfl() {
        // elfutils libdwfl/frame_unwind.c tries EH CFI, then DWARF CFI, then
        // ebl_unwind(). There is no post-filter that trims already accepted
        // backend fallback frames just because the address lacks CFI.
        let mut frames = vec![0x1000, 0x2000, 0x3000, 0x4000];

        super::truncate_at_first_uncovered_unwind_frame(&mut frames, |address| address < 0x3000);

        assert_eq!(frames, vec![0x1000, 0x2000, 0x3000, 0x4000]);
    }

    #[test]
    fn keeps_terminal_object_unwind_frame_without_cfi_like_perf_libdw() {
        let mut frames = vec![0x1000, 0x2000, 0x3000];

        super::truncate_at_first_uncovered_unwind_frame(&mut frames, |address| address < 0x3000);

        assert_eq!(frames, vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn frame_pointer_arch_fallback_matches_elfutils_x86_64_unwind() {
        // elfutils backends/x86_64_unwind.c uses rbp as a conventional frame
        // pointer, reads [rbp] as previous rbp, [rbp + 8] as return address,
        // and advances sp by 16 before accepting the caller.
        let mut registers = [0; 16];
        registers[Reg::RSP as usize] = 0x7fff_ffff_9250;
        registers[Reg::RBP as usize] = 0x7fff_ffff_9260;
        let regs = super::PerfX86_64Regs {
            ip: 0x7fff_f7e1_c03e,
            sp: 0x7fff_ffff_9250,
            bp: 0x7fff_ffff_9260,
            registers,
        };
        let mut stack = vec![0; 0x40];
        stack[0x10..0x18].copy_from_slice(&0x7fff_ffff_9270_u64.to_le_bytes());
        stack[0x18..0x20].copy_from_slice(&0x7fff_f7e1_c084_u64.to_le_bytes());
        stack[0x20..0x28].copy_from_slice(&0_u64.to_le_bytes());
        stack[0x28..0x30].copy_from_slice(&0x7fff_f7e9_9d7e_u64.to_le_bytes());

        assert_eq!(
            super::unwind_x86_64_frame_pointer_stack_like_elfutils(regs, &stack, 256),
            vec![0x7fff_f7e1_c03e, 0x7fff_f7e1_c083, 0x7fff_f7e9_9d7d]
        );
    }

    #[test]
    fn frame_pointer_arch_fallback_rejects_non_advancing_stack_like_elfutils() {
        let mut registers = [0; 16];
        registers[Reg::RSP as usize] = 0x8000;
        registers[Reg::RBP as usize] = 0x7ff0;
        let regs = super::PerfX86_64Regs {
            ip: 0x4000,
            sp: 0x8000,
            bp: 0x7ff0,
            registers,
        };
        let mut stack = vec![0; 0x20];
        stack[0..8].copy_from_slice(&0_u64.to_le_bytes());
        stack[8..16].copy_from_slice(&0x5000_u64.to_le_bytes());

        assert_eq!(
            super::unwind_x86_64_frame_pointer_stack_like_elfutils(regs, &stack, 256),
            vec![0x4000]
        );
    }

    #[test]
    fn keeps_initial_object_unwind_frame_without_cfi_like_perf_libdw() {
        let mut frames = vec![0x3000, 0x1000];

        super::truncate_at_first_uncovered_unwind_frame(&mut frames, |address| address < 0x3000);

        assert_eq!(frames, vec![0x3000, 0x1000]);
    }

    #[test]
    fn keeps_object_unwind_when_all_frames_have_cfi_like_perf_libdw() {
        let mut frames = vec![0x1000, 0x2000];

        super::truncate_at_first_uncovered_unwind_frame(&mut frames, |_| true);

        assert_eq!(frames, vec![0x1000, 0x2000]);
    }

    #[test]
    fn decodes_aarch64_registers_from_perf_mask() {
        // perf record --call-graph dwarf on arm64 captures x0-x30, sp, pc.
        let mask = (1_u64 << 33) - 1;
        let mut values = (0_u64..33).collect::<Vec<_>>();
        values[29] = 0x2900; // fp
        values[30] = 0x3000; // lr
        values[31] = 0x3100; // sp
        values[32] = 0x3200; // pc

        let regs = super::PerfAarch64Regs::from_perf_masked_values(mask, &values).expect("regs");

        assert_eq!(
            regs,
            super::PerfAarch64Regs {
                pc: 0x3200,
                sp: 0x3100,
                fp: 0x2900,
                lr: 0x3000,
            }
        );
    }

    #[test]
    fn decodes_aarch64_registers_from_sparse_perf_mask() {
        let mask = (1 << 29) | (1 << 30) | (1 << 31) | (1 << 32);
        let values = [0x2900, 0x3000, 0x3100, 0x3200];

        let regs = super::PerfAarch64Regs::from_perf_masked_values(mask, &values).expect("regs");

        assert_eq!(regs.fp, 0x2900);
        assert_eq!(regs.lr, 0x3000);
        assert_eq!(regs.sp, 0x3100);
        assert_eq!(regs.pc, 0x3200);
    }

    #[test]
    fn rejects_aarch64_registers_missing_pc() {
        let mask = (1 << 29) | (1 << 30) | (1 << 31);
        let values = [0x2900, 0x3000, 0x3100];

        let error =
            super::PerfAarch64Regs::from_perf_masked_values(mask, &values).expect_err("missing pc");

        assert!(error.contains("PC"));
    }

    #[test]
    fn aarch64_frame_pointer_unwind_walks_fp_chain_like_elfutils() {
        // Stack layout (sp = 0x1000): fp chain records at fp+0 / lr at fp+8,
        // matching elfutils aarch64_unwind.c FP_OFFSET/LR_OFFSET/SP_OFFSET.
        let regs = super::PerfAarch64Regs {
            pc: 0x4000,
            sp: 0x1000,
            fp: 0x1010,
            lr: 0x5000,
        };
        let mut stack = vec![0_u8; 0x40];
        // frame at fp=0x1010: next fp = 0x1030, next lr = 0x6000
        stack[0x10..0x18].copy_from_slice(&0x1030_u64.to_le_bytes());
        stack[0x18..0x20].copy_from_slice(&0x6000_u64.to_le_bytes());
        // frame at fp=0x1030: next fp = 0, next lr = 0 (end of chain)
        stack[0x30..0x38].copy_from_slice(&0_u64.to_le_bytes());
        stack[0x38..0x40].copy_from_slice(&0_u64.to_le_bytes());

        let frames = super::unwind_aarch64_frame_pointer_stack_like_elfutils(regs, &stack, 256);

        // Return addresses after the leaf take the perf `pc - 1` adjustment.
        assert_eq!(frames, vec![0x4000, 0x4fff, 0x5fff]);
    }

    #[test]
    fn aarch64_frame_pointer_unwind_accepts_one_lr_caller_when_fp_is_zero() {
        // elfutils: `return fp == 0 || newSp > sp` — a zero fp still accepts
        // the lr-based caller, then the walk ends on the zeroed next lr.
        let regs = super::PerfAarch64Regs {
            pc: 0x4000,
            sp: 0x1000,
            fp: 0,
            lr: 0x5000,
        };

        let frames =
            super::unwind_aarch64_frame_pointer_stack_like_elfutils(regs, &[0_u8; 0x20], 256);

        assert_eq!(frames, vec![0x4000, 0x4fff]);
    }

    #[test]
    fn aarch64_frame_pointer_unwind_rejects_backwards_stack_growth() {
        // fp != 0 and newSp (fp+16) <= sp must discard the candidate caller.
        let regs = super::PerfAarch64Regs {
            pc: 0x4000,
            sp: 0x1020,
            fp: 0x1000,
            lr: 0x5000,
        };

        let frames =
            super::unwind_aarch64_frame_pointer_stack_like_elfutils(regs, &[0_u8; 0x40], 256);

        assert_eq!(frames, vec![0x4000]);
    }

    #[test]
    fn aarch64_frame_pointer_unwind_stops_on_zero_lr_without_callers() {
        let regs = super::PerfAarch64Regs {
            pc: 0x4000,
            sp: 0x1000,
            fp: 0x1010,
            lr: 0,
        };

        let frames =
            super::unwind_aarch64_frame_pointer_stack_like_elfutils(regs, &[0_u8; 0x40], 256);

        assert_eq!(frames, vec![0x4000]);
    }
}
