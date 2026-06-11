use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::ops::{Deref, Range};
use std::path::Path;
use std::sync::Arc;

use framehop::aarch64::{CacheAarch64, UnwindRegsAarch64, UnwinderAarch64};
use framehop::x86_64::{CacheX86_64, Reg, UnwindRegsX86_64, UnwinderX86_64};
use framehop::{ExplicitModuleSectionInfo, Module, Unwinder};
use gimli::{BaseAddresses, CieOrFde, DebugFrame, EhFrame, LittleEndian, UnwindSection};
use memmap2::Mmap;
use object::read::{Object, ObjectSection, ObjectSegment};
use rustc_hash::FxBuildHasher;

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
/// from the HEADER_ARCH feature string.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PerfArch {
    #[default]
    X86_64,
    Aarch64,
}

impl PerfArch {
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

/// Architecture-neutral user register sample, decoded from a perf REGS_USER
/// payload according to the recording machine's arch.
///
/// The fold path threads this through every unwind site so the x86_64 and
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

    /// The sampled instruction pointer (x86_64 IP / aarch64 PC).
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

    /// Whether the sample looks like an x86_64 syscall-return state, which perf
    /// truncates after the first executable frame. aarch64 has no analogue, so
    /// this is always `false` there.
    #[must_use]
    pub fn is_syscall_return_state(self) -> bool {
        match self {
            Self::X86_64(regs) => regs.is_syscall_return_state(),
            Self::Aarch64(_) => false,
        }
    }

    /// The x86_64 `ebl_unwind` frame-pointer precondition `bp >= sp`.
    ///
    /// elfutils' x86_64 backend only walks the rbp chain when the frame pointer
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
    rejected_mapping_ranges: Vec<Range<u64>>,
    /// Exact-ip memo for `has_unwind_info_for_ip`. Interior-mutable so the
    /// predicate stays `&self`; cleared whenever a new module is added, since
    /// that can extend coverage over a previously-uncovered ip.
    unwind_info_memo: RefCell<HashMap<u64, bool, FxBuildHasher>>,
}

/// Per-architecture framehop unwinder and cache. Module registration is shared
/// (both arches register `framehop::Module<ModuleBytes>` from the same
/// `ExplicitModuleSectionInfo`); only the seeded registers and `iter_frames`
/// differ, so the regs handed to `unwind` must match the active arch.
enum ArchUnwinder {
    X86_64 {
        unwinder: Box<UnwinderX86_64<ModuleBytes>>,
        cache: CacheX86_64,
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

#[derive(Clone, Debug)]
struct ReportedModule {
    base: u64,
    range: Range<u64>,
    memory_segments: Vec<ModuleMemorySegment>,
    unwind_ranges: Vec<Range<u64>>,
}

#[derive(Clone, Debug)]
struct ModuleMemorySegment {
    range: Range<u64>,
    bytes: ModuleBytes,
}

#[derive(Clone, Debug)]
enum ModuleBytes {
    Mapped(MappedBytes),
    Owned(Vec<u8>),
}

#[derive(Clone, Debug)]
struct MappedBytes {
    mmap: Arc<Mmap>,
    range: Range<usize>,
}

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
            rejected_mapping_ranges: Vec::new(),
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
        if len == 0 {
            return Ok(false);
        }
        let file = File::open(path)
            .map_err(|error| format!("failed to open unwind object {}: {error}", path.display()))?;
        let mapped =
            Arc::new(unsafe { Mmap::map(&file) }.map_err(|error| {
                format!("failed to map unwind object {}: {error}", path.display())
            })?);
        let object = object::File::parse(&mapped[..]).map_err(|error| {
            format!("failed to parse unwind object {}: {error}", path.display())
        })?;
        let base = if path
            .to_str()
            .is_some_and(|path| path.starts_with("/tmp/jitted-"))
        {
            start
        } else {
            start.saturating_sub(pgoff)
        };
        let Some(module_range) = object_load_range(&object)
            .map(|range| base.saturating_add(range.start)..base.saturating_add(range.end))
        else {
            return Ok(false);
        };
        let mapping_range = start..start.saturating_add(len);
        if self
            .reported_modules
            .iter()
            .any(|module| ranges_overlap(&module.range, &module_range) && module.base != base)
        {
            self.rejected_mapping_ranges.push(mapping_range);
            return Ok(false);
        }
        if self
            .reported_modules
            .iter()
            .any(|module| module.base == base)
        {
            return Ok(false);
        }
        let section_info = explicit_module_section_info(&mapped, &object);
        let memory_segments = module_memory_segments(&mapped, &object, base);
        let unwind_ranges = object_unwind_ranges(&object, base);
        let module = Module::<ModuleBytes>::new(
            path.to_string_lossy().into_owned(),
            module_range.clone(),
            base,
            section_info,
        );
        self.arch.add_module(module);
        self.reported_modules.push(ReportedModule {
            base,
            range: module_range,
            memory_segments,
            unwind_ranges,
        });
        self.module_count += 1;
        // A newly reported module can add CFI coverage over an ip that was
        // previously memoized as uncovered; drop the memo so the next query
        // re-scans against the full module set.
        self.unwind_info_memo.borrow_mut().clear();
        Ok(true)
    }

    #[must_use]
    pub fn module_count(&self) -> usize {
        self.module_count
    }

    #[must_use]
    pub fn has_reported_module_for_ip(&self, ip: u64) -> bool {
        self.reported_modules
            .iter()
            .any(|module| module.range.contains(&ip))
    }

    #[must_use]
    pub fn has_rejected_mapping_for_ip(&self, ip: u64) -> bool {
        self.rejected_mapping_ranges
            .iter()
            .any(|range| range.contains(&ip))
    }

    #[must_use]
    pub fn has_unwind_info_for_ip(&self, ip: u64) -> bool {
        if let Some(&cached) = self.unwind_info_memo.borrow().get(&ip) {
            return cached;
        }
        let covered = self
            .reported_modules
            .iter()
            .any(|module| module.unwind_ranges.iter().any(|range| range.contains(&ip)));
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
        if self
            .rejected_mapping_ranges
            .iter()
            .any(|range| range.contains(&regs.ip()))
        {
            return UserStackUnwindResult::default();
        }
        let reported_modules = &self.reported_modules;
        let mut memory_reader = PerfUserMemoryReader::new(regs.sp(), stack, |address| {
            read_reported_module_u64(reported_modules, address)
        });
        let mut read_stack = |address| memory_reader.read_u64(address).ok_or(());
        let ip = regs.ip();
        let frames = self
            .arch
            .iter_addresses(ip, regs, &mut read_stack, max_frames);
        let framehop_frame_count = frames.len();
        UserStackUnwindResult {
            accepted_frames: frames,
            framehop_frame_count,
        }
    }
}

impl ArchUnwinder {
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
    ) -> Vec<u64> {
        let mut frames = Vec::new();
        // The seeded register file must match the active arch; a mismatch means
        // the file header arch and the regs decode disagreed, which cannot
        // happen because both flow from the same PerfArch.
        match (self, regs) {
            (Self::X86_64 { unwinder, cache }, PerfUserRegs::X86_64(regs)) => {
                let mut iter = unwinder.iter_frames(ip, regs.to_framehop_regs(), cache, read_stack);
                while frames.len() < max_frames {
                    let Ok(Some(frame)) = iter.next() else {
                        break;
                    };
                    push_perf_unwind_address(&mut frames, frame.address());
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
        match self {
            Self::Mapped(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

impl Deref for MappedBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.mmap[self.range.clone()]
    }
}

fn explicit_module_section_info<'a>(
    mapped: &Arc<Mmap>,
    object: &object::File<'a, &'a [u8]>,
) -> ExplicitModuleSectionInfo<ModuleBytes> {
    ExplicitModuleSectionInfo {
        base_svma: object_base_svma(object),
        text_svma: first_section_svma_range(object, &[b"__text", b".text"]),
        text: first_section_data(mapped, object, &[b"__text", b".text"]),
        stubs_svma: first_section_svma_range(object, &[b"__stubs"]),
        stub_helper_svma: first_section_svma_range(object, &[b"__stub_helper"]),
        got_svma: first_section_svma_range(object, &[b"__got", b".got"]),
        unwind_info: first_section_data(mapped, object, &[b"__unwind_info"]),
        eh_frame_svma: first_section_svma_range(object, &[b"__eh_frame", b".eh_frame"]),
        eh_frame: first_section_data(mapped, object, &[b"__eh_frame", b".eh_frame"]),
        eh_frame_hdr_svma: first_section_svma_range(object, &[b"__eh_frame_hdr", b".eh_frame_hdr"]),
        eh_frame_hdr: first_section_data(mapped, object, &[b"__eh_frame_hdr", b".eh_frame_hdr"]),
        debug_frame: first_section_data(mapped, object, &[b".debug_frame"]),
        text_segment_svma: segment_svma_range(object, b"__TEXT"),
        text_segment: segment_data(mapped, object, b"__TEXT"),
    }
}

fn object_base_svma<'a>(object: &object::File<'a, &'a [u8]>) -> u64 {
    object
        .segments()
        .find(|segment| segment.name() == Ok(Some("__TEXT")))
        .map_or_else(
            || object.relative_address_base(),
            |segment| segment.address(),
        )
}

fn object_load_range<'a>(object: &object::File<'a, &'a [u8]>) -> Option<Range<u64>> {
    object
        .segments()
        .filter(|segment| segment.size() != 0)
        .map(|segment| {
            let start = segment.address();
            start..start.saturating_add(segment.size())
        })
        .reduce(|left, right| left.start.min(right.start)..left.end.max(right.end))
}

fn object_unwind_ranges<'a>(object: &object::File<'a, &'a [u8]>, base: u64) -> Vec<Range<u64>> {
    let bases = object_cfi_base_addresses(object);
    let mut ranges = Vec::new();
    append_eh_frame_unwind_ranges(object, base, &bases, &mut ranges);
    append_debug_frame_unwind_ranges(object, base, &bases, &mut ranges);
    normalize_ranges(&mut ranges);
    ranges
}

fn append_eh_frame_unwind_ranges<'a>(
    object: &object::File<'a, &'a [u8]>,
    base: u64,
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
        push_unwind_range(ranges, base, fde.initial_address(), fde.end_address());
    }
}

fn append_debug_frame_unwind_ranges<'a>(
    object: &object::File<'a, &'a [u8]>,
    base: u64,
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
        push_unwind_range(ranges, base, fde.initial_address(), fde.end_address());
    }
}

fn object_cfi_base_addresses<'a>(object: &object::File<'a, &'a [u8]>) -> BaseAddresses {
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

fn section_address<'a>(object: &object::File<'a, &'a [u8]>, name: &[u8]) -> Option<u64> {
    object
        .section_by_name_bytes(name)
        .map(|section| section.address())
}

fn first_section_address<'a>(object: &object::File<'a, &'a [u8]>, names: &[&[u8]]) -> Option<u64> {
    names.iter().find_map(|name| section_address(object, name))
}

fn push_unwind_range(ranges: &mut Vec<Range<u64>>, base: u64, start: u64, end: u64) {
    let Some(start) = base.checked_add(start) else {
        return;
    };
    let Some(end) = base.checked_add(end) else {
        return;
    };
    if start < end {
        ranges.push(start..end);
    }
}

fn normalize_ranges(ranges: &mut Vec<Range<u64>>) {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut index = 0;
    while index + 1 < ranges.len() {
        if ranges[index].end >= ranges[index + 1].start {
            ranges[index].end = ranges[index].end.max(ranges[index + 1].end);
            ranges.remove(index + 1);
        } else {
            index += 1;
        }
    }
}

fn module_memory_segments<'a>(
    mapped: &Arc<Mmap>,
    object: &object::File<'a, &'a [u8]>,
    base: u64,
) -> Vec<ModuleMemorySegment> {
    object
        .segments()
        .filter_map(|segment| {
            let bytes = map_file_range(mapped, segment.file_range())?;
            let start = base.saturating_add(segment.address());
            let len = u64::try_from(bytes.len()).ok()?;
            Some(ModuleMemorySegment {
                range: start..start.saturating_add(len),
                bytes,
            })
        })
        .collect()
}

fn read_reported_module_u64(modules: &[ReportedModule], address: u64) -> Option<u64> {
    modules
        .iter()
        .flat_map(|module| module.memory_segments.iter())
        .find_map(|segment| {
            let offset = usize::try_from(address.checked_sub(segment.range.start)?).ok()?;
            let bytes = segment.bytes.get(offset..offset.checked_add(8)?)?;
            let bytes: [u8; 8] = bytes.try_into().ok()?;
            Some(u64::from_le_bytes(bytes))
        })
}

fn ranges_overlap(left: &Range<u64>, right: &Range<u64>) -> bool {
    left.start < right.end && right.start < left.end
}

fn first_section_svma_range<'a>(
    object: &object::File<'a, &'a [u8]>,
    names: &[&[u8]],
) -> Option<Range<u64>> {
    names.iter().find_map(|name| {
        let section = object.section_by_name_bytes(name)?;
        Some(section.address()..section.address().saturating_add(section.size()))
    })
}

fn first_section_data<'a>(
    mapped: &Arc<Mmap>,
    object: &object::File<'a, &'a [u8]>,
    names: &[&[u8]],
) -> Option<ModuleBytes> {
    names.iter().find_map(|name| {
        let section = object.section_by_name_bytes(name)?;
        section_data(mapped, &section)
    })
}

fn segment_svma_range<'a>(object: &object::File<'a, &'a [u8]>, name: &[u8]) -> Option<Range<u64>> {
    let segment = object
        .segments()
        .find(|segment| segment.name_bytes() == Ok(Some(name)))?;
    Some(segment.address()..segment.address().saturating_add(segment.size()))
}

fn segment_data<'a>(
    mapped: &Arc<Mmap>,
    object: &object::File<'a, &'a [u8]>,
    name: &[u8],
) -> Option<ModuleBytes> {
    let segment = object
        .segments()
        .find(|segment| segment.name_bytes() == Ok(Some(name)))?;
    map_file_range(mapped, segment.file_range()).or_else(|| {
        segment
            .data()
            .ok()
            .map(|data| ModuleBytes::Owned(data.to_vec()))
    })
}

fn section_data<'a, S>(mapped: &Arc<Mmap>, section: &S) -> Option<ModuleBytes>
where
    S: ObjectSection<'a>,
{
    map_optional_file_range(mapped, section.file_range()).or_else(|| {
        section
            .data()
            .ok()
            .map(|data| ModuleBytes::Owned(data.to_vec()))
    })
}

fn map_optional_file_range(mapped: &Arc<Mmap>, range: Option<(u64, u64)>) -> Option<ModuleBytes> {
    map_file_range(mapped, range?)
}

fn map_file_range(mapped: &Arc<Mmap>, (offset, size): (u64, u64)) -> Option<ModuleBytes> {
    let start = usize::try_from(offset).ok()?;
    let len = usize::try_from(size).ok()?;
    let end = start.checked_add(len)?;
    (end <= mapped.len()).then(|| {
        ModuleBytes::Mapped(MappedBytes {
            mmap: Arc::clone(mapped),
            range: start..end,
        })
    })
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
                8 => ip = Some(value),
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
            bp: bp.ok_or_else(|| "perf sample is missing x86_64 BP register".to_string())?,
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
        const PC: u32 = 32;

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
            pc: masked(PC)
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
/// Faithful to elfutils backends/aarch64_unwind.c: the caller's pc is the
/// current lr (zero lr ends the walk before any caller is accepted), the next
/// lr/fp load from `fp+8`/`fp+0` (zero on failed reads), the next sp is
/// `fp+16`, and a step is accepted iff `fp == 0 || new_sp > sp`. Unlike the
/// x86_64 backend there is no `fp >= sp` precondition, so a zero frame pointer
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
        let new_sp = fp.saturating_add(16);
        if fp != 0 && new_sp <= sp {
            break;
        }
        push_perf_unwind_address(&mut frames, lr);
        lr = new_lr;
        fp = new_fp;
        sp = new_sp;
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
        assert!(!unwinder.has_reported_module_for_ip(perf_dwfl_base + load_range.end));
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
