use std::fs::File;
use std::ops::{Deref, Range};
use std::path::Path;
use std::sync::Arc;

use framehop::x86_64::{CacheX86_64, Reg, UnwindRegsX86_64, UnwinderX86_64};
use framehop::{ExplicitModuleSectionInfo, Unwinder};
use gimli::{BaseAddresses, CieOrFde, DebugFrame, EhFrame, LittleEndian, UnwindSection};
use memmap2::Mmap;
use object::read::{Object, ObjectSection, ObjectSegment};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfX86_64Regs {
    pub ip: u64,
    pub sp: u64,
    pub bp: u64,
    pub registers: [u64; 16],
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
    unwinder: UnwinderX86_64<ModuleBytes>,
    cache: CacheX86_64,
    module_count: usize,
    reported_modules: Vec<ReportedModule>,
    rejected_mapping_ranges: Vec<Range<u64>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserStackUnwindResult {
    pub accepted_frames: Vec<u64>,
    pub framehop_frame_count: usize,
}

pub trait UserStackUnwinder {
    fn unwind_user_stack(
        &mut self,
        regs: PerfX86_64Regs,
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
        Self {
            unwinder: UnwinderX86_64::new(),
            cache: CacheX86_64::new(),
            module_count: 0,
            reported_modules: Vec::new(),
            rejected_mapping_ranges: Vec::new(),
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
        let base = start.saturating_sub(pgoff);
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
        let module = framehop::Module::<ModuleBytes>::new(
            path.to_string_lossy().into_owned(),
            module_range.clone(),
            base,
            section_info,
        );
        self.unwinder.add_module(module);
        self.reported_modules.push(ReportedModule {
            base,
            range: module_range,
            memory_segments,
            unwind_ranges,
        });
        self.module_count += 1;
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
        self.reported_modules
            .iter()
            .any(|module| module.unwind_ranges.iter().any(|range| range.contains(&ip)))
    }

    #[must_use]
    pub fn read_process_u64(&self, address: u64) -> Option<u64> {
        read_reported_module_u64(&self.reported_modules, address)
    }

    #[must_use]
    pub fn unwind_stack(
        &mut self,
        regs: PerfX86_64Regs,
        stack: &[u8],
        max_frames: usize,
    ) -> Vec<u64> {
        self.unwind_stack_with_diagnostics(regs, stack, max_frames)
            .accepted_frames
    }

    #[must_use]
    pub fn unwind_stack_with_diagnostics(
        &mut self,
        regs: PerfX86_64Regs,
        stack: &[u8],
        max_frames: usize,
    ) -> UserStackUnwindResult {
        if self
            .rejected_mapping_ranges
            .iter()
            .any(|range| range.contains(&regs.ip))
        {
            return UserStackUnwindResult::default();
        }
        let reported_modules = &self.reported_modules;
        let mut memory_reader = PerfUserMemoryReader::new(regs.sp, stack, |address| {
            read_reported_module_u64(reported_modules, address)
        });
        let mut read_stack = |address| memory_reader.read_u64(address).ok_or(());
        let ip = regs.ip;
        let regs = regs.to_framehop_regs();
        let mut iter = self
            .unwinder
            .iter_frames(ip, regs, &mut self.cache, &mut read_stack);
        let mut frames = Vec::new();
        while frames.len() < max_frames {
            let Ok(Some(frame)) = iter.next() else {
                break;
            };
            push_perf_unwind_address(&mut frames, frame.address());
        }
        let framehop_frame_count = frames.len();
        UserStackUnwindResult {
            accepted_frames: frames,
            framehop_frame_count,
        }
    }
}

impl UserStackUnwinder for FramehopUnwinder {
    fn unwind_user_stack(
        &mut self,
        regs: PerfX86_64Regs,
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
        let jitted_path =
            std::env::temp_dir().join(format!("jitted-pyroclast-test-{}.so", std::process::id()));
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
}
