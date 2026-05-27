use std::fs::File;
use std::ops::{Deref, Range};
use std::path::Path;
use std::sync::Arc;

use framehop::x86_64::{CacheX86_64, UnwindRegsX86_64, UnwinderX86_64};
use framehop::{ExplicitModuleSectionInfo, Unwinder};
use memmap2::Mmap;
use object::read::{Object, ObjectSection, ObjectSegment};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfX86_64Regs {
    pub ip: u64,
    pub sp: u64,
    pub bp: u64,
}

pub struct PerfStackReader<'a> {
    sp: u64,
    bytes: &'a [u8],
}

pub struct FramehopUnwinder {
    unwinder: UnwinderX86_64<ModuleBytes>,
    cache: CacheX86_64,
    module_count: usize,
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
    let stack_reader = PerfStackReader::new(regs.sp, stack);
    let mut read_stack = |address| stack_reader.read_u64(address).ok_or(());
    let mut cache = CacheX86_64::new();
    let unwinder = UnwinderX86_64::<Vec<u8>>::new();
    let ip = regs.ip;
    let regs = UnwindRegsX86_64::new(ip, regs.sp, regs.bp);
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
        let section_info = explicit_module_section_info(&mapped, &object);
        let module = framehop::Module::<ModuleBytes>::new(
            path.to_string_lossy().into_owned(),
            start..start.saturating_add(len),
            start.saturating_sub(pgoff),
            section_info,
        );
        self.unwinder.add_module(module);
        self.module_count += 1;
        Ok(true)
    }

    #[must_use]
    pub fn module_count(&self) -> usize {
        self.module_count
    }

    #[must_use]
    pub fn unwind_stack(
        &mut self,
        regs: PerfX86_64Regs,
        stack: &[u8],
        max_frames: usize,
    ) -> Vec<u64> {
        let stack_reader = PerfStackReader::new(regs.sp, stack);
        let mut read_stack = |address| stack_reader.read_u64(address).ok_or(());
        let ip = regs.ip;
        let regs = UnwindRegsX86_64::new(ip, regs.sp, regs.bp);
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
        frames
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

impl PerfX86_64Regs {
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
        let mut values = values.iter().copied();
        for register in 0..64 {
            if mask & (1 << register) == 0 {
                continue;
            }
            let value = values
                .next()
                .ok_or_else(|| "perf register value is missing".to_string())?;
            match register {
                6 => bp = Some(value),
                7 => sp = Some(value),
                8 => ip = Some(value),
                _ => {}
            }
        }

        Ok(Self {
            ip: ip.ok_or_else(|| "perf sample is missing x86_64 IP register".to_string())?,
            sp: sp.ok_or_else(|| "perf sample is missing x86_64 SP register".to_string())?,
            bp: bp.ok_or_else(|| "perf sample is missing x86_64 BP register".to_string())?,
        })
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
