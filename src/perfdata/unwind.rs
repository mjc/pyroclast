use std::path::Path;

use framehop::Unwinder;
use framehop::x86_64::{CacheX86_64, UnwindRegsX86_64, UnwinderX86_64};

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
    unwinder: UnwinderX86_64<Vec<u8>>,
    cache: CacheX86_64,
    module_count: usize,
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
        frames.push(frame.address());
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
        let bytes = std::fs::read(path)
            .map_err(|error| format!("failed to read unwind object {}: {error}", path.display()))?;
        let object = object::File::parse(bytes.as_slice()).map_err(|error| {
            format!("failed to parse unwind object {}: {error}", path.display())
        })?;
        let section_info = framehop_object::ObjectSectionInfo::new(object);
        let module = framehop::Module::<Vec<u8>>::new(
            path.to_string_lossy().into_owned(),
            start..start.saturating_add(len),
            start.saturating_sub(pgoff),
            &section_info,
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
            frames.push(frame.address());
        }
        frames
    }
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
