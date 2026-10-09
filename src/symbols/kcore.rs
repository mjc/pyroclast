use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{Kallsyms, KallsymsSymbol, KernelModuleSectionMap, is_kernel_module_symbol_path_str};
use crate::perfdata::fold::recorded_kernel_maps_file;
use crate::perfdata::unwind::PerfArch;

pub(super) struct KcoreSymbols {
    ranges: Vec<(u64, u64)>,
    symbols: BTreeMap<u64, KallsymsSymbol>,
    module_bases: BTreeMap<String, u64>,
    active: AtomicBool,
    rejected: AtomicBool,
}

impl KcoreSymbols {
    pub(super) fn load(recording: &Path, kallsyms_path: &Path) -> Option<Self> {
        // perf util/symbol.c:filename_from_kallsyms_filename only recognizes
        // a file named kallsyms, with kcore and modules alongside it.
        if kallsyms_path.file_name()? != "kallsyms" {
            return None;
        }
        let directory = kallsyms_path.parent()?;
        let (arch, recorded) = recorded_kernel_maps_file(recording).ok()?;
        let core = recorded
            .iter()
            .rev()
            .find(|map| map.path.starts_with("[kernel.kallsyms]"))?;
        let text = std::fs::read_to_string(kallsyms_path).ok()?;
        let reference = core.path.strip_prefix("[kernel.kallsyms]")?;
        // perf validate_kcore_addresses requires an exact reference address;
        // relocation is valid for kallsyms, but never for live kcore maps.
        if core.pgoff != 0
            && !reference.is_empty()
            && Kallsyms::parse(&text).ok()?.address_of(reference)? != core.pgoff
        {
            return None;
        }
        let modules = std::fs::read_to_string(directory.join("modules")).ok()?;
        let module_bases = modules
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                let address = fields.get(5)?.trim_start_matches("0x");
                Some((
                    format!("[{}]", fields.first()?),
                    u64::from_str_radix(address, 16).ok()?,
                ))
            })
            .collect::<BTreeMap<_, _>>();
        for mapping in &recorded {
            if let Some(module) = module_short_name(&mapping.path)
                && module_bases.get(module.as_ref()) != Some(&mapping.start)
            {
                return None;
            }
        }
        let mut file = super::open_regular_object(&directory.join("kcore"))?;
        let ranges = read_load_ranges(&mut file, core.prot & 4 != 0, arch)?;
        if ranges.is_empty() {
            return None;
        }
        // symbol.c:maps__split_kallsyms_for_kcore shares the globally fixed
        // symbol tree across replacement maps, stripping module suffixes.
        let symbols: BTreeMap<_, _> = Kallsyms::parse_module_symbols(&text)
            .into_iter()
            .filter_map(|row| {
                let (_, end) = ranges
                    .iter()
                    .find(|&&(start, end)| start <= row.address && row.address < end)?;
                Some((
                    row.address,
                    KallsymsSymbol {
                        name: row.name.into(),
                        end: Some(row.end.min(*end)),
                        module: None,
                    },
                ))
            })
            .collect();
        if symbols.is_empty() {
            return None;
        }
        Some(Self {
            ranges,
            symbols,
            module_bases,
            active: AtomicBool::new(false),
            rejected: AtomicBool::new(false),
        })
    }

    pub(super) fn is_rejected(&self) -> bool {
        self.rejected.load(Ordering::Relaxed)
    }

    pub(super) fn finish_module_load(&self, path: &Path, maps: &[KernelModuleSectionMap]) {
        self.validate_module_maps(path, maps);
        if !self.is_rejected() {
            self.activate(true);
        }
    }

    pub(super) fn validate_module_maps(&self, path: &Path, maps: &[KernelModuleSectionMap]) {
        // perf symbol.c:do_validate_kcore_modules_cb checks every resulting
        // module map against /proc/modules by DSO short name and start.
        let module = module_dso_short_name(path.to_str().unwrap_or_default());
        if maps.iter().any(|map| {
            self.module_bases.get(&format!("{module}{}", map.section)) != Some(&map.start)
        }) {
            self.rejected.store(true, Ordering::Relaxed);
        }
    }

    pub(super) fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Native's first module load initializes the core source, but that cursor
    /// still owns its old module map. Later lookups use the replacement maps.
    pub(super) fn activate(&self, module: bool) -> bool {
        self.active.swap(true, Ordering::Relaxed) || !module
    }

    pub(super) fn contains(&self, address: u64) -> bool {
        self.ranges
            .iter()
            .any(|&(start, end)| start <= address && address < end)
    }

    pub(super) fn resolve(&self, address: u64) -> Option<String> {
        let (start, symbol) = self.symbols.range(..=address).next_back()?;
        let end = symbol.end?;
        (address < end || (address == end && *start == end))
            .then(|| format!("{}+0x{:x}", symbol.name, address - start))
    }
}

pub(crate) fn module_short_name(path: &str) -> Option<Cow<'_, str>> {
    // perf machine.c:machine__process_kernel_mmap_event creates module DSOs
    // for absolute kernel paths. dso.c:__kmod_path__parse keeps bracketed
    // names, recognizes .ko with gzip/xz suffixes, and maps '-' to '_'.
    if !is_kernel_module_symbol_path_str(path) && !path.starts_with('/') {
        return None;
    }
    Some(module_dso_short_name(path))
}

pub(crate) fn module_dso_short_name(path: &str) -> Cow<'_, str> {
    // dso.c:__kmod_path__parse also accepts relative header filenames.
    // MMAP eligibility is checked separately by module_short_name.
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.starts_with('[') {
        return Cow::Borrowed(name);
    }
    let Some(mut extension) = name.rfind('.') else {
        return Cow::Borrowed(name);
    };
    if matches!(name.get(extension + 1..), Some("gz" | "xz")) {
        extension = extension.saturating_sub(3);
    }
    let short = if extension > 0 && name.as_bytes()[extension..].starts_with(b".ko") {
        format!("[{}]", &name[..extension])
    } else {
        name.to_owned()
    };
    Cow::Owned(short.replace('-', "_"))
}

/// Read only ELF/program headers: /proc/kcore can describe terabytes. Supported
/// perf recording architectures here are 64-bit little-endian x86 and ARM.
fn read_load_ranges(
    reader: &mut (impl Read + Seek),
    executable: bool,
    arch: PerfArch,
) -> Option<Vec<(u64, u64)>> {
    let mut header = [0_u8; 64];
    reader.read_exact(&mut header).ok()?;
    if header[..7] != *b"\x7fELF\x02\x01\x01" {
        return None;
    }
    let u16_at = |bytes: &[u8], offset| {
        Some(u16::from_le_bytes(
            bytes.get(offset..offset + 2)?.try_into().ok()?,
        ))
    };
    let u32_at = |bytes: &[u8], offset| {
        Some(u32::from_le_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    let u64_at = |bytes: &[u8], offset| {
        Some(u64::from_le_bytes(
            bytes.get(offset..offset + 8)?.try_into().ok()?,
        ))
    };
    let machine = match arch {
        PerfArch::X86_64 => 62,
        PerfArch::Aarch64 => 183,
    };
    if u16_at(&header, 16)? != 4 || u16_at(&header, 18)? != machine || u16_at(&header, 54)? != 56 {
        return None;
    }
    let offset = u64_at(&header, 32)?;
    let count = u16_at(&header, 56)?;
    // PN_XNUM needs a section-table lookup, which this bounded reader does not
    // support. Reject rather than interpreting it as an ordinary count.
    if count == u16::MAX {
        return None;
    }
    let mut ranges = Vec::new();
    for index in 0..count {
        reader
            .seek(SeekFrom::Start(offset.checked_add(u64::from(index) * 56)?))
            .ok()?;
        let mut program = [0_u8; 56];
        reader.read_exact(&mut program).ok()?;
        let required = if executable { 1 } else { 4 };
        if u32_at(&program, 0)? != 1 || u32_at(&program, 4)? & required == 0 {
            continue;
        }
        // perf util/symbol-elf.c:elf_read_maps takes min(memsz, filesz).
        let size = u64_at(&program, 32)?.min(u64_at(&program, 40)?);
        if size == 0 {
            continue;
        }
        let start = u64_at(&program, 16)?;
        ranges.push((start, start.checked_add(size)?));
    }
    Some(ranges)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek, SeekFrom};

    use super::read_load_ranges;
    use crate::perfdata::unwind::PerfArch;

    struct HeaderOnlyReader {
        bytes: Cursor<Vec<u8>>,
        bytes_read: usize,
    }

    impl Read for HeaderOnlyReader {
        fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
            let read = self.bytes.read(destination)?;
            self.bytes_read += read;
            Ok(read)
        }
    }
    impl Seek for HeaderOnlyReader {
        fn seek(&mut self, offset: SeekFrom) -> std::io::Result<u64> {
            self.bytes.seek(offset)
        }
    }

    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; 120];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&4_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&4_u32.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x8000_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&(1_u64 << 40).to_le_bytes());
        bytes[104..112].copy_from_slice(&(1_u64 << 41).to_le_bytes());
        bytes
    }

    #[test]
    fn kcore_terabyte_segments_read_headers_only_and_honor_permissions_and_architecture() {
        let mut reader = HeaderOnlyReader {
            bytes: Cursor::new(fixture()),
            bytes_read: 0,
        };
        assert_eq!(
            read_load_ranges(&mut reader, false, PerfArch::X86_64),
            Some(vec![(0x8000, 0x100_0000_8000)])
        );
        assert_eq!(reader.bytes_read, 120);
        assert_eq!(
            read_load_ranges(&mut Cursor::new(fixture()), true, PerfArch::X86_64),
            Some(Vec::new())
        );
        assert!(read_load_ranges(&mut Cursor::new(fixture()), false, PerfArch::Aarch64).is_none());
        let mut overflow = fixture();
        overflow[80..88].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(read_load_ranges(&mut Cursor::new(overflow), false, PerfArch::X86_64).is_none());
        let mut truncated = fixture();
        truncated.truncate(119);
        assert!(read_load_ranges(&mut Cursor::new(truncated), false, PerfArch::X86_64).is_none());
    }
}
