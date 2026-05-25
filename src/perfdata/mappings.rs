use crate::perfdata::records::{Mmap2BuildIdRecord, Mmap2Record, MmapRecord};
use crate::symbols::KernelRelocation;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MmapTable {
    mappings: Vec<Mapping>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMapping {
    pub path: String,
    pub relative_address: u64,
    pub build_id: Option<Vec<u8>>,
    pub kernel_relocation: Option<KernelRelocation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Mapping {
    pid: u32,
    start: u64,
    len: u64,
    pgoff: u64,
    path: String,
    build_id: Option<Vec<u8>>,
}

impl MmapTable {
    pub fn insert_mmap(&mut self, record: MmapRecord) {
        self.mappings.push(Mapping {
            pid: record.pid,
            start: record.start,
            len: record.len,
            pgoff: record.pgoff,
            path: record.path,
            build_id: None,
        });
    }

    pub fn insert_mmap2(&mut self, record: Mmap2Record) {
        self.mappings.push(Mapping {
            pid: record.pid,
            start: record.start,
            len: record.len,
            pgoff: record.pgoff,
            path: record.path,
            build_id: None,
        });
    }

    pub fn insert_mmap2_build_id(&mut self, record: Mmap2BuildIdRecord) {
        self.mappings.push(Mapping {
            pid: record.pid,
            start: record.start,
            len: record.len,
            pgoff: record.pgoff,
            path: record.path,
            build_id: Some(record.build_id),
        });
    }

    #[must_use]
    pub fn resolve(&self, pid: u32, ip: u64) -> Option<ResolvedMapping> {
        self.mappings
            .iter()
            .filter(|mapping| mapping.contains(pid, ip))
            .max_by_key(|mapping| mapping.start)
            .map(|mapping| ResolvedMapping {
                path: mapping.path.clone(),
                relative_address: mapping.relative_address(ip),
                build_id: mapping.build_id.clone(),
                kernel_relocation: mapping.kernel_relocation(),
            })
    }
}

impl Mapping {
    fn contains(&self, pid: u32, ip: u64) -> bool {
        (self.pid == pid || self.pid == u32::MAX)
            && ip >= self.start
            && ip < self.start.saturating_add(self.len)
    }

    fn relative_address(&self, ip: u64) -> u64 {
        if self.path.starts_with("[kernel") || self.path == "[guest.kernel]" {
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
}
