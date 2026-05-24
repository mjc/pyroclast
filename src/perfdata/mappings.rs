use crate::perfdata::records::{Mmap2Record, MmapRecord};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MmapTable {
    mappings: Vec<Mapping>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMapping {
    pub path: String,
    pub relative_address: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Mapping {
    pid: u32,
    start: u64,
    len: u64,
    pgoff: u64,
    path: String,
}

impl MmapTable {
    pub fn insert_mmap(&mut self, record: MmapRecord) {
        self.mappings.push(Mapping {
            pid: record.pid,
            start: record.start,
            len: record.len,
            pgoff: record.pgoff,
            path: record.path,
        });
    }

    pub fn insert_mmap2(&mut self, record: Mmap2Record) {
        self.mappings.push(Mapping {
            pid: record.pid,
            start: record.start,
            len: record.len,
            pgoff: record.pgoff,
            path: record.path,
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
                relative_address: ip - mapping.start + mapping.pgoff,
            })
    }
}

impl Mapping {
    fn contains(&self, pid: u32, ip: u64) -> bool {
        self.pid == pid && ip >= self.start && ip < self.start.saturating_add(self.len)
    }
}
