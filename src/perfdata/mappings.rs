use crate::perfdata::records::{Mmap2BuildIdRecord, Mmap2Record, MmapRecord};
use crate::symbols::KernelRelocation;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const PROT_EXEC: u32 = 4;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MmapTable {
    mappings: Vec<Mapping>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMapping {
    pub path: String,
    pub relative_address: u64,
    pub build_id: Option<Vec<u8>>,
    pub file_identity: Option<FileIdentity>,
    pub kernel_relocation: Option<KernelRelocation>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileIdentity {
    pub major: u32,
    pub minor: u32,
    pub inode: u64,
    pub inode_generation: u64,
}

#[must_use]
#[cfg(unix)]
pub fn file_matches_recorded_identity(path: &Path, identity: FileIdentity) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.ino() == identity.inode)
}

#[cfg(not(unix))]
pub fn file_matches_recorded_identity(_path: &Path, _identity: FileIdentity) -> bool {
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserMapping<'a> {
    pub pid: u32,
    pub start: u64,
    pub len: u64,
    pub pgoff: u64,
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
    path: String,
    build_id: Option<Vec<u8>>,
    file_identity: Option<FileIdentity>,
    prot: Option<u32>,
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
            file_identity: None,
            prot: None,
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
            file_identity: Some(FileIdentity {
                major: record.major,
                minor: record.minor,
                inode: record.inode,
                inode_generation: record.inode_generation,
            }),
            prot: Some(record.prot),
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
            file_identity: None,
            prot: Some(record.prot),
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
                file_identity: mapping.file_identity,
                kernel_relocation: mapping.kernel_relocation(),
            })
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
                path: &mapping.path,
                build_id: mapping.build_id.as_deref(),
                file_identity: mapping.file_identity,
            })
    }

    #[must_use]
    pub fn has_mappings_for_pid(&self, pid: u32) -> bool {
        self.mappings
            .iter()
            .any(|mapping| mapping.pid == pid || mapping.pid == u32::MAX)
    }

    #[must_use]
    pub fn has_executable_mappings_for_pid(&self, pid: u32) -> bool {
        self.mappings
            .iter()
            .any(|mapping| (mapping.pid == pid || mapping.pid == u32::MAX) && mapping.may_execute())
    }

    #[must_use]
    pub fn is_known_non_executable(&self, pid: u32, ip: u64) -> bool {
        self.mappings
            .iter()
            .filter(|mapping| mapping.contains(pid, ip))
            .max_by_key(|mapping| mapping.start)
            .is_some_and(Mapping::is_known_non_executable)
    }
}

impl Mapping {
    fn contains(&self, pid: u32, ip: u64) -> bool {
        (self.pid == pid || self.pid == u32::MAX)
            && ip >= self.start
            && ip < self.start.saturating_add(self.len)
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

    fn is_known_non_executable(&self) -> bool {
        self.prot.is_some_and(|prot| prot & PROT_EXEC == 0) || is_perf_data_path(&self.path)
    }

    fn may_execute(&self) -> bool {
        !self.is_known_non_executable()
    }

    fn is_kernel_symbol_mapping(&self) -> bool {
        self.pid == u32::MAX && self.path.starts_with('[')
    }
}

fn is_perf_data_path(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|file_name| file_name == "perf.data" || file_name.starts_with("perf.data."))
}
