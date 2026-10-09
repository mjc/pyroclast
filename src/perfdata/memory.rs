use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
#[cfg(not(unix))]
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;

use super::mappings::{DsoMemoryMapping, MappingResolveCache, MmapTable};
use crate::symbols::{build_id_hex, perf_build_id_elf_path_for_dso};

// tools/perf/util/dso.h:187 and dso.c:dso_cache__populate cache DSO data
// independently of the modules retained by libdwfl for CFI lookup.
const BLOCK_SIZE: usize = 4096;

#[derive(Default)]
pub(super) struct DsoMemorySources {
    sources: HashMap<usize, Option<DsoMemory>, FxBuildHasher>,
    open_order: VecDeque<usize>,
    fd_limit: Option<usize>,
}

struct DsoMemory {
    file: Option<File>,
    path: PathBuf,
    len: u64,
    failed: bool,
    blocks: HashMap<u64, Box<[u8]>, FxBuildHasher>,
}

pub(super) struct MappedMemory<'a> {
    pub(super) table: &'a MmapTable,
    pub(super) debug_dir: Option<&'a Path>,
    pid: u32,
    sources: &'a mut DsoMemorySources,
    mapping_cache: MappingResolveCache,
}

impl<'a> MappedMemory<'a> {
    pub(super) fn new(
        pid: u32,
        table: &'a MmapTable,
        sources: &'a mut DsoMemorySources,
        debug_dir: Option<&'a Path>,
    ) -> Self {
        Self {
            table,
            debug_dir,
            pid,
            sources,
            mapping_cache: MappingResolveCache::default(),
        }
    }

    pub(super) fn read_u64(&mut self, address: u64) -> Option<u64> {
        address.checked_add(8)?;
        // unwind-libdw.c:access_dso_mem resolves the current user map, not
        // the historical module supplying the frame's CFI.
        let mapping =
            self.table
                .resolve_user_memory_cached(self.pid, address, &mut self.mapping_cache)?;
        self.sources.read_u64(&mapping, self.debug_dir)
    }
}

impl DsoMemorySources {
    fn read_u64(
        &mut self,
        mapping: &DsoMemoryMapping<'_>,
        debug_dir: Option<&Path>,
    ) -> Option<u64> {
        let id = mapping.source_id;
        if !self.sources.contains_key(&id) {
            let source =
                DsoMemory::open_with(mapping, debug_dir, |path| self.open_with_eviction(path)).ok();
            if source.is_some() {
                self.register_open(id);
            }
            self.sources.insert(id, source);
        }
        let source = self.sources.get(&id)?.as_ref()?;
        if source.failed {
            return None;
        }
        if source.file.is_none() {
            // dso.c:try_to_open_dso retains the selected binary type. Do not
            // rerun cache/live selection when an evicted descriptor reopens.
            let path = source.path.clone();
            let reopened = self.open_with_eviction(&path).and_then(|file| {
                let len = file.metadata()?.len();
                Ok((file, len))
            });
            if let Ok((file, len)) = reopened {
                self.register_open(id);
                let source = self.sources.get_mut(&id)?.as_mut()?;
                source.file = Some(file);
                source.len = len;
            } else {
                // Native DSO_DATA_STATUS_ERROR is sticky only after
                // do_open has exhausted its owned-FD eviction retries.
                self.sources.get_mut(&id)?.as_mut()?.failed = true;
                return None;
            }
        }
        // dso.c:dso__data_read_addr uses map__map_ip. A short read from the
        // selected source must not fall through to another or older object.
        self.sources
            .get_mut(&id)?
            .as_mut()?
            .read_u64(mapping.relative_address)
    }

    fn open_with_eviction(&mut self, path: &Path) -> std::io::Result<File> {
        loop {
            match open_regular_object(path) {
                #[cfg(unix)]
                Err(error) if error.raw_os_error() == Some(libc::EMFILE) && self.close_oldest() => {
                }
                result => return result,
            }
        }
    }

    fn register_open(&mut self, id: usize) {
        self.open_order.push_back(id);
        let limit = *self.fd_limit.get_or_insert_with(native_fd_limit);
        // Native checks the half-limit before assigning the new descriptor.
        // Reads do not promote entries: list_add_tail runs on open only.
        if self.open_order.len() >= limit {
            self.close_oldest();
        }
    }

    fn close_oldest(&mut self) -> bool {
        let Some(&id) = self.open_order.front() else {
            return false;
        };
        // dso.c:close_data_fd leaves the opening DSO queued when fd == -1.
        let Some(Some(source)) = self.sources.get_mut(&id) else {
            return false;
        };
        if source.file.is_none() {
            return false;
        }
        source.file = None;
        source.len = 0;
        self.open_order.pop_front();
        true
    }
}

fn native_fd_limit() -> usize {
    #[cfg(unix)]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes one initialized, aligned rlimit value.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } != 0 {
            return 1;
        }
        if limit.rlim_cur != libc::RLIM_INFINITY {
            return usize::try_from(limit.rlim_cur / 2).unwrap_or(usize::MAX);
        }
    }
    usize::MAX
}

impl DsoMemory {
    #[cfg(test)]
    fn open(mapping: &DsoMemoryMapping<'_>, debug_dir: Option<&Path>) -> Option<Self> {
        Self::open_with(mapping, debug_dir, open_regular_object).ok()
    }

    fn open_with(
        mapping: &DsoMemoryMapping<'_>,
        debug_dir: Option<&Path>,
        mut open: impl FnMut(&Path) -> std::io::Result<File>,
    ) -> std::io::Result<Self> {
        // dso.c:try_to_open_dso tries BUILD_ID_CACHE before SYSTEM_PATH_DSO.
        let cached = debug_dir.zip(mapping.build_id).and_then(|(dir, id)| {
            id.iter().any(|byte| *byte != 0).then(|| {
                perf_build_id_elf_path_for_dso(dir, Path::new(mapping.path), &build_id_hex(id))
            })
        });
        if let Some(path) = cached
            && let Ok(file) = open(&path)
        {
            return Self::from_file(file, path);
        }
        let path = PathBuf::from(mapping.path);
        let file = open(&path)?;
        Self::from_file(file, path)
    }

    fn from_file(file: File, path: PathBuf) -> std::io::Result<Self> {
        Ok(Self {
            len: file.metadata()?.len(),
            file: Some(file),
            path,
            failed: false,
            blocks: HashMap::with_hasher(FxBuildHasher),
        })
    }

    fn read_u64(&mut self, offset: u64) -> Option<u64> {
        offset.checked_add(8)?;
        if self.failed || offset > self.len {
            return None;
        }
        let mut bytes = [0; 8];
        let mut written = 0;
        while written < bytes.len() {
            let position = offset.checked_add(u64::try_from(written).ok()?)?;
            let block_start = position & !(u64::try_from(BLOCK_SIZE).ok()? - 1);
            if !self.blocks.contains_key(&block_start) {
                let len =
                    usize::try_from(self.len.checked_sub(block_start)?.min(BLOCK_SIZE as u64))
                        .ok()?;
                let mut block = vec![0; len];
                let read = read_file_at(self.file.as_ref()?, block_start, &mut block).ok()?;
                if read == 0 {
                    return None;
                }
                block.truncate(read);
                self.blocks.insert(block_start, block.into_boxed_slice());
            }
            let block = self.blocks.get(&block_start)?;
            let within = usize::try_from(position - block_start).ok()?;
            let available = block.get(within..)?;
            let count = available.len().min(bytes.len() - written);
            if count == 0 {
                return None;
            }
            bytes[written..written + count].copy_from_slice(&available[..count]);
            written += count;
        }
        Some(u64::from_le_bytes(bytes))
    }
}

pub(super) fn open_regular_object(path: &Path) -> std::io::Result<File> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(std::io::Error::other("object is not a regular file"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("object is not a regular file"));
    }
    Ok(file)
}

fn read_file_at(file: &File, offset: u64, bytes: &mut [u8]) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_at(bytes, offset)
    }
    #[cfg(not(unix))]
    {
        let mut file = file;
        file.seek(SeekFrom::Start(offset))?;
        file.read(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perfdata::records::{
        Mmap2BuildIdRecord, Mmap2Record, MmapRecord, PERF_RECORD_MISC_CPUMODE_USER,
    };

    #[cfg(target_os = "linux")]
    fn isolated_fd_pressure(name: &str, test: fn(&Path)) {
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};

        const CASE: &str = "PYROCLAST_DSO_FD_CHILD";
        const ROOT: &str = "PYROCLAST_DSO_FD_ROOT";
        const SUCCESS: &str = "dso-fd-pressure-ok";
        struct OwnedChild(Option<Child>);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        if let Some(selected) = std::env::var_os(CASE) {
            assert_eq!(
                selected, name,
                "child must execute exactly one selected test"
            );
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: valid rlimit pointers; limits change only in this child.
            unsafe {
                assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &raw const limit), 0);
                assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit), 0);
                assert!(limit.rlim_max >= 64);
                limit.rlim_cur = 64;
                assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit), 0);
            }
            let root = std::path::PathBuf::from(std::env::var_os(ROOT).unwrap());
            test(&root);
            println!("\n{SUCCESS}:{name}");
            return;
        }

        let root = tempfile::tempdir().unwrap();
        for index in 0..96 {
            let mut bytes = vec![0x11; BLOCK_SIZE * 2];
            bytes[BLOCK_SIZE..].fill(0x22);
            std::fs::write(root.path().join(format!("data-{index}")), bytes).unwrap();
        }
        let log_path = root.path().join("child.log");
        let log = File::create(&log_path).unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut child = OwnedChild(Some(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture", "--test-threads=1"])
                .env(CASE, name)
                .env(ROOT, root.path())
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        ));
        let status = loop {
            if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
                child.0.take();
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "child exceeded 15-second deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let output = std::fs::read_to_string(log_path).unwrap();
        assert!(status.success(), "child exited with {status}:\n{output}");
        assert!(
            output
                .lines()
                .any(|line| line == format!("{SUCCESS}:{name}")),
            "{output}"
        );
    }

    #[cfg(target_os = "linux")]
    fn fd_pressure_table(root: &Path) -> MmapTable {
        let mut table = MmapTable::default();
        for index in 0..96 {
            let mut record = mapped_file(&root.join(format!("data-{index}")), 7);
            record.start = 0x1_0000 + index * 0x2000;
            record.len = 0x2000;
            record.pgoff = 0;
            table.insert_mmap(record);
        }
        table
    }

    #[cfg(target_os = "linux")]
    fn low_fd_limit_reads(root: &Path, soft: libc::rlim_t) {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        struct RestoreDescriptors {
            limit: libc::rlimit,
            stdin: OwnedFd,
            stdout: OwnedFd,
        }
        impl Drop for RestoreDescriptors {
            fn drop(&mut self) {
                // SAFETY: the saved descriptors and original limit stay valid.
                unsafe {
                    libc::setrlimit(libc::RLIMIT_NOFILE, &raw const self.limit);
                    libc::dup2(self.stdin.as_raw_fd(), 0);
                    libc::dup2(self.stdout.as_raw_fd(), 1);
                }
            }
        }

        let path = root.join("data-0");
        std::fs::write(root.join("data-1"), vec![0x33; BLOCK_SIZE * 2]).unwrap();
        let table = fd_pressure_table(root);
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes a valid rlimit; dup returns owned descriptors.
        let restore = unsafe {
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit), 0);
            let stdin = libc::dup(0);
            assert!(stdin >= 0);
            let stdin = OwnedFd::from_raw_fd(stdin);
            let stdout = libc::dup(1);
            assert!(stdout >= 0);
            RestoreDescriptors {
                limit,
                stdin,
                stdout: OwnedFd::from_raw_fd(stdout),
            }
        };
        limit.rlim_cur = soft;
        // SAFETY: these changes affect only the isolated child. FD 2 retains
        // the log, and the saved descriptors remain valid above the new limit.
        unsafe {
            assert_eq!(libc::close(0), 0);
            assert_eq!(libc::close(1), 0);
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit), 0);
        }
        let control = open_regular_object(&path).expect("opening must succeed at the low limit");
        let mut word = [0; 8];
        assert_eq!(read_file_at(&control, 0, &mut word).unwrap(), 8);
        assert_eq!(u64::from_le_bytes(word), 0x1111_1111_1111_1111);
        drop(control);

        let mut sources = DsoMemorySources::default();
        for (address, expected) in [
            (0x1_0000, 0x1111_1111_1111_1111),
            (0x1_2000, 0x3333_3333_3333_3333),
            (0x1_1000, 0x2222_2222_2222_2222),
            (0x1_0000, 0x1111_1111_1111_1111),
        ] {
            assert_eq!(
                MappedMemory::new(7, &table, &mut sources, None).read_u64(address),
                Some(expected),
                "native retains the just-opened descriptor at soft limit {soft}"
            );
        }
        drop(sources);
        drop(restore);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fd_pressure_soft_limit_one_preserves_native_open_assignment_timing() {
        isolated_fd_pressure(
            "perfdata::memory::tests::fd_pressure_soft_limit_one_preserves_native_open_assignment_timing",
            |root| low_fd_limit_reads(root, 1),
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fd_pressure_soft_limit_two_preserves_native_open_assignment_timing() {
        isolated_fd_pressure(
            "perfdata::memory::tests::fd_pressure_soft_limit_two_preserves_native_open_assignment_timing",
            |root| low_fd_limit_reads(root, 2),
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fd_pressure_soft_limit_three_preserves_native_open_assignment_timing() {
        isolated_fd_pressure(
            "perfdata::memory::tests::fd_pressure_soft_limit_three_preserves_native_open_assignment_timing",
            |root| low_fd_limit_reads(root, 3),
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fd_pressure_evicts_descriptors_without_discarding_dso_blocks() {
        isolated_fd_pressure(
            "perfdata::memory::tests::fd_pressure_evicts_descriptors_without_discarding_dso_blocks",
            |root| {
                let mut table = fd_pressure_table(root);
                let mut sources = DsoMemorySources::default();
                let baseline = std::fs::read_dir("/proc/self/fd").unwrap().count() - 1;
                for index in 0..96 {
                    assert_eq!(
                        MappedMemory::new(7, &table, &mut sources, None)
                            .read_u64(0x1_0000 + index * 0x2000),
                        Some(0x1111_1111_1111_1111),
                        "DSO {index} must remain readable beyond the descriptor limit"
                    );
                }
                let open = std::fs::read_dir("/proc/self/fd").unwrap().count() - 1;
                assert!(
                    open < baseline + 32,
                    "native reserves half RLIMIT_NOFILE: {open}, baseline {baseline}"
                );
                let mut changed = vec![0x33; BLOCK_SIZE * 2];
                changed[BLOCK_SIZE..].fill(0x44);
                std::fs::write(root.join("data-0"), changed).unwrap();
                table.clone_pid_mappings(7, 8);
                assert_eq!(
                    MappedMemory::new(8, &table, &mut sources, None).read_u64(0x1_0000),
                    Some(0x1111_1111_1111_1111),
                    "cached blocks remain owned by the shared DSO after eviction and fork"
                );
                assert_eq!(
                    MappedMemory::new(8, &table, &mut sources, None).read_u64(0x1_1000),
                    Some(0x4444_4444_4444_4444),
                    "an uncached block reopens the selected DSO"
                );
            },
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fd_pressure_emfile_evicts_and_retries_without_poisoning_the_source() {
        isolated_fd_pressure(
            "perfdata::memory::tests::fd_pressure_emfile_evicts_and_retries_without_poisoning_the_source",
            |root| {
                let table = fd_pressure_table(root);
                let mut sources = DsoMemorySources::default();
                for address in [0x1_0000, 0x1_2000] {
                    assert_eq!(
                        MappedMemory::new(7, &table, &mut sources, None).read_u64(address),
                        Some(0x1111_1111_1111_1111)
                    );
                }
                let mut external = Vec::new();
                let mut exhausted = false;
                for _ in 0..64 {
                    match File::open(root.join("data-95")) {
                        Ok(file) => external.push(file),
                        Err(error) => {
                            assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                            exhausted = true;
                            break;
                        }
                    }
                }
                assert!(exhausted, "fixture must reach actual EMFILE");
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1_4000),
                    Some(0x1111_1111_1111_1111),
                    "native evicts an owned data FD and retries the same open"
                );
                drop(external);
                std::fs::write(root.join("data-0"), vec![0x33; BLOCK_SIZE * 2]).unwrap();
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1_0000),
                    Some(0x1111_1111_1111_1111)
                );
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1_1000),
                    Some(0x3333_3333_3333_3333)
                );
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1_4000),
                    Some(0x1111_1111_1111_1111)
                );
            },
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fd_pressure_cached_reads_do_not_promote_oldest_open_descriptor() {
        isolated_fd_pressure(
            "perfdata::memory::tests::fd_pressure_cached_reads_do_not_promote_oldest_open_descriptor",
            |root| {
                let table = fd_pressure_table(root);
                let mut sources = DsoMemorySources::default();
                for index in 0..31 {
                    assert_eq!(
                        MappedMemory::new(7, &table, &mut sources, None)
                            .read_u64(0x1_0000 + index * 0x2000),
                        Some(0x1111_1111_1111_1111)
                    );
                }
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1_0000),
                    Some(0x1111_1111_1111_1111)
                );
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, None).read_u64(0x4_e000),
                    Some(0x1111_1111_1111_1111)
                );
                std::fs::rename(root.join("data-0"), root.join("old-data-0")).unwrap();
                std::fs::write(root.join("data-0"), vec![0x33; BLOCK_SIZE * 2]).unwrap();
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1_1000),
                    Some(0x3333_3333_3333_3333),
                    "oldest-open eviction reopens the new inode despite a recent cached read"
                );
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1_0000),
                    Some(0x1111_1111_1111_1111)
                );
            },
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fd_pressure_selected_cache_path_and_reopen_failures_remain_sticky() {
        isolated_fd_pressure(
            "perfdata::memory::tests::fd_pressure_selected_cache_path_and_reopen_failures_remain_sticky",
            |root| {
                let path = root.join("data-0");
                let debug = root.join("debug");
                let id = [0x22; 20];
                let cache = perf_build_id_elf_path_for_dso(&debug, &path, &build_id_hex(&id));
                std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
                std::fs::write(&cache, vec![0x22; BLOCK_SIZE * 2]).unwrap();
                let mut table = fd_pressure_table(root);
                let mut record = mapped_file_with_build_id(&path, 7, 0x22);
                record.start = 0x1_0000;
                record.len = 0x2000;
                record.pgoff = 0;
                table.insert_mmap2_build_id(record);
                let mut sources = DsoMemorySources::default();
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, Some(&debug)).read_u64(0x1_0000),
                    Some(0x2222_2222_2222_2222)
                );
                for index in 1..96 {
                    assert_eq!(
                        MappedMemory::new(7, &table, &mut sources, Some(&debug))
                            .read_u64(0x1_0000 + index * 0x2000),
                        Some(0x1111_1111_1111_1111)
                    );
                }
                std::fs::write(&cache, vec![0x44; BLOCK_SIZE * 2]).unwrap();
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, Some(&debug)).read_u64(0x1_1000),
                    Some(0x4444_4444_4444_4444)
                );
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, Some(&debug)).read_u64(0x1_0000),
                    Some(0x2222_2222_2222_2222)
                );
                for index in 1..96 {
                    assert_eq!(
                        MappedMemory::new(7, &table, &mut sources, Some(&debug))
                            .read_u64(0x1_0000 + index * 0x2000),
                        Some(0x1111_1111_1111_1111)
                    );
                }
                std::fs::remove_file(&cache).unwrap();
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, Some(&debug)).read_u64(0x1_1000),
                    None,
                    "an evicted selected cache must not fall through to the live DSO"
                );
                std::fs::write(&cache, vec![0x55; BLOCK_SIZE * 2]).unwrap();
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, Some(&debug)).read_u64(0x1_0000),
                    None,
                    "a final reopen failure remains sticky even for cached blocks"
                );
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, Some(&debug)).read_u64(0x1_2000),
                    Some(0x1111_1111_1111_1111)
                );
            },
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fd_pressure_without_owned_descriptors_caches_the_final_failure() {
        isolated_fd_pressure(
            "perfdata::memory::tests::fd_pressure_without_owned_descriptors_caches_the_final_failure",
            |root| {
                let table = fd_pressure_table(root);
                let mut sources = DsoMemorySources::default();
                let mut external = Vec::new();
                let mut exhausted = false;
                for _ in 0..64 {
                    match File::open(root.join("data-95")) {
                        Ok(file) => external.push(file),
                        Err(error) => {
                            assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                            exhausted = true;
                            break;
                        }
                    }
                }
                assert!(exhausted);
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1_0000),
                    None
                );
                drop(external);
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1_0000),
                    None,
                    "native DSO_DATA_STATUS_ERROR does not retry after final open failure"
                );
                assert_eq!(
                    MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1_2000),
                    Some(0x1111_1111_1111_1111)
                );
            },
        );
    }

    fn mapping(path: &Path, offset: u64) -> DsoMemoryMapping<'_> {
        DsoMemoryMapping {
            source_id: 0,
            path: path.to_str().unwrap(),
            relative_address: offset,
            build_id: None,
        }
    }

    fn mapped_file(path: &Path, pid: u32) -> MmapRecord {
        MmapRecord {
            pid,
            tid: pid,
            start: 0x1000,
            len: 4,
            pgoff: 8,
            path: path.to_str().unwrap().to_string(),
        }
    }

    fn mapped_file_with_identity(path: &Path, pid: u32) -> Mmap2Record {
        Mmap2Record {
            pid,
            tid: pid,
            start: 0x1000,
            len: 4,
            pgoff: 8,
            path: path.to_str().unwrap().to_string(),
            major: 1,
            minor: 2,
            inode: 3,
            inode_generation: 4,
            prot: 5,
            flags: 2,
        }
    }

    fn mapped_file_with_build_id(path: &Path, pid: u32, byte: u8) -> Mmap2BuildIdRecord {
        Mmap2BuildIdRecord {
            pid,
            tid: pid,
            start: 0x1000,
            len: 4,
            pgoff: 8,
            path: path.to_str().unwrap().to_string(),
            build_id_size: 20,
            build_id: vec![byte; 20],
            prot: 5,
            flags: 2,
        }
    }

    #[test]
    fn mixed_mmap_identity_retains_cached_words_across_fork() {
        for known_first in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("object");
            std::fs::write(&path, [0x11; 16]).unwrap();
            let mut table = MmapTable::default();
            if known_first {
                table.insert_mmap2(mapped_file_with_identity(&path, 7));
            } else {
                table.insert_mmap(mapped_file(&path, 7));
            }
            let original_id = table
                .resolve_user_pid_ref_cached(7, 0x1000, &mut MappingResolveCache::default())
                .unwrap()
                .symbol_source_id;
            let mut sources = DsoMemorySources::default();
            assert_eq!(
                MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1000),
                Some(0x1111_1111_1111_1111)
            );
            table.clone_pid_mappings(7, 8);
            std::fs::write(&path, [0x33; 16]).unwrap();
            if known_first {
                table.insert_mmap(mapped_file(&path, 8));
            } else {
                table.insert_mmap2(mapped_file_with_identity(&path, 8));
            }
            let child_id = table
                .resolve_user_pid_ref_cached(8, 0x1000, &mut MappingResolveCache::default())
                .unwrap()
                .symbol_source_id;
            assert_ne!(original_id, child_id, "symbol keys must stay distinct");
            assert_eq!(
                MappedMemory::new(8, &table, &mut sources, None).read_u64(0x1000),
                Some(0x1111_1111_1111_1111),
                "native DSO identity survives mixed mmap forms: known_first={known_first}"
            );
        }
    }

    #[test]
    fn memory_identity_enrichment_retains_cache_but_separates_known_build_ids() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("object");
        let mut table = MmapTable::default();
        table.insert_mmap(mapped_file(&path, 7));
        let mut sources = DsoMemorySources::default();
        std::fs::write(&path, [0x11; 16]).unwrap();
        assert_eq!(
            MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1000),
            Some(0x1111_1111_1111_1111)
        );
        std::fs::write(&path, [0x22; 16]).unwrap();
        table.insert_mmap2_build_id(mapped_file_with_build_id(&path, 8, 0x22));
        assert_eq!(
            MappedMemory::new(8, &table, &mut sources, None).read_u64(0x1000),
            Some(0x1111_1111_1111_1111)
        );
        table.insert_mmap2_build_id(mapped_file_with_build_id(&path, 9, 0x33));
        assert_eq!(
            MappedMemory::new(9, &table, &mut sources, None).read_u64(0x1000),
            Some(0x2222_2222_2222_2222)
        );
        assert_eq!(
            MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1000),
            Some(0x1111_1111_1111_1111)
        );
    }

    #[test]
    fn wildcard_memory_identity_uses_native_ordered_lookup_not_a_permanent_alias() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("object");
        let known = |pid, inode| {
            let mut record = mapped_file_with_identity(&path, pid);
            record.inode = inode;
            record
        };
        let mut table = MmapTable::default();
        table.insert_mmap2(known(7, 2));
        table.insert_mmap2(known(8, 1));
        // Bind before any memory read. Native searches [inode 2, inode 1]
        // and returns the first equal midpoint, index 1.
        table.insert_mmap(mapped_file(&path, 9));
        let mut sources = DsoMemorySources::default();
        std::fs::write(&path, [0x22; 16]).unwrap();
        assert_eq!(
            MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1000),
            Some(0x2222_2222_2222_2222)
        );
        std::fs::write(&path, [0x11; 16]).unwrap();
        assert_eq!(
            MappedMemory::new(8, &table, &mut sources, None).read_u64(0x1000),
            Some(0x1111_1111_1111_1111)
        );
        std::fs::write(&path, [0x44; 16]).unwrap();
        table.insert_mmap2(known(10, 3));
        assert_eq!(
            MappedMemory::new(10, &table, &mut sources, None).read_u64(0x1000),
            Some(0x4444_4444_4444_4444)
        );
        table.clone_pid_mappings(9, 11);
        for pid in [9, 11] {
            assert_eq!(
                MappedMemory::new(pid, &table, &mut sources, None).read_u64(0x1000),
                Some(0x1111_1111_1111_1111),
                "existing wildcard bindings must not change after insertion or fork"
            );
        }
        // A new wildcard map searches [3, 2, 1], now selecting inode 2.
        table.insert_mmap(mapped_file(&path, 12));
        assert_eq!(
            MappedMemory::new(12, &table, &mut sources, None).read_u64(0x1000),
            Some(0x2222_2222_2222_2222)
        );
    }

    #[test]
    fn unread_mapping_uses_enriched_dso_build_id_for_cache_priority() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("object");
        let debug = root.path().join("debug");
        let id = [0x22; 20];
        let cache = perf_build_id_elf_path_for_dso(&debug, &path, &build_id_hex(&id));
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
        std::fs::write(&path, [0x11; 16]).unwrap();
        std::fs::write(&cache, [0x22; 16]).unwrap();
        let mut table = MmapTable::default();
        table.insert_mmap(mapped_file(&path, 7));
        table.insert_mmap2_build_id(mapped_file_with_build_id(&path, 8, 0x22));
        let mut sources = DsoMemorySources::default();
        assert_eq!(
            MappedMemory::new(7, &table, &mut sources, Some(&debug)).read_u64(0x1000),
            Some(0x2222_2222_2222_2222)
        );
        assert_eq!(
            MappedMemory::new(8, &table, &mut sources, Some(&debug)).read_u64(0x1000),
            Some(0x2222_2222_2222_2222)
        );
    }

    #[test]
    fn header_build_id_does_not_turn_later_mmap_into_a_known_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("object");
        let debug = root.path().join("debug");
        let id = [0x22; 20];
        let cache = perf_build_id_elf_path_for_dso(&debug, &path, &build_id_hex(&id));
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
        std::fs::write(&path, [0x11; 16]).unwrap();
        std::fs::write(&cache, [0x22; 16]).unwrap();
        let mut table = MmapTable::default();
        table.insert_mmap_with_build_id_and_misc(
            mapped_file(&path, 7),
            Some(id.to_vec()),
            PERF_RECORD_MISC_CPUMODE_USER,
        );
        let mut sources = DsoMemorySources::default();
        assert_eq!(
            MappedMemory::new(7, &table, &mut sources, Some(&debug)).read_u64(0x1000),
            Some(0x2222_2222_2222_2222)
        );
        table.insert_mmap2_build_id(mapped_file_with_build_id(&path, 8, 0x33));
        assert_eq!(
            MappedMemory::new(8, &table, &mut sources, Some(&debug)).read_u64(0x1000),
            Some(0x1111_1111_1111_1111)
        );
        table.insert_mmap_with_build_id_and_misc(
            mapped_file(&path, 9),
            Some(id.to_vec()),
            PERF_RECORD_MISC_CPUMODE_USER,
        );
        // HEADER_BUILD_ID seeded id 22, but this MMAP still has no identity.
        // Native bsearch over [id 22, id 33] selects the second DSO.
        assert_eq!(
            MappedMemory::new(9, &table, &mut sources, Some(&debug)).read_u64(0x1000),
            Some(0x1111_1111_1111_1111)
        );
        assert_eq!(
            table.resolve_ref(9, 0x1000).unwrap().build_id,
            Some(id.as_slice()),
            "symbol metadata retains the header build ID"
        );
    }

    #[test]
    fn reads_words_across_native_dso_cache_block_boundaries() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("object");
        let mut bytes = vec![0; BLOCK_SIZE + 8];
        let word = 0x1234_5678_90ab_cdef_u64;
        bytes[BLOCK_SIZE - 4..BLOCK_SIZE + 4].copy_from_slice(&word.to_le_bytes());
        std::fs::write(&path, bytes).unwrap();
        let mut source = DsoMemory::open(&mapping(&path, 0), None).unwrap();
        assert_eq!(source.read_u64((BLOCK_SIZE - 4) as u64), Some(word));
        assert_eq!(source.blocks.len(), 2);
        assert_eq!(source.read_u64((BLOCK_SIZE + 1) as u64), None);
        assert_eq!(source.read_u64(u64::MAX - 3), None);
    }

    #[test]
    fn cached_blocks_survive_truncation_but_uncached_reads_fail_without_sigbus() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("object");
        std::fs::write(&path, vec![0x22; BLOCK_SIZE * 2]).unwrap();
        let mut source = DsoMemory::open(&mapping(&path, 0), None).unwrap();
        assert_eq!(source.read_u64(0), Some(0x2222_2222_2222_2222));
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(0)
            .unwrap();
        // dso.c:__dso_cache__find serves a populated block without reopening.
        assert_eq!(source.read_u64(8), Some(0x2222_2222_2222_2222));
        assert_eq!(source.read_u64(BLOCK_SIZE as u64), None);
    }

    #[test]
    fn build_id_cache_precedes_live_dso_and_short_reads_do_not_fall_through() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("object");
        let debug = root.path().join("debug");
        let id = [0x22; 20];
        let cache = perf_build_id_elf_path_for_dso(&debug, &path, &build_id_hex(&id));
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
        std::fs::write(&path, [0x11; 16]).unwrap();
        std::fs::write(&cache, [0x22; 8]).unwrap();
        let mut mapped = mapping(&path, 0);
        mapped.build_id = Some(&id);
        let mut sources = DsoMemorySources::default();
        assert_eq!(
            sources.read_u64(&mapped, Some(&debug)),
            Some(0x2222_2222_2222_2222)
        );
        mapped.relative_address = 8;
        assert_eq!(sources.read_u64(&mapped, Some(&debug)), None);
    }

    #[test]
    fn missing_cache_uses_live_file_and_retains_selected_descriptor() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("object");
        std::fs::write(&path, [0x11; BLOCK_SIZE * 2]).unwrap();
        let id = [0x22; 20];
        let mut mapped = mapping(&path, 0);
        mapped.build_id = Some(&id);
        let mut sources = DsoMemorySources::default();
        assert_eq!(
            sources.read_u64(&mapped, Some(root.path())),
            Some(0x1111_1111_1111_1111)
        );
        std::fs::rename(&path, root.path().join("old")).unwrap();
        std::fs::write(&path, [0x33; BLOCK_SIZE * 2]).unwrap();
        mapped.relative_address = BLOCK_SIZE as u64;
        assert_eq!(
            sources.read_u64(&mapped, Some(root.path())),
            Some(0x1111_1111_1111_1111)
        );
    }

    #[test]
    fn current_mapping_translation_and_fork_share_dso_memory_not_pid_state() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("object");
        let replacement = root.path().join("replacement");
        std::fs::write(&path, [0x11; 16]).unwrap();
        std::fs::write(&replacement, [0x22; 16]).unwrap();
        let mut table = MmapTable::default();
        table.insert_mmap(mapped_file(&path, 7));
        table.clone_pid_mappings(7, 8);
        let mut sources = DsoMemorySources::default();
        // Native resolves only the starting address: a word may cross map.end.
        assert_eq!(
            MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1000),
            Some(0x1111_1111_1111_1111)
        );
        std::fs::write(&path, [0x33; 16]).unwrap();
        assert_eq!(
            MappedMemory::new(8, &table, &mut sources, None).read_u64(0x1000),
            Some(0x1111_1111_1111_1111)
        );
        table.insert_mmap(mapped_file(&replacement, 7));
        assert_eq!(
            MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1000),
            Some(0x2222_2222_2222_2222)
        );
        assert_eq!(
            MappedMemory::new(9, &table, &mut sources, None).read_u64(0x1000),
            None
        );
        assert_eq!(
            MappedMemory::new(7, &table, &mut sources, None).read_u64(u64::MAX),
            None
        );
        table.insert_mmap_with_misc(mapped_file(&path, 7), PERF_RECORD_MISC_CPUMODE_USER);
        assert_eq!(
            MappedMemory::new(7, &table, &mut sources, None).read_u64(0x1000),
            Some(0x1111_1111_1111_1111)
        );
    }
}
