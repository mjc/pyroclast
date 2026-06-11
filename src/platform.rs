// Platform detection and platform-specific tool expectations.

use std::path::{Path, PathBuf};

pub trait ThreadLister {
    /// Returns thread IDs for a process.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform cannot enumerate threads for `pid`.
    fn thread_ids(&self, pid: u32) -> std::io::Result<Vec<u32>>;
}

#[derive(Clone, Debug)]
pub struct LinuxProcfsThreadLister {
    proc_root: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct UnsupportedThreadLister;

#[cfg(target_os = "linux")]
pub type NativeThreadLister = LinuxProcfsThreadLister;

#[cfg(not(target_os = "linux"))]
pub type NativeThreadLister = UnsupportedThreadLister;

impl LinuxProcfsThreadLister {
    #[must_use]
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
        }
    }
}

impl Default for LinuxProcfsThreadLister {
    fn default() -> Self {
        Self::new("/proc")
    }
}

impl ThreadLister for LinuxProcfsThreadLister {
    fn thread_ids(&self, pid: u32) -> std::io::Result<Vec<u32>> {
        linux_thread_ids_from_proc(&self.proc_root, pid)
    }
}

impl ThreadLister for UnsupportedThreadLister {
    fn thread_ids(&self, pid: u32) -> std::io::Result<Vec<u32>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("thread listing is unsupported on this platform for pid {pid}"),
        ))
    }
}

/// Reads Linux thread IDs from a procfs root, usually `/proc`.
///
/// # Errors
///
/// Returns an error when the task directory cannot be read or contains no
/// numeric thread IDs.
pub fn linux_thread_ids_from_proc(proc_root: &Path, pid: u32) -> std::io::Result<Vec<u32>> {
    let task_dir = proc_root.join(pid.to_string()).join("task");
    let mut tids = std::fs::read_dir(&task_dir)?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().and_then(|name| name.parse().ok()))
        .collect::<Vec<u32>>();
    tids.sort_unstable();
    if tids.is_empty() {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no thread ids found in {}", task_dir.display()),
        ))
    } else {
        Ok(tids)
    }
}
