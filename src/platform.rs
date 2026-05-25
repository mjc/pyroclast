// Platform detection and platform-specific tool expectations.

use std::path::Path;

/// Reads Linux thread IDs from a procfs root, usually `/proc`.
///
/// # Errors
///
/// Returns an error when the task directory cannot be read or contains no
/// numeric thread IDs.
pub fn linux_thread_ids_from_proc(proc_root: &Path, pid: u32) -> std::io::Result<Vec<u32>> {
    let task_dir = proc_root.join(pid.to_string()).join("task");
    let mut tids = Vec::new();
    for entry in std::fs::read_dir(&task_dir)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str()
            && let Ok(tid) = name.parse::<u32>()
        {
            tids.push(tid);
        }
    }
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
