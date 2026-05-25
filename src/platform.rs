// Platform detection and platform-specific tool expectations.

use std::path::Path;

/// Reads Linux thread IDs from a procfs root, usually `/proc`.
///
/// # Errors
///
/// Returns an error when the task directory cannot be read or contains no
/// numeric thread IDs.
pub fn linux_thread_ids_from_proc(proc_root: &Path, pid: u32) -> std::io::Result<Vec<u32>> {
    let process = procfs::process::Process::new_with_root(proc_root.join(pid.to_string()))
        .map_err(std::io::Error::other)?;
    let mut tids = process
        .tasks()
        .map_err(std::io::Error::other)?
        .filter_map(Result::ok)
        .filter_map(|task| u32::try_from(task.tid).ok())
        .collect::<Vec<_>>();
    tids.sort_unstable();
    if tids.is_empty() {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "no thread ids found in {}",
                proc_root.join(pid.to_string()).join("task").display()
            ),
        ))
    } else {
        Ok(tids)
    }
}
