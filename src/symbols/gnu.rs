use std::fs::File;
use std::io::{Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;
use std::sync::Arc;

use super::SelectedGnuObject;
use crate::process::CommandSpec;

impl SelectedGnuObject {
    pub(super) fn attach_input(
        &self,
        path: &Path,
        mut command: CommandSpec,
    ) -> Result<CommandSpec, String> {
        let logical_name = path
            .to_str()
            .ok_or("GNU symbolizer requires a UTF-8 object path")?;
        let canonical_name = self
            .canonical_name
            .to_str()
            .ok_or("GNU symbolizer requires a UTF-8 canonical object path")?;
        let file = sealed_input(&self.metadata.object_bytes)
            .map_err(|error| format!("failed to prepare selected GNU object: {error}"))?;
        "pyroclast-addr2line".clone_into(&mut command.program);
        Ok(command
            .env("PYRO_PRIMARY_NAME", logical_name)
            .env("PYRO_PRIMARY_CANONICAL", canonical_name)
            .inherit_file("PYRO_PRIMARY_FD", Arc::new(file)))
    }
}

fn sealed_input(bytes: &[u8]) -> std::io::Result<File> {
    // GNU keeps the original logical name for debug-file discovery. The FD
    // supplies the already-selected bytes, never a relocated -e pathname.
    let fd = unsafe {
        libc::memfd_create(
            c"pyroclast-gnu-primary".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.rewind()?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_gnu_input_rejects_writes_and_size_changes() {
        let mut file = sealed_input(b"selected bytes").unwrap();
        let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        let expected =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        assert_eq!(seals & expected, expected);
        assert_eq!(
            file.write_all(b"replacement").unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            file.set_len(0).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            file.set_len(100).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
    }
}
