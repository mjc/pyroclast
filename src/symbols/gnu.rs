use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Seek;
use std::io::Write;
#[cfg(target_os = "linux")]
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
        let file = self
            .input
            .get_or_init(|| {
                selected_input(&self.metadata.object_bytes)
                    .map(Arc::new)
                    .map_err(|error| format!("failed to prepare selected GNU object: {error}"))
            })
            .as_ref()
            .map_err(Clone::clone)?;
        "pyroclast-addr2line".clone_into(&mut command.program);
        Ok(command
            .env("PYRO_PRIMARY_NAME", logical_name)
            .env("PYRO_PRIMARY_CANONICAL", canonical_name)
            .inherit_file("PYRO_PRIMARY_FD", Arc::clone(file)))
    }
}

#[cfg(target_os = "linux")]
fn selected_input(bytes: &[u8]) -> std::io::Result<File> {
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

#[cfg(not(target_os = "linux"))]
fn selected_input(bytes: &[u8]) -> std::io::Result<File> {
    readonly_input(bytes)
}

#[cfg(any(not(target_os = "linux"), test))]
fn readonly_input(bytes: &[u8]) -> std::io::Result<File> {
    use std::fs::{OpenOptions, Permissions};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    // GNU process_file() and BFD debug discovery retain the logical filename.
    // This is only transport for selected bytes, never a substitute -e path.
    let directory = tempfile::tempdir()?;
    let temporary = tempfile::NamedTempFile::new_in(directory.path())?;
    temporary
        .as_file()
        .set_permissions(Permissions::from_mode(0o400))?;
    let readonly = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(temporary.path())?;
    let original = temporary.as_file().metadata()?;
    let reopened = readonly.metadata()?;
    if (original.dev(), original.ino()) != (reopened.dev(), reopened.ino()) {
        return Err(std::io::Error::from_raw_os_error(libc::ESTALE));
    }
    let (mut writer, path) = temporary.into_parts();
    // Unlink before the potentially long write. Only a read-only FD is
    // published, after its private writer has been closed.
    path.close()?;
    directory.close()?;
    writer.write_all(bytes)?;
    drop(writer);
    Ok(readonly)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn selected_gnu_input_rejects_writes_and_size_changes() {
        let mut file = selected_input(b"selected bytes").unwrap();
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

    #[test]
    fn portable_gnu_input_is_unlinked_readonly_cloexec_and_preserves_bytes() {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;

        let binary = (0..=255).cycle().take(131_073).collect::<Vec<u8>>();
        for bytes in [b"".as_slice(), b"selected\0bytes\n".as_slice(), &binary] {
            let mut file = readonly_input(bytes).unwrap();
            let metadata = file.metadata().unwrap();
            assert_eq!(metadata.nlink(), 0);
            assert_eq!(metadata.mode() & 0o777, 0o400);
            assert_eq!(metadata.len(), bytes.len() as u64);
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0);
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
            assert!(file.write_all(b"replacement").is_err());
            assert!(file.set_len(0).is_err());
            assert!(file.set_len(metadata.len() + 1).is_err());
            let mut actual = Vec::new();
            file.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, bytes);
        }
    }
}
