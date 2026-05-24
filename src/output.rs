use std::io::{ErrorKind, Write};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CliOutput {
    pub stdout: String,
    pub stderr: String,
}

/// Writes CLI output to the provided streams.
///
/// # Errors
///
/// Returns an I/O error when writing to either stream fails for a reason other
/// than a broken pipe.
pub fn write_cli_output(
    output: &CliOutput,
    mut stdout: impl Write,
    mut stderr: impl Write,
) -> std::io::Result<()> {
    write_all_or_ignore_broken_pipe(&mut stdout, output.stdout.as_bytes())?;
    write_all_or_ignore_broken_pipe(&mut stderr, output.stderr.as_bytes())?;
    Ok(())
}

fn write_all_or_ignore_broken_pipe(writer: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    match writer.write_all(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error),
    }
}
