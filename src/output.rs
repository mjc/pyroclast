use std::io::{ErrorKind, Write};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CliOutput {
    pub stdout: String,
    pub stderr: String,
}

pub(crate) struct PipeWriter<W> {
    writer: W,
    broken_pipe: bool,
}

impl<W> PipeWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            broken_pipe: false,
        }
    }

    pub fn broken_pipe(&self) -> bool {
        self.broken_pipe
    }
}

impl<W: Write> Write for PipeWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let result = self.writer.write(bytes);
        if let Err(error) = &result {
            self.broken_pipe |= error.kind() == ErrorKind::BrokenPipe;
        }
        result
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let result = self.writer.flush();
        if let Err(error) = &result {
            self.broken_pipe |= error.kind() == ErrorKind::BrokenPipe;
        }
        result
    }
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
