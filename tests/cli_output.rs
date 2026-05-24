use std::io::{Error, ErrorKind, Write};

use pyroclast::{CliOutput, write_cli_output};

#[test]
fn ignores_broken_pipe_when_writing_stdout() {
    let output = CliOutput {
        stdout: "many mappings\n".to_string(),
        stderr: String::new(),
    };

    write_cli_output(output, BrokenPipeWriter, Vec::new()).expect("broken pipe is ignored");
}

struct BrokenPipeWriter;

impl Write for BrokenPipeWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(Error::from(ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
