use std::path::PathBuf;

use crate::backends::BackendResult;
use crate::process::{CommandRunner, CommandSpec};

#[must_use]
pub fn build_inferno_flamegraph_command(title: &str) -> CommandSpec {
    CommandSpec::new("inferno-flamegraph").args([
        "--title".to_string(),
        title.to_string(),
        "-".to_string(),
    ])
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlamegraphRequest {
    pub title: String,
    pub folded_stacks: String,
    pub output: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlamegraphRenderResult {
    pub stderr: Vec<u8>,
}

pub trait FlamegraphRenderer {
    /// Renders folded stacks to an SVG artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the renderer process or output write fails.
    fn render(&self, request: &FlamegraphRequest) -> BackendResult<FlamegraphRenderResult>;
}

pub struct InfernoFlamegraphRenderer<'a, R> {
    runner: &'a R,
}

impl<'a, R> InfernoFlamegraphRenderer<'a, R> {
    #[must_use]
    pub fn new(runner: &'a R) -> Self {
        Self { runner }
    }
}

impl<R> FlamegraphRenderer for InfernoFlamegraphRenderer<'_, R>
where
    R: CommandRunner,
{
    fn render(&self, request: &FlamegraphRequest) -> BackendResult<FlamegraphRenderResult> {
        let command = build_inferno_flamegraph_command(&request.title)
            .stdin(request.folded_stacks.as_bytes().to_vec());
        let output = self.runner.run(&command)?;
        std::fs::write(&request.output, &output.stdout)?;
        Ok(FlamegraphRenderResult {
            stderr: output.stderr,
        })
    }
}
