use std::path::PathBuf;

use crate::backends::BackendResult;
use crate::process::{CommandRunner, CommandSpec};
use crate::tools::ToolSpec;

pub mod analysis;

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
    fn tool_specs(&self) -> Vec<ToolSpec> {
        Vec::new()
    }

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
    fn tool_specs(&self) -> Vec<ToolSpec> {
        vec![ToolSpec::nix_managed("inferno-flamegraph")]
    }

    fn render(&self, request: &FlamegraphRequest) -> BackendResult<FlamegraphRenderResult> {
        let command = build_inferno_flamegraph_command(&request.title)
            .stdin(request.folded_stacks.as_bytes().to_vec());
        let output = self.runner.run(&command)?;
        if output.status_code != Some(0) {
            return Err(format!(
                "inferno-flamegraph exited with {:?}: {}",
                output.status_code,
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        std::fs::write(&request.output, &output.stdout)?;
        Ok(FlamegraphRenderResult {
            stderr: output.stderr,
        })
    }
}
