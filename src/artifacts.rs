use std::path::{Path, PathBuf};

pub const RUN_JSON: &str = "run.json";
pub const STDOUT_LOG: &str = "stdout.log";
pub const STDERR_LOG: &str = "stderr.log";
pub const COMMAND_TXT: &str = "command.txt";
pub const STACKS_FOLDED: &str = "stacks.folded";
pub const FLAMEGRAPH_SVG: &str = "flamegraph.svg";
pub const SUMMARY_TXT: &str = "summary.txt";
pub const SUMMARY_JSON: &str = "summary.json";
pub const TOOL_ERRORS_LOG: &str = "tool-errors.log";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactLayout {
    root: PathBuf,
}

impl ArtifactLayout {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn run_json(&self) -> PathBuf {
        self.root.join(RUN_JSON)
    }

    pub fn stdout_log(&self) -> PathBuf {
        self.root.join(STDOUT_LOG)
    }

    pub fn stderr_log(&self) -> PathBuf {
        self.root.join(STDERR_LOG)
    }

    pub fn command_txt(&self) -> PathBuf {
        self.root.join(COMMAND_TXT)
    }

    pub fn raw_profile(&self, extension: &str) -> PathBuf {
        self.root.join(format!("profile.raw.{extension}"))
    }

    pub fn stacks_folded(&self) -> PathBuf {
        self.root.join(STACKS_FOLDED)
    }

    pub fn flamegraph_svg(&self) -> PathBuf {
        self.root.join(FLAMEGRAPH_SVG)
    }

    pub fn summary_txt(&self) -> PathBuf {
        self.root.join(SUMMARY_TXT)
    }

    pub fn summary_json(&self) -> PathBuf {
        self.root.join(SUMMARY_JSON)
    }

    pub fn tool_errors_log(&self) -> PathBuf {
        self.root.join(TOOL_ERRORS_LOG)
    }
}
