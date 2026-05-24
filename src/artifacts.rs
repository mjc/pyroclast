use std::path::{Path, PathBuf};

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
        self.root.join("run.json")
    }

    pub fn stdout_log(&self) -> PathBuf {
        self.root.join("stdout.log")
    }

    pub fn stderr_log(&self) -> PathBuf {
        self.root.join("stderr.log")
    }

    pub fn command_txt(&self) -> PathBuf {
        self.root.join("command.txt")
    }

    pub fn raw_profile(&self, extension: &str) -> PathBuf {
        self.root.join(format!("profile.raw.{extension}"))
    }

    pub fn stacks_folded(&self) -> PathBuf {
        self.root.join("stacks.folded")
    }

    pub fn flamegraph_svg(&self) -> PathBuf {
        self.root.join("flamegraph.svg")
    }

    pub fn summary_txt(&self) -> PathBuf {
        self.root.join("summary.txt")
    }

    pub fn summary_json(&self) -> PathBuf {
        self.root.join("summary.json")
    }

    pub fn tool_errors_log(&self) -> PathBuf {
        self.root.join("tool-errors.log")
    }
}
