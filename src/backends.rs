pub mod fake;
pub mod heaptrack;
pub mod linux_perf;
pub mod macos_xctrace;
pub mod offcpu;
pub mod strace;

use std::path::PathBuf;

use crate::artifacts::ArtifactLayout;
use crate::cli::{PerfCallGraph, PerfEvent, ProfileKind};
use crate::manifest::RunManifest;

pub type BackendResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileRequest {
    pub kind: ProfileKind,
    pub command: Vec<String>,
    pub out_dir: PathBuf,
    pub name: Option<String>,
    pub json: bool,
    pub symbols: bool,
    pub frequency: u32,
    pub event: PerfEvent,
    pub call_graph: PerfCallGraph,
    pub pid: Option<u32>,
    pub tids: Vec<u32>,
    pub duration_secs: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileResult {
    pub layout: ArtifactLayout,
    pub manifest: RunManifest,
}

pub trait ProfilerBackend {
    /// Profiles a command and writes Pyroclast artifacts.
    ///
    /// # Errors
    ///
    /// Returns an error when backend setup, process execution, artifact
    /// writing, or backend-specific parsing fails.
    fn profile(&self, request: &ProfileRequest) -> BackendResult<ProfileResult>;
}
