pub mod fake;
pub mod heaptrack;
pub mod linux_perf;
pub mod macos_xctrace;
pub mod offcpu;
pub mod strace;

use std::path::PathBuf;

use crate::artifacts::ArtifactLayout;
use crate::cli::ProfileKind;
use crate::manifest::RunManifest;

pub type BackendResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileRequest {
    pub kind: ProfileKind,
    pub command: Vec<String>,
    pub out_dir: PathBuf,
    pub name: Option<String>,
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileResult {
    pub layout: ArtifactLayout,
    pub manifest: RunManifest,
}

pub trait ProfilerBackend {
    fn profile(&self, request: &ProfileRequest) -> BackendResult<ProfileResult>;
}
