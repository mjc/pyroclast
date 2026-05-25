use std::path::PathBuf;

use serde::Serialize;

use crate::cli::{PerfCallGraph, ProfileKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendName {
    Fake,
    LinuxPerf,
    MacosXctrace,
    Heaptrack,
    Strace,
    Offcpu,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunManifest {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub profile_kind: ProfileKind,
    pub requested_backend: BackendName,
    pub actual_backend: BackendName,
    pub fallback_reason: Option<String>,
    pub platform: String,
    pub started_at_unix_ms: u128,
    pub ended_at_unix_ms: Option<u128>,
    pub exit_status: Option<i32>,
    pub sample_frequency: u32,
    pub call_graph: PerfCallGraph,
    pub symbols: bool,
    pub artifacts: Vec<PathBuf>,
    pub diagnostics: Vec<String>,
}
