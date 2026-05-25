use std::path::PathBuf;

use serde::Serialize;

use crate::cli::{PerfCallGraph, PerfEvent, ProfileKind};
use crate::tools::ToolVersion;

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
    pub sample_event: PerfEvent,
    pub call_graph: PerfCallGraph,
    pub record_target: String,
    pub duration_secs: Option<u32>,
    pub symbols: bool,
    pub tool_versions: Vec<ToolVersion>,
    pub artifacts: Vec<PathBuf>,
    pub diagnostics: Vec<String>,
}
