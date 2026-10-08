use std::path::PathBuf;

use serde::Serialize;

use crate::cli::{PerfCallGraph, PerfEvent, ProfileKind};
use crate::parsers::xctrace::XctraceWeightUnit;
use crate::symbols::SymbolizerKind;
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
pub struct RequestedControls {
    pub frequency: u32,
    pub event: PerfEvent,
    pub call_graph: PerfCallGraph,
    pub symbols: bool,
    pub symbolizer: SymbolizerKind,
    pub duration_secs: u32,
}

/// Native recorder configuration and observed export units, not CLI defaults.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum NativeMeasurement {
    Perf {
        frequency: u32,
        event: PerfEvent,
        call_graph: PerfCallGraph,
    },
    Xctrace {
        template: String,
        weight_unit: XctraceWeightUnit,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunManifest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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
    pub requested_controls: RequestedControls,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement: Option<NativeMeasurement>,
    pub record_target: String,
    pub duration_secs: Option<u32>,
    pub tool_versions: Vec<ToolVersion>,
    pub artifacts: Vec<PathBuf>,
    pub diagnostics: Vec<String>,
}
