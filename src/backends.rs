pub mod fake;
pub mod heaptrack;
pub mod linux_perf;
pub mod macos_xctrace;
pub mod offcpu;
pub mod strace;

use std::path::PathBuf;

use crate::artifacts::ArtifactLayout;
use crate::backends::offcpu::OffcpuMethod;
use crate::cli::{PerfCallGraph, PerfEvent, ProfileKind};
use crate::manifest::{RequestedControls, RunManifest};
use crate::symbols::SymbolizerKind;

pub type BackendResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileRequest {
    pub kind: ProfileKind,
    pub command: Vec<String>,
    pub out_dir: PathBuf,
    pub name: Option<String>,
    pub json: bool,
    pub symbols: bool,
    pub symbolizer: SymbolizerKind,
    pub frequency: u32,
    pub event: PerfEvent,
    pub call_graph: PerfCallGraph,
    pub pid: Option<u32>,
    pub tids: Vec<u32>,
    pub threads_of_pid: Option<u32>,
    pub duration_secs: u32,
    pub offcpu_method: Option<OffcpuMethod>,
}

impl ProfileRequest {
    pub(crate) fn requested_controls(&self) -> RequestedControls {
        RequestedControls {
            frequency: self.frequency,
            event: self.event,
            call_graph: self.call_graph,
            symbols: self.symbols,
            symbolizer: self.symbolizer,
            duration_secs: self.duration_secs,
        }
    }

    pub(crate) fn ensure_command_target(&self, backend: &str) -> BackendResult<()> {
        if self.pid.is_some() || self.threads_of_pid.is_some() || !self.tids.is_empty() {
            return Err(
                format!("{backend} currently supports command-driven workflows only").into(),
            );
        }
        if self.command.is_empty() {
            return Err(format!("{backend} requires a workload command").into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileResult {
    pub layout: ArtifactLayout,
    pub manifest: RunManifest,
    pub completion: ProfileCompletion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkloadOutcome {
    Completed(i32),
    Interrupted,
    DurationLimited,
    Incomplete,
    /// This backend exposes recorder status, not independent workload status.
    Unobserved,
}

impl WorkloadOutcome {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed(_) => "completed",
            Self::Interrupted => "interrupted",
            Self::DurationLimited => "duration_limited",
            Self::Incomplete => "incomplete",
            Self::Unobserved => "unobserved",
        }
    }

    #[must_use]
    pub fn exit_status(self) -> Option<i32> {
        match self {
            Self::Completed(status) => Some(status),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileCompletion {
    pub recorder_status: Option<i32>,
    pub workload: WorkloadOutcome,
    pub cancellation_signal: Option<i32>,
}

impl ProfileCompletion {
    pub(crate) fn from_recorder(status: Option<i32>, cancellation_signal: Option<i32>) -> Self {
        Self {
            recorder_status: status,
            workload: WorkloadOutcome::Unobserved,
            cancellation_signal,
        }
    }

    /// Returns the CLI status without inferring success from missing evidence.
    /// Parent cancellation takes precedence over a known recorder signal.
    ///
    /// # Errors
    /// Returns an error if an external status cannot fit in a process exit code.
    pub fn exit_code(self) -> Result<u8, std::num::TryFromIntError> {
        if let Some(signal) = self.cancellation_signal {
            return u8::try_from(128_i64 + i64::from(signal));
        }
        let status = match self.workload {
            WorkloadOutcome::Completed(status) => Some(status),
            WorkloadOutcome::Interrupted
                if self.recorder_status.is_some_and(|status| status < 0) =>
            {
                self.recorder_status
            }
            WorkloadOutcome::Interrupted => return Ok(130),
            WorkloadOutcome::DurationLimited => return Ok(0),
            WorkloadOutcome::Incomplete => return Ok(1),
            WorkloadOutcome::Unobserved => self.recorder_status,
        };
        match status {
            Some(status) if status < 0 => u8::try_from(128_i64 - i64::from(status)),
            Some(status) => u8::try_from(status),
            None => Ok(1),
        }
    }
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
