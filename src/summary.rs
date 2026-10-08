pub mod heap;
mod streaming;
pub mod syscalls;
pub mod threads;
pub mod timeline;

use crate::perfdata::fold::{PerfSummary, summarize_perfdata};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PerfProfileSummary {
    pub total_samples: usize,
    pub weighted_samples: u64,
    pub lost_records: u64,
    pub unassigned_samples: usize,
    pub threads: Vec<threads::ThreadProfileSummary>,
    pub timeline: timeline::TimelineSummary,
}

/// Summarizes captured thread identities, timestamp span, and sampled activity.
///
/// # Errors
/// Returns an error when bucket width is zero.
pub fn summarize_perf_summary(
    input: &PerfSummary,
    bucket_width_ns: u64,
    limit: usize,
) -> Result<PerfProfileSummary, String> {
    Ok(PerfProfileSummary {
        total_samples: input.sample_stacks.len(),
        weighted_samples: input.sample_stacks.iter().fold(0_u64, |total, sample| {
            total.saturating_add(sample.period.unwrap_or(1))
        }),
        lost_records: input.lost_records,
        unassigned_samples: input
            .sample_stacks
            .iter()
            .filter(|sample| sample.tid.or(sample.pid).is_none())
            .count(),
        threads: threads::summarize_threads(input, limit),
        timeline: timeline::summarize_timeline(input, bucket_width_ns)?,
    })
}

/// Summarizes supported perf bytes using their recorded timestamps.
///
/// # Errors
/// Returns an error for malformed perf data or zero bucket width.
pub fn summarize_perfdata_profile(
    bytes: &[u8],
    bucket_width_ns: u64,
    limit: usize,
) -> Result<PerfProfileSummary, String> {
    summarize_perf_summary(&summarize_perfdata(bytes)?, bucket_width_ns, limit)
}

/// Aggregates supported perf metadata with bounded reads and no sample retention.
/// Storage grows with distinct threads, CPUs, and sparse timestamp buckets.
/// The completed recording must remain unchanged across both metadata passes.
///
/// # Errors
/// Returns an error for unreadable/malformed data or zero bucket width.
pub fn summarize_perfdata_profile_file(
    path: &std::path::Path,
    bucket_width_ns: u64,
    limit: usize,
) -> Result<PerfProfileSummary, String> {
    streaming::summarize_file(path, bucket_width_ns, limit)
}
