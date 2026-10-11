pub mod heap;
mod streaming;
pub mod syscalls;
pub mod threads;
pub mod timeline;

use crate::perfdata::fold::{PerfSummary, summarize_perfdata};
use serde::Serialize;
use std::fmt;

/// Writes the separate unsigned wrapping counters from Linux perf v7.2.9
/// `tools/perf/util/session.c:2050-2059`. Local Linux v7.1
/// `kernel/events/ring_buffer.c:264-265` increments both loss channels on one failure.
pub(crate) fn write_perf_loss_counters(
    output: &mut impl fmt::Write,
    lost_records: u64,
    lost_samples: u64,
    dropped_samples: u64,
) -> fmt::Result {
    writeln!(
        output,
        "PERF_RECORD_LOST reported losses (sum of payload values): {lost_records}"
    )?;
    writeln!(output, "non-BPF LOST_SAMPLES counter: {lost_samples}")?;
    writeln!(
        output,
        "BPF LOST_SAMPLES dropped-sample counter: {dropped_samples}"
    )?;
    writeln!(
        output,
        "loss counters may overlap; they are not unique physical-loss totals"
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PerfProfileSummary {
    pub total_samples: usize,
    pub weighted_samples: u64,
    /// Native unsigned wrapping sum of `PERF_RECORD_LOST` payloads.
    /// May overlap other loss counters; not a unique physical-loss estimate.
    pub lost_records: u64,
    /// Native unsigned wrapping sum of non-BPF `PERF_RECORD_LOST_SAMPLES` payloads.
    /// May overlap other loss counters; not a unique physical-loss estimate.
    pub lost_samples: u64,
    /// Native unsigned wrapping sum of BPF `PERF_RECORD_LOST_SAMPLES` payloads.
    /// May overlap other loss counters; not a unique physical-loss estimate.
    pub dropped_samples: u64,
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
        lost_samples: input.lost_samples,
        dropped_samples: input.dropped_samples,
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

pub(crate) fn summarize_perfdata_profile_file_with_origin(
    path: &std::path::Path,
    bucket_width_ns: u64,
    limit: usize,
    first_sample_ns: Option<u64>,
) -> Result<PerfProfileSummary, String> {
    streaming::summarize_file_with_origin(path, bucket_width_ns, limit, first_sample_ns)
}
