use crate::perfdata::fold::PerfSummary;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimelineSummary {
    pub bucket_width_ns: u64,
    pub first_sample_ns: Option<u64>,
    pub last_sample_ns: Option<u64>,
    /// Span between first and last recorded sample, not process wall time.
    pub duration_ns: Option<u64>,
    pub untimed_samples: usize,
    pub buckets: Vec<TimelineBucket>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimelineBucket {
    pub start_offset_ns: u64,
    pub samples: usize,
    pub weighted_samples: u64,
}

/// Groups timestamped samples into sparse buckets relative to the first sample.
///
/// # Errors
/// Returns an error when bucket width is zero.
pub fn summarize_timeline(
    input: &PerfSummary,
    bucket_width_ns: u64,
) -> Result<TimelineSummary, String> {
    if bucket_width_ns == 0 {
        return Err("timeline bucket width must be greater than zero".to_string());
    }
    let first = input
        .sample_stacks
        .iter()
        .filter_map(|sample| sample.time)
        .min();
    let last = input
        .sample_stacks
        .iter()
        .filter_map(|sample| sample.time)
        .max();
    let mut buckets = BTreeMap::new();
    let mut untimed_samples = 0;
    for sample in &input.sample_stacks {
        let Some(time) = sample.time else {
            untimed_samples += 1;
            continue;
        };
        let offset = time - first.unwrap_or(time);
        let start_offset_ns = offset / bucket_width_ns * bucket_width_ns;
        let bucket = buckets.entry(start_offset_ns).or_insert(TimelineBucket {
            start_offset_ns,
            samples: 0,
            weighted_samples: 0,
        });
        bucket.samples += 1;
        bucket.weighted_samples = bucket
            .weighted_samples
            .saturating_add(sample.period.unwrap_or(1));
    }
    Ok(TimelineSummary {
        bucket_width_ns,
        first_sample_ns: first,
        last_sample_ns: last,
        duration_ns: first.zip(last).map(|(first, last)| last - first),
        untimed_samples,
        buckets: buckets.into_values().collect(),
    })
}
