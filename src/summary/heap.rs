use crate::parsers::heaptrack::{parse_heaptrack_summary, parse_size};
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HeapProfileSummary {
    pub total_allocations: Option<u64>,
    pub peak_heap_bytes: Option<u64>,
    pub temporary_allocations: Option<u64>,
    pub leaked_bytes: Option<u64>,
    pub peak_rss_bytes: Option<u64>,
    pub runtime_seconds: Option<f64>,
}

#[must_use]
pub fn summarize_heaptrack(text: &str) -> HeapProfileSummary {
    let basic = parse_heaptrack_summary(text);
    let mut summary = HeapProfileSummary {
        total_allocations: basic.total_allocations,
        peak_heap_bytes: basic.peak_heap_bytes,
        temporary_allocations: None,
        leaked_bytes: None,
        peak_rss_bytes: None,
        runtime_seconds: None,
    };
    for line in text.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("temporary memory allocations:") {
            summary.temporary_allocations = value
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok());
        } else if let Some(value) = line.strip_prefix("total memory leaked:") {
            summary.leaked_bytes = parse_size(value);
        } else if let Some(value) = line.strip_prefix("peak RSS (including heaptrack overhead):") {
            summary.peak_rss_bytes = parse_size(value);
        } else if let Some(value) = line.strip_prefix("total runtime:") {
            summary.runtime_seconds = value
                .trim()
                .trim_end_matches('.')
                .strip_suffix('s')
                .and_then(|value| value.parse::<f64>().ok())
                .filter(|value| value.is_finite() && *value >= 0.0);
        }
    }
    summary
}
