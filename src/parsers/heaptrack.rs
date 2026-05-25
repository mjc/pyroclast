use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct HeaptrackSummary {
    pub total_allocations: Option<u64>,
    pub peak_heap_bytes: Option<u64>,
}

#[must_use]
pub fn parse_heaptrack_summary(text: &str) -> HeaptrackSummary {
    let mut summary = HeaptrackSummary {
        total_allocations: None,
        peak_heap_bytes: None,
    };

    for line in text.lines() {
        if let Some(value) = number_after_prefix(line, "total allocations:") {
            summary.total_allocations = Some(value);
        }
        if let Some(value) = number_after_prefix(line, "peak heap memory consumption:") {
            summary.peak_heap_bytes = Some(value);
        }
    }

    summary
}

fn number_after_prefix(line: &str, prefix: &str) -> Option<u64> {
    line.trim()
        .strip_prefix(prefix)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[must_use]
pub fn render_heaptrack_summary_text(summary: &HeaptrackSummary) -> String {
    format!(
        "total allocations: {}\npeak heap bytes: {}\n",
        optional_u64(summary.total_allocations),
        optional_u64(summary.peak_heap_bytes)
    )
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_string(), |value| value.to_string())
}
