#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
