#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StraceSummary {
    pub total_calls: u64,
    pub total_seconds: f64,
}

pub fn parse_strace_summary(input: &str) -> StraceSummary {
    let mut summary = StraceSummary {
        total_calls: 0,
        total_seconds: 0.0,
    };

    for line in input.lines() {
        if let Some(seconds) = parse_duration(line) {
            summary.total_calls += 1;
            summary.total_seconds += seconds;
        }
    }

    summary
}

fn parse_duration(line: &str) -> Option<f64> {
    let start = line.rfind('<')?;
    let end = line[start..].find('>')? + start;
    line[start + 1..end].parse().ok()
}
