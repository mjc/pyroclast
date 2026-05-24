use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SyscallStats {
    pub calls: u64,
    pub total_seconds: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StraceSummary {
    pub total_calls: u64,
    pub total_seconds: f64,
    pub by_syscall: BTreeMap<String, SyscallStats>,
}

pub fn parse_strace_summary(input: &str) -> StraceSummary {
    let mut summary = StraceSummary {
        total_calls: 0,
        total_seconds: 0.0,
        by_syscall: BTreeMap::new(),
    };

    for line in input.lines() {
        if let Some(seconds) = parse_duration(line) {
            summary.total_calls += 1;
            summary.total_seconds += seconds;
            if let Some(syscall) = parse_syscall_name(line) {
                let stats = summary
                    .by_syscall
                    .entry(syscall.to_string())
                    .or_insert(SyscallStats {
                        calls: 0,
                        total_seconds: 0.0,
                    });
                stats.calls += 1;
                stats.total_seconds += seconds;
            }
        }
    }

    summary
}

fn parse_duration(line: &str) -> Option<f64> {
    let start = line.rfind('<')?;
    let end = line[start..].find('>')? + start;
    line[start + 1..end].parse().ok()
}

fn parse_syscall_name(line: &str) -> Option<&str> {
    let open = line.find('(')?;
    let before_open = line[..open].trim_end();
    before_open.split_whitespace().last()
}
