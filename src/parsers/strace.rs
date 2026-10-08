use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct SyscallStats {
    pub calls: u64,
    pub total_seconds: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct StraceSummary {
    pub total_calls: u64,
    pub total_seconds: f64,
    pub by_syscall: BTreeMap<String, SyscallStats>,
}

impl StraceSummary {
    fn add_call(&mut self, syscall: Option<&str>, seconds: f64) {
        self.total_calls += 1;
        self.total_seconds += seconds;

        if let Some(syscall) = syscall {
            let stats = self
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

#[must_use]
pub fn parse_strace_summary(input: &str) -> StraceSummary {
    let mut summary = StraceSummary {
        total_calls: 0,
        total_seconds: 0.0,
        by_syscall: BTreeMap::new(),
    };

    for line in input.lines() {
        if let Some(seconds) = parse_duration(line)
            && let Some(syscall) = parse_syscall_name(line)
        {
            summary.add_call(Some(syscall), seconds);
        }
    }

    summary
}

#[must_use]
pub fn render_strace_summary_text(summary: &StraceSummary) -> String {
    let mut text = format!(
        "syscall calls: {}\nsyscall seconds: {:.6}\n",
        summary.total_calls, summary.total_seconds
    );
    for (syscall, stats) in &summary.by_syscall {
        let _ = writeln!(
            text,
            "{syscall}: calls={} seconds={:.6}",
            stats.calls, stats.total_seconds
        );
    }
    text
}

fn parse_duration(line: &str) -> Option<f64> {
    let start = line.rfind('<')?;
    let end = line[start..].find('>')? + start;
    let seconds: f64 = line[start + 1..end].parse().ok()?;
    (seconds.is_finite() && seconds >= 0.0).then_some(seconds)
}

fn parse_syscall_name(line: &str) -> Option<&str> {
    if let Some((_, resumed)) = line.split_once("<... ") {
        let (name, _) = resumed.split_once(" resumed>")?;
        return valid_syscall_name(name).then_some(name);
    }
    let open = line.find('(')?;
    let before_open = line[..open].trim_end();
    let name = before_open.split_whitespace().last()?;
    valid_syscall_name(name).then_some(name)
}

fn valid_syscall_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
