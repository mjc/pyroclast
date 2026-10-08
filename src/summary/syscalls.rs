use crate::parsers::strace::parse_strace_summary;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SyscallLatencySummary {
    pub total_calls: u64,
    pub total_seconds: f64,
    pub syscalls: Vec<SyscallLatency>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SyscallLatency {
    pub name: String,
    pub calls: u64,
    pub total_seconds: f64,
    pub mean_seconds: f64,
    pub percent_of_syscall_time: f64,
}

#[must_use]
#[allow(clippy::cast_precision_loss)] // Displayed averages and percentages are approximate.
pub fn summarize_syscalls(input: &str, limit: usize) -> SyscallLatencySummary {
    let parsed = parse_strace_summary(input);
    let mut syscalls = parsed
        .by_syscall
        .into_iter()
        .map(|(name, stats)| SyscallLatency {
            name,
            calls: stats.calls,
            total_seconds: stats.total_seconds,
            mean_seconds: stats.total_seconds / stats.calls as f64,
            percent_of_syscall_time: if parsed.total_seconds == 0.0 {
                0.0
            } else {
                100.0 * stats.total_seconds / parsed.total_seconds
            },
        })
        .collect::<Vec<_>>();
    syscalls.sort_by(|left, right| {
        right
            .total_seconds
            .total_cmp(&left.total_seconds)
            .then_with(|| left.name.cmp(&right.name))
    });
    syscalls.truncate(limit);
    SyscallLatencySummary {
        total_calls: parsed.total_calls,
        total_seconds: parsed.total_seconds,
        syscalls,
    }
}
