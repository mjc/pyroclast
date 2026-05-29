use std::collections::BTreeMap;

use proptest::prelude::*;
use proptest::string::string_regex;
use pyroclast::parsers::strace::parse_strace_summary;

#[test]
fn parses_total_syscall_time_and_count() {
    let input = "\
123 12:00:00.000000 read(3, \"abc\", 3) = 3 <0.001000>
123 12:00:00.002000 write(1, \"x\", 1) = 1 <0.002500>
";

    let summary = parse_strace_summary(input);

    assert_eq!(summary.total_calls, 2);
    assert!((summary.total_seconds - 0.0035).abs() < f64::EPSILON);
}

#[test]
fn parses_per_syscall_breakdown() {
    let input = "\
123 12:00:00.000000 read(3, \"abc\", 3) = 3 <0.001000>
123 12:00:00.002000 write(1, \"x\", 1) = 1 <0.002500>
123 12:00:00.004000 read(3, \"def\", 3) = 3 <0.004000>
";

    let summary = parse_strace_summary(input);
    let read = summary.by_syscall.get("read").expect("read syscall");
    let write = summary.by_syscall.get("write").expect("write syscall");

    assert_eq!(read.calls, 2);
    assert!((read.total_seconds - 0.005).abs() < f64::EPSILON);
    assert_eq!(write.calls, 1);
    assert!((write.total_seconds - 0.0025).abs() < f64::EPSILON);
}

proptest! {
    #[test]
    fn property_aggregates_total_and_per_syscall_counts(
        calls in prop::collection::vec((syscall_name(), 0_u16..10_000_u16), 0..64),
    ) {
        let input = render_strace_lines(&calls);
        let summary = parse_strace_summary(&input);
        let mut expected = BTreeMap::new();
        let expected_total_seconds = calls.iter().fold(0.0, |total, (_, seconds)| total + f64::from(*seconds));

        for (syscall, seconds) in &calls {
            let stats = expected.entry(syscall.clone()).or_insert((0_u64, 0.0_f64));
            stats.0 += 1;
            stats.1 += f64::from(*seconds);
        }

        prop_assert_eq!(summary.total_calls, calls.len() as u64);
        prop_assert!((summary.total_seconds - expected_total_seconds).abs() < f64::EPSILON);
        prop_assert_eq!(summary.by_syscall.len(), expected.len());

        for (syscall, (calls, total_seconds)) in expected {
            let actual = summary.by_syscall.get(&syscall).expect("syscall entry");
            prop_assert_eq!(actual.calls, calls);
            prop_assert!((actual.total_seconds - total_seconds).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn property_ignores_lines_without_a_parseable_duration(
        calls in prop::collection::vec((syscall_name(), 0_u16..10_000_u16), 0..32),
        noise in prop::collection::vec(string_regex(r"[A-Za-z0-9_ ]{1,24}").expect("valid regex"), 0..32),
    ) {
        let mut lines = calls
            .iter()
            .map(|(syscall, seconds)| strace_line(syscall, *seconds))
            .collect::<Vec<_>>();
        lines.extend(
            noise
                .iter()
                .map(|line| format!("{line} without angle-bracket duration")),
        );

        let summary = parse_strace_summary(&lines.join("\n"));

        prop_assert_eq!(summary.total_calls, calls.len() as u64);
    }
}

fn syscall_name() -> impl Strategy<Value = String> {
    string_regex(r"[a-z][a-z0-9_]{0,10}").expect("valid syscall regex")
}

fn render_strace_lines(calls: &[(String, u16)]) -> String {
    let mut lines = calls
        .iter()
        .map(|(syscall, seconds)| strace_line(syscall, *seconds))
        .collect::<Vec<_>>()
        .join("\n");
    if !lines.is_empty() {
        lines.push('\n');
    }
    lines
}

fn strace_line(syscall: &str, seconds: u16) -> String {
    format!("123 12:00:00.000000 {syscall}(0) = 0 <{seconds}>")
}
