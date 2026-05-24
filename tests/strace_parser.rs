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
