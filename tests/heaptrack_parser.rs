use pyroclast::parsers::heaptrack::parse_heaptrack_summary;

#[test]
fn parses_heaptrack_summary_totals() {
    let text = "\
total allocations: 42
peak heap memory consumption: 1024 bytes
";

    let summary = parse_heaptrack_summary(text);

    assert_eq!(summary.total_allocations, Some(42));
    assert_eq!(summary.peak_heap_bytes, Some(1024));
}
