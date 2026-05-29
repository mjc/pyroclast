use proptest::prelude::*;
use proptest::string::string_regex;
use pyroclast::parsers::heaptrack::{
    HeaptrackSummary, parse_heaptrack_summary, render_heaptrack_summary_text,
};

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

proptest! {
    #[test]
    fn property_parses_last_valid_matching_values(
        lines in prop::collection::vec(heaptrack_line(), 0..64),
    ) {
        let text = lines
            .iter()
            .map(HeaptrackLine::render)
            .collect::<Vec<_>>()
            .join("\n");
        let mut expected = HeaptrackSummary {
            total_allocations: None,
            peak_heap_bytes: None,
        };

        for line in &lines {
            match line {
                HeaptrackLine::Total(value) => expected.total_allocations = Some(*value),
                HeaptrackLine::Peak(value) => expected.peak_heap_bytes = Some(*value),
                HeaptrackLine::InvalidTotal(_)
                | HeaptrackLine::InvalidPeak(_)
                | HeaptrackLine::Noise(_) => {}
            }
        }

        prop_assert_eq!(parse_heaptrack_summary(&text), expected);
    }

    #[test]
    fn property_rendered_summaries_round_trip(
        total_allocations in prop::option::of(any::<u64>()),
        peak_heap_bytes in prop::option::of(any::<u64>()),
    ) {
        let summary = HeaptrackSummary {
            total_allocations,
            peak_heap_bytes,
        };

        prop_assert_eq!(
            parse_heaptrack_summary(&render_heaptrack_summary_text(&summary)),
            summary
        );
    }
}

#[derive(Clone, Debug)]
enum HeaptrackLine {
    Total(u64),
    Peak(u64),
    InvalidTotal(String),
    InvalidPeak(String),
    Noise(String),
}

impl HeaptrackLine {
    fn render(&self) -> String {
        match self {
            Self::Total(value) => format!("total allocations: {value}"),
            Self::Peak(value) => format!("peak heap memory consumption: {value} bytes"),
            Self::InvalidTotal(value) => format!("total allocations: {value}"),
            Self::InvalidPeak(value) => format!("peak heap memory consumption: {value}"),
            Self::Noise(value) => value.clone(),
        }
    }
}

fn heaptrack_line() -> impl Strategy<Value = HeaptrackLine> {
    prop_oneof![
        any::<u64>().prop_map(HeaptrackLine::Total),
        any::<u64>().prop_map(HeaptrackLine::Peak),
        invalid_value().prop_map(HeaptrackLine::InvalidTotal),
        invalid_value().prop_map(HeaptrackLine::InvalidPeak),
        noise_line().prop_map(HeaptrackLine::Noise),
    ]
}

fn invalid_value() -> impl Strategy<Value = String> {
    string_regex(r"[A-Za-z_][A-Za-z0-9_ ]{0,12}").expect("valid invalid-value regex")
}

fn noise_line() -> impl Strategy<Value = String> {
    string_regex(r"[A-Za-z][A-Za-z0-9_ :.-]{0,24}").expect("valid noise regex")
}
