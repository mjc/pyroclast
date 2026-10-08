use proptest::prelude::*;
use proptest::string::string_regex;
use pyroclast::flamegraph::analysis::{
    FlamegraphEntry, categorize_flamegraph_frame, diff_flamegraph_svgs, diff_flamegraphs,
    parse_flamegraph_categories, parse_flamegraph_entries, syscall_breakdown, top_entries,
};

#[test]
fn parses_inferno_svg_title_entries() {
    let svg = r"
<svg>
  <title>all (1,000 samples, 100%)</title>
  <g><title>read (250 samples, 25.00%)</title></g>
  <g><title>tokio::runtime::park (125 samples, 12.50%)</title></g>
</svg>
";

    let entries = parse_flamegraph_entries(svg);

    assert_eq!(
        entries,
        vec![
            FlamegraphEntry {
                name: "read".to_string(),
                samples: 250,
                percent: 25.0,
            },
            FlamegraphEntry {
                name: "tokio::runtime::park".to_string(),
                samples: 125,
                percent: 12.5,
            },
        ]
    );
}

#[test]
fn ranks_top_entries_with_minimum_percent() {
    let entries = vec![
        entry("small", 10, 0.5),
        entry("hot", 40, 40.0),
        entry("warm", 20, 20.0),
    ];

    let top = top_entries(&entries, 2, 1.0);

    assert_eq!(top, vec![entry("hot", 40, 40.0), entry("warm", 20, 20.0)]);
}

#[test]
fn groups_syscall_entries_without_arch_prefixes() {
    let entries = vec![
        entry("__x64_sys_read", 30, 30.0),
        entry("__x86_sys_write", 20, 20.0),
        entry("user_work", 50, 50.0),
    ];

    let syscalls = syscall_breakdown(&entries);

    assert_eq!(
        syscalls,
        vec![entry("read", 30, 30.0), entry("write", 20, 20.0)]
    );
}

#[test]
fn diffs_entries_by_function_name() {
    let before = vec![entry("parse", 80, 80.0), entry("read", 20, 20.0)];
    let after = vec![entry("parse", 50, 50.0), entry("write", 50, 50.0)];

    let diff = diff_flamegraphs(&before, &after, 0.01);

    assert_eq!(diff[0].name, "write");
    assert_float_eq(diff[0].before_percent, 0.0);
    assert_float_eq(diff[0].after_percent, 50.0);
    assert_float_eq(diff[0].delta_percent, 50.0);
    assert_eq!(diff[1].name, "parse");
    assert_float_eq(diff[1].delta_percent, -30.0);
}

#[test]
fn diff_aggregates_disjoint_occurrences_of_the_same_function() {
    let before = vec![entry("work", 60, 60.0), entry("work", 40, 40.0)];
    let after = vec![entry("work", 80, 80.0), entry("work", 20, 20.0)];
    assert!(diff_flamegraphs(&before, &after, 0.01).is_empty());
}

#[test]
fn native_svg_diff_counts_recursive_functions_once_and_keeps_disjoint_samples() {
    let render = |lines: &[&str], direction| {
        let mut options = inferno::flamegraph::Options::default();
        options.direction = direction;
        let mut svg = Vec::new();
        inferno::flamegraph::from_lines(&mut options, lines.iter().copied(), &mut svg).unwrap();
        String::from_utf8(svg).unwrap()
    };
    for direction in [
        inferno::flamegraph::Direction::Straight,
        inferno::flamegraph::Direction::Inverted,
    ] {
        let before = render(&["main;work;helper;work 60", "other;work 40"], direction);
        let after = render(&["main;work 80", "other;work 20"], direction);
        let diff = diff_flamegraph_svgs(&before, &after, 0.01).unwrap();
        assert!(!diff.iter().any(|delta| delta.name == "work"));
        let helper = diff.iter().find(|delta| delta.name == "helper").unwrap();
        assert_eq!(helper.before_samples, 60);
        assert_float_eq(helper.delta_percent, -60.0);
    }
}

#[test]
fn native_flamegraph_categories_count_exclusive_samples_once() {
    let mut options = inferno::flamegraph::Options::default();
    let mut svg = Vec::new();
    inferno::flamegraph::from_lines(
        &mut options,
        [
            "main;tokio::runtime;zfs_read 60",
            "main;tokio::runtime;tokio::runtime 40",
        ],
        &mut svg,
    )
    .unwrap();
    let categories = parse_flamegraph_categories(std::str::from_utf8(&svg).unwrap()).unwrap();
    assert_eq!(categories.len(), 2);
    assert_eq!(categories[0].name, "Disk I/O");
    assert_float_eq(categories[0].percent, 60.0);
    assert_eq!(categories[1].name, "Tokio Runtime");
    assert_float_eq(categories[1].percent, 40.0);
}

#[test]
fn category_summary_requires_rectangle_topology_instead_of_guessing() {
    assert!(
        parse_flamegraph_categories("<svg><title>work (2 samples, 100%)</title></svg>").is_err()
    );
}

#[test]
fn native_inverted_flamegraph_preserves_parent_self_time() {
    let mut options = inferno::flamegraph::Options::default();
    options.direction = inferno::flamegraph::Direction::Inverted;
    let mut svg = Vec::new();
    inferno::flamegraph::from_lines(
        &mut options,
        ["tokio::runtime 25", "tokio::runtime;zfs_read 75"],
        &mut svg,
    )
    .unwrap();
    let categories = parse_flamegraph_categories(std::str::from_utf8(&svg).unwrap()).unwrap();
    assert_eq!(categories[0].name, "Disk I/O");
    assert_float_eq(categories[0].percent, 75.0);
    assert_eq!(categories[1].name, "Tokio Runtime");
    assert_float_eq(categories[1].percent, 25.0);
}

#[test]
fn flamegraph_parser_decodes_xml_symbol_entities() {
    let entries = parse_flamegraph_entries(
        "<svg><g><title>read&lt;T&gt;&amp;work (2 samples, 100%)</title></g></svg>",
    );
    assert_eq!(entries[0].name, "read<T>&work");
}

#[test]
fn categorizes_frames_for_agent_summaries() {
    assert_eq!(
        categorize_flamegraph_frame("tokio::runtime::park"),
        "Tokio Runtime"
    );
    assert_eq!(categorize_flamegraph_frame("zfs_read"), "Disk I/O");
    assert_eq!(categorize_flamegraph_frame("__x64_sys_read"), "Syscall");
}

fn entry(name: &str, samples: u64, percent: f64) -> FlamegraphEntry {
    FlamegraphEntry {
        name: name.to_string(),
        samples,
        percent,
    }
}

fn assert_float_eq(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < f64::EPSILON,
        "expected {actual} to equal {expected}"
    );
}

proptest! {
    #[test]
    fn property_parses_svg_titles_and_sorts_by_percent_then_name(
        entries in prop::collection::vec(flamegraph_entry(), 0..64),
    ) {
        let svg = render_svg(&entries);
        let mut expected = entries.clone();
        expected.sort_by(|left, right| {
            right
                .percent
                .total_cmp(&left.percent)
                .then_with(|| left.name.cmp(&right.name))
        });

        prop_assert_eq!(parse_flamegraph_entries(&svg), expected);
    }

    #[test]
    fn property_top_entries_match_filter_sort_and_limit(
        entries in prop::collection::vec(flamegraph_entry(), 0..64),
        limit in 0_usize..16,
        min_percent in 0_u8..=100_u8,
    ) {
        let mut expected = entries
            .iter()
            .filter(|entry| entry.percent >= f64::from(min_percent))
            .cloned()
            .collect::<Vec<_>>();
        expected.sort_by(|left, right| {
            right
                .percent
                .total_cmp(&left.percent)
                .then_with(|| left.name.cmp(&right.name))
        });
        expected.truncate(limit);

        prop_assert_eq!(top_entries(&entries, limit, f64::from(min_percent)), expected);
    }
}

fn flamegraph_entry() -> impl Strategy<Value = FlamegraphEntry> {
    (flamegraph_name(), any::<u64>(), 0_u8..=100_u8).prop_map(|(name, samples, percent)| {
        FlamegraphEntry {
            name,
            samples,
            percent: f64::from(percent),
        }
    })
}

fn flamegraph_name() -> impl Strategy<Value = String> {
    string_regex(r"[A-Za-z_][A-Za-z0-9_:]{0,15}")
        .expect("valid flamegraph name regex")
        .prop_filter("exclude reserved aggregate frame", |name| name != "all")
}

fn render_svg(entries: &[FlamegraphEntry]) -> String {
    let mut svg = String::from("<svg><title>all (1,000 samples, 100%)</title>");
    for entry in entries {
        let _ = write!(
            svg,
            "<g><title>{} ({} samples, {}%)</title></g>",
            entry.name,
            format_with_commas(entry.samples),
            entry.percent,
        );
    }
    svg.push_str("</svg>");
    svg
}

fn format_with_commas(value: u64) -> String {
    let digits = value.to_string();
    let mut formatted = String::with_capacity(digits.len() + digits.len() / 3);

    for (index, character) in digits.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            formatted.push(',');
        }
        formatted.push(character);
    }

    formatted.chars().rev().collect()
}
use std::fmt::Write as _;
