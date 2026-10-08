use proptest::prelude::*;
use proptest::string::string_regex;
use pyroclast::flamegraph::analysis::{
    FlamegraphEntry, categorize_flamegraph_frame, diff_flamegraphs, parse_flamegraph, top_entries,
};

#[test]
fn parses_inferno_sample_ranges() {
    let svg = ranged_svg(
        r#"
  <g><title>read (25 samples, 25.00%)</title><rect fg:x="0" fg:w="25" y="80"/></g>
  <g><title>tokio::runtime::park (12 samples, 12.00%)</title><rect fg:x="25" fg:w="12" y="80"/></g>
"#,
    );

    let entries = parse_flamegraph(&svg).expect("profile").inclusive;

    assert_eq!(
        entries,
        vec![
            FlamegraphEntry {
                name: "read".to_string(),
                samples: 25,
                percent: 25.0,
            },
            FlamegraphEntry {
                name: "tokio::runtime::park".to_string(),
                samples: 12,
                percent: 12.0,
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
    let svg = ranged_svg(
        r#"
      <g><title>__x64_sys_read (30 samples, 30%)</title><rect fg:x="0" fg:w="30" y="80"/></g>
      <g><title>__x86_sys_write (20 samples, 20%)</title><rect fg:x="30" fg:w="20" y="80"/></g>"#,
    );
    let syscalls = parse_flamegraph(&svg).expect("profile").syscalls;

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
fn categorizes_frames_for_agent_summaries() {
    assert_eq!(
        categorize_flamegraph_frame("tokio::runtime::park"),
        "Tokio Runtime"
    );
    assert_eq!(categorize_flamegraph_frame("zfs_read"), "Disk I/O");
    assert_eq!(categorize_flamegraph_frame("__x64_sys_read"), "Syscall");
}

#[test]
fn cli_top_unions_repeated_and_recursive_function_ranges() {
    let svg = ranged_svg(
        r#"<g><title>work (70 samples, 70%)</title><rect fg:x="0" fg:w="70" y="64"/></g>
        <g><title>work (40 samples, 40%)</title><rect fg:x="10" fg:w="40" y="48"/></g>
        <g><title>work (20 samples, 20%)</title><rect fg:x="80" fg:w="20" y="64"/></g>"#,
    );
    let output = analyze_svg(&svg, "top").expect("analysis");
    assert_eq!(output.as_array().expect("entries").len(), 1);
    assert_eq!(output[0]["samples"], 90);
    assert_eq!(output[0]["percent"], 90.0);
}

#[test]
fn cli_summary_partitions_samples_by_deepest_visible_frame() {
    let svg = ranged_svg(
        r#"<g><title>app (100 samples, 100%)</title><rect fg:x="0" fg:w="100" y="80"/></g>
        <g><title>tokio::runtime (70 samples, 70%)</title><rect fg:x="0" fg:w="70" y="64"/></g>
        <g><title>zfs_read (40 samples, 40%)</title><rect fg:x="0" fg:w="40" y="48"/></g>
        <g><title>rustls::encrypt (30 samples, 30%)</title><rect fg:x="40" fg:w="30" y="48"/></g>"#,
    );
    let output = analyze_svg(&svg, "summary").expect("analysis");
    assert_eq!(output[0]["name"], "Disk I/O");
    assert_eq!(output[0]["percent"], 40.0);
    let percent: f64 = output
        .as_array()
        .expect("categories")
        .iter()
        .map(|row| row["percent"].as_f64().expect("percentage"))
        .sum();
    assert_float_eq(percent, 100.0);
    assert!(
        !output
            .as_array()
            .expect("categories")
            .iter()
            .any(|row| row["name"] == "Tokio Runtime")
    );
}

#[test]
fn cli_analysis_decodes_xml_function_names() {
    let svg = ranged_svg(
        r#"<g><title>&lt;Cache&lt;T&gt; as Trait&gt;::get &amp; check (100 samples, 100%)</title><rect fg:x="0" fg:w="100" y="80"/></g>"#,
    );
    let output = analyze_svg(&svg, "top").expect("analysis");
    assert_eq!(output[0]["name"], "<Cache<T> as Trait>::get & check");
}

#[test]
fn cli_analysis_rejects_frames_outside_declared_sample_range() {
    let svg = ranged_svg(
        r#"<g><title>work (10 samples, 10%)</title><rect fg:x="95" fg:w="10" y="80"/></g>"#,
    );
    assert!(analyze_svg(&svg, "top").is_err());
}

#[test]
fn analyze_shortcut_reports_inclusive_self_categories_and_syscalls() {
    use clap::Parser as _;
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.svg");
    std::fs::write(
        &path,
        ranged_svg(
            r#"
        <g><title>app (100 samples, 100%)</title><rect fg:x="0" fg:w="100" y="80"/></g>
        <g><title>__arm64_sys_read (30 samples, 30%)</title><rect fg:x="0" fg:w="30" y="64"/></g>"#,
        ),
    )
    .expect("SVG");
    let cli = pyroclast::cli::Cli::try_parse_from([
        "pyroclast",
        "analyze",
        path.to_str().expect("path"),
        "--json",
        "--limit",
        "1",
    ])
    .expect("analyze shortcut");
    let output = pyroclast::run_parsed_cli(cli).expect("analysis");
    let report: serde_json::Value = serde_json::from_str(&output.stdout).expect("JSON");
    assert_eq!(report["total_samples"], 100);
    assert_eq!(report["inclusive"].as_array().expect("inclusive").len(), 1);
    assert_eq!(report["inclusive"][0]["name"], "app");
    assert_eq!(report["self_samples"][0]["name"], "app");
    assert_eq!(report["self_samples"][0]["samples"], 70);
    assert_eq!(report["any_syscall_samples"], 30);
    assert_eq!(report["syscalls"][0]["name"], "read");
    assert_eq!(report["categories"][0]["name"], "Other");
}

#[test]
fn real_inferno_normal_and_inverted_graphs_have_identical_accounting() {
    use inferno::flamegraph::{Direction, Options};
    let stacks = "app;work;work;<T as Trait>::get 40\napp;work;rustls::encrypt 30\napp;__arm64_sys_read 20\napp 10\n";
    let render = |direction| {
        let mut options = Options::default();
        options.direction = direction;
        // Titles use scaled/custom units; fg:x/fg:w remain exact raw weights.
        options.factor = 2.0;
        options.count_name = "bytes".to_owned();
        let mut svg = Vec::new();
        inferno::flamegraph::from_lines(&mut options, stacks.lines(), &mut svg)
            .expect("Inferno SVG");
        parse_flamegraph(std::str::from_utf8(&svg).expect("UTF-8 SVG")).expect("profile")
    };
    let profile = render(Direction::Straight);
    assert_eq!(profile, render(Direction::Inverted));
    assert_eq!(profile.total_samples, 100);
    assert_eq!(
        profile
            .inclusive
            .iter()
            .find(|entry| entry.name == "work")
            .expect("work")
            .samples,
        70
    );
    assert_eq!(
        profile
            .self_samples
            .iter()
            .find(|entry| entry.name == "<T as Trait>::get")
            .expect("decoded name")
            .samples,
        40
    );
    assert_eq!(
        profile
            .self_samples
            .iter()
            .find(|entry| entry.name == "app")
            .expect("app")
            .samples,
        10
    );
    assert_eq!(profile.any_syscall_samples, 20);
}

#[test]
fn syscall_ranges_are_unioned_across_recursive_and_architecture_wrappers() {
    let svg = ranged_svg(
        r#"
        <g><title>__x64_sys_read (60 samples, 60%)</title><rect fg:x="0" fg:w="60" y="80"/></g>
        <g><title>__ia32_sys_read (40 samples, 40%)</title><rect fg:x="10" fg:w="40" y="64"/></g>
        <g><title>__arm64_sys_write (20 samples, 20%)</title><rect fg:x="20" fg:w="20" y="48"/></g>
        <g><title>__x86_sys_read (20 samples, 20%)</title><rect fg:x="80" fg:w="20" y="80"/></g>"#,
    );
    let profile = parse_flamegraph(&svg).expect("profile");
    assert_eq!(
        profile.syscalls,
        vec![entry("read", 80, 80.0), entry("write", 20, 20.0)]
    );
    assert_eq!(profile.any_syscall_samples, 80);
}

#[test]
fn rejects_missing_geometry_overflow_nonfinite_coordinates_and_truncated_xml() {
    for frame in [
        r"<g><title>work (10 samples, 10%)</title></g>",
        r#"<g><title>work (10 samples, 10%)</title><rect x="0" width="10" y="80"/></g>"#,
        r#"<g><title>work (10 samples, 10%)</title><rect fg:x="18446744073709551615" fg:w="1" y="80"/></g>"#,
        r#"<g><title>work (10 samples, 10%)</title><rect fg:x="0" fg:w="10" y="NaN"/></g>"#,
        r#"<g><title>work (10 samples, 10%)</title><rect fg:x="0" fg:w="10" y="80"/></a>"#,
    ] {
        assert!(
            parse_flamegraph(&ranged_svg(frame)).is_err(),
            "accepted {frame}"
        );
    }
    assert!(parse_flamegraph("<svg><g>").is_err());
    assert!(parse_flamegraph("not a flamegraph").is_err());
}

#[test]
fn parses_linked_frames_single_quoted_attributes_and_explicit_rect_end_tags() {
    let svg = ranged_svg(
        r"<a href='file:///source.rs'><title>foo&#58;&#58;bar (100 samples, 100%)</title><rect y='80.5' fg:w='100' fg:x='0'></rect></a>",
    );
    assert_eq!(
        parse_flamegraph(&svg).expect("profile").inclusive,
        vec![entry("foo::bar", 100, 100.0)]
    );
}

#[test]
fn real_inferno_differential_titles_do_not_change_sample_accounting() {
    let mut options = inferno::flamegraph::Options::default();
    let mut svg = Vec::new();
    inferno::flamegraph::from_lines(&mut options, ["app;work 50 70", "app;read 50 30"], &mut svg)
        .expect("differential SVG");
    let profile = parse_flamegraph(std::str::from_utf8(&svg).expect("UTF-8 SVG")).expect("profile");
    assert_eq!(profile.total_samples, 100);
    assert_eq!(
        profile.self_samples,
        vec![entry("work", 70, 70.0), entry("read", 30, 30.0)]
    );
}

#[test]
fn rendering_minimum_width_leaves_hidden_samples_at_visible_parent() {
    let mut options = inferno::flamegraph::Options::default();
    options.min_width = 2.0;
    let mut svg = Vec::new();
    inferno::flamegraph::from_lines(&mut options, ["app;tiny 1", "app;work 9999"], &mut svg)
        .expect("SVG");
    let profile = parse_flamegraph(std::str::from_utf8(&svg).expect("UTF-8 SVG")).expect("profile");
    assert_eq!(profile.total_samples, 10000);
    assert!(!profile.inclusive.iter().any(|entry| entry.name == "tiny"));
    assert_eq!(
        profile
            .self_samples
            .iter()
            .find(|entry| entry.name == "app")
            .expect("visible parent")
            .samples,
        1
    );
    assert_eq!(
        profile
            .categories
            .iter()
            .map(|category| category.samples)
            .sum::<u64>(),
        10000
    );
}

#[test]
fn analyze_binary_prints_compact_text_report_without_running_a_profiler() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.svg");
    let mut svg = Vec::new();
    inferno::flamegraph::from_lines(
        &mut inferno::flamegraph::Options::default(),
        ["app;work 70", "app;__x64_sys_read 30"],
        &mut svg,
    )
    .expect("SVG");
    std::fs::write(&path, svg).expect("write SVG");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pyroclast"))
        .arg("analyze")
        .arg(&path)
        .args(["--limit", "1"])
        .output()
        .expect("analyze");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout).expect("text");
    assert!(report.starts_with("100 sample units\n"));
    assert!(report.contains("Inclusive coverage (rows overlap)"));
    assert!(report.contains("Self coverage (deepest visible frame)"));
    assert!(report.contains("Exclusive categories (all samples)"));
    assert!(report.contains("Syscall coverage (rows may overlap)"));
    assert!(report.contains("Any syscall: 30 sample units"));
    assert!(output.stderr.is_empty());
}

#[test]
fn keeps_full_u64_weights_even_when_percentages_require_rounding() {
    let total = u64::MAX;
    let svg = format!(
        r#"<svg total_samples="{total}">
        <g><title>all ({total} samples, 100%)</title><rect fg:x="0" fg:w="{total}" y="96"/></g>
        <g><title>work ({total} samples, 100%)</title><rect fg:x="0" fg:w="{total}" y="80"/></g></svg>"#
    );
    let profile = parse_flamegraph(&svg).expect("profile");
    assert_eq!(profile.inclusive, vec![entry("work", total, 100.0)]);
    assert_eq!(profile.self_samples, profile.inclusive);
    assert_eq!(profile.categories[0].samples, total);
}

fn ranged_svg(frames: &str) -> String {
    format!(
        r#"<svg xmlns:fg="http://github.com/jonhoo/inferno"><svg id="frames" total_samples="100">
        <g><title>all (100 samples, 100%)</title><rect fg:x="0" fg:w="100" y="96"/></g>
        {frames}</svg></svg>"#
    )
}

fn analyze_svg(
    svg: &str,
    mode: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("profile.svg");
    std::fs::write(&path, svg)?;
    let output = pyroclast::run_cli([
        "pyroclast",
        "plumbing",
        "parse",
        "flamegraph",
        mode,
        "--json",
        path.to_str().expect("SVG path"),
    ])?;
    Ok(serde_json::from_str(&output.stdout)?)
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
    fn property_unions_disjoint_function_ranges_and_partitions_self_samples(
        entries in prop::collection::vec((flamegraph_name(), 1_u16..1000), 1..64),
    ) {
        let mut counts = std::collections::BTreeMap::<String, u64>::new();
        let mut frames = String::new();
        let mut total = 0_u64;
        for (name, samples) in entries {
            let samples = u64::from(samples);
            write!(frames, r#"<g><title>{name} ({samples} samples, 0%)</title><rect fg:x="{total}" fg:w="{samples}" y="80"/></g>"#).expect("frame");
            *counts.entry(name).or_default() += samples;
            total += samples;
        }
        let svg = format!(r#"<svg total_samples="{total}"><g><title>all ({total} samples, 100%)</title><rect fg:x="0" fg:w="{total}" y="96"/></g>{frames}</svg>"#);
        let profile = parse_flamegraph(&svg).expect("profile");
        prop_assert_eq!(profile.total_samples, total);
        prop_assert_eq!(&profile.inclusive, &profile.self_samples);
        prop_assert_eq!(profile.self_samples.iter().map(|entry| entry.samples).sum::<u64>(), total);
        for entry in profile.inclusive {
            prop_assert_eq!(entry.samples, counts[&entry.name]);
            let expected = f64::from(u32::try_from(entry.samples).expect("test samples"))
                / f64::from(u32::try_from(total).expect("test total")) * 100.0;
            prop_assert!((entry.percent - expected).abs() < f64::EPSILON);
        }
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

use std::fmt::Write as _;
