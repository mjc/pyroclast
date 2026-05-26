use pyroclast::flamegraph::analysis::{
    FlamegraphEntry, categorize_flamegraph_frame, diff_flamegraphs, parse_flamegraph_entries,
    syscall_breakdown, top_entries,
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
