use std::ffi::OsString;
use std::path::Path;

use clap::Parser as _;
use serde_json::Value;

#[test]
fn analyze_exposes_script_modes_and_self_sample_views() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.svg");
    write_svg(
        &path,
        &["app;work;work 60", "app;__x64_sys_read 30", "app 10"],
    );
    let top = analyze(&path, &["top", "--json", "--limit", "1"]);
    assert_eq!(top[0]["name"], "app");
    let own = analyze(&path, &["top", "--self", "--json", "--limit", "1"]);
    assert_eq!(own[0]["name"], "work");
    assert_eq!(own[0]["samples"], 60);
    let search = analyze(&path, &["search", "WORK", "--self", "--json"]);
    assert_eq!(search[0]["name"], "work");
    let syscalls = analyze(&path, &["syscalls", "--json"]);
    assert_eq!(syscalls[0]["name"], "read");
    let summary = analyze(&path, &["summary", "--json"]);
    assert_eq!(summary[0]["name"], "Other");
    assert_eq!(summary[0]["samples"], 70);
}

#[test]
fn search_includes_small_matches_and_respects_explicit_thresholds() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.svg");
    write_svg(&path, &["app;rare 1", "app;work 9999"]);
    let search = analyze(&path, &["search", "rare", "--json"]);
    assert_eq!(search.as_array().expect("entries").len(), 1);
    assert_eq!(search[0]["samples"], 1);
    let filtered = analyze(&path, &["search", "rare", "--min-percent", "1", "--json"]);
    assert!(filtered.as_array().expect("entries").is_empty());
}

#[test]
fn diff_supports_inclusive_and_self_metrics_with_shared_row_limits() {
    let directory = tempfile::tempdir().expect("directory");
    let before = directory.path().join("before.svg");
    let after = directory.path().join("after.svg");
    write_svg(&before, &["app;work 80", "app;read 20"]);
    write_svg(&after, &["app;work 40", "app;read 20", "app 40"]);
    let path = after.to_str().expect("path");
    let inclusive = analyze(&before, &["diff", path, "--json"]);
    assert_eq!(inclusive.as_array().expect("deltas").len(), 1);
    assert_eq!(inclusive[0]["name"], "work");
    assert_eq!(inclusive[0]["delta_percent"], -40.0);
    let own = analyze(&before, &["diff", path, "--self", "--json", "--limit", "1"]);
    assert_eq!(own.as_array().expect("deltas").len(), 1);
    assert_eq!(own[0]["name"], "app");
    assert_eq!(own[0]["delta_percent"], 40.0);
}

#[test]
fn analysis_rejects_nonfinite_negative_and_out_of_range_percentages() {
    for threshold in ["NaN", "inf", "-1", "101"] {
        assert!(
            pyroclast::cli::Cli::try_parse_from([
                "pyroclast",
                "analyze",
                "profile.svg",
                "--min-percent",
                threshold,
            ])
            .is_err(),
            "accepted {threshold}"
        );
    }
}

#[test]
fn project_category_rules_are_ordered_case_insensitive_and_keep_builtin_fallbacks() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.svg");
    let rules = directory.path().join("categories.json");
    write_svg(
        &path,
        &[
            "app;build::writer::copy_from_7z_archive 40",
            "app;zstd::decompress 30",
            "app;sqlite3_step 20",
            "app;malloc 10",
        ],
    );
    std::fs::write(
        &rules,
        r#"[
        {"name":"Writer","contains":["BUILD::WRITER"]},
        {"name":"Archive","contains":["7z","zstd"]},
        {"name":"SQLite","contains":["sqlite"]}
    ]"#,
    )
    .expect("rules");
    let report = analyze(
        &path,
        &[
            "--categories",
            rules.to_str().expect("path"),
            "--limit",
            "1",
            "--json",
        ],
    );
    assert_eq!(report["inclusive"][0]["name"], "app");
    let categories = report["categories"].as_array().expect("categories");
    let names = categories
        .iter()
        .map(|row| row["name"].as_str().expect("name"))
        .collect::<Vec<_>>();
    assert_eq!(names, ["Writer", "Archive", "SQLite", "Memory"]);
    assert_eq!(categories[0]["samples"], 40);
    assert_eq!(
        categories[0]["inclusive_functions"][0]["name"],
        "build::writer::copy_from_7z_archive"
    );
    assert_eq!(
        categories[1]["inclusive_functions"][0]["name"],
        "zstd::decompress"
    );
    assert_eq!(
        categories
            .iter()
            .map(|row| row["samples"].as_u64().expect("samples"))
            .sum::<u64>(),
        100
    );
    let summary = analyze(
        &path,
        &[
            "summary",
            "--categories",
            rules.to_str().expect("path"),
            "--limit",
            "1",
            "--json",
        ],
    );
    assert_eq!(&summary, &report["categories"]);
}

#[test]
fn category_key_functions_use_inclusive_ranges_without_summing_recursion() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.svg");
    write_svg(
        &path,
        &[
            "app;zstd::decompress;zstd::decompress 40",
            "app;other 1",
            "app;lz4::decode 59",
        ],
    );
    let summary = analyze(&path, &["summary", "--json", "--limit", "1"]);
    assert_eq!(summary[0]["name"], "Compression");
    assert_eq!(summary[0]["samples"], 99);
    assert_eq!(
        summary[0]["inclusive_functions"]
            .as_array()
            .expect("functions")
            .len(),
        1
    );
    assert_eq!(summary[0]["inclusive_functions"][0]["name"], "lz4::decode");
    let summary = analyze(&path, &["summary", "--json", "--limit", "2"]);
    assert_eq!(summary[0]["inclusive_functions"][1]["samples"], 40);
}

#[test]
fn category_totals_remain_complete_when_key_function_tables_are_filtered() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.svg");
    write_svg(&path, &["app;zstd::decompress 60", "app;malloc 40"]);
    let summary = analyze(
        &path,
        &["summary", "--json", "--min-percent", "100", "--limit", "0"],
    );
    assert_eq!(summary.as_array().expect("categories").len(), 2);
    assert_eq!(summary[0]["samples"], 60);
    assert_eq!(summary[1]["samples"], 40);
    assert!(summary[0].get("inclusive_functions").is_none());
    assert!(summary[1].get("inclusive_functions").is_none());
}

#[test]
fn rejects_invalid_category_files_instead_of_silently_using_defaults() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.svg");
    let rules = directory.path().join("categories.json");
    write_svg(&path, &["app;work 100"]);
    for json in [
        "not JSON",
        r#"[{"name":"","contains":["work"]}]"#,
        r#"[{"name":"Work","contains":[]}]"#,
        r#"[{"name":"Work","contains":[" "]}]"#,
        r#"[{"name":"Work","contains":["work"],"regex":true}]"#,
    ] {
        std::fs::write(&rules, json).expect("rules");
        let cli = pyroclast::cli::Cli::try_parse_from([
            "pyroclast",
            "analyze",
            path.to_str().expect("path"),
            "--categories",
            rules.to_str().expect("path"),
        ])
        .expect("arguments");
        assert!(pyroclast::run_parsed_cli(cli).is_err(), "accepted {json}");
    }
}

fn write_svg(path: &Path, stacks: &[&str]) {
    let mut svg = Vec::new();
    let mut options = inferno::flamegraph::Options::default();
    options.min_width = 0.0;
    inferno::flamegraph::from_lines(&mut options, stacks.iter().copied(), &mut svg).expect("SVG");
    std::fs::write(path, svg).expect("write SVG");
}

fn analyze(path: &Path, arguments: &[&str]) -> Value {
    let args = [
        OsString::from("pyroclast"),
        OsString::from("analyze"),
        path.as_os_str().to_owned(),
    ]
    .into_iter()
    .chain(arguments.iter().map(OsString::from));
    let cli = pyroclast::cli::Cli::try_parse_from(args).expect("analyze arguments");
    let output = pyroclast::run_parsed_cli(cli).expect("analysis");
    serde_json::from_str(&output.stdout).expect("JSON")
}
