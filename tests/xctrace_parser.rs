use std::fmt::Write as _;

use proptest::prelude::*;
use proptest::string::string_regex;
use pyroclast::parsers::xctrace::{
    XctraceWeightUnit, parse_cpu_profile, parse_cpu_profile_for_pid,
    render_cpu_profile_summary_text,
};

#[test]
fn parses_live_xcode27_cpu_profiler_cycle_samples() {
    // First four samples of a genuine CPU Profiler export; only workload PID/path
    // were anonymized. Unlike Time Profiler, CPU Profiler measures cycle-weight.
    let xml = include_str!("fixtures/xctrace/cpu-profile-xcode27.xml");
    let profile = parse_cpu_profile_for_pid(xml, Some(7)).unwrap();
    assert_eq!(profile.rows.len(), 4);
    assert_eq!(profile.rows[2].symbol, "hot_loop");
    assert_eq!(profile.rows[3].symbol, "hot_loop");
    assert_float_eq(profile.total_weight, 2_024_198.0);
    assert_eq!(profile.weight_unit, XctraceWeightUnit::Cycles);
    assert!(render_cpu_profile_summary_text(&profile).contains("xctrace weight unit: cycles\n"));
    assert_eq!(
        serde_json::to_value(&profile).unwrap()["weight_unit"],
        "cycles"
    );
    assert!(parse_cpu_profile_for_pid(xml, Some(8)).is_err());
}

#[test]
fn rejects_mixed_cycle_and_time_weights() {
    for xml in [
        "<table><row><symbol>time</symbol><weight>100</weight></row><row><symbol>cycles</symbol><cycle-weight>200</cycle-weight></row></table>",
        "<table><row><symbol>both</symbol><weight>100</weight><cycle-weight>200</cycle-weight></row></table>",
    ] {
        assert!(
            parse_cpu_profile_for_pid(xml, None)
                .unwrap_err()
                .contains("mixed")
        );
    }
}

#[test]
fn parses_referenced_native_cells_frame_attributes_and_target_process() {
    let xml = r#"<trace-query-result><node><schema name="time-profile"/>
    <row><thread id="t"><tid>11</tid><process id="p"><pid>7</pid></process></thread><weight id="w" fmt="1 ms">1000000</weight><backtrace id="b"><frame id="f" name="app::read&lt;T&gt;"/><frame name="main"/></backtrace></row>
    <row><thread ref="t"/><weight ref="w"/><backtrace ref="b"/></row>
    <row><process><pid>8</pid></process><weight>5000000</weight><backtrace><frame name="other"/></backtrace></row>
    </node></trace-query-result>"#;
    let profile = parse_cpu_profile_for_pid(xml, Some(7)).unwrap();
    assert_eq!(profile.rows.len(), 2);
    assert_eq!(profile.rows[0].symbol, "app::read<T>");
    assert_float_eq(profile.total_weight, 2_000_000.0);
    assert_eq!(profile.weight_unit, XctraceWeightUnit::Nanoseconds);
}

#[test]
fn rejects_malformed_exports_and_unmatched_target_without_silent_empty_success() {
    assert!(parse_cpu_profile_for_pid("<table>", None).is_err());
    assert!(
        parse_cpu_profile_for_pid(
            "<table><row><symbol>work</symbol><weight>1</weight></row></table>",
            Some(123)
        )
        .is_err()
    );
    assert!(
        parse_cpu_profile_for_pid(
            "<table><row><symbol>work</symbol><weight>NaN</weight></row></table>",
            None
        )
        .is_err()
    );
}

#[test]
fn rejects_missing_and_cyclic_native_references() {
    for cells in [
        "<symbol ref=\"missing\"/><weight>1</weight>",
        "<symbol id=\"s\" ref=\"s\"/><weight>1</weight>",
    ] {
        assert!(
            parse_cpu_profile_for_pid(&format!("<table><row>{cells}</row></table>"), None).is_err()
        );
    }
}

#[test]
fn rejects_blank_symbols_and_indirect_backtrace_cycles() {
    for cells in [
        "<symbol> </symbol><weight>1</weight>",
        "<weight>1</weight><backtrace id=\"b\"><backtrace ref=\"b\"/></backtrace>",
    ] {
        assert!(
            parse_cpu_profile_for_pid(&format!("<table><row>{cells}</row></table>"), None).is_err()
        );
    }
}

fn assert_float_eq(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < f64::EPSILON);
}

#[test]
fn parses_xctrace_cpu_symbols() {
    let xml = "\
<table>
  <row><symbol>app::main</symbol><weight>12.5</weight></row>
  <row><symbol>tokio::park</symbol><weight>3</weight></row>
</table>";

    let profile = parse_cpu_profile(xml);

    assert_eq!(profile.rows.len(), 2);
    assert_eq!(profile.rows[0].symbol, "app::main");
    assert!((profile.rows[0].weight - 12.5).abs() < f64::EPSILON);
    assert_eq!(profile.rows[1].symbol, "tokio::park");
    assert!((profile.total_weight - 15.5).abs() < f64::EPSILON);
}

proptest! {
    #[test]
    fn property_parses_all_well_formed_rows_in_order(
        rows in prop::collection::vec((symbol_name(), 0_u16..10_000_u16), 0..64),
    ) {
        let xml = render_profile_xml(&rows, &[]);
        let profile = parse_cpu_profile(&xml);
        let expected_total_weight = rows
            .iter()
            .fold(0.0, |total, (_, weight)| total + f64::from(*weight));

        prop_assert_eq!(profile.rows.len(), rows.len());
        prop_assert!((profile.total_weight - expected_total_weight).abs() < f64::EPSILON);

        for (actual, (symbol, weight)) in profile.rows.iter().zip(&rows) {
            prop_assert_eq!(&actual.symbol, symbol.trim());
            prop_assert!((actual.weight - f64::from(*weight)).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn property_ignores_rows_missing_required_fields(
        rows in prop::collection::vec((symbol_name(), 0_u16..10_000_u16), 0..32),
        malformed in prop::collection::vec(string_regex(r"[A-Za-z_: ]{1,24}").expect("valid regex"), 0..32),
    ) {
        let malformed_rows = malformed
            .iter()
            .map(|symbol| format!("<row><symbol>{symbol}</symbol></row>"))
            .collect::<Vec<_>>();
        let xml = render_profile_xml(&rows, &malformed_rows);
        let profile = parse_cpu_profile(&xml);

        prop_assert_eq!(profile.rows.len(), rows.len());
    }
}

fn symbol_name() -> impl Strategy<Value = String> {
    string_regex(r"[A-Za-z_: ][A-Za-z0-9_: ]{0,15}")
        .expect("valid xctrace symbol regex")
        .prop_filter("symbol contains a non-whitespace name", |symbol| {
            !symbol.trim().is_empty()
        })
}

fn render_profile_xml(rows: &[(String, u16)], malformed_rows: &[String]) -> String {
    let mut xml = String::from("<table>");
    for (symbol, weight) in rows {
        let _ = write!(
            xml,
            "<row><symbol>{symbol}</symbol><weight>{weight}</weight></row>"
        );
    }
    for row in malformed_rows {
        xml.push_str(row);
    }
    xml.push_str("</table>");
    xml
}
