use proptest::prelude::*;
use proptest::string::string_regex;
use pyroclast::parsers::xctrace::parse_cpu_profile;

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

        prop_assert_eq!(profile.rows.len(), rows.len());
        prop_assert_eq!(
            profile.total_weight,
            rows.iter().fold(0.0, |total, (_, weight)| total + f64::from(*weight)),
        );

        for (actual, (symbol, weight)) in profile.rows.iter().zip(&rows) {
            prop_assert_eq!(&actual.symbol, symbol.trim());
            prop_assert_eq!(actual.weight, f64::from(*weight));
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
    string_regex(r"[A-Za-z_: ][A-Za-z0-9_: ]{0,15}").expect("valid xctrace symbol regex")
}

fn render_profile_xml(rows: &[(String, u16)], malformed_rows: &[String]) -> String {
    let mut xml = String::from("<table>");
    for (symbol, weight) in rows {
        xml.push_str(&format!(
            "<row><symbol>{symbol}</symbol><weight>{weight}</weight></row>"
        ));
    }
    for row in malformed_rows {
        xml.push_str(row);
    }
    xml.push_str("</table>");
    xml
}
