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
    assert_eq!(profile.rows[0].weight, 12.5);
    assert_eq!(profile.rows[1].symbol, "tokio::park");
    assert_eq!(profile.total_weight, 15.5);
}
