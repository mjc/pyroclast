use std::fmt::Write as _;

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct XctraceCpuProfile {
    pub rows: Vec<XctraceCpuRow>,
    pub total_weight: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct XctraceCpuRow {
    pub symbol: String,
    pub weight: f64,
}

#[must_use]
pub fn parse_cpu_profile(xml: &str) -> XctraceCpuProfile {
    let mut rows = Vec::new();

    for row in xml.split("<row>").skip(1) {
        let Some(row) = row.split("</row>").next() else {
            continue;
        };
        let Some(symbol) = tag_text(row, "symbol") else {
            continue;
        };
        let Some(weight) = tag_text(row, "weight").and_then(|text| text.parse().ok()) else {
            continue;
        };
        rows.push(XctraceCpuRow {
            symbol: symbol.to_string(),
            weight,
        });
    }

    let total_weight = rows.iter().map(|row| row.weight).sum();
    XctraceCpuProfile { rows, total_weight }
}

fn tag_text<'a>(input: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = input.find(&open)? + open.len();
    let end = input[start..].find(&close)? + start;
    Some(input[start..end].trim())
}

#[must_use]
pub fn render_cpu_profile_summary_text(profile: &XctraceCpuProfile) -> String {
    let mut summary = format!(
        "xctrace rows: {}\nxctrace total weight: {:.6}\n",
        profile.rows.len(),
        profile.total_weight
    );
    for row in &profile.rows {
        let _ = writeln!(summary, "{}: {:.6}", row.symbol, row.weight);
    }
    summary
}
