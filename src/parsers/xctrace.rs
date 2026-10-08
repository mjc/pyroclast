use std::fmt::Write as _;

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct XctraceCpuProfile {
    pub rows: Vec<XctraceCpuRow>,
    pub total_weight: f64,
    pub weight_unit: XctraceWeightUnit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XctraceWeightUnit {
    Nanoseconds,
    Cycles,
}

impl XctraceWeightUnit {
    fn as_str(self) -> &'static str {
        match self {
            Self::Nanoseconds => "nanoseconds",
            Self::Cycles => "cycles",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct XctraceCpuRow {
    pub symbol: String,
    pub weight: f64,
}

#[must_use]
pub fn parse_cpu_profile(xml: &str) -> XctraceCpuProfile {
    parse_cpu_profile_for_pid(xml, None).unwrap_or(XctraceCpuProfile {
        rows: Vec::new(),
        total_weight: 0.0,
        weight_unit: XctraceWeightUnit::Nanoseconds,
    })
}

/// Parses exported CPU samples, resolving xctrace's id/ref cells.
/// Weights retain the export's raw units: time-profile uses ns, cpu-profile cycles.
/// Simplified legacy rows with a `weight` cell are interpreted as nanoseconds.
///
/// # Errors
/// Returns an error for invalid XML, broken references, mixed weight units,
/// or no usable target rows.
pub fn parse_cpu_profile_for_pid(
    xml: &str,
    target_pid: Option<u32>,
) -> Result<XctraceCpuProfile, String> {
    let document =
        roxmltree::Document::parse(xml).map_err(|error| format!("invalid xctrace XML: {error}"))?;
    let ids = document
        .descendants()
        .filter_map(|node| node.attribute("id").map(|id| (id, node)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut rows = Vec::new();
    let mut weight_unit = None;
    for row in document
        .descendants()
        .filter(|node| node.has_tag_name("row"))
    {
        if let Some(pid) = target_pid {
            let process = row
                .children()
                .find(|node| node.has_tag_name("process"))
                .or_else(|| row.children().find(|node| node.has_tag_name("thread")));
            let Some(process) = process else {
                continue;
            };
            if node_pid(process, &ids, 0)? != Some(pid) {
                continue;
            }
        }
        let mut weight_cells = row
            .children()
            .filter(|node| node.has_tag_name("weight") || node.has_tag_name("cycle-weight"));
        let Some(weight) = weight_cells.next() else {
            continue;
        };
        let row_unit = if weight.has_tag_name("cycle-weight") {
            XctraceWeightUnit::Cycles
        } else {
            XctraceWeightUnit::Nanoseconds
        };
        if weight_unit.is_some_and(|unit| unit != row_unit)
            || weight_cells.any(|cell| cell.tag_name() != weight.tag_name())
        {
            return Err("mixed xctrace weight units (nanoseconds and cycles)".to_string());
        }
        weight_unit = Some(row_unit);
        let weight = resolve_cell(weight, &ids)?
            .text()
            .and_then(|value| value.trim().parse::<f64>().ok());
        let Some(weight) = weight.filter(|value| value.is_finite() && *value >= 0.0) else {
            continue;
        };
        let symbol = if let Some(symbol) = row.children().find(|node| node.has_tag_name("symbol")) {
            resolve_cell(symbol, &ids)?
                .text()
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
        } else {
            let stack = row.children().find(|node| {
                node.has_tag_name("backtrace") || node.has_tag_name("tagged-backtrace")
            });
            match stack {
                Some(stack) => first_frame(stack, &ids, 0)?,
                None => None,
            }
        };
        if let Some(symbol) = symbol {
            rows.push(XctraceCpuRow { symbol, weight });
        }
    }
    if rows.is_empty() {
        return Err(
            "xctrace export has no usable CPU samples for the requested process".to_string(),
        );
    }
    let total_weight: f64 = rows.iter().map(|row| row.weight).sum();
    if !total_weight.is_finite() {
        return Err("xctrace total weight is not finite".to_string());
    }
    Ok(XctraceCpuProfile {
        rows,
        total_weight,
        weight_unit: weight_unit.unwrap_or(XctraceWeightUnit::Nanoseconds),
    })
}

type CellIds<'a, 'input> = std::collections::BTreeMap<&'input str, roxmltree::Node<'a, 'input>>;

fn resolve_cell<'a, 'input>(
    mut node: roxmltree::Node<'a, 'input>,
    ids: &CellIds<'a, 'input>,
) -> Result<roxmltree::Node<'a, 'input>, String> {
    for _ in 0..32 {
        let Some(reference) = node.attribute("ref") else {
            return Ok(node);
        };
        node = *ids
            .get(reference)
            .ok_or_else(|| format!("missing xctrace reference {reference}"))?;
    }
    Err("cyclic xctrace reference".to_string())
}

fn node_pid<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    ids: &CellIds<'a, 'input>,
    depth: usize,
) -> Result<Option<u32>, String> {
    if depth >= 32 {
        return Err("cyclic or deeply nested xctrace process".to_string());
    }
    let node = resolve_cell(node, ids)?;
    if let Some(pid) = node.attribute("pid").and_then(|value| value.parse().ok()) {
        return Ok(Some(pid));
    }
    for child in node.children().filter(roxmltree::Node::is_element) {
        if child.has_tag_name("pid") {
            return Ok(resolve_cell(child, ids)?
                .text()
                .and_then(|text| text.trim().parse().ok()));
        }
        if child.has_tag_name("process") {
            return node_pid(child, ids, depth + 1);
        }
    }
    Ok(None)
}

fn first_frame<'a, 'input>(
    stack: roxmltree::Node<'a, 'input>,
    ids: &CellIds<'a, 'input>,
    depth: usize,
) -> Result<Option<String>, String> {
    if depth >= 32 {
        return Err("cyclic or deeply nested xctrace backtrace".to_string());
    }
    let stack = resolve_cell(stack, ids)?;
    for child in stack.children().filter(roxmltree::Node::is_element) {
        let child = resolve_cell(child, ids)?;
        if child.has_tag_name("frame") {
            return Ok(child
                .attribute("name")
                .or_else(|| child.text())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned));
        }
        if child.has_tag_name("backtrace") {
            return first_frame(child, ids, depth + 1);
        }
    }
    Ok(None)
}

#[must_use]
pub fn render_cpu_profile_summary_text(profile: &XctraceCpuProfile) -> String {
    let mut summary = format!(
        "xctrace rows: {}\nxctrace weight unit: {}\nxctrace total weight: {:.6}\n",
        profile.rows.len(),
        profile.weight_unit.as_str(),
        profile.total_weight
    );
    for row in &profile.rows {
        let _ = writeln!(summary, "{}: {:.6}", row.symbol, row.weight);
    }
    summary
}
