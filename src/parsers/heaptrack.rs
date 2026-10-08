use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct HeaptrackSummary {
    pub total_allocations: Option<u64>,
    pub peak_heap_bytes: Option<u64>,
}

#[must_use]
pub fn parse_heaptrack_summary(text: &str) -> HeaptrackSummary {
    let mut summary = HeaptrackSummary {
        total_allocations: None,
        peak_heap_bytes: None,
    };

    for line in text.lines() {
        if let Some(value) = number_after_prefix(line, "calls to allocation functions:")
            .or_else(|| number_after_prefix(line, "total allocations:"))
        {
            summary.total_allocations = Some(value);
        }
        if let Some(value) = line
            .trim()
            .strip_prefix("peak heap memory consumption:")
            .and_then(parse_size)
        {
            summary.peak_heap_bytes = Some(value);
        }
    }

    summary
}

pub(crate) fn parse_size(text: &str) -> Option<u64> {
    let text = text.trim();
    let end = text
        .find(|ch: char| !ch.is_ascii_digit() && ch != '.')
        .unwrap_or(text.len());
    let number = &text[..end];
    let unit = text[end..].trim().to_ascii_lowercase();
    let multiplier: u128 = match unit.as_str() {
        "" | "b" | "bytes" => 1,
        "k" | "kb" => 1_000,
        "m" | "mb" => 1_000_000,
        "g" | "gb" => 1_000_000_000,
        "t" | "tb" => 1_000_000_000_000,
        "kib" => 1 << 10,
        "mib" => 1 << 20,
        "gib" => 1 << 30,
        "tib" => 1 << 40,
        _ => return None,
    };
    let (integer, fraction) = number.split_once('.').unwrap_or((number, ""));
    if integer.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let denominator = 10_u128.checked_pow(u32::try_from(fraction.len()).ok()?)?;
    let numerator = integer
        .parse::<u128>()
        .ok()?
        .checked_mul(denominator)?
        .checked_add(if fraction.is_empty() {
            0
        } else {
            fraction.parse().ok()?
        })?;
    let bytes = numerator
        .checked_mul(multiplier)?
        .checked_add(denominator / 2)?
        / denominator;
    u64::try_from(bytes).ok()
}

fn number_after_prefix(line: &str, prefix: &str) -> Option<u64> {
    line.trim()
        .strip_prefix(prefix)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[must_use]
pub fn render_heaptrack_summary_text(summary: &HeaptrackSummary) -> String {
    format!(
        "total allocations: {}\npeak heap memory consumption: {}\n",
        optional_u64(summary.total_allocations),
        optional_bytes(summary.peak_heap_bytes)
    )
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_string(), |value| value.to_string())
}

fn optional_bytes(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_string(), |value| format!("{value} bytes"))
}
