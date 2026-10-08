use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FlamegraphEntry {
    pub name: String,
    pub samples: u64,
    pub percent: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FlamegraphDelta {
    pub name: String,
    pub before_samples: u64,
    pub after_samples: u64,
    pub before_percent: f64,
    pub after_percent: f64,
    pub delta_percent: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FlamegraphCategory {
    pub name: String,
    pub percent: f64,
}

#[must_use]
pub fn parse_flamegraph_entries(svg: &str) -> Vec<FlamegraphEntry> {
    let Ok(document) = parse_svg(svg) else {
        return Vec::new();
    };
    let mut entries = document
        .descendants()
        .filter(|node| node.has_tag_name("title"))
        .filter_map(|node| node.text())
        .filter_map(parse_title)
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .percent
            .total_cmp(&left.percent)
            .then_with(|| left.name.cmp(&right.name))
    });
    entries
}

fn parse_svg(svg: &str) -> Result<roxmltree::Document<'_>, roxmltree::Error> {
    // Inferno emits an SVG DOCTYPE. roxmltree never fetches external DTDs.
    roxmltree::Document::parse_with_options(
        svg,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        },
    )
}

fn flamegraph_frames(svg: &str) -> Result<(Vec<CategoryFrame>, u64), String> {
    let document = parse_svg(svg).map_err(|error| format!("invalid flamegraph SVG: {error}"))?;
    let mut frames = Vec::new();
    for group in document.descendants().filter(|node| node.has_tag_name("g")) {
        let title = group
            .children()
            .find(|node| node.has_tag_name("title"))
            .and_then(|node| node.text());
        let Some(entry) = title.and_then(parse_frame_title) else {
            continue;
        };
        let rect = group
            .children()
            .find(|node| node.has_tag_name("rect"))
            .ok_or("flamegraph frame has no rectangle")?;
        let number = |key: &str| -> Option<f64> {
            rect.attribute(key)?
                .trim_end_matches('%')
                .parse::<f64>()
                .ok()
                .filter(|value| value.is_finite())
        };
        let x = rect
            .attribute(("http://github.com/jonhoo/inferno", "x"))
            .and_then(|value| value.parse().ok())
            .or_else(|| number("x"))
            .ok_or("invalid frame x")?;
        let width = rect
            .attribute(("http://github.com/jonhoo/inferno", "w"))
            .and_then(|value| value.parse().ok())
            .or_else(|| number("width"))
            .ok_or("invalid frame width")?;
        let y = number("y").ok_or("invalid frame y")?;
        if !x.is_finite() || !width.is_finite() || width < 0.0 || !(x + width).is_finite() {
            return Err("invalid frame extent".to_string());
        }
        frames.push(CategoryFrame {
            entry,
            x,
            end: x + width,
            depth: y,
            children: 0,
        });
    }
    let root = frames
        .iter()
        .find(|frame| frame.entry.name == "all")
        .ok_or("flamegraph has no aggregate frame geometry")?;
    let total = root.entry.samples;
    let root_y = root.depth;
    let inverted = frames.iter().any(|frame| frame.depth > root_y);
    if !inverted {
        for frame in &mut frames {
            frame.depth = -frame.depth;
        }
    }
    frames.sort_by(|left, right| {
        left.x
            .total_cmp(&right.x)
            .then_with(|| right.end.total_cmp(&left.end))
            .then_with(|| left.depth.total_cmp(&right.depth))
    });
    Ok((frames, total))
}

/// Groups exclusive sample weights using Inferno's rectangle topology.
///
/// # Errors
/// Returns an error for invalid XML or missing frame geometry/total weight.
#[allow(clippy::cast_precision_loss)] // Percentages are approximate; sample counts remain u64.
pub fn parse_flamegraph_categories(svg: &str) -> Result<Vec<FlamegraphCategory>, String> {
    let (mut frames, total) = flamegraph_frames(svg)?;
    if total == 0 {
        return Ok(Vec::new());
    }
    let mut ancestors: Vec<usize> = Vec::new();
    for index in 0..frames.len() {
        while ancestors.last().is_some_and(|&parent| {
            frames[parent].depth >= frames[index].depth
                || frames[parent].end + 0.0001 < frames[index].end
        }) {
            ancestors.pop();
        }
        if let Some(&parent) = ancestors.last() {
            frames[parent].children = frames[parent]
                .children
                .saturating_add(frames[index].entry.samples);
        }
        ancestors.push(index);
    }
    let exclusive = frames
        .into_iter()
        .filter(|frame| frame.entry.name != "all")
        .map(|frame| FlamegraphEntry {
            name: frame.entry.name,
            samples: frame.entry.samples.saturating_sub(frame.children),
            percent: 100.0 * frame.entry.samples.saturating_sub(frame.children) as f64
                / total as f64,
        })
        .filter(|entry| entry.samples != 0)
        .collect::<Vec<_>>();
    Ok(category_summary(&exclusive))
}

struct CategoryFrame {
    entry: FlamegraphEntry,
    x: f64,
    end: f64,
    depth: f64,
    children: u64,
}

/// Compares inclusive per-function sample weights, counting recursion once per stack.
/// Disjoint occurrences of a function are added; descendant occurrences already
/// covered by an ancestor with the same name contribute no additional samples.
///
/// # Errors
/// Returns an error for invalid SVG geometry or inconsistent sample totals.
pub fn diff_flamegraph_svgs(
    before: &str,
    after: &str,
    min_abs_delta_percent: f64,
) -> Result<Vec<FlamegraphDelta>, String> {
    Ok(diff_flamegraphs(
        &inclusive_function_entries(before)?,
        &inclusive_function_entries(after)?,
        min_abs_delta_percent,
    ))
}

#[allow(clippy::cast_precision_loss)] // Display percentages; counts remain exact.
fn inclusive_function_entries(svg: &str) -> Result<Vec<FlamegraphEntry>, String> {
    let (frames, total) = flamegraph_frames(svg)?;
    if total == 0 {
        return Ok(Vec::new());
    }
    let mut ancestors: Vec<usize> = Vec::new();
    let mut weights = BTreeMap::<&str, u64>::new();
    for (index, frame) in frames.iter().enumerate() {
        while ancestors.last().is_some_and(|&parent| {
            frames[parent].depth >= frame.depth || frames[parent].end + 0.0001 < frame.end
        }) {
            ancestors.pop();
        }
        if frame.entry.name != "all"
            && !ancestors
                .iter()
                .any(|&parent| frames[parent].entry.name == frame.entry.name)
        {
            let weight = weights.entry(&frame.entry.name).or_default();
            *weight = weight
                .checked_add(frame.entry.samples)
                .filter(|weight| *weight <= total)
                .ok_or("flamegraph function samples exceed aggregate total")?;
        }
        ancestors.push(index);
    }
    Ok(weights
        .into_iter()
        .map(|(name, samples)| FlamegraphEntry {
            name: name.to_owned(),
            samples,
            percent: 100.0 * samples as f64 / total as f64,
        })
        .collect())
}

#[must_use]
pub fn top_entries(
    entries: &[FlamegraphEntry],
    limit: usize,
    min_percent: f64,
) -> Vec<FlamegraphEntry> {
    let mut top = entries
        .iter()
        .filter(|entry| entry.percent >= min_percent)
        .cloned()
        .collect::<Vec<_>>();
    top.sort_by(|left, right| {
        right
            .percent
            .total_cmp(&left.percent)
            .then_with(|| left.name.cmp(&right.name))
    });
    top.truncate(limit);
    top
}

#[must_use]
pub fn search_entries(entries: &[FlamegraphEntry], pattern: &str) -> Vec<FlamegraphEntry> {
    let pattern = pattern.to_lowercase();
    entries
        .iter()
        .filter(|entry| entry.name.to_lowercase().contains(&pattern))
        .cloned()
        .collect()
}

#[must_use]
pub fn syscall_breakdown(entries: &[FlamegraphEntry]) -> Vec<FlamegraphEntry> {
    entries
        .iter()
        .filter_map(|entry| {
            let name = entry
                .name
                .strip_prefix("__x64_sys_")
                .or_else(|| entry.name.strip_prefix("__x86_sys_"))?;
            Some(FlamegraphEntry {
                name: name.to_string(),
                samples: entry.samples,
                percent: entry.percent,
            })
        })
        .collect()
}

#[must_use]
/// Sums categories of already-exclusive entries; SVG callers must use
/// [`parse_flamegraph_categories`] to remove overlapping ancestor weights.
pub fn category_summary(entries: &[FlamegraphEntry]) -> Vec<FlamegraphCategory> {
    let mut categories = BTreeMap::<&'static str, f64>::new();
    for entry in entries {
        *categories
            .entry(categorize_flamegraph_frame(&entry.name))
            .or_default() += entry.percent;
    }

    let mut categories = categories
        .into_iter()
        .map(|(name, percent)| FlamegraphCategory {
            name: name.to_string(),
            percent,
        })
        .collect::<Vec<_>>();
    categories.sort_by(|left, right| {
        right
            .percent
            .total_cmp(&left.percent)
            .then_with(|| left.name.cmp(&right.name))
    });
    categories
}

#[must_use]
/// Compares flat entries, adding duplicate names. For inclusive SVG rectangles,
/// use [`diff_flamegraph_svgs`] to avoid counting recursive descendants twice.
pub fn diff_flamegraphs(
    before: &[FlamegraphEntry],
    after: &[FlamegraphEntry],
    min_abs_delta_percent: f64,
) -> Vec<FlamegraphDelta> {
    let before_by_name = entries_by_name(before);
    let after_by_name = entries_by_name(after);
    let names = before_by_name
        .keys()
        .chain(after_by_name.keys())
        .copied()
        .collect::<BTreeSet<_>>();

    let mut deltas = names
        .into_iter()
        .filter_map(|name| {
            let before = before_by_name.get(name);
            let after = after_by_name.get(name);
            let before_percent = before.map_or(0.0, |entry| entry.percent);
            let after_percent = after.map_or(0.0, |entry| entry.percent);
            let delta_percent = after_percent - before_percent;
            (delta_percent.abs() >= min_abs_delta_percent).then(|| FlamegraphDelta {
                name: name.to_string(),
                before_samples: before.map_or(0, |entry| entry.samples),
                after_samples: after.map_or(0, |entry| entry.samples),
                before_percent,
                after_percent,
                delta_percent,
            })
        })
        .collect::<Vec<_>>();

    deltas.sort_by(|left, right| {
        right
            .delta_percent
            .abs()
            .total_cmp(&left.delta_percent.abs())
            .then_with(|| left.name.cmp(&right.name))
    });
    deltas
}

#[must_use]
pub fn categorize_flamegraph_frame(name: &str) -> &'static str {
    let lower = name.to_lowercase();

    if lower.contains("foyer")
        || lower.contains("hybrid_cache")
        || lower.contains("article_cache")
        || lower.contains("cache::")
        || lower.contains("moka")
    {
        "Cache/Foyer"
    } else if lower.contains("nntp")
        || lower.contains("client_session")
        || lower.contains("route_command")
        || lower.contains("message_id")
    {
        "NNTP Protocol"
    } else if lower.contains("tls")
        || lower.contains("ssl")
        || lower.contains("rustls")
        || lower.contains("aes")
        || lower.contains("cipher")
        || lower.contains("ring::")
    {
        "TLS/Crypto"
    } else if lower.contains("lz4")
        || lower.contains("compress")
        || lower.contains("decompress")
        || lower.contains("zstd")
    {
        "Compression"
    } else if lower.contains("recv")
        || lower.contains("send")
        || lower.contains("tcp")
        || lower.contains("socket")
        || lower.contains("skb")
    {
        "Network I/O"
    } else if lower.contains("zfs")
        || lower.contains("zpl")
        || lower.contains("vfs")
        || lower.contains("ext4")
        || lower.contains("xfs")
        || lower.contains("btrfs")
        || lower.contains("io_uring")
        || lower.contains("pread")
        || lower.contains("pwrite")
    {
        "Disk I/O"
    } else if lower.contains("futex")
        || lower.contains("mutex")
        || lower.contains("rwlock")
        || lower.contains("parking_lot")
    {
        "Locks/Futex"
    } else if lower.contains("epoll") || lower.contains("poll") || lower.contains("mio") {
        "Event Loop"
    } else if lower.contains("tokio") || lower.contains("runtime") {
        "Tokio Runtime"
    } else if lower.contains("futures") || lower.contains("async") || lower.contains("waker") {
        "Async/Futures"
    } else if lower.contains("schedule") || lower.contains("switch") || lower.contains("context") {
        "Scheduling"
    } else if lower.contains("alloc")
        || lower.contains("malloc")
        || lower.contains("free")
        || lower.contains("mmap")
        || lower.contains("jemalloc")
    {
        "Memory"
    } else if name.starts_with("__x64_sys_")
        || name.starts_with("__x86_sys_")
        || name.starts_with("syscall")
        || name.starts_with("do_syscall")
        || name.starts_with("entry_SYSCALL")
    {
        "Syscall"
    } else {
        "Other"
    }
}

fn parse_title(title: &str) -> Option<FlamegraphEntry> {
    let entry = parse_frame_title(title)?;
    (entry.name != "all").then_some(entry)
}

fn parse_frame_title(title: &str) -> Option<FlamegraphEntry> {
    let paren_start = title.rfind('(')?;
    let name = title[..paren_start].trim();
    if name.is_empty() {
        return None;
    }

    let meta = &title[paren_start + 1..];
    let samples_end = meta.find(" samples")?;
    let samples = meta[..samples_end].replace(',', "").parse().ok()?;
    let percent_start = meta.rfind(", ")? + 2;
    let percent_end = meta.rfind('%')?;
    let percent = meta[percent_start..percent_end].parse().ok()?;

    Some(FlamegraphEntry {
        name: name.to_string(),
        samples,
        percent,
    })
}

fn entries_by_name(entries: &[FlamegraphEntry]) -> BTreeMap<&str, FlamegraphEntry> {
    let mut aggregated = BTreeMap::new();
    for entry in entries {
        let value = aggregated
            .entry(entry.name.as_str())
            .or_insert_with(|| FlamegraphEntry {
                name: entry.name.clone(),
                samples: 0,
                percent: 0.0,
            });
        value.samples = value.samples.saturating_add(entry.samples);
        value.percent += entry.percent;
    }
    aggregated
}
