use std::collections::{BTreeMap, BTreeSet};
use std::io;

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use serde::{Deserialize, Serialize};

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
    pub samples: u64,
    pub percent: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub inclusive_functions: Vec<FlamegraphEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryRule {
    pub name: String,
    pub contains: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FlamegraphProfile {
    pub total_samples: u64,
    pub inclusive: Vec<FlamegraphEntry>,
    pub self_samples: Vec<FlamegraphEntry>,
    pub categories: Vec<FlamegraphCategory>,
    pub syscalls: Vec<FlamegraphEntry>,
    pub any_syscall_samples: u64,
}

struct Frame {
    name: String,
    start: u64,
    end: u64,
    y: f64,
}

#[derive(Default)]
struct Container {
    frame: bool,
    title: Option<String>,
}

/// Analyzes Inferno's exact sample ranges, not rounded title percentages.
///
/// Self samples mean deepest *visible* frames: frames hidden by the renderer's
/// minimum width cannot be recovered from an SVG.
///
/// # Errors
///
/// Rejects malformed XML, missing sample geometry and invalid sample ranges.
pub fn parse_flamegraph(svg: &str) -> io::Result<FlamegraphProfile> {
    let (mut frames, declared_total) = read_frames(svg)?;
    let root_index = frames
        .iter()
        .position(|frame| {
            frame.name == "all"
                && frame.start == 0
                && declared_total.is_none_or(|total| frame.end == total)
        })
        .ok_or_else(|| invalid_data("missing Inferno aggregate frame and sample ranges"))?;
    let root = frames.remove(root_index);
    let total_samples = declared_total.unwrap_or(root.end);
    if total_samples == 0 || frames.iter().any(|frame| frame.end > total_samples) {
        return Err(invalid_data(
            "empty flamegraph or frame outside total_samples",
        ));
    }
    // inferno/src/flamegraph/mod.rs:568,577-588,899-912: raw total_samples,
    // direction-dependent y, and exact fg:x/fg:w (titles can be scaled).
    let inverted = frames.iter().any(|frame| frame.y > root.y);
    if inverted && frames.iter().any(|frame| frame.y < root.y) {
        return Err(invalid_data("aggregate frame is not at the stack root"));
    }
    let mut by_name = BTreeMap::<&str, Vec<(u64, u64)>>::new();
    let mut syscalls = BTreeMap::<&str, Vec<(u64, u64)>>::new();
    let mut syscall_ranges = Vec::new();
    for frame in &frames {
        by_name
            .entry(&frame.name)
            .or_default()
            .push((frame.start, frame.end));
        if let Some(name) = syscall_name(&frame.name) {
            syscalls
                .entry(name)
                .or_default()
                .push((frame.start, frame.end));
            syscall_ranges.push((frame.start, frame.end));
        }
    }
    let inclusive = range_entries(by_name, total_samples);
    let syscalls = range_entries(syscalls, total_samples);
    let any_syscall_samples = covered_samples(&mut syscall_ranges);
    let self_counts = deepest_samples(&frames, total_samples, inverted);
    let mut profile = FlamegraphProfile {
        total_samples,
        inclusive,
        self_samples: count_entries(self_counts, total_samples),
        categories: Vec::new(),
        syscalls,
        any_syscall_samples,
    };
    categorize_profile(&mut profile, &[], 0, 0.0);
    Ok(profile)
}

/// Parses ordered, case-insensitive substring rules for project categories.
///
/// # Errors
///
/// Rejects invalid JSON, unknown fields and empty labels or match patterns.
pub fn parse_category_rules(json: &str) -> io::Result<Vec<CategoryRule>> {
    let mut rules: Vec<CategoryRule> = serde_json::from_str(json).map_err(invalid_data)?;
    for rule in &mut rules {
        if rule.name.trim().is_empty()
            || rule.contains.is_empty()
            || rule
                .contains
                .iter()
                .any(|pattern| pattern.trim().is_empty())
        {
            return Err(invalid_data(
                "category rules require a name and nonempty contains patterns",
            ));
        }
        for pattern in &mut rule.contains {
            *pattern = pattern.to_lowercase();
        }
    }
    Ok(rules)
}

/// Rebuilds exclusive categories and their inclusive key functions before any
/// report-level truncation. First project rule wins; built-ins are the fallback.
pub fn categorize_profile(
    profile: &mut FlamegraphProfile,
    rules: &[CategoryRule],
    limit: usize,
    min_percent: f64,
) {
    let mut categories = BTreeMap::<&str, FlamegraphCategory>::new();
    for entry in &profile.self_samples {
        let name = category_name(&entry.name, rules);
        let category = categories
            .entry(name)
            .or_insert_with(|| FlamegraphCategory {
                name: name.to_owned(),
                samples: 0,
                percent: 0.0,
                inclusive_functions: Vec::new(),
            });
        category.samples += entry.samples;
    }
    for entry in &profile.inclusive {
        if entry.percent >= min_percent
            && let Some(category) = categories.get_mut(category_name(&entry.name, rules))
            && category.inclusive_functions.len() < limit
        {
            category.inclusive_functions.push(entry.clone());
        }
    }
    profile.categories = categories
        .into_values()
        .map(|mut category| {
            category.percent = percentage(category.samples, profile.total_samples);
            category
        })
        .collect();
    profile.categories.sort_by(|left, right| {
        right
            .samples
            .cmp(&left.samples)
            .then_with(|| left.name.cmp(&right.name))
    });
}

fn category_name<'a>(name: &str, rules: &'a [CategoryRule]) -> &'a str {
    if !rules.is_empty() {
        let lower = name.to_lowercase();
        if let Some(rule) = rules
            .iter()
            .find(|rule| rule.contains.iter().any(|pattern| lower.contains(pattern)))
        {
            return &rule.name;
        }
    }
    categorize_flamegraph_frame(name)
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
    } else if syscall_name(name).is_some()
        || name.starts_with("syscall")
        || name.starts_with("do_syscall")
        || name.starts_with("entry_SYSCALL")
    {
        "Syscall"
    } else {
        "Other"
    }
}

fn read_frames(svg: &str) -> io::Result<(Vec<Frame>, Option<u64>)> {
    let mut reader = Reader::from_str(svg);
    let mut containers = Vec::<Container>::new();
    let mut frames = Vec::new();
    let mut total = None;
    loop {
        match reader.read_event().map_err(invalid_data)? {
            Event::Start(element) if element.name().as_ref() == b"title" => {
                let text = reader.read_text(element.name()).map_err(invalid_data)?;
                let text = text.decode().map_err(invalid_data)?;
                let text = quick_xml::escape::unescape(&text).map_err(invalid_data)?;
                if let Some(container) = containers.last_mut().filter(|container| container.frame)
                    && let Some((name, metadata)) = text.rsplit_once(" (")
                    && !name.is_empty()
                    && metadata.ends_with(')')
                    && metadata.contains('%')
                {
                    validate_title_metadata(metadata)?;
                    container.title = Some(name.to_owned());
                }
            }
            event @ (Event::Start(_) | Event::Empty(_)) => {
                let empty = matches!(event, Event::Empty(_));
                let (Event::Start(element) | Event::Empty(element)) = event else {
                    unreachable!()
                };
                if element.name().as_ref() == b"svg"
                    && let Some(value) = attribute(&element, b"total_samples")?
                {
                    let value = value.parse().map_err(invalid_data)?;
                    if total.replace(value).is_some() {
                        return Err(invalid_data("multiple flamegraphs in one SVG"));
                    }
                }
                if element.name().as_ref() == b"rect"
                    && let Some(name) = containers
                        .last_mut()
                        .and_then(|container| container.title.take())
                {
                    let start = required_attribute(&element, b"fg:x")?
                        .parse::<u64>()
                        .map_err(invalid_data)?;
                    let width = required_attribute(&element, b"fg:w")?
                        .parse::<u64>()
                        .map_err(invalid_data)?;
                    let y = required_attribute(&element, b"y")?
                        .parse::<f64>()
                        .map_err(invalid_data)?;
                    if !y.is_finite() {
                        return Err(invalid_data("invalid frame y coordinate"));
                    }
                    let end = start
                        .checked_add(width)
                        .ok_or_else(|| invalid_data("sample range overflow"))?;
                    frames.push(Frame {
                        name,
                        start,
                        end,
                        y,
                    });
                }
                // Empty elements have no corresponding End event.
                if !empty {
                    containers.push(Container {
                        frame: matches!(element.name().as_ref(), b"g" | b"a"),
                        title: None,
                    });
                }
            }
            Event::End(_) => {
                let container = containers
                    .pop()
                    .ok_or_else(|| invalid_data("unmatched XML end tag"))?;
                if container.title.is_some() {
                    return Err(invalid_data("flamegraph frame has no rectangle"));
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !containers.is_empty() {
        return Err(invalid_data("truncated SVG"));
    }
    Ok((frames, total))
}

fn validate_title_metadata(metadata: &str) -> io::Result<()> {
    // Inferno flamegraph/mod.rs emits "count units, percent%" followed by
    // an optional "; signed-delta%". Weights still come from exact fg:w,
    // never from the rounded or scaled numbers in the title.
    let malformed = || invalid_data("malformed flamegraph title metadata");
    let (_, percentages) = metadata
        .strip_suffix(')')
        .and_then(|text| text.rsplit_once(", "))
        .ok_or_else(malformed)?;
    let mut fields = percentages.split("; ");
    for _ in 0..2 {
        let Some(field) = fields.next() else {
            return Ok(());
        };
        field
            .strip_suffix('%')
            .and_then(|text| text.parse::<f64>().ok())
            .filter(|value| value.is_finite())
            .ok_or_else(malformed)?;
    }
    if fields.next().is_some() {
        return Err(malformed());
    }
    Ok(())
}

fn attribute(element: &BytesStart<'_>, name: &[u8]) -> io::Result<Option<String>> {
    element
        .try_get_attribute(name)
        .map_err(invalid_data)?
        .map(|attribute| {
            attribute
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map(std::borrow::Cow::into_owned)
                .map_err(invalid_data)
        })
        .transpose()
}

fn required_attribute(element: &BytesStart<'_>, name: &[u8]) -> io::Result<String> {
    attribute(element, name)?.ok_or_else(|| {
        invalid_data(format!(
            "missing {}: exact Inferno sample ranges are required",
            String::from_utf8_lossy(name)
        ))
    })
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn percentage(samples: u64, total: u64) -> f64 {
    count_as_f64(samples) / count_as_f64(total) * 100.0
}

fn count_as_f64(value: u64) -> f64 {
    let high = u32::try_from(value >> 32).expect("upper 32 bits");
    let low = u32::try_from(value & u64::from(u32::MAX)).expect("lower 32 bits");
    f64::from(high).mul_add(4_294_967_296.0, f64::from(low))
}

fn covered_samples(ranges: &mut [(u64, u64)]) -> u64 {
    ranges.sort_unstable();
    let (mut covered, mut previous_end) = (0, 0);
    for &(start, end) in ranges.iter() {
        covered += end.saturating_sub(start.max(previous_end));
        previous_end = previous_end.max(end);
    }
    covered
}

fn range_entries(ranges: BTreeMap<&str, Vec<(u64, u64)>>, total: u64) -> Vec<FlamegraphEntry> {
    count_entries(
        ranges
            .into_iter()
            .map(|(name, mut ranges)| (name, covered_samples(&mut ranges)))
            .collect(),
        total,
    )
}

fn count_entries(counts: BTreeMap<&str, u64>, total: u64) -> Vec<FlamegraphEntry> {
    let mut entries = counts
        .into_iter()
        .filter(|(_, samples)| *samples > 0)
        .map(|(name, samples)| FlamegraphEntry {
            name: name.to_owned(),
            samples,
            percent: percentage(samples, total),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .samples
            .cmp(&left.samples)
            .then_with(|| left.name.cmp(&right.name))
    });
    entries
}

fn deepest_samples(frames: &[Frame], total: u64, inverted: bool) -> BTreeMap<&str, u64> {
    let mut order = (0..frames.len()).collect::<Vec<_>>();
    order.sort_by(|&left, &right| {
        let order = frames[left].y.total_cmp(&frames[right].y);
        if inverted { order } else { order.reverse() }
    });
    let mut events = Vec::with_capacity(frames.len() * 2);
    for (depth, &index) in order.iter().enumerate() {
        let frame = &frames[index];
        if frame.start < frame.end {
            events.push((frame.start, true, depth));
            events.push((frame.end, false, depth));
        }
    }
    events.sort_unstable();
    let mut active = BTreeSet::<usize>::new();
    let mut counts = BTreeMap::new();
    let mut previous = 0;
    // At equal positions, ends precede starts. Each interval is charged once
    // to the deepest visible frame, including gaps as [unattributed].
    for (position, start, depth) in events {
        if position > previous {
            let name = active.last().map_or("[unattributed]", |depth| {
                frames[order[*depth]].name.as_str()
            });
            *counts.entry(name).or_default() += position - previous;
            previous = position;
        }
        if start {
            active.insert(depth);
        } else {
            active.remove(&depth);
        }
    }
    if previous < total {
        *counts.entry("[unattributed]").or_default() += total - previous;
    }
    counts
}

fn syscall_name(name: &str) -> Option<&str> {
    ["__x64_sys_", "__x86_sys_", "__ia32_sys_", "__arm64_sys_"]
        .iter()
        .find_map(|prefix| name.strip_prefix(prefix))
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
