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
    let mut entries = svg
        .split("<title>")
        .filter_map(|chunk| chunk.find("</title>").map(|end| &chunk[..end]))
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
    let paren_start = title.rfind('(')?;
    let name = title[..paren_start].trim();
    if name.is_empty() || name == "all" {
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

fn entries_by_name(entries: &[FlamegraphEntry]) -> BTreeMap<&str, &FlamegraphEntry> {
    entries
        .iter()
        .map(|entry| (entry.name.as_str(), entry))
        .collect()
}
