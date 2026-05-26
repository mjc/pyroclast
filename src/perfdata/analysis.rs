use std::collections::BTreeMap;

use serde::Serialize;

use crate::perfdata::fold::summarize_perfdata;
use crate::perfdata::samples::is_perf_context_marker;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PerfdataAnalysis {
    pub total_records: usize,
    pub total_samples: usize,
    pub weighted_samples: u64,
    pub lost_records: u64,
    pub threads: Vec<PerfdataThread>,
    pub top_leaf_ips: Vec<PerfdataIpCount>,
    pub top_edges: Vec<PerfdataEdgeCount>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PerfdataThread {
    pub tid: u32,
    pub comm: String,
    pub samples: usize,
    pub weighted_samples: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PerfdataIpCount {
    pub ip: String,
    pub samples: usize,
    pub weighted_samples: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PerfdataEdgeCount {
    pub caller: String,
    pub callee: String,
    pub samples: usize,
    pub weighted_samples: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Edge {
    caller: u64,
    callee: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Count {
    samples: usize,
    weighted_samples: u64,
}

/// Builds a compact analysis report from Linux `perf.data` bytes.
///
/// # Errors
///
/// Returns an error when the input cannot be parsed as a supported `perf.data`
/// file.
pub fn analyze_perfdata(bytes: &[u8], limit: usize) -> Result<PerfdataAnalysis, String> {
    let summary = summarize_perfdata(bytes)?;
    let mut threads = BTreeMap::<u32, Count>::new();
    let mut leaf_ips = BTreeMap::<u64, Count>::new();
    let mut edges = BTreeMap::<Edge, Count>::new();
    let mut weighted_samples = 0_u64;

    for sample in &summary.sample_stacks {
        let weight = sample.period.unwrap_or(1);
        weighted_samples = weighted_samples.saturating_add(weight);
        if let Some(tid) = sample.tid.or(sample.pid) {
            add_count(threads.entry(tid).or_default(), weight);
        }
        let frames = sample
            .callchain
            .iter()
            .copied()
            .filter(|frame| !is_perf_context_marker(*frame))
            .collect::<Vec<_>>();
        if let Some(leaf) = frames.first().copied() {
            add_count(leaf_ips.entry(leaf).or_default(), weight);
        }
        for window in frames.windows(2) {
            add_count(
                edges
                    .entry(Edge {
                        caller: window[1],
                        callee: window[0],
                    })
                    .or_default(),
                weight,
            );
        }
    }

    Ok(PerfdataAnalysis {
        total_records: summary.total_records,
        total_samples: summary.sample_stacks.len(),
        weighted_samples,
        lost_records: summary.lost_records,
        threads: ranked_threads(threads, &summary.comms_by_tid, limit),
        top_leaf_ips: ranked_ips(leaf_ips, limit),
        top_edges: ranked_edges(edges, limit),
    })
}

fn add_count(count: &mut Count, weight: u64) {
    count.samples += 1;
    count.weighted_samples = count.weighted_samples.saturating_add(weight);
}

fn ranked_threads(
    threads: BTreeMap<u32, Count>,
    comms_by_pid: &BTreeMap<u32, String>,
    limit: usize,
) -> Vec<PerfdataThread> {
    let mut threads = threads
        .into_iter()
        .map(|(tid, count)| PerfdataThread {
            tid,
            comm: comms_by_pid
                .get(&tid)
                .cloned()
                .unwrap_or_else(|| format!("tid {tid}")),
            samples: count.samples,
            weighted_samples: count.weighted_samples,
        })
        .collect::<Vec<_>>();
    threads.sort_by(|left, right| {
        right
            .weighted_samples
            .cmp(&left.weighted_samples)
            .then_with(|| left.tid.cmp(&right.tid))
    });
    threads.truncate(limit);
    threads
}

fn ranked_ips(ips: BTreeMap<u64, Count>, limit: usize) -> Vec<PerfdataIpCount> {
    let mut ips = ips
        .into_iter()
        .map(|(ip, count)| PerfdataIpCount {
            ip: format_ip(ip),
            samples: count.samples,
            weighted_samples: count.weighted_samples,
        })
        .collect::<Vec<_>>();
    ips.sort_by(|left, right| {
        right
            .weighted_samples
            .cmp(&left.weighted_samples)
            .then_with(|| left.ip.cmp(&right.ip))
    });
    ips.truncate(limit);
    ips
}

fn ranked_edges(edges: BTreeMap<Edge, Count>, limit: usize) -> Vec<PerfdataEdgeCount> {
    let mut edges = edges
        .into_iter()
        .map(|(edge, count)| PerfdataEdgeCount {
            caller: format_ip(edge.caller),
            callee: format_ip(edge.callee),
            samples: count.samples,
            weighted_samples: count.weighted_samples,
        })
        .collect::<Vec<_>>();
    edges.sort_by(|left, right| {
        right
            .weighted_samples
            .cmp(&left.weighted_samples)
            .then_with(|| left.caller.cmp(&right.caller))
            .then_with(|| left.callee.cmp(&right.callee))
    });
    edges.truncate(limit);
    edges
}

fn format_ip(ip: u64) -> String {
    format!("0x{ip:016x}")
}
