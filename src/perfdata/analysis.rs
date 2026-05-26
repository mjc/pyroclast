use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::perfdata::fold::summarize_perfdata;
use crate::perfdata::records::{PERF_RECORD_MISC_CPUMODE_KERNEL, PERF_RECORD_MISC_CPUMODE_USER};
use crate::perfdata::samples::is_perf_context_marker;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PerfdataAnalysis {
    pub total_records: usize,
    pub total_samples: usize,
    pub weighted_samples: u64,
    pub lost_records: u64,
    pub user_stack_samples: usize,
    pub user_stack_bytes: usize,
    pub user_stack_dynamic_bytes: u64,
    pub user_register_samples: usize,
    pub user_register_ip_samples: usize,
    pub sample_modes: Vec<PerfdataSampleMode>,
    pub threads: Vec<PerfdataThread>,
    pub top_leaf_ips: Vec<PerfdataIpCount>,
    pub top_edges: Vec<PerfdataEdgeCount>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PerfdataSampleMode {
    pub mode: String,
    pub samples: usize,
    pub weighted_samples: u64,
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
    let mut sample_modes = BTreeMap::<u16, Count>::new();
    let mut leaf_ips = BTreeMap::<u64, Count>::new();
    let mut edges = BTreeMap::<Edge, Count>::new();
    let mut weighted_samples = 0_u64;
    let mut user_stack_samples = 0_usize;
    let mut user_stack_bytes = 0_usize;
    let mut user_stack_dynamic_bytes = 0_u64;
    let mut user_register_samples = 0_usize;
    let mut user_register_ip_samples = 0_usize;

    for sample in &summary.sample_stacks {
        let weight = sample.period.unwrap_or(1);
        weighted_samples = weighted_samples.saturating_add(weight);
        add_count(sample_modes.entry(sample.cpumode).or_default(), weight);
        if sample.has_user_stack {
            user_stack_samples += 1;
            user_stack_bytes = user_stack_bytes.saturating_add(sample.user_stack_size);
            user_stack_dynamic_bytes =
                user_stack_dynamic_bytes.saturating_add(sample.user_stack_dynamic_size);
        }
        if sample.user_register_count != 0 {
            user_register_samples += 1;
        }
        if sample.user_register_ip.is_some() {
            user_register_ip_samples += 1;
        }
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
        user_stack_samples,
        user_stack_bytes,
        user_stack_dynamic_bytes,
        user_register_samples,
        user_register_ip_samples,
        sample_modes: ranked_sample_modes(sample_modes),
        threads: ranked_threads(threads, &summary.comms_by_tid, limit),
        top_leaf_ips: ranked_ips(leaf_ips, limit),
        top_edges: ranked_edges(edges, limit),
    })
}

/// Builds a compact analysis report from a Linux `perf.data` file path without
/// copying the full file into memory.
///
/// # Errors
///
/// Returns an error when the file cannot be opened, mapped, or parsed.
pub fn analyze_perfdata_file(path: &Path, limit: usize) -> Result<PerfdataAnalysis, String> {
    let file =
        std::fs::File::open(path).map_err(|error| format!("failed to open perf.data: {error}"))?;
    let mapping = map_perfdata_file(&file)?;
    analyze_perfdata(&mapping, limit)
}

fn map_perfdata_file(file: &std::fs::File) -> Result<memmap2::Mmap, String> {
    // SAFETY: The mapping is read-only and is only borrowed immutably by the
    // parser while both the file handle and mapping are alive.
    unsafe { memmap2::MmapOptions::new().map(file) }
        .map_err(|error| format!("failed to map perf.data: {error}"))
}

fn add_count(count: &mut Count, weight: u64) {
    count.samples += 1;
    count.weighted_samples = count.weighted_samples.saturating_add(weight);
}

fn ranked_sample_modes(modes: BTreeMap<u16, Count>) -> Vec<PerfdataSampleMode> {
    let mut modes = modes
        .into_iter()
        .map(|(mode, count)| PerfdataSampleMode {
            mode: sample_mode_name(mode).to_owned(),
            samples: count.samples,
            weighted_samples: count.weighted_samples,
        })
        .collect::<Vec<_>>();
    modes.sort_by(|left, right| {
        right
            .weighted_samples
            .cmp(&left.weighted_samples)
            .then_with(|| left.mode.cmp(&right.mode))
    });
    modes
}

fn sample_mode_name(mode: u16) -> &'static str {
    match mode {
        PERF_RECORD_MISC_CPUMODE_KERNEL => "kernel",
        PERF_RECORD_MISC_CPUMODE_USER => "user",
        3 => "hypervisor",
        4 => "guest-kernel",
        5 => "guest-user",
        _ => "unknown",
    }
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
