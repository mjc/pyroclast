use crate::perfdata::fold::PerfSummary;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ThreadProfileSummary {
    pub pid: Option<u32>,
    pub tid: u32,
    pub comm: String,
    pub samples: usize,
    pub weighted_samples: u64,
    pub first_sample_ns: Option<u64>,
    pub last_sample_ns: Option<u64>,
    pub cpus: Vec<u32>,
}

#[must_use]
pub fn summarize_threads(input: &PerfSummary, limit: usize) -> Vec<ThreadProfileSummary> {
    let mut threads = BTreeMap::new();
    for sample in &input.sample_stacks {
        let Some(tid) = sample.tid.or(sample.pid) else {
            continue;
        };
        let thread = threads
            .entry((sample.pid, tid))
            .or_insert_with(|| ThreadProfileSummary {
                pid: sample.pid,
                tid,
                comm: input
                    .comms_by_tid
                    .get(&tid)
                    .cloned()
                    .unwrap_or_else(|| format!("tid {tid}")),
                samples: 0,
                weighted_samples: 0,
                first_sample_ns: None,
                last_sample_ns: None,
                cpus: Vec::new(),
            });
        thread.samples += 1;
        thread.weighted_samples = thread
            .weighted_samples
            .saturating_add(sample.period.unwrap_or(1));
        if let Some(time) = sample.time {
            thread.first_sample_ns =
                Some(thread.first_sample_ns.map_or(time, |first| first.min(time)));
            thread.last_sample_ns = Some(thread.last_sample_ns.map_or(time, |last| last.max(time)));
        }
        if let Some(cpu) = sample.cpu
            && !thread.cpus.contains(&cpu)
        {
            thread.cpus.push(cpu);
        }
    }
    let mut threads = threads.into_values().collect::<Vec<_>>();
    for thread in &mut threads {
        thread.cpus.sort_unstable();
    }
    threads.sort_by(|left, right| {
        right
            .weighted_samples
            .cmp(&left.weighted_samples)
            .then_with(|| left.tid.cmp(&right.tid))
            .then_with(|| left.pid.cmp(&right.pid))
    });
    threads.truncate(limit);
    threads
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TopFoldedStack {
    pub stack: String,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FoldedStackSummary {
    pub folded_lines: usize,
    pub folded_bytes: usize,
    pub total_count: u64,
    pub top_stacks: Vec<TopFoldedStack>,
}

#[must_use]
pub fn summarize_folded_stacks(folded_stacks: &str) -> FoldedStackSummary {
    let mut parsed_stacks = folded_stacks
        .lines()
        .filter_map(parse_folded_line)
        .map(|(stack, count)| TopFoldedStack {
            stack: stack.to_string(),
            count,
        })
        .collect::<Vec<_>>();
    parsed_stacks.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.stack.cmp(&right.stack))
    });

    FoldedStackSummary {
        folded_lines: folded_stacks.lines().count(),
        folded_bytes: folded_stacks.len(),
        total_count: parsed_stacks.iter().map(|stack| stack.count).sum(),
        top_stacks: parsed_stacks,
    }
}

#[must_use]
pub fn render_folded_stack_summary_text(summary: &FoldedStackSummary) -> String {
    format!(
        "folded lines: {}\nfolded bytes: {}\ntotal count: {}\n",
        summary.folded_lines, summary.folded_bytes, summary.total_count
    )
}

fn parse_folded_line(line: &str) -> Option<(&str, u64)> {
    let (stack, count) = line.rsplit_once(' ')?;
    Some((stack, count.parse().ok()?))
}
