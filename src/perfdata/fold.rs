use std::collections::BTreeMap;

use crate::folded::render_folded_stack;
use crate::perfdata::attrs::parse_file_attrs;
use crate::perfdata::header::parse_header;
use crate::perfdata::records::{
    iter_records, parse_comm_record, parse_mmap_record, parse_mmap2_record,
};
use crate::perfdata::samples::{SampleLayout, is_perf_context_marker, parse_sample_record};

const PERF_RECORD_MMAP: u32 = 1;
const PERF_RECORD_COMM: u32 = 3;
const PERF_RECORD_SAMPLE: u32 = 9;
const PERF_RECORD_MMAP2: u32 = 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfSummary {
    pub total_records: usize,
    pub record_counts: BTreeMap<u32, usize>,
    pub comms: Vec<String>,
    pub comms_by_pid: BTreeMap<u32, String>,
    pub mmaps: Vec<String>,
    pub sample_callchains: Vec<Vec<u64>>,
    pub sample_stacks: Vec<PerfSampleStack>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfSampleStack {
    pub pid: Option<u32>,
    pub period: Option<u64>,
    pub callchain: Vec<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FoldOptions {
    pub count_periods: bool,
}

impl PerfSummary {
    #[must_use]
    pub fn record_count(&self, record_type: u32) -> usize {
        self.record_counts.get(&record_type).copied().unwrap_or(0)
    }
}

/// Summarizes record counts and parsed sample callchains from `perf.data`.
///
/// # Errors
///
/// Returns an error when the file header, attr section, record stream, or a
/// supported record payload is malformed.
pub fn summarize_perfdata(bytes: &[u8]) -> Result<PerfSummary, String> {
    let header = parse_header(bytes)?;
    let sample_layout = first_sample_layout(bytes, header)?;
    let records = iter_records(bytes, header)?;
    let mut summary = PerfSummary {
        total_records: 0,
        record_counts: BTreeMap::new(),
        comms: Vec::new(),
        comms_by_pid: BTreeMap::new(),
        mmaps: Vec::new(),
        sample_callchains: Vec::new(),
        sample_stacks: Vec::new(),
    };

    for record in records {
        summary.total_records += 1;
        *summary
            .record_counts
            .entry(record.header.record_type)
            .or_insert(0) += 1;
        let record_result: Result<(), String> = match record.header.record_type {
            PERF_RECORD_COMM => parse_comm_record(record.payload).map(|record| {
                summary.comms_by_pid.insert(record.pid, record.comm.clone());
                summary.comms.push(record.comm);
            }),
            PERF_RECORD_MMAP => parse_mmap_record(record.payload).map(|record| {
                summary.mmaps.push(record.path);
            }),
            PERF_RECORD_SAMPLE => {
                parse_sample_for_summary(record.payload, sample_layout).map(|sample| {
                    if let Some(sample) = sample {
                        summary.sample_callchains.push(sample.callchain.clone());
                        summary.sample_stacks.push(sample);
                    }
                })
            }
            PERF_RECORD_MMAP2 => parse_mmap2_record(record.payload).map(|record| {
                summary.mmaps.push(record.path);
            }),
            _ => Ok(()),
        };
        record_result.map_err(|error| {
            format!(
                "failed to parse record type {} at offset {}: {error}",
                record.header.record_type, record.offset
            )
        })?;
    }

    Ok(summary)
}

/// Collapses parsed perf sample callchains into folded stack lines.
///
/// # Errors
///
/// Returns an error when the `perf.data` input cannot be parsed.
pub fn fold_perfdata_callchains(bytes: &[u8]) -> Result<String, String> {
    fold_perfdata_callchains_with_options(bytes, FoldOptions::default())
}

/// Collapses parsed perf sample callchains into folded stack lines.
///
/// # Errors
///
/// Returns an error when the `perf.data` input cannot be parsed.
pub fn fold_perfdata_callchains_with_options(
    bytes: &[u8],
    options: FoldOptions,
) -> Result<String, String> {
    let summary = summarize_perfdata(bytes)?;
    let mut counts = BTreeMap::<Vec<String>, u64>::new();
    for sample in &summary.sample_stacks {
        let frames = folded_frames_for_sample(sample, &summary.comms_by_pid);
        *counts.entry(frames).or_insert(0) += sample_count(sample, options);
    }

    let mut folded = String::new();
    for (callchain, count) in counts {
        folded.push_str(&render_folded_stack(
            callchain.iter().map(String::as_str),
            count,
        ));
        folded.push('\n');
    }
    Ok(folded)
}

fn sample_count(sample: &PerfSampleStack, options: FoldOptions) -> u64 {
    if options.count_periods {
        sample.period.unwrap_or(1)
    } else {
        1
    }
}

fn folded_frames_for_sample(
    sample: &PerfSampleStack,
    comms_by_pid: &BTreeMap<u32, String>,
) -> Vec<String> {
    let mut frames = if let Some(comm) = sample.pid.and_then(|pid| comms_by_pid.get(&pid)) {
        vec![comm.clone()]
    } else {
        Vec::new()
    };
    frames.extend(
        sample
            .callchain
            .iter()
            .copied()
            .filter(|frame| !is_perf_context_marker(*frame))
            .map(|frame| format!("0x{frame:x}")),
    );
    frames
}

fn parse_sample_for_summary(
    payload: &[u8],
    sample_layout: Option<SampleLayout>,
) -> Result<Option<PerfSampleStack>, String> {
    if let Some(layout) = sample_layout {
        parse_sample_record(payload, layout).map(|record| {
            Some(PerfSampleStack {
                pid: record.pid,
                period: record.period,
                callchain: record.callchain,
            })
        })
    } else {
        Ok(None)
    }
}

fn first_sample_layout(
    bytes: &[u8],
    header: crate::perfdata::header::PerfHeader,
) -> Result<Option<SampleLayout>, String> {
    Ok(parse_file_attrs(bytes, header)?
        .first()
        .map(|attr| SampleLayout {
            sample_type: attr.sample_type,
        }))
}
