use std::collections::BTreeMap;

use crate::folded::render_address_stack;
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
    pub mmaps: Vec<String>,
    pub sample_callchains: Vec<Vec<u64>>,
}

impl PerfSummary {
    pub fn record_count(&self, record_type: u32) -> usize {
        self.record_counts.get(&record_type).copied().unwrap_or(0)
    }
}

pub fn summarize_perfdata(bytes: &[u8]) -> Result<PerfSummary, String> {
    let header = parse_header(bytes)?;
    let sample_layout = first_sample_layout(bytes, header)?;
    let records = iter_records(bytes, header)?;
    let mut summary = PerfSummary {
        total_records: 0,
        record_counts: BTreeMap::new(),
        comms: Vec::new(),
        mmaps: Vec::new(),
        sample_callchains: Vec::new(),
    };

    for record in records {
        summary.total_records += 1;
        *summary
            .record_counts
            .entry(record.header.record_type)
            .or_insert(0) += 1;
        let record_result: Result<(), String> = match record.header.record_type {
            PERF_RECORD_COMM => parse_comm_record(record.payload).map(|record| {
                summary.comms.push(record.comm);
            }),
            PERF_RECORD_MMAP => parse_mmap_record(record.payload).map(|record| {
                summary.mmaps.push(record.path);
            }),
            PERF_RECORD_SAMPLE => {
                parse_sample_for_summary(record.payload, sample_layout).map(|callchain| {
                    if let Some(callchain) = callchain {
                        summary.sample_callchains.push(callchain);
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

pub fn fold_perfdata_callchains(bytes: &[u8]) -> Result<String, String> {
    let summary = summarize_perfdata(bytes)?;
    let mut counts = BTreeMap::<Vec<u64>, u64>::new();
    for callchain in summary.sample_callchains {
        let frames = callchain
            .into_iter()
            .filter(|frame| !is_perf_context_marker(*frame))
            .collect::<Vec<_>>();
        *counts.entry(frames).or_insert(0) += 1;
    }

    let mut folded = String::new();
    for (callchain, count) in counts {
        folded.push_str(&render_address_stack(callchain, count));
        folded.push('\n');
    }
    Ok(folded)
}

fn parse_sample_for_summary(
    payload: &[u8],
    sample_layout: Option<SampleLayout>,
) -> Result<Option<Vec<u64>>, String> {
    if let Some(layout) = sample_layout {
        parse_sample_record(payload, layout).map(|record| Some(record.callchain))
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
