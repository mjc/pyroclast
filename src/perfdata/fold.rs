use std::collections::BTreeMap;

use crate::perfdata::attrs::parse_file_attrs;
use crate::perfdata::header::parse_header;
use crate::perfdata::records::{
    iter_records, parse_comm_record, parse_mmap_record, parse_mmap2_record,
};
use crate::perfdata::samples::{SampleLayout, parse_sample_record};

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
        match record.header.record_type {
            PERF_RECORD_COMM => summary.comms.push(parse_comm_record(record.payload)?.comm),
            PERF_RECORD_MMAP => summary.mmaps.push(parse_mmap_record(record.payload)?.path),
            PERF_RECORD_SAMPLE => {
                if let Some(layout) = sample_layout {
                    summary
                        .sample_callchains
                        .push(parse_sample_record(record.payload, layout)?.callchain);
                }
            }
            PERF_RECORD_MMAP2 => summary.mmaps.push(parse_mmap2_record(record.payload)?.path),
            _ => {}
        }
    }

    Ok(summary)
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
