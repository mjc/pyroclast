use std::collections::BTreeMap;

use crate::perfdata::header::parse_header;
use crate::perfdata::records::{iter_records, parse_comm_record, parse_mmap_record};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfSummary {
    pub total_records: usize,
    pub record_counts: BTreeMap<u32, usize>,
    pub comms: Vec<String>,
    pub mmaps: Vec<String>,
}

impl PerfSummary {
    pub fn record_count(&self, record_type: u32) -> usize {
        self.record_counts.get(&record_type).copied().unwrap_or(0)
    }
}

pub fn summarize_perfdata(bytes: &[u8]) -> Result<PerfSummary, String> {
    let header = parse_header(bytes)?;
    let records = iter_records(bytes, header)?;
    let mut summary = PerfSummary {
        total_records: 0,
        record_counts: BTreeMap::new(),
        comms: Vec::new(),
        mmaps: Vec::new(),
    };

    for record in records {
        summary.total_records += 1;
        *summary
            .record_counts
            .entry(record.header.record_type)
            .or_insert(0) += 1;
        if record.header.record_type == 3 {
            summary.comms.push(parse_comm_record(record.payload)?.comm);
        }
        if record.header.record_type == 1 {
            summary.mmaps.push(parse_mmap_record(record.payload)?.path);
        }
    }

    Ok(summary)
}
