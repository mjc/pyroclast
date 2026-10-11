use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;

use super::{
    FileSource, ParsedRecord, RecordSource, SampleLayouts, header_arch_from_file,
    parse_record_with_context, parse_sample_record_metadata, perfdata_header_from_file,
    sample_layouts_from_file, validate_perfdata_sections, visit_ordered_records,
};
use crate::perfdata::records::{
    PERF_RECORD_MISC_LOST_SAMPLES_BPF, PERF_RECORD_SAMPLE, has_misc_flag,
};

#[derive(Clone, Copy)]
pub(crate) struct PerfSampleMetadata {
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub time: Option<u64>,
    pub cpu: Option<u32>,
    pub period: u64,
}

#[derive(Default)]
pub(crate) struct PerfMetadata {
    pub comms_by_tid: BTreeMap<u32, String>,
    pub lost_records: u64,
    pub lost_samples: u64,
    pub dropped_samples: u64,
}

/// Visits sample metadata without retaining samples or copying their callchains.
/// The completed recording must remain unchanged for the duration of the visit.
pub(crate) fn visit_perfdata_file_metadata(
    path: &Path,
    mut visit: impl FnMut(PerfSampleMetadata),
) -> Result<PerfMetadata, String> {
    let file = File::open(path).map_err(|error| format!("failed to open perf.data: {error}"))?;
    let (header, bytes) = perfdata_header_from_file(&file)?;
    let mut source = FileSource::new(&file)?;
    validate_perfdata_sections(header, source.len())?;
    let layouts = sample_layouts_from_file(&file, header, &bytes)?;
    // Validate the same architecture feature as the retained summary API, even
    // though thread/time metadata does not need architecture-specific registers.
    header_arch_from_file(&file, header, &bytes)?;
    let mut metadata = PerfMetadata::default();
    // Linux v7.2.9 tools/perf/builtin-report.c:1514,1622 enables ordering;
    // tools/perf/util/session.c:2937-2949 delivers queued events chronologically.
    // Reuse the borrowed visitor while parsing only sample metadata.
    visit_ordered_records(
        &mut source,
        header,
        &layouts,
        |_| {},
        |record, offset| {
            let result = if record.header.record_type == PERF_RECORD_SAMPLE {
                visit_sample(record.payload, &layouts, &mut visit)
            } else {
                parse_record_with_context(record)
                    .map(|parsed| metadata.record(parsed, record.header.misc))
            };
            result.map_err(|error| {
                format!(
                    "failed to parse record type {} at offset {}: {error}",
                    record.header.record_type, offset
                )
            })
        },
    )?;
    Ok(metadata)
}

fn visit_sample(
    payload: &[u8],
    layouts: &SampleLayouts,
    visit: &mut impl FnMut(PerfSampleMetadata),
) -> Result<(), String> {
    if let Some(event) = layouts.layout_for_payload(payload)?
        && let Some(sample) = parse_sample_record_metadata(payload, event.layout)?
    {
        visit(PerfSampleMetadata {
            pid: sample.pid,
            tid: sample.tid,
            time: sample.time,
            cpu: sample.cpu,
            period: sample.period.unwrap_or(event.default_period),
        });
    }
    Ok(())
}

impl PerfMetadata {
    fn record(&mut self, record: ParsedRecord, misc: u16) {
        match record {
            ParsedRecord::Comm(record) => {
                self.comms_by_tid
                    .insert(record.tid, record.comm.to_string());
            }
            ParsedRecord::Fork(record) => {
                if let Some(comm) = self.comms_by_tid.get(&record.ptid).cloned() {
                    self.comms_by_tid.insert(record.tid, comm);
                }
            }
            ParsedRecord::Lost(record) => {
                self.lost_records = self.lost_records.wrapping_add(record.lost);
            }
            ParsedRecord::LostSamples(record) => {
                let counter = if has_misc_flag(misc, PERF_RECORD_MISC_LOST_SAMPLES_BPF) {
                    &mut self.dropped_samples
                } else {
                    &mut self.lost_samples
                };
                *counter = counter.wrapping_add(record.lost);
            }
            _ => {}
        }
    }
}

pub(crate) fn perfdata_file_arch(path: &Path) -> Result<super::PerfArch, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    let (header, bytes) = perfdata_header_from_file(&file)?;
    let len = usize::try_from(file.metadata().map_err(|error| error.to_string())?.len())
        .map_err(|error| error.to_string())?;
    validate_perfdata_sections(header, len)?;
    Ok(super::perf_arch_from_header(
        header_arch_from_file(&file, header, &bytes)?.as_deref(),
    ))
}
