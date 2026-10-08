use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;

use super::{
    FileSource, ParsedRecord, RecordSource, SampleLayouts, header_arch_from_file,
    parse_record_with_context, parse_sample_record_metadata, perfdata_header_from_file,
    sample_layouts_from_file, validate_perfdata_sections,
};
use crate::perfdata::records::PERF_RECORD_SAMPLE;

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
    let mut offset = usize::try_from(header.data_offset)
        .map_err(|_| "perf data section offset exceeds usize".to_string())?;
    let size = usize::try_from(header.data_size)
        .map_err(|_| "perf data section size exceeds usize".to_string())?;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| "perf data section range overflows usize".to_string())?;
    let mut metadata = PerfMetadata::default();
    while offset < end {
        let record = source.record_at(offset, end)?;
        offset += usize::from(record.header.size);
        let result = if record.header.record_type == PERF_RECORD_SAMPLE {
            visit_sample(record.payload, &layouts, &mut visit)
        } else {
            parse_record_with_context(record).map(|record| metadata.record(record))
        };
        result.map_err(|error| {
            format!(
                "failed to parse record type {} at offset {}: {error}",
                record.header.record_type, record.offset
            )
        })?;
    }
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
    fn record(&mut self, record: ParsedRecord) {
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
                self.lost_records = self.lost_records.saturating_add(record.lost);
            }
            ParsedRecord::LostSamples(record) => {
                self.lost_records = self.lost_records.saturating_add(record.lost);
            }
            _ => {}
        }
    }
}

/// Recorded host-kernel maps only; no sample payload is decoded or retained.
pub(crate) struct RecordedKernelMap {
    pub path: String,
    pub start: u64,
    pub pgoff: u64,
    pub prot: u32,
}

pub(crate) fn recorded_kernel_maps_file(
    path: &Path,
) -> Result<(super::PerfArch, Vec<RecordedKernelMap>), String> {
    use crate::perfdata::records::{
        PERF_RECORD_MISC_CPUMODE_KERNEL, PERF_RECORD_MISC_CPUMODE_MASK, PERF_RECORD_MMAP,
        PERF_RECORD_MMAP2,
    };
    let file = File::open(path).map_err(|error| error.to_string())?;
    let (header, bytes) = perfdata_header_from_file(&file)?;
    let mut source = FileSource::new(&file)?;
    validate_perfdata_sections(header, source.len())?;
    let arch =
        super::perf_arch_from_header(header_arch_from_file(&file, header, &bytes)?.as_deref());
    let mut offset = usize::try_from(header.data_offset).map_err(|error| error.to_string())?;
    let end = offset
        .checked_add(usize::try_from(header.data_size).map_err(|error| error.to_string())?)
        .ok_or("kernel metadata range overflows")?;
    let mut mappings = Vec::new();
    while offset < end {
        let record = source.record_at(offset, end)?;
        offset += usize::from(record.header.size);
        if !matches!(
            record.header.record_type,
            PERF_RECORD_MMAP | PERF_RECORD_MMAP2
        ) {
            continue;
        }
        let cpumode = record.header.misc & PERF_RECORD_MISC_CPUMODE_MASK;
        // A host kcore cannot identify guest maps, even if names/addresses coincide.
        if cpumode == 4 {
            return Err("guest kernel maps cannot use host kcore".into());
        }
        if cpumode != PERF_RECORD_MISC_CPUMODE_KERNEL {
            continue;
        }
        let mapping = match super::parse_fold_record(record)? {
            super::FoldRecord::Mmap { record, .. } => RecordedKernelMap {
                path: record.path,
                start: record.start,
                pgoff: record.pgoff,
                prot: 0,
            },
            super::FoldRecord::Mmap2 { record, .. } => RecordedKernelMap {
                path: record.path,
                start: record.start,
                pgoff: record.pgoff,
                prot: record.prot,
            },
            super::FoldRecord::Mmap2BuildId { record, .. } => RecordedKernelMap {
                path: record.path,
                start: record.start,
                pgoff: record.pgoff,
                prot: record.prot,
            },
            _ => unreachable!("only mmap records are parsed"),
        };
        mappings.push(mapping);
    }
    Ok((arch, mappings))
}
