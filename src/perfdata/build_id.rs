use std::fmt::Write;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::perfdata::endian::{read_u16, read_u32};
use crate::perfdata::header::{parse_feature_sections, parse_header};
use crate::perfdata::records::{
    PERF_RECORD_HEADER_BUILD_ID, PERF_RECORD_MISC_MMAP_BUILD_ID, PERF_RECORD_MMAP2, iter_records,
    parse_mmap2_build_id_record,
};

const HEADER_BUILD_ID: u16 = 2;
const PERF_RECORD_MISC_BUILD_ID_SIZE: u16 = 1 << 15;
const BUILD_ID_SIZE: usize = 20;
const BUILD_ID_STORAGE_SIZE: usize = 24;
const BUILD_ID_EVENT_MIN_SIZE: usize = 36;
const BUILD_ID_RECORD_PAYLOAD_MIN_SIZE: usize = 28;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildIdEvent {
    pub pid: u32,
    pub build_id: String,
    pub filename: String,
}

/// Parses `HEADER_BUILD_ID` feature payload records.
///
/// # Errors
///
/// Returns an error when a record is truncated, has the wrong type, or carries
/// non-UTF-8 filename data.
pub fn parse_build_id_events(payload: &[u8]) -> Result<Vec<BuildIdEvent>, String> {
    let mut offset = 0;
    let mut events = Vec::new();
    while offset < payload.len() {
        let size = usize::from(read_u16(payload, offset + 6)?);
        if size < BUILD_ID_EVENT_MIN_SIZE {
            return Err(format!(
                "build-id event size {size} is shorter than 36 bytes"
            ));
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| "build-id event size overflows usize".to_string())?;
        let record = payload
            .get(offset..end)
            .ok_or_else(|| "truncated build-id event".to_string())?;
        events.push(parse_build_id_event(record)?);
        offset = end;
    }
    Ok(events)
}

/// Extracts all build IDs recorded in a `perf.data` file header.
///
/// # Errors
///
/// Returns an error when the `perf.data` header or build-id feature payload is
/// malformed.
pub fn build_id_events_from_perfdata(bytes: &[u8]) -> Result<Vec<BuildIdEvent>, String> {
    let mut events = match build_id_feature_payload(bytes)? {
        Some(payload) => parse_build_id_events(payload)?,
        None => Vec::new(),
    };
    events.extend(build_id_events_from_record_stream(bytes)?);
    Ok(events)
}

/// Extracts the kernel build ID recorded in a `perf.data` file.
///
/// # Errors
///
/// Returns an error when the `perf.data` header or build-id feature payload is
/// malformed.
pub fn kernel_build_id_from_perfdata(bytes: &[u8]) -> Result<Option<String>, String> {
    Ok(build_id_events_from_perfdata(bytes)?
        .into_iter()
        .find(|event| is_kernel_build_id_filename(&event.filename))
        .map(|event| event.build_id))
}

/// Extracts the kernel build ID recorded in a `perf.data` file from disk
/// without reading the entire file into memory.
///
/// # Errors
///
/// Returns an error when the `perf.data` header, feature table, or build-id
/// feature payload is malformed or cannot be read.
pub fn kernel_build_id_from_perfdata_file(path: &Path) -> Result<Option<String>, String> {
    let mut file =
        File::open(path).map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    Ok(build_id_events_from_perfdata(&bytes)?
        .into_iter()
        .find(|event| is_kernel_build_id_filename(&event.filename))
        .map(|event| event.build_id))
}

fn build_id_events_from_record_stream(bytes: &[u8]) -> Result<Vec<BuildIdEvent>, String> {
    let header = parse_header(bytes)?;
    let mut events = Vec::new();
    for record in iter_records(bytes, header)? {
        match record.header.record_type {
            PERF_RECORD_HEADER_BUILD_ID => {
                events.push(parse_build_id_record(record.header.misc, record.payload)?);
            }
            PERF_RECORD_MMAP2 if record.header.misc & PERF_RECORD_MISC_MMAP_BUILD_ID != 0 => {
                let mmap = parse_mmap2_build_id_record(record.payload)?;
                events.push(BuildIdEvent {
                    pid: mmap.pid,
                    build_id: build_id_hex(&mmap.build_id),
                    filename: mmap.path,
                });
            }
            _ => {}
        }
    }
    Ok(events)
}

fn build_id_feature_payload(bytes: &[u8]) -> Result<Option<&[u8]>, String> {
    let header = parse_header(bytes)?;
    let Some(section) = parse_feature_sections(bytes, &header)?
        .into_iter()
        .find(|section| section.feature == HEADER_BUILD_ID)
    else {
        return Ok(None);
    };
    let start = usize::try_from(section.offset)
        .map_err(|_| "build-id feature offset exceeds usize".to_string())?;
    let size = usize::try_from(section.size)
        .map_err(|_| "build-id feature size exceeds usize".to_string())?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| "build-id feature range overflows usize".to_string())?;
    let payload = bytes
        .get(start..end)
        .ok_or_else(|| "build-id feature payload is truncated".to_string())?;
    Ok(Some(payload))
}

fn parse_build_id_event(record: &[u8]) -> Result<BuildIdEvent, String> {
    let record_type = read_u32(record, 0)?;
    if record_type != PERF_RECORD_HEADER_BUILD_ID {
        return Err(format!(
            "expected PERF_RECORD_HEADER_BUILD_ID, got {record_type}"
        ));
    }

    Ok(BuildIdEvent {
        pid: read_u32(record, 8)?,
        build_id: build_id_hex(&record[12..12 + BUILD_ID_SIZE]),
        filename: filename(&record[BUILD_ID_EVENT_MIN_SIZE..])?,
    })
}

fn parse_build_id_record(misc: u16, payload: &[u8]) -> Result<BuildIdEvent, String> {
    if payload.len() < BUILD_ID_RECORD_PAYLOAD_MIN_SIZE {
        return Err("PERF_RECORD_HEADER_BUILD_ID payload is shorter than 28 bytes".to_string());
    }
    let build_id_size = if misc & PERF_RECORD_MISC_BUILD_ID_SIZE != 0 {
        usize::from(payload[24])
    } else {
        BUILD_ID_SIZE
    };
    if build_id_size > BUILD_ID_STORAGE_SIZE {
        return Err(format!(
            "PERF_RECORD_HEADER_BUILD_ID build-id size {build_id_size} exceeds 24 bytes"
        ));
    }

    Ok(BuildIdEvent {
        pid: read_u32(payload, 0)?,
        build_id: build_id_hex(&payload[4..4 + build_id_size]),
        filename: filename(&payload[BUILD_ID_RECORD_PAYLOAD_MIN_SIZE..])?,
    })
}

fn is_kernel_build_id_filename(filename: &str) -> bool {
    let path = Path::new(filename);
    path == Path::new("[kernel.kallsyms]")
        || filename.starts_with("[kernel.kallsyms]")
        || path == Path::new("[kernel]")
        || path == Path::new("[guest.kernel]")
}

fn build_id_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(hex, "{byte:02x}").expect("writing to a string cannot fail");
    }
    hex
}

fn filename(bytes: &[u8]) -> Result<String, String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end])
        .map(str::to_string)
        .map_err(|error| format!("build-id filename is not UTF-8: {error}"))
}
