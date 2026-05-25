use std::fmt::Write;
use std::path::Path;

use crate::perfdata::endian::{read_u16, read_u32};
use crate::perfdata::header::{parse_feature_sections, parse_header};

const PERF_RECORD_HEADER_BUILD_ID: u32 = 67;
const HEADER_BUILD_ID: u16 = 2;
const BUILD_ID_SIZE: usize = 20;
const BUILD_ID_EVENT_MIN_SIZE: usize = 36;

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

/// Extracts the kernel build ID recorded in a `perf.data` file.
///
/// # Errors
///
/// Returns an error when the `perf.data` header or build-id feature payload is
/// malformed.
pub fn kernel_build_id_from_perfdata(bytes: &[u8]) -> Result<Option<String>, String> {
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

    Ok(parse_build_id_events(payload)?
        .into_iter()
        .find(|event| is_kernel_build_id_filename(&event.filename))
        .map(|event| event.build_id))
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

fn is_kernel_build_id_filename(filename: &str) -> bool {
    let path = Path::new(filename);
    path == Path::new("[kernel.kallsyms]")
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
