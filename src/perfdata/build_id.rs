use std::fmt::Write;

use crate::perfdata::endian::{read_u16, read_u32};

const PERF_RECORD_HEADER_BUILD_ID: u32 = 67;
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
