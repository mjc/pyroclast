use std::fmt::Write;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::perfdata::endian::{read_u16, read_u32, read_u64};
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

/// Extracts all build IDs recorded in a `perf.data` file header.
///
/// # Errors
///
/// Returns an error when the `perf.data` header or build-id feature payload is
/// malformed.
pub fn build_id_events_from_perfdata(bytes: &[u8]) -> Result<Vec<BuildIdEvent>, String> {
    let Some(payload) = build_id_feature_payload(bytes)? else {
        return Ok(Vec::new());
    };
    parse_build_id_events(payload)
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
    let Some(payload) = build_id_feature_payload_from_file(&mut file)? else {
        return Ok(None);
    };
    Ok(parse_build_id_events(&payload)?
        .into_iter()
        .find(|event| is_kernel_build_id_filename(&event.filename))
        .map(|event| event.build_id))
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

fn build_id_feature_payload_from_file(file: &mut File) -> Result<Option<Vec<u8>>, String> {
    let mut header_bytes = [0_u8; 104];
    file.read_exact(&mut header_bytes)
        .map_err(|error| format!("failed to read perf.data header: {error}"))?;
    let header = parse_header(&header_bytes)?;
    let feature_ids = feature_ids_from_header(&header_bytes)?;
    let feature_table_offset = header
        .data_offset
        .checked_add(header.data_size)
        .ok_or_else(|| "perf.data feature table offset overflows u64".to_string())?;
    let table_size = feature_ids
        .len()
        .checked_mul(16)
        .ok_or_else(|| "perf.data feature table size overflows usize".to_string())?;
    let mut feature_table = vec![0_u8; table_size];
    file.seek(SeekFrom::Start(feature_table_offset))
        .map_err(|error| format!("failed to seek perf.data feature table: {error}"))?;
    file.read_exact(&mut feature_table)
        .map_err(|error| format!("failed to read perf.data feature table: {error}"))?;
    let Some((offset, size)) = feature_ids
        .into_iter()
        .enumerate()
        .find_map(|(index, feature)| {
            (feature == HEADER_BUILD_ID).then(|| {
                let offset = read_u64(&feature_table, index * 16).ok()?;
                let size = read_u64(&feature_table, index * 16 + 8).ok()?;
                Some((offset, size))
            })?
        })
    else {
        return Ok(None);
    };
    let size =
        usize::try_from(size).map_err(|_| "build-id feature size exceeds usize".to_string())?;
    let mut payload = vec![0_u8; size];
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| format!("failed to seek build-id feature payload: {error}"))?;
    file.read_exact(&mut payload)
        .map_err(|error| format!("failed to read build-id feature payload: {error}"))?;
    Ok(Some(payload))
}

fn feature_ids_from_header(bytes: &[u8]) -> Result<Vec<u16>, String> {
    let mut features = Vec::new();
    for word_index in 0..4 {
        let word = read_u64(bytes, 56 + word_index * 8)?;
        for bit_index in 0..64 {
            if word & (1_u64 << bit_index) != 0 {
                let feature = u16::try_from(word_index * 64 + bit_index)
                    .map_err(|_| "perf.data feature bit exceeds u16".to_string())?;
                features.push(feature);
            }
        }
    }
    Ok(features)
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
