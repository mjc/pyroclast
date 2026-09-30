use std::fmt::Write;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::perfdata::endian::{read_u16, read_u32};
use crate::perfdata::header::{feature_sections_from_reader, parse_feature_sections, parse_header};
use crate::perfdata::records::{
    PERF_RECORD_HEADER_BUILD_ID, PERF_RECORD_MISC_MMAP_BUILD_ID, PERF_RECORD_MMAP2, iter_records,
    parse_mmap2_build_id_record, parse_record_header,
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
    kernel_build_id_from_reader(&mut file)
}

fn kernel_build_id_from_reader(reader: &mut (impl Read + Seek)) -> Result<Option<String>, String> {
    let mut header_bytes = [0_u8; 104];
    reader
        .read_exact(&mut header_bytes)
        .map_err(|error| format!("failed to read perf.data header: {error}"))?;
    let header = parse_header(&header_bytes)?;
    let sections = feature_sections_from_reader(reader, &header, &header_bytes)?;
    let file_size = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| format!("failed to read perf.data size: {error}"))?;
    // tools/perf/util/header.c perf_header__read_build_ids() reads the feature
    // section directly, before session.c processes any sample records.
    if let Some(section) = sections
        .into_iter()
        .find(|section| section.feature == HEADER_BUILD_ID)
        && let Some(build_id) = kernel_build_id_from_record_section(
            reader,
            section.offset,
            section.size,
            file_size,
            true,
        )?
    {
        return Ok(Some(build_id));
    }
    kernel_build_id_from_record_section(
        reader,
        header.data_offset,
        header.data_size,
        file_size,
        false,
    )
}

fn kernel_build_id_from_record_section(
    reader: &mut (impl Read + Seek),
    mut offset: u64,
    size: u64,
    file_size: u64,
    feature: bool,
) -> Result<Option<String>, String> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| "build-id record section range overflows u64".to_string())?;
    if end > file_size {
        return Err("build-id record section extends past end of file".to_string());
    }
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|error| format!("failed to seek build-id record section: {error}"))?;
    let mut reader = BufReader::new(reader);
    let mut bytes = Vec::new();
    let mut kernel_build_id = None;
    while offset < end {
        if end - offset < 8 {
            return Err(format!("truncated perf record header at offset {offset}"));
        }
        let mut header_bytes = [0_u8; 8];
        reader.read_exact(&mut header_bytes).map_err(|error| {
            format!("failed to read perf record header at offset {offset}: {error}")
        })?;
        let header = parse_record_header(&header_bytes)?;
        if header.size < 8 || (feature && usize::from(header.size) < BUILD_ID_EVENT_MIN_SIZE) {
            return Err(format!(
                "invalid build-id record section record size {} at offset {offset}",
                header.size
            ));
        }
        let next = offset
            .checked_add(u64::from(header.size))
            .ok_or_else(|| "build-id record size overflows u64".to_string())?;
        if next > end {
            return Err(format!(
                "build-id record overruns section at offset {offset}"
            ));
        }
        let is_mmap_build_id = header.record_type == PERF_RECORD_MMAP2
            && header.misc & PERF_RECORD_MISC_MMAP_BUILD_ID != 0;
        if feature || header.record_type == PERF_RECORD_HEADER_BUILD_ID || is_mmap_build_id {
            bytes.resize(usize::from(header.size), 0);
            bytes[..8].copy_from_slice(&header_bytes);
            reader.read_exact(&mut bytes[8..]).map_err(|error| {
                format!("failed to read build-id record at offset {offset}: {error}")
            })?;
            let event = if feature {
                parse_build_id_event(&bytes)?
            } else if is_mmap_build_id {
                let mmap = parse_mmap2_build_id_record(&bytes[8..])?;
                BuildIdEvent {
                    pid: mmap.pid,
                    build_id: build_id_hex(&mmap.build_id),
                    filename: mmap.path,
                }
            } else {
                parse_build_id_record(header.misc, &bytes[8..])?
            };
            if kernel_build_id.is_none() && is_kernel_build_id_filename(&event.filename) {
                kernel_build_id = Some(event.build_id);
            }
        } else {
            reader
                .seek_relative(i64::from(header.size) - 8)
                .map_err(|error| {
                    format!("failed to skip perf record at offset {offset}: {error}")
                })?;
        }
        offset = next;
    }
    Ok(kernel_build_id)
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
    // tools/perf/util/build-id.c write_buildid() emits these feature-section
    // records WITHOUT setting header.type (it leaves it 0) and sets
    // PERF_RECORD_MISC_BUILD_ID_SIZE in misc with the real build-id length in
    // the size byte at offset 20 of the 24-byte build_id field (record offset
    // 32). Do not gate on the record type; rely on the size field (offset 6)
    // for record framing, as perf_header__read_build_ids does.
    let misc = read_u16(record, 4)?;
    let build_id_size = if misc & PERF_RECORD_MISC_BUILD_ID_SIZE != 0 {
        let size = usize::from(
            *record
                .get(12 + BUILD_ID_SIZE)
                .ok_or_else(|| "truncated build-id size byte".to_string())?,
        );
        if size > BUILD_ID_SIZE {
            return Err(format!(
                "build-id event build-id size {size} exceeds {BUILD_ID_SIZE} bytes"
            ));
        }
        size
    } else {
        BUILD_ID_SIZE
    };

    Ok(BuildIdEvent {
        pid: read_u32(record, 8)?,
        build_id: build_id_hex(&record[12..12 + build_id_size]),
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

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek, SeekFrom};

    struct CountingReader {
        cursor: Cursor<Vec<u8>>,
        bytes_read: usize,
    }

    impl Read for CountingReader {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let count = self.cursor.read(bytes)?;
            self.bytes_read += count;
            Ok(count)
        }
    }

    impl Seek for CountingReader {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.cursor.seek(position)
        }
    }

    #[test]
    fn kernel_build_id_feature_lookup_does_not_read_sample_data_like_perf_header() {
        // tools/perf/util/header.c perf_header__read_build_ids() reads only
        // the feature records, not the perf.data sample section.
        let data_size = 1024 * 1024;
        let table_offset = 104 + data_size;
        let filename = b"[kernel.kallsyms]\0";
        let feature_size = super::BUILD_ID_EVENT_MIN_SIZE + filename.len();
        let feature_offset = table_offset + 16;
        let mut bytes = vec![0; feature_offset + feature_size];
        bytes[..8].copy_from_slice(b"PERFILE2");
        bytes[8..16].copy_from_slice(&104_u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&104_u64.to_le_bytes());
        bytes[48..56].copy_from_slice(&(data_size as u64).to_le_bytes());
        bytes[72..80].copy_from_slice(&(1_u64 << super::HEADER_BUILD_ID).to_le_bytes());
        for record in bytes[104..table_offset].as_chunks_mut::<8>().0 {
            record[..4]
                .copy_from_slice(&crate::perfdata::records::PERF_RECORD_SAMPLE.to_le_bytes());
            record[6..8].copy_from_slice(&8_u16.to_le_bytes());
        }
        bytes[table_offset..table_offset + 8]
            .copy_from_slice(&(feature_offset as u64).to_le_bytes());
        bytes[table_offset + 8..table_offset + 16]
            .copy_from_slice(&(feature_size as u64).to_le_bytes());
        bytes[feature_offset + 6..feature_offset + 8]
            .copy_from_slice(&u16::try_from(feature_size).unwrap().to_le_bytes());
        bytes[feature_offset + 12..feature_offset + 32].fill(0xab);
        bytes[feature_offset + 36..].copy_from_slice(filename);
        let mut reader = CountingReader {
            cursor: Cursor::new(bytes),
            bytes_read: 0,
        };

        assert_eq!(
            super::kernel_build_id_from_reader(&mut reader).unwrap(),
            Some("ab".repeat(20))
        );
        assert!(
            reader.bytes_read <= 4096,
            "build-ID lookup read {} bytes instead of just the metadata",
            reader.bytes_read
        );
    }

    #[test]
    fn kernel_build_id_record_fallback_skips_unrelated_sample_payloads() {
        let record_size = 64 * 1024 - 8;
        let data_size = record_size * 16;
        let mut bytes = vec![0; 104 + data_size];
        bytes[..8].copy_from_slice(b"PERFILE2");
        bytes[8..16].copy_from_slice(&104_u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&104_u64.to_le_bytes());
        bytes[48..56].copy_from_slice(&(data_size as u64).to_le_bytes());
        for record in bytes[104..].chunks_exact_mut(record_size) {
            record[..4]
                .copy_from_slice(&crate::perfdata::records::PERF_RECORD_SAMPLE.to_le_bytes());
            record[6..8].copy_from_slice(&u16::try_from(record_size).unwrap().to_le_bytes());
        }
        let mut reader = CountingReader {
            cursor: Cursor::new(bytes),
            bytes_read: 0,
        };
        assert_eq!(
            super::kernel_build_id_from_reader(&mut reader).unwrap(),
            None
        );
        assert!(
            reader.bytes_read < data_size / 4,
            "build-ID fallback read {} bytes of unrelated payloads",
            reader.bytes_read
        );
    }
}
