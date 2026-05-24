use crate::perfdata::endian::{read_u16, read_u32};
use crate::perfdata::header::PerfHeader;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfRecordHeader {
    pub record_type: u32,
    pub misc: u16,
    pub size: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfRecord<'a> {
    pub offset: usize,
    pub header: PerfRecordHeader,
    pub payload: &'a [u8],
}

pub fn parse_record_header(bytes: &[u8]) -> Result<PerfRecordHeader, String> {
    if bytes.len() < 8 {
        return Err("perf record header is shorter than 8 bytes".to_string());
    }

    Ok(PerfRecordHeader {
        record_type: read_u32(bytes, 0)?,
        misc: read_u16(bytes, 4)?,
        size: read_u16(bytes, 6)?,
    })
}

pub fn iter_records(bytes: &[u8], header: PerfHeader) -> Result<Vec<PerfRecord<'_>>, String> {
    let mut records = Vec::new();
    let mut offset = header.data_offset as usize;
    let end = offset
        .checked_add(header.data_size as usize)
        .ok_or_else(|| "perf data section size overflows usize".to_string())?;

    if end > bytes.len() {
        return Err("perf data section extends past end of file".to_string());
    }

    while offset < end {
        let record_header = parse_record_header(
            bytes.get(offset..offset + 8)
                .ok_or_else(|| format!("truncated perf record header at offset {offset}"))?,
        )?;
        let size = record_header.size as usize;
        if size < 8 {
            return Err(format!("invalid perf record size {size} at offset {offset}"));
        }
        let next = offset
            .checked_add(size)
            .ok_or_else(|| format!("perf record size overflows at offset {offset}"))?;
        if next > end {
            return Err(format!("perf record overruns data section at offset {offset}"));
        }
        records.push(PerfRecord {
            offset,
            header: record_header,
            payload: &bytes[offset + 8..next],
        });
        offset = next;
    }

    Ok(records)
}
