use crate::perfdata::endian::{read_u16, read_u32};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfRecordHeader {
    pub record_type: u32,
    pub misc: u16,
    pub size: u16,
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
