const PERF_MAGIC: &[u8; 8] = b"PERFILE2";

use crate::perfdata::endian::read_u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfHeader {
    pub header_size: u64,
    pub attr_offset: u64,
    pub attr_size: u64,
    pub data_offset: u64,
    pub data_size: u64,
}

pub fn parse_header(bytes: &[u8]) -> Result<PerfHeader, String> {
    if bytes.len() < 104 {
        return Err("perf.data header is shorter than 104 bytes".to_string());
    }
    if &bytes[..8] != PERF_MAGIC {
        return Err("perf.data magic is not PERFILE2".to_string());
    }

    let header_size = read_u64(bytes, 8)?;
    if header_size < 104 {
        return Err(format!("perf.data header size is too small: {header_size}"));
    }

    Ok(PerfHeader {
        header_size,
        attr_offset: read_u64(bytes, 24)?,
        attr_size: read_u64(bytes, 32)?,
        data_offset: read_u64(bytes, 40)?,
        data_size: read_u64(bytes, 48)?,
    })
}
