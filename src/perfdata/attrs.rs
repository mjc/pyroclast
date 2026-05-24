use crate::perfdata::endian::{read_u32, read_u64};
use crate::perfdata::header::PerfHeader;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfFileAttr {
    pub sample_type: u64,
    pub ids_offset: u64,
    pub ids_size: u64,
}

pub fn parse_file_attrs(bytes: &[u8], header: PerfHeader) -> Result<Vec<PerfFileAttr>, String> {
    let offset = header.attr_offset as usize;
    let size = header.attr_size as usize;
    if size == 0 {
        return Ok(Vec::new());
    }
    let end = offset
        .checked_add(size)
        .ok_or_else(|| "perf attr section size overflows usize".to_string())?;
    if end > bytes.len() {
        return Err("perf attr section extends past end of file".to_string());
    }

    let mut attrs = Vec::new();
    let mut cursor = offset;
    while cursor < end {
        let attr_size = read_u32(bytes, cursor + 4)? as usize;
        if attr_size < 32 {
            return Err(format!("perf attr size is too small: {attr_size}"));
        }
        let file_attr_size = attr_size
            .checked_add(16)
            .ok_or_else(|| "perf file attr size overflows usize".to_string())?;
        let next = cursor
            .checked_add(file_attr_size)
            .ok_or_else(|| "perf file attr offset overflows usize".to_string())?;
        if next > end {
            return Err("perf file attr extends past attr section".to_string());
        }

        attrs.push(PerfFileAttr {
            sample_type: read_u64(bytes, cursor + 24)?,
            ids_offset: read_u64(bytes, cursor + attr_size)?,
            ids_size: read_u64(bytes, cursor + attr_size + 8)?,
        });
        cursor = next;
    }

    Ok(attrs)
}
