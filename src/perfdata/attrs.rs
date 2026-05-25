use crate::perfdata::endian::{read_u32, read_u64};
use crate::perfdata::header::PerfHeader;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfFileAttr {
    pub sample_type: u64,
    pub read_format: u64,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_regs_intr: u64,
    pub ids_offset: u64,
    pub ids_size: u64,
}

/// Parses the `perf_file_attr` records from the attr section.
///
/// # Errors
///
/// Returns an error when the attr section points outside the file or contains
/// truncated attr records.
pub fn parse_file_attrs(bytes: &[u8], header: PerfHeader) -> Result<Vec<PerfFileAttr>, String> {
    let offset = to_usize(header.attr_offset, "perf attr section offset")?;
    let size = to_usize(header.attr_size, "perf attr section size")?;
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
            read_format: read_optional_attr_u64(bytes, cursor, attr_size, 32)?,
            branch_sample_type: read_optional_attr_u64(bytes, cursor, attr_size, 72)?,
            sample_regs_user: read_optional_attr_u64(bytes, cursor, attr_size, 80)?,
            sample_regs_intr: read_optional_attr_u64(bytes, cursor, attr_size, 96)?,
            ids_offset: read_u64(bytes, cursor + attr_size)?,
            ids_size: read_u64(bytes, cursor + attr_size + 8)?,
        });
        cursor = next;
    }

    Ok(attrs)
}

/// Parses the event IDs referenced by a `perf_file_attr`.
///
/// # Errors
///
/// Returns an error when the ID section is not `u64` aligned or points outside
/// the file.
pub fn parse_file_attr_ids(bytes: &[u8], attr: &PerfFileAttr) -> Result<Vec<u64>, String> {
    if !attr.ids_size.is_multiple_of(8) {
        return Err("perf attr id section size is not a multiple of 8".to_string());
    }
    let offset = to_usize(attr.ids_offset, "perf attr id section offset")?;
    let size = to_usize(attr.ids_size, "perf attr id section size")?;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| "perf attr id section size overflows usize".to_string())?;
    if end > bytes.len() {
        return Err("perf attr id section extends past end of file".to_string());
    }

    let mut ids = Vec::with_capacity(size / 8);
    let mut cursor = offset;
    while cursor < end {
        ids.push(read_u64(bytes, cursor)?);
        cursor += 8;
    }
    Ok(ids)
}

fn read_optional_attr_u64(
    bytes: &[u8],
    attr_start: usize,
    attr_size: usize,
    field_offset: usize,
) -> Result<u64, String> {
    if attr_size >= field_offset + 8 {
        read_u64(bytes, attr_start + field_offset)
    } else {
        Ok(0)
    }
}

fn to_usize(value: u64, name: &str) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("{name} does not fit in usize"))
}
