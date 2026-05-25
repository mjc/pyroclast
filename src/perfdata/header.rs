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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfFeatureSection {
    pub feature: u16,
    pub offset: u64,
    pub size: u64,
}

/// Parses the fixed-size `perf.data` file header.
///
/// # Errors
///
/// Returns an error when the file is too short, has the wrong magic, or
/// contains invalid section offsets.
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

/// Parses optional perf header feature sections.
///
/// # Errors
///
/// Returns an error when the feature table is truncated or offsets overflow.
pub fn parse_feature_sections(
    bytes: &[u8],
    header: &PerfHeader,
) -> Result<Vec<PerfFeatureSection>, String> {
    let mut table_offset = feature_table_offset(header)?;
    let mut sections = Vec::new();

    for feature in set_feature_bits(bytes)? {
        let offset = read_u64(bytes, table_offset)?;
        let size = read_u64(bytes, table_offset + 8)?;
        sections.push(PerfFeatureSection {
            feature,
            offset,
            size,
        });
        table_offset += 16;
    }

    Ok(sections)
}

fn feature_table_offset(header: &PerfHeader) -> Result<usize, String> {
    let offset = header
        .data_offset
        .checked_add(header.data_size)
        .ok_or_else(|| "perf.data feature table offset overflows u64".to_string())?;
    usize::try_from(offset).map_err(|_| "perf.data feature table offset exceeds usize".to_string())
}

fn set_feature_bits(bytes: &[u8]) -> Result<Vec<u16>, String> {
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
