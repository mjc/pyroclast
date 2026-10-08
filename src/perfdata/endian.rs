/// Reads a little-endian `u16` from a byte slice.
///
/// # Errors
///
/// Returns an error when the requested two-byte range is not present.
pub fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| format!("perf.data u16 range overflows at offset {offset}"))?;
    let data = bytes
        .get(offset..end)
        .ok_or_else(|| format!("unexpected end of perf.data at offset {offset}"))?;
    Ok(u16::from_le_bytes(
        data.try_into()
            .map_err(|_| "failed to read u16".to_string())?,
    ))
}

/// Reads a little-endian `u32` from a byte slice.
///
/// # Errors
///
/// Returns an error when the requested four-byte range is not present.
pub fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| format!("perf.data u32 range overflows at offset {offset}"))?;
    let data = bytes
        .get(offset..end)
        .ok_or_else(|| format!("unexpected end of perf.data at offset {offset}"))?;
    Ok(u32::from_le_bytes(
        data.try_into()
            .map_err(|_| "failed to read u32".to_string())?,
    ))
}

/// Reads a little-endian `u64` from a byte slice.
///
/// # Errors
///
/// Returns an error when the requested eight-byte range is not present.
pub fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| format!("perf.data u64 range overflows at offset {offset}"))?;
    let data = bytes
        .get(offset..end)
        .ok_or_else(|| format!("unexpected end of perf.data at offset {offset}"))?;
    Ok(u64::from_le_bytes(
        data.try_into()
            .map_err(|_| "failed to read u64".to_string())?,
    ))
}
