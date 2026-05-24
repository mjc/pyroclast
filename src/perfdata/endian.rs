pub fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let data = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| format!("unexpected end of perf.data at offset {offset}"))?;
    Ok(u64::from_le_bytes(
        data.try_into()
            .map_err(|_| "failed to read u64".to_string())?,
    ))
}
