#![allow(dead_code)]

pub fn perfdata_with_records<const N: usize>(records: [Vec<u8>; N]) -> Vec<u8> {
    perfdata_with_records_and_attrs([], records)
}

pub fn perfdata_with_attrs<const N: usize>(attrs: [[u8; 144]; N]) -> Vec<u8> {
    let mut bytes = vec![0; 104];
    for attr in attrs {
        bytes.extend(attr);
    }
    bytes
}

pub fn perfdata_with_records_and_attrs<const A: usize, const R: usize>(
    attrs: [[u8; 144]; A],
    records: [Vec<u8>; R],
) -> Vec<u8> {
    let attr_size = attrs.len() * 144;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size;
    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    for attr in attrs {
        bytes.extend(attr);
    }
    for record in records {
        bytes.extend(record);
    }
    bytes
}

pub fn file_attr_bytes(sample_type: u64, ids_offset: u64, ids_size: u64) -> [u8; 144] {
    let mut bytes = [0; 144];
    put_u32(&mut bytes, 4, 128);
    put_u64(&mut bytes, 24, sample_type);
    put_u64(&mut bytes, 128, ids_offset);
    put_u64(&mut bytes, 136, ids_size);
    bytes
}

pub fn record_bytes(record_type: u32, payload: &[u8]) -> Vec<u8> {
    let size = 8 + payload.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.extend(record_type.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend((size as u16).to_le_bytes());
    bytes.extend(payload);
    bytes
}

pub fn sample_payload<const N: usize>(ip: u64, pid: u32, tid: u32, callchain: [u64; N]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

pub fn comm_payload(pid: u32, tid: u32, comm: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(comm.as_bytes());
    payload.push(0);
    payload
}

pub fn mmap_payload(pid: u32, tid: u32, start: u64, len: u64, pgoff: u64, path: &str) -> Vec<u8> {
    let mut payload = mmap_range_payload(pid, tid, start, len, pgoff);
    payload.extend(path.as_bytes());
    payload.push(0);
    payload
}

pub fn mmap2_payload(pid: u32, tid: u32, start: u64, len: u64, pgoff: u64, path: &str) -> Vec<u8> {
    let mut payload = mmap_range_payload(pid, tid, start, len, pgoff);
    payload.extend(8u32.to_le_bytes());
    payload.extend(1u32.to_le_bytes());
    payload.extend(99u64.to_le_bytes());
    payload.extend(7u64.to_le_bytes());
    payload.extend(5u32.to_le_bytes());
    payload.extend(2u32.to_le_bytes());
    payload.extend(path.as_bytes());
    payload.push(0);
    payload
}

pub fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn mmap_range_payload(pid: u32, tid: u32, start: u64, len: u64, pgoff: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(start.to_le_bytes());
    payload.extend(len.to_le_bytes());
    payload.extend(pgoff.to_le_bytes());
    payload
}
