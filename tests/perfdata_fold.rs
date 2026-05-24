use pyroclast::perfdata::fold::summarize_perfdata;

#[test]
fn summarizes_record_counts_and_comm_names() {
    let bytes = perfdata_with_records([
        record_bytes(3, &comm_payload(1, 2, "sftp-s3")),
        record_bytes(9, b"sample"),
    ]);

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.total_records, 2);
    assert_eq!(summary.record_count(3), 1);
    assert_eq!(summary.record_count(9), 1);
    assert_eq!(summary.comms, vec!["sftp-s3"]);
}

fn perfdata_with_records<const N: usize>(records: [Vec<u8>; N]) -> Vec<u8> {
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 40, 104);
    put_u64(&mut bytes, 48, data_size as u64);
    for record in records {
        bytes.extend(record);
    }
    bytes
}

fn record_bytes(record_type: u32, payload: &[u8]) -> Vec<u8> {
    let size = 8 + payload.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.extend(record_type.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend((size as u16).to_le_bytes());
    bytes.extend(payload);
    bytes
}

fn comm_payload(pid: u32, tid: u32, comm: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(comm.as_bytes());
    payload.push(0);
    payload
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
