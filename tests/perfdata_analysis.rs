use pyroclast::perfdata::analysis::{analyze_perfdata, analyze_perfdata_file};
use pyroclast::perfdata::samples::{
    PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_PERIOD, PERF_SAMPLE_TID,
};

#[test]
fn analyzes_threads_leaf_ips_and_edges() {
    let perfdata = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(1, 11, "reader")),
            record_bytes(3, &comm_payload(2, 22, "writer")),
            record_bytes(9, &sample_payload(0x1000, 1, 11, 7, [0x1000, 0x2000])),
            record_bytes(9, &sample_payload(0x3000, 2, 22, 5, [0x3000, 0x4000])),
            record_bytes(9, &sample_payload(0x1000, 1, 11, 3, [0x1000, 0x2000])),
        ],
    );

    let report = analyze_perfdata(&perfdata, 10).expect("analysis");

    assert_eq!(report.total_samples, 3);
    assert_eq!(report.weighted_samples, 15);
    assert_eq!(report.threads[0].comm, "reader");
    assert_eq!(report.threads[0].tid, 11);
    assert_eq!(report.threads[0].samples, 2);
    assert_eq!(report.threads[0].weighted_samples, 10);
    assert_eq!(report.top_leaf_ips[0].ip, "0x0000000000001000");
    assert_eq!(report.top_leaf_ips[0].samples, 2);
    assert_eq!(report.top_leaf_ips[0].weighted_samples, 10);
    assert_eq!(report.top_edges[0].caller, "0x0000000000002000");
    assert_eq!(report.top_edges[0].callee, "0x0000000000001000");
}

#[test]
fn ignores_perf_context_markers_when_ranking_leaf_ips() {
    let perfdata = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(0x1000, 1, 11, 7, [0xffff_ffff_ffff_ff80, 0x1000, 0x2000]),
        )],
    );

    let report = analyze_perfdata(&perfdata, 10).expect("analysis");

    assert_eq!(report.top_leaf_ips[0].ip, "0x0000000000001000");
    assert_eq!(report.top_edges[0].caller, "0x0000000000002000");
    assert_eq!(report.top_edges[0].callee, "0x0000000000001000");
}

#[test]
fn analyzes_perfdata_from_file_without_requiring_a_byte_vec() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("perf.data");
    std::fs::write(
        &path,
        perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            [record_bytes(9, &sample_payload(0x1000, 1, 11, 7, [0x1000]))],
        ),
    )
    .expect("perfdata");

    let report = analyze_perfdata_file(&path, 10).expect("file analysis");

    assert_eq!(report.total_samples, 1);
    assert_eq!(report.weighted_samples, 7);
    assert_eq!(report.top_leaf_ips[0].ip, "0x0000000000001000");
}

fn perfdata_with_records_and_attrs<const A: usize, const R: usize>(
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

fn file_attr_bytes(sample_type: u64, ids_offset: u64, ids_size: u64) -> [u8; 144] {
    let mut bytes = [0; 144];
    put_u32(&mut bytes, 4, 128);
    put_u64(&mut bytes, 24, sample_type);
    put_u64(&mut bytes, 128, ids_offset);
    put_u64(&mut bytes, 136, ids_size);
    bytes
}

fn record_bytes(record_type: u32, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend(record_type.to_le_bytes());
    record.extend(0_u16.to_le_bytes());
    record.extend(
        u16::try_from(8 + payload.len())
            .expect("record size")
            .to_le_bytes(),
    );
    record.extend(payload);
    record
}

fn sample_payload<const N: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((N as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn comm_payload(pid: u32, tid: u32, comm: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(comm.as_bytes());
    payload.push(0);
    payload
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
