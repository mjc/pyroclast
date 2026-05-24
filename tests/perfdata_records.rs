use pyroclast::perfdata::header::parse_header;
use pyroclast::perfdata::records::{
    PerfRecordHeader, iter_records, parse_comm_record, parse_record_header,
};

#[test]
fn parses_perf_record_header() {
    let mut bytes = [0; 8];
    bytes[0..4].copy_from_slice(&9u32.to_le_bytes());
    bytes[4..6].copy_from_slice(&0u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&24u16.to_le_bytes());

    let header = parse_record_header(&bytes).expect("record header");

    assert_eq!(
        header,
        PerfRecordHeader {
            record_type: 9,
            misc: 0,
            size: 24,
        }
    );
}

#[test]
fn rejects_short_perf_record_header() {
    let error = parse_record_header(&[0; 7]).expect_err("short header");

    assert!(error.contains("record header"));
}

#[test]
fn iterates_records_from_perfdata_data_section() {
    let bytes = perfdata_with_records([record_bytes(3, b"comm"), record_bytes(9, b"sample")]);
    let header = parse_header(&bytes).expect("perf header");

    let records = iter_records(&bytes, header).expect("records");

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].header.record_type, 3);
    assert_eq!(records[0].payload, b"comm");
    assert_eq!(records[1].header.record_type, 9);
    assert_eq!(records[1].payload, b"sample");
}

#[test]
fn parses_comm_record_payload() {
    let mut payload = Vec::new();
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(b"sftp-s3\0");

    let comm = parse_comm_record(&payload).expect("comm record");

    assert_eq!(comm.pid, 123);
    assert_eq!(comm.tid, 456);
    assert_eq!(comm.comm, "sftp-s3");
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

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
