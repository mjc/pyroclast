use pyroclast::perfdata::header::parse_header;
use pyroclast::perfdata::records::{
    ParsedRecord, PerfRecord, PerfRecordHeader, iter_records, parse_comm_record, parse_exit_record,
    parse_fork_record, parse_lost_record, parse_lost_samples_record, parse_mmap_record,
    parse_mmap2_build_id_record, parse_mmap2_record, parse_record, parse_record_header,
    parse_throttle_record, parse_unthrottle_record,
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

#[test]
fn dispatches_comm_record_by_perf_record_type() {
    let payload = {
        let mut payload = Vec::new();
        payload.extend(123u32.to_le_bytes());
        payload.extend(456u32.to_le_bytes());
        payload.extend(b"sftp-s3\0");
        payload
    };
    let record = PerfRecord {
        offset: 104,
        header: PerfRecordHeader {
            record_type: 3,
            misc: 0,
            size: u16::try_from(8 + payload.len()).expect("record size"),
        },
        payload: &payload,
    };

    let parsed = parse_record(record).expect("parsed record");

    assert_eq!(
        parsed,
        ParsedRecord::Comm(pyroclast::perfdata::records::CommRecord {
            pid: 123,
            tid: 456,
            comm: "sftp-s3".to_string(),
        })
    );
}

#[test]
fn parses_mmap_record_payload() {
    let mut payload = Vec::new();
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(0x7f00u64.to_le_bytes());
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(0x40u64.to_le_bytes());
    payload.extend(b"/usr/bin/sftp-s3\0");

    let mmap = parse_mmap_record(&payload).expect("mmap record");

    assert_eq!(mmap.pid, 123);
    assert_eq!(mmap.tid, 456);
    assert_eq!(mmap.start, 0x7f00);
    assert_eq!(mmap.len, 0x1000);
    assert_eq!(mmap.pgoff, 0x40);
    assert_eq!(mmap.path, "/usr/bin/sftp-s3");
}

#[test]
fn dispatches_mmap_record_by_perf_record_type() {
    let payload = mmap_payload();
    let record = PerfRecord {
        offset: 104,
        header: PerfRecordHeader {
            record_type: 1,
            misc: 0,
            size: u16::try_from(8 + payload.len()).expect("record size"),
        },
        payload: &payload,
    };

    let parsed = parse_record(record).expect("parsed record");

    assert_eq!(
        parsed,
        ParsedRecord::Mmap(pyroclast::perfdata::records::MmapRecord {
            pid: 123,
            tid: 456,
            start: 0x7f00,
            len: 0x1000,
            pgoff: 0x40,
            path: "/usr/bin/sftp-s3".to_string(),
        })
    );
}

#[test]
fn parses_mmap2_record_payload() {
    let mut payload = Vec::new();
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(0x7f00u64.to_le_bytes());
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(0x40u64.to_le_bytes());
    payload.extend(8u32.to_le_bytes());
    payload.extend(1u32.to_le_bytes());
    payload.extend(99u64.to_le_bytes());
    payload.extend(7u64.to_le_bytes());
    payload.extend(5u32.to_le_bytes());
    payload.extend(2u32.to_le_bytes());
    payload.extend(b"/usr/lib/libssl.so\0");

    let mmap = parse_mmap2_record(&payload).expect("mmap2 record");

    assert_eq!(mmap.pid, 123);
    assert_eq!(mmap.tid, 456);
    assert_eq!(mmap.start, 0x7f00);
    assert_eq!(mmap.len, 0x1000);
    assert_eq!(mmap.pgoff, 0x40);
    assert_eq!(mmap.major, 8);
    assert_eq!(mmap.minor, 1);
    assert_eq!(mmap.inode, 99);
    assert_eq!(mmap.inode_generation, 7);
    assert_eq!(mmap.prot, 5);
    assert_eq!(mmap.flags, 2);
    assert_eq!(mmap.path, "/usr/lib/libssl.so");
}

#[test]
fn parses_mmap2_build_id_payload_from_perf_event_header_shape() {
    let mut payload = Vec::new();
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(0x7f00u64.to_le_bytes());
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(0x40u64.to_le_bytes());
    payload.push(4);
    payload.push(0);
    payload.extend(0u16.to_le_bytes());
    payload.extend([0xaa, 0xbb, 0xcc, 0xdd]);
    payload.extend([0; 16]);
    payload.extend(5u32.to_le_bytes());
    payload.extend(2u32.to_le_bytes());
    payload.extend(b"/usr/lib/libssl.so\0");

    let mmap = parse_mmap2_build_id_record(&payload).expect("mmap2 build id record");

    assert_eq!(mmap.pid, 123);
    assert_eq!(mmap.tid, 456);
    assert_eq!(mmap.start, 0x7f00);
    assert_eq!(mmap.len, 0x1000);
    assert_eq!(mmap.pgoff, 0x40);
    assert_eq!(mmap.build_id_size, 4);
    assert_eq!(mmap.build_id, vec![0xaa, 0xbb, 0xcc, 0xdd]);
    assert_eq!(mmap.prot, 5);
    assert_eq!(mmap.flags, 2);
    assert_eq!(mmap.path, "/usr/lib/libssl.so");
}

#[test]
fn dispatches_mmap2_inode_record_by_perf_record_type() {
    let payload = mmap2_inode_payload();
    let record = PerfRecord {
        offset: 104,
        header: PerfRecordHeader {
            record_type: 10,
            misc: 0,
            size: u16::try_from(8 + payload.len()).expect("record size"),
        },
        payload: &payload,
    };

    let parsed = parse_record(record).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::Mmap2(_)));
}

#[test]
fn dispatches_mmap2_build_id_record_when_misc_flag_is_set() {
    let payload = mmap2_build_id_payload();
    let record = PerfRecord {
        offset: 104,
        header: PerfRecordHeader {
            record_type: 10,
            misc: 1 << 14,
            size: u16::try_from(8 + payload.len()).expect("record size"),
        },
        payload: &payload,
    };

    let parsed = parse_record(record).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::Mmap2BuildId(_)));
}

#[test]
fn parses_fork_record_payload_from_perf_event_header_shape() {
    let mut payload = Vec::new();
    payload.extend(123u32.to_le_bytes());
    payload.extend(12u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(45u32.to_le_bytes());
    payload.extend(99_000u64.to_le_bytes());

    let fork = parse_fork_record(&payload).expect("fork record");

    assert_eq!(fork.pid, 123);
    assert_eq!(fork.ppid, 12);
    assert_eq!(fork.tid, 456);
    assert_eq!(fork.ptid, 45);
    assert_eq!(fork.time, 99_000);
}

#[test]
fn dispatches_fork_record_by_perf_record_type() {
    let payload = lifecycle_payload();
    let record = PerfRecord {
        offset: 104,
        header: PerfRecordHeader {
            record_type: 7,
            misc: 0,
            size: u16::try_from(8 + payload.len()).expect("record size"),
        },
        payload: &payload,
    };

    let parsed = parse_record(record).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::Fork(_)));
}

#[test]
fn parses_exit_record_payload_from_perf_event_header_shape() {
    let mut payload = Vec::new();
    payload.extend(123u32.to_le_bytes());
    payload.extend(12u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(45u32.to_le_bytes());
    payload.extend(99_000u64.to_le_bytes());

    let exit = parse_exit_record(&payload).expect("exit record");

    assert_eq!(exit.pid, 123);
    assert_eq!(exit.ppid, 12);
    assert_eq!(exit.tid, 456);
    assert_eq!(exit.ptid, 45);
    assert_eq!(exit.time, 99_000);
}

#[test]
fn dispatches_exit_record_by_perf_record_type() {
    let payload = lifecycle_payload();
    let record = PerfRecord {
        offset: 104,
        header: PerfRecordHeader {
            record_type: 4,
            misc: 0,
            size: u16::try_from(8 + payload.len()).expect("record size"),
        },
        payload: &payload,
    };

    let parsed = parse_record(record).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::Exit(_)));
}

#[test]
fn parses_lost_record_payload_from_perf_event_header_shape() {
    let mut payload = Vec::new();
    payload.extend(77u64.to_le_bytes());
    payload.extend(1234u64.to_le_bytes());

    let lost = parse_lost_record(&payload).expect("lost record");

    assert_eq!(lost.id, 77);
    assert_eq!(lost.lost, 1234);
}

#[test]
fn dispatches_lost_record_by_perf_record_type() {
    let payload = lost_payload();
    let record = PerfRecord {
        offset: 104,
        header: PerfRecordHeader {
            record_type: 2,
            misc: 0,
            size: u16::try_from(8 + payload.len()).expect("record size"),
        },
        payload: &payload,
    };

    let parsed = parse_record(record).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::Lost(_)));
}

#[test]
fn parses_lost_samples_record_payload_from_perf_event_header_shape() {
    let payload = 4321u64.to_le_bytes();

    let lost_samples = parse_lost_samples_record(&payload).expect("lost samples record");

    assert_eq!(lost_samples.lost, 4321);
}

#[test]
fn dispatches_lost_samples_record_by_perf_record_type() {
    let payload = 4321u64.to_le_bytes();
    let record = PerfRecord {
        offset: 104,
        header: PerfRecordHeader {
            record_type: 13,
            misc: 0,
            size: u16::try_from(8 + payload.len()).expect("record size"),
        },
        payload: &payload,
    };

    let parsed = parse_record(record).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::LostSamples(_)));
}

#[test]
fn parses_throttle_record_payload_from_perf_event_header_shape() {
    let mut payload = Vec::new();
    payload.extend(10_000u64.to_le_bytes());
    payload.extend(77u64.to_le_bytes());
    payload.extend(88u64.to_le_bytes());

    let throttle = parse_throttle_record(&payload).expect("throttle record");

    assert_eq!(throttle.time, 10_000);
    assert_eq!(throttle.id, 77);
    assert_eq!(throttle.stream_id, 88);
}

#[test]
fn dispatches_throttle_record_by_perf_record_type() {
    let payload = throttle_payload();
    let record = PerfRecord {
        offset: 104,
        header: PerfRecordHeader {
            record_type: 5,
            misc: 0,
            size: u16::try_from(8 + payload.len()).expect("record size"),
        },
        payload: &payload,
    };

    let parsed = parse_record(record).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::Throttle(_)));
}

#[test]
fn parses_unthrottle_record_payload_from_perf_event_header_shape() {
    let mut payload = Vec::new();
    payload.extend(10_000u64.to_le_bytes());
    payload.extend(77u64.to_le_bytes());
    payload.extend(88u64.to_le_bytes());

    let unthrottle = parse_unthrottle_record(&payload).expect("unthrottle record");

    assert_eq!(unthrottle.time, 10_000);
    assert_eq!(unthrottle.id, 77);
    assert_eq!(unthrottle.stream_id, 88);
}

#[test]
fn dispatches_unthrottle_record_by_perf_record_type() {
    let payload = throttle_payload();
    let record = PerfRecord {
        offset: 104,
        header: PerfRecordHeader {
            record_type: 6,
            misc: 0,
            size: u16::try_from(8 + payload.len()).expect("record size"),
        },
        payload: &payload,
    };

    let parsed = parse_record(record).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::Unthrottle(_)));
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

fn mmap_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(0x7f00u64.to_le_bytes());
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(0x40u64.to_le_bytes());
    payload.extend(b"/usr/bin/sftp-s3\0");
    payload
}

fn mmap2_inode_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(0x7f00u64.to_le_bytes());
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(0x40u64.to_le_bytes());
    payload.extend(8u32.to_le_bytes());
    payload.extend(1u32.to_le_bytes());
    payload.extend(99u64.to_le_bytes());
    payload.extend(7u64.to_le_bytes());
    payload.extend(5u32.to_le_bytes());
    payload.extend(2u32.to_le_bytes());
    payload.extend(b"/usr/lib/libssl.so\0");
    payload
}

fn mmap2_build_id_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(0x7f00u64.to_le_bytes());
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(0x40u64.to_le_bytes());
    payload.push(4);
    payload.push(0);
    payload.extend(0u16.to_le_bytes());
    payload.extend([0xaa, 0xbb, 0xcc, 0xdd]);
    payload.extend([0; 16]);
    payload.extend(5u32.to_le_bytes());
    payload.extend(2u32.to_le_bytes());
    payload.extend(b"/usr/lib/libssl.so\0");
    payload
}

fn lifecycle_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(123u32.to_le_bytes());
    payload.extend(12u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(45u32.to_le_bytes());
    payload.extend(99_000u64.to_le_bytes());
    payload
}

fn lost_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(77u64.to_le_bytes());
    payload.extend(1234u64.to_le_bytes());
    payload
}

fn throttle_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(10_000u64.to_le_bytes());
    payload.extend(77u64.to_le_bytes());
    payload.extend(88u64.to_le_bytes());
    payload
}

fn record_bytes(record_type: u32, payload: &[u8]) -> Vec<u8> {
    let size = 8 + payload.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.extend(record_type.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend(
        u16::try_from(size)
            .expect("record fits in u16")
            .to_le_bytes(),
    );
    bytes.extend(payload);
    bytes
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
