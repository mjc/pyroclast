use pyroclast::perfdata::records::{PerfRecordHeader, parse_record_header};

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
