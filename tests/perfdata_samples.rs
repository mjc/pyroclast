use pyroclast::perfdata::samples::{
    PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_TID, SampleLayout, parse_sample_record,
};

#[test]
fn parses_ip_tid_and_callchain_sample_payload() {
    let mut payload = Vec::new();
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(2u64.to_le_bytes());
    payload.extend(0x2000u64.to_le_bytes());
    payload.extend(0x3000u64.to_le_bytes());

    let sample = parse_sample_record(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
        },
    )
    .expect("sample");

    assert_eq!(sample.ip, Some(0x1000));
    assert_eq!(sample.pid, Some(123));
    assert_eq!(sample.tid, Some(456));
    assert_eq!(sample.callchain, vec![0x2000, 0x3000]);
}
