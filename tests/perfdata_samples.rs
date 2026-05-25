use pyroclast::perfdata::samples::{
    PERF_FORMAT_GROUP, PERF_FORMAT_ID, PERF_FORMAT_LOST, PERF_FORMAT_TOTAL_TIME_ENABLED,
    PERF_FORMAT_TOTAL_TIME_RUNNING, PERF_SAMPLE_ADDR, PERF_SAMPLE_BRANCH_STACK,
    PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_CPU, PERF_SAMPLE_ID, PERF_SAMPLE_IDENTIFIER, PERF_SAMPLE_IP,
    PERF_SAMPLE_PERIOD, PERF_SAMPLE_RAW, PERF_SAMPLE_READ, PERF_SAMPLE_REGS_USER,
    PERF_SAMPLE_STACK_USER, PERF_SAMPLE_STREAM_ID, PERF_SAMPLE_TID, PERF_SAMPLE_TIME, SampleLayout,
    is_kernel_space_frame, is_perf_context_marker, parse_sample_record,
    parse_sample_record_callchain,
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
            read_format: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
        },
    )
    .expect("sample");

    assert_eq!(sample.ip, Some(0x1000));
    assert_eq!(sample.pid, Some(123));
    assert_eq!(sample.tid, Some(456));
    assert_eq!(sample.period, None);
    assert_eq!(sample.callchain, vec![0x2000, 0x3000]);
}

#[test]
fn consumes_perf_record_default_sample_fields_before_callchain() {
    let mut payload = Vec::new();
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(99u64.to_le_bytes());
    payload.extend(0xfeedu64.to_le_bytes());
    payload.extend(77u64.to_le_bytes());
    payload.extend(3u32.to_le_bytes());
    payload.extend(0u32.to_le_bytes());
    payload.extend(1u64.to_le_bytes());
    payload.extend(2u64.to_le_bytes());
    payload.extend(0x2000u64.to_le_bytes());
    payload.extend(0x3000u64.to_le_bytes());

    let sample = parse_sample_record(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_TIME
                | PERF_SAMPLE_ADDR
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_ID
                | PERF_SAMPLE_CPU
                | PERF_SAMPLE_PERIOD,
            read_format: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
        },
    )
    .expect("sample");

    assert_eq!(sample.ip, Some(0x1000));
    assert_eq!(sample.pid, Some(123));
    assert_eq!(sample.tid, Some(456));
    assert_eq!(sample.period, Some(1));
    assert_eq!(sample.callchain, vec![0x2000, 0x3000]);
}

#[test]
fn skips_stream_id_before_cpu_period_and_callchain() {
    let mut payload = Vec::new();
    payload.extend(99u64.to_le_bytes());
    payload.extend(3u32.to_le_bytes());
    payload.extend(0u32.to_le_bytes());
    payload.extend(7u64.to_le_bytes());
    payload.extend(2u64.to_le_bytes());
    payload.extend(0x2000u64.to_le_bytes());
    payload.extend(0x3000u64.to_le_bytes());

    let sample = parse_sample_record(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_STREAM_ID
                | PERF_SAMPLE_CPU
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN,
            read_format: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
        },
    )
    .expect("sample");

    assert_eq!(sample.period, Some(7));
    assert_eq!(sample.callchain, vec![0x2000, 0x3000]);
}

#[test]
fn skips_single_read_format_before_callchain() {
    let mut payload = Vec::new();
    payload.extend(11u64.to_le_bytes());
    payload.extend(22u64.to_le_bytes());
    payload.extend(33u64.to_le_bytes());
    payload.extend(44u64.to_le_bytes());
    payload.extend(55u64.to_le_bytes());
    payload.extend(2u64.to_le_bytes());
    payload.extend(0x2000u64.to_le_bytes());
    payload.extend(0x3000u64.to_le_bytes());

    let sample = parse_sample_record(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_READ | PERF_SAMPLE_CALLCHAIN,
            read_format: PERF_FORMAT_TOTAL_TIME_ENABLED
                | PERF_FORMAT_TOTAL_TIME_RUNNING
                | PERF_FORMAT_ID
                | PERF_FORMAT_LOST,
            sample_regs_user: 0,
            sample_regs_intr: 0,
        },
    )
    .expect("sample");

    assert_eq!(sample.callchain, vec![0x2000, 0x3000]);
}

#[test]
fn skips_group_read_format_before_callchain() {
    let mut payload = Vec::new();
    payload.extend(2u64.to_le_bytes());
    payload.extend(77u64.to_le_bytes());
    payload.extend(88u64.to_le_bytes());
    payload.extend(11u64.to_le_bytes());
    payload.extend(12u64.to_le_bytes());
    payload.extend(13u64.to_le_bytes());
    payload.extend(21u64.to_le_bytes());
    payload.extend(22u64.to_le_bytes());
    payload.extend(23u64.to_le_bytes());
    payload.extend(2u64.to_le_bytes());
    payload.extend(0x2000u64.to_le_bytes());
    payload.extend(0x3000u64.to_le_bytes());

    let sample = parse_sample_record_callchain(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_READ | PERF_SAMPLE_CALLCHAIN,
            read_format: PERF_FORMAT_GROUP
                | PERF_FORMAT_TOTAL_TIME_ENABLED
                | PERF_FORMAT_TOTAL_TIME_RUNNING
                | PERF_FORMAT_ID
                | PERF_FORMAT_LOST,
            sample_regs_user: 0,
            sample_regs_intr: 0,
        },
    )
    .expect("sample")
    .expect("callchain");

    assert_eq!(sample.frames.collect::<Vec<_>>(), vec![0x2000, 0x3000]);
}

#[test]
fn skips_identifier_before_ip_tid_and_callchain() {
    let mut payload = Vec::new();
    payload.extend(77u64.to_le_bytes());
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(2u64.to_le_bytes());
    payload.extend(0x2000u64.to_le_bytes());
    payload.extend(0x3000u64.to_le_bytes());

    let sample = parse_sample_record(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_IDENTIFIER
                | PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN,
            read_format: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
        },
    )
    .expect("sample");

    assert_eq!(sample.ip, Some(0x1000));
    assert_eq!(sample.pid, Some(123));
    assert_eq!(sample.tid, Some(456));
    assert_eq!(sample.callchain, vec![0x2000, 0x3000]);
}

#[test]
fn rejects_truncated_raw_sample_payload() {
    let mut payload = Vec::new();
    payload.extend(4u32.to_le_bytes());
    payload.extend([1, 2]);

    let error = parse_sample_record(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_RAW,
            read_format: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
        },
    )
    .expect_err("truncated raw sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_truncated_branch_stack_sample_payload() {
    let mut payload = Vec::new();
    payload.extend(1u64.to_le_bytes());
    payload.extend(0x1000u64.to_le_bytes());

    let error = parse_sample_record(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_BRANCH_STACK,
            read_format: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
        },
    )
    .expect_err("truncated branch stack sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_truncated_user_regs_sample_payload() {
    let mut payload = Vec::new();
    payload.extend(1u64.to_le_bytes());
    payload.extend(0xaaaa_u64.to_le_bytes());

    let error = parse_sample_record(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_REGS_USER,
            read_format: 0,
            sample_regs_user: 0b11,
            sample_regs_intr: 0,
        },
    )
    .expect_err("truncated regs user sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_truncated_user_stack_sample_payload() {
    let mut payload = Vec::new();
    payload.extend(4u64.to_le_bytes());
    payload.extend([1, 2, 3, 4]);

    let error = parse_sample_record(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_STACK_USER,
            read_format: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
        },
    )
    .expect_err("truncated stack user sample");

    assert!(error.contains("truncated"));
}

#[test]
fn parses_sample_callchain_without_building_sample_record() {
    let mut payload = Vec::new();
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(9u64.to_le_bytes());
    payload.extend(2u64.to_le_bytes());
    payload.extend(0x2000u64.to_le_bytes());
    payload.extend(0x3000u64.to_le_bytes());

    let sample = parse_sample_record_callchain(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN,
            read_format: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
        },
    )
    .expect("sample")
    .expect("callchain");

    assert_eq!(sample.pid, Some(123));
    assert_eq!(sample.period, Some(9));
    assert_eq!(sample.frames.collect::<Vec<_>>(), vec![0x2000, 0x3000]);
}

#[test]
fn detects_perf_context_marker_addresses() {
    assert!(is_perf_context_marker(0xffff_ffff_ffff_fe00));
    assert!(!is_perf_context_marker(0x7fff_ffff_f000));
}

#[test]
fn detects_kernel_space_frames() {
    assert!(is_kernel_space_frame(0xffff_ffff_8800_1280));
    assert!(!is_kernel_space_frame(0x0000_7fff_ffff_f000));
    assert!(!is_kernel_space_frame(0xffff_ffff_ffff_fe00));
}
