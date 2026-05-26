use proptest::prelude::*;
use pyroclast::perfdata::samples::{
    PERF_FORMAT_GROUP, PERF_FORMAT_ID, PERF_FORMAT_LOST, PERF_FORMAT_TOTAL_TIME_ENABLED,
    PERF_FORMAT_TOTAL_TIME_RUNNING, PERF_SAMPLE_ADDR, PERF_SAMPLE_AUX, PERF_SAMPLE_BRANCH_COUNTERS,
    PERF_SAMPLE_BRANCH_HW_INDEX, PERF_SAMPLE_BRANCH_STACK, PERF_SAMPLE_CALLCHAIN,
    PERF_SAMPLE_CGROUP, PERF_SAMPLE_CODE_PAGE_SIZE, PERF_SAMPLE_CPU, PERF_SAMPLE_DATA_PAGE_SIZE,
    PERF_SAMPLE_DATA_SRC, PERF_SAMPLE_ID, PERF_SAMPLE_IDENTIFIER, PERF_SAMPLE_IP,
    PERF_SAMPLE_PERIOD, PERF_SAMPLE_PHYS_ADDR, PERF_SAMPLE_RAW, PERF_SAMPLE_READ,
    PERF_SAMPLE_REGS_INTR, PERF_SAMPLE_REGS_USER, PERF_SAMPLE_STACK_USER, PERF_SAMPLE_STREAM_ID,
    PERF_SAMPLE_TID, PERF_SAMPLE_TIME, PERF_SAMPLE_TRANSACTION, PERF_SAMPLE_WEIGHT,
    PERF_SAMPLE_WEIGHT_STRUCT, SampleLayout, is_kernel_space_frame, is_perf_context_marker,
    parse_sample_record, parse_sample_record_callchain, supported_perf_sample_flags,
};

#[test]
fn supports_every_known_linux_perf_sample_flag() {
    let expected = (0..=24).map(|bit| 1u64 << bit).collect::<Vec<_>>();

    assert_eq!(supported_perf_sample_flags(), expected);
}

#[test]
fn rejects_unsupported_perf_sample_flags() {
    let error = parse_sample_record(&[], layout(1 << 30)).expect_err("unsupported sample flag");

    assert!(error.contains("unsupported perf sample flags"));
}

#[test]
fn callchain_parser_rejects_unsupported_perf_sample_flags() {
    let error =
        parse_sample_record_callchain(&[], layout(1 << 30)).expect_err("unsupported sample flag");

    assert!(error.contains("unsupported perf sample flags"));
}

fn layout(sample_type: u64) -> SampleLayout {
    SampleLayout {
        sample_type,
        read_format: 0,
        branch_sample_type: 0,
        sample_regs_user: 0,
        sample_regs_intr: 0,
    }
}

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
        layout(PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN),
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
        layout(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_TIME
                | PERF_SAMPLE_ADDR
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_ID
                | PERF_SAMPLE_CPU
                | PERF_SAMPLE_PERIOD,
        ),
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
        layout(
            PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
        ),
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
            ..layout(0)
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
            ..layout(0)
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
        layout(PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN),
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

    let error =
        parse_sample_record(&payload, layout(PERF_SAMPLE_RAW)).expect_err("truncated raw sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_trailing_sample_payload_bytes() {
    let mut payload = Vec::new();
    payload.extend(0x1000u64.to_le_bytes());
    payload.push(0xff);

    let error = parse_sample_record(&payload, layout(PERF_SAMPLE_IP))
        .expect_err("sample with trailing bytes");

    assert!(error.contains("trailing bytes"));
}

#[test]
fn rejects_truncated_branch_stack_sample_payload() {
    let mut payload = Vec::new();
    payload.extend(1u64.to_le_bytes());
    payload.extend(0x1000u64.to_le_bytes());

    let error = parse_sample_record(&payload, layout(PERF_SAMPLE_BRANCH_STACK))
        .expect_err("truncated branch stack sample");

    assert!(error.contains("truncated"));
}

#[test]
fn skips_branch_stack_hardware_index_before_following_sample_fields() {
    let mut payload = Vec::new();
    payload.extend(1u64.to_le_bytes());
    payload.extend(99u64.to_le_bytes());
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(0x2000u64.to_le_bytes());
    payload.extend(0u64.to_le_bytes());
    payload.extend(1u64.to_le_bytes());
    payload.extend(0xaaaa_u64.to_le_bytes());

    let sample = parse_sample_record(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_BRANCH_STACK | PERF_SAMPLE_REGS_USER,
            branch_sample_type: PERF_SAMPLE_BRANCH_HW_INDEX,
            sample_regs_user: 0b1,
            ..layout(0)
        },
    )
    .expect("sample");

    assert_eq!(sample.callchain, Vec::<u64>::new());
}

#[test]
fn skips_branch_stack_counters_before_following_sample_fields() {
    let mut payload = Vec::new();
    payload.extend(2u64.to_le_bytes());
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(0x2000u64.to_le_bytes());
    payload.extend(0u64.to_le_bytes());
    payload.extend(0x3000u64.to_le_bytes());
    payload.extend(0x4000u64.to_le_bytes());
    payload.extend(0u64.to_le_bytes());
    payload.extend(7u64.to_le_bytes());
    payload.extend(8u64.to_le_bytes());
    payload.extend(1u64.to_le_bytes());
    payload.extend(0xaaaa_u64.to_le_bytes());

    let sample = parse_sample_record(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_BRANCH_STACK | PERF_SAMPLE_REGS_USER,
            branch_sample_type: PERF_SAMPLE_BRANCH_COUNTERS,
            sample_regs_user: 0b1,
            ..layout(0)
        },
    )
    .expect("sample");

    assert_eq!(sample.callchain, Vec::<u64>::new());
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
            sample_regs_user: 0b11,
            ..layout(0)
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

    let error = parse_sample_record(&payload, layout(PERF_SAMPLE_STACK_USER))
        .expect_err("truncated stack user sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_truncated_weight_sample_payload() {
    let error = parse_sample_record(&[1, 2, 3, 4], layout(PERF_SAMPLE_WEIGHT))
        .expect_err("truncated weight sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_truncated_data_src_sample_payload() {
    let error = parse_sample_record(&[1, 2, 3, 4], layout(PERF_SAMPLE_DATA_SRC))
        .expect_err("truncated data source sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_truncated_transaction_sample_payload() {
    let error = parse_sample_record(&[1, 2, 3, 4], layout(PERF_SAMPLE_TRANSACTION))
        .expect_err("truncated transaction sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_truncated_intr_regs_sample_payload() {
    let mut payload = Vec::new();
    payload.extend(1u64.to_le_bytes());
    payload.extend(0xaaaa_u64.to_le_bytes());

    let error = parse_sample_record(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_REGS_INTR,
            sample_regs_intr: 0b11,
            ..layout(0)
        },
    )
    .expect_err("truncated regs intr sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_truncated_phys_addr_sample_payload() {
    let error = parse_sample_record(&[1, 2, 3, 4], layout(PERF_SAMPLE_PHYS_ADDR))
        .expect_err("truncated physical address sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_truncated_aux_sample_payload() {
    let mut payload = Vec::new();
    payload.extend(4u64.to_le_bytes());
    payload.extend([1, 2]);

    let error =
        parse_sample_record(&payload, layout(PERF_SAMPLE_AUX)).expect_err("truncated aux sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_truncated_cgroup_sample_payload() {
    let error = parse_sample_record(&[1, 2, 3, 4], layout(PERF_SAMPLE_CGROUP))
        .expect_err("truncated cgroup sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_truncated_data_page_size_sample_payload() {
    let error = parse_sample_record(&[1, 2, 3, 4], layout(PERF_SAMPLE_DATA_PAGE_SIZE))
        .expect_err("truncated data page size sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_truncated_code_page_size_sample_payload() {
    let error = parse_sample_record(&[1, 2, 3, 4], layout(PERF_SAMPLE_CODE_PAGE_SIZE))
        .expect_err("truncated code page size sample");

    assert!(error.contains("truncated"));
}

#[test]
fn rejects_truncated_weight_struct_sample_payload() {
    let error = parse_sample_record(&[1, 2, 3, 4], layout(PERF_SAMPLE_WEIGHT_STRUCT))
        .expect_err("truncated weight struct sample");

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
        layout(PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN),
    )
    .expect("sample")
    .expect("callchain");

    assert_eq!(sample.pid, Some(123));
    assert_eq!(sample.tid, Some(456));
    assert_eq!(sample.period, Some(9));
    assert_eq!(sample.frames.collect::<Vec<_>>(), vec![0x2000, 0x3000]);
}

#[test]
fn callchain_parser_preserves_user_regs_and_stack_for_dwarf_unwinding() {
    let mut payload = Vec::new();
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(9u64.to_le_bytes());
    payload.extend(1u64.to_le_bytes());
    payload.extend(0x2000u64.to_le_bytes());
    payload.extend(1u64.to_le_bytes());
    payload.extend(0xaaaa_u64.to_le_bytes());
    payload.extend(3u64.to_le_bytes());
    payload.extend([1, 2, 3]);
    payload.extend([0; 5]);
    payload.extend(3u64.to_le_bytes());

    let sample = parse_sample_record_callchain(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            sample_regs_user: 0b1,
            ..layout(0)
        },
    )
    .expect("sample")
    .expect("callchain");

    assert_eq!(sample.user_regs.as_ref().expect("regs").abi, 1);
    assert_eq!(
        sample.user_regs.as_ref().expect("regs").values,
        vec![0xaaaa]
    );
    assert_eq!(sample.user_stack.as_ref().expect("stack").bytes, &[1, 2, 3]);
    assert_eq!(sample.user_stack.as_ref().expect("stack").dynamic_size, 3);
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

proptest! {
    #[test]
    fn parses_generated_callchain_sample_payloads(
        ip in any::<u64>(),
        pid in any::<u32>(),
        tid in any::<u32>(),
        period in any::<u64>(),
        frames in proptest::collection::vec(any::<u64>(), 0..64),
    ) {
        let mut payload = Vec::new();
        payload.extend(ip.to_le_bytes());
        payload.extend(pid.to_le_bytes());
        payload.extend(tid.to_le_bytes());
        payload.extend(period.to_le_bytes());
        payload.extend((frames.len() as u64).to_le_bytes());
        for frame in &frames {
            payload.extend(frame.to_le_bytes());
        }

        let sample = parse_sample_record(
            &payload,
            layout(PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN),
        )
        .expect("sample");

        prop_assert_eq!(sample.ip, Some(ip));
        prop_assert_eq!(sample.pid, Some(pid));
        prop_assert_eq!(sample.tid, Some(tid));
        prop_assert_eq!(sample.period, Some(period));
        prop_assert_eq!(sample.callchain, frames);
    }
}
