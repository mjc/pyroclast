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
        sample_id_all: false,
    }
}

#[derive(Clone, Debug)]
struct CallchainUnwindCase {
    pid: u32,
    tid: u32,
    time: u64,
    period: u64,
    frames: Vec<u64>,
    regs_mask: u64,
    abi: u64,
    regs_values: Vec<u64>,
    user_stack: Vec<u8>,
    dynamic_size: u64,
}

fn callchain_unwind_case() -> impl Strategy<Value = CallchainUnwindCase> {
    (
        any::<u32>(),
        any::<u32>(),
        any::<u64>(),
        any::<u64>(),
        prop::collection::vec(any::<u64>(), 0..32),
        0_u64..=0xffff,
        any::<u64>(),
        prop::collection::vec(any::<u8>(), 0..31),
    )
        .prop_flat_map(
            |(pid, tid, time, period, frames, regs_mask, abi, user_stack)| {
                let reg_count = if abi == 0 {
                    0
                } else {
                    regs_mask.count_ones() as usize
                };
                (
                    Just(pid),
                    Just(tid),
                    Just(time),
                    Just(period),
                    Just(frames),
                    Just(regs_mask),
                    Just(abi),
                    prop::collection::vec(any::<u64>(), reg_count),
                    0..=user_stack.len() as u64,
                    Just(user_stack),
                )
            },
        )
        .prop_map(
            |(
                pid,
                tid,
                time,
                period,
                frames,
                regs_mask,
                abi,
                regs_values,
                dynamic_size,
                user_stack,
            )| CallchainUnwindCase {
                pid,
                tid,
                time,
                period,
                frames,
                regs_mask,
                abi,
                regs_values,
                user_stack,
                dynamic_size,
            },
        )
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
fn parses_borrowed_callchain_without_dropping_the_independent_event_ip() {
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

    // perf builtin-script.c:process_sample_event preprocesses sample->ip in
    // machine__resolve before thread__resolve_callchain uses chain->ips.
    assert_eq!(sample.sample_ip, Some(0x1000));
    assert_eq!(sample.pid, Some(123));
    assert_eq!(sample.tid, Some(456));
    assert_eq!(sample.period, Some(9));
    assert_eq!(sample.frames.collect::<Vec<_>>(), vec![0x2000, 0x3000]);
}

#[test]
fn callchain_parser_keeps_sample_ip_with_unpadded_unwind_payload_without_callchain() {
    let mut payload = Vec::new();
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(9u64.to_le_bytes());
    payload.extend(1u64.to_le_bytes());
    payload.extend(0xaaaa_u64.to_le_bytes());
    payload.extend(3u64.to_le_bytes());
    payload.extend([1, 2, 3]);
    payload.extend(3u64.to_le_bytes());

    let sample = parse_sample_record_callchain(
        &payload,
        SampleLayout {
            sample_type: PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            sample_regs_user: 0b1,
            ..layout(0)
        },
    )
    .expect("sample")
    .expect("perf script falls back to the sample ip when sample->callchain is null");

    assert_eq!(sample.pid, Some(123));
    assert_eq!(sample.tid, Some(456));
    assert_eq!(sample.period, Some(9));
    assert_eq!(sample.frames.collect::<Vec<_>>(), vec![0x1000]);
    assert!(sample.user_regs.is_none());
    assert!(sample.user_stack.is_none());
}

#[test]
fn callchain_parser_preserves_unpadded_user_regs_and_stack_for_dwarf_unwinding() {
    // Installed perf 7.2.9 evsel.c:3703-3720 reads dynamic size immediately
    // after the captured bytes; this is parser fidelity, not a typical dump size.
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
fn callchain_parser_accepts_empty_user_stack_without_dynamic_size() {
    let mut payload = Vec::new();
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(1u64.to_le_bytes());
    payload.extend(0x2000u64.to_le_bytes());
    payload.extend(0u64.to_le_bytes());

    let sample = parse_sample_record_callchain(
        &payload,
        layout(PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_STACK_USER),
    )
    .expect("sample")
    .expect("callchain");

    let stack = sample.user_stack.as_ref().expect("stack");
    assert!(stack.bytes.is_empty());
    assert_eq!(stack.dynamic_size, 0);
}

fn captured_stack_payload(
    stack: &[u8],
    dynamic_size: u64,
    callchain: bool,
) -> (Vec<u8>, SampleLayout) {
    let mut payload = 0x1000_u64.to_le_bytes().to_vec();
    let mut flags = PERF_SAMPLE_IP | PERF_SAMPLE_STACK_USER;
    if callchain {
        flags |= PERF_SAMPLE_CALLCHAIN;
        payload.extend(1_u64.to_le_bytes());
        payload.extend(0x2000_u64.to_le_bytes());
    }
    payload.extend((stack.len() as u64).to_le_bytes());
    payload.extend(stack);
    if !stack.is_empty() {
        payload.extend(dynamic_size.to_le_bytes());
    }
    (payload, layout(flags))
}

fn assert_unpadded_stack_parsers(size: usize) {
    let stack = vec![0xa5; size];
    let mut failures = Vec::new();
    for dynamic_size in [0, size.saturating_sub(1) as u64, size as u64] {
        for callchain in [false, true] {
            let (payload, sample_layout) = captured_stack_payload(&stack, dynamic_size, callchain);
            let owned = parse_sample_record(&payload, sample_layout);
            if !owned.as_ref().is_ok_and(|sample| {
                sample.ip == Some(0x1000)
                    && sample.callchain == if callchain { vec![0x2000] } else { vec![] }
            }) {
                failures.push(format!(
                    "owned size={size} dynamic={dynamic_size}: {owned:?}"
                ));
            }
            let borrowed = parse_sample_record_callchain(&payload, sample_layout);
            let correct = borrowed.as_ref().is_ok_and(|sample| {
                sample.as_ref().is_some_and(|sample| {
                    sample.frames.clone().collect::<Vec<_>>()
                        == if callchain {
                            vec![0x2000]
                        } else {
                            vec![0x1000]
                        }
                        && if callchain {
                            sample.user_stack.as_ref().is_some_and(|parsed| {
                                parsed.bytes == stack
                                    && parsed.dynamic_size == dynamic_size
                                    && (stack.is_empty()
                                        || parsed.bytes.as_ptr() == payload[32..].as_ptr())
                            })
                        } else {
                            sample.user_stack.is_none()
                        }
                })
            });
            if !correct {
                failures.push(format!("borrowed callchain={callchain} size={size} dynamic={dynamic_size}: {borrowed:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// Native parser source admits exact captured extents, including unaligned data.
// The kernel normally aligns requested dump sizes before serializing them.
macro_rules! unpadded_stack_case {
    ($name:ident, $size:expr) => {
        #[test]
        fn $name() {
            assert_unpadded_stack_parsers($size);
        }
    };
}

unpadded_stack_case!(user_stack_unpadded_extent_1, 1);
unpadded_stack_case!(user_stack_unpadded_extent_2, 2);
unpadded_stack_case!(user_stack_unpadded_extent_3, 3);
unpadded_stack_case!(user_stack_unpadded_extent_4, 4);
unpadded_stack_case!(user_stack_unpadded_extent_5, 5);
unpadded_stack_case!(user_stack_unpadded_extent_6, 6);
unpadded_stack_case!(user_stack_unpadded_extent_7, 7);
unpadded_stack_case!(user_stack_unpadded_extent_9, 9);
unpadded_stack_case!(user_stack_unpadded_extent_15, 15);
unpadded_stack_case!(user_stack_unpadded_extent_17, 17);
unpadded_stack_case!(user_stack_aligned_extent_0, 0);
unpadded_stack_case!(user_stack_aligned_extent_8, 8);
unpadded_stack_case!(user_stack_aligned_extent_16, 16);

#[test]
fn user_stack_rejects_dynamic_extent_larger_than_capture_in_all_public_parsers() {
    let mut accepted = Vec::new();
    for size in [8, 16] {
        for dynamic_size in [size as u64 + 1, u64::MAX] {
            for callchain in [false, true] {
                let (payload, sample_layout) =
                    captured_stack_payload(&vec![0xa5; size], dynamic_size, callchain);
                if parse_sample_record(&payload, sample_layout).is_ok() {
                    accepted.push(("owned", size, dynamic_size, callchain));
                }
                if parse_sample_record_callchain(&payload, sample_layout).is_ok() {
                    accepted.push(("borrowed", size, dynamic_size, callchain));
                }
            }
        }
    }
    assert!(
        accepted.is_empty(),
        "invalid extents accepted: {accepted:?}"
    );
}

#[test]
fn user_stack_owned_parser_reads_following_weight_without_a_padding_gap() {
    for size in [1, 3, 7, 9] {
        let (mut payload, mut sample_layout) = captured_stack_payload(&vec![0xa5; size], 0, true);
        sample_layout.sample_type |= PERF_SAMPLE_WEIGHT;
        // Seven following bytes are not enough for WEIGHT. An imagined gap
        // must not consume part of this field or require more than eight bytes.
        payload.extend([0xc3; 7]);
        assert!(parse_sample_record(&payload, sample_layout).is_err());
        payload.push(0xc3);
        let parsed = parse_sample_record(&payload, sample_layout).expect("complete weight");
        assert_eq!(parsed.callchain, [0x2000]);
    }
}

#[test]
fn user_stack_parsers_reject_every_truncated_static_or_dynamic_extent() {
    for size in [1, 3, 8, 9, 16] {
        for callchain in [false, true] {
            let (payload, sample_layout) = captured_stack_payload(&vec![0xa5; size], 0, callchain);
            for end in 0..payload.len() {
                assert!(
                    parse_sample_record(&payload[..end], sample_layout).is_err(),
                    "owned size={size} callchain={callchain} end={end}"
                );
                assert!(
                    parse_sample_record_callchain(&payload[..end], sample_layout).is_err(),
                    "borrowed size={size} callchain={callchain} end={end}"
                );
            }
        }
    }
}

#[test]
fn detects_perf_context_markers_at_the_uapi_minus_4095_boundary() {
    // linux/include/uapi/linux/perf_event.h: PERF_CONTEXT_MAX = (__u64)-4095.
    assert!(!is_perf_context_marker(0xffff_ffff_ffff_f000));
    assert!(is_perf_context_marker(0xffff_ffff_ffff_f001));
    assert!(is_perf_context_marker(0xffff_ffff_ffff_fe00));
    assert!(!is_perf_context_marker(0x7fff_ffff_f000));
}

#[test]
fn detects_kernel_space_frames() {
    assert!(is_kernel_space_frame(0xffff_ffff_ffff_f000));
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

    #[test]
    fn property_callchain_parser_preserves_valid_unpadded_unwind_metadata(
        case in callchain_unwind_case(),
    ) {
        let mut payload = Vec::new();
        payload.extend(case.pid.to_le_bytes());
        payload.extend(case.tid.to_le_bytes());
        payload.extend(case.time.to_le_bytes());
        payload.extend(case.period.to_le_bytes());
        payload.extend((case.frames.len() as u64).to_le_bytes());
        for frame in &case.frames {
            payload.extend(frame.to_le_bytes());
        }
        payload.extend(case.abi.to_le_bytes());
        for value in &case.regs_values {
            payload.extend(value.to_le_bytes());
        }
        payload.extend((case.user_stack.len() as u64).to_le_bytes());
        payload.extend(&case.user_stack);
        if !case.user_stack.is_empty() {
            payload.extend(case.dynamic_size.to_le_bytes());
        }

        let sample_layout = SampleLayout {
                sample_type: PERF_SAMPLE_TID
                    | PERF_SAMPLE_TIME
                    | PERF_SAMPLE_PERIOD
                    | PERF_SAMPLE_CALLCHAIN
                    | PERF_SAMPLE_REGS_USER
                    | PERF_SAMPLE_STACK_USER,
                sample_regs_user: case.regs_mask,
                ..layout(0)
            };
        let owned = parse_sample_record(&payload, sample_layout).expect("owned sample");
        prop_assert_eq!(&owned.callchain, &case.frames);
        prop_assert_eq!(owned.pid, Some(case.pid));
        prop_assert_eq!(owned.tid, Some(case.tid));
        prop_assert_eq!(owned.period, Some(case.period));
        let sample = parse_sample_record_callchain(&payload, sample_layout)
        .expect("sample")
        .expect("callchain");

        prop_assert_eq!(sample.pid, Some(case.pid));
        prop_assert_eq!(sample.tid, Some(case.tid));
        prop_assert_eq!(sample.time, Some(case.time));
        prop_assert_eq!(sample.period, Some(case.period));
        prop_assert_eq!(sample.frames.len(), case.frames.len());
        prop_assert_eq!(sample.frames.collect::<Vec<_>>(), case.frames);

        let user_regs = sample.user_regs.expect("user regs");
        prop_assert_eq!(user_regs.abi, case.abi);
        prop_assert_eq!(user_regs.values, case.regs_values);

        let user_stack = sample.user_stack.expect("user stack");
        prop_assert_eq!(user_stack.bytes, case.user_stack.as_slice());
        prop_assert_eq!(
            user_stack.dynamic_size,
            if case.user_stack.is_empty() {
                0
            } else {
                case.dynamic_size
            }
        );
    }

    #[test]
    fn property_user_stack_parsers_reject_generated_oversized_dynamic_extents(
        stack in prop::collection::vec(any::<u8>(), 1..32),
        dynamic_size in any::<u64>(),
        callchain in any::<bool>(),
    ) {
        prop_assume!(dynamic_size > stack.len() as u64);
        let (payload, sample_layout) = captured_stack_payload(&stack, dynamic_size, callchain);
        let owned = parse_sample_record(&payload, sample_layout);
        let borrowed = parse_sample_record_callchain(&payload, sample_layout);
        prop_assert!(owned.is_err() && borrowed.is_err(),
            "oversized dynamic={} captured={} owned={:?} borrowed={:?}",
            dynamic_size, stack.len(), owned, borrowed);
    }

    #[test]
    fn property_classifies_context_markers_using_the_perf_uapi_boundary(
        frame in prop_oneof![any::<u64>(), Just(0xffff_ffff_ffff_f000), Just(0xffff_ffff_ffff_f001)]
    ) {
        // linux/include/uapi/linux/perf_event.h: PERF_CONTEXT_MAX = (__u64)-4095.
        prop_assert_eq!(is_perf_context_marker(frame), frame >= 0xffff_ffff_ffff_f001);
        prop_assert_eq!(
            is_kernel_space_frame(frame),
            (0xffff_8000_0000_0000..0xffff_ffff_ffff_f001).contains(&frame)
        );
    }
}
