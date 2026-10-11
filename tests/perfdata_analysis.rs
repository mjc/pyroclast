use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use pyroclast::perfdata::analysis::{
    PerfdataEdgeCount, PerfdataIpCount, PerfdataSampleMode, PerfdataThread, analyze_perfdata,
    analyze_perfdata_file,
};
use pyroclast::perfdata::fold::summarize_perfdata;
use pyroclast::perfdata::fold::summarize_perfdata_file;
use pyroclast::perfdata::records::{
    PERF_RECORD_COMM, PERF_RECORD_FORK, PERF_RECORD_LOST, PERF_RECORD_MISC_COMM_EXEC,
    PERF_RECORD_MISC_CPUMODE_KERNEL, PERF_RECORD_MISC_CPUMODE_USER, PERF_RECORD_MMAP,
    PERF_RECORD_SAMPLE,
};
use pyroclast::perfdata::samples::{
    PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_PERIOD, PERF_SAMPLE_REGS_USER,
    PERF_SAMPLE_STACK_USER, PERF_SAMPLE_TID, PERF_SAMPLE_TIME,
};
use pyroclast::summary::{
    PerfProfileSummary, summarize_perfdata_profile, summarize_perfdata_profile_file,
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
fn analyzes_sample_modes_and_unpadded_user_stack_payloads() {
    let perfdata = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            1 << 8,
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_user_stack(
                sample_payload(0x1000, 1, 11, 7, [0x1000]),
                [0xaaaa],
                [1, 2, 3],
            ),
        )],
    );

    let report = analyze_perfdata(&perfdata, 10).expect("analysis");

    assert_eq!(report.sample_modes[0].mode, "kernel");
    assert_eq!(report.sample_modes[0].samples, 1);
    assert_eq!(report.sample_modes[0].weighted_samples, 7);
    assert_eq!(report.user_stack_samples, 1);
    assert_eq!(report.user_stack_bytes, 3);
    assert_eq!(report.user_stack_dynamic_bytes, 3);
    assert_eq!(report.user_register_samples, 1);
    assert_eq!(report.user_register_ip_samples, 1);
}

#[test]
fn analysis_retains_the_real_ip_immediately_below_perf_context_max() {
    // linux/include/uapi/linux/perf_event.h:1298 sets PERF_CONTEXT_MAX to
    // (u64)-4095, so -4096 is an address, not a context marker.
    let boundary_ip = 0xffff_ffff_ffff_f000;
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(boundary_ip, 1, 11, 7, [boundary_ip, 0x2000]),
        )],
    );
    let report = analyze_perfdata(&bytes, 10).expect("analysis");
    assert_eq!(report.top_leaf_ips[0].ip, "0xfffffffffffff000");
    assert_eq!(report.top_edges[0].callee, "0xfffffffffffff000");
    assert_eq!(report.top_edges[0].caller, "0x0000000000002000");
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

#[test]
fn summary_orders_generic_child_exec_after_older_fork_like_perf_report() {
    // Linux v7.2.9 tools/perf/builtin-report.c:1514,1622 enables ordering;
    // tools/perf/util/session.c:225-228 disables it without sample_id_all, and
    // session.c:2934-2949 queues timestamped records or dispatches them directly.
    let bytes = child_exec_order_fixture(
        PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_TIME
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        true,
        Some([30, 10, 20]),
    );

    let summary = summarize_perfdata(&bytes).expect("summary");
    assert_eq!(summary.total_records, 9);
    assert_eq!(summary.record_count(PERF_RECORD_COMM), 2);
    assert_eq!(summary.record_count(PERF_RECORD_FORK), 1);
    assert_eq!(summary.record_count(PERF_RECORD_LOST), 1);
    assert_eq!(summary.record_count(68), 2);
    assert_eq!(summary.record_count(PERF_RECORD_SAMPLE), 3);
    assert_eq!(summary.lost_records, 4);
    assert_eq!(summary.sample_stacks.len(), 3);
    assert_eq!(
        summary
            .sample_stacks
            .iter()
            .map(|sample| sample.period.unwrap())
            .sum::<u64>(),
        12
    );
    assert!(
        summary
            .sample_stacks
            .iter()
            .all(|sample| sample.tid == Some(201))
    );
    assert!(
        summary
            .sample_stacks
            .iter()
            .all(|sample| sample.callchain == [0x1000, 0x2000])
    );

    let report = analyze_perfdata(&bytes, 10).expect("analysis");
    assert_eq!(report.total_records, 9);
    assert_eq!(report.total_samples, 3);
    assert_eq!(report.weighted_samples, 12);
    assert_eq!(report.lost_records, 4);
    assert_eq!(report.profile.unassigned_samples, 0);
    assert_eq!(report.threads[0].tid, 201);
    assert_eq!(report.threads[0].samples, 3);
    assert_eq!(report.threads[0].weighted_samples, 12);
    assert_eq!(report.top_leaf_ips[0].ip, "0x0000000000001000");
    assert_eq!(report.top_leaf_ips[0].weighted_samples, 12);

    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("perf.data");
    std::fs::write(&path, &bytes).expect("write fixture");
    let file_summary = summarize_perfdata_file(&path).expect("file summary");
    assert_eq!(file_summary.total_records, 9);
    assert_eq!(file_summary.lost_records, 4);
    let file_report = analyze_perfdata_file(&path, 10).expect("file analysis");
    assert_eq!(file_report.weighted_samples, 12);
    assert_eq!(file_report.lost_records, 4);
    assert_eq!(summary.comms_by_pid[&200], "child-exec");
    assert_eq!(summary.comms_by_tid[&201], "child-exec");
    assert_eq!(report.threads[0].comm, "child-exec");
    assert_eq!(file_summary.comms_by_tid[&201], "child-exec");
    assert_eq!(file_report.threads[0].comm, "child-exec");
}

#[test]
fn streamed_profile_orders_child_exec_after_older_fork_like_perf_report() {
    // Linux v7.2.9 tools/perf/builtin-report.c:1514,1622 enables ordering;
    // tools/perf/util/session.c:2937-2949 queues records by the timestamps
    // parsed by evsel__parse_sample_timestamp (evsel.c:3808-3849).
    let bytes = child_exec_order_fixture(
        PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_TIME
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        true,
        Some([30, 10, 20]),
    );
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    std::fs::write(file.path(), &bytes).expect("write fixture");
    let reference = analyze_perfdata(&bytes, 10).expect("analysis").profile;
    let profile = summarize_perfdata_profile_file(file.path(), 10, 10).expect("streamed profile");

    assert_eq!(profile.total_samples, 3);
    assert_eq!(profile.total_samples, reference.total_samples);
    assert_eq!(profile.weighted_samples, 12);
    assert_eq!(profile.weighted_samples, reference.weighted_samples);
    assert_eq!(profile.lost_records, 4);
    assert_eq!(profile.lost_records, reference.lost_records);
    assert_eq!(profile.unassigned_samples, 0);
    assert_eq!(profile.timeline.bucket_width_ns, 10);
    assert_eq!(profile.timeline.first_sample_ns, Some(32));
    assert_eq!(profile.timeline.last_sample_ns, Some(37));
    assert_eq!(profile.timeline.duration_ns, Some(5));
    assert_eq!(profile.timeline.untimed_samples, 0);
    assert_eq!(profile.timeline.buckets.len(), 1);
    assert_eq!(profile.timeline.buckets[0].start_offset_ns, 0);
    assert_eq!(profile.timeline.buckets[0].samples, 3);
    assert_eq!(profile.timeline.buckets[0].weighted_samples, 12);
    assert_eq!(profile.threads.len(), 1);
    assert_eq!(profile.threads[0].pid, Some(200));
    assert_eq!(profile.threads[0].tid, 201);
    assert_eq!(profile.threads[0].samples, 3);
    assert_eq!(profile.threads[0].weighted_samples, 12);
    assert_eq!(profile.threads[0].first_sample_ns, Some(32));
    assert_eq!(profile.threads[0].last_sample_ns, Some(37));
    assert!(profile.threads[0].cpus.is_empty());
    assert_eq!(profile.threads[0].comm, "child-exec");
    assert_eq!(profile.threads, reference.threads);
}

#[test]
fn streamed_profile_keeps_perf_ordering_fallbacks_ties_and_max_timestamp_delivery() {
    // Linux v7.2.9 tools/perf/util/evsel.c:3814-3826 requires TIME and SID;
    // ordered-events.c:40-60 keeps ties stable and :199-200 rejects ~0ULL.
    let untimed = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN;
    let timed = untimed | PERF_SAMPLE_TIME;
    for (sample_type, sample_id_all, times) in [
        (untimed, true, [30, 10, 20]),
        (timed, false, [30, 10, 20]),
        (timed, true, [20, 10, 20]),
        (timed, true, [u64::MAX, 10, 20]),
    ] {
        let bytes = child_exec_order_fixture(sample_type, sample_id_all, Some(times));
        for width in [3, 10] {
            let profile = streamed_profile_fixture(&bytes, width);
            assert_eq!(profile.total_samples, 3);
            assert_eq!(profile.weighted_samples, 12);
            assert_eq!(profile.lost_records, 4);
            assert_eq!(profile.unassigned_samples, 0);
            assert_eq!(profile.threads.len(), 1);
            assert_eq!(profile.threads[0].pid, Some(200));
            assert_eq!(profile.threads[0].tid, 201);
            if sample_type & PERF_SAMPLE_TIME == 0 {
                assert_eq!(profile.timeline.untimed_samples, 3);
                assert_eq!(profile.timeline.first_sample_ns, None);
                assert_eq!(profile.timeline.last_sample_ns, None);
                assert_eq!(profile.timeline.duration_ns, None);
                assert!(profile.timeline.buckets.is_empty());
            } else {
                assert_eq!(profile.timeline.untimed_samples, 0);
                assert_eq!(profile.timeline.first_sample_ns, Some(32));
                assert_eq!(profile.timeline.last_sample_ns, Some(37));
                assert_eq!(profile.timeline.duration_ns, Some(5));
            }
            assert_eq!(profile.threads[0].comm, "parent");
            assert_eq!(
                profile,
                summarize_perfdata_profile(&bytes, width, 10).expect("retained profile")
            );
        }
    }
}

#[test]
fn streamed_profile_without_sample_time_does_not_queue_fork_body_time() {
    // Linux v7.2.9 tools/perf/util/evsel.c:3808-3816,
    // evsel__parse_sample_timestamp requires PERF_SAMPLE_TIME independently
    // of FORK's body time. Queueing only FORK would overwrite the later EXEC.
    let sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN;
    let mut attr = file_attr_bytes(sample_type, 0, 0);
    put_u64(&mut attr, 40, 1 << 18);
    let bytes = perfdata_with_records_and_attrs(
        [attr],
        [
            comm_record(100, 101, "parent", false, true, sample_type, 10),
            fork_record(100, 101, 200, 201, true, sample_type, 20),
            comm_record(200, 201, "child-exec", true, true, sample_type, 30),
            record_bytes(
                PERF_RECORD_SAMPLE,
                &timed_sample_payload(sample_type, 0x1000, 200, 201, 40, 7, &[0x1000]),
            ),
        ],
    );
    let profile = streamed_profile_fixture(&bytes, 10);
    assert_eq!(profile.total_samples, 1);
    assert_eq!(profile.weighted_samples, 7);
    assert_eq!(profile.lost_records, 0);
    assert_eq!(profile.unassigned_samples, 0);
    assert_eq!(profile.timeline.untimed_samples, 1);
    assert_eq!(profile.timeline.first_sample_ns, None);
    assert_eq!(profile.timeline.last_sample_ns, None);
    assert_eq!(profile.timeline.duration_ns, None);
    assert!(profile.timeline.buckets.is_empty());
    assert_eq!(profile.threads.len(), 1);
    assert_eq!(profile.threads[0].pid, Some(200));
    assert_eq!(profile.threads[0].tid, 201);
    assert_eq!(profile.threads[0].samples, 1);
    assert_eq!(profile.threads[0].weighted_samples, 7);
    assert_eq!(profile.threads[0].first_sample_ns, None);
    assert_eq!(profile.threads[0].last_sample_ns, None);
    assert_eq!(profile.threads[0].comm, "child-exec");
    assert_eq!(
        profile,
        summarize_perfdata_profile(&bytes, 10, 10).expect("retained profile")
    );
}

#[test]
fn streamed_profile_delivers_zero_timestamp_comm_before_max_timestamp_comm() {
    // Linux v7.2.9 tools/perf/util/ordered-events.c:199-200 returns -ETIME for
    // both sentinels; session.c:2944-2949 delivers them immediately. Queueing
    // zero would overwrite the later immediate MAX COMM at the final flush.
    let sample_type = PERF_SAMPLE_IP
        | PERF_SAMPLE_TID
        | PERF_SAMPLE_TIME
        | PERF_SAMPLE_PERIOD
        | PERF_SAMPLE_CALLCHAIN;
    let mut attr = file_attr_bytes(sample_type, 0, 0);
    put_u64(&mut attr, 40, 1 << 18);
    let bytes = perfdata_with_records_and_attrs(
        [attr],
        [
            comm_record(200, 201, "zero-time", false, true, sample_type, 0),
            comm_record(200, 201, "max-time", false, true, sample_type, u64::MAX),
            record_bytes(
                PERF_RECORD_SAMPLE,
                &timed_sample_payload(sample_type, 0x1000, 200, 201, 37, 7, &[0x1000]),
            ),
        ],
    );
    let profile = streamed_profile_fixture(&bytes, 3);
    assert_eq!(profile.total_samples, 1);
    assert_eq!(profile.weighted_samples, 7);
    assert_eq!(profile.lost_records, 0);
    assert_eq!(profile.unassigned_samples, 0);
    assert_eq!(profile.timeline.first_sample_ns, Some(37));
    assert_eq!(profile.timeline.last_sample_ns, Some(37));
    assert_eq!(profile.threads[0].pid, Some(200));
    assert_eq!(profile.threads[0].tid, 201);
    assert_eq!(profile.threads[0].comm, "max-time");
    assert_eq!(
        profile,
        summarize_perfdata_profile(&bytes, 3, 10).expect("retained profile")
    );
}

#[test]
fn streamed_profile_keeps_exact_sparse_timeline_origin_for_unassigned_samples() {
    let sample_type =
        PERF_SAMPLE_IP | PERF_SAMPLE_TIME | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN;
    let mut attr = file_attr_bytes(sample_type, 0, 0);
    put_u64(&mut attr, 40, 1 << 18);
    let mut records = Vec::new();
    for (time, period) in [(37_u64, 7_u64), (32, 2), (33, 3)] {
        // PERF_SAMPLE_TID is absent, so the payload has no PID/TID field.
        let payload = [0x1000_u64, time, period, 1, 0x1000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        records.push(record_bytes(PERF_RECORD_SAMPLE, &payload));
    }
    records.push(lost_record(true, sample_type));
    let bytes = perfdata_with_records_and_attrs([attr], records);
    let profile = streamed_profile_fixture(&bytes, 3);
    assert_eq!(profile.total_samples, 3);
    assert_eq!(profile.weighted_samples, 12);
    assert_eq!(profile.lost_records, 4);
    assert_eq!(profile.unassigned_samples, 3);
    assert!(profile.threads.is_empty());
    assert_eq!(profile.timeline.bucket_width_ns, 3);
    assert_eq!(profile.timeline.first_sample_ns, Some(32));
    assert_eq!(profile.timeline.last_sample_ns, Some(37));
    assert_eq!(profile.timeline.duration_ns, Some(5));
    assert_eq!(profile.timeline.untimed_samples, 0);
    assert_eq!(profile.timeline.buckets.len(), 2);
    assert_eq!(profile.timeline.buckets[0].start_offset_ns, 0);
    assert_eq!(profile.timeline.buckets[0].samples, 2);
    assert_eq!(profile.timeline.buckets[0].weighted_samples, 5);
    assert_eq!(profile.timeline.buckets[1].start_offset_ns, 3);
    assert_eq!(profile.timeline.buckets[1].samples, 1);
    assert_eq!(profile.timeline.buckets[1].weighted_samples, 7);
    assert_eq!(
        profile,
        summarize_perfdata_profile(&bytes, 3, 10).expect("retained profile")
    );
}

#[test]
fn streamed_profile_metadata_errors_keep_the_original_record_offset() {
    let sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
    let mut attr = file_attr_bytes(sample_type, 0, 0);
    put_u64(&mut attr, 40, 1 << 18);
    let prefix = comm_record(100, 101, "parent", false, true, sample_type, 30);
    let offset = 104 + 144 + prefix.len();
    let mut payload = Vec::new();
    append_sample_id(&mut payload, true, sample_type, 200, 201, 10);
    let bytes =
        perfdata_with_records_and_attrs([attr], [prefix, record_bytes(PERF_RECORD_FORK, &payload)]);
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    std::fs::write(file.path(), bytes).expect("write fixture");
    let error = summarize_perfdata_profile_file(file.path(), 10, 10)
        .expect_err("FORK body is missing despite a complete SID trailer");
    assert!(error.contains(&format!("record type 7 at offset {offset}")));
    assert!(error.ends_with("PERF_RECORD_FORK payload is shorter than 24 bytes"));
}

#[test]
fn streamed_profile_truncated_timestamp_errors_keep_the_original_record_offset() {
    let sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
    let mut attr = file_attr_bytes(sample_type, 0, 0);
    put_u64(&mut attr, 40, 1 << 18);
    let prefix = comm_record(100, 101, "parent", false, true, sample_type, 30);
    let offset = 104 + 144 + prefix.len();
    let payload = [200_u32, 201]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let bytes = perfdata_with_records_and_attrs(
        [attr],
        [prefix, record_bytes(PERF_RECORD_SAMPLE, &payload)],
    );
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    std::fs::write(file.path(), bytes).expect("write fixture");
    let error = summarize_perfdata_profile_file(file.path(), 10, 10)
        .expect_err("sample timestamp is truncated");
    assert!(
        error.contains(&format!("record type 9 at offset {offset}")),
        "missing original sample location: {error}"
    );
}

fn streamed_profile_fixture(bytes: &[u8], width: u64) -> PerfProfileSummary {
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    std::fs::write(file.path(), bytes).expect("write fixture");
    summarize_perfdata_profile_file(file.path(), width, 10).expect("streamed profile")
}

#[test]
fn summary_keeps_physical_order_without_timestamps_or_sample_id_all() {
    let no_time = child_exec_order_fixture(
        PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
        true,
        Some([30, 10, 20]),
    );
    let report = analyze_perfdata(&no_time, 10).expect("untimed analysis");
    assert_eq!(report.threads[0].comm, "parent");
    assert_eq!(report.total_records, 9);
    assert_eq!(report.total_samples, 3);
    assert_eq!(report.weighted_samples, 12);

    let without_sample_id_all = child_exec_order_fixture(
        PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_TIME
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        false,
        Some([30, 10, 20]),
    );
    let report = analyze_perfdata(&without_sample_id_all, 10).expect("unordered analysis");
    assert_eq!(report.threads[0].comm, "parent");
    assert_eq!(report.total_records, 9);
    assert_eq!(report.total_samples, 3);
    assert_eq!(report.weighted_samples, 12);
}

#[test]
fn summary_keeps_source_order_for_tied_timestamps() {
    let bytes = child_exec_order_fixture(
        PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_TIME
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        true,
        Some([20, 10, 20]),
    );

    let summary = summarize_perfdata(&bytes).expect("summary");
    assert_eq!(summary.comms_by_tid[&201], "parent");
    assert_eq!(summary.sample_stacks.len(), 3);
    assert_eq!(
        summary
            .sample_stacks
            .iter()
            .map(|sample| sample.period.unwrap())
            .sum::<u64>(),
        12
    );
}

#[test]
fn summary_delivers_max_timestamp_events_immediately() {
    let bytes = child_exec_order_fixture(
        PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_TIME
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        true,
        Some([u64::MAX, 10, 20]),
    );

    let summary = summarize_perfdata(&bytes).expect("summary");
    assert_eq!(summary.comms_by_tid[&201], "parent");
    assert_eq!(summary.sample_stacks.len(), 3);
    assert_eq!(
        summary
            .sample_stacks
            .iter()
            .map(|sample| sample.period.unwrap())
            .sum::<u64>(),
        12
    );
}

#[test]
fn summary_delivers_zero_timestamp_events_immediately() {
    // Linux v7.2.9 tools/perf/util/ordered-events.c:199-200 rejects zero and
    // ~0ULL with -ETIME; session.c:2944-2949 dispatches both immediately.
    let sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
    let mut attr = file_attr_bytes(sample_type, 0, 0);
    put_u64(&mut attr, 40, 1 << 18);
    let bytes = perfdata_with_records_and_attrs(
        [attr],
        [
            comm_record(200, 200, "zero-time", false, true, sample_type, 0),
            comm_record(200, 200, "max-time", false, true, sample_type, u64::MAX),
        ],
    );

    let summary = summarize_perfdata(&bytes).expect("summary");
    assert_eq!(summary.total_records, 2);
    assert_eq!(summary.comms_by_tid[&200], "max-time");
}

#[test]
fn summary_orders_parent_mapping_before_child_fork_inheritance() {
    // Linux v7.2.9 tools/perf/util/session.c:2937-2949 applies the earlier
    // timestamped MMAP before FORK; child map inheritance follows that order.
    let sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
    let mut attr = file_attr_bytes(sample_type, 0, 0);
    put_u64(&mut attr, 40, 1 << 18);
    let bytes = perfdata_with_records_and_attrs(
        [attr],
        [
            fork_record(100, 101, 200, 201, true, sample_type, 20),
            mmap_record(100, 101, 10, sample_type),
        ],
    );

    let summary = summarize_perfdata(&bytes).expect("summary");
    assert_eq!(
        summary.mmap_table.mapping_path(200, 0x4100),
        Some("parent.so")
    );
    assert_eq!(
        summary.mmap_table.mapping_path(100, 0x4100),
        Some("parent.so")
    );
}

fn child_exec_order_fixture(
    sample_type: u64,
    sample_id_all: bool,
    times: Option<[u64; 3]>,
) -> Vec<u8> {
    let mut attr = file_attr_bytes(sample_type, 0, 0);
    if sample_id_all {
        put_u64(&mut attr, 40, 1 << 18);
    }

    let [exec_time, parent_time, fork_time] = times.unwrap_or([0, 0, 0]);
    let mut records = vec![
        comm_record(
            200,
            201,
            "child-exec",
            true,
            sample_id_all,
            sample_type,
            exec_time,
        ),
        comm_record(
            100,
            101,
            "parent",
            false,
            sample_id_all,
            sample_type,
            parent_time,
        ),
        fork_record(100, 101, 200, 201, sample_id_all, sample_type, fork_time),
    ];
    records.push(lost_record(sample_id_all, sample_type));
    records.push(record_bytes(68, &[]));
    records.push(record_bytes(68, &[]));
    for period in [2, 3, 7] {
        records.push(record_bytes(
            PERF_RECORD_SAMPLE,
            &timed_sample_payload(
                sample_type,
                0x1000,
                200,
                201,
                period + 30,
                period,
                &[0x1000, 0x2000],
            ),
        ));
    }
    perfdata_with_records_and_attrs([attr], records)
}

fn mmap_record(pid: u32, tid: u32, time: u64, sample_type: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(0x4000_u64.to_le_bytes());
    payload.extend(0x1000_u64.to_le_bytes());
    payload.extend(0_u64.to_le_bytes());
    payload.extend(b"parent.so\0");
    payload.resize(payload.len().next_multiple_of(8), 0);
    append_sample_id(&mut payload, true, sample_type, pid, tid, time);
    record_bytes(PERF_RECORD_MMAP, &payload)
}

fn lost_record(sample_id_all: bool, sample_type: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(1_u64.to_le_bytes());
    payload.extend(4_u64.to_le_bytes());
    append_sample_id(&mut payload, sample_id_all, sample_type, 200, 201, 25);
    record_bytes(PERF_RECORD_LOST, &payload)
}

fn comm_record(
    pid: u32,
    tid: u32,
    comm: &str,
    is_exec: bool,
    sample_id_all: bool,
    sample_type: u64,
    time: u64,
) -> Vec<u8> {
    let mut payload = comm_payload(pid, tid, comm);
    payload.resize(payload.len().next_multiple_of(8), 0);
    append_sample_id(&mut payload, sample_id_all, sample_type, pid, tid, time);
    record_bytes_with_misc(
        PERF_RECORD_COMM,
        if is_exec {
            PERF_RECORD_MISC_COMM_EXEC
        } else {
            0
        },
        &payload,
    )
}

fn fork_record(
    parent_process: u32,
    parent_thread: u32,
    child_process: u32,
    child_thread: u32,
    sample_id_all: bool,
    sample_type: u64,
    time: u64,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(child_process.to_le_bytes());
    payload.extend(parent_process.to_le_bytes());
    payload.extend(child_thread.to_le_bytes());
    payload.extend(parent_thread.to_le_bytes());
    payload.extend(time.to_le_bytes());
    append_sample_id(
        &mut payload,
        sample_id_all,
        sample_type,
        child_process,
        child_thread,
        time,
    );
    record_bytes(PERF_RECORD_FORK, &payload)
}

fn append_sample_id(
    payload: &mut Vec<u8>,
    sample_id_all: bool,
    sample_type: u64,
    pid: u32,
    tid: u32,
    time: u64,
) {
    // Linux v7.2.9 tools/perf/util/evsel.c:3240-3263,
    // perf_evsel__parse_id_sample: TID and TIME are independent trailer fields.
    if !sample_id_all {
        return;
    }
    if sample_type & PERF_SAMPLE_TID != 0 {
        payload.extend(pid.to_le_bytes());
        payload.extend(tid.to_le_bytes());
    }
    if sample_type & PERF_SAMPLE_TIME != 0 {
        payload.extend(time.to_le_bytes());
    }
}

fn timed_sample_payload(
    sample_type: u64,
    ip: u64,
    pid: u32,
    tid: u32,
    time: u64,
    period: u64,
    callchain: &[u64],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    if sample_type & PERF_SAMPLE_TIME != 0 {
        payload.extend(time.to_le_bytes());
    }
    payload.extend(period.to_le_bytes());
    payload.extend(
        u64::try_from(callchain.len())
            .expect("callchain size")
            .to_le_bytes(),
    );
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

proptest! {
    #[test]
    fn property_analyzes_generated_sample_aggregates(
        generated in prop::collection::vec(generated_sample(), 0..48),
        limit in 0_usize..16,
    ) {
        let mut records = generated
            .iter()
            .map(|sample| {
                record_bytes_with_misc(
                    9,
                    sample.cpumode,
                    &sample_payload_vec(
                        sample.ip,
                        sample.tid,
                        sample.tid,
                        u64::from(sample.period),
                        &sample.callchain,
                    ),
                )
            })
            .collect::<Vec<_>>();

        for tid in generated
            .iter()
            .map(|sample| sample.tid)
            .collect::<BTreeSet<_>>()
        {
            let comm = generated
                .iter()
                .find(|sample| sample.tid == tid)
                .expect("comm source")
                .comm
                .clone();
            records.push(record_bytes(3, &comm_payload(tid, tid, &comm)));
        }
        let total_records = records.len();

        let perfdata = perfdata_with_records_and_attrs(
            [file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            records,
        );
        let report = analyze_perfdata(&perfdata, limit).expect("analysis");

        prop_assert_eq!(report.total_records, total_records);
        prop_assert_eq!(report.total_samples, generated.len());
        prop_assert_eq!(
            report.weighted_samples,
            generated
                .iter()
                .map(|sample| u64::from(sample.period))
                .sum::<u64>()
        );
        prop_assert_eq!(report.lost_records, 0);
        prop_assert_eq!(report.user_stack_samples, 0);
        prop_assert_eq!(report.user_stack_bytes, 0);
        prop_assert_eq!(report.user_stack_dynamic_bytes, 0);
        prop_assert_eq!(report.user_register_samples, 0);
        prop_assert_eq!(report.user_register_ip_samples, 0);
        prop_assert_eq!(report.sample_modes, expected_sample_modes(&generated));
        prop_assert_eq!(report.threads, expected_threads(&generated, limit));
        prop_assert_eq!(report.top_leaf_ips, expected_leaf_ips(&generated, limit));
        prop_assert_eq!(report.top_edges, expected_edges(&generated, limit));
    }
}

fn perfdata_with_records_and_attrs<const A: usize, I>(attrs: [[u8; 144]; A], records: I) -> Vec<u8>
where
    I: IntoIterator<Item = Vec<u8>>,
{
    let records = records.into_iter().collect::<Vec<_>>();
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

fn file_attr_bytes_with_regs(sample_type: u64, sample_regs_user: u64) -> [u8; 144] {
    let mut bytes = file_attr_bytes(sample_type, 0, 0);
    put_u64(&mut bytes, 80, sample_regs_user);
    bytes
}

fn record_bytes(record_type: u32, payload: &[u8]) -> Vec<u8> {
    record_bytes_with_misc(record_type, 0, payload)
}

fn record_bytes_with_misc(record_type: u32, misc: u16, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend(record_type.to_le_bytes());
    record.extend(misc.to_le_bytes());
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
    sample_payload_vec(ip, pid, tid, period, &callchain)
}

fn sample_payload_vec(ip: u64, pid: u32, tid: u32, period: u64, callchain: &[u64]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_user_stack<const R: usize, const S: usize>(
    mut payload: Vec<u8>,
    regs: [u64; R],
    stack: [u8; S],
) -> Vec<u8> {
    payload.extend(1_u64.to_le_bytes());
    for reg in regs {
        payload.extend(reg.to_le_bytes());
    }
    payload.extend((stack.len() as u64).to_le_bytes());
    payload.extend(stack);
    // Installed perf 7.2.9 evsel.c:3703-3720: exact data[size], then dyn_size.
    if S != 0 {
        payload.extend((S as u64).to_le_bytes());
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

#[derive(Clone, Debug)]
struct GeneratedSample {
    ip: u64,
    tid: u32,
    period: u16,
    cpumode: u16,
    callchain: Vec<u64>,
    comm: String,
}

fn generated_sample() -> impl Strategy<Value = GeneratedSample> {
    (
        1_u16..8_u16,
        1_u16..5_000_u16,
        prop_oneof![
            Just(PERF_RECORD_MISC_CPUMODE_USER),
            Just(PERF_RECORD_MISC_CPUMODE_KERNEL),
        ],
        0_usize..3_usize,
        prop::collection::vec(0x10_u64..0x10_000_u64, 1..5),
    )
        .prop_map(|(tid, period, cpumode, marker_count, frames)| {
            let mut callchain = vec![0xffff_ffff_ffff_ff80; marker_count];
            callchain.extend(frames);
            let tid = u32::from(tid);
            GeneratedSample {
                ip: *callchain
                    .iter()
                    .find(|frame| !is_context_marker(**frame))
                    .expect("leaf ip"),
                tid,
                period,
                cpumode,
                callchain,
                comm: format!("thread-{tid}"),
            }
        })
}

fn expected_threads(samples: &[GeneratedSample], limit: usize) -> Vec<PerfdataThread> {
    let mut counts = BTreeMap::<u32, (String, usize, u64)>::new();
    for sample in samples {
        let entry = counts
            .entry(sample.tid)
            .or_insert_with(|| (sample.comm.clone(), 0, 0));
        entry.1 += 1;
        entry.2 += u64::from(sample.period);
    }

    let mut threads = counts
        .into_iter()
        .map(|(tid, (comm, samples, weighted_samples))| PerfdataThread {
            tid,
            comm,
            samples,
            weighted_samples,
        })
        .collect::<Vec<_>>();
    threads.sort_by(|left, right| {
        right
            .weighted_samples
            .cmp(&left.weighted_samples)
            .then_with(|| left.tid.cmp(&right.tid))
    });
    threads.truncate(limit);
    threads
}

fn expected_sample_modes(samples: &[GeneratedSample]) -> Vec<PerfdataSampleMode> {
    let mut counts = BTreeMap::<&'static str, (usize, u64)>::new();
    for sample in samples {
        let entry = counts
            .entry(sample_mode_name(sample.cpumode))
            .or_insert((0, 0));
        entry.0 += 1;
        entry.1 += u64::from(sample.period);
    }

    let mut modes = counts
        .into_iter()
        .map(|(mode, (samples, weighted_samples))| PerfdataSampleMode {
            mode: mode.to_string(),
            samples,
            weighted_samples,
        })
        .collect::<Vec<_>>();
    modes.sort_by(|left, right| {
        right
            .weighted_samples
            .cmp(&left.weighted_samples)
            .then_with(|| left.mode.cmp(&right.mode))
    });
    modes
}

fn expected_leaf_ips(samples: &[GeneratedSample], limit: usize) -> Vec<PerfdataIpCount> {
    let mut counts = BTreeMap::<String, (usize, u64)>::new();
    for sample in samples {
        let leaf = format_ip(
            filtered_callchain(&sample.callchain)
                .into_iter()
                .next()
                .expect("leaf"),
        );
        let entry = counts.entry(leaf).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += u64::from(sample.period);
    }

    let mut ips = counts
        .into_iter()
        .map(|(ip, (samples, weighted_samples))| PerfdataIpCount {
            ip,
            samples,
            weighted_samples,
        })
        .collect::<Vec<_>>();
    ips.sort_by(|left, right| {
        right
            .weighted_samples
            .cmp(&left.weighted_samples)
            .then_with(|| left.ip.cmp(&right.ip))
    });
    ips.truncate(limit);
    ips
}

fn expected_edges(samples: &[GeneratedSample], limit: usize) -> Vec<PerfdataEdgeCount> {
    let mut counts = BTreeMap::<(String, String), (usize, u64)>::new();
    for sample in samples {
        let frames = filtered_callchain(&sample.callchain);
        for edge in frames.windows(2) {
            let key = (format_ip(edge[1]), format_ip(edge[0]));
            let entry = counts.entry(key).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += u64::from(sample.period);
        }
    }

    let mut edges = counts
        .into_iter()
        .map(
            |((caller, callee), (samples, weighted_samples))| PerfdataEdgeCount {
                caller,
                callee,
                samples,
                weighted_samples,
            },
        )
        .collect::<Vec<_>>();
    edges.sort_by(|left, right| {
        right
            .weighted_samples
            .cmp(&left.weighted_samples)
            .then_with(|| left.caller.cmp(&right.caller))
            .then_with(|| left.callee.cmp(&right.callee))
    });
    edges.truncate(limit);
    edges
}

fn filtered_callchain(callchain: &[u64]) -> Vec<u64> {
    callchain
        .iter()
        .copied()
        .filter(|frame| !is_context_marker(*frame))
        .collect()
}

fn sample_mode_name(cpumode: u16) -> &'static str {
    match cpumode {
        PERF_RECORD_MISC_CPUMODE_KERNEL => "kernel",
        PERF_RECORD_MISC_CPUMODE_USER => "user",
        _ => "unknown",
    }
}

fn is_context_marker(ip: u64) -> bool {
    // linux/include/uapi/linux/perf_event.h: PERF_CONTEXT_MAX = (__u64)-4095.
    ip >= 0xffff_ffff_ffff_f001
}

fn format_ip(ip: u64) -> String {
    format!("0x{ip:016x}")
}
