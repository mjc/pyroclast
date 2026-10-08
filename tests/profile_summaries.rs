use pyroclast::perfdata::fold::{PerfSampleStack, PerfSummary};
use pyroclast::summary::{
    heap::summarize_heaptrack, summarize_perf_summary, syscalls::summarize_syscalls,
};

fn sample(tid: u32, time: Option<u64>, period: u64) -> PerfSampleStack {
    PerfSampleStack {
        misc: 0,
        cpumode: 0,
        pid: Some(7),
        tid: Some(tid),
        time,
        cpu: Some(2),
        period: Some(period),
        callchain: vec![],
        has_user_stack: false,
        user_register_count: 0,
        user_register_ip: None,
        user_stack_size: 0,
        user_stack_dynamic_size: 0,
    }
}

#[test]
fn profile_summary_uses_real_threads_and_sparse_timestamp_buckets() {
    let mut input = PerfSummary::default();
    input.comms_by_tid.insert(11, "reader".into());
    input.comms_by_tid.insert(12, "writer".into());
    input.sample_stacks = vec![
        sample(11, Some(1_000), 4),
        sample(12, Some(3_000), 7),
        sample(11, Some(1_500), 3),
        sample(12, None, 2),
    ];
    let summary = summarize_perf_summary(&input, 1_000, 10).unwrap();
    assert_eq!(summary.threads[0].tid, 12);
    assert_eq!(summary.threads[0].comm, "writer");
    assert_eq!(summary.threads[0].weighted_samples, 9);
    assert_eq!(summary.threads[1].first_sample_ns, Some(1_000));
    assert_eq!(summary.threads[1].last_sample_ns, Some(1_500));
    assert_eq!(summary.timeline.duration_ns, Some(2_000));
    assert_eq!(summary.timeline.untimed_samples, 1);
    assert_eq!(summary.timeline.buckets.len(), 2);
    assert_eq!(summary.timeline.buckets[0].weighted_samples, 7);
    assert_eq!(summary.timeline.buckets[1].start_offset_ns, 2_000);
    assert_eq!(summary.timeline.buckets[1].samples, 1);
}

#[test]
fn profile_summary_does_not_invent_timing_and_rejects_zero_bucket_width() {
    let input = PerfSummary {
        sample_stacks: vec![sample(11, None, 3)],
        ..PerfSummary::default()
    };
    let summary = summarize_perf_summary(&input, 1_000, 1).unwrap();
    assert_eq!(summary.timeline.duration_ns, None);
    assert!(summary.timeline.buckets.is_empty());
    assert_eq!(summary.timeline.untimed_samples, 1);
    assert!(summarize_perf_summary(&input, 0, 1).is_err());
}

#[test]
fn detailed_heap_summary_reports_native_runtime_leaks_and_temporary_allocations() {
    let summary = summarize_heaptrack(
        "calls to allocation functions: 42 (100/s)\npeak heap memory consumption: 1.5M\ntemporary memory allocations: 3 (7/s)\ntotal memory leaked: 4.10K\npeak RSS (including heaptrack overhead): 3.49M\ntotal runtime: 0.42s.\n",
    );
    assert_eq!(summary.total_allocations, Some(42));
    assert_eq!(summary.peak_heap_bytes, Some(1_500_000));
    assert_eq!(summary.temporary_allocations, Some(3));
    assert_eq!(summary.leaked_bytes, Some(4_100));
    assert_eq!(summary.peak_rss_bytes, Some(3_490_000));
    assert_eq!(summary.runtime_seconds, Some(0.42));
}

#[test]
fn syscall_summary_ranks_total_latency_and_reports_average_time() {
    let summary = summarize_syscalls(
        "11 read(0) = 0 <0.001>\n11 read(0) = 0 <0.003>\n11 write(0) = 0 <0.006>\n",
        10,
    );
    assert_eq!(summary.total_calls, 3);
    assert_eq!(summary.syscalls[0].name, "write");
    assert!((summary.syscalls[0].percent_of_syscall_time - 60.0).abs() < 1e-10);
    assert!((summary.syscalls[1].mean_seconds - 0.002).abs() < 1e-10);
}
