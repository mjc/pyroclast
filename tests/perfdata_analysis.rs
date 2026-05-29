use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use pyroclast::perfdata::analysis::{
    PerfdataEdgeCount, PerfdataIpCount, PerfdataSampleMode, PerfdataThread, analyze_perfdata,
    analyze_perfdata_file,
};
use pyroclast::perfdata::records::{
    PERF_RECORD_MISC_CPUMODE_KERNEL, PERF_RECORD_MISC_CPUMODE_USER,
};
use pyroclast::perfdata::samples::{
    PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_PERIOD, PERF_SAMPLE_REGS_USER,
    PERF_SAMPLE_STACK_USER, PERF_SAMPLE_TID,
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
fn analyzes_sample_modes_and_user_stack_payloads() {
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
    payload.extend(vec![0; stack.len().next_multiple_of(8) - stack.len()]);
    payload.extend((S as u64).to_le_bytes());
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
    ip >= 0xffff_ffff_ffff_f000
}

fn format_ip(ip: u64) -> String {
    format!("0x{ip:016x}")
}
