use proptest::prelude::*;
use pyroclast::perfdata::header::parse_header;
use pyroclast::perfdata::records::{
    ParsedRecord, PerfRecord, PerfRecordHeader, iter_records, parse_aux_output_hw_id_record,
    parse_aux_record, parse_bpf_event_record, parse_callchain_deferred_record, parse_cgroup_record,
    parse_comm_record, parse_exit_record, parse_fork_record, parse_itrace_start_record,
    parse_ksymbol_record, parse_lost_record, parse_lost_samples_record, parse_mmap_record,
    parse_mmap2_build_id_record, parse_mmap2_record, parse_namespaces_record, parse_read_record,
    parse_record, parse_record_header, parse_switch_cpu_wide_record, parse_switch_record,
    parse_text_poke_record, parse_throttle_record, parse_unthrottle_record,
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

proptest! {
    #[test]
    fn parses_perf_record_header_from_little_endian_fields(
        record_type in any::<u32>(),
        misc in any::<u16>(),
        size in 8u16..=u16::MAX,
    ) {
        let mut bytes = [0; 8];
        bytes[0..4].copy_from_slice(&record_type.to_le_bytes());
        bytes[4..6].copy_from_slice(&misc.to_le_bytes());
        bytes[6..8].copy_from_slice(&size.to_le_bytes());

        let header = parse_record_header(&bytes).expect("record header");

        prop_assert_eq!(header.record_type, record_type);
        prop_assert_eq!(header.misc, misc);
        prop_assert_eq!(header.size, size);
    }
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

#[test]
fn parses_read_record_payload_from_perf_event_header_shape() {
    let payload = read_payload();

    let read = parse_read_record(&payload).expect("read record");

    assert_eq!(read.pid, 123);
    assert_eq!(read.tid, 456);
    assert_eq!(read.values, vec![1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn dispatches_read_record_by_perf_record_type() {
    let payload = read_payload();
    let record = PerfRecord {
        offset: 104,
        header: PerfRecordHeader {
            record_type: 8,
            misc: 0,
            size: u16::try_from(8 + payload.len()).expect("record size"),
        },
        payload: &payload,
    };

    let parsed = parse_record(record).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::Read(_)));
}

proptest! {
    #[test]
    fn parses_aux_record_payload_from_little_endian_fields(
        aux_offset in any::<u64>(),
        aux_size in any::<u64>(),
        flags in any::<u64>(),
        sample_id in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let payload = aux_payload(aux_offset, aux_size, flags, &sample_id);

        let aux = parse_aux_record(&payload).expect("aux record");

        prop_assert_eq!(aux.aux_offset, aux_offset);
        prop_assert_eq!(aux.aux_size, aux_size);
        prop_assert_eq!(aux.flags, flags);
        prop_assert_eq!(aux.sample_id, sample_id);
    }

    #[test]
    fn parses_itrace_start_record_payload_from_little_endian_fields(
        pid in any::<u32>(),
        tid in any::<u32>(),
        sample_id in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let payload = two_u32_payload(pid, tid, &sample_id);

        let itrace_start = parse_itrace_start_record(&payload).expect("itrace start record");

        prop_assert_eq!(itrace_start.pid, pid);
        prop_assert_eq!(itrace_start.tid, tid);
        prop_assert_eq!(itrace_start.sample_id, sample_id);
    }

    #[test]
    fn parses_switch_record_payload_losslessly(
        sample_id in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let switch = parse_switch_record(&sample_id).expect("switch record");

        prop_assert_eq!(switch.sample_id, sample_id);
    }

    #[test]
    fn parses_switch_cpu_wide_record_payload_from_little_endian_fields(
        next_prev_pid in any::<u32>(),
        next_prev_tid in any::<u32>(),
        sample_id in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let payload = two_u32_payload(next_prev_pid, next_prev_tid, &sample_id);

        let switch = parse_switch_cpu_wide_record(&payload).expect("switch cpu wide record");

        prop_assert_eq!(switch.next_prev_pid, next_prev_pid);
        prop_assert_eq!(switch.next_prev_tid, next_prev_tid);
        prop_assert_eq!(switch.sample_id, sample_id);
    }

    #[test]
    fn parses_bpf_event_record_payload_from_little_endian_fields(
        event_type in any::<u16>(),
        flags in any::<u16>(),
        id in any::<u32>(),
        tag in any::<[u8; 8]>(),
        sample_id in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let payload = bpf_event_payload(event_type, flags, id, tag, &sample_id);

        let event = parse_bpf_event_record(&payload).expect("bpf event record");

        prop_assert_eq!(event.event_type, event_type);
        prop_assert_eq!(event.flags, flags);
        prop_assert_eq!(event.id, id);
        prop_assert_eq!(event.tag, tag);
        prop_assert_eq!(event.sample_id, sample_id);
    }

    #[test]
    fn parses_aux_output_hw_id_record_payload_from_little_endian_fields(
        hw_id in any::<u64>(),
        sample_id in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let payload = one_u64_payload(hw_id, &sample_id);

        let record = parse_aux_output_hw_id_record(&payload).expect("aux output hw id record");

        prop_assert_eq!(record.hw_id, hw_id);
        prop_assert_eq!(record.sample_id, sample_id);
    }
}

#[test]
fn dispatches_aux_record_by_perf_record_type() {
    let payload = aux_payload(1, 2, 3, &[4, 5]);
    let parsed = parse_record(perf_record(11, &payload)).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::Aux(_)));
}

#[test]
fn dispatches_itrace_start_record_by_perf_record_type() {
    let payload = two_u32_payload(123, 456, &[7, 8]);
    let parsed = parse_record(perf_record(12, &payload)).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::ItraceStart(_)));
}

#[test]
fn dispatches_switch_record_by_perf_record_type() {
    let payload = vec![1, 2, 3];
    let parsed = parse_record(perf_record(14, &payload)).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::Switch(_)));
}

#[test]
fn dispatches_switch_cpu_wide_record_by_perf_record_type() {
    let payload = two_u32_payload(123, 456, &[7, 8]);
    let parsed = parse_record(perf_record(15, &payload)).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::SwitchCpuWide(_)));
}

#[test]
fn parses_namespaces_record_payload_from_perf_event_header_shape() {
    let payload = namespaces_payload();

    let namespaces = parse_namespaces_record(&payload).expect("namespaces record");

    assert_eq!(namespaces.pid, 123);
    assert_eq!(namespaces.tid, 456);
    assert_eq!(namespaces.namespaces.len(), 2);
    assert_eq!(namespaces.namespaces[0].dev, 11);
    assert_eq!(namespaces.namespaces[0].inode, 22);
    assert_eq!(namespaces.namespaces[1].dev, 33);
    assert_eq!(namespaces.namespaces[1].inode, 44);
    assert_eq!(namespaces.sample_id, vec![9, 8]);
}

#[test]
fn dispatches_namespaces_record_by_perf_record_type() {
    let payload = namespaces_payload();
    let parsed = parse_record(perf_record(16, &payload)).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::Namespaces(_)));
}

#[test]
fn parses_ksymbol_record_payload_from_perf_event_header_shape() {
    let payload = ksymbol_payload();

    let ksymbol = parse_ksymbol_record(&payload).expect("ksymbol record");

    assert_eq!(ksymbol.addr, 0xfeed);
    assert_eq!(ksymbol.len, 64);
    assert_eq!(ksymbol.ksym_type, 1);
    assert_eq!(ksymbol.flags, 2);
    assert_eq!(ksymbol.name, "bpf_prog");
    assert_eq!(ksymbol.sample_id, vec![7, 6]);
}

#[test]
fn dispatches_ksymbol_record_by_perf_record_type() {
    let payload = ksymbol_payload();
    let parsed = parse_record(perf_record(17, &payload)).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::Ksymbol(_)));
}

#[test]
fn dispatches_bpf_event_record_by_perf_record_type() {
    let payload = bpf_event_payload(1, 2, 3, [4; 8], &[5, 6]);
    let parsed = parse_record(perf_record(18, &payload)).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::BpfEvent(_)));
}

#[test]
fn parses_cgroup_record_payload_from_perf_event_header_shape() {
    let payload = cgroup_payload();

    let cgroup = parse_cgroup_record(&payload).expect("cgroup record");

    assert_eq!(cgroup.id, 77);
    assert_eq!(cgroup.path, "/sys/fs/cgroup/work");
    assert_eq!(cgroup.sample_id, vec![1, 3, 5]);
}

#[test]
fn dispatches_cgroup_record_by_perf_record_type() {
    let payload = cgroup_payload();
    let parsed = parse_record(perf_record(19, &payload)).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::Cgroup(_)));
}

#[test]
fn parses_text_poke_record_payload_from_perf_event_header_shape() {
    let payload = text_poke_payload();

    let text_poke = parse_text_poke_record(&payload).expect("text poke record");

    assert_eq!(text_poke.addr, 0xabc);
    assert_eq!(text_poke.old_len, 2);
    assert_eq!(text_poke.new_len, 3);
    assert_eq!(text_poke.bytes, vec![0x90, 0x90, 0xcc, 0xcc, 0xcc]);
    assert_eq!(text_poke.sample_id, vec![4, 2]);
}

#[test]
fn dispatches_text_poke_record_by_perf_record_type() {
    let payload = text_poke_payload();
    let parsed = parse_record(perf_record(20, &payload)).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::TextPoke(_)));
}

#[test]
fn dispatches_aux_output_hw_id_record_by_perf_record_type() {
    let payload = one_u64_payload(123, &[4, 5]);
    let parsed = parse_record(perf_record(21, &payload)).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::AuxOutputHwId(_)));
}

#[test]
fn parses_callchain_deferred_record_payload_from_perf_event_header_shape() {
    let payload = callchain_deferred_payload();

    let callchain = parse_callchain_deferred_record(&payload).expect("callchain deferred record");

    assert_eq!(callchain.cookie, 42);
    assert_eq!(callchain.ips, vec![0x1000, 0x2000]);
    assert_eq!(callchain.sample_id, vec![9, 9]);
}

#[test]
fn dispatches_callchain_deferred_record_by_perf_record_type() {
    let payload = callchain_deferred_payload();
    let parsed = parse_record(perf_record(22, &payload)).expect("parsed record");

    assert!(matches!(parsed, ParsedRecord::CallchainDeferred(_)));
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

fn read_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend([1, 2, 3, 4, 5, 6, 7, 8]);
    payload
}

fn aux_payload(aux_offset: u64, aux_size: u64, flags: u64, sample_id: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(aux_offset.to_le_bytes());
    payload.extend(aux_size.to_le_bytes());
    payload.extend(flags.to_le_bytes());
    payload.extend(sample_id);
    payload
}

fn one_u64_payload(value: u64, sample_id: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(value.to_le_bytes());
    payload.extend(sample_id);
    payload
}

fn two_u32_payload(first: u32, second: u32, sample_id: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(first.to_le_bytes());
    payload.extend(second.to_le_bytes());
    payload.extend(sample_id);
    payload
}

fn namespaces_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(123u32.to_le_bytes());
    payload.extend(456u32.to_le_bytes());
    payload.extend(2u64.to_le_bytes());
    payload.extend(11u64.to_le_bytes());
    payload.extend(22u64.to_le_bytes());
    payload.extend(33u64.to_le_bytes());
    payload.extend(44u64.to_le_bytes());
    payload.extend([9, 8]);
    payload
}

fn ksymbol_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(0xfeedu64.to_le_bytes());
    payload.extend(64u32.to_le_bytes());
    payload.extend(1u16.to_le_bytes());
    payload.extend(2u16.to_le_bytes());
    payload.extend(b"bpf_prog\0");
    payload.extend([7, 6]);
    payload
}

fn bpf_event_payload(
    event_type: u16,
    flags: u16,
    id: u32,
    tag: [u8; 8],
    sample_id: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(event_type.to_le_bytes());
    payload.extend(flags.to_le_bytes());
    payload.extend(id.to_le_bytes());
    payload.extend(tag);
    payload.extend(sample_id);
    payload
}

fn cgroup_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(77u64.to_le_bytes());
    payload.extend(b"/sys/fs/cgroup/work\0");
    payload.extend([1, 3, 5]);
    payload
}

fn text_poke_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(0xabcu64.to_le_bytes());
    payload.extend(2u16.to_le_bytes());
    payload.extend(3u16.to_le_bytes());
    payload.extend([0x90, 0x90, 0xcc, 0xcc, 0xcc]);
    payload.extend([4, 2]);
    payload
}

fn callchain_deferred_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(42u64.to_le_bytes());
    payload.extend(2u64.to_le_bytes());
    payload.extend(0x1000u64.to_le_bytes());
    payload.extend(0x2000u64.to_le_bytes());
    payload.extend([9, 9]);
    payload
}

fn perf_record(record_type: u32, payload: &[u8]) -> PerfRecord<'_> {
    PerfRecord {
        offset: 104,
        header: PerfRecordHeader {
            record_type,
            misc: 0,
            size: u16::try_from(8 + payload.len()).expect("record size"),
        },
        payload,
    }
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
