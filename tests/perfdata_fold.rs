mod common;

use common::{
    comm_payload, file_attr_bytes, mmap_payload, mmap2_payload, perfdata_with_records_and_attrs,
    record_bytes, sample_payload,
};
use pyroclast::perfdata::fold::summarize_perfdata;
use pyroclast::perfdata::samples::{PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_TID};

#[test]
fn summarizes_record_counts_and_comm_names() {
    let bytes = perfdata_with_records_and_attrs(
        [],
        [
            record_bytes(3, &comm_payload(1, 2, "sftp-s3")),
            record_bytes(
                1,
                &mmap_payload(1, 2, 0x1000, 0x2000, 0, "/usr/bin/sftp-s3"),
            ),
            record_bytes(
                10,
                &mmap2_payload(1, 2, 0x3000, 0x4000, 0, "/usr/lib/libc.so"),
            ),
            record_bytes(9, b"sample"),
        ],
    );

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.total_records, 4);
    assert_eq!(summary.record_count(1), 1);
    assert_eq!(summary.record_count(3), 1);
    assert_eq!(summary.record_count(9), 1);
    assert_eq!(summary.record_count(10), 1);
    assert_eq!(summary.comms, vec!["sftp-s3"]);
    assert_eq!(summary.mmaps, vec!["/usr/bin/sftp-s3", "/usr/lib/libc.so"]);
}

#[test]
fn summarizes_sample_callchain_counts_using_file_attr_layout() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0x2000, 0x3000]),
        )],
    );

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.sample_callchains, vec![vec![0x2000, 0x3000]]);
}
