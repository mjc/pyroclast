use std::cell::RefCell;

use pyroclast::perfdata::fold::{
    FoldOptions, fold_perfdata_callchains, fold_perfdata_callchains_with_options,
    fold_perfdata_callchains_with_symbols, fold_perfdata_file_with_options, summarize_perfdata,
};
use pyroclast::perfdata::samples::{
    PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_PERIOD, PERF_SAMPLE_TID,
};
use pyroclast::symbols::{SymbolRequest, SymbolResolver};

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

#[test]
fn includes_record_context_when_sample_parsing_fails() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(9, &[0; 8])],
    );

    let error = summarize_perfdata(&bytes).expect_err("bad sample");

    assert!(error.contains("record type 9"));
    assert!(error.contains("offset"));
}

#[test]
fn folds_identical_sample_callchains_as_hex_frames() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000, 0x3000])),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000, 0x3000])),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x4000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "0x2000;0x3000 2\n0x4000 1\n");
}

#[test]
fn drops_perf_context_marker_frames_when_folding() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0xffff_ffff_ffff_fe00, 0x2000]),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "0x2000 1\n");
}

#[test]
fn prefixes_folded_stacks_with_matching_comm_name() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "sftp-s3")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "sftp-s3;0x2000 1\n");
}

#[test]
fn can_fold_samples_weighted_by_period() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 7, [0x2000])),
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 3, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
        },
    )
    .expect("folded");

    assert_eq!(folded, "0x2000 10\n");
}

#[test]
fn folds_perfdata_from_file_path() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 7, [0x2000])),
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 3, [0x2000])),
        ],
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded = fold_perfdata_file_with_options(
        &perfdata,
        FoldOptions {
            count_periods: true,
        },
    )
    .expect("folded");

    assert_eq!(folded, "0x2000 10\n");
}

#[test]
fn folds_mapped_user_frames_as_file_relative_addresses() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "/bin/app+0x10 1\n");
}

#[test]
fn folds_mapped_user_frames_with_symbol_names() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x1010])),
        ],
    );
    let resolver = StaticSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, "app::main;app::main 1\n");
}

#[test]
fn leaves_kernel_space_frames_as_hex_without_symbol_lookup() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0xffff_ffff_8800_0000, 0x2000, 0, "/bin/app"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0xffff_ffff_8800_0010])),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, "0xffffffff88000010 1\n");
    assert_eq!(resolver.calls(), Vec::<Vec<SymbolRequest>>::new());
}

#[test]
fn prefetches_unique_symbol_requests_before_folding() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x1020])),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x1020])),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, "app::main;app::work 2\n");
    assert_eq!(
        resolver.calls(),
        vec![vec![
            SymbolRequest {
                path: std::path::PathBuf::from("/bin/app"),
                relative_address: 0x10,
            },
            SymbolRequest {
                path: std::path::PathBuf::from("/bin/app"),
                relative_address: 0x20,
            }
        ]]
    );
}

fn perfdata_with_records_and_attrs<const A: usize, const R: usize>(
    attrs: [[u8; 144]; A],
    records: [Vec<u8>; R],
) -> Vec<u8> {
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

fn sample_payload<const N: usize>(ip: u64, pid: u32, tid: u32, callchain: [u64; N]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_period<const N: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
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

fn comm_payload(pid: u32, tid: u32, comm: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(comm.as_bytes());
    payload.push(0);
    payload
}

fn mmap_payload(pid: u32, tid: u32, start: u64, len: u64, pgoff: u64, path: &str) -> Vec<u8> {
    let mut payload = mmap_range_payload(pid, tid, start, len, pgoff);
    payload.extend(path.as_bytes());
    payload.push(0);
    payload
}

fn mmap2_payload(pid: u32, tid: u32, start: u64, len: u64, pgoff: u64, path: &str) -> Vec<u8> {
    let mut payload = mmap_range_payload(pid, tid, start, len, pgoff);
    payload.extend(8u32.to_le_bytes());
    payload.extend(1u32.to_le_bytes());
    payload.extend(99u64.to_le_bytes());
    payload.extend(7u64.to_le_bytes());
    payload.extend(5u32.to_le_bytes());
    payload.extend(2u32.to_le_bytes());
    payload.extend(path.as_bytes());
    payload.push(0);
    payload
}

fn mmap_range_payload(pid: u32, tid: u32, start: u64, len: u64, pgoff: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(start.to_le_bytes());
    payload.extend(len.to_le_bytes());
    payload.extend(pgoff.to_le_bytes());
    payload
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

struct StaticSymbolResolver;

impl SymbolResolver for StaticSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(requests
            .iter()
            .map(|request| {
                (request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10)
                    .then(|| "app::main".to_string())
                    .or_else(|| {
                        (request.path == std::path::Path::new("/bin/app")
                            && request.relative_address == 0x20)
                            .then(|| "app::work".to_string())
                    })
            })
            .collect())
    }
}

#[derive(Default)]
struct RecordingSymbolResolver {
    calls: RefCell<Vec<Vec<SymbolRequest>>>,
}

impl RecordingSymbolResolver {
    fn calls(&self) -> Vec<Vec<SymbolRequest>> {
        self.calls.borrow().clone()
    }
}

impl SymbolResolver for RecordingSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        self.calls.borrow_mut().push(requests.to_vec());
        Ok(requests
            .iter()
            .map(|request| {
                (request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10)
                    .then(|| "app::main".to_string())
                    .or_else(|| {
                        (request.path == std::path::Path::new("/bin/app")
                            && request.relative_address == 0x20)
                            .then(|| "app::work".to_string())
                    })
            })
            .collect())
    }
}
