use proptest::prelude::*;
use proptest::string::string_regex;
use pyroclast::perfdata::build_id::{
    BuildIdEvent, build_id_events_from_perfdata, kernel_build_id_from_perfdata,
    kernel_build_id_from_perfdata_file, parse_build_id_events,
};
use pyroclast::perfdata::records::{PERF_RECORD_MISC_MMAP_BUILD_ID, PERF_RECORD_MMAP2};

#[test]
fn parses_build_id_events_from_header_feature_payload() {
    let payload = build_id_event_payload(
        123,
        &[
            0x16, 0xed, 0x3d, 0x53, 0x17, 0xad, 0x21, 0x9c, 0x89, 0xd0, 0xe3, 0xc5, 0xea, 0x0e,
            0xa2, 0xca, 0xa3, 0xcd, 0x49, 0x49,
        ],
        "[kernel.kallsyms]",
    );

    let events = parse_build_id_events(&payload).expect("build ids");

    assert_eq!(
        events,
        vec![BuildIdEvent {
            pid: 123,
            build_id: "16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949".to_string(),
            filename: "[kernel.kallsyms]".to_string(),
        }]
    );
}

#[test]
fn extracts_kernel_build_id_from_perfdata_header_feature() {
    let build_id = [
        0x16, 0xed, 0x3d, 0x53, 0x17, 0xad, 0x21, 0x9c, 0x89, 0xd0, 0xe3, 0xc5, 0xea, 0x0e, 0xa2,
        0xca, 0xa3, 0xcd, 0x49, 0x49,
    ];
    let payload = build_id_event_payload(u32::MAX, &build_id, "[kernel.kallsyms]");
    let bytes = perfdata_with_build_id_feature(&payload);

    let kernel_build_id = kernel_build_id_from_perfdata(&bytes).expect("build id");

    assert_eq!(
        kernel_build_id,
        Some("16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949".to_string())
    );
}

#[test]
fn extracts_kernel_build_id_from_perfdata_record_stream() {
    let build_id = [
        0xb4, 0x2c, 0xe5, 0x21, 0xdb, 0xc9, 0xfc, 0x99, 0x43, 0x96, 0x02, 0x11, 0xa7, 0xf6, 0x4e,
        0x44, 0x8f, 0xc9, 0x07, 0x1b,
    ];
    let payload = build_id_event_payload(u32::MAX, &build_id, "[kernel.kallsyms]");
    let bytes = perfdata_with_data_records(&payload);

    let kernel_build_id = kernel_build_id_from_perfdata(&bytes).expect("build id");

    assert_eq!(
        kernel_build_id,
        Some("b42ce521dbc9fc9943960211a7f64e448fc9071b".to_string())
    );
}

#[test]
fn extracts_kernel_build_id_from_mmap2_build_id_record() {
    let build_id = [
        0xb4, 0x2c, 0xe5, 0x21, 0xdb, 0xc9, 0xfc, 0x99, 0x43, 0x96, 0x02, 0x11, 0xa7, 0xf6, 0x4e,
        0x44, 0x8f, 0xc9, 0x07, 0x1b,
    ];
    let payload = mmap2_build_id_payload(u32::MAX, &build_id, "[kernel.kallsyms]_text");
    let record = perf_record(PERF_RECORD_MMAP2, PERF_RECORD_MISC_MMAP_BUILD_ID, &payload);
    let bytes = perfdata_with_data_records(&record);

    let kernel_build_id = kernel_build_id_from_perfdata(&bytes).expect("build id");

    assert_eq!(
        kernel_build_id,
        Some("b42ce521dbc9fc9943960211a7f64e448fc9071b".to_string())
    );
}

#[test]
fn extracts_all_build_id_events_from_perfdata_header_feature() {
    let kernel_build_id = [
        0x16, 0xed, 0x3d, 0x53, 0x17, 0xad, 0x21, 0x9c, 0x89, 0xd0, 0xe3, 0xc5, 0xea, 0x0e, 0xa2,
        0xca, 0xa3, 0xcd, 0x49, 0x49,
    ];
    let user_build_id = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90,
        0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
    ];
    let mut payload = build_id_event_payload(u32::MAX, &kernel_build_id, "[kernel.kallsyms]");
    payload.extend(build_id_event_payload(42, &user_build_id, "/tmp/stale-app"));
    let bytes = perfdata_with_build_id_feature(&payload);

    let events = build_id_events_from_perfdata(&bytes).expect("build ids");

    assert_eq!(
        events,
        vec![
            BuildIdEvent {
                pid: u32::MAX,
                build_id: "16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949".to_string(),
                filename: "[kernel.kallsyms]".to_string(),
            },
            BuildIdEvent {
                pid: 42,
                build_id: "aabbccddeeff102030405060708090a0b0c0d0e0".to_string(),
                filename: "/tmp/stale-app".to_string(),
            },
        ]
    );
}

#[test]
fn extracts_kernel_build_id_from_perfdata_file() {
    let build_id = [
        0x16, 0xed, 0x3d, 0x53, 0x17, 0xad, 0x21, 0x9c, 0x89, 0xd0, 0xe3, 0xc5, 0xea, 0x0e, 0xa2,
        0xca, 0xa3, 0xcd, 0x49, 0x49,
    ];
    let payload = build_id_event_payload(u32::MAX, &build_id, "[kernel.kallsyms]");
    let bytes = perfdata_with_build_id_feature(&payload);
    let path = std::env::temp_dir().join(format!(
        "pyroclast-build-id-{}-{}.perf.data",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::write(&path, bytes).expect("write perf.data");

    let kernel_build_id = kernel_build_id_from_perfdata_file(&path).expect("build id");

    std::fs::remove_file(&path).expect("remove perf.data");
    assert_eq!(
        kernel_build_id,
        Some("16ed3d5317ad219c89d0e3c5ea0ea2caa3cd4949".to_string())
    );
}

proptest! {
    #[test]
    fn property_parses_concatenated_build_id_events_in_order(
        specs in prop::collection::vec(build_id_spec(), 0..32),
    ) {
        let payload = specs.iter().flat_map(BuildIdSpec::payload).collect::<Vec<_>>();
        let expected = specs
            .iter()
            .map(|spec| BuildIdEvent {
                pid: spec.pid,
                build_id: build_id_hex(&spec.build_id),
                filename: spec.filename.clone(),
            })
            .collect::<Vec<_>>();

        prop_assert_eq!(parse_build_id_events(&payload).expect("build-id events"), expected);
    }

    #[test]
    fn property_kernel_build_id_picks_first_kernelish_filename(
        specs in prop::collection::vec(build_id_spec(), 0..32),
    ) {
        let payload = specs.iter().flat_map(BuildIdSpec::payload).collect::<Vec<_>>();
        let perfdata = perfdata_with_build_id_feature(&payload);
        let expected = specs
            .iter()
            .find(|spec| is_kernel_filename(&spec.filename))
            .map(|spec| build_id_hex(&spec.build_id));

        prop_assert_eq!(
            kernel_build_id_from_perfdata(&perfdata).expect("kernel build id"),
            expected
        );
    }
}

#[derive(Clone, Debug)]
struct BuildIdSpec {
    pid: u32,
    build_id: [u8; 20],
    filename: String,
}

impl BuildIdSpec {
    fn payload(&self) -> Vec<u8> {
        build_id_event_payload(self.pid, &self.build_id, &self.filename)
    }
}

fn build_id_spec() -> impl Strategy<Value = BuildIdSpec> {
    (
        any::<u32>(),
        prop::array::uniform20(any::<u8>()),
        prop_oneof![
            kernel_filename().prop_map(str::to_string),
            non_kernel_filename(),
        ],
    )
        .prop_map(|(pid, build_id, filename)| BuildIdSpec {
            pid,
            build_id,
            filename,
        })
}

fn kernel_filename() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("[kernel.kallsyms]"),
        Just("[kernel]"),
        Just("[guest.kernel]"),
    ]
}

fn non_kernel_filename() -> impl Strategy<Value = String> {
    string_regex(r"[A-Za-z0-9_./-]{1,24}")
        .expect("valid filename regex")
        .prop_filter("exclude kernel-like paths", |filename| {
            !is_kernel_filename(filename)
        })
}

fn is_kernel_filename(filename: &str) -> bool {
    matches!(
        filename,
        "[kernel.kallsyms]" | "[kernel]" | "[guest.kernel]"
    )
}

fn build_id_hex(build_id: &[u8; 20]) -> String {
    let mut hex = String::with_capacity(build_id.len() * 2);
    for byte in build_id {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("write hex");
    }
    hex
}

fn build_id_event_payload(pid: u32, build_id: &[u8; 20], filename: &str) -> Vec<u8> {
    let size = 36 + filename.len() + 1;
    let mut payload = Vec::new();
    payload.extend(67_u32.to_le_bytes());
    payload.extend(0_u16.to_le_bytes());
    payload.extend(u16::try_from(size).expect("event size").to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(build_id);
    payload.extend([0; 4]);
    payload.extend(filename.as_bytes());
    payload.push(0);
    payload
}

fn perfdata_with_build_id_feature(payload: &[u8]) -> Vec<u8> {
    let feature_table_offset = 128;
    let payload_offset = 160;
    let mut bytes = vec![0; payload_offset + payload.len()];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 40, 128);
    put_u64(&mut bytes, 48, 0);
    put_u64(&mut bytes, 56, 1 << 2);
    put_u64(&mut bytes, feature_table_offset, payload_offset as u64);
    put_u64(
        &mut bytes,
        feature_table_offset + 8,
        u64::try_from(payload.len()).expect("payload size"),
    );
    bytes[payload_offset..].copy_from_slice(payload);
    bytes
}

fn perfdata_with_data_records(records: &[u8]) -> Vec<u8> {
    let data_offset = 128;
    let mut bytes = vec![0; data_offset + records.len()];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(
        &mut bytes,
        48,
        u64::try_from(records.len()).expect("data size"),
    );
    bytes[data_offset..].copy_from_slice(records);
    bytes
}

fn perf_record(record_type: u32, misc: u16, payload: &[u8]) -> Vec<u8> {
    let size = 8 + payload.len();
    let mut record = Vec::new();
    record.extend(record_type.to_le_bytes());
    record.extend(misc.to_le_bytes());
    record.extend(u16::try_from(size).expect("record size").to_le_bytes());
    record.extend(payload);
    record
}

fn mmap2_build_id_payload(pid: u32, build_id: &[u8], path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(0u32.to_le_bytes());
    payload.extend(0xffff_ffff_8360_0000u64.to_le_bytes());
    payload.extend(0x022a_8480_u64.to_le_bytes());
    payload.extend(0xffff_ffff_8360_0000u64.to_le_bytes());
    payload.push(u8::try_from(build_id.len()).expect("build id length"));
    payload.push(0);
    payload.extend(0u16.to_le_bytes());
    payload.extend(build_id);
    payload.extend(vec![0; 20 - build_id.len()]);
    payload.extend(0u32.to_le_bytes());
    payload.extend(0u32.to_le_bytes());
    payload.extend(path.as_bytes());
    payload.push(0);
    payload
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos()
}
