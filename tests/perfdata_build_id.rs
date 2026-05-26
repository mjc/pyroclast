use pyroclast::perfdata::build_id::{
    BuildIdEvent, build_id_events_from_perfdata, kernel_build_id_from_perfdata,
    parse_build_id_events,
};

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

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
