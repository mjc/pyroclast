use pyroclast::perfdata::build_id::{BuildIdEvent, parse_build_id_events};

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
