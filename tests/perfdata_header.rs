use pyroclast::perfdata::header::{
    PerfFeatureSection, PerfHeader, parse_feature_sections, parse_header,
};

#[test]
fn parses_perfdata_header_sections() {
    let bytes = header_bytes("PERFILE2", 104, 128, 64, 256, 4096);

    let header = parse_header(&bytes).expect("header");

    assert_eq!(
        header,
        PerfHeader {
            header_size: 104,
            attr_offset: 128,
            attr_size: 64,
            data_offset: 256,
            data_size: 4096,
        }
    );
}

#[test]
fn rejects_non_perfdata_magic() {
    let bytes = header_bytes("NOTPERF!", 104, 128, 64, 256, 4096);

    let error = parse_header(&bytes).expect_err("invalid magic");

    assert!(error.contains("PERFILE2"));
}

#[test]
fn parses_feature_sections_from_set_header_bits() {
    let mut bytes = vec![0; 520];
    bytes[..104].copy_from_slice(&header_bytes("PERFILE2", 104, 128, 64, 256, 128));
    put_u64(&mut bytes, 56, 1 << 2);
    put_u64(&mut bytes, 384, 448);
    put_u64(&mut bytes, 392, 72);

    let header = parse_header(&bytes).expect("header");
    let sections = parse_feature_sections(&bytes, &header).expect("features");

    assert_eq!(
        sections,
        vec![PerfFeatureSection {
            feature: 2,
            offset: 448,
            size: 72,
        }]
    );
}

fn header_bytes(
    magic: &str,
    header_size: u64,
    attr_offset: u64,
    attr_size: u64,
    data_offset: u64,
    data_size: u64,
) -> [u8; 104] {
    let mut bytes = [0; 104];
    bytes[..8].copy_from_slice(magic.as_bytes());
    put_u64(&mut bytes, 8, header_size);
    put_u64(&mut bytes, 24, attr_offset);
    put_u64(&mut bytes, 32, attr_size);
    put_u64(&mut bytes, 40, data_offset);
    put_u64(&mut bytes, 48, data_size);
    bytes
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
