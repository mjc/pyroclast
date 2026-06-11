use proptest::prelude::*;
use pyroclast::perfdata::header::{
    PerfFeatureSection, PerfHeader, parse_feature_sections, parse_header, parse_header_arch,
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
    // tools/perf/util/header.h struct perf_file_header places the
    // adds_features DECLARE_BITMAP at byte offset 72 (after magic[8], size[8],
    // attr_size[8], and the three 16-byte perf_file_section structs attrs,
    // data, event_types). The feature section table follows the data section.
    let mut bytes = vec![0; 520];
    bytes[..104].copy_from_slice(&header_bytes("PERFILE2", 104, 128, 64, 256, 128));
    put_u64(&mut bytes, 72, 1 << 2);
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

#[test]
fn parses_header_arch_feature_string() {
    // HEADER_ARCH (bit 6) payload is a perf_header_string: u32 length followed
    // by that many bytes of NUL-terminated text (util/header.c do_read_string).
    let mut bytes = vec![0; 520];
    bytes[..104].copy_from_slice(&header_bytes("PERFILE2", 104, 128, 64, 256, 128));
    // adds_features bitmap lives at offset 72 (struct perf_file_header).
    put_u64(&mut bytes, 72, 1 << 6);
    put_u64(&mut bytes, 384, 448);
    put_u64(&mut bytes, 392, 16);
    bytes[448..452].copy_from_slice(&12_u32.to_le_bytes());
    bytes[452..459].copy_from_slice(b"aarch64");

    let header = parse_header(&bytes).expect("header");

    assert_eq!(
        parse_header_arch(&bytes, &header).expect("arch"),
        Some("aarch64".to_string())
    );
}

#[test]
fn header_arch_is_none_when_feature_is_absent() {
    let bytes = header_bytes("PERFILE2", 104, 128, 64, 256, 0);

    let header = parse_header(&bytes).expect("header");

    assert_eq!(parse_header_arch(&bytes, &header).expect("arch"), None);
}

proptest! {
    #[test]
    fn property_parses_arbitrary_valid_headers(
        header_size in 104_u64..1_000_000_u64,
        attr_offset in any::<u64>(),
        attr_size in any::<u64>(),
        data_offset in any::<u64>(),
        data_size in any::<u64>(),
    ) {
        let bytes = header_bytes(
            "PERFILE2",
            header_size,
            attr_offset,
            attr_size,
            data_offset,
            data_size,
        );

        prop_assert_eq!(
            parse_header(&bytes).expect("valid header"),
            PerfHeader {
                header_size,
                attr_offset,
                attr_size,
                data_offset,
                data_size,
            }
        );
    }

    #[test]
    fn property_parses_feature_sections_for_any_set_bits(
        features in prop::collection::btree_set(0_u16..256_u16, 0..32),
    ) {
        let table_offset = 104_usize;
        let mut bytes = vec![0; table_offset + features.len() * 16];
        bytes[..104].copy_from_slice(&header_bytes("PERFILE2", 104, 128, 64, 104, 0));
        let mut expected = Vec::new();

        for (index, feature) in features.iter().copied().enumerate() {
            // adds_features bitmap starts at offset 72 (struct perf_file_header,
            // tools/perf/util/header.h).
            let word_offset = 72 + usize::from(feature / 64) * 8;
            let bit = 1_u64 << u32::from(feature % 64);
            let word = u64::from_le_bytes(
                bytes[word_offset..word_offset + 8]
                    .try_into()
                    .expect("word"),
            );
            put_u64(&mut bytes, word_offset, word | bit);

            let offset = 1_000_u64 + (index as u64) * 17;
            let size = 2_000_u64 + (index as u64) * 19;
            put_u64(&mut bytes, table_offset + index * 16, offset);
            put_u64(&mut bytes, table_offset + index * 16 + 8, size);
            expected.push(PerfFeatureSection {
                feature,
                offset,
                size,
            });
        }

        let header = parse_header(&bytes).expect("valid header");
        prop_assert_eq!(parse_feature_sections(&bytes, &header).expect("feature sections"), expected);
    }
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
