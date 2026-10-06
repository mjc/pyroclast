use proptest::prelude::*;
use pyroclast::perfdata::attrs::{PerfFileAttr, parse_file_attr_ids, parse_file_attrs};
use pyroclast::perfdata::header::PerfHeader;
use pyroclast::perfdata::samples::{PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_IP, PERF_SAMPLE_TID};

#[test]
fn parses_sample_type_from_file_attr_section() {
    let sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN;
    let bytes = perfdata_with_attrs([file_attr_bytes(sample_type, 512, 24)]);
    let header = PerfHeader {
        header_size: 104,
        attr_offset: 104,
        attr_size: 144,
        data_offset: 248,
        data_size: 0,
    };

    let attrs = parse_file_attrs(&bytes, header).expect("attrs");

    assert_eq!(
        attrs,
        vec![PerfFileAttr {
            event_type: 0,
            config: 0,
            sample_period: 0,
            sample_type,
            read_format: 0,
            branch_sample_type: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
            sample_id_all: false,
            defer_callchain: false,
            ids_offset: 512,
            ids_size: 24,
        }]
    );
}

#[test]
fn parses_branch_sample_type_from_file_attr_section() {
    let mut attr = file_attr_bytes(PERF_SAMPLE_IP, 512, 24);
    put_u64(&mut attr, 72, 1 << 17);
    let bytes = perfdata_with_attrs([attr]);
    let header = PerfHeader {
        header_size: 104,
        attr_offset: 104,
        attr_size: 144,
        data_offset: 248,
        data_size: 0,
    };

    let attrs = parse_file_attrs(&bytes, header).expect("attrs");

    assert_eq!(attrs[0].branch_sample_type, 1 << 17);
}

#[test]
fn defer_callchain_flag_is_preserved_in_parsed_file_attrs() {
    // include/uapi/linux/perf_event.h:418-469 puts defer_callchain at bit 38
    // of the flags word at offset 40. tools/perf/util/evsel.c:3391 uses it
    // to gate deferred-cookie recognition, so parsing must retain the flag.
    let disabled = file_attr_bytes(PERF_SAMPLE_IP, 512, 24);
    let mut enabled = disabled;
    put_u64(&mut enabled, 40, 1_u64 << 38);
    let bytes = perfdata_with_attrs([disabled, enabled]);
    let header = PerfHeader {
        header_size: 104,
        attr_offset: 104,
        attr_size: 288,
        data_offset: 392,
        data_size: 0,
    };

    let attrs = parse_file_attrs(&bytes, header).expect("attrs");

    assert_ne!(
        attrs[0], attrs[1],
        "parsing discarded the defer_callchain flag at bit 38"
    );
    assert!(!attrs[0].defer_callchain);
    assert!(attrs[1].defer_callchain);
}

#[test]
fn parses_enabled_defer_callchain_from_flags_bit_38() {
    // include/uapi/linux/perf_event.h:467, tools/perf/util/evsel.c:3391.
    for attr_size in [48, 64, 128] {
        let mut attr = file_attr_bytes_with_attr_size(PERF_SAMPLE_IP, attr_size, 512, 24);
        put_u64(&mut attr, 40, 1_u64 << 38);

        let parsed = parse_single_file_attr(attr);

        assert!(parsed.defer_callchain, "attr size {attr_size}");
        assert!(!parsed.sample_id_all);
        assert_eq!(parsed.ids_offset, 512);
        assert_eq!(parsed.ids_size, 24);
    }
}

#[test]
fn leaves_defer_callchain_disabled_when_bit_38_is_clear() {
    // sigtrap (37), defer_output (39), and sample_id_all (18) are independent.
    for flags in [0, 1_u64 << 37, 1_u64 << 39, 1_u64 << 18, !(1_u64 << 38)] {
        let mut attr = file_attr_bytes_with_attr_size(PERF_SAMPLE_IP, 128, 512, 24);
        put_u64(&mut attr, 40, flags);

        let parsed = parse_single_file_attr(attr);

        assert!(!parsed.defer_callchain, "flags {flags:#x}");
        assert_eq!(parsed.sample_id_all, flags & (1_u64 << 18) != 0);
    }
}

#[test]
fn defaults_defer_callchain_to_false_when_attr_has_no_complete_flags_word() {
    // A short attr must not read flags from its following ID section descriptor.
    for attr_size in [32, 40, 47] {
        let mut attr =
            file_attr_bytes_with_attr_size(PERF_SAMPLE_IP, attr_size, 1_u64 << 38, 1_u64 << 38);
        if attr_size == 47 {
            attr[40..47].copy_from_slice(&(1_u64 << 38).to_le_bytes()[..7]);
        }

        let parsed = parse_single_file_attr(attr);

        assert!(!parsed.defer_callchain, "attr size {attr_size}");
        assert!(!parsed.sample_id_all);
        assert_eq!(parsed.ids_offset, 1_u64 << 38);
        assert_eq!(parsed.ids_size, 1_u64 << 38);
    }
}

#[test]
fn defaults_newer_attr_fields_when_file_attr_is_older() {
    let bytes = perfdata_with_old_attr(file_attr_bytes_with_attr_size(PERF_SAMPLE_IP, 64, 512, 24));
    let header = PerfHeader {
        header_size: 104,
        attr_offset: 104,
        attr_size: 80,
        data_offset: 184,
        data_size: 0,
    };

    let attrs = parse_file_attrs(&bytes, header).expect("attrs");

    assert_eq!(attrs[0].sample_type, PERF_SAMPLE_IP);
    assert_eq!(attrs[0].branch_sample_type, 0);
    assert_eq!(attrs[0].sample_regs_user, 0);
    assert_eq!(attrs[0].sample_regs_intr, 0);
    assert!(!attrs[0].defer_callchain);
}

#[test]
fn parses_mixed_file_attr_sizes() {
    let mut bytes = vec![0; 104];
    bytes.extend(file_attr_bytes_with_attr_size(PERF_SAMPLE_IP, 64, 512, 24));
    bytes.extend(file_attr_bytes(PERF_SAMPLE_TID, 1024, 8));
    let header = PerfHeader {
        header_size: 104,
        attr_offset: 104,
        attr_size: 224,
        data_offset: 328,
        data_size: 0,
    };

    let attrs = parse_file_attrs(&bytes, header).expect("attrs");

    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[0].sample_type, PERF_SAMPLE_IP);
    assert_eq!(attrs[0].ids_offset, 512);
    assert_eq!(attrs[1].sample_type, PERF_SAMPLE_TID);
    assert_eq!(attrs[1].ids_offset, 1024);
}

#[test]
fn parses_file_attr_id_lists() {
    let mut bytes = vec![0; 256];
    bytes[200..208].copy_from_slice(&11u64.to_le_bytes());
    bytes[208..216].copy_from_slice(&22u64.to_le_bytes());
    let attr = PerfFileAttr {
        event_type: 0,
        config: 0,
        sample_period: 0,
        sample_type: PERF_SAMPLE_IP,
        read_format: 0,
        branch_sample_type: 0,
        sample_regs_user: 0,
        sample_regs_intr: 0,
        sample_id_all: false,
        defer_callchain: false,
        ids_offset: 200,
        ids_size: 16,
    };

    let ids = parse_file_attr_ids(&bytes, &attr).expect("ids");

    assert_eq!(ids, vec![11, 22]);
}

#[test]
fn parses_sample_register_masks_from_file_attr_section() {
    let mut attr = file_attr_bytes(PERF_SAMPLE_IP, 512, 24);
    put_u64(&mut attr, 80, 0b101);
    put_u64(&mut attr, 96, 0b11);
    let bytes = perfdata_with_attrs([attr]);
    let header = PerfHeader {
        header_size: 104,
        attr_offset: 104,
        attr_size: 144,
        data_offset: 248,
        data_size: 0,
    };

    let attrs = parse_file_attrs(&bytes, header).expect("attrs");

    assert_eq!(attrs[0].sample_regs_user, 0b101);
    assert_eq!(attrs[0].sample_regs_intr, 0b11);
}

fn perfdata_with_attrs<const N: usize>(attrs: [[u8; 144]; N]) -> Vec<u8> {
    let mut bytes = vec![0; 104];
    for attr in attrs {
        bytes.extend(attr);
    }
    bytes
}

fn perfdata_with_old_attr(attr: Vec<u8>) -> Vec<u8> {
    let mut bytes = vec![0; 104];
    bytes.extend(attr);
    bytes
}

fn parse_single_file_attr(attr: Vec<u8>) -> PerfFileAttr {
    let attr_size = u64::try_from(attr.len()).expect("attr size fits u64");
    let header = PerfHeader {
        header_size: 104,
        attr_offset: 104,
        attr_size,
        data_offset: 104 + attr_size,
        data_size: 0,
    };
    let bytes = perfdata_with_old_attr(attr);
    let mut attrs = parse_file_attrs(&bytes, header).expect("attrs");
    assert_eq!(attrs.len(), 1);
    attrs.pop().expect("one attr")
}

fn file_attr_bytes(sample_type: u64, ids_offset: u64, ids_size: u64) -> [u8; 144] {
    let mut bytes = [0; 144];
    put_u32(&mut bytes, 4, 128);
    put_u64(&mut bytes, 24, sample_type);
    put_u64(&mut bytes, 128, ids_offset);
    put_u64(&mut bytes, 136, ids_size);
    bytes
}

fn file_attr_bytes_with_attr_size(
    sample_type: u64,
    attr_size: usize,
    ids_offset: u64,
    ids_size: u64,
) -> Vec<u8> {
    let mut bytes = vec![0; attr_size + 16];
    put_u32(
        &mut bytes,
        4,
        u32::try_from(attr_size).expect("attr size fits u32"),
    );
    put_u64(&mut bytes, 24, sample_type);
    put_u64(&mut bytes, attr_size, ids_offset);
    put_u64(&mut bytes, attr_size + 8, ids_size);
    bytes
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

proptest! {
    #[test]
    fn property_parses_file_attr_fields_for_any_record(
        sample_type in any::<u64>(),
        sample_period in any::<u64>(),
        read_format in any::<u64>(),
        branch_sample_type in any::<u64>(),
        sample_regs_user in any::<u64>(),
        sample_regs_intr in any::<u64>(),
        sample_id_all in any::<bool>(),
        defer_callchain in any::<bool>(),
        ids_offset in any::<u64>(),
        ids_size in any::<u64>(),
    ) {
        let mut attr = file_attr_bytes(sample_type, ids_offset, ids_size);
        put_u64(&mut attr, 16, sample_period);
        put_u64(&mut attr, 32, read_format);
        put_u64(
            &mut attr,
            40,
            (if sample_id_all { 1 << 18 } else { 0 })
                | (if defer_callchain { 1 << 38 } else { 0 }),
        );
        put_u64(&mut attr, 72, branch_sample_type);
        put_u64(&mut attr, 80, sample_regs_user);
        put_u64(&mut attr, 96, sample_regs_intr);
        let bytes = perfdata_with_attrs([attr]);
        let header = PerfHeader {
            header_size: 104,
            attr_offset: 104,
            attr_size: 144,
            data_offset: 248,
            data_size: 0,
        };

        prop_assert_eq!(
            parse_file_attrs(&bytes, header).expect("attrs"),
            vec![PerfFileAttr {
                event_type: 0,
                config: 0,
                sample_period,
                sample_type,
                read_format,
                branch_sample_type,
                sample_regs_user,
                sample_regs_intr,
                sample_id_all,
                defer_callchain,
                ids_offset,
                ids_size,
            }]
        );
    }

    #[test]
    fn property_parses_any_u64_id_list(ids in prop::collection::vec(any::<u64>(), 0..32)) {
        let mut bytes = vec![0; 32 + ids.len() * 8];
        for (index, id) in ids.iter().enumerate() {
            bytes[32 + index * 8..32 + (index + 1) * 8].copy_from_slice(&id.to_le_bytes());
        }
        let attr = PerfFileAttr {
            event_type: 0,
            config: 0,
            sample_period: 0,
            sample_type: PERF_SAMPLE_IP,
            read_format: 0,
            branch_sample_type: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
            sample_id_all: false,
            defer_callchain: false,
            ids_offset: 32,
            ids_size: (ids.len() * 8) as u64,
        };

        prop_assert_eq!(parse_file_attr_ids(&bytes, &attr).expect("ids"), ids);
    }
}
