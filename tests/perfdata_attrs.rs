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
            sample_type,
            read_format: 0,
            branch_sample_type: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
            sample_id_all: false,
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
        sample_type: PERF_SAMPLE_IP,
        read_format: 0,
        branch_sample_type: 0,
        sample_regs_user: 0,
        sample_regs_intr: 0,
        sample_id_all: false,
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
        read_format in any::<u64>(),
        branch_sample_type in any::<u64>(),
        sample_regs_user in any::<u64>(),
        sample_regs_intr in any::<u64>(),
        sample_id_all in any::<bool>(),
        ids_offset in any::<u64>(),
        ids_size in any::<u64>(),
    ) {
        let mut attr = file_attr_bytes(sample_type, ids_offset, ids_size);
        put_u64(&mut attr, 32, read_format);
        put_u64(
            &mut attr,
            40,
            if sample_id_all { 1 << 18 } else { 0 },
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
                sample_type,
                read_format,
                branch_sample_type,
                sample_regs_user,
                sample_regs_intr,
                sample_id_all,
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
            sample_type: PERF_SAMPLE_IP,
            read_format: 0,
            branch_sample_type: 0,
            sample_regs_user: 0,
            sample_regs_intr: 0,
            sample_id_all: false,
            ids_offset: 32,
            ids_size: (ids.len() * 8) as u64,
        };

        prop_assert_eq!(parse_file_attr_ids(&bytes, &attr).expect("ids"), ids);
    }
}
