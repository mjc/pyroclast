use pyroclast::perfdata::mappings::{MmapTable, ResolvedMapping};
use pyroclast::perfdata::records::{Mmap2Record, MmapRecord};
use pyroclast::symbols::KernelRelocation;

#[test]
fn resolves_user_ip_to_mapping_relative_address() {
    let mut table = MmapTable::default();
    table.insert_mmap(MmapRecord {
        pid: 42,
        tid: 42,
        start: 0x1000,
        len: 0x200,
        pgoff: 0x40,
        path: "/bin/app".to_string(),
    });

    assert_eq!(
        table.resolve(42, 0x1010),
        Some(ResolvedMapping {
            path: "/bin/app".to_string(),
            relative_address: 0x50,
            kernel_relocation: None,
        })
    );
}

#[test]
fn prefers_most_specific_mapping_for_overlapping_ranges() {
    let mut table = MmapTable::default();
    table.insert_mmap(MmapRecord {
        pid: 42,
        tid: 42,
        start: 0x1000,
        len: 0x1000,
        pgoff: 0,
        path: "/bin/app".to_string(),
    });
    table.insert_mmap2(Mmap2Record {
        pid: 42,
        tid: 42,
        start: 0x1800,
        len: 0x100,
        pgoff: 0x20,
        major: 8,
        minor: 1,
        inode: 99,
        inode_generation: 7,
        prot: 5,
        flags: 2,
        path: "/bin/plugin.so".to_string(),
    });

    assert_eq!(
        table.resolve(42, 0x1810),
        Some(ResolvedMapping {
            path: "/bin/plugin.so".to_string(),
            relative_address: 0x30,
            kernel_relocation: None,
        })
    );
}

#[test]
fn resolves_wildcard_pid_kernel_mapping() {
    let mut table = MmapTable::default();
    table.insert_mmap(MmapRecord {
        pid: u32::MAX,
        tid: u32::MAX,
        start: 0xffff_ffff_8800_0000,
        len: 0x2000,
        pgoff: 0,
        path: "[kernel.kallsyms]".to_string(),
    });

    assert_eq!(
        table.resolve(42, 0xffff_ffff_8800_0010),
        Some(ResolvedMapping {
            path: "[kernel.kallsyms]".to_string(),
            relative_address: 0xffff_ffff_8800_0010,
            kernel_relocation: None,
        })
    );
}

#[test]
fn resolves_kernel_relocation_from_suffixed_mapping_name() {
    let mut table = MmapTable::default();
    table.insert_mmap(MmapRecord {
        pid: u32::MAX,
        tid: u32::MAX,
        start: 0xffff_ffff_8800_0000,
        len: 0x2000,
        pgoff: 0xffff_ffff_8800_0000,
        path: "[kernel.kallsyms]_text".to_string(),
    });

    assert_eq!(
        table.resolve(42, 0xffff_ffff_8800_1280),
        Some(ResolvedMapping {
            path: "[kernel.kallsyms]_text".to_string(),
            relative_address: 0xffff_ffff_8800_1280,
            kernel_relocation: Some(KernelRelocation {
                reference_symbol: "_text".to_string(),
                recorded_reference_address: 0xffff_ffff_8800_0000,
            }),
        })
    );
}

#[test]
fn does_not_resolve_other_pids_or_out_of_range_ips() {
    let mut table = MmapTable::default();
    table.insert_mmap(MmapRecord {
        pid: 42,
        tid: 42,
        start: 0x1000,
        len: 0x200,
        pgoff: 0,
        path: "/bin/app".to_string(),
    });

    assert_eq!(table.resolve(41, 0x1010), None);
    assert_eq!(table.resolve(42, 0x1200), None);
}
