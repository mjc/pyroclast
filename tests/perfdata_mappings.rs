use std::os::unix::fs::MetadataExt;

use pyroclast::perfdata::mappings::{
    FileIdentity, MmapTable, ResolvedMapping, file_matches_recorded_identity,
};
use pyroclast::perfdata::records::{Mmap2BuildIdRecord, Mmap2Record, MmapRecord};
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
            build_id: None,
            file_identity: None,
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
            build_id: None,
            file_identity: Some(FileIdentity {
                major: 8,
                minor: 1,
                inode: 99,
                inode_generation: 7,
            }),
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
            build_id: None,
            file_identity: None,
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
            build_id: None,
            file_identity: None,
            kernel_relocation: Some(KernelRelocation {
                reference_symbol: "_text".to_string(),
                recorded_reference_address: 0xffff_ffff_8800_0000,
            }),
        })
    );
}

#[test]
fn resolves_kernel_module_mapping_as_absolute_kernel_address() {
    let mut table = MmapTable::default();
    table.insert_mmap(MmapRecord {
        pid: u32::MAX,
        tid: u32::MAX,
        start: 0xffff_ffff_c000_0000,
        len: 0x2000,
        pgoff: 0,
        path: "[zfs]".to_string(),
    });

    assert_eq!(
        table.resolve(42, 0xffff_ffff_c000_0123),
        Some(ResolvedMapping {
            path: "[zfs]".to_string(),
            relative_address: 0xffff_ffff_c000_0123,
            build_id: None,
            file_identity: None,
            kernel_relocation: None,
        })
    );
}

#[test]
fn resolves_build_id_from_mmap2_build_id_mapping() {
    let mut table = MmapTable::default();
    table.insert_mmap2_build_id(Mmap2BuildIdRecord {
        pid: 42,
        tid: 42,
        start: 0x1000,
        len: 0x200,
        pgoff: 0x40,
        build_id_size: 4,
        build_id: vec![0xaa, 0xbb, 0xcc, 0xdd],
        prot: 5,
        flags: 2,
        path: "[igb]".to_string(),
    });

    assert_eq!(
        table.resolve(42, 0x1010),
        Some(ResolvedMapping {
            path: "[igb]".to_string(),
            relative_address: 0x50,
            build_id: Some(vec![0xaa, 0xbb, 0xcc, 0xdd]),
            file_identity: None,
            kernel_relocation: None,
        })
    );
}

#[test]
fn resolves_file_identity_from_mmap2_mapping() {
    let mut table = MmapTable::default();
    table.insert_mmap2(Mmap2Record {
        pid: 42,
        tid: 42,
        start: 0x1000,
        len: 0x200,
        pgoff: 0x40,
        major: 8,
        minor: 1,
        inode: 99,
        inode_generation: 7,
        prot: 5,
        flags: 2,
        path: "/bin/app".to_string(),
    });

    assert_eq!(
        table.resolve(42, 0x1010).unwrap().file_identity,
        Some(FileIdentity {
            major: 8,
            minor: 1,
            inode: 99,
            inode_generation: 7,
        })
    );
}

#[test]
fn compares_recorded_file_identity_with_current_path() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("app");
    std::fs::write(&path, b"binary").expect("write app");
    let metadata = std::fs::metadata(&path).expect("metadata");

    assert!(file_matches_recorded_identity(
        &path,
        FileIdentity {
            major: 0,
            minor: 0,
            inode: metadata.ino(),
            inode_generation: 0,
        }
    ));
    assert!(!file_matches_recorded_identity(
        &path,
        FileIdentity {
            major: 0,
            minor: 0,
            inode: metadata.ino() + 1,
            inode_generation: 0,
        }
    ));
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

#[test]
fn exposes_user_mappings_for_unwind_module_loading() {
    let mut table = MmapTable::default();
    table.insert_mmap(MmapRecord {
        pid: 42,
        tid: 42,
        start: 0x1000,
        len: 0x200,
        pgoff: 0,
        path: "/bin/app".to_string(),
    });
    table.insert_mmap(MmapRecord {
        pid: u32::MAX,
        tid: u32::MAX,
        start: 0xffff_ffff_8800_0000,
        len: 0x2000,
        pgoff: 0,
        path: "[kernel.kallsyms]".to_string(),
    });

    let mappings = table.user_mappings().collect::<Vec<_>>();

    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].pid, 42);
    assert_eq!(mappings[0].start, 0x1000);
    assert_eq!(mappings[0].len, 0x200);
    assert_eq!(mappings[0].pgoff, 0);
    assert_eq!(mappings[0].path, "/bin/app");
}

#[test]
fn tracks_executable_mappings_without_rescanning_every_lookup() {
    let mut table = MmapTable::default();
    table.insert_mmap2(Mmap2Record {
        pid: 42,
        tid: 42,
        start: 0x1000,
        len: 0x200,
        pgoff: 0,
        major: 8,
        minor: 1,
        inode: 99,
        inode_generation: 7,
        prot: 0,
        flags: 2,
        path: "/tmp/not-exec".to_string(),
    });
    table.insert_mmap2(Mmap2Record {
        pid: u32::MAX,
        tid: u32::MAX,
        start: 0xffff_ffff_8800_0000,
        len: 0x2000,
        pgoff: 0,
        major: 0,
        minor: 0,
        inode: 0,
        inode_generation: 0,
        prot: 5,
        flags: 2,
        path: "[kernel.kallsyms]".to_string(),
    });

    assert!(table.has_mappings_for_pid(42));
    assert!(table.has_mappings_for_pid(7));
    assert!(table.has_executable_mappings_for_pid(42));
    assert!(table.has_executable_mappings_for_pid(7));
}

#[test]
fn uses_most_specific_mapping_for_non_executable_checks() {
    let mut table = MmapTable::default();
    table.insert_mmap2(Mmap2Record {
        pid: 42,
        tid: 42,
        start: 0x1000,
        len: 0x1000,
        pgoff: 0,
        major: 8,
        minor: 1,
        inode: 99,
        inode_generation: 7,
        prot: 5,
        flags: 2,
        path: "/bin/app".to_string(),
    });
    table.insert_mmap2(Mmap2Record {
        pid: 42,
        tid: 42,
        start: 0x1800,
        len: 0x100,
        pgoff: 0,
        major: 8,
        minor: 1,
        inode: 100,
        inode_generation: 8,
        prot: 0,
        flags: 2,
        path: "/tmp/not-exec".to_string(),
    });

    assert!(!table.is_known_non_executable(42, 0x1400));
    assert!(table.is_known_non_executable(42, 0x1810));
}
