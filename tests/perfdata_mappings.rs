use std::os::unix::fs::MetadataExt;

use proptest::prelude::*;
use pyroclast::perfdata::mappings::{
    FileIdentity, MmapTable, ResolvedMapping, file_matches_recorded_identity,
};
use pyroclast::perfdata::records::{Mmap2BuildIdRecord, Mmap2Record, MmapRecord};
use pyroclast::symbols::KernelRelocation;

#[derive(Clone, Debug)]
struct OverlapMappingCase {
    pid: u32,
    outer_start: u64,
    outer_len: u64,
    inner_start: u64,
    inner_len: u64,
    outer_pgoff: u64,
    inner_pgoff: u64,
    ip: u64,
    ip_offset: u64,
}

fn overlap_mapping_case() -> impl Strategy<Value = OverlapMappingCase> {
    (
        1_u32..u32::MAX,
        0x1000_u64..0x0001_0000_0000_u64,
        2_u64..0x3000,
        0_u64..0x0010_0000,
        0_u64..0x0010_0000,
    )
        .prop_flat_map(|(pid, outer_start, outer_len, outer_pgoff, inner_pgoff)| {
            (
                Just(pid),
                Just(outer_start),
                Just(outer_len),
                Just(outer_pgoff),
                Just(inner_pgoff),
                1_u64..outer_len,
            )
        })
        .prop_flat_map(
            |(pid, outer_start, outer_len, outer_pgoff, inner_pgoff, inner_offset)| {
                (
                    Just(pid),
                    Just(outer_start),
                    Just(outer_len),
                    Just(outer_pgoff),
                    Just(inner_pgoff),
                    Just(inner_offset),
                    1_u64..(outer_len - inner_offset + 1),
                )
            },
        )
        .prop_flat_map(
            |(pid, outer_start, outer_len, outer_pgoff, inner_pgoff, inner_offset, inner_len)| {
                (
                    Just(pid),
                    Just(outer_start),
                    Just(outer_len),
                    Just(outer_pgoff),
                    Just(inner_pgoff),
                    Just(inner_offset),
                    Just(inner_len),
                    0_u64..inner_len,
                )
            },
        )
        .prop_map(
            |(
                pid,
                outer_start,
                outer_len,
                outer_pgoff,
                inner_pgoff,
                inner_offset,
                inner_len,
                ip_offset,
            )| OverlapMappingCase {
                pid,
                outer_start,
                outer_len,
                inner_start: outer_start + inner_offset,
                inner_len,
                outer_pgoff,
                inner_pgoff,
                ip: outer_start + inner_offset + ip_offset,
                ip_offset,
            },
        )
}

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
    assert!(table.has_mapping_for_pid(42, 0x1010));
    assert_eq!(table.mapping_path(42, 0x1010), Some("/bin/app"));
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
fn resolves_perf_split_executable_mapping_over_initial_read_mapping_like_perf_maps_fixup() {
    let mut table = MmapTable::default();
    table.insert_mmap2(Mmap2Record {
        pid: 2_764_143,
        tid: 2_764_143,
        start: 0x5555_5555_4000,
        len: 0x002b_e000,
        pgoff: 0,
        major: 0,
        minor: 0x61,
        inode: 716_299,
        inode_generation: 20_005_098,
        prot: 1,
        flags: 2,
        path: "/home/mjc/projects/pyroclast/target/profiling/pyroclast".to_string(),
    });
    table.insert_mmap2(Mmap2Record {
        pid: 2_764_143,
        tid: 2_764_143,
        start: 0x5555_555d_6000,
        len: 0x0022_b000,
        pgoff: 0x0008_1000,
        major: 0,
        minor: 0x61,
        inode: 716_299,
        inode_generation: 20_005_098,
        prot: 5,
        flags: 2,
        path: "/home/mjc/projects/pyroclast/target/profiling/pyroclast".to_string(),
    });

    assert_eq!(
        table.resolve(2_764_143, 0x5555_5567_66de),
        Some(ResolvedMapping {
            path: "/home/mjc/projects/pyroclast/target/profiling/pyroclast".to_string(),
            relative_address: 0x0012_16de,
            build_id: None,
            file_identity: Some(FileIdentity {
                major: 0,
                minor: 0x61,
                inode: 716_299,
                inode_generation: 20_005_098,
            }),
            kernel_relocation: None,
        })
    );
}

#[test]
fn prefers_newer_mapping_when_it_broadly_overlaps_older_mapping_like_perf() {
    let mut table = MmapTable::default();
    table.insert_mmap(MmapRecord {
        pid: 42,
        tid: 42,
        start: 0x1800,
        len: 0x100,
        pgoff: 0x20,
        path: "/bin/old-plugin.so".to_string(),
    });
    table.insert_mmap(MmapRecord {
        pid: 42,
        tid: 42,
        start: 0x1000,
        len: 0x1000,
        pgoff: 0,
        path: "/bin/new-app".to_string(),
    });

    assert_eq!(
        table.resolve(42, 0x1810),
        Some(ResolvedMapping {
            path: "/bin/new-app".to_string(),
            relative_address: 0x810,
            build_id: None,
            file_identity: None,
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

// Mirrors the glibc MAJOR()/MINOR() decomposition perf uses when recording
// device numbers in PERF_RECORD_MMAP2 (tools/perf/util/dso.c __dso_id__cmp
// compares maj/min/ino together, never the inode alone).
fn device_major(device: u64) -> u32 {
    (((device >> 8) & 0xfff) | ((device >> 32) & !0xfff)) as u32
}

fn device_minor(device: u64) -> u32 {
    ((device & 0xff) | ((device >> 12) & !0xff)) as u32
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
            major: device_major(metadata.dev()),
            minor: device_minor(metadata.dev()),
            inode: metadata.ino(),
            inode_generation: 0,
        }
    ));
    assert!(!file_matches_recorded_identity(
        &path,
        FileIdentity {
            major: device_major(metadata.dev()),
            minor: device_minor(metadata.dev()),
            inode: metadata.ino() + 1,
            inode_generation: 0,
        }
    ));
}

#[test]
fn rejects_recorded_file_identity_on_a_different_device() {
    // perf's __dso_id__cmp compares maj/min/ino together; an inode number is
    // unique only within a filesystem, so a matching inode on a different
    // device must NOT be accepted as the same backing store.
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("app");
    std::fs::write(&path, b"binary").expect("write app");
    let metadata = std::fs::metadata(&path).expect("metadata");

    assert!(!file_matches_recorded_identity(
        &path,
        FileIdentity {
            major: device_major(metadata.dev()).wrapping_add(1),
            minor: device_minor(metadata.dev()),
            inode: metadata.ino(),
            inode_generation: 0,
        }
    ));
    assert!(!file_matches_recorded_identity(
        &path,
        FileIdentity {
            major: device_major(metadata.dev()),
            minor: device_minor(metadata.dev()).wrapping_add(1),
            inode: metadata.ino(),
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
    assert!(!table.has_mapping_for_pid(41, 0x1010));
    assert!(!table.has_mapping_for_pid(42, 0x1200));
    assert_eq!(table.mapping_path(41, 0x1010), None);
    assert_eq!(table.mapping_path(42, 0x1200), None);
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

#[test]
fn prefers_latest_mapping_when_ranges_share_the_same_start() {
    let mut table = MmapTable::default();
    table.insert_mmap(MmapRecord {
        pid: 42,
        tid: 42,
        start: 0x1000,
        len: 0x200,
        pgoff: 0,
        path: "/bin/old".to_string(),
    });
    table.insert_mmap(MmapRecord {
        pid: 42,
        tid: 42,
        start: 0x1000,
        len: 0x100,
        pgoff: 0x20,
        path: "/bin/new".to_string(),
    });

    assert_eq!(table.resolve(42, 0x1050).unwrap().path, "/bin/new");
    assert_eq!(table.resolve(42, 0x1150).unwrap().path, "/bin/old");
}

proptest! {
    #[test]
    fn property_resolve_matches_mapping_path_and_relative_address(
        pid in 1_u32..u32::MAX,
        start in 0x1000_u64..0x0001_0000_0000_u64,
        len in 1_u64..0x2000,
        pgoff in 0_u64..0x0010_0000,
        offset in 0_u64..0x2000,
    ) {
        prop_assume!(offset < len);

        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid,
            tid: pid,
            start,
            len,
            pgoff,
            path: "/usr/bin/test-app".to_string(),
        });

        let ip = start + offset;
        let resolved = table.resolve(pid, ip).expect("resolved mapping");
        let resolved_ref = table.resolve_ref(pid, ip).expect("resolved ref");

        prop_assert_eq!(resolved.path.as_str(), "/usr/bin/test-app");
        prop_assert_eq!(resolved.path.as_str(), resolved_ref.path);
        prop_assert_eq!(resolved.relative_address, pgoff + offset);
        prop_assert_eq!(resolved.relative_address, resolved_ref.relative_address);
        prop_assert_eq!(table.mapping_path(pid, ip), Some("/usr/bin/test-app"));
        prop_assert!(table.has_mapping_for_pid(pid, ip));
    }

    #[test]
    fn property_prefers_more_specific_mapping_in_overlap(
        case in overlap_mapping_case(),
    ) {
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid: case.pid,
            tid: case.pid,
            start: case.outer_start,
            len: case.outer_len,
            pgoff: case.outer_pgoff,
            path: "/usr/bin/base".to_string(),
        });
        table.insert_mmap(MmapRecord {
            pid: case.pid,
            tid: case.pid,
            start: case.inner_start,
            len: case.inner_len,
            pgoff: case.inner_pgoff,
            path: "/usr/lib/plugin.so".to_string(),
        });

        let resolved = table
            .resolve(case.pid, case.ip)
            .expect("resolved overlap");

        prop_assert_eq!(resolved.path.as_str(), "/usr/lib/plugin.so");
        prop_assert_eq!(resolved.relative_address, case.inner_pgoff + case.ip_offset);
    }

    #[test]
    fn property_prefers_latest_mapping_when_starts_match(
        pid in 1_u32..u32::MAX,
        start in 0x1000_u64..0x0001_0000_0000_u64,
        newer_len in 1_u64..0x2000,
        tail_len in 0_u64..0x1000,
        older_pgoff in 0_u64..0x0010_0000,
        newer_pgoff in 0_u64..0x0010_0000,
        offset in 0_u64..0x2000,
    ) {
        prop_assume!(offset < newer_len);

        let older_len = newer_len + tail_len;
        let mut table = MmapTable::default();
        table.insert_mmap(MmapRecord {
            pid,
            tid: pid,
            start,
            len: older_len,
            pgoff: older_pgoff,
            path: "/usr/bin/older".to_string(),
        });
        table.insert_mmap(MmapRecord {
            pid,
            tid: pid,
            start,
            len: newer_len,
            pgoff: newer_pgoff,
            path: "/usr/bin/newer".to_string(),
        });

        let ip = start + offset;
        let resolved = table.resolve(pid, ip).expect("resolved same-start mapping");
        prop_assert_eq!(resolved.path.as_str(), "/usr/bin/newer");
        prop_assert_eq!(resolved.relative_address, newer_pgoff + offset);

        if tail_len > 0 {
            let older_only_ip = start + newer_len;
            let older_only = table
                .resolve(pid, older_only_ip)
                .expect("older mapping still covers tail");
            prop_assert_eq!(older_only.path.as_str(), "/usr/bin/older");
            prop_assert_eq!(older_only.relative_address, older_pgoff + newer_len);
        }
    }
}
