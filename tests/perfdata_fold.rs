// Only the linux-gated libc leaf test parses real objects.
#[cfg(target_os = "linux")]
use object::{Object as _, ObjectSegment as _, ObjectSymbol as _};
use proptest::prelude::*;
use pyroclast::perfdata::fold::{
    FoldOptions, fold_perfdata_callchains, fold_perfdata_callchains_with_options,
    fold_perfdata_callchains_with_symbols, fold_perfdata_file_with_options, summarize_perfdata,
};
use pyroclast::perfdata::mappings::FileIdentity;
use pyroclast::perfdata::records::{
    PERF_RECORD_FINISHED_ROUND, PERF_RECORD_FORK, PERF_RECORD_MISC_COMM_EXEC,
    PERF_RECORD_MISC_CPUMODE_KERNEL, PERF_RECORD_MISC_CPUMODE_USER,
};
use pyroclast::perfdata::samples::{
    PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_ID, PERF_SAMPLE_IDENTIFIER, PERF_SAMPLE_IP,
    PERF_SAMPLE_PERIOD, PERF_SAMPLE_REGS_USER, PERF_SAMPLE_STACK_USER, PERF_SAMPLE_TID,
    PERF_SAMPLE_TIME,
};
use pyroclast::symbols::{SymbolRequest, SymbolResolver};
use std::cell::RefCell;

fn render_unknown_folded_callchain(frames: &[u64], count: u64) -> String {
    if frames.is_empty() {
        return String::new();
    }

    let mut rendered = String::from(":12");
    for _ in frames.iter().rev() {
        rendered.push_str(";[unknown]");
    }
    rendered.push(' ');
    rendered.push_str(&count.to_string());
    rendered.push('\n');
    rendered
}

#[test]
fn summarizes_record_counts_and_comm_names() {
    let bytes = perfdata_with_records_and_attrs(
        [],
        [
            record_bytes(3, &comm_payload(1, 2, "sftp-s3")),
            record_bytes(
                1,
                &mmap_payload(1, 2, 0x1000, 0x2000, 0, "/usr/bin/sftp-s3"),
            ),
            record_bytes(
                10,
                &mmap2_payload(1, 2, 0x3000, 0x4000, 0, 5, "/usr/lib/libc.so"),
            ),
            record_bytes(9, b"sample"),
        ],
    );

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.total_records, 4);
    assert_eq!(summary.record_count(1), 1);
    assert_eq!(summary.record_count(3), 1);
    assert_eq!(summary.record_count(9), 1);
    assert_eq!(summary.record_count(10), 1);
    assert_eq!(summary.comms, vec!["sftp-s3"]);
    assert_eq!(summary.mmaps, vec!["/usr/bin/sftp-s3", "/usr/lib/libc.so"]);
}

#[test]
fn summarizes_lost_record_counts() {
    let bytes = perfdata_with_records_and_attrs(
        [],
        [
            record_bytes(2, &lost_payload(7, 10)),
            record_bytes(2, &lost_payload(8, 20)),
        ],
    );

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.record_count(2), 2);
    assert_eq!(summary.lost_records, 30);
}

#[test]
fn summarizes_lost_sample_record_counts() {
    let bytes = perfdata_with_records_and_attrs([], [record_bytes(13, &42u64.to_le_bytes())]);

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.record_count(13), 1);
    assert_eq!(summary.lost_records, 42);
}

#[test]
fn summarizes_sample_callchain_counts_using_file_attr_layout() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0x2000, 0x3000]),
        )],
    );

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.sample_stacks.len(), 1);
    assert_eq!(summary.sample_stacks[0].callchain, vec![0x2000, 0x3000]);
}

#[test]
fn summarizes_dwarf_user_stack_payloads() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            1 << 8,
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_user_stack(0x1000, 11, 12, [0x2000], 1, [0xaaaa], [1, 2, 3]),
        )],
    );

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.sample_stacks.len(), 1);
    assert_eq!(
        summary.sample_stacks[0].misc,
        PERF_RECORD_MISC_CPUMODE_KERNEL
    );
    assert_eq!(
        summary.sample_stacks[0].cpumode,
        PERF_RECORD_MISC_CPUMODE_KERNEL
    );
    assert!(summary.sample_stacks[0].has_user_stack);
    assert_eq!(summary.sample_stacks[0].user_register_count, 1);
    assert_eq!(summary.sample_stacks[0].user_register_ip, Some(0xaaaa));
    assert_eq!(summary.sample_stacks[0].user_stack_size, 3);
    assert_eq!(summary.sample_stacks[0].user_stack_dynamic_size, 3);
}

#[test]
fn keeps_unmapped_dwarf_user_stack_payloads_like_perf_libdw_ebl() {
    // perf machine.c attempts thread__resolve_callchain_unwind() whenever the
    // sample has user regs and a non-empty user stack. libdw
    // __report_module() succeeds with no DSO, and elfutils frame_unwind.c can
    // still fall back to x86_64_unwind() using frame pointers.
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes(
            9,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn folds_aarch64_dwarf_user_stack_with_frame_pointer_fallback_like_perf_libdw_ebl() {
    // perf record --call-graph dwarf on arm64 captures x0-x30, sp, pc. The
    // recording machine's HEADER_ARCH ("aarch64") tells the fold path to decode
    // PerfAarch64Regs (fp=29, lr=30, sp=31, pc=32) and use elfutils'
    // backends/aarch64_unwind.c frame-pointer fallback when no DSO/CFI covers
    // the sampled pc: the caller pc comes from lr (taking the perf pc-1
    // adjustment), and the walk ends on the zeroed next lr.
    let mask = (1_u64 << 29) | (1_u64 << 30) | (1_u64 << 31) | (1_u64 << 32);
    let bytes = perfdata_with_records_attrs_and_arch_feature(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            mask,
        )],
        [record_bytes(
            9,
            // Registers are in ascending perf-register order: fp, lr, sp, pc.
            // sp = 0x1000, fp = 0x1010: the fp chain record at fp+0 (next fp)
            // and fp+8 (next lr) are both zero, so the lr-derived caller is the
            // only unwound frame.
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [],
                1,
                [0x1010, 0x5000, 0x1000, 0x4000],
                [0_u8; 0x40],
            ),
        )],
        "aarch64",
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn drops_dwarf_user_stack_when_mapped_object_cannot_be_loaded_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/missing-app"),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn drops_dwarf_user_stack_but_keeps_kernel_callchain_when_object_cannot_be_loaded_like_perf_script()
{
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/missing-app"),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [
                        0xffff_ffff_ffff_fe00,
                        0xffff_ffff_8100_0000,
                        0xffff_ffff_8200_0000,
                    ],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn drops_dwarf_user_stack_when_current_object_is_missing_even_if_other_modules_loaded_like_perf_script()
 {
    let current_exe = std::env::current_exe().expect("current exe");
    let current_exe = current_exe.to_string_lossy();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x8000, 0x100, 0, current_exe.as_ref()),
            ),
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/missing-app"),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [
                        0xffff_ffff_ffff_fe00,
                        0xffff_ffff_8100_0000,
                        0xffff_ffff_8200_0000,
                    ],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn drops_dwarf_user_stack_when_current_mapping_replaces_broad_loaded_mapping_like_perf_script() {
    let current_exe = std::env::current_exe().expect("current exe");
    let current_exe = current_exe.to_string_lossy();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4000, 0x3000, 0, current_exe.as_ref()),
            ),
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4800, 0x1000, 0, "/tmp/missing-app"),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4900,
                    11,
                    12,
                    [
                        0xffff_ffff_ffff_fe00,
                        0xffff_ffff_8100_0000,
                        0xffff_ffff_8200_0000,
                    ],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4900],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x49, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn keeps_dwarf_user_stack_when_newer_mapping_overlaps_before_first_report_like_perf_script() {
    // perf's libdw module reporting is lazy: tools/perf/util/unwind-libdw.c
    // does not call report_module() until a sample enters the unwind path.
    // Overlapping MMAP records before that first report update the maps, but
    // there is no prior DWFL module yet for the later mapping to conflict with.
    let current_exe = std::env::current_exe().expect("current exe");
    let current_exe = current_exe.to_string_lossy();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4000, 0x1000, 0, current_exe.as_ref()),
            ),
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x4800, 0x1000, 0, current_exe.as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4900,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4900],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x49, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = format!(":12;[{}] 1\n", current_exe_file_name());

    assert_eq!(folded, expected);
}

#[test]
fn keeps_dwarf_user_stack_when_build_id_mapping_overlaps_before_first_report_like_perf_script() {
    // Same lazy report_module() rule as plain MMAP: a build-id-backed mapping
    // can only overlap a prior DWFL module after an earlier unwind report
    // populated that module.
    let current_exe = std::env::current_exe().expect("current exe");
    let current_exe = current_exe.to_string_lossy();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                23,
                &mmap2_build_id_payload(11, 11, 0x4000, 0x3000, 0, current_exe.as_ref()),
            ),
            record_bytes(
                23,
                &mmap2_build_id_payload(11, 11, 0x4800, 0x1000, 0x1000, current_exe.as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4900,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4900],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x49, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn keeps_dwarf_user_stack_when_header_build_id_mmap2_overlaps_before_first_report_like_perf_script()
{
    // Header FEATURE_BUILD_ID resolution also happens when the mapping is
    // reported to DWFL. Without a sample before the overlap, there is no prior
    // reported module to reject this mapping.
    let build_id = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90,
        0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
    ];
    let fixture = SyntheticX86_64Object::create();
    let current_exe = fixture.path_string();
    let bytes = perfdata_with_records_attrs_and_build_id_feature(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x4000, 0x3000, 0, 5, current_exe.as_ref()),
            ),
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x4800, 0x1000, 0x1000, 5, current_exe.as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4900,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4900],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x49, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
        &build_id_event_payload(u32::MAX, &build_id, current_exe.as_ref()),
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = format!(":12;[{}] 1\n", fixture.file_name());

    assert_eq!(folded, expected);
}

#[test]
fn folds_dwarf_user_stack_payloads_before_kernel_callchain_frames() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes(
            9,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [0x9000, 0xa000],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn keeps_unmapped_kernel_looking_user_unwind_frame_like_perf_libdw_entry() {
    // perf's libdw entry path reports unwind frames with
    // thread__find_symbol(..., PERF_RECORD_MISC_USER, ip). If that lookup finds
    // no DSO, __report_module() returns success and unwind_entry() later keeps
    // the unresolved frame unless hide_unresolved is set.
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes(
            9,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [0x9000],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0, 0, 0, 0x81, 0xff, 0xff, 0xff, 0xff,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;0xffffffff80ffffff;[unknown];[unknown] 1\n");
}

#[test]
fn keeps_dwarf_user_stack_payloads_when_kernel_callchain_has_user_context_marker() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes(
            9,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [
                    0xffff_ffff_ffff_fe00,
                    0xffff_ffff_8100_0000,
                    0xffff_ffff_8200_0000,
                ],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn keeps_dwarf_user_stack_payloads_when_kernel_callchain_has_no_user_context_marker() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_USER,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [
                    0xffff_ffff_ffff_ff80,
                    0xffff_ffff_8100_0000,
                    0xffff_ffff_8200_0000,
                ],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn keeps_dwarf_user_stack_payloads_for_kernel_samples_without_user_context_marker_like_perf_script()
{
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [
                    0xffff_ffff_ffff_ff80,
                    0xffff_ffff_8100_0000,
                    0xffff_ffff_8200_0000,
                ],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn keeps_recorded_user_frame_without_dwarf_callers_for_kernel_user_context_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [
                    0xffff_ffff_ffff_fe00,
                    0xffff_ffff_8100_0000,
                    0xffff_ffff_8200_0000,
                    0x4000,
                ],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn keeps_recorded_user_frame_without_dwarf_callers_for_kernel_user_frame_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [0xffff_ffff_8100_0000, 0xffff_ffff_8200_0000, 0x4000],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn keeps_recorded_user_frame_without_dwarf_callers_for_mixed_callchain_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_USER,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [0xffff_ffff_8100_0000, 0xffff_ffff_8200_0000, 0x4000],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn keeps_dwarf_user_stack_for_kernel_sample_without_kernel_callchain_like_perf_libdw_ebl() {
    // For ORDER_CALLEE, perf resolves the recorded callchain first and then
    // calls thread__resolve_callchain_unwind(); an empty kernel callchain does
    // not suppress the captured user-regs/user-stack unwind path.
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_user_stack(
                0x4000,
                11,
                12,
                [],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn skips_dwarf_unwind_when_perf_user_stack_dynamic_size_is_zero_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample_payload_with_zero_dynamic_user_stack(
                0x4000,
                11,
                12,
                [
                    0xffff_ffff_ffff_ff80,
                    0xffff_ffff_8100_0000,
                    0xffff_ffff_8200_0000,
                ],
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn limits_dwarf_unwind_to_perf_user_stack_dynamic_size_like_perf_script() {
    let mut sample = sample_payload(
        0x4000,
        11,
        12,
        [
            0xffff_ffff_ffff_ff80,
            0xffff_ffff_8100_0000,
            0xffff_ffff_8200_0000,
        ],
    );
    append_user_stack_payload(
        &mut sample,
        1,
        [0x7fff_0008, 0x7fff_0000, 0x4000],
        [
            0, 0, 0, 0, 0, 0, 0, 0, //
            0x40, 0, 0, 0, 0, 0, 0, 0, //
            0x34, 0x12, 0, 0, 0, 0, 0, 0,
        ],
        8,
    );
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes_with_misc(
            9,
            PERF_RECORD_MISC_CPUMODE_KERNEL,
            &sample,
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn keeps_current_ip_only_object_unwind_for_mapped_dwarf_user_stack_like_perf_libdw() {
    // elfutils dwfl_thread_getframes() invokes the callback for the initial
    // state before attempting to unwind callers. perf's frame_callback() then
    // calls entry(pc), so a single current-IP callback is a real frame, not
    // something to drop.
    let fixture = SyntheticX86_64Object::create();
    let current_exe = fixture.path_string();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0, 0x1000_0000, 0, current_exe.as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = format!(":12;[{}] 1\n", fixture.file_name());

    assert_eq!(folded, expected);
}

#[test]
fn keeps_current_ip_only_object_unwind_after_first_non_text_mapping_like_perf_libdw() {
    // perf reports the module selected by thread__find_symbol() for the
    // callback PC. If that report succeeds, entry() stores the current IP even
    // when no caller is recovered.
    let fixture = SyntheticX86_64Object::create();
    let current_exe = fixture.path_string();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x1000_0000, 0x1000, 0, current_exe.as_ref()),
            ),
            record_bytes(
                1,
                &mmap_payload(11, 11, 0x1000_1000, 0x1000, 0x1000, current_exe.as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x1000_1000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = format!(":12;[{}] 1\n", fixture.file_name());

    assert_eq!(folded, expected);
}

#[test]
fn keeps_current_ip_only_object_unwind_from_executable_mmap2_like_perf_libdw() {
    let fixture = SyntheticX86_64Object::create();
    let current_exe = fixture.path_string();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x1000_0000, 0x0040_0000, 0, 1, current_exe.as_ref()),
            ),
            record_bytes(
                10,
                &mmap2_payload(
                    11,
                    11,
                    0x1000_2000,
                    0x0020_0000,
                    0x1000,
                    5,
                    current_exe.as_ref(),
                ),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x1000_5000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x1000_5000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = format!(":12;[{}] 1\n", fixture.file_name());

    assert_eq!(folded, expected);
}

#[test]
fn keeps_current_ip_only_object_unwind_from_pid_specific_modules_like_perf_libdw() {
    let fixture = SyntheticX86_64Object::create();
    let current_exe = fixture.path_string();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x1000_0000, 0x30_0000, 0, 5, current_exe.as_ref()),
            ),
            record_bytes(
                10,
                &mmap2_payload(12, 12, 0x1000_1000, 0x30_0000, 0, 5, current_exe.as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x1000_5000,
                    12,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x1000_5000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = format!(":12;[{}] 1\n", fixture.file_name());

    assert_eq!(folded, expected);
}

/// Build a `--call-graph dwarf` x86_64 perf.data with a single sample over the
/// synthetic fixture: one MMAP covering `[0, 0x1000_0000)` and one user-stack
/// sample. `regs` are `[bp, sp, ip]` in perf's ascending register order
/// (RBP=6, RSP=7, IP=8).
fn x86_leaf_only_perfdata(fixture_path: &str, regs: [u64; 3], stack: [u8; 24]) -> Vec<u8> {
    perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0, 0x1000_0000, 0, fixture_path)),
            record_bytes(
                9,
                &sample_payload_with_user_stack(regs[2], 11, 12, [], 1, regs, stack),
            ),
        ],
    )
}

#[test]
fn emits_scenario_d_leaf_when_no_cfi_and_bp_below_sp_like_perf_libdw() {
    // gap-5gr scenario D: the sampled IP (0x4000) is reported into a module
    // but no .eh_frame FDE covers it (the fixture's only FDE is at [0x100,
    // 0x104)), and bp < sp so elfutils' x86_64 rbp fallback (`if (sp >= fp)
    // return false;`, backends/x86_64_unwind.c) can never advance. libdwfl
    // fires the initial-frame callback exactly once, so perf prints the single
    // leaf. bp=0x7ffe_ff00 < sp=0x7fff_0000.
    let fixture = SyntheticX86_64Object::create();
    let bytes = x86_leaf_only_perfdata(
        &fixture.path_string(),
        [0x7ffe_ff00, 0x7fff_0000, 0x4000],
        [
            0, 0, 0, 0, 0, 0, 0, 0, //
            0x40, 0, 0, 0, 0, 0, 0, 0, //
            0x34, 0x12, 0, 0, 0, 0, 0, 0,
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    assert_eq!(folded, format!(":12;[{}] 1\n", fixture.file_name()));
}

#[test]
fn does_not_take_leaf_only_path_when_bp_at_or_above_sp_is_fallback_territory_like_perf_libdw() {
    // bp >= sp is exactly when elfutils attempts the rbp fallback
    // (backends/x86_64_unwind.c only fails on the *final* `if (sp >= fp)`
    // guard), so the leaf-only predicate's register clause is false and this
    // sample is MustUnwind, not LeafOnly: framehop is authoritative and the
    // result is whatever it (and the elfutils fp fallback) recover, never a
    // truncated synthetic leaf. Here framehop yields the seeded IP and the
    // elfutils fallback only runs when framehop returned nothing, so the result
    // is the genuine single seed frame — identical bytes to case 1's output,
    // but reached through the full unwind path rather than leaf-only
    // truncation. (The companion unit test
    // `arch_fallback_cannot_advance_only_when_x86_bp_below_sp` pins the
    // predicate edge directly.)
    let fixture = SyntheticX86_64Object::create();
    let bytes = x86_leaf_only_perfdata(
        &fixture.path_string(),
        [0x7fff_0008, 0x7fff_0000, 0x4000],
        [
            0, 0, 0, 0, 0, 0, 0, 0, //
            0x40, 0, 0, 0, 0, 0, 0, 0, //
            0x34, 0x12, 0, 0, 0, 0, 0, 0,
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    assert_eq!(folded, format!(":12;[{}] 1\n", fixture.file_name()));
}

#[test]
fn does_not_truncate_to_leaf_when_cfi_covers_ip_like_perf_libdw() {
    // When an FDE covers the sampled IP, handle_cfi (libdwfl/frame_unwind.c)
    // may yield either PC_UNDEFINED (clean end-of-stack -> leaf only) or a
    // PC_SET caller, and the two are indistinguishable a priori — so this case
    // is MustUnwind and framehop is authoritative. The fixture's FDE covers
    // [0x100, 0x104); sample at vaddr 0x100 (mapping base 0) with bp < sp. The
    // leaf-only predicate's `!has_unwind_info_for_ip` clause is false here, so
    // no leaf-only truncation occurs and framehop's own result (the seed IP,
    // since the FDE has only nops and recovers no usable caller) stands.
    let fixture = SyntheticX86_64Object::create();
    let bytes = x86_leaf_only_perfdata(
        &fixture.path_string(),
        [0x7ffe_ff00, 0x7fff_0000, 0x100],
        [0_u8; 24],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    // CFI covers the IP, so this is not leaf-only; framehop runs and yields the
    // seed. The output is the single covered-IP frame produced by the real
    // unwind, NOT a leaf-only-truncated synthetic.
    assert_eq!(folded, format!(":12;[{}] 1\n", fixture.file_name()));
}

#[test]
fn skip_gate_is_byte_identical_to_running_the_full_unwind_for_leaf_only_samples() {
    // The gap-pkh skip gate is a pure optimization: classifying a leaf-only
    // sample and skipping framehop must produce the exact same folded output
    // as running framehop and letting the shared acceptance tail truncate to
    // the leaf. The fold path always takes the gated route, so we assert the
    // gated output equals the independently-known perf-correct single leaf.
    let fixture = SyntheticX86_64Object::create();
    let leaf_only = x86_leaf_only_perfdata(
        &fixture.path_string(),
        [0x7ffe_ff00, 0x7fff_0000, 0x4000],
        [
            0, 0, 0, 0, 0, 0, 0, 0, //
            0x40, 0, 0, 0, 0, 0, 0, 0, //
            0x34, 0x12, 0, 0, 0, 0, 0, 0,
        ],
    );

    let gated = fold_perfdata_callchains(&leaf_only).expect("folded");
    assert_eq!(gated, format!(":12;[{}] 1\n", fixture.file_name()));
}

#[test]
fn emits_scenario_d_leaf_on_aarch64_when_no_cfi_and_lr_is_zero_like_perf_libdw() {
    // gap-5gr scenario D on aarch64: pc (0x4000) is reported into a module with
    // no FDE covering it (the fixture's only FDE is [0x100, 0x104)) and lr == 0,
    // so elfutils' backends/aarch64_unwind.c fails before producing any caller
    // (`if (lr == 0 || !setfunc(...)) return false;`). libdwfl fires the
    // initial-frame callback exactly once, so perf prints the single leaf.
    // Registers are ascending fp(29), lr(30), sp(31), pc(32) = [fp, lr, sp, pc].
    let fixture = SyntheticAarch64Object::create();
    let mask = (1_u64 << 29) | (1_u64 << 30) | (1_u64 << 31) | (1_u64 << 32);
    let bytes = perfdata_with_records_attrs_and_arch_feature(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            mask,
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0, 0x1000_0000, 0, fixture.path_string().as_ref()),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    // fp = 0x1010, lr = 0 (ends the walk), sp = 0x1000, pc = 0x4000.
                    [0x1010, 0, 0x1000, 0x4000],
                    [0_u8; 0x40],
                ),
            ),
        ],
        "aarch64",
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    assert_eq!(folded, format!(":12;[{}] 1\n", fixture.file_name()));
}

#[cfg(target_os = "linux")]
#[test]
fn keeps_object_unwind_dso_leaf_when_framehop_only_returns_current_ip_like_perf_libdw() {
    let Some(libc) = process_libc_path() else {
        return;
    };
    let libc_bytes = std::fs::read(&libc).expect("read libc");
    let object = object::File::parse(&libc_bytes[..]).expect("parse libc");
    let Some(symbol) = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("__memcmp_avx2_movbe"))
    else {
        return;
    };
    let Some(segment) = object.segments().find(|segment| {
        let start = segment.address();
        let end = start.saturating_add(segment.size());
        start <= symbol.address() && symbol.address() < end
    }) else {
        return;
    };
    let base = 0x7000_0000_0000_u64;
    let pgoff = segment.file_range().0;
    let start = base + pgoff;
    let ip_offset = symbol.address() + 0xe0;
    let ip = base + ip_offset;
    let libc = libc.to_string_lossy();
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(
                    11,
                    11,
                    start,
                    segment.file_range().1,
                    pgoff,
                    5,
                    libc.as_ref(),
                ),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    ip,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, ip],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");
    let expected = ":12;[libc.so.6] 1\n".to_string();

    assert_eq!(folded, expected);
}

#[test]
fn drops_dwarf_user_stack_when_only_synthetic_mappings_exist_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/app")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn drops_dwarf_user_stack_frames_from_anon_mappings_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1200, 0x100, 0, "[anon]")),
            record_bytes(1, &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/app")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn drops_dwarf_user_stack_frames_from_slash_anon_mappings_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1200, 0x100, 0, "//anon")),
            record_bytes(1, &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/app")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn symbolized_fold_drops_dwarf_user_stack_when_object_cannot_be_loaded_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/app")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn drops_dwarf_user_stack_when_late_synthetic_mapping_cannot_be_loaded_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x4000, 0x100, 0, "/tmp/app")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        1, 0x80, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
            record_bytes(1, &mmap_payload(11, 11, 0x8000, 0x100, 0, "/tmp/lib")),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn drops_dwarf_user_stack_frames_from_known_non_executable_mappings() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x1200, 0x100, 0, 1, "/tmp/perf.data"),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [0x9000],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn keeps_dwarf_user_stack_frames_from_mapped_non_executable_libraries_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x1200, 0x100, 0, 1, "/lib/libc.so.6"),
            ),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [0x9000],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[libc.so.6];[unknown];[unknown] 1\n");
}

#[test]
fn drops_dwarf_user_stack_frames_from_stack_mappings_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(10, &mmap2_payload(11, 11, 0x1200, 0x100, 0, 1, "[stack]")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [0x9000],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn drops_dwarf_user_stack_frames_from_perf_data_file_mappings_without_prot() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1200, 0x100, 0, "/tmp/perf.data")),
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [0x9000],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn drops_perf_data_file_frames_when_mapping_arrives_after_sample() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [
            record_bytes(
                9,
                &sample_payload_with_user_stack(
                    0x4000,
                    11,
                    12,
                    [0x9000],
                    1,
                    [0x7fff_0008, 0x7fff_0000, 0x4000],
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, //
                        0x40, 0, 0, 0, 0, 0, 0, 0, //
                        0x34, 0x12, 0, 0, 0, 0, 0, 0,
                    ],
                ),
            ),
            record_bytes(1, &mmap_payload(11, 11, 0x1200, 0x100, 0, "/tmp/perf.data")),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown] 1\n");
}

#[test]
fn folds_callchains_in_flamegraph_root_to_leaf_order() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0x2000, 0x3000, 0x4000]),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn includes_record_context_when_sample_parsing_fails() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(9, &[0; 8])],
    );

    let error = summarize_perfdata(&bytes).expect_err("bad sample");

    assert!(error.contains("record type 9"));
    assert!(error.contains("offset"));
}

#[test]
fn folds_identical_sample_callchains_as_hex_frames() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000, 0x3000])),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000, 0x3000])),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x4000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n:12;[unknown];[unknown] 2\n");
}

#[test]
fn drops_perf_context_marker_frames_when_folding() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0xffff_ffff_ffff_fe00, 0x2000]),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn merges_deferred_user_callchains_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "pyroclast")),
            record_bytes(
                9,
                &sample_payload(
                    0x1000,
                    11,
                    12,
                    [0x2000, 0x3000, 0xffff_ffff_ffff_fd80, 0x4444],
                ),
            ),
            record_bytes(22, &callchain_deferred_payload(0x4444, [0x5000, 0x6000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown];[unknown];[unknown];[unknown] 1\n");
}

#[test]
fn does_not_merge_deferred_callchains_from_a_different_tid_like_perf_script() {
    let mut deferred = callchain_deferred_payload(0x4444, [0x5000, 0x6000]);
    deferred.extend(11_u32.to_le_bytes());
    deferred.extend(99_u32.to_le_bytes());
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_flags(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            1 << 18,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "pyroclast")),
            record_bytes(
                9,
                &sample_payload(
                    0x1000,
                    11,
                    12,
                    [0x2000, 0x3000, 0xffff_ffff_ffff_fd80, 0x4444],
                ),
            ),
            record_bytes(22, &deferred),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn flushes_unmatched_deferred_user_callchains_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "pyroclast")),
            record_bytes(
                9,
                &sample_payload(
                    0x1000,
                    11,
                    12,
                    [0x2000, 0x3000, 0xffff_ffff_ffff_fd80, 0x4444],
                ),
            ),
            record_bytes(22, &callchain_deferred_payload(0x5555, [0x5000, 0x6000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn omits_samples_that_have_no_frames_after_filtering_like_inferno() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0xffff_ffff_ffff_fe00]),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "");
}

#[test]
fn missing_sample_thread_comm_uses_perf_thread_placeholder() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "sftp-s3")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn prefixes_folded_stacks_with_sample_tid_comm_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "pyroclast")),
            record_bytes(
                3,
                &comm_payload_with_sample_id_time(11, 12, "perf-exec", 10),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 11, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "pyroclast;[unknown] 1\n");
}

#[test]
fn uses_comm_name_from_sample_time_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 11, "perf-exec")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000])),
            record_bytes(3, &comm_payload(11, 11, "pyroclast")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x3000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 2\n");
}

#[test]
fn thread_comm_takes_precedence_over_process_exec_comm_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                3,
                &comm_payload_with_sample_id_time(11, 12, "perf-exec", 10),
            ),
            record_bytes_with_misc(
                3,
                PERF_RECORD_MISC_COMM_EXEC,
                &comm_payload(11, 11, "pyroclast"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "perf-exec;[unknown] 1\n");
}

#[test]
fn process_exec_comm_is_fallback_when_sample_thread_has_no_comm() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes_with_misc(
                3,
                PERF_RECORD_MISC_COMM_EXEC,
                &comm_payload(11, 11, "pyroclast"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn applies_comm_records_by_perf_timestamp_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_flags(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            1 << 18,
        )],
        [
            record_bytes(
                3,
                &comm_payload_with_sample_id_time(11, 12, "perf-exec", 10),
            ),
            record_bytes(9, &sample_payload_with_time(0x1000, 11, 12, 30, [0x2000])),
            record_bytes_with_misc(
                3,
                PERF_RECORD_MISC_COMM_EXEC,
                &comm_payload_with_sample_id_time(11, 11, "pyroclast", 20),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "perf-exec;[unknown] 1\n");
}

#[test]
fn normalizes_comm_spaces_like_inferno() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 12, "V8 WorkerThread")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "V8_WorkerThread;[unknown] 1\n");
}

#[test]
fn can_fold_samples_weighted_by_period() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 7, [0x2000])),
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 3, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 10\n");
}

#[test]
fn folds_sample_ip_when_callchain_is_absent_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD,
            0,
            0,
        )],
        [
            record_bytes(
                9,
                &sample_payload_with_period_no_callchain(0x2000, 11, 12, 7),
            ),
            record_bytes(
                9,
                &sample_payload_with_period_no_callchain(0x2000, 11, 12, 3),
            ),
        ],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 10\n");
}

#[test]
fn emits_sample_ip_when_callchain_field_is_absent_even_with_dwarf_payload_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_regs(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER,
            (1 << 6) | (1 << 7) | (1 << 8),
        )],
        [record_bytes(
            9,
            &sample_payload_with_period_and_user_stack_no_callchain(
                0x4000,
                11,
                12,
                7,
                1,
                [0x7fff_0008, 0x7fff_0000, 0x4000],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, //
                    0x40, 0, 0, 0, 0, 0, 0, 0, //
                    0x34, 0x12, 0, 0, 0, 0, 0, 0,
                ],
            ),
        )],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 7\n");
}

#[test]
fn selects_sample_layout_by_identifier() {
    let attr1 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
        392,
        [111],
    );
    let attr2 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IDENTIFIER
            | PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        400,
        [222],
    );
    let bytes = perfdata_with_attrs_ids_and_records(
        [attr1, attr2],
        [111, 222],
        [record_bytes(
            9,
            &sample_payload_with_identifier_and_period(222, 0x1000, 11, 12, 7, [0x2000]),
        )],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 7\n");
}

#[test]
fn selects_sample_layout_by_id_field() {
    let attr1 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ID | PERF_SAMPLE_CALLCHAIN,
        392,
        [111],
    );
    let attr2 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_ID
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        400,
        [222],
    );
    let bytes = perfdata_with_attrs_ids_and_records(
        [attr1, attr2],
        [111, 222],
        [record_bytes(
            9,
            &sample_payload_with_id_and_period(0x1000, 11, 12, 222, 7, [0x2000]),
        )],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 7\n");
}

#[test]
fn folds_samples_from_multiple_attrs_when_generated_perf_script_event_name_matches_inferno_filter()
{
    let attr1 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IDENTIFIER
            | PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        392,
        [111],
    );
    let attr2 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IDENTIFIER
            | PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        400,
        [222],
    );
    let bytes = perfdata_with_attrs_ids_and_records(
        [attr1, attr2],
        [111, 222],
        [
            record_bytes(
                9,
                &sample_payload_with_identifier_and_period(222, 0x1000, 11, 12, 2, [0x2222]),
            ),
            record_bytes(
                9,
                &sample_payload_with_identifier_and_period(111, 0x1000, 11, 12, 1, [0x1111]),
            ),
        ],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 3\n");
}

#[test]
fn folds_perfdata_from_file_path() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 7, [0x2000])),
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 3, [0x2000])),
        ],
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded = fold_perfdata_file_with_options(
        &perfdata,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 10\n");
}

#[test]
fn file_path_folding_applies_late_untimed_mmaps_before_timed_samples_like_global_sort() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let mut records = Vec::new();
    for _ in 0..10_000 {
        records.push(record_bytes(
            9,
            &sample_payload_with_time(0x1000, 11, 12, 30, [0x2000]),
        ));
    }
    records.push(record_bytes(
        1,
        &mmap_payload(11, 11, 0x2000, 0x100, 0, "/bin/app"),
    ));
    let bytes = perfdata_with_records_and_attrs_vec(
        vec![file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        records,
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded =
        fold_perfdata_file_with_options(&perfdata, FoldOptions::default()).expect("folded");

    assert_eq!(folded, ":12;[app] 10000\n");
}

#[test]
fn file_path_folding_uses_finished_round_as_perf_ordered_event_watermark() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload_with_time(0x1000, 11, 12, 30, [0x2000])),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
            record_bytes(1, &mmap_payload(11, 11, 0x2000, 0x100, 0, "/bin/app")),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
        ],
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded =
        fold_perfdata_file_with_options(&perfdata, FoldOptions::default()).expect("folded");

    assert_eq!(folded, ":12;[app] 1\n");
}

#[test]
fn folds_perfdata_from_multiple_finished_rounds_into_one_total() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 7, [0x2000])),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 3, [0x2000])),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
        ],
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded = fold_perfdata_file_with_options(
        &perfdata,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 10\n");
}

#[test]
fn folds_later_rounds_with_updated_mappings_after_cacheable_rounds() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 1, [0x2000])),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
            record_bytes(1, &mmap_payload(11, 11, 0x2000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 1, [0x2000])),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
        ],
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded =
        fold_perfdata_file_with_options(&perfdata, FoldOptions::default()).expect("folded");

    assert_eq!(folded, ":12;[app] 1\n:12;[unknown] 1\n");
}

#[test]
fn folds_identical_rendered_stacks_across_pids_into_one_line() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 12, "pyroclast")),
            record_bytes(3, &comm_payload(21, 22, "pyroclast")),
            record_bytes(9, &sample_payload_with_period(0x1000, 11, 12, 7, [0x2000])),
            record_bytes(9, &sample_payload_with_period(0x1000, 21, 22, 3, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, "pyroclast;[unknown] 10\n");
}

#[test]
fn forked_process_inherits_parent_mappings_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x2000, 0x100, 0, "/bin/app")),
            record_bytes(PERF_RECORD_FORK, &fork_payload(22, 11, 22, 11, 99)),
            record_bytes(9, &sample_payload_with_period(0x1000, 22, 22, 7, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":22;[app] 7\n");
}

#[test]
fn synthesized_fork_does_not_clone_parent_mappings_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x2000, 0x100, 0, "/bin/app")),
            record_bytes_with_misc(
                PERF_RECORD_FORK,
                PERF_RECORD_MISC_COMM_EXEC,
                &fork_payload(22, 11, 22, 11, 99),
            ),
            record_bytes(9, &sample_payload_with_period(0x1000, 22, 22, 7, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains_with_options(
        &bytes,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":22;[unknown] 7\n");
}

#[test]
fn applies_comm_records_by_perf_timestamp_from_file_path_like_perf_script() {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_flags(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            1 << 18,
        )],
        [
            record_bytes(
                3,
                &comm_payload_with_sample_id_time(11, 12, "perf-exec", 10),
            ),
            record_bytes(9, &sample_payload_with_time(0x1000, 11, 12, 30, [0x2000])),
            record_bytes_with_misc(
                3,
                PERF_RECORD_MISC_COMM_EXEC,
                &comm_payload_with_sample_id_time(11, 11, "pyroclast", 20),
            ),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
        ],
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded =
        fold_perfdata_file_with_options(&perfdata, FoldOptions::default()).expect("folded");

    assert_eq!(folded, "perf-exec;[unknown] 1\n");
}

#[test]
fn folds_file_samples_from_multiple_attrs_when_generated_perf_script_event_name_matches_inferno_filter()
 {
    let root = tempfile::tempdir().expect("tempdir");
    let perfdata = root.path().join("perf.data");
    let attr1 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IDENTIFIER
            | PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_TIME
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        392,
        [111],
    );
    let attr2 = file_attr_bytes_with_ids(
        PERF_SAMPLE_IDENTIFIER
            | PERF_SAMPLE_IP
            | PERF_SAMPLE_TID
            | PERF_SAMPLE_TIME
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_CALLCHAIN,
        400,
        [222],
    );
    let bytes = perfdata_with_attrs_ids_and_records(
        [attr1, attr2],
        [111, 222],
        [
            record_bytes(
                9,
                &sample_payload_with_identifier_time_and_period(
                    222,
                    0x1000,
                    11,
                    12,
                    30,
                    2,
                    [0x2222],
                ),
            ),
            record_bytes(
                9,
                &sample_payload_with_identifier_time_and_period(
                    111,
                    0x1000,
                    11,
                    12,
                    20,
                    1,
                    [0x1111],
                ),
            ),
            record_bytes(PERF_RECORD_FINISHED_ROUND, b""),
        ],
    );
    std::fs::write(&perfdata, bytes).expect("write perfdata");

    let folded = fold_perfdata_file_with_options(
        &perfdata,
        FoldOptions {
            count_periods: true,
            inline: false,
        },
    )
    .expect("folded");

    assert_eq!(folded, ":12;[unknown] 3\n");
}

proptest! {
    #[test]
    fn property_summarizes_generated_lost_record_totals(
        entries in prop::collection::vec((any::<bool>(), any::<u64>()), 0..32),
    ) {
        let records = entries
            .iter()
            .enumerate()
            .map(|(index, (is_lost_samples, lost))| {
                if *is_lost_samples {
                    record_bytes(13, &lost.to_le_bytes())
                } else {
                    record_bytes(2, &lost_payload(index as u64, *lost))
                }
            })
            .collect::<Vec<_>>();
        let bytes = perfdata_with_records_and_attrs_vec(Vec::new(), records);

        let summary = summarize_perfdata(&bytes).expect("summary");
        let expected_lost = entries
            .iter()
            .fold(0_u64, |total, (_, lost)| total.saturating_add(*lost));
        let expected_lost_records = entries.iter().filter(|(is_lost_samples, _)| !is_lost_samples).count();
        let expected_lost_samples = entries.iter().filter(|(is_lost_samples, _)| *is_lost_samples).count();

        prop_assert_eq!(summary.total_records, entries.len());
        prop_assert_eq!(summary.record_count(2), expected_lost_records);
        prop_assert_eq!(summary.record_count(13), expected_lost_samples);
        prop_assert_eq!(summary.lost_records, expected_lost);
    }

    #[test]
    fn property_folds_generated_periods_for_user_callchains(
        frames in prop::collection::vec(0x1000_u64..0x0001_0000_0000_u64, 1..12),
        periods in prop::collection::vec(1_u64..10_000, 1..16),
    ) {
        let records = periods
            .iter()
            .map(|period| {
                record_bytes(
                    9,
                    &sample_payload_with_period_vec(0x1000, 11, 12, *period, &frames),
                )
            })
            .collect::<Vec<_>>();
        let bytes = perfdata_with_records_and_attrs_vec(
            vec![file_attr_bytes(
                PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PERIOD | PERF_SAMPLE_CALLCHAIN,
                0,
                0,
            )],
            records,
        );

        let folded = fold_perfdata_callchains_with_options(
            &bytes,
            FoldOptions { count_periods: true, inline: false },
        )
        .expect("folded");
        let expected = render_unknown_folded_callchain(&frames, periods.iter().sum());

        prop_assert_eq!(folded, expected);
    }

    #[test]
    fn property_selects_sample_layout_by_identifier(
        base_id in 1_u64..u64::MAX,
        period in 1_u64..10_000,
        frame in 0x1000_u64..0x0001_0000_0000_u64,
    ) {
        let attr1 = file_attr_bytes_with_ids(
            PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            392,
            [base_id],
        );
        let attr2 = file_attr_bytes_with_ids(
            PERF_SAMPLE_IDENTIFIER
                | PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN,
            400,
            [base_id + 1],
        );
        let bytes = perfdata_with_attrs_ids_and_records(
            [attr1, attr2],
            [base_id, base_id + 1],
            [record_bytes(
                9,
                &sample_payload_with_identifier_and_period_vec(base_id + 1, 0x1000, 11, 12, period, &[frame]),
            )],
        );

        let folded = fold_perfdata_callchains_with_options(
            &bytes,
            FoldOptions { count_periods: true, inline: false },
        )
        .expect("folded");

        prop_assert_eq!(folded, render_unknown_folded_callchain(&[frame], period));
    }

    #[test]
    fn property_selects_sample_layout_by_id_field(
        base_id in 1_u64..u64::MAX,
        period in 1_u64..10_000,
        frame in 0x1000_u64..0x0001_0000_0000_u64,
    ) {
        let attr1 = file_attr_bytes_with_ids(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ID | PERF_SAMPLE_CALLCHAIN,
            392,
            [base_id],
        );
        let attr2 = file_attr_bytes_with_ids(
            PERF_SAMPLE_IP
                | PERF_SAMPLE_TID
                | PERF_SAMPLE_ID
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN,
            400,
            [base_id + 1],
        );
        let bytes = perfdata_with_attrs_ids_and_records(
            [attr1, attr2],
            [base_id, base_id + 1],
            [record_bytes(
                9,
                &sample_payload_with_id_and_period_vec(0x1000, 11, 12, base_id + 1, period, &[frame]),
            )],
        );

        let folded = fold_perfdata_callchains_with_options(
            &bytes,
            FoldOptions { count_periods: true, inline: false },
        )
        .expect("folded");

        prop_assert_eq!(folded, render_unknown_folded_callchain(&[frame], period));
    }
}

#[test]
fn folds_unsymbolized_mapped_user_frames_like_inferno_module_fallback() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[app] 1\n");
}

#[test]
fn folds_unsymbolized_bracket_mappings_like_inferno_module_fallback() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x7000, 0x100, 0, "[vdso]")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x7010])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[[vdso]] 1\n");
}

#[test]
fn folds_mmap2_build_id_records_as_mappings() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes_with_misc(
                10,
                1 << 14,
                &mmap2_build_id_payload(11, 11, 0x4000, 0x100, 0x20, "/bin/build-id-app"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x4010])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[build-id-app] 1\n");
}

#[test]
fn symbolized_fold_carries_mmap2_build_ids_to_symbol_requests() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes_with_misc(
                10,
                1 << 14,
                &mmap2_build_id_payload(11, 11, 0x4000, 0x100, 0x20, "[igb]"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x4010])),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[[igb]] 1\n");
    assert_eq!(
        resolver.calls(),
        vec![vec![SymbolRequest {
            path: std::path::PathBuf::from("[igb]"),
            relative_address: 0x30,
            build_id: Some("aabbccdd".to_string()),
            file_identity: None,
            kernel_relocation: None,
        }]]
    );
}

#[test]
fn symbolized_fold_carries_mmap2_file_identity_to_symbol_requests() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x4000, 0x100, 0x20, 5, "/bin/app"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x4010])),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[app] 1\n");
    assert_eq!(
        resolver.calls(),
        vec![vec![SymbolRequest {
            path: std::path::PathBuf::from("/bin/app"),
            relative_address: 0x30,
            build_id: None,
            file_identity: Some(FileIdentity {
                major: 8,
                minor: 1,
                inode: 99,
                inode_generation: 7,
            }),
            kernel_relocation: None,
        }]]
    );
}

#[test]
fn symbolized_fold_carries_header_build_ids_to_mmap2_symbol_requests() {
    let build_id = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90,
        0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
    ];
    let bytes = perfdata_with_records_attrs_and_build_id_feature(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x4000, 0x100, 0x20, 5, "/tmp/stale-app"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x4010])),
        ],
        &build_id_event_payload(u32::MAX, &build_id, "/tmp/stale-app"),
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[stale-app] 1\n");
    assert_eq!(
        resolver.calls(),
        vec![vec![SymbolRequest {
            path: std::path::PathBuf::from("/tmp/stale-app"),
            relative_address: 0x30,
            build_id: Some("aabbccddeeff102030405060708090a0b0c0d0e0".to_string()),
            file_identity: Some(FileIdentity {
                major: 8,
                minor: 1,
                inode: 99,
                inode_generation: 7,
            }),
            kernel_relocation: None,
        }]]
    );
}

#[test]
fn folds_mapped_user_frames_with_symbol_names() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x1010])),
        ],
    );
    let resolver = StaticSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;app::main;app::main 1\n");
}

#[test]
fn symbolized_fold_expands_inline_symbol_frames() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010])),
        ],
    );
    let resolver = InlineSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;app::outer;app::inner 1\n");
}

#[test]
fn symbolized_fold_renders_inline_arrows_like_inferno_collapse_perf() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010])),
        ],
    );
    let resolver = ArrowInlineSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;app::outer;app::middle;app::inner_[i] 1\n");
}

#[test]
fn symbolized_fold_keeps_unknown_caller_before_inline_frames_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(1, &mmap_payload(11, 11, 0x2000, 0x100, 0, "[unknown]")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x2010])),
        ],
    );
    let resolver = InlineSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[unknown];app::outer;app::inner 1\n");
}

#[test]
fn symbolized_fold_keeps_module_fallback_caller_before_inline_frames_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(
                10,
                &mmap2_payload(11, 11, 0x2000, 0x100, 0, 0, "/lib/libc.so.6"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x2010])),
        ],
    );
    let resolver = InlineSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[libc.so.6];app::outer;app::inner 1\n");
}

#[test]
fn symbolized_fold_renders_unmapped_user_caller_as_unknown_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x2010])),
        ],
    );
    let resolver = InlineSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[unknown];app::outer;app::inner 1\n");
}

#[test]
fn symbolized_fold_uses_module_fallback_for_unresolved_user_frames_like_inferno() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/usr/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010])),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[app] 1\n");
}

#[test]
fn symbolized_fold_omits_process_name_frames_like_inferno_collapse_perf() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010])),
        ],
    );
    let resolver = ProcessNameSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[app] 1\n");
}

#[test]
fn leaves_kernel_space_frames_as_hex_without_symbol_lookup() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                1,
                &mmap_payload(11, 11, 0xffff_ffff_8800_0000, 0x2000, 0, "/bin/app"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0xffff_ffff_8800_0010])),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;0xffffffff88000010 1\n");
    assert_eq!(resolver.calls(), Vec::<Vec<SymbolRequest>>::new());
}

#[test]
fn folds_unmapped_kernel_frames_as_unknown_like_inferno() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0xffff_ffff_8800_0010]),
        )],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[unknown] 1\n");
}

#[test]
fn keeps_kernel_frames_from_mmap2_records_without_exec_prot() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                10,
                &mmap2_payload(
                    u32::MAX,
                    u32::MAX,
                    0xffff_ffff_8800_0000,
                    0x2000,
                    0,
                    0,
                    "[kernel.kallsyms]",
                ),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0xffff_ffff_8800_0010])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, ":12;[[kernel.kallsyms]] 1\n");
}

#[test]
fn symbolized_fold_uses_module_fallback_for_unresolved_kernel_frames_like_inferno() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                1,
                &mmap_payload(
                    u32::MAX,
                    u32::MAX,
                    0xffff_ffff_8800_0000,
                    0x2000,
                    0,
                    "[kernel.kallsyms]_text",
                ),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0xffff_ffff_8800_0010])),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[[kernel.kallsyms]] 1\n");
}

#[test]
fn symbolized_fold_resolves_mapped_kernel_frames() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                1,
                &mmap_payload(
                    u32::MAX,
                    u32::MAX,
                    0xffff_ffff_8800_0000,
                    0x2000,
                    0,
                    "[kernel.kallsyms]",
                ),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0xffff_ffff_8800_0010])),
        ],
    );
    let resolver = StaticSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;asm_exc_page_fault 1\n");
}

#[test]
fn symbolized_fold_resolves_kernel_module_frames() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(
                1,
                &mmap_payload(
                    u32::MAX,
                    u32::MAX,
                    0xffff_ffff_c000_0000,
                    0x2000,
                    0,
                    "[zfs]",
                ),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0xffff_ffff_c000_0123])),
        ],
    );
    let resolver = StaticSymbolResolver;

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;zfs_read 1\n");
}

#[test]
fn prefetches_unique_symbol_requests_before_folding() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(1, &mmap_payload(11, 11, 0x1000, 0x100, 0, "/bin/app")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x1020])),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x1010, 0x1020])),
        ],
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;app::work;app::main 2\n");
    let mut calls = resolver.calls();
    assert_eq!(calls.len(), 1);
    let mut requests = calls.pop().expect("prefetch batch");
    requests.sort_by_key(|request| request.relative_address);
    assert_eq!(
        requests,
        vec![
            SymbolRequest {
                path: std::path::PathBuf::from("/bin/app"),
                relative_address: 0x10,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            },
            SymbolRequest {
                path: std::path::PathBuf::from("/bin/app"),
                relative_address: 0x20,
                build_id: None,
                file_identity: None,
                kernel_relocation: None,
            }
        ]
    );
}

#[test]
fn prefetches_symbol_requests_in_batches_before_folding() {
    let mut records = vec![record_bytes(
        1,
        &mmap_payload(11, 11, 0x1000, 0x3000, 0, "/bin/app"),
    )];
    for index in 0..4097_u64 {
        records.push(record_bytes(
            9,
            &sample_payload(0x1000, 11, 12, [0x1030 + index]),
        ));
    }
    let bytes = perfdata_with_records_and_attrs_vec(
        vec![file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        records,
    );
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, ":12;[app] 4097\n");
    let calls = resolver.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].len(), 4096);
    assert_eq!(calls[1].len(), 1);
}

fn perfdata_with_records_and_attrs<const A: usize, const R: usize>(
    attrs: [[u8; 144]; A],
    records: [Vec<u8>; R],
) -> Vec<u8> {
    let attr_size = attrs.len() * 144;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size;
    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    for attr in attrs {
        bytes.extend(attr);
    }
    for record in records {
        bytes.extend(record);
    }
    bytes
}

fn perfdata_with_records_and_attrs_vec(attrs: Vec<[u8; 144]>, records: Vec<Vec<u8>>) -> Vec<u8> {
    let attr_size = attrs.len() * 144;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size;
    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    for attr in attrs {
        bytes.extend(attr);
    }
    for record in records {
        bytes.extend(record);
    }
    bytes
}

fn perfdata_with_records_attrs_and_build_id_feature<const A: usize, const R: usize>(
    attrs: [[u8; 144]; A],
    records: [Vec<u8>; R],
    build_id_payload: &[u8],
) -> Vec<u8> {
    let attr_size = attrs.len() * 144;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size;
    let feature_table_offset = data_offset + data_size;
    let build_id_payload_offset = feature_table_offset + 16;
    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    // HEADER_BUILD_ID feature bit (2) in the adds_features bitmap, which struct
    // perf_file_header (tools/perf/util/header.h) places at byte offset 72.
    put_u64(&mut bytes, 72, 1 << 2);
    for attr in attrs {
        bytes.extend(attr);
    }
    for record in records {
        bytes.extend(record);
    }
    bytes.resize(build_id_payload_offset, 0);
    put_u64(
        &mut bytes,
        feature_table_offset,
        build_id_payload_offset as u64,
    );
    put_u64(
        &mut bytes,
        feature_table_offset + 8,
        u64::try_from(build_id_payload.len()).expect("payload size"),
    );
    bytes.extend(build_id_payload);
    bytes
}

/// Builds a perf.data carrying a single HEADER_ARCH feature string (the
/// recording machine's `uname -m`). perf stores it as a `perf_header_string`:
/// a u32 length followed by that many NUL-terminated bytes (util/header.c
/// write_arch/do_write_string).
fn perfdata_with_records_attrs_and_arch_feature<const A: usize, const R: usize>(
    attrs: [[u8; 144]; A],
    records: [Vec<u8>; R],
    arch: &str,
) -> Vec<u8> {
    let attr_size = attrs.len() * 144;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size;
    let feature_table_offset = data_offset + data_size;
    let arch_payload_offset = feature_table_offset + 16;
    // do_write_string aligns the length to NAME_ALIGN (64) and writes the
    // NUL-terminated name plus zero padding.
    let aligned = (arch.len() + 1).next_multiple_of(64);
    let mut arch_payload = Vec::new();
    arch_payload.extend(u32::try_from(aligned).expect("arch len").to_le_bytes());
    let mut name_bytes = arch.as_bytes().to_vec();
    name_bytes.resize(aligned, 0);
    arch_payload.extend(name_bytes);

    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    // HEADER_ARCH feature bit (6) in the adds_features bitmap, which struct
    // perf_file_header (tools/perf/util/header.h) places at byte offset 72.
    put_u64(&mut bytes, 72, 1 << 6);
    for attr in attrs {
        bytes.extend(attr);
    }
    for record in records {
        bytes.extend(record);
    }
    bytes.resize(arch_payload_offset, 0);
    put_u64(&mut bytes, feature_table_offset, arch_payload_offset as u64);
    put_u64(
        &mut bytes,
        feature_table_offset + 8,
        u64::try_from(arch_payload.len()).expect("payload size"),
    );
    bytes.extend(arch_payload);
    bytes
}

fn perfdata_with_attrs_ids_and_records<const A: usize, const I: usize, const R: usize>(
    attrs: [[u8; 144]; A],
    ids: [u64; I],
    records: [Vec<u8>; R],
) -> Vec<u8> {
    let attr_size = attrs.len() * 144;
    let ids_size = ids.len() * 8;
    let data_size = records.iter().map(Vec::len).sum::<usize>();
    let data_offset = 104 + attr_size + ids_size;
    let mut bytes = vec![0; 104];
    bytes[..8].copy_from_slice(b"PERFILE2");
    put_u64(&mut bytes, 8, 104);
    put_u64(&mut bytes, 24, 104);
    put_u64(&mut bytes, 32, attr_size as u64);
    put_u64(&mut bytes, 40, data_offset as u64);
    put_u64(&mut bytes, 48, data_size as u64);
    for attr in attrs {
        bytes.extend(attr);
    }
    for id in ids {
        bytes.extend(id.to_le_bytes());
    }
    for record in records {
        bytes.extend(record);
    }
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

fn file_attr_bytes_with_flags(sample_type: u64, flags: u64) -> [u8; 144] {
    let mut bytes = file_attr_bytes(sample_type, 0, 0);
    put_u64(&mut bytes, 40, flags);
    bytes
}

fn file_attr_bytes_with_regs(sample_type: u64, sample_regs_user: u64) -> [u8; 144] {
    let mut bytes = file_attr_bytes(sample_type, 0, 0);
    put_u64(&mut bytes, 80, sample_regs_user);
    bytes
}

fn file_attr_bytes_with_ids<const N: usize>(
    sample_type: u64,
    ids_offset: u64,
    ids: [u64; N],
) -> [u8; 144] {
    file_attr_bytes(sample_type, ids_offset, (ids.len() * 8) as u64)
}

fn record_bytes(record_type: u32, payload: &[u8]) -> Vec<u8> {
    record_bytes_with_misc(record_type, 0, payload)
}

fn record_bytes_with_misc(record_type: u32, misc: u16, payload: &[u8]) -> Vec<u8> {
    let size = 8 + payload.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.extend(record_type.to_le_bytes());
    bytes.extend(misc.to_le_bytes());
    bytes.extend(
        u16::try_from(size)
            .expect("record fits in u16")
            .to_le_bytes(),
    );
    bytes.extend(payload);
    bytes
}

fn callchain_deferred_payload<const N: usize>(cookie: u64, ips: [u64; N]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(cookie.to_le_bytes());
    payload.extend((ips.len() as u64).to_le_bytes());
    for ip in ips {
        payload.extend(ip.to_le_bytes());
    }
    payload
}

fn sample_payload<const N: usize>(ip: u64, pid: u32, tid: u32, callchain: [u64; N]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_time<const N: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    time: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(time.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_period<const N: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_period_no_callchain(ip: u64, pid: u32, tid: u32, period: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload
}

fn sample_payload_with_period_and_user_stack_no_callchain<const R: usize, const S: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    abi: u64,
    regs: [u64; R],
    stack: [u8; S],
) -> Vec<u8> {
    let mut payload = sample_payload_with_period_no_callchain(ip, pid, tid, period);
    append_user_stack_payload(&mut payload, abi, regs, stack, S as u64);
    payload
}

fn sample_payload_with_identifier_and_period<const N: usize>(
    identifier: u64,
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(identifier.to_le_bytes());
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_identifier_time_and_period<const N: usize>(
    identifier: u64,
    ip: u64,
    pid: u32,
    tid: u32,
    time: u64,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(identifier.to_le_bytes());
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(time.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_id_and_period<const N: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    id: u64,
    period: u64,
    callchain: [u64; N],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(id.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_period_vec(
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    callchain: &[u64],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_identifier_and_period_vec(
    identifier: u64,
    ip: u64,
    pid: u32,
    tid: u32,
    period: u64,
    callchain: &[u64],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(identifier.to_le_bytes());
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_id_and_period_vec(
    ip: u64,
    pid: u32,
    tid: u32,
    id: u64,
    period: u64,
    callchain: &[u64],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(ip.to_le_bytes());
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(id.to_le_bytes());
    payload.extend(period.to_le_bytes());
    payload.extend((callchain.len() as u64).to_le_bytes());
    for frame in callchain {
        payload.extend(frame.to_le_bytes());
    }
    payload
}

fn sample_payload_with_user_stack<const C: usize, const R: usize, const S: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    callchain: [u64; C],
    abi: u64,
    regs: [u64; R],
    stack: [u8; S],
) -> Vec<u8> {
    let mut payload = sample_payload(ip, pid, tid, callchain);
    append_user_stack_payload(&mut payload, abi, regs, stack, S as u64);
    payload
}

fn sample_payload_with_zero_dynamic_user_stack<const C: usize, const R: usize, const S: usize>(
    ip: u64,
    pid: u32,
    tid: u32,
    callchain: [u64; C],
    abi: u64,
    regs: [u64; R],
    stack: [u8; S],
) -> Vec<u8> {
    let mut payload = sample_payload(ip, pid, tid, callchain);
    append_user_stack_payload(&mut payload, abi, regs, stack, 0);
    payload
}

fn append_user_stack_payload<const R: usize, const S: usize>(
    payload: &mut Vec<u8>,
    abi: u64,
    regs: [u64; R],
    stack: [u8; S],
    dynamic_size: u64,
) {
    payload.extend(abi.to_le_bytes());
    for reg in regs {
        payload.extend(reg.to_le_bytes());
    }
    payload.extend((stack.len() as u64).to_le_bytes());
    payload.extend(stack);
    payload.extend(vec![0; stack.len().next_multiple_of(8) - stack.len()]);
    payload.extend(dynamic_size.to_le_bytes());
}

#[cfg(target_os = "linux")]
fn process_libc_path() -> Option<std::path::PathBuf> {
    std::fs::read_to_string("/proc/self/maps")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let _range = fields.next()?;
            let perms = fields.next()?;
            let _offset = fields.next()?;
            let _dev = fields.next()?;
            let _inode = fields.next()?;
            let path = fields.next()?;
            (perms.contains('x') && path.contains("libc.so.6"))
                .then(|| std::path::PathBuf::from(path))
        })
}

fn comm_payload(pid: u32, tid: u32, comm: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(comm.as_bytes());
    payload.push(0);
    payload
}

fn comm_payload_with_sample_id_time(pid: u32, tid: u32, comm: &str, time: u64) -> Vec<u8> {
    let mut payload = comm_payload(pid, tid, comm);
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(time.to_le_bytes());
    payload
}

#[allow(clippy::similar_names)]
fn fork_payload(
    child_pid: u32,
    parent_pid: u32,
    child_tid: u32,
    parent_tid: u32,
    time: u64,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(child_pid.to_le_bytes());
    payload.extend(parent_pid.to_le_bytes());
    payload.extend(child_tid.to_le_bytes());
    payload.extend(parent_tid.to_le_bytes());
    payload.extend(time.to_le_bytes());
    payload
}

fn mmap_payload(pid: u32, tid: u32, start: u64, len: u64, pgoff: u64, path: &str) -> Vec<u8> {
    let mut payload = mmap_range_payload(pid, tid, start, len, pgoff);
    payload.extend(path.as_bytes());
    payload.push(0);
    payload
}

fn mmap2_payload(
    pid: u32,
    tid: u32,
    start: u64,
    len: u64,
    pgoff: u64,
    prot: u32,
    path: &str,
) -> Vec<u8> {
    let mut payload = mmap_range_payload(pid, tid, start, len, pgoff);
    payload.extend(8u32.to_le_bytes());
    payload.extend(1u32.to_le_bytes());
    payload.extend(99u64.to_le_bytes());
    payload.extend(7u64.to_le_bytes());
    payload.extend(prot.to_le_bytes());
    payload.extend(2u32.to_le_bytes());
    payload.extend(path.as_bytes());
    payload.push(0);
    payload
}

fn mmap2_build_id_payload(
    pid: u32,
    tid: u32,
    start: u64,
    len: u64,
    pgoff: u64,
    path: &str,
) -> Vec<u8> {
    let mut payload = mmap_range_payload(pid, tid, start, len, pgoff);
    payload.push(4);
    payload.push(0);
    payload.extend(0u16.to_le_bytes());
    payload.extend([0xaa, 0xbb, 0xcc, 0xdd]);
    payload.extend([0; 16]);
    payload.extend(5u32.to_le_bytes());
    payload.extend(2u32.to_le_bytes());
    payload.extend(path.as_bytes());
    payload.push(0);
    payload
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

fn lost_payload(id: u64, lost: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(id.to_le_bytes());
    payload.extend(lost.to_le_bytes());
    payload
}

fn mmap_range_payload(pid: u32, tid: u32, start: u64, len: u64, pgoff: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(pid.to_le_bytes());
    payload.extend(tid.to_le_bytes());
    payload.extend(start.to_le_bytes());
    payload.extend(len.to_le_bytes());
    payload.extend(pgoff.to_le_bytes());
    payload
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

struct StaticSymbolResolver;

impl SymbolResolver for StaticSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(requests
            .iter()
            .map(|request| {
                (request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10)
                    .then(|| "app::main".to_string())
                    .or_else(|| {
                        (request.path == std::path::Path::new("/bin/app")
                            && request.relative_address == 0x20)
                            .then(|| "app::work".to_string())
                    })
                    .or_else(|| {
                        (request.path == std::path::Path::new("[kernel.kallsyms]")
                            && request.relative_address == 0xffff_ffff_8800_0010)
                            .then(|| "asm_exc_page_fault".to_string())
                    })
                    .or_else(|| {
                        (request.path == std::path::Path::new("[zfs]")
                            && request.relative_address == 0xffff_ffff_c000_0123)
                            .then(|| "zfs_read".to_string())
                    })
            })
            .collect())
    }
}

struct InlineSymbolResolver;

impl SymbolResolver for InlineSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(vec![None; requests.len()])
    }

    fn resolve_frame_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
        Ok(requests
            .iter()
            .map(|request| {
                if request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10
                {
                    vec!["app::outer".to_string(), "app::inner".to_string()]
                } else {
                    Vec::new()
                }
            })
            .collect())
    }
}

struct ArrowInlineSymbolResolver;

struct SyntheticX86_64Object {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
}

impl SyntheticX86_64Object {
    /// Minimal x86_64 ELF with one PT_LOAD covering [0, 0x10000) and no unwind
    /// info. The current-IP-only tests previously mapped the host test binary,
    /// which made framehop's unwind host-dependent (a Mach-O/arm64 test binary
    /// recovers callers through __unwind_info that a Linux x86_64 binary does
    /// not have at these offsets). A synthetic ELF pins the libdw scenario the
    /// tests encode: module reports, framehop yields only the seeded IP.
    fn create() -> Self {
        let mut bytes = vec![0_u8; 0x240];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // ELFDATA2LSB
        bytes[6] = 1; // EV_CURRENT
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes()); // ET_DYN
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes()); // EM_X86_64
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes()); // e_version
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes()); // e_phoff
        bytes[40..48].copy_from_slice(&0x180_u64.to_le_bytes()); // e_shoff
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes()); // e_ehsize
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes()); // e_phentsize
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes()); // e_phnum
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes()); // e_shentsize
        bytes[60..62].copy_from_slice(&3_u16.to_le_bytes()); // e_shnum
        bytes[62..64].copy_from_slice(&2_u16.to_le_bytes()); // e_shstrndx
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes()); // PT_LOAD
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes()); // PF_R | PF_X
        bytes[96..104].copy_from_slice(&0x200_u64.to_le_bytes()); // p_filesz
        bytes[104..112].copy_from_slice(&0x1_0000_u64.to_le_bytes()); // p_memsz
        bytes[112..120].copy_from_slice(&0x1000_u64.to_le_bytes()); // p_align
        // .eh_frame at vaddr/offset 0x100: one CIE and one FDE covering only
        // [0x100, 0x104), so the module HAS unwind info but none of the
        // sampled IPs are covered — the configuration where framehop stops
        // after the seeded IP instead of taking a frame-pointer fallback,
        // matching a real Linux binary sampled outside its FDE ranges.
        let eh_frame: [u8; 52] = [
            0x14, 0, 0, 0, // CIE length
            0, 0, 0, 0, // CIE id
            0x01, b'z', b'R', 0, // version, augmentation "zR"
            0x01, 0x78, 0x10, // code align 1, data align -8, ra 16
            0x01, 0x1b, // augmentation: FDE encoding pcrel|sdata4
            0, 0, 0, 0, 0, 0, 0, // DW_CFA_nop padding
            0x14, 0, 0, 0, // FDE length
            0x1c, 0, 0, 0, // CIE pointer (back 28 bytes)
            0xe0, 0xff, 0xff, 0xff, // pc_begin: pcrel -0x20 -> vaddr 0x100
            0x04, 0, 0, 0, // pc_range 4
            0, // augmentation data length
            0, 0, 0, 0, 0, 0, 0, // DW_CFA_nop padding
            0, 0, 0, 0, // terminator
        ];
        bytes[0x100..0x100 + eh_frame.len()].copy_from_slice(&eh_frame);
        let strtab = b"\0.eh_frame\0.shstrtab\0";
        bytes[0x140..0x140 + strtab.len()].copy_from_slice(strtab);
        // Section headers: [0] SHT_NULL, [1] .eh_frame, [2] .shstrtab.
        let mut section =
            |index: usize, name: u32, kind: u32, flags: u64, addr: u64, offset: u64, size: u64| {
                let base = 0x180 + index * 64;
                bytes[base..base + 4].copy_from_slice(&name.to_le_bytes());
                bytes[base + 4..base + 8].copy_from_slice(&kind.to_le_bytes());
                bytes[base + 8..base + 16].copy_from_slice(&flags.to_le_bytes());
                bytes[base + 16..base + 24].copy_from_slice(&addr.to_le_bytes());
                bytes[base + 24..base + 32].copy_from_slice(&offset.to_le_bytes());
                bytes[base + 32..base + 40].copy_from_slice(&size.to_le_bytes());
                bytes[base + 48..base + 56].copy_from_slice(&8_u64.to_le_bytes());
            };
        section(1, 1, 1, 2, 0x100, 0x100, 52); // .eh_frame PROGBITS ALLOC
        section(2, 11, 3, 0, 0, 0x140, 21); // .shstrtab STRTAB
        let dir = tempfile::tempdir().expect("fixture dir");
        let path = dir.path().join("fixture-x86-64");
        std::fs::write(&path, &bytes).expect("write fixture elf");
        Self { _dir: dir, path }
    }

    fn path_string(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    fn file_name(&self) -> &'static str {
        "fixture-x86-64"
    }
}

/// Minimal aarch64 ELF, structurally identical to `SyntheticX86_64Object` but
/// with `e_machine = EM_AARCH64` (183) and a `.eh_frame` FDE that covers only
/// `[0x100, 0x104)`. Used to pin the aarch64 scenario-D leaf-only case: a
/// reported module, no FDE covering the sampled pc, and `lr == 0` so the
/// elfutils `backends/aarch64_unwind.c` fallback fails before producing any
/// caller.
struct SyntheticAarch64Object {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
}

impl SyntheticAarch64Object {
    fn create() -> Self {
        let mut bytes = vec![0_u8; 0x240];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // ELFDATA2LSB
        bytes[6] = 1; // EV_CURRENT
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes()); // ET_DYN
        bytes[18..20].copy_from_slice(&183_u16.to_le_bytes()); // EM_AARCH64
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes()); // e_version
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes()); // e_phoff
        bytes[40..48].copy_from_slice(&0x180_u64.to_le_bytes()); // e_shoff
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes()); // e_ehsize
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes()); // e_phentsize
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes()); // e_phnum
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes()); // e_shentsize
        bytes[60..62].copy_from_slice(&3_u16.to_le_bytes()); // e_shnum
        bytes[62..64].copy_from_slice(&2_u16.to_le_bytes()); // e_shstrndx
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes()); // PT_LOAD
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes()); // PF_R | PF_X
        bytes[96..104].copy_from_slice(&0x200_u64.to_le_bytes()); // p_filesz
        bytes[104..112].copy_from_slice(&0x1_0000_u64.to_le_bytes()); // p_memsz
        bytes[112..120].copy_from_slice(&0x1000_u64.to_le_bytes()); // p_align
        let eh_frame: [u8; 52] = [
            0x14, 0, 0, 0, // CIE length
            0, 0, 0, 0, // CIE id
            0x01, b'z', b'R', 0, // version, augmentation "zR"
            0x01, 0x78, 0x1e, // code align 1, data align -8, ra 30 (aarch64 LR)
            0x01, 0x1b, // augmentation: FDE encoding pcrel|sdata4
            0, 0, 0, 0, 0, 0, 0, // DW_CFA_nop padding
            0x14, 0, 0, 0, // FDE length
            0x1c, 0, 0, 0, // CIE pointer (back 28 bytes)
            0xe0, 0xff, 0xff, 0xff, // pc_begin: pcrel -0x20 -> vaddr 0x100
            0x04, 0, 0, 0, // pc_range 4
            0, // augmentation data length
            0, 0, 0, 0, 0, 0, 0, // DW_CFA_nop padding
            0, 0, 0, 0, // terminator
        ];
        bytes[0x100..0x100 + eh_frame.len()].copy_from_slice(&eh_frame);
        let strtab = b"\0.eh_frame\0.shstrtab\0";
        bytes[0x140..0x140 + strtab.len()].copy_from_slice(strtab);
        let mut section =
            |index: usize, name: u32, kind: u32, flags: u64, addr: u64, offset: u64, size: u64| {
                let base = 0x180 + index * 64;
                bytes[base..base + 4].copy_from_slice(&name.to_le_bytes());
                bytes[base + 4..base + 8].copy_from_slice(&kind.to_le_bytes());
                bytes[base + 8..base + 16].copy_from_slice(&flags.to_le_bytes());
                bytes[base + 16..base + 24].copy_from_slice(&addr.to_le_bytes());
                bytes[base + 24..base + 32].copy_from_slice(&offset.to_le_bytes());
                bytes[base + 32..base + 40].copy_from_slice(&size.to_le_bytes());
                bytes[base + 48..base + 56].copy_from_slice(&8_u64.to_le_bytes());
            };
        section(1, 1, 1, 2, 0x100, 0x100, 52); // .eh_frame PROGBITS ALLOC
        section(2, 11, 3, 0, 0, 0x140, 21); // .shstrtab STRTAB
        let dir = tempfile::tempdir().expect("fixture dir");
        let path = dir.path().join("fixture-aarch64");
        std::fs::write(&path, &bytes).expect("write fixture elf");
        Self { _dir: dir, path }
    }

    fn path_string(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    fn file_name(&self) -> &'static str {
        "fixture-aarch64"
    }
}

fn current_exe_file_name() -> String {
    std::env::current_exe()
        .expect("current exe")
        .file_name()
        .expect("current exe file name")
        .to_string_lossy()
        .into_owned()
}

impl SymbolResolver for ArrowInlineSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(vec![None; requests.len()])
    }

    fn resolve_frame_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Vec<String>>, String> {
        Ok(requests
            .iter()
            .map(|request| {
                if request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10
                {
                    vec![
                        "app::outer".to_string(),
                        "app::middle->app::inner".to_string(),
                    ]
                } else {
                    Vec::new()
                }
            })
            .collect())
    }
}

struct ProcessNameSymbolResolver;

impl SymbolResolver for ProcessNameSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        Ok(requests
            .iter()
            .map(|request| {
                (request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10)
                    .then(|| "(python)".to_string())
            })
            .collect())
    }
}

#[derive(Default)]
struct RecordingSymbolResolver {
    calls: RefCell<Vec<Vec<SymbolRequest>>>,
}

impl RecordingSymbolResolver {
    fn calls(&self) -> Vec<Vec<SymbolRequest>> {
        self.calls.borrow().clone()
    }
}

impl SymbolResolver for RecordingSymbolResolver {
    fn resolve_batch(&self, requests: &[SymbolRequest]) -> Result<Vec<Option<String>>, String> {
        self.calls.borrow_mut().push(requests.to_vec());
        Ok(requests
            .iter()
            .map(|request| {
                (request.path == std::path::Path::new("/bin/app")
                    && request.relative_address == 0x10)
                    .then(|| "app::main".to_string())
                    .or_else(|| {
                        (request.path == std::path::Path::new("/bin/app")
                            && request.relative_address == 0x20)
                            .then(|| "app::work".to_string())
                    })
            })
            .collect())
    }
}
