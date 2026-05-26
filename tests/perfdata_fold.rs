use std::cell::RefCell;

use pyroclast::perfdata::fold::{
    FoldOptions, fold_perfdata_callchains, fold_perfdata_callchains_with_options,
    fold_perfdata_callchains_with_symbols, fold_perfdata_file_with_options, summarize_perfdata,
};
use pyroclast::perfdata::mappings::FileIdentity;
use pyroclast::perfdata::records::{
    PERF_RECORD_MISC_COMM_EXEC, PERF_RECORD_MISC_CPUMODE_KERNEL, PERF_RECORD_MISC_CPUMODE_USER,
};
use pyroclast::perfdata::samples::{
    PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_ID, PERF_SAMPLE_IDENTIFIER, PERF_SAMPLE_IP,
    PERF_SAMPLE_PERIOD, PERF_SAMPLE_REGS_USER, PERF_SAMPLE_STACK_USER, PERF_SAMPLE_TID,
    PERF_SAMPLE_TIME,
};
use pyroclast::symbols::{SymbolRequest, SymbolResolver};

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
            0b1,
        )],
        [record_bytes(
            9,
            &sample_payload_with_user_stack(0x1000, 11, 12, [0x2000], 1, [0xaaaa], [1, 2, 3]),
        )],
    );

    let summary = summarize_perfdata(&bytes).expect("summary");

    assert_eq!(summary.sample_stacks.len(), 1);
    assert!(summary.sample_stacks[0].has_user_stack);
    assert_eq!(summary.sample_stacks[0].user_register_count, 1);
    assert_eq!(summary.sample_stacks[0].user_stack_size, 3);
}

#[test]
fn folds_dwarf_user_stack_payloads_when_callchain_is_empty() {
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

    assert_eq!(folded, "0x1233;0x4000 1\n");
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

    assert_eq!(folded, "0x1233;0x4000;0xa000;0x9000 1\n");
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

    assert_eq!(folded, "0x1233;0x4000;[unknown];[unknown] 1\n");
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

    assert_eq!(folded, "0x1233;0x4000;[unknown];[unknown] 1\n");
}

#[test]
fn ignores_dwarf_user_stack_payloads_for_kernel_samples_without_user_context_marker() {
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

    assert_eq!(folded, "[unknown];[unknown] 1\n");
}

#[test]
fn uses_mapped_object_unwinder_for_dwarf_user_stack_frames() {
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

    assert_eq!(folded, format!("{current_exe}+0x4000 1\n"));
}

#[test]
fn drops_unwound_user_stack_frames_outside_known_mappings() {
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

    assert_eq!(folded, "/tmp/app+0x0 1\n");
}

#[test]
fn symbolized_fold_renders_unmapped_user_unwind_frames_as_unknown_like_perf_script() {
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

    assert_eq!(folded, "[unknown];[app] 1\n");
}

#[test]
fn keeps_unwound_user_stack_frames_from_mappings_after_sample() {
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

    assert_eq!(folded, "/tmp/lib+0x0;/tmp/app+0x0 1\n");
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

    assert_eq!(folded, "0x4000;0x9000 1\n");
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

    assert_eq!(folded, "/lib/libc.so.6+0x33;0x4000;0x9000 1\n");
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

    assert_eq!(folded, "0x4000;0x9000 1\n");
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

    assert_eq!(folded, "0x4000;0x9000 1\n");
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

    assert_eq!(folded, "0x4000;0x3000;0x2000 1\n");
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

    assert_eq!(folded, "0x3000;0x2000 2\n0x4000 1\n");
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

    assert_eq!(folded, "0x2000 1\n");
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

    assert_eq!(folded, "pyroclast;0x6000;0x5000;0x3000;0x2000 1\n");
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
fn prefixes_folded_stacks_with_matching_comm_name() {
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

    assert_eq!(folded, "sftp-s3;0x2000 1\n");
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
            record_bytes(3, &comm_payload(11, 12, "perf-exec")),
            record_bytes(9, &sample_payload(0x1000, 11, 11, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "pyroclast;0x2000 1\n");
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

    assert_eq!(folded, "perf-exec;0x2000 1\npyroclast;0x3000 1\n");
}

#[test]
fn exec_comm_replaces_stale_thread_comm_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN,
            0,
            0,
        )],
        [
            record_bytes(3, &comm_payload(11, 12, "perf-exec")),
            record_bytes_with_misc(
                3,
                PERF_RECORD_MISC_COMM_EXEC,
                &comm_payload(11, 11, "pyroclast"),
            ),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "pyroclast;0x2000 1\n");
}

#[test]
fn applies_comm_records_by_perf_timestamp_like_perf_script() {
    let bytes = perfdata_with_records_and_attrs(
        [file_attr_bytes_with_flags(
            PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN,
            1 << 18,
        )],
        [
            record_bytes(3, &comm_payload(11, 12, "perf-exec")),
            record_bytes(9, &sample_payload_with_time(0x1000, 11, 12, 30, [0x2000])),
            record_bytes_with_misc(
                3,
                PERF_RECORD_MISC_COMM_EXEC,
                &comm_payload_with_sample_id_time(11, 11, "pyroclast", 20),
            ),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "pyroclast;0x2000 1\n");
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
            record_bytes(3, &comm_payload(11, 11, "V8 WorkerThread")),
            record_bytes(9, &sample_payload(0x1000, 11, 12, [0x2000])),
        ],
    );

    let folded = fold_perfdata_callchains(&bytes).expect("folded");

    assert_eq!(folded, "V8_WorkerThread;0x2000 1\n");
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
        },
    )
    .expect("folded");

    assert_eq!(folded, "0x2000 10\n");
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
        },
    )
    .expect("folded");

    assert_eq!(folded, "0x2000 7\n");
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
        },
    )
    .expect("folded");

    assert_eq!(folded, "0x2000 7\n");
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
        },
    )
    .expect("folded");

    assert_eq!(folded, "0x2000 10\n");
}

#[test]
fn folds_mapped_user_frames_as_file_relative_addresses() {
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

    assert_eq!(folded, "/bin/app+0x10 1\n");
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

    assert_eq!(folded, "/bin/build-id-app+0x30 1\n");
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

    assert_eq!(folded, "[igb]+0x30 1\n");
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

    assert_eq!(folded, "[app] 1\n");
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

    assert_eq!(folded, "app::main;app::main 1\n");
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

    assert_eq!(folded, "app::outer;app::inner 1\n");
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

    assert_eq!(folded, "[unknown];app::outer;app::inner 1\n");
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

    assert_eq!(folded, "[libc.so.6];app::outer;app::inner 1\n");
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

    assert_eq!(folded, "[unknown];app::outer;app::inner 1\n");
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

    assert_eq!(folded, "[app] 1\n");
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

    assert_eq!(folded, "0xffffffff88000010 1\n");
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

    assert_eq!(folded, "[unknown] 1\n");
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

    assert_eq!(folded, "[unknown] 1\n");
}

#[test]
fn folds_unresolved_kernel_mappings_as_unknown_like_inferno() {
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
    let resolver = RecordingSymbolResolver::default();

    let folded = fold_perfdata_callchains_with_symbols(&bytes, FoldOptions::default(), &resolver)
        .expect("folded");

    assert_eq!(folded, "[unknown] 1\n");
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

    assert_eq!(folded, "asm_exc_page_fault 1\n");
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

    assert_eq!(folded, "zfs_read 1\n");
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

    assert_eq!(folded, "app::work;app::main 2\n");
    assert_eq!(
        resolver.calls(),
        vec![vec![
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
        ]]
    );
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
    payload.extend(abi.to_le_bytes());
    for reg in regs {
        payload.extend(reg.to_le_bytes());
    }
    payload.extend((stack.len() as u64).to_le_bytes());
    payload.extend(stack);
    payload.extend(vec![0; stack.len().next_multiple_of(8) - stack.len()]);
    payload.extend((S as u64).to_le_bytes());
    payload
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
