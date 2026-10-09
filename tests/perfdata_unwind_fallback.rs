#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use framehop::x86_64::Reg;
use pyroclast::perfdata::unwind::{FramehopUnwinder, PerfUserRegs, PerfX86_64Regs};

fn registers(ip: u64, sp: u64, bp: u64) -> PerfUserRegs {
    let mut registers = [0; 16];
    registers[Reg::RSP as usize] = sp;
    registers[Reg::RBP as usize] = bp;
    PerfUserRegs::X86_64(PerfX86_64Regs {
        ip,
        sp,
        bp,
        registers,
    })
}

fn registered_object_without_cfi_at(ip: u64) -> FramehopUnwinder {
    let mut unwinder = FramehopUnwinder::new();
    assert!(
        unwinder
            .add_object_mapping(
                &std::env::current_exe().expect("test ELF"),
                ip - 1,
                0x1000_0000,
                0,
            )
            .expect("report test ELF")
    );
    assert!(unwinder.has_reported_module_for_ip(ip));
    assert!(!unwinder.has_unwind_info_for_ip(ip));
    unwinder
}

#[test]
fn missing_cfi_uses_rbp_return_slot_instead_of_sampled_sp_like_libdw() {
    // elfutils 0.195 libdwfl/frame_unwind.c:738-788 tries CFI then ebl_unwind;
    // backends/x86_64_unwind.c:48-91 reads [rbp+8], even for the initial frame.
    // perf util/unwind-libdw.c:memory_read supplies these sampled stack bytes.
    let sp = 0x7000_0000_u64;
    let ip = 0x5555_0001;
    let mut stack = [0; 48];
    stack[..8].copy_from_slice(&(sp + 8).to_le_bytes());
    stack[40..48].copy_from_slice(&0x5001_u64.to_le_bytes());
    let mut unwinder = registered_object_without_cfi_at(ip);
    assert_eq!(
        unwinder.unwind_stack(registers(ip, sp, sp + 32), &stack, 2),
        [ip, 0x5000]
    );
}

#[test]
fn missing_cfi_with_zero_rbp_stops_at_leaf_even_when_sp_contains_a_pointer() {
    // x86_64_unwind.c:54 rejects fp == 0 before reading any return slot.
    let ip = 0x5555_0001;
    let mut unwinder = registered_object_without_cfi_at(ip);
    assert_eq!(
        unwinder.unwind_stack(registers(ip, 0x7000_0000, 0), &0x5001_u64.to_le_bytes(), 2,),
        [ip]
    );
}

#[test]
fn missing_cfi_accepts_rbp_below_sp_when_caller_sp_still_advances_like_libdw() {
    // x86_64_unwind.c:63 permits a missing previous FP; its final check is
    // old_sp < fp + 16, not fp >= old_sp.
    let sp = 0x7000_0000_u64;
    let mut unwinder = FramehopUnwinder::new();
    assert_eq!(
        unwinder.unwind_stack(registers(0x4000, sp, sp - 8), &0x5001_u64.to_le_bytes(), 2),
        [0x4000, 0x5000]
    );
}

#[test]
fn covered_cfi_failure_does_not_fall_back_to_rbp_like_libdw() {
    // elfutils 0.195 libdwfl/frame_unwind.c:529-538 allocates a successor once
    // dwarf_cfi_addrframe succeeds; :578 and :641-674 leave its PC undefined
    // when RA is undefined or unrecoverable. :738-763 returns without EBL.
    // perf util/unwind-libdw.c:252-302 zero-fills unrecorded registers through
    // RIP, so the missing recorded R12 is zero. Native perf/libdw emit only
    // [0x401001] for each vector (target/native-cfi-failure-20261008/RESULTS.md).
    let root = tempfile::tempdir().expect("CFI failure fixture directory");
    let vectors = [
        (
            "MISSING_CFA_REGISTER",
            ".cfi_def_cfa %r12,8\n.cfi_offset %rip,-8",
        ),
        (
            "UNREADABLE_RA_MEMORY",
            ".cfi_def_cfa %rsp,4096\n.cfi_offset %rip,-8",
        ),
        ("UNDEFINED_RA", ".cfi_def_cfa %rsp,8\n.cfi_undefined %rip"),
    ];
    let ip = 0x0040_1001;
    let sp = 0x7000_0000;
    let mut stack = [0; 48];
    stack[40..48].copy_from_slice(&0x0040_1021_u64.to_le_bytes());
    let mut observed = Vec::new();
    for (name, cfi) in vectors {
        let source = root.path().join(format!("{name}.S"));
        let binary = root.path().join(format!("{name}.elf"));
        std::fs::write(
            &source,
            format!(
                ".text\n.globl leaf\n.type leaf,@function\nleaf:\n.cfi_startproc\n\
                 {cfi}\n.fill 16,1,0x90\nret\n.cfi_endproc\n.size leaf,.-leaf\n\
                 .p2align 5\n.globl caller\n.type caller,@function\ncaller:\n\
                 .fill 16,1,0x90\nret\n.size caller,.-caller\n\
                 .section .note.GNU-stack,\"\",@progbits\n"
            ),
        )
        .expect("write CFI failure assembly");
        let output = std::process::Command::new("cc")
            .args([
                "-nostdlib",
                "-no-pie",
                "-Wl,-e,leaf",
                "-Wl,-Ttext=0x401000",
                "-Wl,--eh-frame-hdr",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .expect("compile CFI failure fixture");
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut unwinder = FramehopUnwinder::new();
        assert!(
            unwinder
                .add_object_mapping(&binary, 0x0040_0000, 0x10000, 0)
                .expect("report CFI failure ELF"),
            "{name}"
        );
        assert!(unwinder.has_reported_module_for_ip(ip), "{name}");
        assert!(unwinder.has_unwind_info_for_ip(ip), "{name}");
        observed.push((
            name,
            unwinder.unwind_stack(registers(ip, sp, sp + 32), &stack, 2),
        ));
    }
    assert_eq!(
        observed,
        vectors.map(|(name, _)| (name, vec![ip])),
        "covered CFI must stop instead of using the readable RBP caller slot"
    );
}

fn compile_cfi_fixture(
    root: &std::path::Path,
    name: &str,
    section: &str,
    leaf: Option<&str>,
    caller: &str,
) -> std::path::PathBuf {
    compile_cfi_fixture_with_initial_cfa(root, name, section, leaf, caller, true)
}

fn compile_cfi_fixture_with_initial_cfa(
    root: &std::path::Path,
    name: &str,
    section: &str,
    leaf: Option<&str>,
    caller: &str,
    initial_cfa: bool,
) -> std::path::PathBuf {
    let source = root.join(format!("{name}.S"));
    let binary = root.join(format!("{name}.elf"));
    let simple = if initial_cfa { "" } else { " simple" };
    let leaf_start = leaf.map_or(String::new(), |cfi| {
        format!(".cfi_startproc{simple}\n{cfi}\n")
    });
    let leaf_end = if leaf.is_some() { ".cfi_endproc\n" } else { "" };
    std::fs::write(
        &source,
        format!(
            ".cfi_sections {section}\n.text\n.globl leaf\n.type leaf,@function\nleaf:\n\
             {leaf_start}.fill 16,1,0x90\nret\n{leaf_end}.size leaf,.-leaf\n\
             .p2align 5\n.globl caller\n.type caller,@function\ncaller:\n\
             .cfi_startproc\n{caller}\n.fill 16,1,0x90\nret\n.cfi_endproc\n\
             .size caller,.-caller\n.p2align 5\n.globl grandcaller\n\
             .type grandcaller,@function\ngrandcaller:\n.cfi_startproc\n\
             .cfi_undefined %rip\n.fill 16,1,0x90\nret\n.cfi_endproc\n\
             .size grandcaller,.-grandcaller\n.section .note.GNU-stack,\"\",@progbits\n"
        ),
    )
    .expect("write native-equivalent CFI fixture");
    let output = std::process::Command::new("cc")
        .args([
            "-nostdlib",
            "-no-pie",
            "-Wl,-e,leaf",
            "-Wl,-Ttext=0x401000",
            "-Wl,--eh-frame-hdr",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("compile CFI fixture");
    assert!(
        output.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

fn load_cfi_fixture(binary: &std::path::Path) -> FramehopUnwinder {
    let mut unwinder = FramehopUnwinder::new();
    assert!(
        unwinder
            .add_object_mapping(binary, 0x0040_0000, 0x10000, 0)
            .expect("report ELF")
    );
    assert!(unwinder.has_reported_module_for_ip(0x0040_1001));
    assert!(unwinder.has_unwind_info_for_ip(0x0040_1001));
    unwinder
}

fn registers_with_r12(r12: u64) -> PerfUserRegs {
    let PerfUserRegs::X86_64(mut regs) = registers(0x0040_1001, 0x7000_0000, 0x7000_0020) else {
        unreachable!()
    };
    regs.registers[Reg::R12 as usize] = r12;
    PerfUserRegs::X86_64(regs)
}

#[test]
fn recorded_r12_cfa_uses_cfi_in_both_sample_orders_and_sections() {
    // Native perf/libdw: extended/RESULTS.md, SINGLE_R12 in both orders.
    // frame_unwind.c:529-675 evaluates the row against this sample's registers.
    let root = tempfile::tempdir().expect("fixtures");
    let mut stack = [0; 64];
    stack[8..16].copy_from_slice(&0x0040_1021_u64.to_le_bytes());
    stack[40..48].copy_from_slice(&0x6001_u64.to_le_bytes());
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for section in [".eh_frame", ".debug_frame"] {
        let binary = compile_cfi_fixture(
            root.path(),
            section,
            section,
            Some(".cfi_def_cfa %r12,8\n.cfi_offset %rip,-8"),
            ".cfi_undefined %rip",
        );
        for order in [[0, 0x7000_0008], [0x7000_0008, 0]] {
            let mut unwinder = load_cfi_fixture(&binary);
            for r12 in order {
                actual.push((
                    section,
                    r12,
                    unwinder.unwind_stack(registers_with_r12(r12), &stack, 4),
                ));
                expected.push((
                    section,
                    r12,
                    if r12 == 0 {
                        vec![0x0040_1001]
                    } else {
                        vec![0x0040_1001, 0x0040_1020]
                    },
                ));
            }
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn dwarf_recovers_caller_registers_without_reusing_undefined_values() {
    // x86_64_cfi.c:39-61 supplies native ABI defaults; frame_unwind.c:566-638
    // recovers each caller register independently, including definedness.
    let root = tempfile::tempdir().expect("fixtures");
    let mut stack = [0; 64];
    stack[..8].copy_from_slice(&0x7000_0018_u64.to_le_bytes());
    stack[8..16].copy_from_slice(&0x0040_1021_u64.to_le_bytes());
    stack[24..32].copy_from_slice(&0x0040_1041_u64.to_le_bytes());
    stack[40..48].copy_from_slice(&0x6001_u64.to_le_bytes());
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for section in [".eh_frame", ".debug_frame"] {
        for (name, rule, r12, count) in [
            ("restore", ".cfi_offset %r12,-16", 0x7000_0008, 3),
            ("same", ".cfi_same_value %r12", 0x7000_0018, 3),
            ("undefined", ".cfi_undefined %r12", 0x7000_0008, 2),
        ] {
            let leaf = format!(".cfi_def_cfa %rsp,16\n.cfi_offset %rip,-8\n{rule}");
            let binary = compile_cfi_fixture(
                root.path(),
                &format!("{section}-{name}"),
                section,
                Some(&leaf),
                ".cfi_def_cfa %r12,8\n.cfi_offset %rip,-8",
            );
            actual.push((
                section,
                name,
                load_cfi_fixture(&binary).unwind_stack(registers_with_r12(r12), &stack, 4),
            ));
            expected.push((
                section,
                name,
                vec![0x0040_1001, 0x0040_1020, 0x0040_1040][..count].to_vec(),
            ));
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn dwarf_expressions_and_register_ra_use_recorded_registers() {
    // Native CFA_EXPRESSION/CFA_MEMORY_EXPRESSION/RA_REGISTER controls, plus
    // UNREADABLE_CFA_VALID_RA: an unavailable CFA need not make RA unavailable.
    let root = tempfile::tempdir().expect("fixtures");
    let mut stack = [0; 64];
    stack[..8].copy_from_slice(&0x7000_0010_u64.to_le_bytes());
    stack[8..16].copy_from_slice(&0x0040_1021_u64.to_le_bytes());
    stack[40..48].copy_from_slice(&0x6001_u64.to_le_bytes());
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for section in [".eh_frame", ".debug_frame"] {
        for (name, leaf, r12) in [
            (
                "expression",
                ".cfi_escape 0x0f,0x02,0x7c,0x08\n.cfi_offset %rip,-8",
                0x7000_0008,
            ),
            (
                "memory",
                ".cfi_escape 0x0f,0x03,0x7c,0x00,0x06\n.cfi_offset %rip,-8",
                0x7000_0000,
            ),
            (
                "register",
                ".cfi_def_cfa %rsp,16\n.cfi_register %rip,%r12",
                0x0040_1021,
            ),
            (
                "unreadable-cfa",
                ".cfi_escape 0x0f,0x03,0x7d,0x00,0x06\n.cfi_register %rip,%r12",
                0x0040_1021,
            ),
        ] {
            let binary = compile_cfi_fixture(
                root.path(),
                &format!("{section}-{name}"),
                section,
                Some(leaf),
                ".cfi_undefined %rip",
            );
            actual.push((
                section,
                name,
                load_cfi_fixture(&binary).unwind_stack(registers_with_r12(r12), &stack, 4),
            ));
            expected.push((section, name, vec![0x0040_1001, 0x0040_1020]));
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn dwarf_accepts_missing_recorded_bp_like_perf_libdw() {
    // perf unwind-libdw.c:252-302 seeds omitted BP as zero, not unavailable.
    // Native entry-requirements/RESULTS.md proves both RSP and R12 CFA cases.
    let regs = PerfX86_64Regs::from_perf_masked_values(
        (1 << 7) | (1 << 8) | (1 << 20),
        &[0x7000_0000, 0x0040_1001, 0x7000_0008],
    )
    .expect("missing BP is valid for CFI");
    assert_eq!(regs.bp, 0);
    assert_eq!(regs.registers[Reg::RBP as usize], 0);
    let root = tempfile::tempdir().expect("fixtures");
    let mut stack = [0; 32];
    stack[..8].copy_from_slice(&0x0040_1021_u64.to_le_bytes());
    stack[8..16].copy_from_slice(&0x0040_1021_u64.to_le_bytes());
    for section in [".eh_frame", ".debug_frame"] {
        for register in ["rsp", "r12"] {
            let leaf = format!(".cfi_def_cfa %{register},8\n.cfi_offset %rip,-8");
            let binary = compile_cfi_fixture(
                root.path(),
                &format!("{section}-{register}"),
                section,
                Some(&leaf),
                ".cfi_undefined %rip",
            );
            assert_eq!(
                load_cfi_fixture(&binary).unwind_stack(PerfUserRegs::X86_64(regs), &stack, 4),
                [0x0040_1001, 0x0040_1020]
            );
        }
    }
}

#[test]
fn eh_row_failure_stops_but_missing_eh_row_uses_debug_cfi() {
    // Native extended/priority.sh: a decoded EH row blocks debug retry;
    // an absent EH row permits debug CFI (frame_unwind.c:738-763).
    let root = tempfile::tempdir().expect("fixtures");
    let debug = compile_cfi_fixture(
        root.path(),
        "debug",
        ".debug_frame",
        Some(".cfi_def_cfa %rsp,8\n.cfi_offset %rip,-8"),
        ".cfi_undefined %rip",
    );
    let debug_section = root.path().join("debug.section");
    let output = std::process::Command::new("objcopy")
        .arg("--dump-section")
        .arg(format!(".debug_frame={}", debug_section.display()))
        .arg(debug)
        .output()
        .expect("extract debug CFI");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut actual = Vec::new();
    for (name, leaf) in [
        ("covered", Some(".cfi_def_cfa %r12,8\n.cfi_offset %rip,-8")),
        ("uncovered", None),
    ] {
        let eh = compile_cfi_fixture(root.path(), name, ".eh_frame", leaf, ".cfi_undefined %rip");
        let combined = root.path().join(format!("{name}-combined.elf"));
        let output = std::process::Command::new("objcopy")
            .arg("--add-section")
            .arg(format!(".debug_frame={}", debug_section.display()))
            .arg(eh)
            .arg(&combined)
            .output()
            .expect("combine CFI sections");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        actual.push(load_cfi_fixture(&combined).unwind_stack(
            registers_with_r12(0),
            &0x0040_1021_u64.to_le_bytes(),
            4,
        ));
    }
    assert_eq!(actual, [vec![0x0040_1001], vec![0x0040_1001, 0x0040_1020]]);
}

#[test]
fn register_expressions_start_with_cfa_and_preserve_location_semantics_like_libdw() {
    // dwarf_frame_register.c:122-129 requests a CFA prefix for both expression
    // kinds; dwarf_getlocation.c:313-321 synthesizes DW_OP_call_frame_cfa.
    // frame_unwind.c:465-500 dereferences locations but not stack values.
    // Native perf/libdw controls: native-cfi-failure-20261008/cfa-seeded.
    let root = tempfile::tempdir().expect("fixtures");
    let mut stack = [0; 64];
    stack[8..16].copy_from_slice(&0x0040_1021_u64.to_le_bytes());
    stack[40..48].copy_from_slice(&0x6001_u64.to_le_bytes());
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for section in [".eh_frame", ".debug_frame"] {
        for (name, cfi, r12, caller) in [
            (
                "location-cfa",
                ".cfi_escape 0x10,0x10,0x02,0x38,0x1c",
                0x7000_0008,
                true,
            ),
            (
                "value-cfa",
                ".cfi_escape 0x16,0x10,0x03,0x38,0x1c,0x06",
                0x7000_0008,
                true,
            ),
            (
                "location-register",
                ".cfi_escape 0x10,0x10,0x01,0x5c",
                0x7000_0008,
                true,
            ),
            (
                "value-register",
                ".cfi_escape 0x16,0x10,0x01,0x5c",
                0x0040_1021,
                true,
            ),
            (
                "location-no-cfa",
                ".cfi_escape 0x0f,0x03,0x7d,0x00,0x06\n.cfi_escape 0x10,0x10,0x02,0x7c,0x00",
                0x7000_0008,
                false,
            ),
            (
                "value-no-cfa",
                ".cfi_escape 0x0f,0x03,0x7d,0x00,0x06\n.cfi_escape 0x16,0x10,0x02,0x7c,0x00",
                0x0040_1021,
                false,
            ),
        ] {
            let leaf = format!(".cfi_def_cfa %rsp,16\n{cfi}");
            let binary = compile_cfi_fixture(
                root.path(),
                &format!("{section}-{name}"),
                section,
                Some(&leaf),
                ".cfi_undefined %rip",
            );
            actual.push((
                section,
                name,
                load_cfi_fixture(&binary).unwind_stack(registers_with_r12(r12), &stack, 4),
            ));
            expected.push((
                section,
                name,
                if caller {
                    vec![0x0040_1001, 0x0040_1020]
                } else {
                    vec![0x0040_1001]
                },
            ));
        }
    }
    assert_eq!(actual, expected);
}

fn native_register_case(number: usize, value: u64) -> PerfUserRegs {
    let mut dwarf = [0; 17];
    dwarf[6] = 0x7000_0020;
    dwarf[7] = 0x7000_0000;
    dwarf[16] = 0x0040_1001;
    if number != 7 && number != 16 {
        dwarf[number] = value;
    }
    // Ascending perf mask order, deliberately distinct from DWARF order.
    let values =
        [0, 3, 2, 1, 4, 5, 6, 7, 16, 8, 9, 10, 11, 12, 13, 14, 15].map(|index| dwarf[index]);
    PerfUserRegs::X86_64(
        PerfX86_64Regs::from_perf_masked_values(0xff_01ff, &values).expect("17 native registers"),
    )
}

#[test]
fn cfa_can_read_all_seventeen_recorded_x86_registers() {
    // Native all-registers/RESULTS.md: 17 initial-CFA vectors, including RIP
    // with a linked-IP-relative CFA offset. Both sections share the evaluator.
    let root = tempfile::tempdir().expect("fixtures");
    let mut stack = [0; 64];
    stack[..8].copy_from_slice(&0x0040_1021_u64.to_le_bytes());
    stack[8..16].copy_from_slice(&0x0040_1021_u64.to_le_bytes());
    for section in [".eh_frame", ".debug_frame"] {
        for number in 0..17 {
            let offset = if number == 16 { 0x6fbf_f00f } else { 8 };
            let leaf = format!(".cfi_def_cfa {number},{offset}\n.cfi_offset %rip,-8");
            let binary = compile_cfi_fixture(
                root.path(),
                &format!("{section}-{number}"),
                section,
                Some(&leaf),
                ".cfi_undefined %rip",
            );
            assert_eq!(
                load_cfi_fixture(&binary).unwind_stack(
                    native_register_case(number, 0x7000_0008),
                    &stack,
                    4
                ),
                [0x0040_1001, 0x0040_1020],
                "{section} register {number}"
            );
        }
    }
}

#[test]
fn caller_register_defaults_and_saved_values_match_native_libdw() {
    // backends/x86_64_cfi.c:39-61 and native all-registers/RESULTS.md.
    // Native preserves numeric register 0, not register 3; unspecified
    // volatile registers must not leak initial values into the next row.
    let root = tempfile::tempdir().expect("fixtures");
    let mut stack = [0; 64];
    stack[..8].copy_from_slice(&0x7000_0018_u64.to_le_bytes());
    stack[8..16].copy_from_slice(&0x0040_1021_u64.to_le_bytes());
    stack[16..24].copy_from_slice(&0x0040_1041_u64.to_le_bytes());
    stack[24..32].copy_from_slice(&0x0040_1041_u64.to_le_bytes());
    stack[40..48].copy_from_slice(&0x6001_u64.to_le_bytes());
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for section in [".eh_frame", ".debug_frame"] {
        for restore in [false, true] {
            for number in 0..16 {
                if restore && number == 7 {
                    continue;
                }
                let saved = if restore {
                    format!(".cfi_offset {number},-16\n")
                } else {
                    String::new()
                };
                let leaf = format!(".cfi_def_cfa %rsp,16\n{saved}.cfi_offset %rip,-8");
                let caller = format!(".cfi_def_cfa {number},8\n.cfi_offset %rip,-8");
                let binary = compile_cfi_fixture(
                    root.path(),
                    &format!("{section}-{restore}-{number}"),
                    section,
                    Some(&leaf),
                    &caller,
                );
                actual.push((
                    section,
                    restore,
                    number,
                    load_cfi_fixture(&binary).unwind_stack(
                        native_register_case(number, 0x7000_0018),
                        &stack,
                        4,
                    ),
                ));
                let count = if restore || matches!(number, 0 | 6 | 7 | 12..=15) {
                    3
                } else {
                    2
                };
                expected.push((
                    section,
                    restore,
                    number,
                    vec![0x0040_1001, 0x0040_1020, 0x0040_1040][..count].to_vec(),
                ));
            }
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn unspecified_cfa_does_not_become_explicit_zero_cfa_like_libdw() {
    // Native unspecified-cfa/RESULTS.md: libdw keeps an absent/restored CFA
    // undefined, but accepts explicit RAX+0. frame_unwind.c:566-638 still
    // recovers RA from R12 and only leaves CFA-dependent registers undefined.
    let root = tempfile::tempdir().expect("fixtures");
    let mut stack = [0; 64];
    stack[24..32].copy_from_slice(&0x0040_1041_u64.to_le_bytes());
    stack[40..48].copy_from_slice(&0x6001_u64.to_le_bytes());
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for section in [".eh_frame", ".debug_frame"] {
        for (name, cfa, count) in [
            ("unspecified", "", 2),
            ("explicit-zero", ".cfi_def_cfa %rax,0", 3),
            (
                "restored-undefined",
                ".cfi_remember_state\n.cfi_def_cfa %rsp,16\n.cfi_restore_state",
                2,
            ),
        ] {
            let leaf = format!("{cfa}\n.cfi_register %rip,%r12");
            let binary = compile_cfi_fixture_with_initial_cfa(
                root.path(),
                &format!("{section}-{name}"),
                section,
                Some(&leaf),
                ".cfi_def_cfa %rsp,0x70000020\n.cfi_offset %rip,-8",
                false,
            );
            actual.push((
                section,
                name,
                load_cfi_fixture(&binary).unwind_stack(registers_with_r12(0x0040_1021), &stack, 4),
            ));
            expected.push((
                section,
                name,
                vec![0x0040_1001, 0x0040_1020, 0x0040_1040][..count].to_vec(),
            ));
        }
    }
    assert_eq!(actual, expected);
}

fn native_expression_policy_vectors() -> [(&'static str, &'static str, u64, bool); 12] {
    [
        (
            "reg-plus",
            ".cfi_escape 0x0f,0x03,0x5c,0x23,0x08",
            0x7000_0008,
            true,
        ),
        (
            "regx-plus",
            ".cfi_escape 0x0f,0x04,0x90,0x0c,0x23,0x08",
            0x7000_0008,
            true,
        ),
        (
            "breg-control",
            ".cfi_escape 0x0f,0x02,0x7c,0x08",
            0x7000_0008,
            true,
        ),
        (
            "ra-reg-plus",
            ".cfi_escape 0x10,0x10,0x03,0x5c,0x23,0x00",
            0x7000_0008,
            true,
        ),
        (
            "ra-stack-continue",
            ".cfi_escape 0x10,0x10,0x05,0x7c,0x00,0x9f,0x23,0x00",
            0x0040_1021,
            true,
        ),
        (
            "value-stack-continue",
            ".cfi_escape 0x16,0x10,0x05,0x7c,0x00,0x9f,0x23,0x00",
            0x0040_1021,
            true,
        ),
        (
            "cfa-stack-continue",
            ".cfi_escape 0x0f,0x04,0x7c,0x08,0x9f,0x96",
            0x7000_0008,
            true,
        ),
        (
            "valid-branch",
            ".cfi_escape 0x0f,0x07,0x2f,0x02,0x00,0x10,0x00,0x7c,0x08",
            0x7000_0008,
            true,
        ),
        (
            "middle-branch",
            ".cfi_escape 0x0f,0x05,0x2f,0x01,0x00,0x7c,0x08",
            0x7000_0008,
            false,
        ),
        (
            "end-branch",
            ".cfi_escape 0x0f,0x05,0x2f,0x02,0x00,0x7c,0x08",
            0x7000_0008,
            false,
        ),
        (
            "unsupported",
            ".cfi_escape 0x0f,0x01,0x97",
            0x7000_0008,
            false,
        ),
        (
            "unavailable-register",
            ".cfi_escape 0x0f,0x03,0x61,0x23,0x08",
            0x7000_0008,
            false,
        ),
    ]
}

#[test]
fn cfi_expressions_use_native_register_stack_value_and_branch_policy() {
    // Native expression-policy/{fixture.S,run.sh}: 24 perf/libdw vectors.
    // frame_unwind.c:202-216 pushes regN/regx without terminating; :430-450
    // requires branches to land on decoded operations; :469-472 makes
    // stack_value a continuing location/value flag, not a terminal location.
    let root = tempfile::tempdir().expect("fixtures");
    let mut stack = [0; 64];
    stack[8..16].copy_from_slice(&0x0040_1021_u64.to_le_bytes());
    stack[40..48].copy_from_slice(&0x6001_u64.to_le_bytes());
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for section in [".eh_frame", ".debug_frame"] {
        for (name, cfi, r12, caller) in native_expression_policy_vectors() {
            let leaf = format!(".cfi_def_cfa %rsp,16\n.cfi_offset %rip,-8\n{cfi}");
            let binary = compile_cfi_fixture(
                root.path(),
                &format!("{section}-{name}"),
                section,
                Some(&leaf),
                ".cfi_undefined %rip",
            );
            actual.push((
                section,
                name,
                load_cfi_fixture(&binary).unwind_stack(registers_with_r12(r12), &stack, 4),
            ));
            expected.push((
                section,
                name,
                if caller {
                    vec![0x0040_1001, 0x0040_1020]
                } else {
                    vec![0x0040_1001]
                },
            ));
        }
    }
    assert_eq!(actual, expected);
}
