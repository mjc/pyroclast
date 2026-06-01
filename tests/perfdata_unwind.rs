use framehop::x86_64::Reg;
use object::{Object, ObjectSection, ObjectSegment};
use proptest::prelude::*;
use pyroclast::perfdata::unwind::{
    FramehopUnwinder, PerfStackReader, PerfX86_64Regs, unwind_x86_64_stack,
};

#[test]
fn maps_perf_x86_64_register_mask_values_by_perf_register_number() {
    let regs = PerfX86_64Regs::from_perf_masked_values(
        (1 << 6) | (1 << 7) | (1 << 8),
        &[0x7000, 0x8000, 0x9000],
    )
    .expect("registers");

    assert_eq!(regs.bp, 0x7000);
    assert_eq!(regs.sp, 0x8000);
    assert_eq!(regs.ip, 0x9000);
}

#[test]
fn maps_perf_x86_64_callee_saved_registers_for_dwarf_unwinding() {
    let regs = PerfX86_64Regs::from_perf_masked_values(
        (1 << 1) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 20),
        &[0xbbbb, 0x7000, 0x8000, 0x9000, 0x1212],
    )
    .expect("registers")
    .to_framehop_regs();

    assert_eq!(regs.get(Reg::RBX), 0xbbbb);
    assert_eq!(regs.sp(), 0x8000);
    assert_eq!(regs.ip(), 0x9000);
    assert_eq!(regs.get(Reg::R12), 0x1212);
}

#[test]
fn sampled_stack_reader_reads_little_endian_words_from_sampled_sp() {
    let stack = [
        0x10, 0, 0, 0, 0, 0, 0, 0, //
        0x20, 0, 0, 0, 0, 0, 0, 0,
    ];
    let reader = PerfStackReader::new(0x7fff_0000, &stack);

    assert_eq!(reader.read_u64(0x7fff_0000), Some(0x10));
    assert_eq!(reader.read_u64(0x7fff_0008), Some(0x20));
    assert_eq!(reader.read_u64(0x7fff_0010), None);
}

#[test]
fn unwinds_x86_64_frame_pointer_stack_from_sampled_stack_bytes() {
    let stack = [
        0, 0, 0, 0, 0, 0, 0, 0, //
        0x40, 0, 0, 0, 0, 0, 0, 0, //
        0x34, 0x12, 0, 0, 0, 0, 0, 0,
    ];
    let regs = PerfX86_64Regs {
        ip: 0x4000,
        sp: 0x7fff_0000,
        bp: 0x7fff_0008,
        registers: registers_with_bp_sp(0x7fff_0008, 0x7fff_0000),
    };

    let frames = unwind_x86_64_stack(regs, &stack, 4);

    assert_eq!(frames, vec![0x4000, 0x1233]);
}

#[test]
fn loads_framehop_module_from_object_mapping() {
    let current_exe = std::env::current_exe().expect("current exe");
    let mut unwinder = FramehopUnwinder::new();

    let loaded = unwinder
        .add_object_mapping(&current_exe, 0x5555_0000, 0x1000_0000, 0)
        .expect("load object mapping");

    assert!(loaded);
    assert_eq!(unwinder.module_count(), 1);
}

#[test]
fn reads_mapped_object_memory_outside_sampled_stack_like_perf_libdw() {
    let current_exe = std::env::current_exe().expect("current exe");
    let bytes = std::fs::read(&current_exe).expect("read object");
    let object = object::File::parse(&bytes[..]).expect("parse object");
    let segment = object
        .segments()
        .find(|segment| segment.size() >= 8 && segment.file_range().1 >= 8)
        .expect("load segment with bytes");
    let (file_offset, _) = segment.file_range();
    let file_offset_usize = usize::try_from(file_offset).expect("file offset fits usize");
    let expected = u64::from_le_bytes(
        bytes[file_offset_usize..file_offset_usize + 8]
            .try_into()
            .expect("word"),
    );
    let base = 0x5555_0000;
    let mut unwinder = FramehopUnwinder::new();

    assert!(
        unwinder
            .add_object_mapping(
                &current_exe,
                base + file_offset,
                segment.size(),
                file_offset,
            )
            .expect("load object mapping")
    );

    assert_eq!(
        unwinder.read_process_u64(base + segment.address()),
        Some(expected)
    );
}

#[test]
fn loaded_object_does_not_imply_unwind_info_for_every_address_like_perf_libdw() {
    let current_exe = std::env::current_exe().expect("current exe");
    let bytes = std::fs::read(&current_exe).expect("read object");
    let object = object::File::parse(&bytes[..]).expect("parse object");
    let data_section = object
        .sections()
        .find(|section| {
            section.size() != 0
                && matches!(section.name(), Ok(".data" | ".bss" | "__data" | "__bss"))
        })
        .expect("data section");
    let base = 0x5555_0000;
    let mut unwinder = FramehopUnwinder::new();

    assert!(
        unwinder
            .add_object_mapping(&current_exe, base, 0x1000_0000, 0)
            .expect("load object mapping")
    );
    let data_address = base + data_section.address();

    assert!(unwinder.has_reported_module_for_ip(data_address));
    assert!(!unwinder.has_unwind_info_for_ip(data_address));
}

#[test]
fn rejects_overlapping_module_base_like_dwfl_report_elf() {
    let current_exe = std::env::current_exe().expect("current exe");
    let first_start = 0x5555_0000;
    let gap = adjacent_mapping_gap_for_overlapping_module_ranges(&current_exe);
    let mut unwinder = FramehopUnwinder::new();

    let first = unwinder
        .add_object_mapping(&current_exe, first_start, gap, 0)
        .expect("load first object mapping");
    let second = unwinder
        .add_object_mapping(&current_exe, first_start + gap, gap, 0)
        .expect("load overlapping object mapping");

    assert!(first);
    assert!(!second);
    assert_eq!(unwinder.module_count(), 1);
}

#[test]
fn rejected_overlapping_module_range_does_not_unwind_through_prior_module() {
    let current_exe = std::env::current_exe().expect("current exe");
    let first_start = 0x5555_0000;
    let gap = adjacent_mapping_gap_for_overlapping_module_ranges(&current_exe);
    let mut unwinder = FramehopUnwinder::new();
    let stack = [
        0, 0, 0, 0, 0, 0, 0, 0, //
        0x40, 0, 0, 0, 0, 0, 0, 0, //
        0x34, 0x12, 0, 0, 0, 0, 0, 0,
    ];
    let regs = PerfX86_64Regs {
        ip: first_start + gap,
        sp: 0x7fff_0000,
        bp: 0x7fff_0008,
        registers: registers_with_bp_sp(0x7fff_0008, 0x7fff_0000),
    };

    assert!(
        unwinder
            .add_object_mapping(&current_exe, first_start, gap, 0)
            .expect("load first object mapping")
    );
    assert!(
        !unwinder
            .add_object_mapping(&current_exe, first_start + gap, gap, 0)
            .expect("reject overlapping object mapping")
    );

    assert_eq!(unwinder.unwind_stack(regs, &stack, 4), Vec::<u64>::new());
}

#[test]
fn overlapping_raw_mapping_keeps_prior_reported_module_like_libdw() {
    let current_exe = std::env::current_exe().expect("current exe");
    let first_start = 0x5555_0000;
    let first_len = adjacent_mapping_gap_for_overlapping_module_ranges(&current_exe) * 4;
    let second_pgoff = first_len / 2;
    let second_start = first_start + second_pgoff + 0x1000;
    let mut unwinder = FramehopUnwinder::new();

    assert!(
        unwinder
            .add_object_mapping(&current_exe, first_start, first_len, 0)
            .expect("load first object mapping")
    );

    assert!(
        !unwinder
            .add_object_mapping(&current_exe, second_start, 0x1000, second_pgoff)
            .expect("reject shifted overlapping object mapping")
    );
}

fn adjacent_mapping_gap_for_overlapping_module_ranges(path: &std::path::Path) -> u64 {
    let bytes = std::fs::read(path).expect("read object");
    let object = object::File::parse(&bytes[..]).expect("parse object");
    let range = object
        .segments()
        .filter(|segment| segment.size() != 0)
        .map(|segment| {
            let start = segment.address();
            start..start + segment.size()
        })
        .reduce(|left, right| left.start.min(right.start)..left.end.max(right.end))
        .expect("object load range");

    1_u64.max((range.end - range.start) / 2)
}

fn registers_with_bp_sp(bp: u64, sp: u64) -> [u64; 16] {
    let mut registers = [0_u64; 16];
    registers[Reg::RBP as usize] = bp;
    registers[Reg::RSP as usize] = sp;
    registers
}

proptest! {
    #[test]
    fn property_reads_little_endian_words_from_arbitrary_sampled_stack(
        sp in 0x1000_u64..0x0001_0000_0000_u64,
        words in prop::collection::vec(any::<u64>(), 0..32),
    ) {
        let stack = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let reader = PerfStackReader::new(sp, &stack);

        for (index, word) in words.iter().enumerate() {
            let address = sp + (index as u64) * 8;
            prop_assert_eq!(reader.read_u64(address), Some(*word));
        }

        prop_assert_eq!(reader.read_u64(sp + (words.len() as u64) * 8), None);
        if sp >= 8 {
            prop_assert_eq!(reader.read_u64(sp - 8), None);
        }
    }

    #[test]
    fn property_extracts_bp_sp_ip_from_perf_register_masks(
        before in prop::collection::vec(any::<u64>(), 0..6),
        bp in any::<u64>(),
        sp in any::<u64>(),
        ip in any::<u64>(),
        after in prop::collection::vec(any::<u64>(), 0..8),
    ) {
        let mut mask = 0_u64;
        let mut values = Vec::with_capacity(before.len() + after.len() + 3);

        for (register, value) in before.iter().enumerate() {
            mask |= 1_u64 << register;
            values.push(*value);
        }

        mask |= (1_u64 << 6) | (1_u64 << 7) | (1_u64 << 8);
        values.push(bp);
        values.push(sp);
        values.push(ip);

        for (register, value) in after.iter().enumerate() {
            mask |= 1_u64 << (register + 9);
            values.push(*value);
        }

        let regs = PerfX86_64Regs::from_perf_masked_values(mask, &values).expect("registers");

        prop_assert_eq!(regs.ip, ip);
        prop_assert_eq!(regs.sp, sp);
        prop_assert_eq!(regs.bp, bp);
        prop_assert_eq!(regs.registers[Reg::RBP as usize], bp);
        prop_assert_eq!(regs.registers[Reg::RSP as usize], sp);
    }

    #[test]
    fn property_rejects_register_value_count_mismatches(
        mask in any::<u64>(),
        values in prop::collection::vec(any::<u64>(), 0..32),
    ) {
        prop_assume!(mask.count_ones() as usize != values.len());

        prop_assert!(PerfX86_64Regs::from_perf_masked_values(mask, &values).is_err());
    }
}
