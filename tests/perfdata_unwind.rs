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

        prop_assert_eq!(
            PerfX86_64Regs::from_perf_masked_values(mask, &values).expect("registers"),
            PerfX86_64Regs { ip, sp, bp }
        );
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
