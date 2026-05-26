use pyroclast::perfdata::unwind::{PerfStackReader, PerfX86_64Regs};

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
