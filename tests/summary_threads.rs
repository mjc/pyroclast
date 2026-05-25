use pyroclast::summary::threads::summarize_folded_stacks;

#[test]
fn summarizes_folded_stack_counts() {
    let summary = summarize_folded_stacks("main;work 2\nmain;idle 3\n");

    assert_eq!(summary.folded_lines, 2);
    assert_eq!(summary.folded_bytes, 24);
    assert_eq!(summary.total_count, 5);
}

#[test]
fn ignores_malformed_folded_counts() {
    let summary = summarize_folded_stacks("main;work nope\nmain;idle 3\n");

    assert_eq!(summary.folded_lines, 2);
    assert_eq!(summary.total_count, 3);
}
