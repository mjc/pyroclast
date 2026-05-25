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

#[test]
fn summarizes_hottest_folded_stacks() {
    let summary = summarize_folded_stacks("main;small 2\nmain;hot 9\nmain;mid 5\n");

    assert_eq!(summary.top_stacks.len(), 3);
    assert_eq!(summary.top_stacks[0].stack, "main;hot");
    assert_eq!(summary.top_stacks[0].count, 9);
    assert_eq!(summary.top_stacks[1].stack, "main;mid");
    assert_eq!(summary.top_stacks[1].count, 5);
    assert_eq!(summary.top_stacks[2].stack, "main;small");
    assert_eq!(summary.top_stacks[2].count, 2);
}
