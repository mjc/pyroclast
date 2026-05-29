use proptest::prelude::*;
use proptest::string::string_regex;
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

proptest! {
    #[test]
    fn property_summarizes_valid_folded_lines(
        records in prop::collection::vec((folded_stack(), bounded_count()), 0..64),
    ) {
        let input = records
            .iter()
            .map(|(stack, count)| format!("{stack} {count}"))
            .collect::<Vec<_>>()
            .join("\n");
        let summary = summarize_folded_stacks(&input);
        let mut expected = records
            .iter()
            .map(|(stack, count)| (stack.clone(), *count))
            .collect::<Vec<_>>();
        expected.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

        prop_assert_eq!(summary.folded_lines, records.len());
        prop_assert_eq!(summary.folded_bytes, input.len());
        prop_assert_eq!(
            summary.total_count,
            records.iter().map(|(_, count)| *count).sum::<u64>()
        );
        prop_assert_eq!(summary.top_stacks.len(), expected.len());

        for (actual, (stack, count)) in summary.top_stacks.iter().zip(expected) {
            prop_assert_eq!(&actual.stack, &stack);
            prop_assert_eq!(actual.count, count);
        }
    }

    #[test]
    fn property_ignores_malformed_counts_but_keeps_line_statistics(
        lines in prop::collection::vec(folded_line(), 0..64),
    ) {
        let input = lines
            .iter()
            .map(FoldedLine::render)
            .collect::<Vec<_>>()
            .join("\n");
        let summary = summarize_folded_stacks(&input);
        let mut expected = lines
            .iter()
            .filter_map(|line| match line {
                FoldedLine::Valid { stack, count } => Some((stack.clone(), *count)),
                FoldedLine::Malformed(_) => None,
            })
            .collect::<Vec<_>>();
        expected.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

        prop_assert_eq!(summary.folded_lines, lines.len());
        prop_assert_eq!(summary.folded_bytes, input.len());
        prop_assert_eq!(
            summary.total_count,
            expected.iter().map(|(_, count)| *count).sum::<u64>()
        );
        prop_assert_eq!(summary.top_stacks.len(), expected.len());

        for (actual, (stack, count)) in summary.top_stacks.iter().zip(expected) {
            prop_assert_eq!(&actual.stack, &stack);
            prop_assert_eq!(actual.count, count);
        }
    }
}

#[derive(Clone, Debug)]
enum FoldedLine {
    Valid { stack: String, count: u64 },
    Malformed(String),
}

impl FoldedLine {
    fn render(&self) -> String {
        match self {
            Self::Valid { stack, count } => format!("{stack} {count}"),
            Self::Malformed(line) => line.clone(),
        }
    }
}

fn folded_line() -> impl Strategy<Value = FoldedLine> {
    prop_oneof![
        (folded_stack(), bounded_count())
            .prop_map(|(stack, count)| FoldedLine::Valid { stack, count }),
        folded_stack().prop_map(|stack| FoldedLine::Malformed(format!("{stack} nope"))),
        folded_stack().prop_map(FoldedLine::Malformed),
    ]
}

fn folded_stack() -> impl Strategy<Value = String> {
    prop::collection::vec(frame_name(), 1..5).prop_map(|frames| frames.join(";"))
}

fn frame_name() -> impl Strategy<Value = String> {
    string_regex(r"[A-Za-z_][A-Za-z0-9_:]{0,11}").expect("valid folded frame regex")
}

fn bounded_count() -> impl Strategy<Value = u64> {
    (0_u32..1_000_000_u32).prop_map(u64::from)
}
