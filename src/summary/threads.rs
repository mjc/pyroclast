use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TopFoldedStack {
    pub stack: String,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FoldedStackSummary {
    pub folded_lines: usize,
    pub folded_bytes: usize,
    pub total_count: u64,
    pub top_stacks: Vec<TopFoldedStack>,
}

#[must_use]
pub fn summarize_folded_stacks(folded_stacks: &str) -> FoldedStackSummary {
    let mut parsed_stacks = folded_stacks
        .lines()
        .filter_map(parse_folded_line)
        .map(|(stack, count)| TopFoldedStack {
            stack: stack.to_string(),
            count,
        })
        .collect::<Vec<_>>();
    parsed_stacks.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.stack.cmp(&right.stack))
    });

    FoldedStackSummary {
        folded_lines: folded_stacks.lines().count(),
        folded_bytes: folded_stacks.len(),
        total_count: parsed_stacks.iter().map(|stack| stack.count).sum(),
        top_stacks: parsed_stacks,
    }
}

#[must_use]
pub fn render_folded_stack_summary_text(summary: &FoldedStackSummary) -> String {
    format!(
        "folded lines: {}\nfolded bytes: {}\ntotal count: {}\n",
        summary.folded_lines, summary.folded_bytes, summary.total_count
    )
}

fn parse_folded_line(line: &str) -> Option<(&str, u64)> {
    let (stack, count) = line.rsplit_once(' ')?;
    Some((stack, count.parse().ok()?))
}
