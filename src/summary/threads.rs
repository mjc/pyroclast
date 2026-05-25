use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FoldedStackSummary {
    pub folded_lines: usize,
    pub folded_bytes: usize,
    pub total_count: u64,
}

#[must_use]
pub fn summarize_folded_stacks(folded_stacks: &str) -> FoldedStackSummary {
    FoldedStackSummary {
        folded_lines: folded_stacks.lines().count(),
        folded_bytes: folded_stacks.len(),
        total_count: folded_stacks
            .lines()
            .filter_map(|line| line.rsplit_once(' '))
            .filter_map(|(_, count)| count.parse::<u64>().ok())
            .sum(),
    }
}

#[must_use]
pub fn render_folded_stack_summary_text(summary: FoldedStackSummary) -> String {
    format!(
        "folded lines: {}\nfolded bytes: {}\ntotal count: {}\n",
        summary.folded_lines, summary.folded_bytes, summary.total_count
    )
}
