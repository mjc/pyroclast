use crate::folded::render_folded_stack;

pub fn collapse_offcpu(input: &str) -> Vec<String> {
    let mut collapsed = Vec::new();
    let mut frames: Option<Vec<String>> = None;

    for line in input.lines() {
        if line.starts_with("@offcpu[") {
            frames = Some(Vec::new());
            continue;
        }

        let Some(current) = frames.as_mut() else {
            continue;
        };

        if let Some(count) = parse_count(line) {
            if !current.is_empty() {
                current.reverse();
                collapsed.push(render_folded_stack(
                    current.iter().map(String::as_str),
                    count,
                ));
            }
            frames = None;
            continue;
        }

        if line.starts_with(char::is_whitespace) {
            if let Some(frame) = parse_frame(line) {
                current.push(frame.to_string());
            }
        }
    }

    collapsed
}

fn parse_count(line: &str) -> Option<u64> {
    line.trim().strip_prefix("]:")?.trim().parse().ok()
}

fn parse_frame(line: &str) -> Option<&str> {
    let (_, frame) = line.trim().split_once(' ')?;
    let frame = frame.trim();
    let frame = frame
        .rfind(" (")
        .filter(|_| frame.ends_with(')'))
        .map(|idx| &frame[..idx])
        .unwrap_or(frame);
    let frame = frame
        .rfind('+')
        .filter(|idx| frame[*idx + 1..].chars().all(|ch| ch.is_ascii_digit()))
        .map(|idx| &frame[..idx])
        .unwrap_or(frame);
    if frame.is_empty() || frame.ends_with("([unknown])") {
        None
    } else {
        Some(frame)
    }
}
