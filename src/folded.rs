#[must_use]
pub fn escape_frame(frame: &str) -> String {
    frame.replace(';', "\\;").replace(['\r', '\n'], " ")
}

#[must_use]
pub fn render_folded_stack<'a>(frames: impl IntoIterator<Item = &'a str>, count: u64) -> String {
    let mut rendered = String::new();
    for frame in frames {
        if !rendered.is_empty() {
            rendered.push(';');
        }
        rendered.push_str(&escape_frame(frame));
    }
    rendered.push(' ');
    rendered.push_str(&count.to_string());
    rendered
}

#[must_use]
pub fn render_inferno_perf_folded_stack<'a>(
    frames: impl IntoIterator<Item = &'a str>,
    count: u64,
) -> String {
    let mut rendered = render_inferno_perf_stack(frames);
    rendered.push(' ');
    rendered.push_str(&count.to_string());
    rendered
}

#[must_use]
pub(crate) fn render_inferno_perf_stack<'a>(frames: impl IntoIterator<Item = &'a str>) -> String {
    let mut rendered = String::new();
    for frame in frames {
        for (index, part) in frame.split("->").enumerate() {
            if !rendered.is_empty() {
                rendered.push(';');
            }
            let mut part = tidy_inferno_perf_generic(part);
            if index > 0 && !part.contains("_[i]") {
                part.push_str("_[i]");
            }
            rendered.push_str(&escape_frame(&part));
        }
    }
    rendered
}

#[must_use]
pub fn render_address_stack(frames: impl IntoIterator<Item = u64>, count: u64) -> String {
    let rendered_frames = frames
        .into_iter()
        .map(|frame| format!("0x{frame:x}"))
        .collect::<Vec<_>>();
    render_folded_stack(rendered_frames.iter().map(String::as_str), count)
}

fn tidy_inferno_perf_generic(frame: &str) -> String {
    let mut frame = frame.replace(';', ":");
    let mut bracket_depth = 0_u32;
    let mut last_dot_index = None;
    let mut length_without_parameters = frame.len();
    for (index, character) in frame.char_indices() {
        match character {
            '<' | '{' | '[' => bracket_depth += 1,
            '>' | '}' | ']' | ')' => bracket_depth = bracket_depth.saturating_sub(1),
            '(' => {
                if bracket_depth == 0 {
                    let is_go_function = last_dot_index == Some(index);
                    let is_anonymous_namespace =
                        frame[index..].starts_with("(anonymous namespace)");
                    if !is_go_function && !is_anonymous_namespace {
                        length_without_parameters = index;
                        break;
                    }
                }
                bracket_depth += 1;
            }
            '.' => last_dot_index = Some(index + 1),
            _ => {}
        }
    }
    frame.truncate(length_without_parameters);
    frame
}
