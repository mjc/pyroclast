use std::fmt::Write;

#[must_use]
pub fn escape_frame(frame: &str) -> String {
    let mut escaped = String::with_capacity(frame.len());
    escape_frame_into(&mut escaped, frame);
    escaped
}

#[must_use]
pub fn render_folded_stack<'a>(frames: impl IntoIterator<Item = &'a str>, count: u64) -> String {
    let mut rendered = String::new();
    render_folded_stack_into(&mut rendered, frames);
    write!(&mut rendered, " {count}").expect("writing to a string cannot fail");
    rendered
}

#[must_use]
pub fn render_inferno_perf_folded_stack<'a>(
    frames: impl IntoIterator<Item = &'a str>,
    count: u64,
) -> String {
    let mut rendered = render_inferno_perf_stack(frames);
    write!(&mut rendered, " {count}").expect("writing to a string cannot fail");
    rendered
}

#[must_use]
pub(crate) fn render_inferno_perf_stack<'a>(frames: impl IntoIterator<Item = &'a str>) -> String {
    let mut rendered = String::new();
    let mut scratch = String::new();
    render_inferno_perf_stack_into(&mut rendered, frames, &mut scratch);
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

pub(crate) fn render_inferno_perf_stack_into<'a>(
    rendered: &mut String,
    frames: impl IntoIterator<Item = &'a str>,
    scratch: &mut String,
) {
    rendered.clear();
    for frame in frames {
        append_inferno_perf_frame(rendered, frame, scratch);
    }
}

pub(crate) fn append_inferno_perf_frame(rendered: &mut String, frame: &str, scratch: &mut String) {
    for (index, part) in frame.split("->").enumerate() {
        if !rendered.is_empty() {
            rendered.push(';');
        }
        tidy_inferno_perf_generic_into(scratch, part);
        if index > 0 && !scratch.contains("_[i]") {
            scratch.push_str("_[i]");
        }
        escape_frame_into(rendered, scratch);
    }
}

fn render_folded_stack_into<'a>(rendered: &mut String, frames: impl IntoIterator<Item = &'a str>) {
    rendered.clear();
    for frame in frames {
        if !rendered.is_empty() {
            rendered.push(';');
        }
        escape_frame_into(rendered, frame);
    }
}

fn tidy_inferno_perf_generic_into(scratch: &mut String, frame: &str) {
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
    scratch.clear();
    scratch.reserve(length_without_parameters);
    for character in frame[..length_without_parameters].chars() {
        if character == ';' {
            scratch.push(':');
        } else {
            scratch.push(character);
        }
    }
}

fn escape_frame_into(escaped: &mut String, frame: &str) {
    for character in frame.chars() {
        match character {
            ';' => escaped.push_str("\\;"),
            '\r' | '\n' => escaped.push(' '),
            _ => escaped.push(character),
        }
    }
}
