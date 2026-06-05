use std::borrow::Cow;
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
    let mut rendered = render_inferno_perf_raw_stack(frames);
    write!(&mut rendered, " {count}").expect("writing to a string cannot fail");
    rendered
}

#[must_use]
pub(crate) fn render_inferno_perf_raw_stack<'a>(
    frames: impl IntoIterator<Item = &'a str>,
) -> String {
    let mut rendered = String::new();
    let mut scratch = String::new();
    render_inferno_perf_raw_stack_into(&mut rendered, frames, &mut scratch);
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

pub(crate) fn render_inferno_perf_raw_stack_into<'a>(
    rendered: &mut String,
    frames: impl IntoIterator<Item = &'a str>,
    scratch: &mut String,
) {
    rendered.clear();
    for frame in frames {
        append_inferno_perf_raw_function(rendered, frame, scratch);
    }
}

pub(crate) fn append_inferno_perf_raw_function(
    rendered: &mut String,
    mut frame: &str,
    scratch: &mut String,
) {
    if let Some(offset) = frame.rfind("+0x") {
        let suffix = &frame[offset + 3..];
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_hexdigit()) {
            frame = &frame[..offset];
        }
    }
    if frame.starts_with('(') {
        return;
    }
    let fixed_frame = fix_partially_demangled_rust_symbol(frame);
    for (index, part) in fixed_frame.as_ref().split("->").enumerate() {
        append_separator(rendered);
        tidy_inferno_perf_generic_into(scratch, part);
        if index > 0 && !scratch.contains("_[i]") {
            scratch.push_str("_[i]");
        }
        escape_frame_into(rendered, scratch);
    }
}

fn fix_partially_demangled_rust_symbol(symbol: &str) -> Cow<'_, str> {
    const RUST_HASH_LENGTH: usize = 17;

    let is_rust_hash =
        |value: &str| value.starts_with('h') && value[1..].chars().all(|c| c.is_ascii_hexdigit());

    if symbol.len() < RUST_HASH_LENGTH || !is_rust_hash(&symbol[symbol.len() - RUST_HASH_LENGTH..])
    {
        return Cow::Borrowed(symbol);
    }

    let mut rest = &symbol[..symbol.len() - RUST_HASH_LENGTH];
    if rest.ends_with("::") {
        rest = &rest[..rest.len() - 2];
    }
    if rest.starts_with("_$") {
        rest = &rest[1..];
    }

    let mut demangled = String::new();
    while !rest.is_empty() {
        if let Some(after_dot) = rest.strip_prefix('.') {
            if let Some(after_double_dot) = after_dot.strip_prefix('.') {
                demangled.push_str("::");
                rest = after_double_dot;
            } else {
                demangled.push('.');
                rest = after_dot;
            }
        } else if rest.starts_with('$') {
            if let Some((encoded, decoded)) = rust_symbol_escape(rest) {
                demangled.push_str(decoded);
                rest = &rest[encoded.len()..];
            } else {
                demangled.push_str(rest);
                break;
            }
        } else {
            let next_escape = rest
                .char_indices()
                .find(|&(_, character)| character == '$' || character == '.')
                .map_or(rest.len(), |(index, _)| index);
            demangled.push_str(&rest[..next_escape]);
            rest = &rest[next_escape..];
        }
    }

    Cow::Owned(demangled)
}

fn rust_symbol_escape(rest: &str) -> Option<(&'static str, &'static str)> {
    [
        ("$SP$", "@"),
        ("$BP$", "*"),
        ("$RF$", "&"),
        ("$LT$", "<"),
        ("$GT$", ">"),
        ("$LP$", "("),
        ("$RP$", ")"),
        ("$C$", ","),
        ("$u7e$", "~"),
        ("$u20$", " "),
        ("$u27$", "'"),
        ("$u3d$", "="),
        ("$u5b$", "["),
        ("$u5d$", "]"),
        ("$u7b$", "{"),
        ("$u7d$", "}"),
        ("$u3b$", ";"),
        ("$u2b$", "+"),
        ("$u21$", "!"),
        ("$u22$", "\""),
    ]
    .into_iter()
    .find(|(encoded, _)| rest.starts_with(encoded))
}

pub(crate) fn append_inferno_perf_folded_label(rendered: &mut String, frame: &str) {
    append_separator(rendered);
    escape_frame_into(rendered, frame);
}

#[must_use]
pub(crate) fn render_inferno_perf_folded_label(frame: &str) -> String {
    let mut rendered = String::new();
    append_inferno_perf_folded_label(&mut rendered, frame);
    rendered
}

fn render_folded_stack_into<'a>(rendered: &mut String, frames: impl IntoIterator<Item = &'a str>) {
    rendered.clear();
    for frame in frames {
        append_separator(rendered);
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

fn append_separator(rendered: &mut String) {
    if !rendered.is_empty() {
        rendered.push(';');
    }
}
