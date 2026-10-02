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
    let mut has_segment = false;
    for frame in frames {
        has_segment |= append_inferno_perf_raw_function(rendered, frame, scratch, has_segment);
    }
}

pub(crate) fn append_inferno_perf_raw_function(
    rendered: &mut String,
    mut frame: &str,
    scratch: &mut String,
    has_prefix: bool,
) -> bool {
    if let Some(offset) = memchr::memrchr(b'+', frame.as_bytes())
        && frame[offset..].starts_with("+0x")
    {
        let suffix = &frame[offset + 3..];
        if suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            frame = &frame[..offset];
        }
    }
    if frame.starts_with('(') {
        return false;
    }
    // Inferno perf.rs:on_stack_line fixes Rust hashes before any tidy fast path.
    let fixed_frame = fix_partially_demangled_rust_symbol(frame);
    let frame = fixed_frame.as_ref();
    if memchr::memchr3(b'$', b'(', b';', frame.as_bytes()).is_none()
        && memchr::memchr2(b'\n', b'\r', frame.as_bytes()).is_none()
        && !frame.contains("->")
    {
        append_separator(rendered, has_prefix);
        rendered.push_str(frame);
        return true;
    }
    for (index, part) in frame.split("->").enumerate() {
        append_separator(rendered, has_prefix || index != 0);
        tidy_inferno_perf_generic_into(scratch, part);
        if index > 0 && !scratch.contains("_[i]") {
            scratch.push_str("_[i]");
        }
        escape_frame_into(rendered, scratch);
    }
    true
}

fn fix_partially_demangled_rust_symbol(symbol: &str) -> Cow<'_, str> {
    const RUST_HASH_LENGTH: usize = 17;

    let Some(hash_start) = symbol.len().checked_sub(RUST_HASH_LENGTH) else {
        return Cow::Borrowed(symbol);
    };
    let hash = &symbol.as_bytes()[hash_start..];
    if hash[0] != b'h' || !hash[1..].iter().all(u8::is_ascii_hexdigit) {
        return Cow::Borrowed(symbol);
    }

    let mut rest = &symbol[..hash_start];
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

pub(crate) fn append_inferno_perf_folded_label(
    rendered: &mut String,
    frame: &str,
    has_prefix: bool,
) {
    append_separator(rendered, has_prefix);
    escape_frame_into(rendered, frame);
}

fn render_folded_stack_into<'a>(rendered: &mut String, frames: impl IntoIterator<Item = &'a str>) {
    rendered.clear();
    for (index, frame) in frames.into_iter().enumerate() {
        append_separator(rendered, index != 0);
        escape_frame_into(rendered, frame);
    }
}

pub(crate) fn tidy_inferno_perf_generic_into(scratch: &mut String, frame: &str) {
    let mut bracket_depth = 0_i32;
    let mut last_dot_index = None;
    let mut length_without_parameters = frame.len();
    for (index, byte) in frame.bytes().enumerate() {
        match byte {
            b'<' | b'{' | b'[' => bracket_depth += 1,
            b'>' | b'}' | b']' | b')' => bracket_depth -= 1,
            b'(' => {
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
            b'.' => last_dot_index = Some(index + 1),
            _ => {}
        }
    }
    scratch.clear();
    scratch.reserve(length_without_parameters);
    let frame = &frame[..length_without_parameters];
    let mut start = 0;
    for index in memchr::memchr_iter(b';', frame.as_bytes()) {
        scratch.push_str(&frame[start..index]);
        scratch.push(':');
        start = index + 1;
    }
    scratch.push_str(&frame[start..]);
}

pub(crate) fn escape_frame_into(escaped: &mut String, frame: &str) {
    append_escaped_spans(escaped, frame, "\\;");
}

pub(crate) fn append_escaped_spans(escaped: &mut String, frame: &str, semicolon: &str) {
    escaped.reserve(frame.len());
    let mut start = 0;
    // ASCII delimiter matches are UTF-8 boundaries; copy unchanged spans whole.
    for index in memchr::memchr3_iter(b';', b'\r', b'\n', frame.as_bytes()) {
        escaped.push_str(&frame[start..index]);
        if frame.as_bytes()[index] == b';' {
            escaped.push_str(semicolon);
        } else {
            escaped.push(' ');
        }
        start = index + 1;
    }
    escaped.push_str(&frame[start..]);
}

pub(crate) fn append_separator(rendered: &mut String, has_prefix: bool) {
    // Inferno after_event joins logical segments, including empty strings.
    if has_prefix || !rendered.is_empty() {
        rendered.push(';');
    }
}
