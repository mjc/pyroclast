pub fn escape_frame(frame: &str) -> String {
    frame.replace(';', "\\;").replace(['\r', '\n'], " ")
}

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

pub fn render_address_stack(frames: impl IntoIterator<Item = u64>, count: u64) -> String {
    let rendered_frames = frames
        .into_iter()
        .map(|frame| format!("0x{frame:x}"))
        .collect::<Vec<_>>();
    render_folded_stack(rendered_frames.iter().map(String::as_str), count)
}
