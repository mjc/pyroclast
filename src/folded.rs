pub fn escape_frame(frame: &str) -> String {
    frame.replace(';', "\\;").replace(['\r', '\n'], " ")
}

pub fn render_folded_stack<'a>(
    frames: impl IntoIterator<Item = &'a str>,
    count: u64,
) -> String {
    let stack = frames
        .into_iter()
        .map(escape_frame)
        .collect::<Vec<_>>()
        .join(";");
    format!("{stack} {count}")
}
