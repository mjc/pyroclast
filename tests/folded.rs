use pyroclast::folded::{escape_frame, render_address_stack, render_folded_stack};

#[test]
fn escapes_frame_delimiters_and_newlines() {
    assert_eq!(escape_frame("foo;bar\nbaz"), "foo\\;bar baz");
}

#[test]
fn renders_folded_stack_with_count() {
    let stack = render_folded_stack(["root", "leaf;semi"], 7);

    assert_eq!(stack, "root;leaf\\;semi 7");
}

#[test]
fn renders_address_stack_as_hex_frames() {
    let stack = render_address_stack([0x2000, 0x3000], 2);

    assert_eq!(stack, "0x2000;0x3000 2");
}
