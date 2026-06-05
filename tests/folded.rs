use proptest::prelude::*;
use pyroclast::folded::{
    escape_frame, render_address_stack, render_folded_stack, render_inferno_perf_folded_stack,
};

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

#[test]
fn renders_inferno_perf_inlined_arrow_suffixes() {
    let stack = render_inferno_perf_folded_stack(["root", "a->b", "leaf"], 3);

    assert_eq!(stack, "root;a;b_[i];leaf 3");
}

#[test]
fn renders_inferno_perf_tidy_generic_names() {
    let stack = render_inferno_perf_folded_stack(
        [
            "fn(&str) -> core::option::Option<(u64, alloc::string::String)>",
            "method(arg)",
            "java;semi",
        ],
        5,
    );

    assert_eq!(
        stack,
        "fn; core::option::Option<(u64, alloc::string::String)>_[i];method;java:semi 5",
    );
}

#[test]
fn renders_inferno_perf_partially_demangled_rust_symbols() {
    let stack = render_inferno_perf_folded_stack(
        [
            "_$LT$std..fs..ReadDir$u20$as$u20$core..iter..traits..iterator..Iterator$GT$::next::hc14f1750ca79129b",
            "_$LT$$RF$std..fs..File$u20$as$u20$std..io..Read$GT$::read::h5d84059cf335c8e6",
        ],
        2,
    );

    assert_eq!(
        stack,
        "<std::fs::ReadDir as core::iter::traits::iterator::Iterator>::next;<&std::fs::File as std::io::Read>::read 2",
    );
}

proptest! {
    #[test]
    fn escaping_frames_removes_newlines_and_only_keeps_escaped_semicolons(frame in arbitrary_frame()) {
        let escaped = escape_frame(&frame);

        prop_assert!(!escaped.contains('\n'));
        prop_assert!(!escaped.contains('\r'));

        for (index, byte) in escaped.bytes().enumerate() {
            if byte == b';' {
                prop_assert!(index > 0);
                prop_assert_eq!(escaped.as_bytes()[index - 1], b'\\');
            }
        }
    }

    #[test]
    fn rendered_folded_stacks_escape_each_frame(
        frames in prop::collection::vec(arbitrary_frame(), 0..8),
        count in any::<u64>(),
    ) {
        let rendered = render_folded_stack(frames.iter().map(String::as_str), count);
        let (stack, rendered_count) = rendered.rsplit_once(' ').expect("count suffix");
        let mut expected_stack = String::new();
        for frame in &frames {
            if !expected_stack.is_empty() {
                expected_stack.push(';');
            }
            expected_stack.push_str(&escape_frame(frame));
        }

        prop_assert_eq!(stack, expected_stack);
        prop_assert_eq!(rendered_count, count.to_string());
    }

    #[test]
    fn rendered_address_stacks_format_all_frames_as_lower_hex(
        frames in prop::collection::vec(any::<u64>(), 0..8),
        count in any::<u64>(),
    ) {
        let rendered = render_address_stack(frames.iter().copied(), count);
        let (stack, rendered_count) = rendered.rsplit_once(' ').expect("count suffix");
        let expected_stack = frames
            .iter()
            .map(|frame| format!("0x{frame:x}"))
            .collect::<Vec<_>>()
            .join(";");

        prop_assert_eq!(stack, expected_stack);
        prop_assert_eq!(rendered_count, count.to_string());
    }
}

fn arbitrary_frame() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![Just(b';'), Just(b'\n'), Just(b'\r'), b' '..=b'~'],
        0..24,
    )
    .prop_map(|bytes| String::from_utf8(bytes).expect("ASCII frame"))
}
