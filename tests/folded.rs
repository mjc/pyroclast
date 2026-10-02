use proptest::prelude::*;
use pyroclast::folded::{
    escape_frame, render_address_stack, render_folded_stack, render_inferno_perf_folded_stack,
};

#[test]
fn escapes_frame_delimiters_and_newlines() {
    assert_eq!(escape_frame("foo;bar\nbaz"), "foo\\;bar baz");
}

#[test]
fn leaves_plain_frames_untouched() {
    assert_eq!(escape_frame("plain_frame_123"), "plain_frame_123");
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
fn leading_empty_inline_segment_is_preserved_like_infernos_stack_join() {
    // Inferno perf.rs:on_stack_line pushes the empty first arrow segment;
    // after_event joins by position, not by testing serialized text length.
    assert_eq!(
        render_inferno_perf_folded_stack(["->inner"], 1),
        ";inner_[i] 1"
    );
}

#[test]
fn renders_empty_folded_segments_by_position() {
    assert_eq!(render_folded_stack(["", "leaf", ""], 7), ";leaf; 7");
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
fn renders_inferno_perf_split_return_type_with_unbalanced_generic_depth_like_inferno() {
    let stack = render_inferno_perf_folded_stack(
        [
            "with<core::cell::RefCell<alloc::string::String>, tracing_subscriber::fmt::fmt_layer::{impl#12}::on_event::{closure_env#0}<tracing_subscriber::registry::sharded::Registry, tracing_subscriber::fmt::format::DefaultFields, tracing_subscriber::fmt::format::Format<tracing_subscriber::fmt::format::Full, tracing_subscriber::fmt::time::SystemTime>, fn() -> std::io::stdio::Stdout>, ()>",
        ],
        1,
    );

    assert_eq!(
        stack,
        "with<core::cell::RefCell<alloc::string::String>, tracing_subscriber::fmt::fmt_layer::{impl#12}::on_event::{closure_env#0}<tracing_subscriber::registry::sharded::Registry, tracing_subscriber::fmt::format::DefaultFields, tracing_subscriber::fmt::format::Format<tracing_subscriber::fmt::format::Full, tracing_subscriber::fmt::time::SystemTime>, fn() ; std::io::stdio::Stdout>, ()>_[i] 1",
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

#[test]
fn raw_function_normalization_matches_native_inferno_before_and_after_fast_paths() {
    // Inferno perf.rs:on_stack_line strips offsets and fixes Rust names before
    // splitting inline arrows, regardless of whether the name needs tidying.
    for symbol in [
        "plain+0xdead",
        "plain+0xdead+tail",
        "plain+0xdead+0x2",
        "plain-name",
        "method(arg)+0x1a",
        "root->inner",
        "->inner",
        "net/http.(*Client).Do",
        "(anonymous namespace)::entry()",
        "java;name",
        "fn<closure(arg)>(u64)",
    ] {
        assert_function_matches_native_inferno(symbol);
    }
}

#[test]
fn empty_offset_suffix_is_stripped_like_native_inferno() {
    assert_function_matches_native_inferno("plain+0x");
}

#[test]
fn plain_function_fast_path_still_strips_trailing_rust_hashes_like_native_inferno() {
    for symbol in [
        "already_demangled::h0123456789abcdef",
        "\u{e9}::h0123456789abcdef",
    ] {
        assert_function_matches_native_inferno(symbol);
    }
}

fn assert_function_matches_native_inferno(symbol: &str) {
    use inferno::collapse::Collapse as _;
    let script = format!(
        "worker 7 1.000000: 1 cycles:\n\t1020 {symbol} (/bin/app)\n\t1010 root (/bin/app)\n\n"
    );
    let mut options = inferno::collapse::perf::Options::default();
    options.nthreads = 1;
    let mut expected = Vec::new();
    inferno::collapse::perf::Folder::from(options)
        .collapse(std::io::Cursor::new(script), &mut expected)
        .unwrap();
    let actual = render_inferno_perf_folded_stack(["worker", "root", symbol], 1) + "\n";
    assert_eq!(actual.as_bytes(), expected, "symbol: {symbol}");
}

proptest! {
    #[test]
    fn span_escaping_matches_character_reference_for_all_utf8(
        characters in prop::collection::vec(
            prop_oneof![any::<char>(), Just(';'), Just('\r'), Just('\n')], 0..256,
        ),
    ) {
        let frame: String = characters.into_iter().collect();
        let mut expected = String::new();
        for character in frame.chars() {
            match character {
                ';' => expected.push_str("\\;"),
                '\r' | '\n' => expected.push(' '),
                _ => expected.push(character),
            }
        }
        prop_assert_eq!(escape_frame(&frame), expected);
    }

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
        for (index, frame) in frames.iter().enumerate() {
            if index != 0 {
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
