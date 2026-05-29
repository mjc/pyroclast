use std::fmt::Write as _;

use proptest::prelude::*;
use proptest::string::string_regex;
use pyroclast::parsers::bpftrace::collapse_offcpu;

#[test]
fn collapses_bpftrace_offcpu_stacks() {
    let input = "\
@offcpu[
    55 tokio::runtime::park+12 (/bin/app)
    44 app::serve+7 (/bin/app)
]: 1500
";

    let folded = collapse_offcpu(input);

    assert_eq!(folded, vec!["app::serve;tokio::runtime::park 1500"]);
}

proptest! {
    #[test]
    fn property_collapses_each_block_with_reversed_valid_frames(
        blocks in prop::collection::vec(offcpu_block(), 0..24),
    ) {
        let input = render_offcpu_blocks(&blocks);
        let collapsed = collapse_offcpu(&input);
        let expected = blocks
            .iter()
            .filter_map(expected_folded_line)
            .collect::<Vec<_>>();

        prop_assert_eq!(collapsed, expected);
    }
}

#[derive(Clone, Debug)]
struct OffcpuBlock {
    frames: Vec<FrameSpec>,
    count: u64,
}

#[derive(Clone, Debug)]
enum FrameSpec {
    Valid(String),
    Unknown(String),
}

fn offcpu_block() -> impl Strategy<Value = OffcpuBlock> {
    (
        prop::collection::vec(frame_spec(), 0..6),
        1_u64..100_000_u64,
    )
        .prop_map(|(frames, count)| OffcpuBlock { frames, count })
}

fn frame_spec() -> impl Strategy<Value = FrameSpec> {
    prop_oneof![
        symbol_name().prop_map(FrameSpec::Valid),
        symbol_name().prop_map(|symbol| FrameSpec::Unknown(format!("{symbol}([unknown])"))),
    ]
}

fn symbol_name() -> impl Strategy<Value = String> {
    string_regex(r"[A-Za-z_:;][A-Za-z0-9_:;]{0,15}").expect("valid symbol regex")
}

fn render_offcpu_blocks(blocks: &[OffcpuBlock]) -> String {
    let mut input = String::new();
    for block in blocks {
        input.push_str("@offcpu[\n");
        for frame in &block.frames {
            match frame {
                FrameSpec::Valid(symbol) => {
                    let _ = writeln!(input, "    55 {symbol}+12 (/bin/app)");
                }
                FrameSpec::Unknown(symbol) => {
                    let _ = writeln!(input, "    55 {symbol}");
                }
            }
        }
        let _ = writeln!(input, "]: {}", block.count);
    }
    input
}

fn expected_folded_line(block: &OffcpuBlock) -> Option<String> {
    let frames = block
        .frames
        .iter()
        .filter_map(|frame| match frame {
            FrameSpec::Valid(symbol) => Some(symbol.as_str()),
            FrameSpec::Unknown(_) => None,
        })
        .rev()
        .collect::<Vec<_>>();

    (!frames.is_empty()).then(|| pyroclast::folded::render_folded_stack(frames, block.count))
}
