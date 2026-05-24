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
