use std::path::PathBuf;

use clap::Parser;
use proptest::prelude::*;
use proptest::string::string_regex;
use pyroclast::cli::{
    Cli, CliCommand, FlamegraphAnalysisMode, ParseCommand, ParseFlamegraphCommand,
    ParsePerfCommand, PerfCallGraph, PerfEvent, PlumbingCommand, ProfileArgs, ProfileKind, RunArgs,
    SymbolizerKind,
};

fn profile_kind_from_case(case: u8) -> ProfileKind {
    match case % 5 {
        0 => ProfileKind::Cpu,
        1 => ProfileKind::Memory,
        2 => ProfileKind::Offcpu,
        3 => ProfileKind::Latency,
        _ => ProfileKind::Async,
    }
}

fn perf_event_from_case(case: u8) -> PerfEvent {
    match case % 4 {
        0 => PerfEvent::Default,
        1 => PerfEvent::CpuClock,
        2 => PerfEvent::TaskClock,
        _ => PerfEvent::Cycles,
    }
}

fn perf_call_graph_from_case(case: u8) -> PerfCallGraph {
    match case % 2 {
        0 => PerfCallGraph::Fp,
        _ => PerfCallGraph::Dwarf,
    }
}

fn run_args_for_property(
    no_symbols: bool,
    frequency: u32,
    event: PerfEvent,
    call_graph: PerfCallGraph,
    duration_secs: u32,
    command: Vec<String>,
) -> RunArgs {
    RunArgs {
        out: Some(PathBuf::from("runs/out")),
        name: Some("named-run".to_string()),
        json: true,
        no_symbols,
        symbolizer: SymbolizerKind::RustAddr2line,
        frequency,
        event,
        call_graph,
        pid: None,
        tids: Vec::new(),
        threads_of_pid: None,
        duration_secs,
        command,
    }
}

#[test]
fn parses_profile_defaults() {
    let cli = Cli::parse_from(["pyroclast", "profile", "--", "true"]);

    match cli.command {
        CliCommand::Profile(profile) => {
            assert_eq!(profile.kind, ProfileKind::Cpu);
            assert_eq!(profile.out, None);
            assert_eq!(profile.name, None);
            assert!(!profile.json);
            assert!(!profile.no_symbols);
            assert_eq!(profile.symbolizer, SymbolizerKind::RustAddr2line);
            assert_eq!(profile.frequency, 997);
            assert_eq!(profile.event, PerfEvent::Default);
            assert_eq!(profile.call_graph, PerfCallGraph::Dwarf);
            assert_eq!(profile.command, vec!["true"]);
        }
        other => panic!("expected profile command, got {other:?}"),
    }
}

#[test]
fn profile_invocation_defaults_cpu_symbols_on() {
    let cli = Cli::parse_from(["pyroclast", "profile", "--", "true"]);

    let profile = cli
        .command
        .profile_invocation()
        .expect("profile invocation");

    assert_eq!(profile.kind, ProfileKind::Cpu);
    assert!(profile.symbols);
    assert_eq!(profile.symbolizer, SymbolizerKind::RustAddr2line);
}

#[test]
fn profile_invocation_defaults_offcpu_symbols_on() {
    let cli = Cli::parse_from(["pyroclast", "profile", "--kind", "offcpu", "--", "true"]);

    let profile = cli
        .command
        .profile_invocation()
        .expect("profile invocation");

    assert_eq!(profile.kind, ProfileKind::Offcpu);
    assert!(profile.symbols);
    assert_eq!(profile.symbolizer, SymbolizerKind::RustAddr2line);
}

#[test]
fn profile_invocation_keeps_memory_symbols_off_by_default() {
    let cli = Cli::parse_from(["pyroclast", "profile", "--kind", "memory", "--", "true"]);

    let profile = cli
        .command
        .profile_invocation()
        .expect("profile invocation");

    assert_eq!(profile.kind, ProfileKind::Memory);
    assert!(!profile.symbols);
    assert_eq!(profile.symbolizer, SymbolizerKind::RustAddr2line);
}

#[test]
fn dwarf_call_graph_matches_cargo_flamegraph_record_argument() {
    assert_eq!(PerfCallGraph::Dwarf.to_string(), "dwarf,64000");
}

#[test]
fn parses_profile_options() {
    let cli = Cli::parse_from([
        "pyroclast",
        "profile",
        "--kind",
        "memory",
        "--out",
        "runs/h",
        "--name",
        "heap-run",
        "--json",
        "--symbolizer",
        "rust-addr2line",
        "--frequency",
        "199",
        "--event",
        "cycles",
        "--call-graph",
        "dwarf",
        "--",
        "cargo",
        "check",
    ]);

    match cli.command {
        CliCommand::Profile(profile) => {
            assert_eq!(profile.kind, ProfileKind::Memory);
            assert_eq!(profile.out, Some(PathBuf::from("runs/h")));
            assert_eq!(profile.name.as_deref(), Some("heap-run"));
            assert!(profile.json);
            assert!(!profile.no_symbols);
            assert_eq!(profile.symbolizer, SymbolizerKind::RustAddr2line);
            assert_eq!(profile.frequency, 199);
            assert_eq!(profile.event, PerfEvent::Cycles);
            assert_eq!(profile.call_graph, PerfCallGraph::Dwarf);
            assert_eq!(profile.command, vec!["cargo", "check"]);
        }
        other => panic!("expected profile command, got {other:?}"),
    }
}

#[test]
fn parses_profile_kind_aliases_from_plan() {
    let heap = Cli::parse_from(["pyroclast", "profile", "--kind", "heap", "--", "true"]);
    let syscalls = Cli::parse_from(["pyroclast", "profile", "--kind", "syscalls", "--", "true"]);

    assert_eq!(
        heap.command
            .profile_invocation()
            .expect("heap invocation")
            .kind,
        ProfileKind::Memory
    );
    assert_eq!(
        syscalls
            .command
            .profile_invocation()
            .expect("syscalls invocation")
            .kind,
        ProfileKind::Latency
    );
}

#[test]
fn parses_profile_process_attach_options() {
    let cli = Cli::parse_from([
        "pyroclast",
        "profile",
        "--pid",
        "99",
        "--duration-secs",
        "15",
    ]);

    match cli.command {
        CliCommand::Profile(profile) => {
            assert_eq!(profile.pid, Some(99));
            assert!(profile.tids.is_empty());
            assert_eq!(profile.duration_secs, 15);
            assert!(profile.command.is_empty());
        }
        other => panic!("expected profile command, got {other:?}"),
    }
}

#[test]
fn parses_profile_thread_attach_options() {
    let cli = Cli::parse_from([
        "pyroclast",
        "profile",
        "--tid",
        "101,102",
        "--tid",
        "103",
        "--duration-secs",
        "5",
    ]);

    match cli.command {
        CliCommand::Profile(profile) => {
            assert_eq!(profile.pid, None);
            assert_eq!(profile.tids, vec![101, 102, 103]);
            assert_eq!(profile.duration_secs, 5);
            assert!(profile.command.is_empty());
        }
        other => panic!("expected profile command, got {other:?}"),
    }
}

#[test]
fn parses_profile_threads_of_pid_option() {
    let cli = Cli::parse_from([
        "pyroclast",
        "profile",
        "--threads-of-pid",
        "99",
        "--duration-secs",
        "10",
    ]);

    match cli.command {
        CliCommand::Profile(profile) => {
            assert_eq!(profile.pid, None);
            assert_eq!(profile.threads_of_pid, Some(99));
            assert!(profile.tids.is_empty());
            assert_eq!(profile.duration_secs, 10);
            assert!(profile.command.is_empty());
        }
        other => panic!("expected profile command, got {other:?}"),
    }
}

#[test]
fn rejects_conflicting_attach_targets() {
    let pid_and_tid = Cli::try_parse_from(["pyroclast", "profile", "--pid", "99", "--tid", "101"]);
    assert!(pid_and_tid.is_err());

    let pid_and_threads = Cli::try_parse_from([
        "pyroclast",
        "profile",
        "--pid",
        "99",
        "--threads-of-pid",
        "99",
    ]);
    assert!(pid_and_threads.is_err());

    let tid_and_threads = Cli::try_parse_from([
        "pyroclast",
        "profile",
        "--tid",
        "101",
        "--threads-of-pid",
        "99",
    ]);
    assert!(tid_and_threads.is_err());
}

#[test]
fn top_level_cpu_accepts_threads_of_pid() {
    let cli = Cli::parse_from([
        "pyroclast",
        "cpu",
        "--threads-of-pid",
        "99",
        "--duration-secs",
        "10",
    ]);

    let profile = cli
        .command
        .profile_invocation()
        .expect("profile invocation");
    assert_eq!(profile.kind, ProfileKind::Cpu);
    assert_eq!(profile.threads_of_pid, Some(99));
    assert_eq!(profile.duration_secs, 10);
    assert!(profile.command.is_empty());
}

#[test]
fn parses_top_level_profiler_commands() {
    let cases = [
        ("memory", ProfileKind::Memory),
        ("heap", ProfileKind::Memory),
        ("cpu", ProfileKind::Cpu),
        ("offcpu", ProfileKind::Offcpu),
        ("latency", ProfileKind::Latency),
        ("syscalls", ProfileKind::Latency),
        ("async", ProfileKind::Async),
    ];

    for (verb, kind) in cases {
        let cli = Cli::parse_from(["pyroclast", verb, "--", "cargo", "check"]);

        let command = cli.command;
        let profile = command
            .profile_invocation()
            .unwrap_or_else(|| panic!("expected profile invocation for {verb}"));
        assert_eq!(profile.kind, kind, "verb {verb}");
        assert_eq!(
            profile.symbols,
            matches!(kind, ProfileKind::Cpu | ProfileKind::Offcpu),
            "verb {verb}"
        );
        assert_eq!(
            profile.symbolizer,
            SymbolizerKind::RustAddr2line,
            "verb {verb}"
        );
        assert_eq!(profile.frequency, 997, "verb {verb}");
        assert_eq!(profile.event, PerfEvent::Default, "verb {verb}");
        assert_eq!(profile.call_graph, PerfCallGraph::Dwarf, "verb {verb}");
        assert_eq!(profile.command, vec!["cargo", "check"]);
    }

    let cpu = Cli::parse_from([
        "pyroclast",
        "cpu",
        "--no-symbols",
        "--symbolizer",
        "rust-addr2line",
        "--frequency",
        "199",
        "--event",
        "task-clock",
        "--call-graph",
        "dwarf",
        "--",
        "cargo",
        "check",
    ]);
    let profile = cpu
        .command
        .profile_invocation()
        .expect("expected profile invocation");
    assert!(!profile.symbols);
    assert_eq!(profile.symbolizer, SymbolizerKind::RustAddr2line);
    assert_eq!(profile.frequency, 199);
    assert_eq!(profile.event, PerfEvent::TaskClock);
    assert_eq!(profile.call_graph, PerfCallGraph::Dwarf);
}

#[test]
fn parses_plumbing_fold_and_summarize_commands() {
    let fold = Cli::parse_from(["pyroclast", "plumbing", "fold", "perf.data"]);
    assert!(
        matches!(fold.command, CliCommand::Plumbing { command: PlumbingCommand::Fold(command) } if command.input == std::path::Path::new("perf.data") && !command.count_periods)
    );

    let weighted_fold = Cli::parse_from([
        "pyroclast",
        "plumbing",
        "fold",
        "--count-periods",
        "perf.data",
    ]);
    assert!(
        matches!(weighted_fold.command, CliCommand::Plumbing { command: PlumbingCommand::Fold(command) } if command.input == std::path::Path::new("perf.data") && command.count_periods && command.symbols)
    );

    let symbolized_fold = Cli::parse_from(["pyroclast", "plumbing", "fold", "perf.data"]);
    assert!(
        matches!(symbolized_fold.command, CliCommand::Plumbing { command: PlumbingCommand::Fold(command) } if command.input == std::path::Path::new("perf.data") && command.symbols && command.symbolizer == SymbolizerKind::RustAddr2line)
    );

    let rust_symbolized_fold = Cli::parse_from([
        "pyroclast",
        "plumbing",
        "fold",
        "--no-symbols",
        "--symbolizer",
        "rust-addr2line",
        "perf.data",
    ]);
    assert!(
        matches!(rust_symbolized_fold.command, CliCommand::Plumbing { command: PlumbingCommand::Fold(command) } if command.input == std::path::Path::new("perf.data") && !command.symbols && command.symbolizer == SymbolizerKind::RustAddr2line)
    );

    let summarize = Cli::parse_from(["pyroclast", "plumbing", "summarize", "--json", "run-dir"]);
    assert!(
        matches!(summarize.command, CliCommand::Plumbing { command: PlumbingCommand::Summarize(command) } if command.json && command.artifact_dir == std::path::Path::new("run-dir"))
    );
}

#[test]
fn rejects_removed_dev_helper_plumbing_commands() {
    let bench = Cli::try_parse_from(["pyroclast", "plumbing", "bench"]);
    let precommit = Cli::try_parse_from(["pyroclast", "plumbing", "precommit"]);

    assert!(bench.is_err());
    assert!(precommit.is_err());
}

#[test]
fn parses_plumbing_flamegraph_commands() {
    let flamegraph = Cli::parse_from([
        "pyroclast",
        "plumbing",
        "flamegraph",
        "perf.data",
        "-o",
        "out.svg",
    ]);
    assert!(
        matches!(flamegraph.command, CliCommand::Plumbing { command: PlumbingCommand::Flamegraph(command) } if command.input == std::path::Path::new("perf.data") && command.output.as_deref() == Some(std::path::Path::new("out.svg")) && command.symbols)
    );

    let symbolized_flamegraph =
        Cli::parse_from(["pyroclast", "plumbing", "flamegraph", "perf.data"]);
    assert!(
        matches!(symbolized_flamegraph.command, CliCommand::Plumbing { command: PlumbingCommand::Flamegraph(command) } if command.input == std::path::Path::new("perf.data") && command.symbols && command.symbolizer == SymbolizerKind::RustAddr2line)
    );

    let rust_symbolized_flamegraph = Cli::parse_from([
        "pyroclast",
        "plumbing",
        "flamegraph",
        "--no-symbols",
        "--symbolizer",
        "rust-addr2line",
        "perf.data",
    ]);
    assert!(
        matches!(rust_symbolized_flamegraph.command, CliCommand::Plumbing { command: PlumbingCommand::Flamegraph(command) } if command.input == std::path::Path::new("perf.data") && !command.symbols && command.symbolizer == SymbolizerKind::RustAddr2line)
    );
}

#[test]
fn parses_plumbing_parse_commands() {
    let flamegraph_analysis = Cli::parse_from([
        "pyroclast",
        "plumbing",
        "parse",
        "flamegraph",
        "top",
        "--json",
        "--limit",
        "12",
        "--min-percent",
        "0.5",
        "flamegraph.svg",
    ]);
    match flamegraph_analysis.command {
        CliCommand::Plumbing {
            command:
                PlumbingCommand::Parse {
                    command:
                        ParseCommand::Flamegraph {
                            command: ParseFlamegraphCommand::Top(command),
                        },
                },
        } => {
            let analyze = command.analyze_args();
            assert!(analyze.json);
            assert_eq!(analyze.mode, FlamegraphAnalysisMode::Top);
            assert_eq!(analyze.limit, 12);
            assert!((analyze.min_percent - 0.5).abs() < f64::EPSILON);
            assert_eq!(analyze.input, std::path::Path::new("flamegraph.svg"));
        }
        other => panic!("expected plumbing parse flamegraph top command, got {other:?}"),
    }

    let flamegraph_diff = Cli::parse_from([
        "pyroclast",
        "plumbing",
        "parse",
        "flamegraph",
        "diff",
        "before.svg",
        "after.svg",
    ]);
    assert!(
        matches!(flamegraph_diff.command, CliCommand::Plumbing { command: PlumbingCommand::Parse { command: ParseCommand::Flamegraph { command: ParseFlamegraphCommand::Diff(command) } } } if command.before == std::path::Path::new("before.svg") && command.after == std::path::Path::new("after.svg"))
    );

    let perfdata_analysis = Cli::parse_from([
        "pyroclast",
        "plumbing",
        "parse",
        "perf",
        "summary",
        "--json",
        "--limit",
        "20",
        "perf.data",
    ]);
    assert!(
        matches!(perfdata_analysis.command, CliCommand::Plumbing { command: PlumbingCommand::Parse { command: ParseCommand::Perf { command: ParsePerfCommand::Summary(command) } } } if command.json && command.limit == 20 && command.input == std::path::Path::new("perf.data"))
    );
}

#[test]
fn rejects_removed_top_level_plumbing_commands() {
    assert!(Cli::try_parse_from(["pyroclast", "fold", "perf.data"]).is_err());
    assert!(Cli::try_parse_from(["pyroclast", "flamegraph", "perf.data"]).is_err());
    assert!(Cli::try_parse_from(["pyroclast", "summarize", "run-dir"]).is_err());
    assert!(Cli::try_parse_from(["pyroclast", "analyze-flamegraph", "graph.svg"]).is_err());
    assert!(Cli::try_parse_from(["pyroclast", "analyze-perfdata", "perf.data"]).is_err());
}

proptest! {
    #[test]
    fn property_profile_command_invocation_preserves_generated_fields(
        profile_kind_case in any::<u8>(),
        no_symbols in any::<bool>(),
        frequency in 1_u32..20_000,
        perf_event_case in any::<u8>(),
        call_graph_case in any::<u8>(),
        duration_secs in 0_u32..10_000,
        command in prop::collection::vec(
            string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,15}").expect("valid command-arg regex"),
            1..4,
        ),
    ) {
        let kind = profile_kind_from_case(profile_kind_case);
        let event = perf_event_from_case(perf_event_case);
        let call_graph = perf_call_graph_from_case(call_graph_case);
        let cli_command = CliCommand::Profile(ProfileArgs {
            kind,
            out: Some(PathBuf::from("runs/out")),
            name: Some("named-run".to_string()),
            json: true,
            no_symbols,
            symbolizer: SymbolizerKind::RustAddr2line,
            frequency,
            event,
            call_graph,
            pid: None,
            tids: Vec::new(),
            threads_of_pid: None,
            duration_secs,
            command: command.clone(),
        });

        let profile = cli_command.profile_invocation().expect("profile invocation");

        prop_assert_eq!(profile.kind, kind);
        prop_assert_eq!(profile.out, Some(PathBuf::from("runs/out")));
        prop_assert_eq!(profile.name.as_deref(), Some("named-run"));
        prop_assert!(profile.json);
        prop_assert_eq!(
            profile.symbols,
            !no_symbols && matches!(kind, ProfileKind::Cpu | ProfileKind::Offcpu)
        );
        prop_assert_eq!(profile.symbolizer, SymbolizerKind::RustAddr2line);
        prop_assert_eq!(profile.frequency, frequency);
        prop_assert_eq!(profile.event, event);
        prop_assert_eq!(profile.call_graph, call_graph);
        prop_assert_eq!(profile.duration_secs, duration_secs);
        prop_assert_eq!(profile.command, command);
        prop_assert_eq!(profile.pid, None);
        prop_assert!(profile.tids.is_empty());
        prop_assert_eq!(profile.threads_of_pid, None);
    }

    #[test]
    fn property_top_level_profile_commands_map_to_expected_kind(
        kind_case in 0_u8..5,
        no_symbols in any::<bool>(),
        frequency in 1_u32..20_000,
        perf_event_case in any::<u8>(),
        call_graph_case in any::<u8>(),
        duration_secs in 0_u32..10_000,
        command in prop::collection::vec(
            string_regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,15}").expect("valid top-level command-arg regex"),
            1..4,
        ),
    ) {
        let event = perf_event_from_case(perf_event_case);
        let call_graph = perf_call_graph_from_case(call_graph_case);
        let cli_command = match kind_case {
            0 => CliCommand::Memory(run_args_for_property(
                no_symbols,
                frequency,
                event,
                call_graph,
                duration_secs,
                command.clone(),
            )),
            1 => CliCommand::Cpu(run_args_for_property(
                no_symbols,
                frequency,
                event,
                call_graph,
                duration_secs,
                command.clone(),
            )),
            2 => CliCommand::Offcpu(run_args_for_property(
                no_symbols,
                frequency,
                event,
                call_graph,
                duration_secs,
                command.clone(),
            )),
            3 => CliCommand::Latency(run_args_for_property(
                no_symbols,
                frequency,
                event,
                call_graph,
                duration_secs,
                command.clone(),
            )),
            _ => CliCommand::Async(run_args_for_property(
                no_symbols,
                frequency,
                event,
                call_graph,
                duration_secs,
                command.clone(),
            )),
        };

        let profile = cli_command.profile_invocation().expect("profile invocation");
        let expected_kind = match kind_case {
            0 => ProfileKind::Memory,
            1 => ProfileKind::Cpu,
            2 => ProfileKind::Offcpu,
            3 => ProfileKind::Latency,
            _ => ProfileKind::Async,
        };

        prop_assert_eq!(profile.kind, expected_kind);
        prop_assert_eq!(profile.out, Some(PathBuf::from("runs/out")));
        prop_assert_eq!(profile.name.as_deref(), Some("named-run"));
        prop_assert!(profile.json);
        prop_assert_eq!(
            profile.symbols,
            !no_symbols && matches!(expected_kind, ProfileKind::Cpu | ProfileKind::Offcpu)
        );
        prop_assert_eq!(profile.symbolizer, SymbolizerKind::RustAddr2line);
        prop_assert_eq!(profile.frequency, frequency);
        prop_assert_eq!(profile.event, event);
        prop_assert_eq!(profile.call_graph, call_graph);
        prop_assert_eq!(profile.duration_secs, duration_secs);
        prop_assert_eq!(profile.command, command);
    }
}
