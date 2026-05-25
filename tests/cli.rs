use std::path::PathBuf;

use pyroclast::cli::{Cli, CliCommand, PerfCallGraph, PerfEvent, ProfileKind};

#[test]
fn parses_profile_defaults() {
    let cli = Cli::parse_from(["pyroclast", "profile", "--", "true"]);

    match cli.command {
        CliCommand::Profile(profile) => {
            assert_eq!(profile.kind, ProfileKind::Cpu);
            assert_eq!(profile.out, None);
            assert_eq!(profile.name, None);
            assert!(!profile.json);
            assert!(!profile.symbols);
            assert_eq!(profile.frequency, 997);
            assert_eq!(profile.event, PerfEvent::CpuClock);
            assert_eq!(profile.call_graph, PerfCallGraph::Fp);
            assert_eq!(profile.command, vec!["true"]);
        }
        other => panic!("expected profile command, got {other:?}"),
    }
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
        "--symbols",
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
            assert!(profile.symbols);
            assert_eq!(profile.frequency, 199);
            assert_eq!(profile.event, PerfEvent::Cycles);
            assert_eq!(profile.call_graph, PerfCallGraph::Dwarf);
            assert_eq!(profile.command, vec!["cargo", "check"]);
        }
        other => panic!("expected profile command, got {other:?}"),
    }
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
fn parses_top_level_profiler_commands() {
    let cases = [
        ("memory", ProfileKind::Memory),
        ("cpu", ProfileKind::Cpu),
        ("offpcu", ProfileKind::Offcpu),
        ("latency", ProfileKind::Latency),
        ("async", ProfileKind::Async),
    ];

    for (verb, kind) in cases {
        let cli = Cli::parse_from(["pyroclast", verb, "--", "cargo", "check"]);

        let command = cli.command;
        let profile = command
            .profile_invocation()
            .unwrap_or_else(|| panic!("expected profile invocation for {verb}"));
        assert_eq!(profile.kind, kind, "verb {verb}");
        assert!(!profile.symbols, "verb {verb}");
        assert_eq!(profile.frequency, 997, "verb {verb}");
        assert_eq!(profile.event, PerfEvent::CpuClock, "verb {verb}");
        assert_eq!(profile.call_graph, PerfCallGraph::Fp, "verb {verb}");
        assert_eq!(profile.command, vec!["cargo", "check"]);
    }

    let cpu = Cli::parse_from([
        "pyroclast",
        "cpu",
        "--symbols",
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
    assert!(profile.symbols);
    assert_eq!(profile.frequency, 199);
    assert_eq!(profile.event, PerfEvent::TaskClock);
    assert_eq!(profile.call_graph, PerfCallGraph::Dwarf);
}

#[test]
fn parses_analysis_commands() {
    let fold = Cli::parse_from(["pyroclast", "fold", "perf.data"]);
    assert!(
        matches!(fold.command, CliCommand::Fold(command) if command.input == std::path::Path::new("perf.data") && !command.count_periods)
    );

    let weighted_fold = Cli::parse_from(["pyroclast", "fold", "--count-periods", "perf.data"]);
    assert!(
        matches!(weighted_fold.command, CliCommand::Fold(command) if command.input == std::path::Path::new("perf.data") && command.count_periods && !command.symbols)
    );

    let symbolized_fold = Cli::parse_from(["pyroclast", "fold", "--symbols", "perf.data"]);
    assert!(
        matches!(symbolized_fold.command, CliCommand::Fold(command) if command.input == std::path::Path::new("perf.data") && command.symbols)
    );

    let summarize = Cli::parse_from(["pyroclast", "summarize", "--json", "run-dir"]);
    assert!(
        matches!(summarize.command, CliCommand::Summarize(command) if command.json && command.artifact_dir == std::path::Path::new("run-dir"))
    );

    let flamegraph = Cli::parse_from(["pyroclast", "flamegraph", "perf.data", "-o", "out.svg"]);
    assert!(
        matches!(flamegraph.command, CliCommand::Flamegraph(command) if command.input == std::path::Path::new("perf.data") && command.output.as_deref() == Some(std::path::Path::new("out.svg")) && !command.symbols)
    );

    let symbolized_flamegraph =
        Cli::parse_from(["pyroclast", "flamegraph", "--symbols", "perf.data"]);
    assert!(
        matches!(symbolized_flamegraph.command, CliCommand::Flamegraph(command) if command.input == std::path::Path::new("perf.data") && command.symbols)
    );
}
