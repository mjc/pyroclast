use std::path::PathBuf;

use pyroclast::cli::{Cli, CliCommand, ProfileKind};

#[test]
fn parses_profile_defaults() {
    let cli = Cli::parse_from(["pyroclast", "profile", "--", "true"]);

    match cli.command {
        CliCommand::Profile(profile) => {
            assert_eq!(profile.kind, ProfileKind::Cpu);
            assert_eq!(profile.out, None);
            assert_eq!(profile.name, None);
            assert!(!profile.json);
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
            assert_eq!(profile.command, vec!["cargo", "check"]);
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
        assert_eq!(profile.command, vec!["cargo", "check"]);
    }
}

#[test]
fn parses_analysis_commands() {
    let fold = Cli::parse_from(["pyroclast", "fold", "perf.data"]);
    assert!(
        matches!(fold.command, CliCommand::Fold(command) if command.input == std::path::Path::new("perf.data") && !command.count_periods)
    );

    let weighted_fold = Cli::parse_from(["pyroclast", "fold", "--count-periods", "perf.data"]);
    assert!(
        matches!(weighted_fold.command, CliCommand::Fold(command) if command.input == std::path::Path::new("perf.data") && command.count_periods)
    );

    let summarize = Cli::parse_from(["pyroclast", "summarize", "--json", "run-dir"]);
    assert!(
        matches!(summarize.command, CliCommand::Summarize(command) if command.json && command.artifact_dir == std::path::Path::new("run-dir"))
    );

    let flamegraph = Cli::parse_from(["pyroclast", "flamegraph", "perf.data", "-o", "out.svg"]);
    assert!(
        matches!(flamegraph.command, CliCommand::Flamegraph(command) if command.input == std::path::Path::new("perf.data") && command.output.as_deref() == Some(std::path::Path::new("out.svg")))
    );
}
