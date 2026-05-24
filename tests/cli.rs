use std::path::PathBuf;

use pyroclast::cli::{Cli, Command, ProfileKind};

#[test]
fn parses_profile_defaults() {
    let cli = Cli::parse_from(["pyroclast", "profile", "--", "true"]);

    match cli.command {
        Command::Profile(profile) => {
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
        "heap",
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
        Command::Profile(profile) => {
            assert_eq!(profile.kind, ProfileKind::Heap);
            assert_eq!(profile.out, Some(PathBuf::from("runs/h")));
            assert_eq!(profile.name.as_deref(), Some("heap-run"));
            assert!(profile.json);
            assert_eq!(profile.command, vec!["cargo", "check"]);
        }
        other => panic!("expected profile command, got {other:?}"),
    }
}

#[test]
fn parses_analysis_commands() {
    let fold = Cli::parse_from(["pyroclast", "fold", "perf.data"]);
    assert!(matches!(fold.command, Command::Fold(command) if command.input == PathBuf::from("perf.data")));

    let summarize = Cli::parse_from(["pyroclast", "summarize", "--json", "run-dir"]);
    assert!(
        matches!(summarize.command, Command::Summarize(command) if command.json && command.artifact_dir == PathBuf::from("run-dir"))
    );

    let flamegraph = Cli::parse_from(["pyroclast", "flamegraph", "perf.data", "-o", "out.svg"]);
    assert!(
        matches!(flamegraph.command, Command::Flamegraph(command) if command.input == PathBuf::from("perf.data") && command.output == Some(PathBuf::from("out.svg")))
    );
}
