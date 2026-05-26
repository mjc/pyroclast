use std::process::{Command, ExitCode};

struct Check {
    name: &'static str,
    program: &'static str,
    args: &'static [&'static str],
}

const CHECKS: &[Check] = &[
    Check {
        name: "rustfmt",
        program: "cargo",
        args: &["fmt", "--check"],
    },
    Check {
        name: "clippy pedantic",
        program: "cargo",
        args: &[
            "clippy",
            "--all-targets",
            "--",
            "-D",
            "warnings",
            "-W",
            "clippy::pedantic",
        ],
    },
    Check {
        name: "nextest",
        program: "cargo",
        args: &["nextest", "run"],
    },
    Check {
        name: "flake check",
        program: "nix",
        args: &["flake", "check", "--no-build"],
    },
];

fn main() -> ExitCode {
    for check in CHECKS {
        eprintln!("pre-commit: {}", check.name);
        let status = match Command::new(check.program).args(check.args).status() {
            Ok(status) => status,
            Err(error) => {
                eprintln!(
                    "pre-commit: failed to run {}: {error}",
                    shell_command(check)
                );
                return ExitCode::FAILURE;
            }
        };

        if !status.success() {
            eprintln!("pre-commit: {} failed", check.name);
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}

fn shell_command(check: &Check) -> String {
    std::iter::once(check.program)
        .chain(check.args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}
