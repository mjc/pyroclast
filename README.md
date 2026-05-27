# Pyroclast

Rust-first profiling orchestration and perf.data analysis.

Pyroclast is being built to replace the slow `perf script | inferno-collapse | inferno-flamegraph`
path with direct Rust parsing and folding. External profilers and renderers still come from the
Nix flake; Pyroclast owns orchestration, manifests, folding, summaries, and command construction.

## Porcelain

```sh
pyroclast profile -- <command...>
pyroclast profile --kind cpu -- <command...>
pyroclast profile --kind heap -- <command...>
pyroclast profile --kind memory -- <command...>
pyroclast profile --kind offcpu -- <command...>
pyroclast profile --kind syscalls -- <command...>
pyroclast profile --kind latency -- <command...>

```

Top-level profiler aliases are also available:

```sh
pyroclast cpu -- <command...>
pyroclast heap -- <command...>
pyroclast memory -- <command...>
pyroclast offcpu -- <command...>
pyroclast syscalls -- <command...>
pyroclast latency -- <command...>
```

## Plumbing

```sh
pyroclast plumbing fold <perf.data>
pyroclast plumbing flamegraph <perf.data>
pyroclast plumbing summarize <artifact-dir>

pyroclast plumbing parse perf summary <perf.data>
pyroclast plumbing parse flamegraph summary <flamegraph.svg>
pyroclast plumbing parse flamegraph top <flamegraph.svg>
pyroclast plumbing parse flamegraph search <flamegraph.svg> <pattern>
pyroclast plumbing parse flamegraph syscalls <flamegraph.svg>
pyroclast plumbing parse flamegraph diff <before.svg> <after.svg>
```

## Outputs

Profile runs write a Pyroclast artifact directory containing the command, stdout/stderr logs,
raw profiler output, summaries, tool diagnostics, and a `run.json` manifest.

CPU profiling on Linux records with `perf`, folds `perf.data` directly in Rust, and only invokes
`inferno-flamegraph` for SVG rendering. Memory profiling uses `heaptrack`; latency profiling uses
`strace`; off-CPU profiling defaults to the command-driven `perf sched` path. On macOS, CPU
profiling uses Apple-provided `xctrace`.

## Development

Build or run the CLI from the flake:

```sh
nix build .#
nix run .# -- --help
```

Use the Nix shell:

```sh
nix develop
cargo nextest run
```

The pre-commit hook runs rustfmt, Clippy pedantic, `cargo nextest run`, and `nix flake check`.
