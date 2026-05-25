# Pyroclast

Rust-first profiling orchestration and perf.data analysis.

Pyroclast is being built to replace the slow `perf script | inferno-collapse | inferno-flamegraph`
path with direct Rust parsing and folding. External profilers and renderers still come from the
Nix flake; Pyroclast owns orchestration, manifests, folding, summaries, and command construction.

## Usage

```sh
pyroclast profile -- <command...>
pyroclast profile --kind cpu -- <command...>
pyroclast profile --kind heap -- <command...>
pyroclast profile --kind memory -- <command...>
pyroclast profile --kind offcpu -- <command...>
pyroclast profile --kind syscalls -- <command...>
pyroclast profile --kind latency -- <command...>

pyroclast fold <perf.data>
pyroclast flamegraph <perf.data>
pyroclast summarize <artifact-dir>
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

## Outputs

Profile runs write a Pyroclast artifact directory containing the command, stdout/stderr logs,
raw profiler output, summaries, tool diagnostics, and a `run.json` manifest.

CPU profiling on Linux records with `perf`, folds `perf.data` directly in Rust, and only invokes
`inferno-flamegraph` for SVG rendering. Memory profiling uses `heaptrack`; latency profiling uses
`strace`; off-CPU profiling uses `bpftrace`. On macOS, CPU profiling uses Apple-provided `xctrace`.

## Development

Use the Nix shell:

```sh
nix develop
cargo test
```

The pre-commit hook runs rustfmt, Clippy pedantic, the test suite, and `nix flake check`.
