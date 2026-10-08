# Pyroclast

Rust-first profiling orchestration and perf.data analysis.

Pyroclast is being built to replace the slow `perf script | inferno-collapse | inferno-flamegraph`
path with direct Rust parsing and folding. External profilers and renderers come from the host or
the development environment; Pyroclast owns orchestration, manifests, folding, summaries, and
command construction.

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

Pyroclast also ships a cargo-subcommand wrapper that mirrors `cargo-flamegraph` target
selection/build behavior and forwards trailing arguments to the built executable:

```sh
cargo pyroclast cpu -- --tui
cargo pyroclast --profile profiling cpu -- --tui
cargo pyroclast memory --example demo -- --serve
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

## Flamegraph Analysis

```sh
pyroclast analyze flamegraph.svg
pyroclast analyze flamegraph.svg --json --limit 10 --min-percent 1
```

Reports inclusive hotspots, self samples, heuristic categories and syscall coverage.
Uses Inferno's exact sample ranges, unions recursive/repeated function frames, and
supports normal, inverted and differential SVGs. Inclusive rows overlap; category
rows partition all samples. Self samples refer to the deepest visible frame, not
children hidden by rendering thresholds. Counts are raw SVG sample weights, even
when titles use scaled units. SVGs without exact Inferno ranges are rejected.
Use the plumbing commands above for search and before/after comparisons.

## Outputs

Profile runs write a Pyroclast artifact directory containing the command, stdout/stderr logs,
raw profiler output, summaries, tool diagnostics, and a `run.json` manifest.

CPU profiling on Linux records with `perf`, folds `perf.data` directly in Rust, and only invokes
`inferno-flamegraph` for SVG rendering. Memory profiling uses `heaptrack`; latency profiling uses
`strace`; off-CPU profiling defaults to the command-driven `perf sched` path. On macOS, CPU
profiling uses Apple-provided `xctrace`.

## Development

Build or run the CLI from the Nix flake:

```sh
nix build .#
nix run .# -- --help
```

Enter the development environment and run the full test suite:

```sh
devenv shell
cargo nextest run
scripts/pyroclast-bench [<perf.data>] [--perf-script <perf.script>] [--export-perf-script <out>] [--symbols]
```

The pre-commit hook enters `devenv shell` and runs rustfmt, Clippy pedantic,
`cargo nextest run`, and `nix flake check`.

The Linux test suite requires `cc`, `objcopy`, `addr2line`, and `perf` in `PATH`.
The development shell supplies them. Native-oracle tests compile ELF fixtures
and compare against `perf script` and GNU addr2line; missing tools fail the tests
rather than silently skipping parity checks. When running outside the development
shell, install a C toolchain, binutils, and perf first.

Process completed recordings: keep the input file unchanged until analysis
finishes. Like native `perf script`, ordered file delivery uses a read-only
file mapping, not a snapshot protected against concurrent writes or truncation.
