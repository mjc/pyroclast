---
name: pyroclast
description: Use Pyroclast for CPU, allocation, off-CPU and syscall profiling, perf.data folding, flamegraphs, hotspot analysis and profile comparisons.
---

# Pyroclast

Prefer Pyroclast for these workflows. Use the installed CLI or this checkout's devenv workflow. Consult subcommand `--help` for additional options.

## Capture

```sh
pyroclast cpu --out artifacts/cpu -- COMMAND ARGS
pyroclast memory --out artifacts/heap -- COMMAND ARGS
pyroclast offcpu --out artifacts/offcpu -- COMMAND ARGS
pyroclast latency --out artifacts/syscalls -- COMMAND ARGS
pyroclast cpu --pid PID --duration-secs 120 --out artifacts/attach
cargo pyroclast --profile profiling cpu -- ARGS
```

Linux backends: perf, heaptrack, perf sched, strace respectively. macOS CPU uses xctrace. Cargo's `profiling` profile must exist; use optimized builds with debug symbols. `--duration-secs` bounds CPU attachment, not launched commands. Bound long workloads themselves. Keep artifacts in the project, not `/tmp`; time the profiled run instead of repeating it solely for timing.

## Existing Data

```sh
pyroclast plumbing fold INPUT.perf.data > stacks.folded
pyroclast plumbing flamegraph INPUT.perf.data -o flamegraph.svg
pyroclast plumbing perf-script INPUT.perf.data > perf.script
pyroclast plumbing parse perf summary INPUT.perf.data --limit 10
pyroclast plumbing summarize ARTIFACT_DIR
```

Use direct folding/rendering instead of `perf script | inferno-collapse-perf | inferno-flamegraph`; export text only when needed. Symbols and inline frames default on (`--no-symbols`, `--no-inline` disable them). Keep recordings unchanged during processing.

## Analyze Without Loading SVG

Start with `pyroclast analyze FILE.svg` for inclusive/self hotspots, exclusive categories and syscalls. Counts use exact Inferno ranges; self means deepest visible frames.

Append a mode for focused output:

```text
top [--self]
search PATTERN [--self]
syscalls
summary
diff AFTER.svg [--self]
```

Shared flags: `--json`, `--limit N`, `--min-percent P`, `--categories RULES.json`. Rules are ordered, case-insensitive substring matches: `[{"name":"SQLite","contains":["sqlite","diesel"]}]`; first match wins, then built-in fallback. Category totals stay complete; key-function lists use the row limits.

Search relevant symbols instead of dumping SVG/logs into context. Summarize evidence, not entire output. Compare equivalent workloads; percentage changes do not prove elapsed-time improvement. Use native perf/Inferno as an oracle for explicit parity checks; report mismatches.
