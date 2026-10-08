# Pyroclast

Profile applications in any language with the appropriate tools already available on the OS.
Pyroclast chooses the recorder for the requested question, collects its output, and produces
summaries and flamegraphs. Its aim is the fastest correct end-to-end profiling path with as
few additional dependencies as possible.

On Linux, completed `perf.data` recordings are parsed, symbolized, and folded directly,
avoiding the `perf script | inferno-collapse-perf` text pipeline. SVG rendering is built in.
The Cargo wrapper is an optional convenience for Rust projects; ordinary commands can profile
C, C++, Go, Python, services, and other workloads supported by the native recorder. Symbol and
stack quality still depends on the runtime, debug information, and recording configuration.

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
pyroclast async -- <command...>
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
pyroclast analyze flamegraph.svg top --self --limit 30
pyroclast analyze flamegraph.svg search planner
pyroclast analyze flamegraph.svg syscalls
pyroclast analyze flamegraph.svg summary
pyroclast analyze before.svg diff after.svg --self
```

Reports inclusive hotspots, self samples, heuristic categories and syscall coverage.
Uses Inferno's exact sample ranges, unions recursive/repeated function frames, and
supports normal, inverted and differential SVGs. Inclusive rows overlap; category
rows partition all samples. Self samples refer to the deepest visible frame, not
children hidden by rendering thresholds. Counts are raw SVG sample weights, even
when titles use scaled units. SVGs without exact Inferno ranges are rejected.
`--json`, `--limit` and `--min-percent` work before or after the analysis mode.
Search is a case-insensitive substring match, including small functions by
default. Diff defaults to a 0.01 percentage-point threshold; compare equivalent
workloads, since coverage changes are not elapsed-time speedups.

Use `--categories categories.json` to adapt the full report or `summary` to a
project without forking the analyzer. Rules are ordered, case-insensitive
substring matches; the first match wins, then built-in categories are the fallback:

```json
[
  {"name": "Writer", "contains": ["build::writer", "copy_from_archive"]},
  {"name": "Archive", "contains": ["r7z", "zstd", "libarchive"]},
  {"name": "SQLite", "contains": ["sqlite", "diesel"]}
]
```

Category rows cover all samples regardless of `--limit` or `--min-percent`.
Each category also lists its top inclusive functions, with those controls
applied per category. Their coverage overlaps and must not be added together.

## Outputs

Profile runs write a Pyroclast artifact directory containing the command, stdout/stderr logs,
raw profiler output, summaries, tool diagnostics, and a `run.json` manifest.
The manifest separates `requested_controls` from native `measurement` metadata.
For xctrace, measurement records the CPU Profiler template and exported weight unit,
not perf sampling or unwinding settings. Unsupported overrides are rejected before recording.

CPU profiling on Linux records with `perf`; on macOS it uses Apple's `xctrace`. Memory
profiling currently uses `heaptrack`, and syscall latency uses `strace` on Linux. Blocked-time
profiling checks `perf sched` access first, falling back to a checked `bpftrace`; use
`--offcpu-method perf-sched|bpftrace` to override that choice. The scheduler report tracks the
launched process and its threads. Bpftrace captures kernel stacks at switch-out and charges
them when the thread resumes. These modes do not include child processes.

`async` runs the blocked-time path for executor and worker-thread stalls. It reports OS thread
waiting rather than individual futures or runtime tasks. Linux CPU profiling supports process
and thread attachment; the other backends reject attachment before launching a workload.

`--name` labels the saved run. `--json` returns the run manifest with artifact paths on stdout;
failed CLI profiles return a JSON error and a nonzero exit status. A rerun clears prior generated
artifacts before recording so failed runs cannot expose an older successful result.

`plumbing parse perf summary --json` includes recorded process/thread IDs, CPU IDs, first and
last sample timestamps, and sparse one-second activity buckets under `profile`. The sample span
is distinct from process wall time; captures without timestamps report missing timing explicitly.
Heap summaries include allocation counts and available heap, leak, RSS, and runtime totals.
Syscall summaries include call counts, total time, and per-call averages.

Supported recorder selection:

| Question | Host | Target | Automatic recorder | Requirements |
| --- | --- | --- | --- | --- |
| CPU hotspots | Linux | Command, PID, or thread IDs | perf; direct folding and built-in SVG | perf access, usable stacks/symbols |
| CPU hotspots | macOS | Command | xctrace | Xcode, recording permission |
| Allocation growth | Linux | Command | heaptrack | heaptrack and heaptrack_print |
| Syscall latency | Linux | Command | strace | ptrace permission |
| Blocked or async worker threads | Linux | Command | perf sched, then bpftrace if perf is unavailable or unusable | scheduler trace access; bpftrace for stack attribution |

Other host/question/target combinations report an unsupported case before launching. Tool
availability is checked before recording. Automatic blocked-time selection probes recorder access
using a disposable recording or a brief tracepoint/stack-helper check before launching the workload.
Permission or recording failures after launch are reported rather
than retrying a workload that may already have run. Missing tools identify the package to install;
generic profiling does not require Cargo or a Rust toolchain. `perf sched` provides scheduler
wait totals, while the bpftrace alternative additionally attributes waiting to captured kernel stacks.

Default CPU profile summaries aggregate file metadata with bounded read windows. Their storage
grows with distinct threads, CPUs, and sparse timeline buckets, rather than sample count. The
explicit detailed perf analysis and retained-summary APIs still retain samples and callchains.
Folding uses bounded read windows. Performance claims must compare equivalent
completed output and include recording, analysis, rendering, and peak memory on the tested workload.

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

The pre-commit hook uses the current project environment, entering `devenv shell`
when necessary, and runs rustfmt, Clippy pedantic,
`cargo nextest run`, the `perf script | Inferno` parity check, and `nix flake check`.
The parity check uses `/mnt/downloads/inferno-slow-collapse.perf.data` by default;
set `PERF_PARITY_DATA` to select another recording.

The Linux test suite requires `cc`, `objcopy`, `addr2line`, and `perf` in `PATH`.
The development shell supplies them. Native-oracle tests compile ELF fixtures
and compare against `perf script` and GNU addr2line; missing tools fail the tests
rather than silently skipping parity checks. When running outside the development
shell, install a C toolchain, binutils, and perf first.

Some older symbol tests optionally inspect `target/profiling/pyroclast` or
historical store binaries. A passing test count does not prove those optional
fixtures were exercised. The required native parity gate rejects missing inputs,
tool failures, empty oracle output, and script, folded-stack, or SVG differences.
Mandatory compiled C fixtures cover inline frames and non-PIE PLT addresses;
the checked-in Xcode fixture covers native referenced CPU rows and cycle units.

Kernel text parity validates bracketed module mappings against host kcore.
Absolute or compressed module paths and an initially loaded ET_DYN module keep
their original sources instead of using host kcore. These fallbacks can differ
from native text exports; broader kernel/version parity remains tracked work.

Process completed recordings: keep the input file unchanged until analysis
finishes. Timestamp-ordered records retain read windows until delivery, avoiding
per-record payload copies and backward rereads. Metadata preparation can make
separate passes. Input is not protected against concurrent writes or truncation.

Folded per-stack counts saturate at `u64::MAX` on overflow in both direct and
Inferno folding; representable counts and continuous-stream parser state are
unchanged. Saturation is an explicit overflow policy, not native Inferno parity
for sums beyond the representable range.
