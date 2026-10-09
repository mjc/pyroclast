# Shipping Workflow Measurements

Build before measuring, inside the repository's devenv:

```sh
cargo build --release --bin pyroclast --example measure-workflows
```

The helper executes that prebuilt CLI, never an internal folding API. GNU time
with `%Tt/%Tx/%Tn` support is required (the devenv supplies it). Commands inherit
the working directory/environment, with `LC_ALL=C`. Each argv entry remains one
argument. Only `{pyroclast}` and `{run_dir}` are expanded, without rescanning
inserted paths. There is no implicit shell; pipelines explicitly use Bash with
`pipefail`.

## Completed Capture

Checked workloads in `scripts/benchmarks/workload.{c,rs}` accept a mode and
positive round count. `cpu` performs dependent integer work, `threads` performs
that work on four independent workers, and `alloc` retains 8 MiB while churning
variable-sized buffers. Both languages print independently checked checksums;
usage failures exit 2. These synthetic cases complement real application
recordings; they do not establish universal performance.

```sh
mkdir -p target/workflow-workloads
cc -O2 -g -fno-omit-frame-pointer -pthread \
  scripts/benchmarks/workload.c -o target/workflow-workloads/c
rustc --edition=2024 -C opt-level=2 -C debuginfo=2 \
  -C force-frame-pointers=yes scripts/benchmarks/workload.rs \
  -o target/workflow-workloads/rust
```

Append the chosen mode/rounds to the workload argv in the baseline, shipping
`profile_total` and native `capture` stages. Do not append them to the native
analysis pipeline. Compile and calibrate workloads before measuring; retain
that calibration separately from the alternating acceptance observations.

Use a prebuilt, bounded workload. Bind its absolute path with jq:

```sh
mkdir -p target/workflow-matrices
jq --arg workload "$PWD/target/workload" '
  .inputs = [$workload] |
  (.rows[].stages[].argv[] | select(. == "WORKLOAD")) = $workload
' scripts/benchmarks/shipping-cpu.json > target/workflow-matrices/cpu.json
target/release/examples/measure-workflows \
  --pyroclast target/release/pyroclast \
  --matrix target/workflow-matrices/cpu.json --out target/workflow-cpu
```

The output directory must not exist. This matrix alternates baseline, shipping
CPU and native capture-plus-streaming-analysis order over ten repetitions. The
shipping CLI also generates summaries; the native pipeline only generates SVG.
Match event, frequency, callgraph and inline settings explicitly. The shipped
example uses the actual CLI's `dwarf,64000` stack size, not the smaller oracle
fixture's dump size.

Independently captured recordings are not parity oracles for one another.
After timing, replay each completed recording through `scripts/check-perf-parity`
with persistent `PERF_PARITY_OUT` and the same `PYROCLAST_BIN`. This verifies each
recording against fresh native output outside measured workflow intervals.
Do not run the entire 121 GB recording: use bounded two-minute diagnostics.

## Shared Recording

`scripts/benchmarks/offline-cpu.json` measures fold and analysis/render separately
on the same existing recording, comparing nonempty folded output and SVG.
Bind `PERF_DATA` in `.inputs` and argv entries with jq as above. Its row-total
includes two separate analyses; use the stage times to compare fold or complete
analysis/render, not that total as a single-pass workflow. The native render
pipeline is timed directly, not reconstructed by adding overlapping stages.

## Evidence And Limits

Before invoking the runner, record host, binary/tool versions, affinity and
pre/post CPU load in the matrix's `conditions`. Declare warm-cache measurements;
input hashing before measurement warms the input. Binary/input BLAKE3 hashes,
sizes, matrix, architecture and working directory are retained. This runner does
not determine whether a busy host is acceptable or automatically retry failures.

`observations.jsonl` is flushed before launch and after completion. A missing
finish record is incomplete, not a fast result. Per-command stdout, stderr and
GNU time resource reports live in each repetition's reserved
`.measurement/ROW/STAGE.*` namespace. Failed stages stop their row, but remaining
rows/repetitions still run. `summary.json` retains all observations; no failures
are filtered out. Required artifacts must be nonempty files. Comparison failures
make the runner fail without changing successful command timings.

Wall time is measured monotonically and includes the GNU time launch. Row time
also includes orchestration between stages, but excludes artifact validation and
comparison. GNU time's user/system CPU and maximum RSS are recorded separately.
Maximum RSS is **not** simultaneous process-tree RSS, target-only memory, or
owned heap. Do not sum RSS peaks across stages. Wrapper status and actual target
termination are separate: target SIGTERM must not be confused with `exit 143`.
Use a separate, explicitly instrumented diagnostic for heap/process-tree memory.

This harness alone does not establish arbitrary-application performance,
allocation-backend parity, Darwin workflow parity, or a speedup.
