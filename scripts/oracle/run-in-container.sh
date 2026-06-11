#!/usr/bin/env bash
# Runs inside the oracle container: records perf.data from the sample
# workload, exports perf script text, folds it with inferno-collapse-perf,
# folds it with pyroclast, and writes everything to $ORACLE_OUT.
set -euo pipefail

ORACLE_OUT="${ORACLE_OUT:-/oracle-out}"
REPO="${REPO:-/work}"
export CARGO_TARGET_DIR="$ORACLE_OUT/target"

mkdir -p "$ORACLE_OUT"
perf version | tee "$ORACLE_OUT/perf.version"

rustc -O -Cdebuginfo=2 -o /tmp/oracle-workload "$REPO/scripts/oracle/workload.rs"

sysctl -w kernel.perf_event_paranoid=-1 >/dev/null 2>&1 || true
sysctl -w kernel.kptr_restrict=0 >/dev/null 2>&1 || true

record() {
    local name="$1"
    shift
    perf record -o "$ORACLE_OUT/$name.perf.data" "$@" -- /tmp/oracle-workload >/dev/null
    perf script -i "$ORACLE_OUT/$name.perf.data" > "$ORACLE_OUT/$name.perf.script"
    inferno-collapse-perf "$ORACLE_OUT/$name.perf.script" > "$ORACLE_OUT/$name.inferno.folded"
}

record dwarf -F 997 --call-graph dwarf,16384
record fp -F 997 --call-graph fp

cd "$REPO"
cargo build --quiet --release --bin pyroclast --example pyroclast-bench

for name in dwarf fp; do
    timeout 600 "$CARGO_TARGET_DIR/release/examples/pyroclast-bench" \
        "$ORACLE_OUT/$name.perf.data" \
        --perf-script "$ORACLE_OUT/$name.perf.script" \
        --symbols \
        | tee "$ORACLE_OUT/$name.bench.txt" \
        || echo "pyroclast-bench failed for $name (continuing)" >&2
    timeout 600 "$CARGO_TARGET_DIR/release/pyroclast" plumbing fold \
        "$ORACLE_OUT/$name.perf.data" > "$ORACLE_OUT/$name.pyroclast.folded" \
        || echo "plumbing fold failed for $name (continuing)" >&2
    timeout 600 "$CARGO_TARGET_DIR/release/pyroclast" plumbing perf-script \
        "$ORACLE_OUT/$name.perf.data" > "$ORACLE_OUT/$name.pyroclast.script" \
        || echo "plumbing perf-script failed for $name (continuing)" >&2
done
