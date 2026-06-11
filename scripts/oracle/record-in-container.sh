#!/usr/bin/env bash
# Runs inside the oracle container: records perf.data from the sample
# workload, exports perf script text, and folds it with inferno-collapse-perf.
# Writes ONLY the recorded oracle inputs (*.perf.data, *.perf.script,
# *.inferno.folded) plus perf.version. Does NOT build or run pyroclast — use
# compare-in-container.sh for the fast pyroclast iteration path.
set -euo pipefail

ORACLE_OUT="${ORACLE_OUT:-/oracle-out}"
REPO="${REPO:-/work}"

mkdir -p "$ORACLE_OUT"
# Ubuntu's /usr/bin/perf wrapper insists on a kernel-matched build; call the
# packaged binary directly since any modern perf works for the oracle.
if ! perf version >/dev/null 2>&1; then
    PERF_BIN="$(find /usr/lib/linux-tools* -name perf -type f 2>/dev/null | head -n 1)"
    [ -n "$PERF_BIN" ] || { echo "no perf binary found" >&2; exit 1; }
    perf() { "$PERF_BIN" "$@"; }
fi
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
