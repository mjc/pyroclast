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
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/oracle/perf-env.sh
source "$here/perf-env.sh"
"$PERF_BIN" version | tee "$ORACLE_OUT/perf.version"

rustc -O -Cdebuginfo=2 -o /tmp/oracle-workload "$REPO/scripts/oracle/workload.rs"

original_perf_paranoid=$(sysctl -n kernel.perf_event_paranoid)
original_kptr_restrict=$(sysctl -n kernel.kptr_restrict)
restore_settings() {
    sysctl -w "kernel.perf_event_paranoid=$original_perf_paranoid" >/dev/null
    sysctl -w "kernel.kptr_restrict=$original_kptr_restrict" >/dev/null
}
trap restore_settings EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
sysctl -w kernel.perf_event_paranoid=-1 >/dev/null
sysctl -w kernel.kptr_restrict=0 >/dev/null

record() {
    local name="$1"
    shift
    "$PERF_BIN" record -o "$ORACLE_OUT/$name.perf.data" "$@" -- /tmp/oracle-workload >/dev/null
    "$PERF_BIN" script -i "$ORACLE_OUT/$name.perf.data" > "$ORACLE_OUT/$name.perf.script"
    inferno-collapse-perf "$ORACLE_OUT/$name.perf.script" > "$ORACLE_OUT/$name.inferno.folded"
}

record dwarf -F 997 --call-graph dwarf,16384
record fp -F 997 --call-graph fp
