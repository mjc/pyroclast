#!/usr/bin/env bash
# Runs inside the oracle container: rebuilds pyroclast incrementally (target
# under $ORACLE_OUT so builds persist across runs), regenerates ONLY the
# *.pyroclast.* artifacts and bench reports, and prints the script/folded
# diffs against the recorded oracle inputs. Does NOT re-record perf.data and
# does NOT touch the recorded oracle inputs (*.perf.data, *.perf.script,
# *.inferno.folded).
set -euo pipefail

ORACLE_OUT="${ORACLE_OUT:-/oracle-out}"
REPO="${REPO:-/work}"
export CARGO_TARGET_DIR="$ORACLE_OUT/target"

# The recorded perf.data references the workload at /tmp/oracle-workload (by
# path) and the system DSOs that existed at record time. In a fresh compare
# container those DSOs are gone, so symbolization falls back to module names.
# Rebuild the workload deterministically with the same rustc flags used by the
# recording step so pyroclast can resolve its symbols by path.
if [ -f "$REPO/scripts/oracle/workload.rs" ] && [ ! -x /tmp/oracle-workload ]; then
    rustc -O -Cdebuginfo=2 -o /tmp/oracle-workload "$REPO/scripts/oracle/workload.rs"
fi

# perf recorded the C library mapping as "/ (deleted)" (the file was unlinked
# during the run) but symbolized it at record time from the live mapping, and
# it stored the DSO build-ids in the HEADER_BUILD_ID feature. pyroclast resolves
# build-ids out of ~/.debug/.build-id/<aa>/<rest>/elf, so seed that cache from
# the container's on-disk DSOs (whose build-ids match the recording, since the
# record and compare containers share the same image). Without this the deleted
# libc cannot be symbolized and shows up as the lone residual diff.
seed_build_id_cache() {
    local dso="$1"
    [ -e "$dso" ] || return 0
    local id
    id=$(readelf -n "$dso" 2>/dev/null | awk '/Build ID:/ {print $3; exit}')
    [ -n "$id" ] || return 0
    local dir="$HOME/.debug/.build-id/${id:0:2}/${id:2}"
    mkdir -p "$dir"
    ln -sf "$dso" "$dir/elf"
}
for dso in /usr/lib/*/libc.so.6 /usr/lib/*/ld-linux-*.so.* /usr/lib/*/libgcc_s.so.1; do
    seed_build_id_cache "$dso"
done

cd "$REPO"
cargo build --quiet --release --bin pyroclast --example pyroclast-bench

for name in ${ORACLE_NAMES:-fp dwarf}; do
    recording="$ORACLE_OUT/$name.perf.data"
    [ -f "$recording" ] || { echo "missing required oracle recording: $recording" >&2; exit 1; }
    # Export fresh native perf text with the same explicit inline mode as the
    # implementation. This job fails on missing input, tool errors, or any diff.
    PYROCLAST_BIN="$CARGO_TARGET_DIR/release/pyroclast" \
        timeout 600 "$REPO/scripts/check-perf-parity" "$recording" \
        | tee "$ORACLE_OUT/$name.parity.txt"
    for mode in inline no-inline; do
        perf script --force "--$mode" -i "$recording" > "$ORACLE_OUT/$name.$mode.perf.script"
        timeout 600 "$CARGO_TARGET_DIR/release/examples/pyroclast-bench" \
            "$recording" --perf-script "$ORACLE_OUT/$name.$mode.perf.script" \
            --symbols "--$mode" | tee "$ORACLE_OUT/$name.$mode.bench.txt"
    done
done
