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
# recording step so pyroclast can resolve its symbols by path. (System DSOs
# such as libc were already recorded as "/ (deleted)" by perf at record time
# and are not symbolized by perf either.)
if [ -f "$REPO/scripts/oracle/workload.rs" ] && [ ! -x /tmp/oracle-workload ]; then
    rustc -O -Cdebuginfo=2 -o /tmp/oracle-workload "$REPO/scripts/oracle/workload.rs"
fi

cd "$REPO"
cargo build --quiet --release --bin pyroclast --example pyroclast-bench

for name in ${ORACLE_NAMES:-fp dwarf}; do
    [ -f "$ORACLE_OUT/$name.perf.data" ] || continue
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

echo "================ fp script diff (perf vs pyroclast) ================"
diff "$ORACLE_OUT/fp.perf.script" "$ORACLE_OUT/fp.pyroclast.script" | head -50 || true
echo "================ fp folded diff (inferno vs pyroclast) ============="
diff <(sort "$ORACLE_OUT/fp.inferno.folded") <(sort "$ORACLE_OUT/fp.pyroclast.folded") | head -50 || true
echo "================ fp bench scoreboard ==============================="
grep -E 'inferno_compare\.(matches|only_)' "$ORACLE_OUT/fp.bench.txt" || true
