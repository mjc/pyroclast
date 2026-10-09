#!/usr/bin/env bash
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
mkdir -p "$repo/target"
root=$(mktemp -d "$repo/target/native-parity-inputs.XXXXXX")
trap 'rm -rf "$root"' EXIT
tools="$root/bin"
mkdir -p "$tools"
export AUDIT_LOG="$root/calls"

printf '%s\n' '#!/bin/sh' \
    "printf 'rustc %s\\n' \"\$*\" >> \"\$AUDIT_LOG\"" \
    "[ \"\${FAIL_RUSTC:-}\" != yes ] || exit 24" \
    "while [ \"\$#\" -gt 0 ]; do if [ \"\$1\" = -o ]; then shift; printf '#!/bin/sh\\nexit 0\\n' > \"\$1\"; chmod +x \"\$1\"; exit 0; fi; shift; done" \
    'exit 90' > "$tools/rustc"
printf '%s\n' '#!/bin/sh' \
    "printf 'perf %s\\n' \"\$*\" >> \"\$AUDIT_LOG\"" \
    "case \"\$1\" in" \
    "record) [ \"\${FAIL_RECORD:-}\" != yes ] || exit 23; shift; while [ \"\$#\" -gt 0 ]; do if [ \"\$1\" = -o ]; then shift; : > \"\$1\"; exit 0; fi; shift; done; exit 91;;" \
    "script) [ \"\${EMPTY_ORACLE:-}\" != yes ] || exit 0; echo 'stack 1';;" \
    '*) exit 92;; esac' > "$tools/perf"
printf '%s\n' '#!/bin/sh' 'echo "stack 1"' > "$tools/pyroclast"
printf '%s\n' '#!/bin/sh' "cat \"\$1\"" > "$tools/inferno-collapse-perf"
printf '%s\n' '#!/bin/sh' 'cat' > "$tools/inferno-flamegraph"
chmod +x "$tools/"*
export PATH="$tools:$PATH" PYROCLAST_BIN="$tools/pyroclast" PERF_BIN="$tools/perf"
export PERF_PARITY_OUT="$root/parity" TMPDIR="$root/does-not-exist"
unset PERF_PARITY_DATA
: > "$AUDIT_LOG"
bash "$repo/scripts/check-perf-parity" > "$root/report"
records=$(grep -c '^perf record ' "$AUDIT_LOG" || true)
[ "$records" = 2 ] || { echo "fresh checkout must record DWARF and FP inputs; got $records" >&2; exit 1; }
grep -q -- '--call-graph dwarf' "$AUDIT_LOG"
grep -q -- '--call-graph fp' "$AUDIT_LOG"
[ "$(grep -c '^native-perf-parity ' "$root/report")" = 8 ]
if grep -q '/mnt/downloads\|/tmp/' "$AUDIT_LOG"; then
    echo 'default parity input still depends on an external machine path' >&2
    exit 1
fi

explicit="$root/explicit.perf.data"
: > "$explicit"
: > "$AUDIT_LOG"
PERF_PARITY_DATA="$explicit" bash "$repo/scripts/check-perf-parity" > "$root/report"
if grep -q '^perf record ' "$AUDIT_LOG"; then
    echo 'explicit input must not capture a replacement' >&2
    exit 1
fi
grep -Fq -- "-i $explicit" "$AUDIT_LOG"
[ "$(grep -c '^native-perf-parity ' "$root/report")" = 4 ]

: > "$AUDIT_LOG"
if bash "$repo/scripts/check-perf-parity" "$root/missing.perf.data" > "$root/report" 2>&1; then
    echo 'missing explicit input must fail, not capture a replacement' >&2
    exit 1
fi
if grep -q '^perf record ' "$AUDIT_LOG"; then
    echo 'missing explicit input must not capture a replacement' >&2
    exit 1
fi

check_failure() {
    local setting=$1 expected=$2 status=0
    env "$setting=yes" bash "$repo/scripts/check-perf-parity" > "$root/report" 2>&1 || status=$?
    [ "$status" = "$expected" ] || { cat "$root/report" >&2; echo "wrong status: $status (expected $expected)" >&2; return 1; }
}
check_failure FAIL_RECORD 23
check_failure FAIL_RUSTC 24
check_failure EMPTY_ORACLE 1
echo 'fresh native parity input checks passed'
