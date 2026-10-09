#!/usr/bin/env bash
# Mocks test gate contracts only; they are not native Darwin verification.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
[ -f "$repo/scripts/check-native-parity" ] || { echo 'missing native-platform parity gate' >&2; exit 1; }
mkdir -p "$repo/target"
root=$(mktemp -d "$repo/target/native-platform-parity.XXXXXX")
trap 'rm -rf "$root"' EXIT
fixture="$root/repo"
tools="$root/bin"
mkdir -p "$fixture/scripts/oracle" "$tools"
cp "$repo/scripts/check-native-parity" "$repo/scripts/check-xctrace-parity" "$fixture/scripts/"
cp "$repo/scripts/oracle/xctrace-cpu.xsl" "$repo/scripts/oracle/xctrace-workload.c" "$fixture/scripts/oracle/"
export PARITY_LOG="$root/calls" FAKE_EXPORT="$root/apple.xml"
cat > "$tools/uname" <<'SH'
#!/bin/sh
printf '%s\n' "$TEST_PLATFORM"
SH
cat > "$fixture/scripts/check-perf-parity" <<'SH'
#!/bin/sh
printf 'linux %s\n' "$*" >> "$PARITY_LOG"
exit "${FAIL_LINUX:-0}"
SH
cat > "$tools/cc" <<'SH'
#!/bin/sh
echo compile >> "$PARITY_LOG"
[ "${FAIL_COMPILE:-no}" != yes ] || exit 23
while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ]; then shift; printf '#!/bin/sh\nexit 0\n' > "$1"; chmod +x "$1"; exit 0; fi
    shift
done
exit 90
SH
cat > "$tools/pyroclast" <<'SH'
#!/bin/sh
echo record >> "$PARITY_LOG"
[ "${FAIL_RECORD:-no}" != yes ] || exit 24
while [ "$#" -gt 0 ]; do
    case "$1" in --out) shift; out=$1;; --) shift; workload=$1; shift; identity=$1; break;; esac
    shift
done
mkdir -p "$out/profile.raw.xctrace.trace"
printf '7\n' > "$out/xctrace-target.pid"
printf '7\n' > "$identity"
printf '<not-the-oracle/>' > "$out/profile.raw.xctrace.xml"
printf '{"actual_backend":"macos_xctrace","platform":"macos","exit_status":0,"measurement":{"source":"xctrace","template":"CPU Profiler","weight_unit":"cycles"}}\n' > "$out/run.json"
first=11 weight=13 total=24
[ "${FLOAT_SUMMARY:-no}" != yes ] || { first=11.0; weight=13.0; total=24.0; }
[ "${BAD_SUMMARY:-no}" != yes ] || { weight=14; total=25; }
[ "${FRACTIONAL_MISMATCH:-no}" != yes ] || { weight=13.0000001; total=24.0000001; }
[ "${REORDER_ROWS:-no}" != yes ] || { first=13; weight=11; }
printf '{"rows":[{"symbol":"pyroclast_parity_hot_loop","weight":%s},{"symbol":"pyroclast_parity_hot_loop","weight":%s}],"total_weight":%s,"weight_unit":"cycles"}\n' "$first" "$weight" "$total" > "$out/summary.json"
if [ "${MISSING_ROW:-no}" = yes ]; then
    jq '.rows |= .[0:1]' "$out/summary.json" > "$out/short.json"
    mv "$out/short.json" "$out/summary.json"
fi
SH
cat > "$tools/xctrace" <<'SH'
#!/bin/sh
[ "$1" = export ] || exit 91
echo export >> "$PARITY_LOG"
[ "${FAIL_EXPORT:-no}" != yes ] || exit 25
while [ "$#" -gt 0 ]; do
    case "$1" in --output) shift; output=$1;; --input) shift; input=$1;; esac
    shift
done
[ -d "$input" ] || exit 92
case "$input" in */run/profile.raw.xctrace.trace) ;; *) exit 93 ;; esac
if [ "${EMPTY_EXPORT:-no}" = yes ]; then printf '<trace-query-result/>' > "$output"; else cp "$FAKE_EXPORT" "$output"; fi
SH
chmod +x "$tools/"* "$fixture/scripts/"*
cat > "$FAKE_EXPORT" <<'XML'
<trace-query-result><node><schema name="cpu-profile"/>
<row><process id="p"><pid>7</pid></process><cycle-weight>11</cycle-weight><tagged-backtrace id="b"><frame name="pyroclast_parity_hot_loop"/><frame name="main"/></tagged-backtrace></row>
<row><process pid="8"/><cycle-weight>99</cycle-weight><tagged-backtrace><frame name="pyroclast_parity_other_process"/></tagged-backtrace></row>
<row><process ref="p"/><cycle-weight>13</cycle-weight><tagged-backtrace ref="b"/></row>
</node></trace-query-result>
XML
export PATH="$tools:$PATH" PYROCLAST_BIN="$tools/pyroclast" XCTRACE_PARITY_OUT="$root/output"
unset PERF_PARITY_DATA
: > "$PARITY_LOG"
TEST_PLATFORM=Linux bash "$fixture/scripts/check-native-parity" 'explicit recording' > "$root/report"
grep -Fxq 'linux explicit recording' "$PARITY_LOG"
if TEST_PLATFORM=Linux FAIL_LINUX=26 bash "$fixture/scripts/check-native-parity" > "$root/report" 2>&1; then
    echo 'dispatcher ignored Linux parity failure' >&2; exit 1
fi
: > "$PARITY_LOG"
TEST_PLATFORM=Darwin bash "$fixture/scripts/check-native-parity" > "$root/report"
for call in compile record export; do [ "$(grep -Fxc "$call" "$PARITY_LOG")" = 1 ]; done
grep -q '^native-xctrace-parity .*rows=true .*weights=true' "$root/report"
TEST_PLATFORM=Darwin FLOAT_SUMMARY=yes bash "$fixture/scripts/check-native-parity" > "$root/report"
grep -q '^native-xctrace-parity .*rows=true .*weights=true' "$root/report"
check_failure() {
    local setting=$1 expected=$2 status=0
    env TEST_PLATFORM=Darwin "$setting=yes" bash "$fixture/scripts/check-native-parity" > "$root/report" 2>&1 || status=$?
    [ "$status" = "$expected" ] || { cat "$root/report" >&2; echo "$setting: got $status, expected $expected" >&2; return 1; }
}
check_failure FAIL_COMPILE 23
check_failure FAIL_RECORD 24
check_failure FAIL_EXPORT 25
check_failure BAD_SUMMARY 1
check_failure FRACTIONAL_MISMATCH 1
check_failure REORDER_ROWS 1
check_failure MISSING_ROW 1
check_failure EMPTY_EXPORT 1
if TEST_PLATFORM=Darwin bash "$fixture/scripts/check-native-parity" "$root/existing.trace" > "$root/report" 2>&1; then
    echo 'Darwin gate must require a fresh Pyroclast recording' >&2; exit 1
fi
if TEST_PLATFORM=Unsupported bash "$fixture/scripts/check-native-parity" > "$root/report" 2>&1; then
    echo 'unsupported platforms must fail rather than skip' >&2; exit 1
fi
echo 'native platform routing and Darwin gate contract checks passed'
