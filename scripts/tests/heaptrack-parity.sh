#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$root/target"
work=$(mktemp -d "$root/target/heaptrack-parity-tests.XXXXXX")
echo "Logs: $work"
mkdir -p "$work/bin" "$work/caller"
cat_fixture='total runtime: 0.32s.
calls to allocation functions: 130 (406/s)
temporary memory allocations: 100 (312/s)
peak heap memory consumption: 8.46M
peak RSS (including heaptrack overhead): 1.25G
total memory leaked: 512B'
printf '%s\n' "$cat_fixture" > "$work/footer"
printf '%s\n' '#!/usr/bin/env bash' '[[ $1 == -f && $2 == "$RAW" ]] || exit 90' 'cat "$FOOTER"' '[[ ${MODIFY:-0} == 0 ]] || printf changed >> "$RAW"' 'exit "${NATIVE_EXIT:-0}"' > "$work/bin/heaptrack_print"
chmod +x "$work/bin/heaptrack_print"
export PATH="$work/bin:$PATH" FOOTER="$work/footer"
case_run() {
    local name=$1 expected=$2
    if (cd "$work/caller" && bash "$root/scripts/check-heaptrack-parity" "$work/input" "$work/$name") > "$work/$name.log" 2>&1; then
        [[ $expected == pass ]] || { echo "unexpected success: $name"; exit 1; }
    else
        [[ $expected == fail ]] || { cat "$work/$name.log"; exit 1; }
    fi
    echo "PASS $name"
}
reset_input() {
    mkdir -p "$work/input"
    export RAW="$work/input/profile.raw.heaptrack.zst"
    printf raw > "$RAW"
    jq -n --arg raw "$RAW" '{actual_backend:"heaptrack",exit_status:0,artifacts:[$raw]}' > "$work/input/run.json"
    printf '%s\n' '{"total_allocations":130,"temporary_allocations":100,"peak_heap_bytes":8460000,"leaked_bytes":512,"peak_rss_bytes":1250000000,"runtime_seconds":0.32}' > "$work/input/summary.json"
    printf '%s\n' "$cat_fixture" > "$FOOTER"
    export MODIFY=0 NATIVE_EXIT=0
}
edit_json() {
    jq "$2" "$work/input/$1" > "$work/edit.json"
    mv "$work/edit.json" "$work/input/$1"
}
edit_footer() {
    sed "$@" "$FOOTER" > "$work/edit.footer"
    mv "$work/edit.footer" "$FOOTER"
}
reset_input
case_run decimals pass
jq -e --arg raw "$RAW" '.raw_input == $raw and .sha256_before == .sha256_after and .native_exit_status == 0 and (.report_sha256 | length) == 64' "$work/decimals"/check.*/identity.json > "$work/identity-check.log"
reset_input
edit_footer 's/8.46M/1.25K/;s/512B/15B/'
edit_json summary.json '.peak_heap_bytes=1250 | .leaked_bytes=15'
case_run decimal-k-b pass
reset_input
edit_footer 's/512B/1.5B/'
edit_json summary.json '.leaked_bytes=1.5'
case_run bad-bytes-fraction fail
reset_input
edit_footer 's/8.46M/1.25T/;s/1.25G/2.50T/;s/512B/1.01T/'
edit_json summary.json '.peak_heap_bytes=1250000000000 | .peak_rss_bytes=2500000000000 | .leaked_bytes=1010000000000'
case_run terabytes pass
reset_input
edit_footer 's/8.46M/2.01K/'
edit_json summary.json '.peak_heap_bytes=2010'
case_run decimal-rounding pass
reset_input
edit_footer 's/512B/0.0001K/'
edit_json summary.json '.leaked_bytes=0'
case_run bad-scaled-precision fail
reset_input
edit_json run.json '.artifacts=["profile.raw.heaptrack.zst"]'
case_run relative-raw pass
reset_input
edit_json run.json ".cwd=\"$work/caller\""
case_run absolute-raw-with-cwd pass
reset_input
jq --arg cwd "$root" --arg raw "${RAW#"$root/"}" '.cwd=$cwd | .artifacts=[$raw]' "$work/input/run.json" > "$work/edit.json"
mv "$work/edit.json" "$work/input/run.json"
case_run manifest-cwd-relative-raw pass
reset_input
edit_json run.json ".cwd=\"$work/input\" | .artifacts=[\"profile.raw.heaptrack.zst\"]"
case_run manifest-cwd-basename pass
reset_input
edit_json run.json ".cwd=\"$work/caller\" | .artifacts=[\"profile.raw.heaptrack.zst\"]"
case_run declared-cwd-no-fallback fail
reset_input
edit_json run.json '.cwd="relative-cwd" | .artifacts=["profile.raw.heaptrack.zst"]'
case_run invalid-relative-cwd fail
reset_input
edit_json run.json '.artifacts=["input/profile.raw.heaptrack.zst"]'
case_run no-cwd-nested-path fail
for field in total_allocations temporary_allocations peak_heap_bytes leaked_bytes peak_rss_bytes runtime_seconds; do
    reset_input
    edit_json summary.json ".$field += 1"
    case_run "mismatch-$field" fail
done
reset_input
edit_footer -E 's/0.32s/0s/;s/130 \(/0 (/;s/100 \(/0 (/;s/8.46M/0B/;s/1.25G/0B/;s/512B/0B/'
edit_json summary.json 'map_values(0)'
case_run zero pass
for mode in modified no-raw multiple missing-raw empty-raw backend status native-exit missing-prefix bad-units bad-count bad-runtime truncated duplicate malformed missing-field string-field multiple-summary-documents multiple-run-documents; do
    reset_input
    case $mode in
        modified) export MODIFY=1 ;;
        no-raw) edit_json run.json '.artifacts=[]' ;;
        multiple) edit_json run.json '.artifacts += .artifacts' ;;
        missing-raw) rm "$RAW" ;;
        empty-raw) : > "$RAW" ;;
        backend) edit_json run.json '.actual_backend="other"' ;;
        status) edit_json run.json '.exit_status=1' ;;
        native-exit) export NATIVE_EXIT=7 ;;
        missing-prefix) edit_footer 's/total memory leaked:/leaked:/' ;;
        bad-units) edit_footer 's/512B/512KiB/' ;;
        bad-count) edit_footer 's/130 (/1.3 (/' ;;
        bad-runtime) edit_footer 's/0.32s/0.32ms/' ;;
        truncated) edit_footer '$d' ;;
        duplicate) printf 'total memory leaked: 512B\n' >> "$FOOTER" ;;
        malformed) printf '{' > "$work/input/summary.json" ;;
        missing-field) edit_json summary.json 'del(.leaked_bytes)' ;;
        string-field) edit_json summary.json '.leaked_bytes="512"' ;;
        multiple-summary-documents) printf '{}\n' >> "$work/input/summary.json" ;;
        multiple-run-documents) printf '{}\n' >> "$work/input/run.json" ;;
    esac
    case_run "$mode" fail
done
reset_input
jq -c . "$work/input/summary.json" > "$work/edit.json"
jq -c . "$work/input/summary.json" >> "$work/edit.json"
cp "$work/edit.json" "$work/input/summary.json"
case_run concatenated-valid-summary fail
