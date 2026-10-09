#!/usr/bin/env bash
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
provider=(--provider)
libraries=()
if [[ -n ${PYRO_PROVIDER_LIBRARY_PATH:-} ]]; then
    libraries=(--library-path "$PYRO_PROVIDER_LIBRARY_PATH")
fi
if [[ ${1:-} == --stock ]]; then
    provider=()
    shift
    [[ $# == 1 ]] || exit 2
    binary=$1
    oracle=$1
else
    [[ $# == 2 ]] || exit 2
    binary=$1
    oracle=$2
fi
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
    printf '%s\n' 'native ptrace proof requires Linux x86_64' >&2
    exit 2
fi
for tool in "${CC:-cc}" objcopy nm python3 timeout mktemp; do
    command -v "$tool" >/dev/null
done
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pyroclast-gnu-provider.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
timeout --kill-after=1 15 "${CC:-cc}" -g -O0 -no-pie "$here/selected.c" -o "$scratch/selected"
timeout --kill-after=1 15 "${CC:-cc}" -g -O0 -no-pie "$here/replacement.c" -o "$scratch/replacement"
timeout --kill-after=1 15 "${CC:-cc}" -c "$here/alternate.s" -o "$scratch/alt.debug"
timeout --kill-after=1 15 "${CC:-cc}" -nostdlib -no-pie "$here/alt-primary.s" -o "$scratch/alt-primary"
objcopy --only-keep-debug "$scratch/selected" "$scratch/selected.debug"
objcopy --strip-all "$scratch/selected" "$scratch/debug-primary"
objcopy --add-gnu-debuglink="$scratch/selected.debug" "$scratch/debug-primary"
selected_pc=$(nm -n "$scratch/selected" | awk '$3 == "selected_leaf" { print $1 }')
alt_pc=$(nm -n "$scratch/alt-primary" | awk '$3 == "_start" { print $1 }')
[[ -n $selected_pc && -n $alt_pc ]]
failed=0
run() {
    local name=$1 primary=$2 pc=$3 leaf=$4
    shift 4
    local directory="$scratch/$name"
    mkdir "$directory"
    cp "$scratch/"{selected,replacement,selected.debug,debug-primary,alt-primary,alt.debug} "$directory/"
    local mutation=()
    case "$name" in
        selected-primary-replaced)
            mutation=(--replace-primary "$directory/replacement")
            ;;
        debuglink-crc-reopen-replacement)
            mutation=(--watch "$directory/selected.debug" --replace-after-close "$directory/replacement")
            ;;
        altlink-probe-reopen-fifo)
            mutation=(--watch "$directory/alt.debug" --fifo-after-close)
            ;;
    esac
    if ! python3 "$here/trace.py" "$binary" --name "$name" \
        --primary "$directory/$primary" --address "$pc" --leaf "$leaf" \
        --oracle "$oracle" "${provider[@]}" "${libraries[@]}" "${mutation[@]}"; then
        failed=$((failed + 1))
    fi
}
run valid-primary selected "$selected_pc" selected_leaf
run valid-debuglink debug-primary "$selected_pc" selected_leaf
run valid-altlink alt-primary "$alt_pc" alternate_leaf
run selected-primary-replaced selected "$selected_pc" selected_leaf
run debuglink-crc-reopen-replacement debug-primary "$selected_pc" selected_leaf
run altlink-probe-reopen-fifo alt-primary "$alt_pc" alternate_leaf
total=6
if [[ ${#provider[@]} != 0 ]]; then
    total=7
    if env -u PYRO_PRIMARY_FD -u PYRO_PRIMARY_NAME -u PYRO_PRIMARY_CANONICAL \
        LD_LIBRARY_PATH="${PYRO_PROVIDER_LIBRARY_PATH:-${LD_LIBRARY_PATH:-}}" \
        timeout --kill-after=1 4 "$binary" -f -e "$scratch/selected" "$selected_pc" \
        >"$scratch/no-bootstrap.stdout" 2>"$scratch/no-bootstrap.stderr"; then
        printf '%s\n' 'FAIL missing-selected-primary: live pathname fallback accepted'
        failed=$((failed + 1))
    else
        bootstrap_status=$?
        if [[ $bootstrap_status == 1 && ! -s $scratch/no-bootstrap.stdout ]] \
            && grep -q 'selected primary descriptor required' "$scratch/no-bootstrap.stderr"; then
            printf '%s\n' 'PASS missing-selected-primary: no live pathname fallback'
        else
            printf 'FAIL missing-selected-primary: unexpected status %s\n' "$bootstrap_status"
            failed=$((failed + 1))
        fi
    fi
fi
printf 'native-provider: %s/%s failed\n' "$failed" "$total"
[[ $failed == 0 ]]
