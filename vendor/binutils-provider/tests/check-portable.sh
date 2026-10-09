#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 ]] || exit 2
helper=$1
oracle=$2
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pyroclast-gnu-portable.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
flags=()
if [[ -n ${PYRO_FIXTURE_TARGET:-} ]]; then
    flags=(--target="$PYRO_FIXTURE_TARGET")
fi
"${PYRO_FIXTURE_CC:-${CC:-cc}}" "${flags[@]}" -g -O0 -c "$here/selected.c" -o "$scratch/selected.o"
"${PYRO_FIXTURE_CC:-${CC:-cc}}" "${flags[@]}" -g -O0 -c "$here/replacement.c" -o "$scratch/replacement.o"
env -u LD_LIBRARY_PATH -u DYLD_LIBRARY_PATH \
    timeout --kill-after=1 4 "$oracle" -f -C -e "$scratch/selected.o" 0 \
    > "$scratch/independent.stdout"
grep -q selected_leaf "$scratch/independent.stdout"
cp "$scratch/selected.o" "$scratch/snapshot"
exec 9< "$scratch/snapshot"
rm "$scratch/snapshot"
canonical=$(realpath "$scratch/selected.o")
cp "$scratch/replacement.o" "$scratch/selected.o"
libraries=()
if [[ -n ${PYRO_PROVIDER_LIBRARY_PATH:-} ]]; then
    case $(uname -s) in
        Darwin) libraries=("DYLD_LIBRARY_PATH=$PYRO_PROVIDER_LIBRARY_PATH") ;;
        *) libraries=("LD_LIBRARY_PATH=$PYRO_PROVIDER_LIBRARY_PATH") ;;
    esac
fi
timeout --kill-after=1 4 env -u LD_LIBRARY_PATH -u DYLD_LIBRARY_PATH \
    "${libraries[@]}" PYRO_PRIMARY_FD=9 PYRO_PRIMARY_NAME="$scratch/selected.o" \
    PYRO_PRIMARY_CANONICAL="$canonical" \
    "$helper" -f -C -e "$scratch/selected.o" 0 > "$scratch/retained.stdout"
exec 9<&-
cmp "$scratch/independent.stdout" "$scratch/retained.stdout"
env -u LD_LIBRARY_PATH -u DYLD_LIBRARY_PATH \
    timeout --kill-after=1 4 "$oracle" -f -C -e "$scratch/selected.o" 0 \
    > "$scratch/replaced.stdout"
grep -q replacement_leaf "$scratch/replaced.stdout"
printf '%s\n' 'PASS selected-primary stdout equals independent GNU after live replacement'
if timeout --kill-after=1 4 env -u LD_LIBRARY_PATH -u DYLD_LIBRARY_PATH \
    -u PYRO_PRIMARY_FD -u PYRO_PRIMARY_NAME -u PYRO_PRIMARY_CANONICAL \
    "${libraries[@]}" "$helper" -f -C -e "$scratch/selected.o" 0 \
    > "$scratch/no-bootstrap.stdout" 2> "$scratch/no-bootstrap.stderr"; then
    printf '%s\n' 'FAIL live input accepted without selected primary' >&2
    exit 1
fi
test ! -s "$scratch/no-bootstrap.stdout"
grep -q 'selected primary descriptor required' "$scratch/no-bootstrap.stderr"
printf '%s\n' 'PASS missing bootstrap has no live pathname fallback'
