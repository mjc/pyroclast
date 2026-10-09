#!/usr/bin/env bash
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
mkdir -p "$repo/target"
root=$(mktemp -d "$repo/target/hook-environment.XXXXXX")
trap 'rm -rf "$root"' EXIT
fixture="$root/repo"
tools="$root/bin"
mkdir -p "$fixture/.githooks" "$fixture/scripts" "$tools"
git init -q "$fixture"
cp "$repo/.githooks/pre-commit" "$fixture/.githooks/pre-commit"

printf '%s\n' '#!/bin/sh' "printf 'cargo %s\\n' \"\$*\" >> \"\$HOOK_LOG\"" \
    "[ \"\${FAIL_CARGO:-no}\" != yes ]" > "$tools/cargo"
printf '%s\n' '#!/bin/sh' "printf 'nix %s\\n' \"\$*\" >> \"\$HOOK_LOG\"" > "$tools/nix"
printf '%s\n' '#!/bin/sh' "echo parity >> \"\$HOOK_LOG\"" \
    "[ \"\${FAIL_PARITY:-no}\" != yes ]" > "$fixture/scripts/check-native-parity"
printf '%s\n' '#!/bin/sh' "echo devenv >> \"\$HOOK_LOG\"" \
    "[ \"\$1\" = shell ] && [ \"\$2\" = -- ] || exit 90" 'shift 2' \
    "export DEVENV_ROOT=\"\$EXPECTED_ROOT\"" "exec \"\$@\"" > "$tools/devenv"
chmod +x "$tools/"* "$fixture/scripts/check-native-parity"
export PATH="$tools:$PATH" EXPECTED_ROOT="$fixture" HOOK_LOG="$root/calls"
cd "$fixture"

check() {
    local environment=$1 expected_entries=$2
    : > "$HOOK_LOG"
    DEVENV_ROOT="$environment" sh .githooks/pre-commit
    local entries
    entries=$(grep -c '^devenv$' "$HOOK_LOG" || true)
    [ "$entries" = "$expected_entries" ] || {
        echo "wrong devenv entry count for DEVENV_ROOT=$environment: $entries (wanted $expected_entries)" >&2
        cat "$HOOK_LOG" >&2
        return 1
    }
    for call in 'cargo fmt --check' 'cargo clippy --all-targets -- -D warnings -W clippy::pedantic' \
        'cargo nextest run' 'cargo build --quiet --release --bin pyroclast' \
        parity 'nix flake check --no-build'; do
        [ "$(grep -Fxc -- "$call" "$HOOK_LOG")" = 1 ] || return 1
    done
}

check "$fixture" 0
check '' 1
check "$root/unrelated-project" 1

git config --local core.hooksPath .githooks
# An already configured checkout must not try to take Git's write lock.
: > .git/config.lock
sh "$repo/scripts/install-hooks"
rm .git/config.lock
git config --local core.hooksPath old-hooks
sh "$repo/scripts/install-hooks"
[ "$(git config --local --get core.hooksPath)" = .githooks ]

if FAIL_PARITY=yes DEVENV_ROOT="$fixture" sh .githooks/pre-commit; then
    echo 'hook ignored parity failure' >&2
    exit 1
fi
if FAIL_CARGO=yes DEVENV_ROOT="$fixture" sh .githooks/pre-commit; then
    echo 'hook ignored Cargo failure' >&2
    exit 1
fi
echo 'hook environment and required-gate checks passed'
