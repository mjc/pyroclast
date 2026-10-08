#!/usr/bin/env bash
# Sourced by each entrypoint; exported selection survives child parity scripts.
if [ -z "${PERF_BIN:-}" ]; then
    if perf version >/dev/null 2>&1; then
        PERF_BIN=$(command -v perf)
    else
        # Ubuntu's PATH wrapper can reject the host kernel even though its
        # packaged perf binary can read and record the oracle data.
        PERF_BIN=$(find /usr/lib/linux-tools* -name perf -type f -executable -print -quit 2>/dev/null) || PERF_BIN=
    fi
fi
if [ -z "$PERF_BIN" ] || [ ! -x "$PERF_BIN" ] || ! "$PERF_BIN" version >/dev/null 2>&1; then
    echo "no working perf executable found: ${PERF_BIN:-perf}" >&2
    exit 1
fi
export PERF_BIN
