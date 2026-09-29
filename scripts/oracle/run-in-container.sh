#!/usr/bin/env bash
# Runs inside the oracle container: records the oracle inputs and then runs the
# pyroclast comparison. This is the full path (record + compare); for fast
# iteration that skips re-recording use compare-in-container.sh (driven from
# the host by scripts/oracle-compare).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$here/record-in-container.sh"
bash "$here/compare-in-container.sh"
