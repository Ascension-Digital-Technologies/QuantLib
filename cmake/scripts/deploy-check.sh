#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
BIN_DIR="${1:-build}"
"$BIN_DIR/quantlib-inspect" --version
"$BIN_DIR/quantlib-inspect" --selftest
"$BIN_DIR/quantlib-inspect" --release
"$BIN_DIR/quantlib-inspect" --inventory
"$BIN_DIR/quantlib-inspect" --ops
"$BIN_DIR/quantlib-inspect" --runbook >/dev/null
