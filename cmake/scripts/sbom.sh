#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
BIN="${1:-./build/quantlib-inspect}"
OUT="${2:-SBOM.txt}"
"$BIN" --sbom > "$OUT"
echo "wrote $OUT"
