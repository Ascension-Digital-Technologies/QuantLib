#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
TARGET="${1:-.}"
OUT="${2:-SHA256SUMS}"
find "$TARGET" -type f ! -name "$OUT" -print0 | sort -z | xargs -0 sha256sum > "$OUT"
echo "wrote $OUT"
