#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
BUILD="${1:-build}"
ITERS="${2:-100000}"
cmake -S . -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_BUILD_BENCHES=ON
cmake --build "$BUILD" --target quantlib-bench --config Release
"$BUILD/quantlib-bench" "$ITERS"
