#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
BUILD="${1:-build}"
cmake -S . -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_ENABLE_HARDENING=ON
cmake --build "$BUILD" --config Release
ctest --test-dir "$BUILD" --output-on-failure
