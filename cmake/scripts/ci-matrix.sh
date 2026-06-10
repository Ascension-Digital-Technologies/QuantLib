#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
BUILD="build-ci"
cmake -S . -B "$BUILD" -DQUANTLIB_BUILD_EXAMPLES=ON -DQUANTLIB_ENABLE_HARDENING=ON
cmake --build "$BUILD" --config Release
ctest --test-dir "$BUILD" --output-on-failure
"$BUILD/quantlib-inspect" --selftest
"$BUILD/quantlib-inspect" --release
"$BUILD/quantlib-inspect" --test-infra
