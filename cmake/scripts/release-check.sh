#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
BUILD="build-release-check"
cmake -S . -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_BUILD_TESTS=ON -DQUANTLIB_BUILD_BENCHES=ON -DQUANTLIB_BUILD_EXAMPLES=ON -DQUANTLIB_ENABLE_HARDENING=ON
cmake --build "$BUILD" --config Release
ctest --test-dir "$BUILD" --output-on-failure
"$BUILD/quantlib-inspect" --selftest
"$BUILD/quantlib-inspect" --release
"$BUILD/quantlib-inspect" --inventory
"$BUILD/quantlib-inspect" --stable-api
"$BUILD/quantlib-inspect" --production-ready
