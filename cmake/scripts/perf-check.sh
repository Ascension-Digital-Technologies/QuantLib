#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
BUILD="build-perf"
cmake -S . -B "$BUILD" -DQUANTLIB_BUILD_BENCHES=ON -DQUANTLIB_ENABLE_HARDENING=ON
cmake --build "$BUILD" --config Release
"$BUILD/quantlib-bench"
"$BUILD/quantlib-inspect" --test-infra
