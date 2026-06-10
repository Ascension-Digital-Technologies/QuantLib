#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
BUILD="build-coverage"
cmake -S . -B "$BUILD" -DQUANTLIB_ENABLE_COVERAGE=ON -DQUANTLIB_BUILD_TESTS=ON
cmake --build "$BUILD" --config Debug
ctest --test-dir "$BUILD" --output-on-failure
"$BUILD/quantlib-inspect" --test-infra
