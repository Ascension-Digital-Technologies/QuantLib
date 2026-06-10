#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
BUILD="build-fuzz"
cmake -S . -B "$BUILD" -DQUANTLIB_BUILD_FUZZERS=ON
cmake --build "$BUILD" --config Release
printf "QUANTLIB-FUZZ-SMOKE" | "$BUILD/quantlib-fuzz-record-decode" || true
printf "QUANTLIB-FUZZ-SMOKE" | "$BUILD/quantlib-fuzz-protocol-limits" || true
