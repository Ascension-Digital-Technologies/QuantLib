#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
BUILD="build-package"
PREFIX="package-root"
cmake -S . -B "$BUILD" -DQUANTLIB_BUILD_EXAMPLES=ON -DQUANTLIB_ENABLE_HARDENING=ON
cmake --build "$BUILD" --config Release
cmake --install "$BUILD" --prefix "$PREFIX"
"$PREFIX/bin/quantlib-inspect" --version
"$PREFIX/bin/quantlib-inspect" --selftest
