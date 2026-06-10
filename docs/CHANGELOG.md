# Changelog

## QuantLib v3.0.1

- Production-ready documentation pass.
- Added root `VERSION`, `SECURITY.md`, `CONTRIBUTING.md`, `SUPPORT.md`, `NOTICE`, `.gitignore`, `.gitattributes`, `.editorconfig`, `.clang-format`, and `CMakePresets.json`.
- Added production documentation index, build guide, threat model, provider guide, API map, release process, and repository hygiene guide.
- Updated README to remove stale v2 status text and clearly document provider-dependent boundaries.
- Updated version stamping to `3.0.1`.
- Kept PQ provider behavior fail-closed unless liboqs is linked.

## QuantLib v3.0.0

- Cleaned source layout and grouped implementation files by responsibility.
- Removed unused empty source directories.
- Added `docs/SOURCE-CLEANUP.md`.
- Kept the public API and namespace stable.

## v2.2.0

- Added `quantlib::easy` integration wrapper/facade.
- Added `include/quantlib/easy.hpp` and `src/easy.cpp`.
- Added `QuantVault` high-level create/open/generate/sign/verify/rotate/save API.
- Added one-shot helper functions for simple vault creation, signing-key generation, and signing.
- Added `docs/EASY.md`, `examples/easy-wrapper.cpp`, and `quantlib-inspect --easy`.
- Added integration tests for wrapper vault roundtrip, domain-bound signing, reopen, and rotation.

## v2.1.0

- Added operational readiness layer.
- Added deployment profiles for local-dev, workstation, server, validator, ci-release, and custody-host.
- Added operator runbook metadata and config templates.
- Added `quantlib-inspect --ops` and `quantlib-inspect --runbook`.
- Added deployment-check scripts.
- Extended release gate and self-test coverage.

## v2.0.0

- Added production-baseline release boundary APIs.
- Added required release artifact manifest.
- Added SBOM component inventory scaffolding.
- Added security document set manifest.
- Added release signing/checksum step metadata.
- Added `quantlib-inspect --production`.
- Added `quantlib-inspect --sbom`.
- Added `docs/PRODUCTION-BASELINE.md`, `docs/SBOM.md`, `docs/RELEASE-SIGNING.md`, and `docs/AUDIT-PACKAGE.md`.
- Added checksum, SBOM, and release-signing scaffold scripts for Windows and Unix.
- Expanded hardened release gate with artifact, security-doc, and production-boundary checks.
- Expanded self-test with v2 production-baseline readiness check.

## v1.13.0

- Added test/fuzz/CI readiness layer.
- Added `include/quantlib/testing.hpp` and `src/testing.cpp`.
- Added `quantlib-inspect --test-infra`.
- Added sanitizer, coverage, fuzz, package-check, CI matrix, and performance-budget metadata.
- Added CMake options `QUANTLIB_ENABLE_SANITIZERS`, `QUANTLIB_ENABLE_COVERAGE`, `QUANTLIB_BUILD_FUZZERS`, and `QUANTLIB_ENABLE_PERF_GUARD`.
- Added CMake install/export rules for package verification.
- Added GitHub Actions CI scaffold and local CI/package/fuzz/coverage/perf scripts.
- Added `docs/TESTING.md` and `docs/CI.md`.
- Updated release gate and self-test to include test/fuzz/CI readiness.

## v1.12.0

- Added QuantLink protocol production stack.
- Added cipher-suite negotiation, downgrade protection, handshake state transitions, record/plaintext limits, close-notify validation, and rekey threshold metadata.
- Added protocol self-test and unit tests.
- Added initial fuzz scaffolds for record decoding and protocol limits.

## v1.11.0

- Added vault hardening, atomic save, backup recovery, generation anchors, and audit-head verification.

## v2.4.0 GPU Acceleration Boundary

- Added optional GPU provider hooks.
- Added `quantlib::gpu` batch hashing API.
- Added `quantlib-inspect --gpu`.
- Added production-safe CPU fallback when CUDA/OpenCL backends are unavailable.


## v2.4.0 Hardware Acceleration + Batch Crypto

- Added hardware dispatch metadata for CPU native, AES-NI, AVX2, AVX-512, NEON, CUDA, and OpenCL paths.
- Added batch SHA-256 API through `quantlib::batch::sha256`.
- Added fail-closed batch signature verification boundary.
- Added `quantlib-inspect --hardware` and `quantlib-inspect --batch`.
- Upgraded `quantlib-bench` with batch hashing metrics.

## v2.5.0 - Throughput Engine

- Added `quantlib::throughput` scheduler and zero-copy batch views.
- Added parallel batch SHA-256 helper.
- Routed large batch SHA-256 work through the throughput engine.
- Added `quantlib-inspect --throughput` and docs/tests.


## QuantLib v3.0.0

Added the SIMD Engine: CPU feature detection, SIMD dispatch table, aligned buffers, `--cpu`, `--simd`, and SIMD benchmark/test coverage. The accelerated kernels remain provider-gated and correctness is anchored to scalar/provider paths.
