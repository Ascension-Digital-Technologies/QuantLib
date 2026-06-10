# QuantLib v4.0.0 Final Production Release

QuantLib v4.0.0 is the final production packaging pass for the current crypto library line. It does not pretend that every optional provider is present on every machine; instead it makes provider status, benchmark output, release readiness, and integration boundaries explicit.

## Highlights

- Added full health inspection through `quantlib-inspect --full`.
- Added full benchmark suite mode through `quantlib-bench --all`.
- Finalized production status documentation and release artifact checklist.
- Added final build/provider/GPU/PQ/SIMD docs for deployment handoff.
- Kept PQ, CUDA, OpenCL, and FIPS paths provider-gated and fail-closed unless linked and validated.

## Production boundary

Production-ready means the repository builds, tests, packages, documents, and reports its security state correctly. Optional cryptographic providers remain dependent on the target build environment:

- OpenSSL-backed classical crypto: production path when OpenSSL is linked.
- liboqs-backed PQ crypto: production path only when liboqs is linked and provider tests pass.
- OpenCL GPU SHA-256: accelerated path only when OpenCL is linked and runtime detection succeeds.
- CUDA: provider boundary exists; CUDA kernels remain off unless explicitly provided and enabled.
