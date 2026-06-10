# QuantLib v2.7.0 Release Notes

## Added

- CPU feature detection layer.
- SIMD dispatch table.
- SHA-256 SIMD dispatch boundary with scalar equivalence tests.
- AES-NI and AVX2 ChaCha20 provider boundary reporting.
- Aligned buffer helper.
- `quantlib-inspect --cpu`.
- `quantlib-inspect --simd`.
- `quantlib-bench --simd`.
- SIMD docs and tests.

## Safety

The SIMD layer is fail-safe: accelerated providers must prove equivalence to scalar/provider paths before they are treated as production-ready. v2.7.0 exposes the hardware and dispatch boundaries, while cryptographic correctness remains anchored to the existing scalar/OpenSSL-backed code paths.
