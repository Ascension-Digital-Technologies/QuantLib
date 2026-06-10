# QuantLib SIMD Engine

QuantLib v2.7.0 adds a SIMD dispatch foundation for hardware-aware crypto routing.

## Included

- CPU feature detection for x86/x86_64 and ARM/ARM64 feature paths.
- CPUID-backed reporting for AVX, AVX2, AVX-512, AES-NI, SHA-NI, PCLMULQDQ, BMI2, and ADX where available.
- NEON compile/runtime reporting on ARM platforms.
- SIMD dispatch table for SHA-256, AES-GCM, and ChaCha20 provider boundaries.
- Aligned byte buffers for future AVX-512/GPU upload paths.
- SIMD self-tests that compare all SIMD dispatch boundaries against scalar SHA-256 output.

## Important production boundary

The v2.7.0 SIMD layer is a safe dispatch and validation foundation. It does not falsely claim unaudited in-tree vector cryptography as production accelerated crypto. Provider-backed crypto remains authoritative until dedicated AVX2/AVX-512/AES-NI/ChaCha20 kernels are implemented, benchmarked, fuzzed, and audited.

## CLI

```bash
quantlib-inspect --cpu
quantlib-inspect --simd
quantlib-bench --simd
```
