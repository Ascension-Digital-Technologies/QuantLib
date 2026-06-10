# Post-Quantum Provider Plan

QuantLib v0.4.0 adds a post-quantum provider boundary without claiming unsafe in-tree PQ implementations.

## Current status

- ML-KEM, ML-DSA, and SLH-DSA metadata is registered.
- Default hybrid APIs fail closed unless a vetted PQ backend is enabled.
- `quantlib-inspect --pq` reports expected key, ciphertext, signature, and shared-secret sizes.
- The CMake option `QUANTLIB_ENABLE_LIBOQS` detects `oqs/oqs.h` and enables the adapter flag, but the production symbols are intentionally not implemented in-tree yet.

## Supported metadata

| Family | Algorithms |
|---|---|
| ML-KEM | ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
| ML-DSA | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| SLH-DSA | SLH-DSA-SHA2-128s |

## Default hybrid profile

| Operation | Default |
|---|---|
| KEM | X25519 + ML-KEM-768 |
| Signature | Ed25519 + ML-DSA-65 |
| Secret combiner | HKDF-SHA256 with `QuantLib Hybrid KEM v1` domain separation |

## Integration rule

Do not replace this adapter with ad-hoc PQ code. Wire only a vetted backend with official known-answer tests, malformed-input tests, fuzzing, and constant-time review.
