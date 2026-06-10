# QuantLib v3.0.0 — Production PQ Engine

This release completes the post-quantum provider integration boundary. ML-KEM, ML-DSA, and SLH-DSA operations are wired through liboqs when it is linked at build time. Builds without liboqs remain fail-closed.

## Added

- liboqs-backed ML-KEM keypair/encapsulate/decapsulate paths
- liboqs-backed ML-DSA and SLH-DSA keypair/sign/verify paths
- Hybrid X25519 + ML-KEM-768 KEM
- Hybrid Ed25519 + ML-DSA-65 signature mode
- PQ provider smoke-KAT roundtrip harness
- PQ downgrade guard remains enforced
- Packed hybrid key/ciphertext/signature containers

## Production boundary

PQ is active only when `QUANTLIB_ENABLE_LIBOQS=ON` and liboqs is found. Without liboqs, all PQ operations return `unsupported_algorithm`.
