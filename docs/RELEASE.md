# Release Notes: v1.0.0

QuantLib v1.0.0 is the first production-baseline package of the library architecture.

## Release scope

This release is suitable as a hardened foundation for protocol integration, encrypted internal RPC experiments, channel-state testing, key blob formatting, transcript binding, policy enforcement, and backend-provider integration.

## Crypto claims

QuantLib v1.0.0 does not claim in-tree implementations of ML-KEM, ML-DSA, SLH-DSA, secp256k1, SHA-3, SHA-512, or BLAKE3. Those algorithms remain explicit typed errors or provider-gated features until vetted implementations are linked.

OpenSSL-backed AES-256-GCM, ChaCha20-Poly1305, X25519, and Ed25519 are available only when OpenSSL is found at build time.

## Release checklist

- CMake configure passes
- CMake build passes
- CTest passes
- `quantlib-inspect --version` reports `1.0.0`
- `quantlib-inspect --selftest` reports pass
- `quantlib-inspect --providers` exposes provider state
- `quantlib-bench` runs benchmark smoke

## Recommended integration path

1. Call self-test at startup.
2. Inspect provider availability at startup.
3. Refuse unsafe policy/profile combinations.
4. Use transcript-bound sessions for protocol traffic.
5. Use channel wrappers for record send/receive flows.
6. Keep PQ and hybrid production paths gated until vetted PQ provider support is enabled.
