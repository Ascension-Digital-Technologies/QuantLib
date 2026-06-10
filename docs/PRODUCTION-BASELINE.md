# QuantLib v2.0.0 Production Baseline

QuantLib v2.0.0 is the first production-baseline package for the classical provider-backed crypto, SSM custody, vault, audit, protocol, and release-gate layers.

## Production-ready scope

- Stable public API manifest is versioned.
- Classical cryptography is routed through provider-backed OpenSSL paths when linked.
- SSM keys are sealed, policy-controlled, session-gated, auditable, rotatable, and protected by best-effort secure memory.
- Vault files use authenticated encryption, audit-head verification, generation anchors, atomic save, and backup recovery helpers.
- QuantLink exposes handshake state, suite negotiation, downgrade guards, record limits, replay protection, and close/rekey metadata.
- Release gates include provider inventory, self-test, testing/fuzz/CI metadata, security boundary docs, SBOM inventory, and release artifact requirements.

## Provider-dependent scope

- ML-KEM, ML-DSA, and SLH-DSA require a vetted PQ provider before use.
- Argon2id and scrypt require linked memory-hard KDF providers before production use.
- FIPS-compatible mode requires an externally configured and validated OpenSSL FIPS provider deployment.
- Release signing requires a real operator-held signing key outside the repository.

## Not claimed

- QuantLib is not itself FIPS certified.
- The software SSM cannot protect secrets against a fully compromised host OS.
- Experimental PQ/provider code is not a production claim until backend validation and KATs pass.
- No custom cryptographic algorithm is claimed as proven.
