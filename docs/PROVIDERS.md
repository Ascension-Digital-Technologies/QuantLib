# Provider Architecture

QuantLib v0.3.0 introduces a provider registry so algorithm support can be discovered without changing public APIs.

## Built-in Providers

- `builtin`: internal safe utilities, SHA-256, key encoding, secure memory helpers.
- `openssl`: optional vetted classical backend for AES-256-GCM, ChaCha20-Poly1305, X25519, and Ed25519.
- `pq-placeholder`: adapter slot for ML-KEM, ML-DSA, SLH-DSA, HQC, and hybrid modes. It is intentionally marked unavailable until a vetted PQ backend is wired.

## CLI Discovery

```bash
quantlib-inspect --providers
```

## Policy

Provider discovery is intentionally separate from algorithm dispatch. Unsupported algorithms continue to fail closed with `unsupported_algorithm` instead of silently falling back or downgrading.

Future providers should be added behind the registry and must expose:

- provider name
- provider version
- availability status
- capabilities
- supported algorithms
- deterministic failure behavior

## Upcoming Provider Targets

- `liboqs` provider for ML-KEM/ML-DSA/SLH-DSA experimentation.
- `native-fast` provider for optimized internal implementations after test vectors and audits.
- `hardware` provider for HSM/enclave/private-key-never-leaves-handle flows.
