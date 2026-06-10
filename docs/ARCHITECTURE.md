# Architecture

QuantLib is organized around stable public APIs and swappable backend implementations.

## Layers

```txt
include/quantlib/      Public C++20 APIs
src/core/           Result, bytes, secure memory primitives
src/rng/            Entropy and random byte generation
src/hash/           Hash algorithms
src/aead/           Authenticated encryption APIs/backends
src/classical/      X25519, Ed25519, future secp256k1 adapters
src/pq/             PQ adapter anchors for ML-KEM, ML-DSA, SLH-DSA
src/hybrid/         PQ/classical hybrid facades
src/key/            Versioned key container and key IDs
tests/              Correctness and rejection tests
benches/            Performance smoke benchmarks
tools/              CLI utilities
```

## Backend Policy

The public API should not expose backend details. Backends may include:

- OpenSSL EVP / providers
- liboqs
- platform security modules
- hardware-backed providers
- internal formally reviewed implementations

Algorithms that are declared but not backed by a vetted implementation must fail closed with `unsupported_algorithm`.

## Current Backend

v0.2.0 uses OpenSSL when available for:

- AES-256-GCM
- ChaCha20-Poly1305
- X25519
- Ed25519

CMake defines `QUANTLIB_HAVE_OPENSSL=1` only when OpenSSL is found.


## Session Layer

The session layer derives deterministic protocol key material after a KEM/hybrid-KEM exchange. It binds client nonce, server nonce, and transcript hash to handshake secrets, then derives role-separated write keys, base nonces, confirmation tags, and exporter secrets.
