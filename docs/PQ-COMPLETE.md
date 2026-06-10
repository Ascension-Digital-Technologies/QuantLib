# QuantLib PQ Completion

QuantLib now has real provider-backed post-quantum operation paths.

## Supported through provider

- ML-KEM-512, ML-KEM-768, ML-KEM-1024
- ML-DSA-44, ML-DSA-65, ML-DSA-87
- SLH-DSA-SHA2-128s

## Hybrid defaults

- KEM: X25519 + ML-KEM-768
- Signature: Ed25519 + ML-DSA-65

## Fail-closed rule

If liboqs is not linked, QuantLib reports PQ metadata but refuses to generate keys, encapsulate, decapsulate, sign, or verify with PQ algorithms.

## Build

```bash
cmake -S . -B build -DQUANTLIB_ENABLE_LIBOQS=ON
cmake --build build --config Release
```

The provider check commands are:

```bash
quantlib-inspect --pq-provider
quantlib-inspect --pq-kat
```
