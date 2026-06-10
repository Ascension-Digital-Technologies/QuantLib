# PQ Production Integration

QuantLib v1.10.0 adds the production-safe post-quantum provider integration boundary.

## Scope

This release does not fabricate in-tree ML-KEM, ML-DSA, or SLH-DSA implementations. Instead, it adds the adapter boundary, provider status reporting, planned KAT harness, metadata validation, and downgrade guards required before a vetted backend can be treated as production.

## Provider states

- `unavailable`: PQ APIs fail closed.
- `linked`: a vetted PQ provider such as liboqs is linked and discoverable.
- `production_ready`: reserved until KATs, fuzzing, audit, and release gates pass.

## Required algorithms

- ML-KEM-512 / 768 / 1024
- ML-DSA-44 / 65 / 87
- SLH-DSA-SHA2-128s
- Hybrid X25519 + ML-KEM-768
- Hybrid Ed25519 + ML-DSA-65

## Required release gates

- Provider reports name/version/status.
- All algorithm sizes match the selected standard profile.
- Unsupported providers fail closed.
- Downgrades to lower NIST security levels are rejected.
- KAT harness exists and reports planned/runnable vectors.
- Real KAT vector execution must be added before claiming production PQ support.

## CLI

```bash
./quantlib-inspect --pq
./quantlib-inspect --pq-provider
./quantlib-inspect --pq-kat
```
