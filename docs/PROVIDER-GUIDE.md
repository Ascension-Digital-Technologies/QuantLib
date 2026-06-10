# Provider Guide

QuantLib uses provider boundaries so optional crypto backends are explicit and fail closed.

## OpenSSL

OpenSSL enables production classical algorithms such as AES-256-GCM, ChaCha20-Poly1305, X25519, and Ed25519.

```bash
cmake -S . -B build -DQUANTLIB_ENABLE_OPENSSL=ON
```

Verify:

```bash
quantlib-inspect --providers
quantlib-inspect --inventory
```

## liboqs

liboqs enables ML-KEM, ML-DSA, and SLH-DSA provider paths.

```bash
cmake -S . -B build -DQUANTLIB_ENABLE_LIBOQS=ON
```

Verify:

```bash
quantlib-inspect --pq-provider
quantlib-inspect --pq-kat
```

If liboqs is not found, PQ operations remain fail-closed.

## CUDA/OpenCL

GPU support is optional and routed through provider hooks. QuantLib falls back to CPU paths unless a vetted provider is linked.

```bash
cmake -S . -B build -DQUANTLIB_ENABLE_GPU=ON -DQUANTLIB_ENABLE_CUDA=ON
```

Verify:

```bash
quantlib-inspect --gpu
```

## Provider rules

- No silent downgrade.
- No unsupported algorithm activation.
- Provider name and version must be visible in inventory output.
- Tests must cover unavailable provider behavior.
