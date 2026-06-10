# KDF Layer

QuantLib v0.4.0 adds `HMAC-SHA256` and `HKDF-SHA256`.

The KDF layer is used by hybrid KEM secret combination so classical and post-quantum shared secrets are mixed with explicit domain separation.

## Hybrid KEM combiner

```cpp
const auto secret = quantlib::hybrid::combine_kem_secrets(
  {.classical_secret = x25519_secret,
   .pq_secret = ml_kem_secret,
   .salt = transcript_hash},
  context,
  32);
```

The combiner rejects missing classical or PQ secrets and refuses zero-length output.
