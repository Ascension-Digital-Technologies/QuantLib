# Algorithms

## Implemented in v0.2.0

| Area | Algorithm | Backend | Status |
|---|---|---|---|
| Hash | SHA-256 | internal portable C++ | Working |
| AEAD | AES-256-GCM | OpenSSL EVP | Working when OpenSSL is found |
| AEAD | ChaCha20-Poly1305 | OpenSSL EVP | Working when OpenSSL is found |
| KEM-style ECDH | X25519 | OpenSSL EVP_PKEY | Working when OpenSSL is found |
| Signature | Ed25519 | OpenSSL EVP_PKEY | Working when OpenSSL is found |

## Exposed but adapter-gated

| Area | Algorithm | Status |
|---|---|---|
| Hash | SHA-512 | Exposed, not implemented |
| Hash | SHA3-256 | Exposed, not implemented |
| Hash | BLAKE3 | Exposed, not implemented |
| KEM | ML-KEM-512/768/1024 | Exposed, waiting for vetted PQ backend/provider |
| Signature | ML-DSA-44/65/87 | Exposed, waiting for vetted PQ backend/provider |
| Signature | SLH-DSA-SHA2-128s | Exposed, waiting for vetted PQ backend/provider |
| Hybrid KEM | X25519 + ML-KEM-768 | Exposed, waiting for ML-KEM backend |
| Hybrid Sign | Ed25519 + ML-DSA-65 | Exposed, waiting for ML-DSA backend |

## X25519 KEM-style Encapsulation

QuantLib treats X25519 as a KEM-style operation for API consistency:

1. Recipient generates a static X25519 keypair.
2. Sender generates an ephemeral X25519 keypair.
3. Sender derives `ECDH(ephemeral_secret, recipient_public)`.
4. Sender returns ephemeral public key as ciphertext.
5. Recipient derives `ECDH(recipient_secret, ephemeral_public)`.

This is not post-quantum safe by itself. It is intended to become one side of the hybrid KEM once ML-KEM is wired.

## Default Future Hybrid Profile

```txt
KEM:       X25519 + ML-KEM-768
Signature: Ed25519 + ML-DSA-65
KDF:       HKDF-SHA256 or SHAKE256 with domain separation
```
