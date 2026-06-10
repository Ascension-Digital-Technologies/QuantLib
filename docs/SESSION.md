# QuantLib Session Layer

QuantLib v0.6.0 adds a small deterministic session/key-schedule layer. It does not replace TLS and it is not a transport protocol. It provides reusable helpers for protocols that already completed a classical, PQ, or hybrid KEM and need consistent key derivation.

## What it provides

- 12-byte client/server nonce binding
- 32-byte transcript hash binding
- handshake secret derivation with HKDF-SHA256
- separate client/server write keys
- separate client/server base nonces
- role-separated key-confirmation tags
- exporter secrets for RPC/storage/application subkeys

## Safety rules

- Both nonces must be exactly 12 bytes.
- Transcript hash must be exactly 32 bytes.
- Confirmation tags are verified with constant-time comparison.
- Client and server keys use different labels.
- Exported keys require explicit labels and context.

## Typical flow

```cpp
auto hello = quantlib::session::make_hello(client_nonce, server_nonce, transcript_hash);
auto hs = quantlib::session::derive_handshake_secret(shared_secret, hello.value());
auto keys = quantlib::session::derive_keys(hs.value(), hello.value());
auto tag = quantlib::session::confirmation_tag(quantlib::session::Role::client, hs.value(), hello.value());
```

Use the transcript hash to bind the exact protocol messages, algorithm choices, public keys, ciphertexts, and policy profile used during negotiation.
