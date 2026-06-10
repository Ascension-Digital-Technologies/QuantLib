# QuantLib Record Layer

QuantLib v0.7.0 adds a small encrypted record layer for RPC, node-to-node traffic, storage channels, and application protocols.

The record layer is not a network stack. It is a safe framing helper built on top of the session key schedule.

## Frame layout

```text
header      19 bytes
nonce       12 bytes
ciphertext  variable
tag         16 bytes
```

## Header fields

```text
version         u8
content_type    u8
role            u8
sequence        u64 big endian
ciphertext_len  u32 big endian
tag_len         u32 big endian
```

The encoded header is authenticated as AEAD associated data. Caller-supplied associated data is also transcript-bound into the AEAD AAD.

## Nonce construction

Each sender receives a base nonce from the session key schedule. Per-record nonces are produced by XORing the final eight nonce bytes with the big-endian sequence number.

```text
record_nonce = base_nonce XOR sequence
```

A sequence must never repeat for the same write key. The record layer rejects exhausted sequence values.

## Roles

Client and server directions use separate keys and separate base nonces.

```text
client -> server: client_write_key + client_write_nonce
server -> client: server_write_key + server_write_nonce
```

This prevents accidental key/nonce overlap between directions.

## Fail-closed checks

The implementation rejects:

- unsupported record versions
- invalid roles
- invalid tag sizes
- mismatched frame lengths
- sequence exhaustion
- nonce mismatch
- AEAD authentication failures
- tampered associated data

## Intended use

Use the record layer after a KEM/hybrid-KEM handshake has produced a shared secret and the session layer has derived `KeyMaterial`.

```cpp
auto frame = quantlib::record::seal(
  quantlib::aead::Algorithm::chacha20_poly1305,
  key_material,
  quantlib::session::Role::client,
  quantlib::record::ContentType::data,
  sequence,
  plaintext,
  associated_data);
```
