# QuantLib Software Security Module

The Software Security Module, or SSM, is the private-key custody layer for QuantLib.
It is designed for applications that need software-only key management without exposing raw private keys to normal application code.

## Goals

- Generate signing, KEM, and symmetric keys.
- Store private material only as sealed AES-256-GCM records.
- Return opaque key handles instead of raw private keys.
- Allow controlled operations such as signing and decapsulation by handle.
- Export public keys and sealed objects without exporting raw private material.
- Reject tampered sealed objects before import.
- Zeroize temporary private material after use.

## Non-goals

- This is not a hardware security module.
- This does not claim side-channel resistance equal to dedicated hardware.
- This does not protect against a fully compromised host process.
- This does not yet include OS keychain, TPM, enclave, or HSM binding.

## Sealing model

The caller provides or generates a 32-byte master key. The SSM derives an internal seal key using HKDF-SHA256:

```text
seal_key = HKDF-SHA256(master_key, "ssm-seal-salt", "QuantLib SSM Seal v1", 32)
```

Private key payloads are sealed with AES-256-GCM. The associated data contains the object handle, object type, algorithm, flags, creation time, label, public key, and key id. This prevents metadata swapping and tampering.

## Handles

Each object receives an opaque 128-bit hex handle derived from SHA-256 over stable object metadata. Applications should store and use handles instead of raw key bytes.

## Supported operations

- `generate_sign_key`
- `generate_kem_key`
- `generate_symmetric_key`
- `sign_message`
- `decapsulate`
- `public_key`
- `export_sealed`
- `import_sealed`
- `encode_sealed`
- `decode_sealed`
- `erase`
- `list`

## Future hardening

Recommended future additions:

- OS secure storage integration.
- TPM / Secure Enclave / hardware-backed master-key wrapping.
- passphrase KDF using Argon2id or scrypt.
- per-key access policy with rate limits and PIN/session unlocks.
- append-only audit log with hash-chain integrity.
- process isolation: SSM daemon with IPC instead of in-process use.

## v1.2.0 Policy additions

The SSM now supports lifecycle and operation policy enforcement:

- key states: active, locked, disabled, expired, destroyed, compromised
- domain allow-list for signing keys
- maximum private operation counters
- domain-separated signing through `sign_domain()`
- public verification through `verify_domain_signature()`
- usage metadata through `ObjectInfo::used_operations` and `ObjectInfo::last_used_at`

Raw `sign_message()` remains available for compatibility, but protocol integrations should prefer `sign_domain()` so signatures cannot be replayed across unrelated protocol contexts.
