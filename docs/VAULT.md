# QuantLib Vault

The vault layer turns the Software Security Module into persistent encrypted storage.

## Purpose

The SSM keeps private keys behind handles while a process is running. The vault stores the SSM master key, sealed SSM objects, and the tamper-evident audit log on disk without exposing raw private-key bytes.

## File format

Vault files use magic `AVAULT1` and version `5`.

A vault contains:

- vault id
- label
- KDF name
- KDF iteration count
- KDF memory KiB
- KDF parallelism
- created/updated timestamps
- vault generation counter
- previous audit-head metadata
- 16-byte salt
- AES-256-GCM nonce
- encrypted SSM master key
- authentication tag
- encoded sealed SSM objects
- encoded audit log
- stored audit-head hash
- SHA-256 file checksum

The encrypted master key is authenticated with vault metadata as AEAD associated data.

## KDF

v1.11.0 uses `pbkdf2-hmac-sha256` as the portable built-in password/PIN unlock foundation.

Argon2id and scrypt remain fail-closed provider hooks until vetted memory-hard backends are linked.

## Unlock flow

```txt
passphrase/PIN
  -> PBKDF2-HMAC-SHA256
  -> AES-256-GCM unwrap key
  -> decrypt SSM master key
  -> decode sealed objects and audit log
  -> verify audit hash chain + stored audit head
  -> import sealed objects into SSM
  -> operate by handle/session
```

Wrong passphrases fail closed during AEAD authentication.

## Durability helpers

`save_vault_atomic()` writes a temporary file, backs up the previous primary vault to `.bak`, and renames the temporary file into place.

`load_vault()` opens the primary vault first and falls back to `.bak` when the primary is unreadable.

`VaultAnchor` can be persisted by applications to reject older vault generations and same-generation audit-head mismatches.

See `docs/VAULT-HARDENING.md`.

## CLI

```bash
quantlib-ssm info
quantlib-ssm init vault.quantlib passphrase "local vault"
quantlib-ssm inspect vault.quantlib
quantlib-ssm generate-ed25519 vault.quantlib passphrase validator
quantlib-ssm list vault.quantlib passphrase
quantlib-ssm recover vault.quantlib passphrase
```

## Safety rules

- The vault does not add raw private-key export.
- Private-key operations still happen through SSM handles and sessions.
- Sealed object metadata remains authenticated.
- Vault metadata is authenticated during master-key unwrap.
- The vault rejects tampered files and wrong passphrases.
- The audit-head stored in the vault must match the decoded audit hash chain.
- Rollback protection requires an application to persist and compare an external `VaultAnchor`.
