# Vault KDF Layer

QuantLib v1.7.0 introduces explicit vault KDF metadata and migration hooks.

## Goals

- Keep existing PBKDF2-HMAC-SHA256 vaults compatible.
- Make KDF parameters visible in vault metadata.
- Add provider boundaries for Argon2id and scrypt without pretending they are available.
- Allow vault wrapping parameters to be rewrapped without changing sealed SSM objects.

## Current support

| KDF | Status | Memory hard | Notes |
|---|---:|---:|---|
| PBKDF2-HMAC-SHA256 | available | no | portable built-in compatibility KDF |
| Argon2id | provider hook | yes | fail-closed until a vetted backend is linked |
| scrypt | provider hook | yes | fail-closed until a vetted backend is linked |

## Metadata

Vault v3 stores:

```txt
kdf name
iteration count
memory_kib
parallelism
```

These fields are authenticated as vault metadata and are also included in the AEAD associated data for the wrapped SSM master key.

## Rewrapping

`rewrap_vault_kdf()` changes the vault wrapping parameters for future saves while preserving:

- vault id
- sealed SSM objects
- audit log
- master key

The current built-in rewrap target is PBKDF2-HMAC-SHA256. Argon2id and scrypt return `unsupported_algorithm` until real providers are linked.
