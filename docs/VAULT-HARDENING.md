# QuantLib Vault Hardening

QuantLib v1.11.0 upgrades the persistent vault layer from a simple encrypted file format into a safer custody container with atomic save, backup recovery, audit-head verification, and rollback anchors.

## Features

- Vault format version 5.
- Atomic save helper: `save_vault_atomic()`.
- Primary/backup load helper: `load_vault()`.
- Backup format helper: `encode_vault_backup()`.
- Generation counter in vault metadata.
- Previous audit-head metadata field.
- Stored audit-head field verified against the decoded audit hash chain.
- Rollback anchor helper: `anchor_for()`.
- Rollback check helper: `verify_anchor()`.
- CLI recovery command: `quantlib-ssm recover <vault-file> <passphrase>`.

## Atomic save behavior

`save_vault_atomic()` writes the new encrypted vault to a temporary file first. If a primary vault already exists, it is copied to `<vault>.bak`. The temporary file is then renamed into place.

This protects against many normal update failures. A future production pass should add platform-specific directory `fsync` support and stronger crash-consistency checks on filesystems that require it.

## Recovery behavior

`load_vault()` opens the primary vault first. If the primary file is unreadable, tampered, or fails authentication, it attempts to open the `.bak` file.

The recovery report records:

- whether the primary file existed
- whether the primary file decoded
- whether the backup file existed
- whether the backup file decoded
- which source was selected
- a diagnostic detail string

## Audit-head verification

Vault files now store an authenticated audit-head value. During decode, the audit log is decoded and verified, then its computed head hash is compared with the stored vault audit head. A mismatch fails closed.

This detects attempts to splice, truncate, or replace the audit log inside a vault file without updating all authenticated fields correctly.

## Rollback anchors

`VaultAnchor` stores:

```txt
vault_id
generation
audit_head
```

Applications can persist the latest trusted anchor outside the vault. On future unlocks, `verify_anchor()` can reject older generations and same-generation audit-head mismatches.

This is not a complete remote transparency system yet, but it gives applications the right local hook for rollback detection.
