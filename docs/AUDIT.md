# QuantLib Audit Log

QuantLib v1.4.0 adds a tamper-evident audit log for vault and SSM custody operations.

## Purpose

The audit layer records security-sensitive events without storing private key material. It is intended for local vault custody, validator key usage, wallet signing history, and future policy/session enforcement.

## Event chain

Each event contains:

- version
- sequence number
- timestamp
- event type
- subject, usually a vault id or key handle
- detail, such as a label or operation note
- previous event hash
- event hash

The chain is verified by checking monotonic sequence numbers and recomputing every hash:

```text
event_hash = SHA256(canonical_event_without_hash)
```

The first event links to a domain-separated QuantLib audit genesis hash.

## Supported events

- `vault_created`
- `vault_unlocked`
- `key_generated`
- `key_used_sign`
- `key_used_decapsulate`
- `key_erased`
- `policy_changed`
- `failed_unlock`
- `tamper_rejected`
- `vault_saved`
- `vault_loaded`

## Vault integration

Vault format v2 stores the encoded audit log alongside sealed SSM objects. The vault checksum covers the audit log bytes, and the audit log itself verifies internally through the hash chain.

## CLI

```bash
quantlib-inspect --audit
quantlib-ssm audit <vault-file>
quantlib-ssm audit-verify <vault-file>
```

## Security notes

The audit log is tamper-evident, not secret. It should avoid sensitive plaintext. Store handles, labels, domains, operation classes, and policy decisions, not raw messages or private material.
