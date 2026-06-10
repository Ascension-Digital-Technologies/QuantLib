# Threat Model

## Assets

- Private signing keys.
- KEM private keys.
- Symmetric vault keys.
- Vault passphrases.
- Shared secrets and session keys.
- Audit log integrity.
- Provider selection and algorithm policy.

## Defended threats

QuantLib is designed to help defend against:

- stolen vault files without the passphrase;
- tampered vault files;
- accidental algorithm downgrade;
- unavailable provider fallback mistakes;
- unauthorized private-key use through missing session/policy checks;
- replayed encrypted records;
- audit log event mutation or reordering;
- accidental secret copies where secure buffers are used;
- malformed protocol frames and record tampering.

## Out of scope

QuantLib cannot protect against:

- a fully compromised host process;
- a malicious kernel or hypervisor;
- a malicious compiler or linker;
- malicious provider libraries;
- hardware side-channel attacks outside the implemented software boundary;
- passphrases exposed through shell history, logs, keyloggers, or malware.

## Required deployment controls

- Hardened OS permissions for vault files and backups.
- Separate storage for audit anchors where rollback detection matters.
- External secret input handling for production passphrases.
- Provider pinning and inventory verification.
- Regular self-tests and release-gate checks.
