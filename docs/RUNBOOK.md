# Operator Runbook

## Preflight

- Configure and build with the hardened profile.
- Run `ctest`.
- Run `quantlib-inspect --selftest`.
- Run `quantlib-inspect --release`.
- Run `quantlib-inspect --inventory`.

## Vault initialization

- Initialize the encrypted vault.
- Create a separate external anchor containing the vault generation and audit-head hash.
- Back up the encrypted vault and external anchor separately.

## Normal operation

- Open short-lived SSM sessions.
- Use domain-separated signing.
- Verify audit log after sensitive operations.
- Rotate long-lived keys on schedule.

## Incident response

- Mark suspected keys compromised.
- Preserve the audit chain and provider inventory.
- Rotate affected keys.
- Verify backups and anchors before restoring.
