# Rekey and Key Update

QuantLib v0.8.0 adds deterministic key-update helpers for long-lived encrypted sessions.

## Design

`session::update_keys()` derives a fresh `KeyMaterial` from the current exporter secret, the original hello transcript, a non-zero generation counter, and caller supplied context.

The generation counter must be monotonic at the protocol layer. A generation of zero is rejected so generation `0` remains the initial key epoch.

## Confirmation

`session::key_update_tag()` produces a 32-byte confirmation value over the current traffic keys and update context. Protocols should exchange this inside an encrypted `key_update` record before switching epochs.

## Safety Rules

- Rekey before sequence exhaustion.
- Bind the update to the transcript and protocol context.
- Never silently roll back to an older generation.
- Reset replay windows when a new epoch is activated.
