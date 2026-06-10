# QuantLib v2.2.0 Release Notes

v2.2.0 adds the Easy Integration Wrapper for applications that want to use vaults, SSM keys, sessions, and domain-separated signatures without manually wiring every lower-level component.

## Highlights

- Added `quantlib::easy::QuantVault`.
- Added one-call vault creation/opening helpers.
- Added wrapper methods for signing-key generation, X25519 exchange-key generation, signing, verifying, key rotation, state changes, erasing, listing, and saving.
- Added automatic short-lived SSM session handling.
- Added autosave support through atomic vault saves.
- Added `docs/EASY.md` and `examples/easy-wrapper.cpp`.
- Added `quantlib-inspect --easy`.

## Safety boundary

The wrapper does not expose raw private keys and does not bypass SSM/vault policy. It is a convenience layer over the existing custody system.
