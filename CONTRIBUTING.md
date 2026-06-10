# Contributing to QuantLib

QuantLib is security-sensitive software. Contributions must preserve correctness, fail-closed behavior, and provider boundaries.

## Required checks before submitting changes

```bash
cmake -S . -B build -DQUANTLIB_ENABLE_HARDENING=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure
cmake/scripts/package-check.sh
cmake/scripts/release-check.sh
```

## Coding rules

- Do not add custom cryptographic algorithms as production features.
- Optional cryptographic backends must be provider-gated and fail closed when unavailable.
- Do not log secrets, passphrases, private keys, shared secrets, raw signatures, or ciphertext payloads.
- Keep secret material in secure/move-only buffers where practical.
- Prefer explicit typed errors over exceptions for security-sensitive paths.
- Add tests for success, malformed input, tampering, unsupported providers, and downgrade paths.

## Documentation requirements

Every new public API must include:

- Header comments or API documentation.
- A docs entry or update.
- A safe-use example when appropriate.
- A security boundary note if it touches keys, signatures, sessions, vaults, providers, or protocol records.
