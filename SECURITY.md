# Security Policy

QuantLib is a cryptography and private-key custody library. Treat every change as security-sensitive.

## Supported branch

This package is a source snapshot for `3.0.1`. Downstream projects should vendor or pin a reviewed release archive.

## Reporting vulnerabilities

Do not disclose vulnerabilities publicly before maintainers have reviewed them. Provide:

- Affected version and build options.
- Platform and compiler.
- Reproduction steps.
- Whether secrets, private keys, vaults, or protocol sessions may be exposed.

## Security boundaries

QuantLib provides hardened software controls, encrypted vault storage, audit trails, and provider-gated algorithms. It does not protect secrets from a fully compromised host process, kernel, debugger, malicious compiler, or malicious provider library.

## Production deployment requirements

- Run `quantlib-inspect --production-ready`.
- Run `quantlib-inspect --inventory`.
- Verify OpenSSL/liboqs provider status according to your deployment profile.
- Use hardened builds for release.
- Keep vault files, audit anchors, and backups under strict OS permissions.
- Never pass real passphrases on command lines in production automation.
