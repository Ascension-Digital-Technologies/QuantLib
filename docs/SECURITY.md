# Security Policy

## Supported branch

The current security-review branch is v1.9.x.

## Reporting vulnerabilities

Report security issues privately before public disclosure. Include:

- affected version
- build options
- operating system
- proof of concept if available
- expected and observed behavior

Do not include private keys, passphrases, or production vault files in reports.

## Current limitations

- PQ providers are gated/fail-closed until real vetted backends are linked.
- Argon2id/scrypt providers are metadata hooks until linked.
- The library is not FIPS certified.
