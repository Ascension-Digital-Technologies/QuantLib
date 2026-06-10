# QuantLib v2.1.0 Release Notes

v2.1.0 is the post-production operational hardening release.

## Highlights

- Added deployment profile metadata.
- Added operational readiness validation.
- Added operator runbook and deployment templates.
- Added `quantlib-inspect --ops` and `quantlib-inspect --runbook`.
- Added deployment-check scripts for Windows and Unix-like systems.
- Extended self-test and release gate coverage.

## Production boundary

This release does not change the cryptographic claims from v2.0.0. PQ, Argon2id/scrypt, FIPS-compatible deployments, and release signing remain provider/deployment-dependent unless separately linked and validated.
