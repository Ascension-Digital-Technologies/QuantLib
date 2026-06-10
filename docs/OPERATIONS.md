# QuantLib Operations Guide

QuantLib v2.1.0 adds an operational readiness layer for production deployments.

## Required preflight

1. Build a clean release tree.
2. Run `ctest`.
3. Run `quantlib-inspect --selftest`.
4. Run `quantlib-inspect --release`.
5. Run `quantlib-inspect --inventory` and capture provider versions.
6. Run `quantlib-inspect --memory` and verify best-effort secure-memory support.
7. Run `quantlib-inspect --ops`.

## Deployment profiles

The built-in profiles are:

- `local-dev`
- `workstation`
- `server`
- `validator`
- `ci-release`
- `custody-host`

Production systems should use `server`, `validator`, or `custody-host` as the baseline and keep experimental PQ disabled unless a vetted backend is linked and validated.

## Operator rules

- Do not use raw handles directly in application code when a session can be used.
- Keep SSM sessions short lived.
- Persist vault anchors outside the vault file.
- Verify the audit log after every backup, recovery, key rotation, or incident response.
- Keep provider inventory with every release artifact.
- Do not claim FIPS certification unless the whole deployment is separately validated.
