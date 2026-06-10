# Deployment Profiles

QuantLib v2.1.0 exposes deployment metadata through `quantlib-inspect --ops`.

## Server profile

```txt
profile: server
session_ttl_seconds: 300
rekey_records: 1000000
require_audit: true
require_vault_anchor: true
allow_experimental_pq: false
```

## Validator profile

```txt
profile: validator
session_ttl_seconds: 120
rekey_records: 250000
require_secure_memory: true
domain: validator.vote
allow_experimental_pq: false
```

## Custody host profile

```txt
profile: custody-host
session_ttl_seconds: 60
rekey_records: 100000
require_reauth: true
require_external_anchor: true
operator_approval: required
```

## Deployment validation

`quantlib::ops::validate_deployment()` checks release-gate status, provider inventory, secure memory, audit availability, vault anchor support, atomic vault-save support, session TTL policy, and experimental PQ boundaries.
