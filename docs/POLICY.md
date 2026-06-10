# Algorithm Policy

QuantLib v0.5.0 adds an explicit policy layer so applications can reject weak or incompatible algorithms before a key, handshake, signature, or encrypted message is accepted.

## Profiles

- `fast`: allows classical algorithms for high-speed compatibility paths.
- `balanced`: prefers hybrid/PQ algorithms while keeping classical algorithms available for migration.
- `conservative`: requires level-5 PQ algorithms where possible.
- `pq-transition`: disables classical-only KEM/signature choices and expects hybrid or PQ algorithms.

The policy layer is intentionally separate from providers. A provider may support an algorithm, but the selected policy can still reject it.

## CLI

```bash
quantlib-inspect --policies
```

## Design rules

- No silent algorithm downgrade.
- Classical-only algorithms must be explicitly allowed by policy.
- Hybrid/PQ transition profiles reject classical-only KEM/signature modes.
- Security level checks happen before dispatching into backend providers.
