# API Reference Map

This document maps the production API surface. See headers under `include/quantlib/` for exact signatures.

## Core

- `result.hpp` — typed result/error handling.
- `bytes.hpp` — byte containers and views.
- `secure.hpp` — secure zeroization, constant-time comparisons, locked buffers.
- `rng.hpp` — random bytes.

## Crypto primitives

- `hash.hpp` — SHA-256 and hash helpers.
- `kdf.hpp` — HMAC/HKDF and vault KDF helpers.
- `aead.hpp` — AEAD encryption/decryption boundary.
- `kem.hpp` — KEM API.
- `sign.hpp` — signature API.
- `hybrid.hpp` — hybrid classical/PQ helpers.
- `pq.hpp` — PQ metadata, provider status, and KAT harness.

## Policy and protocols

- `policy.hpp` — algorithm policy profiles.
- `transcript.hpp` — transcript hashing.
- `session.hpp` — key schedule and confirmation tags.
- `record.hpp` — encrypted records.
- `replay.hpp` — replay window.
- `channel.hpp` — stateful encrypted channel helper.
- `protocol.hpp` — QuantLink protocol state machine and suite negotiation.

## Custody

- `ssm.hpp` — software security module.
- `vault.hpp` — encrypted persistent vaults.
- `audit.hpp` — hash-chained audit logs.
- `easy.hpp` — high-level integration facade.

## Runtime and operations

- `provider.hpp` — provider inventory.
- `release.hpp` — release profile and gate information.
- `production.hpp` — production readiness report.
- `testing.hpp` — test infrastructure metadata.
- `ops.hpp` — operational readiness profiles.
- `cpu.hpp`, `simd.hpp`, `aligned.hpp`, `hardware.hpp`, `batch.hpp`, `throughput.hpp`, `gpu.hpp` — performance and hardware boundary.
