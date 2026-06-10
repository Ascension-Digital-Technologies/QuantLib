# SSM Policy Engine

QuantLib v1.2.0 adds the first policy enforcement layer for the Software Security Module.

## Key states

Each SSM object now carries a lifecycle state:

- `active` - operations are allowed.
- `locked` - all operations fail closed.
- `disabled` - administrative disable state.
- `expired` - retired/expired state.
- `destroyed` - terminal state; cannot be restored through `set_state`.
- `compromised` - blocked and explicitly marked unsafe.

Only `active` keys can be used or exported.

## Domain-separated signing

Use `sign_domain()` instead of signing raw protocol bytes when a signature is intended for a specific protocol context.

The SSM builds a transcript under:

```txt
QuantLib SSM Domain Sign v1
```

and binds:

```txt
handle
domain
algorithm
message
```

The matching verifier is `verify_domain_signature()`.

## Per-key policy fields

`CreateOptions` supports:

```cpp
allowed_domain
max_operations
```

If `allowed_domain` is set, signing is only allowed for that exact domain. If `max_operations` is non-zero, signing and decapsulation are blocked after that many successful operations.

## Usage metadata

`ObjectInfo` now tracks:

```txt
state
allowed_domain
max_operations
used_operations
last_used_at
```

Mutable counters are intentionally not included in the AEAD associated data, so usage updates do not make existing sealed private material undecryptable.
