# QuantLib SSM Key Rotation

QuantLib v1.8.0 adds first-class key rotation for the Software Security Module.

## Goals

Key rotation lets applications replace private keys without losing custody history. The SSM creates a fresh replacement key, links it to the original handle, and can automatically retire the old key so future private-key operations fail closed.

## Rotation metadata

Each SSM object now carries optional rotation lineage:

```txt
original_handle
replacement_handle
generation
rotated_at
reason
```

The old object stores `replacement_handle`; the replacement stores `original_handle`. Both store the same generation and rotation timestamp.

## Default behavior

By default, `rotate_key()`:

```txt
creates a replacement key using the same object type
uses the same algorithm
preserves allowed_domain and max_operations
marks the old key as retired
stores the reason string
returns both old and new ObjectInfo values
```

Retired keys cannot sign or decapsulate. Public export and sealed export remain available so the old key can stay in the vault for verification, lineage, migration, and audit purposes.

## API

```cpp
ssm::RotateOptions options;
options.label = "validator-key-v2";
options.reason = "scheduled_rotation";
options.retire_old = true;

auto result = module.rotate_key(old_handle, options);
```

`RotationResult` contains:

```txt
old_handle
new_handle
old_info
new_info
```

## CLI

```bash
quantlib-ssm rotate <vault-file> <passphrase> <handle> [label] [reason]
```

The vault is opened, the selected key is rotated, the old key is retired, and audit events are appended.

## Audit events

v1.8.0 adds:

```txt
key_rotated
key_retired
key_marked_compromised
```

The CLI writes `key_rotated` and `key_retired` during normal rotation.

## Security notes

Rotation does not expose private key bytes. Replacement keys are generated inside the SSM and sealed with the existing vault/SSM protections. Retired keys remain sealed and cannot perform private-key operations.
