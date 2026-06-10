# SSM Sessions

QuantLib v1.5.0 adds short-lived Software Security Module sessions. Sessions sit above key handles and make private-key use explicit, temporary, and permissioned.

## Goals

- Prevent arbitrary code with a key handle from using private keys forever.
- Bind access to a short-lived random session token.
- Restrict a session to specific permissions, handles, and signing domains.
- Enforce per-session operation limits.
- Close or expire sessions fail-closed.

## Session controls

A session can define:

- `ttl_seconds`
- permission bitmask
- allowed key handles
- allowed signing domains
- maximum signing operations
- maximum decapsulation operations

Supported permission bits are:

- `sign`
- `decapsulate`
- `export_public`
- `generate_key`
- `change_policy`
- `erase_key`
- `export_sealed`
- `import_sealed`
- `admin`

## Example

```cpp
ssm::SsmSessionManager sessions(module);

ssm::SessionOptions options;
options.ttl_seconds = 300;
options.permissions = static_cast<uint32_t>(ssm::SessionPermission::sign);
options.allowed_handles = {handle};
options.allowed_domains = {"wallet.tx"};
options.max_sign_operations = 100;

auto token = sessions.open_session(options);
auto sig = sessions.sign_domain(token.value(), handle, "wallet.tx", message);
sessions.close_session(token.value());
```

## Security notes

Raw session tokens should not be written to logs. The session API exposes a token hash for diagnostics and audit correlation. Session authorization is not a replacement for key policy. Both are enforced: a session can allow a domain, but the key-level SSM policy can still deny it.
