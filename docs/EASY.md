# Easy Integration Wrapper

`quantlib::easy` is the high-level facade for applications that do not want to wire the vault, SSM, sessions, policies, and persistence manually.

It is intentionally small and opinionated:

- creates or opens an encrypted vault
- opens a short-lived SSM session automatically
- generates Ed25519 signing keys and X25519 exchange keys
- signs with domain separation by default
- verifies domain-bound signatures
- persists key changes automatically unless `autosave=false`
- exposes key summaries for UI/admin integrations

## Minimal example

```cpp
#include "quantlib/quantlib.hpp"

int main() {
  quantlib::easy::EasyOptions options{};
  options.label = "my-app";
  options.default_domain = "my-app.messages";

  auto vault = quantlib::easy::QuantVault::create("app.vault", "passphrase", options);
  if (!vault) return 1;

  auto handle = vault.value().generate_signing_key("main", "my-app.messages");
  if (!handle) return 1;

  auto sig = vault.value().sign(handle.value(), "hello", "my-app.messages");
  if (!sig) return 1;

  auto ok = vault.value().verify(handle.value(), "hello", sig.value().signature, "my-app.messages");
  return ok && ok.value() ? 0 : 1;
}
```

## Simple one-shot helpers

```cpp
quantlib::easy::quick_create_vault("app.vault", "passphrase", "my-app");
auto handle = quantlib::easy::quick_generate_signing_key("app.vault", "passphrase", "main", "my-app.messages");
auto sig = quantlib::easy::quick_sign("app.vault", "passphrase", handle.value(), "hello", "my-app.messages");
```

## Notes

The wrapper does not bypass lower-level safeguards. It still uses:

- encrypted vault storage
- SSM sealed private keys
- short-lived SSM sessions
- domain-separated signing
- policy and key state enforcement
- secure memory and audit-capable vault persistence

Use the lower-level APIs when you need custom protocol stacks, custom session permissions, custom KDF migration, or manual audit anchoring.
