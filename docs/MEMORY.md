# Secure Memory

QuantLib v1.6.0 adds a secure-memory layer for private-key custody and protocol secrets.

## Features

- `secure_zero()` wipes buffers with a compiler-resistant implementation.
- `SecureBytes` is move-only and zeroizes on destruction or move assignment.
- `LockedBytes` is move-only, zeroizes on destruction, and attempts OS-backed memory locking.
- `secure_memory_status()` reports the active platform backend.
- Linux builds attempt `mlock` and `MADV_DONTDUMP` where available.
- Windows builds use `VirtualLock` and `SecureZeroMemory`.
- macOS/Unix builds use `mlock` where available.

## Design Rule

Memory locking is best-effort because operating systems can reject it due to limits or policy. The library never treats a failed lock as permission to skip zeroization. Secrets are always wiped on destruction even when locking is unavailable.

## Recommended Use

Use `LockedBytes` for long-lived master keys, vault keys, and key-encryption keys. Use `SecureBytes` for shorter-lived secrets that still need deterministic wiping.

```cpp
auto secret = quantlib::LockedBytes::allocate(32);
if (!secret) return secret.error();
// secret.value().locked() reports whether OS locking succeeded.
```

## Current Limitations

Guard-page allocation is reported but not yet enabled. A future version can add a guarded heap with canaries and page-protected red zones for high-risk secrets.
