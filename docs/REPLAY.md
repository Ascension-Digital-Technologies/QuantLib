# Replay Window

QuantLib v0.8.0 includes a compact 64-bit replay window for record protocols.

## Behavior

- Accepts new higher sequence numbers.
- Accepts unseen out-of-order records inside the 64-record window.
- Rejects duplicates.
- Rejects records older than the active window.

## Protocol Use

Use one replay window per receiving direction and per key epoch. When a key update is completed, reset the receiving window for that epoch.
