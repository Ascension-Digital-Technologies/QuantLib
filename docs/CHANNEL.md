# QuantLib Channel Layer

QuantLib includes a small protocol-state wrapper above the session, record, and replay layers.

The channel layer is intentionally narrow. It does not perform network I/O. It owns only the cryptographic state needed to safely send and receive encrypted frames:

- local role
- send sequence counter
- receive replay window
- active key material
- key generation
- closed flag

## Flow

```txt
KEM / Hybrid KEM
  -> transcript hash
  -> session key schedule
  -> channel state
  -> encrypted records
  -> replay-protected receive path
```

## Send path

`channel::seal_data` creates a `record::Frame`, encodes it, increments the send sequence, and authenticates both:

- channel associated context
- per-call associated data

This keeps a caller from accidentally using the same encrypted frame in the wrong protocol route, RPC method, or node channel.

## Receive path

`channel::open` decodes the frame, checks that the sender role is the expected peer, checks the replay window, decrypts the frame, and only then accepts the sequence number.

Duplicate frames fail closed.

## Key update

`channel::seal_key_update` sends a key-update frame protected by the current keys, then advances the local state to the following key generation.

The receiver calls `channel::apply_key_update` on the opened key-update record. The update payload contains:

```txt
u64 generation || key_update_tag
```

The key-update tag is validated before the receiver advances its key material.

## Close notify

`channel::seal_alert(..., close_notify)` marks the sender closed after the alert is emitted. Receiving a valid `close_notify` alert marks the receiving channel closed.

Further sends or receives fail closed.
