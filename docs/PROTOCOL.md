# QuantLink Protocol v1

QuantLink is the production protocol boundary for QuantLib sessions. It turns the lower-level handshake/session/record/channel pieces into a stricter protocol surface.

## Goals

- explicit handshake state transitions
- cipher-suite negotiation
- downgrade rejection
- record and frame size limits
- close-notify enforcement
- rekey thresholds
- transcript-bound negotiation metadata

## Cipher suites

The built-in suite list is intentionally small:

- `QUANTLIBLINK_X25519_MLKEM768_ED25519_MLDSA65_CHACHA20_SHA256`
- `QUANTLIBLINK_X25519_ED25519_AES256GCM_SHA256`
- `QUANTLIBLINK_X25519_ED25519_CHACHA20_SHA256`

PQ/hybrid suites remain bounded by provider availability and policy. Unsupported PQ crypto still fails closed at the primitive/provider layer.

## Downgrade protection

`reject_downgrade()` rejects selection of a lower-security suite when a higher-security mutually known suite was offered. This is a protocol-level guard; applications should also authenticate the transcript hash before treating a session as established.

## Limits

The default maximum plaintext size is 1 MiB. Applications can lower this for node control-plane protocols, RPC calls, or validator gossip frames.

## Close behavior

Production profiles should require `close_notify`. Abrupt transport close without a close alert is treated as a suspicious termination unless the embedding application explicitly disables that requirement.
