# Transcript Hashing

QuantLib v0.5.0 includes a small transcript builder for domain-separated handshakes, signatures, protocol proofs, and session binding.

Every transcript begins with a domain field and every appended field is length-prefixed:

```text
u32 label_len || label || u32 value_len || value
```

The current digest backend is SHA-256. This keeps transcript binding deterministic, portable, and easy to test. Future versions can add SHAKE256/BLAKE3 transcript backends without changing the field framing.

## Recommended use

Use transcripts for:

- hybrid KEM handshakes
- signed protocol messages
- key confirmation
- version negotiation
- domain-separated blockchain/node messages

Never sign or key-derive from raw concatenated fields without framing. Length-prefixing prevents ambiguous encodings.
