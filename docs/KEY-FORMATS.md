# Key Format

Binary key blobs use:

```text
magic        6 bytes   "ACRYPT"
version      u16       big endian
algorithm    u16       big endian
purpose      u16       big endian
flags        u32       big endian
created_at   u64       unix seconds
key_id_len   u8
key_id       variable
payload_len  u32       big endian
payload      variable
checksum     32 bytes  SHA-256(header || payload)
```

This format is intentionally simple for v0.1.0. Future versions can add authenticated encryption for secret blobs and public metadata extensions.
