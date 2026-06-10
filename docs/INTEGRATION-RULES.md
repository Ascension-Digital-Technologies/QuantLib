# QuantLib Integration Rules

Use these rules when embedding QuantLib into wallets, validators, custody tools, nodes, or remote signers.

1. Prefer `include/quantlib/easy.hpp` for application-level vault/signing integration.
2. Use SSM sessions and domain-separated signing. Do not sign raw protocol bytes directly.
3. Run `quantlib-inspect --selftest` during startup on custody hosts.
4. Run `quantlib-inspect --production-ready` in release packaging and deployment validation.
5. Treat PQ APIs as unavailable unless `quantlib-inspect --pq-provider` reports `production_ready: yes`.
6. Persist vault rollback anchors outside the encrypted vault when rollback detection matters.
7. Store provider inventory, SBOM, release gate output, checksums, and release notes alongside deployed binaries.
8. Never log passphrases, session tokens, private-key payloads, shared secrets, or decrypted vault data.
