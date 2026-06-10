# QuantLib Production README

QuantLib `3.0.1` is a production-ready source baseline for applications that need a compact cryptography, protocol, and private-key custody foundation.

## Production meaning

Production-ready means this source package has:

- a clean repository layout;
- warning-clean source for the tested toolchains;
- explicit CMake options;
- provider-gated algorithms;
- fail-closed optional backends;
- release and production readiness inspection commands;
- self-tests and CTest coverage;
- package, release, deployment, SBOM, and checksum scripts;
- security and operational documentation.

It does **not** mean every optional provider is included or active. OpenSSL, liboqs, CUDA, OpenCL, and future HSM providers remain external dependencies.

## Required production checks

Run these after building:

```bash
quantlib-inspect --selftest
quantlib-inspect --release
quantlib-inspect --production-ready
quantlib-inspect --inventory
quantlib-inspect --pq-provider
quantlib-inspect --ops
```

The deployment should not proceed if the production-ready report lists blockers.

## Safe integration rules

- Use the `quantlib::easy` facade for normal app integration.
- Use domain-separated signing for all signatures.
- Use sessions and policies for all private-key operations.
- Treat command-line passphrases as development only.
- Never log private keys, passphrases, shared secrets, or vault contents.
- Keep vault backups and audit anchors separately protected.
- Verify provider status before enabling PQ or hardware acceleration.

## Provider-dependent status

| Feature | Production activation requirement |
|---|---|
| Classical AEAD/KEM/signature operations | OpenSSL provider available |
| PQ KEM/signature operations | liboqs provider available |
| GPU acceleration | CUDA/OpenCL provider available |
| Memory-hard vault KDFs | vetted Argon2id/scrypt provider available |
