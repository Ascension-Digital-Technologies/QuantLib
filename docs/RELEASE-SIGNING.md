# Release Signing

QuantLib does not store release signing keys in the repository. Release signing must be performed by the release operator.

Recommended flow:

1. Build from a clean checkout.
2. Run `ctest`.
3. Run `quantlib-inspect --selftest`.
4. Run `quantlib-inspect --release`.
5. Generate `SHA256SUMS`.
6. Generate SBOM output.
7. Sign the source archive and checksum manifest using the operator key.
8. Verify checksums and signatures before publishing.

The repository provides scripts for checksums and signing scaffolds, but the real signing key must remain outside the project tree.
