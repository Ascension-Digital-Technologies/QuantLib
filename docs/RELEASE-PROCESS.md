# Release Process

## 1. Clean build

```bash
cmake -S . -B build -DQUANTLIB_ENABLE_HARDENING=ON -DQUANTLIB_ENABLE_OPENSSL=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

## 2. Required CLI checks

```bash
build/quantlib-inspect --version
build/quantlib-inspect --selftest
build/quantlib-inspect --release
build/quantlib-inspect --production-ready
build/quantlib-inspect --inventory
build/quantlib-inspect --ops
```

## 3. Package checks

```bash
cmake/scripts/package-check.sh
cmake/scripts/release-check.sh
cmake/scripts/deploy-check.sh
cmake/scripts/sbom.sh
```

## 4. Archive hygiene

The release archive must not include:

- `build/` contents;
- compiled binaries except intentional files under `bin/`;
- local vaults or logs;
- provider binaries unless explicitly documented;
- private keys, passphrases, or real audit logs.

## 5. Checksums and signing

Generate checksums:

```bash
cmake/scripts/checksums.sh quantlib-vX.Y.Z.zip
```

Sign the release only with the maintainer-controlled release key. The included signing script is a scaffold and must be wired to the actual signing tool used by the project.

## 6. Release notes

Update:

- `VERSION`;
- `docs/VERSION`;
- `docs/CHANGELOG.md`;
- `docs/BUILD_REPORT.md`;
- `docs/RELEASE-NOTES-vX.Y.Z.md`.
