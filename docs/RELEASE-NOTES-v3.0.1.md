# QuantLib v3.0.1 — Production Documentation and Repository Readiness

QuantLib v3.0.1 focuses on making the repository production-ready as a complete source package, not just as compiled code.

## Added

- Root project hygiene files: `.gitignore`, `.gitattributes`, `.editorconfig`, `.clang-format`.
- Root governance files: `SECURITY.md`, `CONTRIBUTING.md`, `SUPPORT.md`, `NOTICE`.
- Root `VERSION` file.
- CMake presets for release, dev, sanitizer, and PQ configurations.
- Production documentation index.
- Build, provider, threat-model, API, release-process, and repository-hygiene docs.

## Updated

- README rewritten for current `3.0.1` status.
- Version stamps updated from `3.0.0` to `3.0.1`.
- Changelog updated with production documentation pass.

## Security boundary

No optional backend is claimed active unless discovered and reported by the provider inventory. PQ remains liboqs-backed and fail-closed when liboqs is unavailable.
