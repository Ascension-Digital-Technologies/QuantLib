# Script Reference

All project helper scripts live in `cmake/scripts/` to preserve the requested clean project root.

Each shell script resolves the repository root relative to its own location, so it can be run from any working directory.

## Common scripts

- `build.sh` / `build.bat` — configure and build release mode.
- `test.sh` / `test.bat` — configure, build, and run CTest.
- `bench.sh` / `bench.bat` — build and run `quantlib-bench`.
- `package-check.sh` / `package-check.bat` — install into a temporary package root and run self-tests.
- `release-check.sh` / `release-check.bat` — run the release gate, tests, inventory, and production readiness checks.
- `deploy-check.sh` / `deploy-check.bat` — validate a built deployment directory.
- `fuzz-smoke.sh` — build fuzz harness targets and run smoke input.
- `sbom.sh` / `sbom.bat` — generate the SBOM report from `quantlib-inspect --sbom`.
- `checksums.sh` / `checksums.bat` — generate SHA-256 checksums.
- `sign-release.sh` / `sign-release.bat` — release-signing scaffold.

Production signing keys must never be stored in this repository.
