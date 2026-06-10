# SBOM

QuantLib v2.0.0 includes an SBOM scaffold through `quantlib-inspect --sbom` and `scripts/sbom.sh` / `scripts/sbom.bat`.

The built-in inventory intentionally separates:

- first-party QuantLib code,
- optional OpenSSL classical crypto provider,
- optional liboqs PQ provider,
- CMake/toolchain components,
- compiler/runtime platform dependencies.

The script emits a simple text SBOM suitable for release packages. A production release can convert this into SPDX or CycloneDX using an external SBOM generator.
