# QuantLib

QuantLib is a C++20 cryptography and private-key custody library for classical, post-quantum, and hybrid security workflows. It includes secure byte utilities, hashing and KDF primitives, provider-backed classical crypto, provider-gated post-quantum crypto, encrypted protocol channels, a software security module, encrypted vault storage, audit logs, and an easy integration facade.

**Current release:** `4.0.0`  
**Status:** production-ready source baseline with provider-dependent PQ activation.

## What is production-ready today

QuantLib is ready to integrate as a hardened source package when built with the configured provider set and release checks enabled. The repository includes:

- CMake package installation support.
- Warning-clean source under the tested Windows/Clang and Linux/GCC-style paths used during packaging.
- Hardened build option: `QUANTLIB_ENABLE_HARDENING=ON`.
- Provider inventory and release-gate inspection commands.
- Self-tests, unit tests, examples, fuzz harness scaffolds, and package-check scripts.
- Security, threat-model, operations, deployment, and release documentation.
- Fail-closed behavior for unavailable providers.

## Important boundaries

QuantLib does **not** claim that every optional backend is active in every build. Provider-dependent features must be explicitly linked and verified.

| Area | Status |
|---|---|
| SHA-256, HMAC-SHA256, HKDF-SHA256 | Built in |
| AES-256-GCM, ChaCha20-Poly1305, X25519, Ed25519 | OpenSSL-backed when OpenSSL is available |
| ML-KEM, ML-DSA, SLH-DSA | liboqs-backed when `QUANTLIB_ENABLE_LIBOQS=ON` and liboqs is found |
| Argon2id/scrypt vault KDFs | Provider-gated; PBKDF2-HMAC-SHA256 remains the portable built-in compatibility KDF |
| CUDA/OpenCL acceleration | Provider-gated hooks with CPU fallback |
| Hardware key isolation | Not included; integrate through a future provider/HSM boundary |

Use `quantlib-inspect --production-ready`, `quantlib-inspect --inventory`, and `quantlib-inspect --pq-provider` before deploying.

## Repository layout

```text
ProjectRoot/
├── bin/        # Final executable files; usually ignored by git
├── build/      # Local build artifacts; ignored by git
├── cmake/      # CMake package files and helper scripts
├── data/       # Non-code assets, sample configs, and local data placeholders
├── docs/       # Production documentation
├── external/   # Third-party provider/vendor drop-in area
├── include/    # Public headers
│   └── quantlib/
├── src/        # Implementation source
├── tests/      # Unit tests, fuzz harnesses, benchmarks, and examples
├── CMakeLists.txt
├── README.md
└── LICENSE
```

## Build

```bash
cmake -S . -B build -DQUANTLIB_ENABLE_OPENSSL=ON -DQUANTLIB_ENABLE_HARDENING=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

For liboqs-backed PQ support:

```bash
cmake -S . -B build -DQUANTLIB_ENABLE_LIBOQS=ON -DQUANTLIB_ENABLE_OPENSSL=ON
cmake --build build --config Release
```

QuantLib fails closed when liboqs is requested but not discovered; use the PQ inspection commands to confirm the active provider state.

## Production verification

After building, run:

```bash
build/quantlib-inspect --version
build/quantlib-inspect --selftest
build/quantlib-inspect --release
build/quantlib-inspect --production-ready
build/quantlib-inspect --inventory
build/quantlib-inspect --pq-provider
```

Then run the helper scripts:

```bash
cmake/scripts/package-check.sh
cmake/scripts/release-check.sh
cmake/scripts/deploy-check.sh
cmake/scripts/sbom.sh
cmake/scripts/checksums.sh <release-archive.zip>
```

Windows equivalents are provided as `.bat` files under `cmake/scripts/`.

## Main tools

| Tool | Purpose |
|---|---|
| `quantlib-inspect` | Provider, release, production, CPU/SIMD/GPU, vault, SSM, and protocol inspection |
| `quantlib-ssm` | Vault and software-security-module operations |
| `quantlib-keygen` | Key generation helper |
| `quantlib-bench` | Benchmark and throughput checks |

## Integration path

For normal applications, start with the easy facade:

```cpp
#include <quantlib/easy.hpp>

quantlib::easy::EasyOptions options{};
options.label = "my-app";
options.default_domain = "my-app.messages";

auto vault = quantlib::easy::QuantVault::create("app.vault", "change-me", options);
auto handle = vault.value().generate_signing_key("main", "my-app.messages");
auto sig = vault.value().sign(handle.value(), "hello", "my-app.messages");
```

The public C++ namespace is `quantlib`; the high-level facade is `quantlib::easy::QuantVault`.

## Documentation map

Start here:

- `docs/DOCS-INDEX.md` — documentation index.
- `docs/PRODUCTION-README.md` — production usage overview.
- `docs/BUILD.md` — build and install guide.
- `docs/SECURITY.md` — security policy and boundaries.
- `docs/THREAT-MODEL.md` — threat model.
- `docs/PROVIDER-GUIDE.md` — OpenSSL/liboqs/GPU provider setup.
- `docs/RELEASE-PROCESS.md` — release checklist.
- `docs/API-REFERENCE.md` — API map.
- `docs/OPERATIONS.md` and `docs/RUNBOOK.md` — deployment operations.

## License

See `LICENSE`.


## GPU batch benchmark

Run GPU routing and fallback diagnostics with:

```bash
quantlib-bench --gpu
```

If no validated CUDA/OpenCL kernel provider is linked, QuantLib reports `cpu-fallback` instead of silently doing nothing.
