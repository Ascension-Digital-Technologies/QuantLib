# QuantLib Production Status

QuantLib v4.0.0 is a production-baseline cryptography, custody, protocol, and acceleration library with explicit provider boundaries.

## Stable areas

- Core result, byte, secure memory, RNG, hash, KDF, key encoding, policy, transcript, session, record, replay, channel, protocol, SSM, vault, audit, release, production, easy wrapper, hardware, batch, throughput, SIMD, and GPU routing APIs.
- OpenSSL-backed classical provider paths when OpenSSL is present.
- Vault/SSM custody model with sealed keys, sessions, policy, audit log, key rotation, atomic save, recovery, and production readiness reporting.
- OpenCL GPU batch SHA-256 provider path when OpenCL is present.

## Provider-dependent areas

- PQ algorithms require liboqs and remain fail-closed without it.
- OpenCL acceleration requires OpenCL headers, loader, platform runtime, and valid device.
- CUDA remains provider-gated unless CUDA kernels are compiled in.
- FIPS-compatible deployments require the OpenSSL FIPS provider and deployment-specific validation; QuantLib itself does not claim FIPS certification.

## Final release checks

Run these before integrating into another project:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure
./build/quantlib-inspect --full
./build/quantlib-bench --all
```
