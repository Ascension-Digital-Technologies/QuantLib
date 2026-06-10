# QuantLib v4.0.0 Build Report

## Sandbox verification

- Configure: passed
- Build: passed after continuation from existing build tree
- CTest: passed, 1/1
- Version CLI: `QuantLib 4.0.0`
- Full health CLI: passed
- Full benchmark CLI: passed

## Commands used

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_ENABLE_OPENCL=OFF -DQUANTLIB_ENABLE_LIBOQS=OFF
cmake --build build --config Release -j2
ctest --test-dir build --output-on-failure
./build/quantlib-inspect --version
./build/quantlib-inspect --full
./build/quantlib-bench --all
```

## Provider boundary

The sandbox build used OpenSSL and CPU/SIMD paths. liboqs and OpenCL were disabled for verification in this environment, so PQ and GPU acceleration correctly reported provider-gated fallback/unavailable status.
