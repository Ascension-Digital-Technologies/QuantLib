# Benchmarks

The current benchmark executable is intentionally small and stable. It provides a SHA-256 smoke benchmark and will be expanded as more primitives are wired.

## Run

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/quantlib-bench
```

## v0.2.0 Sandbox Smoke Result

```txt
sha256_1kb_iters 100000
ns_per_op 4650.64
ops_per_sec 215024
```

## Future Metrics

For each crypto primitive, track:

- ns/op
- ops/sec
- p50/p95/p99 latency
- bytes/sec for streaming algorithms
- allocations/op
- backend selected
- CPU feature path selected
