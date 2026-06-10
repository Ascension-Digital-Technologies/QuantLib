# QuantLib Throughput Engine

QuantLib v2.5.0 adds a throughput layer for high-volume crypto workloads.

## Goals

- Keep the default crypto path safe and deterministic.
- Avoid copies by building zero-copy `ByteView` batches over caller-owned input buffers.
- Split large batches into bounded chunks.
- Process chunks across a small worker fanout.
- Preserve output order by writing each digest to its final result slot.
- Use thread-local scratch hooks for future SIMD/PQ/GPU kernels.

## Public API

```cpp
quantlib::throughput::EngineOptions options{};
options.min_parallel_items = 512;
options.target_chunk_items = 256;

auto result = quantlib::throughput::sha256_parallel(messages, options);
```

## Routing

`quantlib::batch::sha256()` now routes large CPU batches through the throughput engine before falling back to the scalar CPU path. GPU routing remains optional and provider-gated.

## Current implementation

The v2.5.0 implementation parallelizes batch SHA-256 using the existing vetted hash implementation. It does not claim new SIMD or GPU cryptographic kernels yet.

## Future acceleration hooks

- CPU pinning
- NUMA-local queues
- AVX2/AVX-512 SHA lanes
- ARM NEON lanes
- CUDA/OpenCL batch kernels
- batch signature verification once provider-backed
