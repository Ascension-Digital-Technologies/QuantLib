# Final Production Checklist

- Clean configure/build/test passes.
- `quantlib-inspect --full` has no blockers.
- `quantlib-bench --all` prints CPU, SIMD, GPU, batch, throughput, and vault/SSM-relevant measurements.
- Provider status is explicit for OpenSSL, liboqs, OpenCL, CUDA, SIMD, and CPU fallback.
- No generated build outputs are shipped in the source package.
- Security boundaries, threat model, release process, and provider guide are included.
