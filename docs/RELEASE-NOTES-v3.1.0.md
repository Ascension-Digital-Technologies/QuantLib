# QuantLib v3.1.0 — GPU Batch Routing and Benchmark Pass

QuantLib v3.1.0 improves the GPU integration layer so GPU-related commands no longer appear silent when no CUDA/OpenCL kernel provider is linked.

## Added

- `quantlib-bench --gpu` output with GPU status, routing, throughput, and fallback reporting.
- GPU route decision API for large batch workloads.
- GPU routing thresholds by item count and total input bytes.
- CUDA/OpenCL kernel compile flags:
  - `QUANTLIB_ENABLE_CUDA_KERNELS`
  - `QUANTLIB_ENABLE_OPENCL_KERNELS`
- GPU status fields for kernel-provider availability.
- Improved `quantlib-inspect --gpu` output.

## Production boundary

The GPU path remains production-honest. QuantLib will only mark GPU acceleration active when a validated CUDA/OpenCL kernel provider is compiled in. Otherwise it uses the vetted CPU path and explicitly reports `cpu-fallback`.
