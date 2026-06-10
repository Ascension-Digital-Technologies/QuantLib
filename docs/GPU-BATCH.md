# GPU Batch Acceleration

QuantLib GPU acceleration is designed for large batch workloads. Small messages are normally faster on CPU/SIMD because GPU transfer and launch overhead can dominate.

## Build options

```bash
cmake -S . -B build -DQUANTLIB_ENABLE_GPU=ON
```

Optional provider flags:

```bash
-DQUANTLIB_ENABLE_CUDA=ON
-DQUANTLIB_ENABLE_CUDA_KERNELS=ON
-DQUANTLIB_ENABLE_OPENCL=ON
-DQUANTLIB_ENABLE_OPENCL_KERNELS=ON
```

Kernel flags are intentionally separate from provider detection. Detecting CUDA/OpenCL is not enough to claim accelerated crypto; a validated kernel provider must be built in.

## Inspect

```bash
quantlib-inspect --gpu
```

## Benchmark

```bash
quantlib-bench --gpu
```

Expected fallback output on systems without GPU kernels:

```txt
gpu_runtime_available no
gpu_batch_route cpu-fallback
gpu_batch_sha256_cpu_fallback yes
```

## API

```cpp
quantlib::gpu::BatchHashOptions options{};
options.preferred_backend = quantlib::gpu::Backend::cuda;
options.min_gpu_batch_items = 4096;
options.min_gpu_total_bytes = 4 * 1024 * 1024;

const auto result = quantlib::gpu::batch_sha256(messages, options);
```

## Safety

GPU output must be byte-for-byte identical to `quantlib::hash::sha256`. If a GPU provider is unavailable or not validated, QuantLib fails closed or uses CPU fallback depending on the caller's `allow_cpu_fallback` setting.
