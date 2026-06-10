# GPU Build Guide

GPU acceleration is optional. QuantLib remains safe without it and will report CPU fallback.

## OpenCL

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_ENABLE_OPENCL=ON -DQUANTLIB_ENABLE_OPENCL_KERNELS=ON
cmake --build build --config Release
./build/quantlib-inspect --gpu
./build/quantlib-bench --gpu
```

Expected accelerated output includes:

```text
gpu_opencl_kernels yes
gpu_runtime_available yes
gpu_batch_sha256_accelerated yes
```
