# QuantLib OpenCL GPU SHA-256

QuantLib v4.0.0 adds a real OpenCL batch SHA-256 execution path. The GPU path is optional and remains safe by default:

- If OpenCL is found and `QUANTLIB_ENABLE_OPENCL_KERNELS=ON`, large batch SHA-256 requests can route to OpenCL.
- If OpenCL is missing, the library still builds and uses the CPU fallback.
- If the OpenCL runtime fails at execution time and CPU fallback is allowed, the operation falls back to the production CPU hash path.

## Build

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_ENABLE_OPENCL=ON -DQUANTLIB_ENABLE_OPENCL_KERNELS=ON
cmake --build build --config Release
```

OpenCL is enabled by default in v4.0.0, but passing the flags explicitly makes the intent clear.

## Check status

```powershell
.\\build\\quantlib-inspect.exe --gpu
.\\build\\quantlib-bench.exe --gpu
```

A working OpenCL path should report `gpu_selected_backend opencl` and `gpu_batch_sha256_accelerated yes` for large enough batches.

## Routing

The default routing thresholds are:

- minimum batch items: 4096
- minimum total input bytes: 4 MiB

Below those thresholds, CPU/SIMD is usually faster because GPU transfer overhead dominates.
