# GPU Acceleration

QuantLib includes an optional GPU acceleration boundary for high-volume batch workloads. GPU providers are optional and fail closed or fall back to CPU paths according to policy.


The initial production-safe implementation adds:

- `include/quantlib/gpu.hpp`
- `quantlib::gpu::status()`
- `quantlib::gpu::batch_sha256(...)`
- CMake switches for CUDA/OpenCL provider hooks
- CLI inspection through `quantlib-inspect --gpu`

## Design rule

QuantLib does not pretend to have unsafe placeholder GPU cryptography. If no vetted GPU backend is linked, batch operations use the existing CPU/provider path and report `cpu-fallback`.

## CMake options

```txt
QUANTLIB_ENABLE_GPU=ON
QUANTLIB_ENABLE_CUDA=OFF
QUANTLIB_ENABLE_OPENCL=OFF
```

## API example

```cpp
#include <quantlib/gpu.hpp>

std::vector<quantlib::Bytes> messages = {
  quantlib::Bytes{'h','e','l','l','o'},
  quantlib::Bytes{'w','o','r','l','d'}
};

auto result = quantlib::gpu::batch_sha256(messages);
if (result) {
  for (const auto& digest : result.value().digests) {
    // digest is SHA-256(message)
  }
}
```

## Planned acceleration targets

The GPU boundary is designed for operations that are naturally batch-oriented:

- batch SHA-256 / SHA-512 / BLAKE3
- batch transcript hashing
- batch public-key verification where a vetted provider exists
- large sealed-object/vault scan verification
- benchmark-only experimental kernels under explicit build flags

Private-key operations should remain conservative. GPU acceleration should never expose raw private material or create provider downgrade paths.
