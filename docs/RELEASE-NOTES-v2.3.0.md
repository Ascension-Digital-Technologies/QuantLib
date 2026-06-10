# QuantLib v2.3.0 Release Notes

## Added

- Optional GPU acceleration boundary.
- New `quantlib::gpu` API.
- New `quantlib-inspect --gpu` command.
- Batch SHA-256 dispatcher with production-safe CPU fallback.
- CMake options for CUDA/OpenCL provider detection hooks.
- GPU documentation and tests.

## Safety

GPU crypto remains fail-safe. If a vetted GPU backend is not linked, QuantLib uses the existing CPU/provider implementation and reports that clearly.
