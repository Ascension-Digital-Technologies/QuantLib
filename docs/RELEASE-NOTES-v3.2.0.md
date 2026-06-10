# QuantLib v4.0.0 Release Notes

## Added

- Real OpenCL batch SHA-256 kernel path.
- Runtime OpenCL platform/device detection.
- OpenCL device metadata reporting through GPU status.
- OpenCL execution path inside `quantlib::gpu::batch_sha256`.
- CPU fallback if OpenCL is unavailable or fails and fallback is allowed.
- OpenCL GPU documentation.

## Notes

CUDA remains a provider boundary. OpenCL is the first real GPU execution backend because it is more portable across NVIDIA, AMD, and Intel systems.
