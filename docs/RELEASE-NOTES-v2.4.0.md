# QuantLib v2.4.0 Release Notes

## Hardware Acceleration + Batch Crypto Layer

Added:

- `include/quantlib/hardware.hpp`
- `include/quantlib/batch.hpp`
- hardware dispatch metadata
- CPU/GPU routing policy
- production-safe batch SHA-256 API
- fail-closed batch signature verification boundary
- `quantlib-inspect --hardware`
- `quantlib-inspect --batch`
- benchmark upgrades for batch SHA-256
- hardware and batch tests

GPU/vector acceleration remains provider-gated. QuantLib reports accelerator capability clearly but does not silently use unvetted GPU crypto for private-key or protocol security operations.
