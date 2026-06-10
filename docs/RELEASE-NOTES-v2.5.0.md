# QuantLib v2.5.0 Release Notes

## Added

- Throughput engine API: `include/quantlib/throughput.hpp`.
- Parallel batch SHA-256 scheduler.
- Zero-copy batch view helper.
- Throughput status CLI: `quantlib-inspect --throughput`.
- Throughput documentation and tests.
- Batch layer routing into the throughput engine for large CPU batches.

## Verified

- Configure/build/CTest pass.
- Self-test includes throughput-engine coverage.
- Benchmark reports single SHA-256 plus batch throughput.
