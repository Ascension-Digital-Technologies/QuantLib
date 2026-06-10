# Warning Fixes

QuantLib v3.0.0 removed the Windows/Clang `fopen` deprecation warnings by replacing the affected test file operations with portable C++ file streams. QuantLib v3.0.1 keeps those warning-clean fixes.


## Fixed

- Replaced `std::fopen` usage in `tests/test-vault.cpp` with portable C++ file streams to avoid Windows CRT deprecation warnings under Clang/MSVC headers.
- Reworked internal PQ hybrid packing to avoid warning-prone vector append patterns and removed unused helper functions.

## Verification

- Configure: passed
- Build: passed
- CTest: passed
- Version CLI: `QuantLib 3.0.0`
- Production readiness CLI: passed, no blockers
