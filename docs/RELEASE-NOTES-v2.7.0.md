# QuantLib v2.7.0 Release Notes

## Production readiness pass

QuantLib v2.7.0 adds a production-readiness layer on top of the cleaned v2.6.1 source tree.

### Added

- `include/quantlib/production.hpp`
- `src/runtime/production.cpp`
- `quantlib-inspect --production-ready`
- production readiness report API
- build hardening CMake option
- warnings-as-errors CMake option
- compile-time hardening status reporting
- integration rules and deployment blockers
- production hardening documentation

### CMake options

- `QUANTLIB_ENABLE_HARDENING=ON` by default
- `QUANTLIB_WARNINGS_AS_ERRORS=OFF` by default

### Safety boundary

The production-ready report verifies release discipline, provider status, self-tests, deployment checks, and security docs. It does not claim FIPS certification or active PQ production support unless those providers are actually linked and validated.
