# Source Cleanup

QuantLib v2.7.0 reorganizes the source tree without changing the public API.

## Cleanup applied

- Removed the unused empty `src/dispatch/` directory.
- Moved security and custody implementations under `src/security/`.
- Moved protocol/session/record/channel code under `src/protocol/`.
- Moved release, operations, testing, batch, hardware, throughput, and self-test code under `src/runtime/`.
- Moved the easy integration facade under `src/facade/`.
- Kept public headers under `include/quantlib/`.
- Kept examples, fuzz targets, and benchmarks under `tests/`.
- Kept operational scripts under `cmake/scripts/`.

## Public compatibility

The public namespace and include path remain:

```cpp
#include <quantlib/quantlib.hpp>
namespace ql = quantlib;
```

No raw private-key export APIs were added. The cleanup is layout-focused.
