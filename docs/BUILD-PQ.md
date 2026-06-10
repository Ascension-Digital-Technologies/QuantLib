# Post-Quantum Build Guide

PQ support requires a vetted liboqs build. Without liboqs, QuantLib fails closed and reports PQ unavailable.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_ENABLE_LIBOQS=ON
cmake --build build --config Release
./build/quantlib-inspect --pq-provider
./build/quantlib-inspect --pq-kat
```
