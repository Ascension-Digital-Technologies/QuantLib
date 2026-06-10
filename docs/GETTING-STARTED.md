# Getting Started

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Inspect health

```bash
./build/quantlib-inspect --full
```

## Benchmark

```bash
./build/quantlib-bench --all
```

## Use in CMake

```cmake
find_package(QuantLib CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE QuantLib::quantlib)
```
