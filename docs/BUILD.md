# Build and Install Guide

## Requirements

- CMake 3.20 or newer.
- C++20 compiler.
- Ninja recommended.
- OpenSSL recommended for production classical crypto.
- liboqs optional for post-quantum crypto.

## Standard release build

```bash
cmake -S . -B build -DQUANTLIB_ENABLE_OPENSSL=ON -DQUANTLIB_ENABLE_HARDENING=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

## Developer build

```bash
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

## Sanitizer build

```bash
cmake --preset sanitizer
cmake --build --preset sanitizer
ctest --preset sanitizer
```

## PQ build

```bash
cmake -S . -B build-pq -DQUANTLIB_ENABLE_LIBOQS=ON -DQUANTLIB_ENABLE_OPENSSL=ON
cmake --build build-pq --config Release
```

Then verify:

```bash
build-pq/quantlib-inspect --pq-provider
build-pq/quantlib-inspect --pq-kat
```

## Install

```bash
cmake --install build --prefix install
```

The install exports `QuantLibTargets.cmake` and `QuantLibConfig.cmake` for downstream `find_package(QuantLib)` use.
