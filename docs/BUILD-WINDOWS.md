# Build on Windows

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure
.\build\quantlib-inspect.exe --full
.\build\quantlib-bench.exe --all
```

Optional OpenCL:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_ENABLE_OPENCL=ON -DQUANTLIB_ENABLE_OPENCL_KERNELS=ON
```

Optional liboqs:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_ENABLE_LIBOQS=ON
```
