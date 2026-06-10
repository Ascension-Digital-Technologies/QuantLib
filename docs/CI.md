# CI Matrix

QuantLib production CI should run the following jobs before a release candidate is accepted.

## Platforms

- Windows MSVC
- Windows clang-cl
- Linux GCC
- Linux Clang
- macOS Clang

## Jobs

1. Configure
2. Build
3. CTest
4. Built-in self-test
5. Release gate
6. Examples
7. Package check
8. Sanitizer build
9. Coverage build
10. Fuzz smoke
11. Benchmark smoke
12. Performance budget check

The current repository includes scripts for local smoke execution. Full hosted CI should wire these scripts into GitHub Actions or another CI runner.
