# Fuzzing

QuantLib v1.12.0 includes initial fuzz-entry scaffolds under `fuzz/`.

Initial targets:

- `record-decode.cpp` — encrypted record frame decoder
- `protocol-limits.cpp` — protocol frame/plaintext limit handling

Recommended future targets:

- vault decode
- sealed object decode
- audit decode
- key blob decode
- transcript field parser
- channel open path

These are scaffolds and are not wired into the normal CMake build by default. Production CI should add libFuzzer/AFL++ jobs separately.
