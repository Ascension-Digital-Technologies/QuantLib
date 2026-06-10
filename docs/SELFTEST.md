# Self-Test

QuantLib v1.0.0 includes a built-in self-test layer exposed through `quantlib::selftest`.

The self-test intentionally checks deterministic, safe invariants rather than attempting to prove cryptographic security at runtime. It currently covers:

- SHA-256 known-answer test
- HKDF-SHA256 RFC 5869 known-answer test
- versioned key blob encode/decode roundtrip
- versioned key blob tamper rejection
- transcript digest determinism and mutation detection
- encrypted channel seal/open roundtrip
- encrypted channel replay rejection
- balanced policy validation for hybrid KEM preference

Run it from the CLI:

```bash
quantlib-inspect --selftest
```

Use it from code:

```cpp
const auto report = quantlib::selftest::run();
if (!report.passed()) {
  // refuse startup or mark the provider unhealthy
}
```

For services, call `quantlib::selftest::require_pass()` during process startup before accepting network traffic.
