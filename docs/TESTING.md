# QuantLib Testing, Fuzzing, and CI

QuantLib v2.0.0 adds the production test-readiness layer. The goal is to make release quality measurable instead of relying on a single local build.

## Build profiles

- `debug`: normal developer build.
- `release`: optimized local release build.
- `hardened`: release gate plus provider inventory and self-test.
- `sanitizer`: AddressSanitizer/UndefinedBehaviorSanitizer on supported compilers.
- `coverage`: coverage-instrumented build.
- `fuzz`: fuzz harness build entry points.

## CMake options

```bash
cmake -S . -B build -DQUANTLIB_ENABLE_SANITIZERS=ON
cmake -S . -B build-coverage -DQUANTLIB_ENABLE_COVERAGE=ON
cmake -S . -B build-fuzz -DQUANTLIB_BUILD_FUZZERS=ON
```

## Fuzz targets

Implemented entry points:

- `record-decode`: exercises encrypted record frame parsing.
- `protocol-limits`: exercises QuantLink record/frame size limit validation.

Planned parser targets:

- `vault-decode`
- `audit-decode`

These are intentionally parser-focused because malformed external input is the highest-value fuzzing surface.

## Coverage policy

Default release-readiness threshold:

- line coverage: 80%
- branch coverage: 65%
- fail under threshold: yes

## Performance budgets

The test metadata declares regression budgets for:

- `sha256-1kb`
- `channel-roundtrip`
- `vault-unlock`

The budget policy is intentionally separated from benchmark implementation so CI can compare current results to checked-in baselines later.

## CLI inspection

```bash
quantlib-inspect --test-infra
```

This prints the test matrix, fuzz targets, coverage policy, performance budgets, and release readiness capabilities.
