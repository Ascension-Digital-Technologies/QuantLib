# QuantLib Production Hardening

QuantLib v2.7.0 adds a production-readiness layer that makes deployment assumptions explicit and machine-checkable.

## Required production checks

- `quantlib-inspect --selftest` must pass before using custody keys.
- `quantlib-inspect --release` must pass for the hardened profile.
- `quantlib-inspect --production-ready` must pass before packaging a production build.
- Provider inventory must show a vetted classical provider, normally OpenSSL.
- PQ algorithms remain fail-closed until a vetted backend reports production-ready.

## Build hardening

The default CMake configuration now enables `QUANTLIB_ENABLE_HARDENING=ON`.

On GCC/Clang this enables stack protector support and Linux RELRO/NOW linker flags where supported. On MSVC it enables `/sdl` in addition to the existing warning profile.

Optional stricter mode:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_WARNINGS_AS_ERRORS=ON
```

## Important boundary

This release improves production discipline. It does not magically certify the library, PQ providers, deployment environment, or host OS. The production-readiness report is a release gate and integration checklist, not a substitute for external security review.
