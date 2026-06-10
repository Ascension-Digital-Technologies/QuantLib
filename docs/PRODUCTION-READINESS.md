# Production Readiness

QuantLib v1.9.0 is a production-candidate cleanup pass, not a final security certification.

## Release gates

A release candidate must pass:

- clean configure/build/test
- `quantlib-inspect --selftest`
- `quantlib-inspect --release`
- provider inventory review
- stable API manifest review
- package verification script

## Stable vs experimental

Stable public headers live under `include/quantlib/` and are listed by:

```bash
quantlib-inspect --stable-api
```

Experimental or provider-gated work is listed separately. PQ and memory-hard KDF hooks must fail closed unless a vetted backend is linked and tested.

## Production claim boundary

QuantLib may provide a FIPS-compatible provider mode, but the library is not FIPS certified unless the full build, provider configuration, packaging, and deployment path are validated under the relevant program.


## v1.12.0 Protocol Gate

The release gate now verifies QuantLink protocol APIs for suite negotiation, downgrade protection, record limits, and handshake state-machine availability.
