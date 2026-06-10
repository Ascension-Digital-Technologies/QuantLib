# API Freeze Manifest

v1.9.0 introduces the first public API freeze manifest.

## Stable headers

The stable surface is the set returned by `quantlib::release::stable_headers()` and printed by `quantlib-inspect --stable-api`.

Breaking changes to these headers require:

1. changelog entry
2. migration note
3. version bump
4. test update
5. release-gate review

## Experimental boundary

Experimental modules may change without compatibility guarantees. They must be feature-gated, documented, and fail closed when unavailable.

- `protocol.hpp` — QuantLink protocol state machine, suite negotiation, downgrade protection, and limits.
