# Release Gate Checklist

Before publishing a release:

- [ ] VERSION matches CMake project version and `quantlib::kVersion`.
- [ ] CHANGELOG has an entry for the release.
- [ ] `quantlib-inspect --selftest` passes.
- [ ] `quantlib-inspect --release` passes for the intended profile.
- [ ] `quantlib-inspect --inventory` output is reviewed.
- [ ] `quantlib-inspect --stable-api` output is reviewed.
- [ ] Package verification script passes from a clean tree.
- [ ] `quantlib-inspect --test-infra` passes.
- [ ] Sanitizer build passes on supported compilers.
- [ ] Coverage job reports against policy.
- [ ] Fuzz smoke targets build and run.
- [ ] Performance regression budget is checked against the release baseline.
- [ ] No unsupported provider is silently enabled.
- [ ] No production docs claim unsupported PQ, FIPS certification, or unaudited algorithms.
