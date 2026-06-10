# Repository Hygiene

## Root files

The root should contain only high-value project files and the requested project folders. Build products stay ignored under `build/` and `bin/`.

## Naming

- Public headers live under `include/quantlib/`.
- Implementation code lives under `src/` by responsibility.
- Tests, examples, benchmarks, and fuzz harnesses live under `tests/`.
- Scripts live under `cmake/scripts/` to preserve the requested root layout.

## Formatting

Use `.clang-format` and `.editorconfig`. Do not reformat generated third-party code under `external/`.

## Secrets

Never commit:

- vault files;
- private keys;
- passphrases;
- signing keys;
- production audit logs;
- provider credentials.

## Release archive rules

A release source archive should include source, headers, docs, CMake files, scripts, tests, examples, fuzz harnesses, and metadata. It should not include local build directories or compiled artifacts.
