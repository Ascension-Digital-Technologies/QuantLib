# QuantLib v2.0.0 Release Notes

QuantLib v2.0.0 converts the project from a feature-complete custody prototype into a production-baseline release package.

## Highlights

- Production boundary API and CLI output.
- Required release artifact manifest.
- SBOM component inventory scaffolding.
- Security document set manifest.
- Release signing/checksum steps.
- Expanded hardened release gate.
- New self-test check for v2 production baseline readiness.
- New CLI commands: `quantlib-inspect --production` and `quantlib-inspect --sbom`.

## Boundary

The classical crypto, SSM, vault, audit, protocol, test/fuzz/CI, and release-gate layers are included in the production baseline. PQ crypto, memory-hard KDFs, and FIPS-compatible deployments remain provider-dependent and fail closed unless configured with vetted external providers.
