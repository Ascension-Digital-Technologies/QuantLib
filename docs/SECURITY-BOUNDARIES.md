# Security Boundaries

## Implemented production-candidate boundaries

- No raw private-key export API in SSM.
- Sealed objects are authenticated and encrypted.
- Vault metadata is authenticated.
- Sessions are short-lived and permission-scoped.
- Audit records are hash chained.
- PQ hooks are fail-closed unless a backend is linked.

## Not certification claims

- FIPS mode is a provider/deployment configuration target, not a certification claim for this source tree.
- PQ implementations are not production until backed by vetted provider code and KATs.
- Side-channel resistance still requires dedicated review and timing analysis.
