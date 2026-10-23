# Track 23: P2 Remediation — `LtHash` Custom DST Length-Prefix Framing, `AES-256-CTR` Profile, Stack Reduction & Constant-Time Equality

## Artifacts
- [Remediation Specification (`./spec.md`)](./spec.md)
- [Implementation Plan (`./plan.md`)](./plan.md)
- [Track Metadata (`./metadata.json`)](./metadata.json)

## Upstream Historical Reviews & Audit Traceability
- [Track 08 Review (`../08_lthash_cryptography_20260705/review.md`)](../08_lthash_cryptography_20260705/review.md) — Findings `F-08-04`, `F-08-05`, `F-08-06`, `F-08-07`, `F-08-08`
- [Public-Safety & Architectural Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md)

## Linked Documentation & Source Files
- [`src/incremental/lthash/encoding.rs`](../../../src/incremental/lthash/encoding.rs)
- [`src/incremental/lthash/lattice.rs`](../../../src/incremental/lthash/lattice.rs)
- [`src/state/lthash.rs`](../../../src/state/lthash.rs)
- [`src/state/at.rs`](../../../src/state/at.rs)
- [`benches/aesctr_crosscheck.rs`](../../../benches/aesctr_crosscheck.rs)
- [`benches/math/expansion_backends.rs`](../../../benches/math/expansion_backends.rs)
