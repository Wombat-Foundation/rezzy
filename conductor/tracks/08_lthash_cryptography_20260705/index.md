# Track 08: MSC4500 Homomorphic LtHash Cryptography, BLAKE3 XOF & AES-CTR Profile

- **Track ID**: `08_lthash_cryptography_20260705`
- **Type**: `feature`
- **Status**: `completed` (Historical Stage A Track — Audited)
- **Commit Range**: `b28ffbb..8dcd1c1` (`2026-07-05` – `2026-08-31`)

## Quick Links

- [Specification (`./spec.md`)](./spec.md)
- [Implementation Plan (`./plan.md`)](./plan.md)
- [Track Metadata (`./metadata.json`)](./metadata.json)
- [Public Safety & Documentation Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md)

## Reviews & Critiques

- [Track Review & 8-Persona Critique (`./review.md`)](./review.md)

## Key Artifacts & Source Files

- `src/incremental/lthash/lattice.rs` — `LtLattice<const LANES: usize>` and `LtHash` (`LtLattice<1024>`) over $\mathbb{Z}_{2^{16}}^{1024}$
- `src/incremental/lthash/encoding.rs` — Length-prefixed element framing and BLAKE3 XOF lane expansion (`msc4500:lthash16:blake3:v1`)
- `src/state/lthash.rs` — `RedactionOverlay`, `ResolutionInputRecord`, `ResolutionInputs`, `PduLtHash`, `StateDigest`, and `DigestAgreement`
- `src/state/at.rs` — `HashedState` and `resolve_merge_fast_path_hashed_with_cache`
- `benches/aesctr_crosscheck.rs` — Cross-implementation test vector verification against `gomatrixcrypto` (`msc4500:lthash16:aes-ctr:v1`)
- `benches/math/expansion_backends.rs` — Comparative benchmark of BLAKE3 XOF, SHA-3 (`SHAKE128`/`TurboShake128`), and AES-256-CTR backends
