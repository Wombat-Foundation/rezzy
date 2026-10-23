# Track 08: MSC4500 Homomorphic LtHash Cryptography, BLAKE3 XOF & AES-CTR Profile (`08_lthash_cryptography_20260705`)

- **Track ID**: `08_lthash_cryptography_20260705`
- **Epoch**: `v0.5.0`–`0.6.0-rc.2` + Oct 2026 (`2026-07-03` to `2026-10-15`)
- **Commit Range**: `b28ffbb..8dcd1c1` (`b28ffbb`, `907287a`, `41a34cf`, `6fd32c9`, `cd46ba2`, `a6d9580`, `3f7383f`, `bd3598c`, `71c596d`, `91522e0`, `767c876`, `8e6f73c`, `efc06d7`, `2acae2d`, `6acedab`, `9f152dc`, `fea3310`, `40416d4`, `9cc147b`, `daa37f0`, `7d2653a`, `f463203`, `d5cc8a3`, `72779f5`, `36bc9ba`, `8dcd1c1`)
- **Status**: Completed (`[x]`)

## Track Artifacts

- **[Track Specification (`./spec.md`)](./spec.md)** — Reverse-engineered requirements for `MSC4500` 2048-byte homomorphic lattice state hashing (`LtLattice<1024>`), extraction from `delta.rs`, cryptographic migration from `SHAKE256`+`BLAKE2b` to SIMD `BLAKE3` XOF, `RedactionOverlay` and `ResolutionInputs` accumulators, and `gomatrixcrypto` `AES-256-CTR` cross-checking.
- **[Implementation Plan (`./plan.md`)](./plan.md)** — 4-phase historical execution plan mapping 14 verified git commits across July–October 2026.
- **[Track Metadata (`./metadata.json`)](./metadata.json)** — Machine-readable metadata, commit boundaries, linked documentation, and Public-Safety Audit risk summary.

## Linked Documentation & Public-Safety Audit

- **[`../../../docs/homeserver_utilities.md`](../../../docs/homeserver_utilities.md)** — Documents `state::delta::*` state delta compression and incremental state hashing utilities alongside missing Tier-2 validation guards.
- **[`../../../docs/gf128_widening_analysis.md`](../../../docs/gf128_widening_analysis.md)** — Documents accumulator forgery bounds and the sibling `gomatrixcrypto` `AES-256-CTR` `LtHash` profile (`8dcd1c1`).
- **[`../../../docs/perf_audits.md`](../../../docs/perf_audits.md)** — Documents the decision to adopt **Path A** (`resolve_merge_fast_path_hashed` identical-fork fast path with `ptr_eq || ==` authority) and reject **Path B** (skipping resolution on partial `LtHash` sub-accumulators).
- **[`../../audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md)** — Public-Safety Audit rows **#8 (`homeserver_utilities.md` — High: Missing Guards)** and **#6 (`gf128_widening_analysis.md` — Moderate: Algebraic Floor)**.

## Primary Source & Test Files

- [`../../../src/incremental/lthash/lattice.rs`](../../../src/incremental/lthash/lattice.rs) — Domain-independent `LtLattice<const LANES: usize>` and `pub type LtHash = LtLattice<1024>`.
- [`../../../src/incremental/lthash/encoding.rs`](../../../src/incremental/lthash/encoding.rs) — Zero-allocation `HashWriter`, `truncate_to_u16_limit`, 256-byte windowed `expand_lanes` (`BLAKE3` XOF), 8-lane chunked SIMD `add_lattice`/`sub_lattice`, and `lattice_digest`.
- [`../../../src/state/lthash.rs`](../../../src/state/lthash.rs) — `MSC4500` state adapters: `LtLattice::from_state`, `RedactionOverlay`, `ResolutionInputs`, `PduLtHash`, and `StateDigest`.
- [`../../../benches/aesctr_crosscheck.rs`](../../../benches/aesctr_crosscheck.rs) & [`../../../benches/math/expansion_backends.rs`](../../../benches/math/expansion_backends.rs) — Cross-implementation test vector verification against `gomatrixcrypto`'s `lthash.TestAESCTRVector` (`L5WCOKR7yn1u44_LVhGVrttjSxq5gLCbwWUCs0eq1iQ`).
