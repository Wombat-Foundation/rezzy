# Implementation Plan: MSC4500 Homomorphic LtHash Cryptography, BLAKE3 XOF & AES-CTR Profile (`08_lthash_cryptography_20260705`)

## Phase 1: MSC4500 Homomorphic `LtHash` Extraction & Algebraic Test Suite [checkpoint: bd3598c]

- [x] Task: Align `LtHash` primitives with MSC4500 and extract dedicated `src/state/lthash.rs` module cd46ba2
  - [x] Migrate state hashing from 64-bit FNV-1a/Zobrist to 2048-byte (1024 $\times$ `u16`) homomorphic `LtHash` and accept `impl Display + ?Sized` for event IDs (`b28ffbb`, `907287a`)
  - [x] Align `LtHash` expand/collapse domain-separation prefixes and test vectors with the MSC4500 specification (`41a34cf`, `6fd32c9`)
  - [x] Extract `LtHash` implementation and unit tests out of `src/state/delta.rs` into dedicated `src/state/lthash.rs` (`cd46ba2`)
- [x] Task: Finalize pure-lattice collapse semantics and merge `fix/lthash-msc4500-primitives` bd3598c
  - [x] Evaluate binding state cardinality $N$ into the collapse digest (`a6d9580`) and revert to standard pure-lattice collapse so digest equality depends solely on the 2048-byte lattice vector (`3f7383f`)
  - [x] Merge branch `fix/lthash-msc4500-primitives` with complete MSC4500 primitive alignment (`bd3598c`)
- [x] Task: Add comprehensive algebraic, boundary, and differential mutation tests for `LtHash` 71c596d
  - [x] Add commutativity, associativity, inverse cancellation, and multi-batch replacement property tests in `src/state/lthash.rs` (`71c596d`)
  - [x] Add 64KiB (`u16::MAX`) UTF-8 char-boundary truncation tests and differential state-map vs. incremental accumulator mutation tests (`71c596d`)

## Phase 2: Zero-Allocation Seed Framing, Sorting Optimizations & Fast-Path Integration [checkpoint: 8e6f73c]

- [x] Task: Implement zero-allocation `LtHash` seed generation for arbitrary Matrix Event IDs 767c876
  - [x] Replace heap-allocating string formatting with stack-buffered `HashWriter` (`core::fmt::Write`) streaming directly into the XOF state (`91522e0`)
  - [x] Streamline seed generation in `src/state/lthash.rs` to accept any event ID format (legacy, v4+ base64, or integer IDs) without heap allocation (`767c876`)
- [x] Task: Integrate `LtHash` sorting optimizations and identical-fork fast path into `src/state/at.rs` 8e6f73c
  - [x] Thread incremental `LtHash` state updates through `src/state/at.rs`, `src/state/cache.rs`, and `src/state/delta.rs` (`8e6f73c`)
  - [x] Implement `resolve_merge_fast_path_hashed` (Path A) in `src/state/at.rs` with differential verification against full uncached state resolution (`efc06d7`)
  - [x] Update `lthash16` domain tag to `lthash16-v1` per MSC4500 updates and make `StateUpdate` borrow `&LtHash` to avoid 2048-byte copies (`2acae2d`, `e74a5e8`)

## Phase 3: Cryptographic Migration from `BLAKE2b`/`SHAKE256` to Hand-Rolled SIMD `BLAKE3` XOF [checkpoint: fea3310]

- [x] Task: Remove `blake2` dependency and migrate `LtHash` to `BLAKE3` XOF specification 6acedab
  - [x] Remove `blake2` from `Cargo.toml` and `benches/Cargo.lock`, switching lattice expansion and collapse to `blake3` (`6acedab`)
  - [x] Prototype SIMD multi-buffer BLAKE3 expansion skeleton (`2cfa6fe`, `6429e4a`)
- [x] Task: Complete the `BLAKE3` XOF refactor across `src/state/lthash.rs`, `rezzy-cli`, and benchmarks 9f152dc
  - [x] Update `src/state/lthash.rs`, `src/hamt/hash.rs`, `src/state/at.rs`, and `src/state/delta.rs` to use `msc4500:lthash16:blake3:v1` (`9f152dc`)
  - [x] Add `rezzy-cli/src/hash.rs` CLI hashing subcommands and update `benches/math/lthash_comprehensive.rs` (`9f152dc`)
- [x] Task: Encapsulate `LtHash` lanes field and add canonical byte/array conversions fea3310
  - [x] Make the internal `[u16; 1024]` lanes field private and expose `from_bytes`, `to_bytes`, `from_lanes`, and array `From`/`TryFrom` conversions (`fea3310`)

## Phase 4: Generic `LtLattice` Split, `MSC4500` Resolution Inputs & `AES-256-CTR` Interoperability [checkpoint: 8dcd1c1]

- [x] Task: Implement `MSC4500` `ResolutionInputs` accumulator and pin cross-implementation vectors daa37f0
  - [x] Implement `ResolutionInputs` and `RedactionOverlay` accumulators in `src/state/lthash.rs` (`daa37f0`)
  - [x] Pin cross-implementation `MSC4500` resolution-input proposal test vectors in `src/state/lthash.rs` (`7d2653a`, `f463203`, `4d2e7b1`)
- [x] Task: Split `LtHash` into domain-independent `src/incremental/lthash/` and state adapters in `src/state/lthash.rs` 72779f5
  - [x] Move generic `LtLattice<const LANES: usize>` and `encoding.rs` into `src/incremental/lthash/` (`d5cc8a3`)
  - [x] Split state-specific `from_state`, `RedactionOverlay`, `ResolutionInputs`, and `PduLtHash` adapters into `src/state/lthash.rs` and remove legacy re-exports (`72779f5`, `8616b66`)
- [x] Task: Benchmark `SHAKE256`+`BLAKE2b` vs `BLAKE3` vs `AES-256-CTR` and cross-check `gomatrixcrypto` 8dcd1c1
  - [x] Benchmark `SHAKE256`+`BLAKE2b` against `BLAKE3`+`BLAKE3`, `SHA-512-CTR`, and `AES-256-CTR` in `benches/math/expansion_backends.rs` (`40416d4`, `9cc147b`)
  - [x] Add `benches/aesctr_crosscheck.rs` verifying both portable and `AES-NI` `AES-256-CTR` `LtHash16` digests match `gomatrixcrypto`'s `lthash.TestAESCTRVector` (`36bc9ba`)
  - [x] Document the sibling `gomatrixcrypto` `AES-256-CTR` `LtHash` profile and its architectural boundary with `rezzy-recon` in `docs/gf128_widening_analysis.md` (`8dcd1c1`)

---

## History & Audit Traceability

| Commit SHA | Date | Subject | Primary Source & Test Files | Linked Docs & Public-Safety Audit Mapping |
| :--- | :--- | :--- | :--- | :--- |
| `cd46ba2` | 2026-07-05 | `refactor: move LtHash to dedicated lthash.rs out of cluttered delta.rs` | `src/state/lthash.rs`, `src/state/delta.rs`, `src/state/mod.rs` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) — **Audit #8 (High: Missing Guards)** |
| `bd3598c` | 2026-07-05 | `Merge branch 'fix/lthash-msc4500-primitives'` | `src/state/lthash.rs`, `src/state/delta.rs`, `tests/test_critique.rs` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) |
| `71c596d` | 2026-07-05 | `test: add algebraic, boundary, and differential mutation tests for LtHash` | `src/state/lthash.rs` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) |
| `91522e0` | 2026-07-06 | `perf: implement zero-allocation LtHash with strict event ID validation` | `src/state/lthash.rs` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) |
| `767c876` | 2026-07-06 | `lthash: streamline seed generation to allow any event ID format while preserving zero-allocation performance` | `src/state/lthash.rs` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) — Delegates syntactic Event ID validation to caller boundary (**Audit #8**). |
| `8e6f73c` | 2026-07-06 | `Merge branch 'feature/lthash-sorting-optimizations'` | `src/state/at.rs`, `src/state/lthash.rs`, `src/state/cache.rs` | [`perf_audits.md`](../../../docs/perf_audits.md) — Establishes Path A identical-fork fast path; rejects Path B partial-digest skip. |
| `6acedab` | 2026-10-01 | `wip: lthash remove blake2, use blake3 hand-rolled spec` | `Cargo.toml`, `src/hamt/hash.rs` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) |
| `9f152dc` | 2026-10-01 | `continue the blake3 simd refactor` | `src/state/lthash.rs`, `rezzy-cli/src/hash.rs`, `benches/math/lthash_comprehensive.rs` | [`jsonl-aggregation.md`](../../../docs/jsonl-aggregation.md), [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) |
| `fea3310` | 2026-10-02 | `feat(lthash): private lanes field, from_bytes/to_bytes, array conversions` | `src/state/lthash.rs` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) |
| `daa37f0` | 2026-10-03 | `feat(msc4500): add resolution-input accumulator` | `src/state/lthash.rs` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) |
| `72779f5` | 2026-10-09 | `Split LtHash into generic core and state adapters` | `src/incremental/lthash/lattice.rs`, `src/incremental/lthash/encoding.rs`, `src/state/lthash.rs` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) |
| `36bc9ba` | 2026-10-11 | `test: cross-check AES-256-CTR LtHash digest against gomatrixcrypto` | `benches/aesctr_crosscheck.rs`, `benches/Cargo.toml` | [`gf128_widening_analysis.md`](../../../docs/gf128_widening_analysis.md) |
| `8dcd1c1` | 2026-10-15 | `Document gomatrixcrypto AES-CTR LtHash profile` | `docs/gf128_widening_analysis.md` | [`gf128_widening_analysis.md`](../../../docs/gf128_widening_analysis.md) — **Audit #6 (Moderate: Algebraic Floor & Crypto Profile Separation)** |

> **Public-Safety Remediation Linkage**: Open findings from [`../../audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #8: Missing pre-auth syntactic validation `src/auth/validate.rs` ahead of zero-allocation `LtHash::seed`; Row #6: Algebraic/cryptographic accumulator profile boundaries) are tracked in Stage B Priority P1 Item #5.
