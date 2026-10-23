# Implementation Plan: `rezzy-recon` (`MSC4521` $\text{GF}(2^{64})$ PinSketch Reconciliation, `h64` Prefix Grinding & `MSC4511` Causal Tries)

## Phase 1: `MSC4511` Merkle Tries, Cuckoo Verification & `rezzy-recon` Extraction [checkpoint: f56b068]

- [x] Task: Land Cuckoo cycle verifier and `MSC4511` causal Merkle trie proofs `3fe8542`
  - [x] Merge `src/cuckoo_verify.rs` implementing Cuckoo cycle graph verification (`3fe8542`) and mask Cuckoo node indices to 29 bits with a mined 42-cycle regression test (`f9414ce`, `727333b`).
  - [x] Merge `src/merkle.rs` and `tests/test_merkle.rs` implementing `MSC4511` state and causal Merkle inclusion/exclusion proofs (`b74bda8`).
- [x] Task: Extract `rezzy-recon` crate and harden PinSketch work budgets and aggregate capacity `3d5de22`
  - [x] Verify PinSketch Frobenius root-finding cost model ceilings in `rezzy-recon/src/pinsketch.rs` (`3d5de22`) and make aggregate reconciliation capacity configurable (`f011a0a`).
  - [x] Document guard reachability and `transition_bucket_batch` untrusted-capacity asymmetry (`541037d`) and merge full reconciliation suite to `master` (`f56b068`).
- [x] Task: Replace external `roaring` crate with in-tree `#![no_std]` `u32` bitmap engine `04dc560`
  - [x] Implement `Bitmap`, `Bitmap64`, and `Bitmap128` with in-place chunk unions, branch-free array intersections, removal, predicates, and versioned binary codec (`04dc560`, `7ad9903`, `1f1d704`, `7bfb7bb`, `c8eb885`, `60a2b93`).
  - [x] Move bitmap implementation into `rezzy-recon/src/bitmap/` (`045c52f`, `19814bc`) and verify dense bitmap set operations against a linear oracle (`047ff3c`, `13d13dc`).

## Phase 2: Two-Phase Verification, Disjoint `h128` Residuals & `SortedPopulation` [checkpoint: 61ae5a9]

- [x] Task: Derive disjoint `h128` residuals and implement two-phase decoded difference verification `d5f9fca`
  - [x] Persist `ResidentKernel` (`9d06660`, `8aac325`) and derive `h128` from SHA-256 digest bytes `16..32` so it is strictly disjoint from `h64` (`d5f9fca`).
  - [x] Implement two-phase verification (`3384611`, `09be37c`, `8cb4fe8`) and re-encode syndrome validation inside the shared PinSketch decoder (`119ca48`).
- [x] Task: Enforce V3/V4+ content-hashed event IDs, cap bucket depth at 32, and introduce `Population` trait `37922e1`
  - [x] Drop legacy V1/V2 sender-chosen event ID formats (`37922e1`, `134d2ee`) and cap bucket trie depth at `MAX_DEPTH = 32` per MSC4521 (`571c5c2`).
  - [x] Replace parallel `h64`/`h128` slices with `SortedPopulation` (`da3f644`) and generalize `build_bucket_nodes` and `ReconciliationContext` over the `Population` trait (`61ae5a9`, `3e520b7`).
- [x] Task: Add per-node `(count, digest)` summaries and verified split-consistency checks `4851086`
  - [x] Implement 24-byte `NodeSummary` wire serialization and verified bucket exchange (`4851086`, `05a1f53`, `497c5a4`).
  - [x] Ladder-fail confirmed `h64` collisions and inconsistent split prefixes (`864336f`) and implement Phase-1 split / Phase-2 stop rules (`1ad8fde`, `f7a8f38`, `1e20d19`).

## Phase 3: Cryptographic Domain Separation, `MSC4511` v2 & $\text{GF}(2^{128})$ / `h64` Grinding Analyses [checkpoint: 1ced0da]

- [x] Task: Specify `MSC4511` v2 leaf-compressed causal trie and harden SHA-256 domain tags `0616326`
  - [x] Author [`docs/msc4511_compressed_trie.md`](../../../docs/msc4511_compressed_trie.md) specifying leaf compression (Option A), depth-bound `BRANCH` hashing, checked `u64` count addition, and 3-terminal proofs (`0616326`).
  - [x] Harden proof validation paths (`94dc056`) and explicitly name `sha256` in `msc4511:<name>:sha256:v1` domain separation tags (`1728c49`).
- [x] Task: Analyze and reject $\text{GF}(2^{64}) \to \text{GF}(2^{128})$ field widening `eeb0b90`
  - [x] Author [`docs/gf128_widening_analysis.md`](../../../docs/gf128_widening_analysis.md) proving that widening to $\text{GF}(2^{128})$ multiplies decode work by $4\text{--}5\times$, weakens CPU DoS ceilings by $4\text{--}7\times$, doubles wire/sketch memory, and breaks `libminisketch` interoperability (`eeb0b90`).
  - [x] Document `gomatrixcrypto` AES-256-CTR LtHash profile relationship (`8dcd1c1`, `36bc9ba`).
- [x] Task: Analyze `h64` prefix grinding threat model and structural epoch impossibility `f940966`
  - [x] Author [`docs/2026-10-12-h64-prefix-grinding.md`](../../../docs/2026-10-12-h64-prefix-grinding.md) analyzing unkeyed `h64` prefix grinding and local mitigation bounds (`f940966`).
  - [x] Prove why structurally-derived DAG epochs cannot provide authoring-time unpredictability without consensus finality (`1ced0da`).

## Phase 4: Local No-Amplification Retry Policy, Wire Overflow Decode & Wide-Split Validation [checkpoint: 7e81097]

- [x] Task: Route estimator work exhaustion and add strata wire / zero-residual fast paths `a3925d4`
  - [x] Improve reconciliation fallback handling and route strata estimator `BudgetExhausted` directly to bucket extraction (`a3925d4`, `7421ebf`).
  - [x] Add strata wire encode/decode (`RemoteDigest::from_wire`), shared `NodeSummary::is_split_of`, `bucket_prefix` helpers, and zero-residual sketch short-circuiting (`c503ca4`, `285736c`, `9a939a2`, `1c3a53f`).
- [x] Task: Implement local no-amplification retry policy and wire overflow bucket decoding `553841b`
  - [x] Replace the 1-bit split ladder in `BucketExchange::advance_verified` with capacity-256 overflow retries for small residuals ($\le 256$) and up to 7-bit wide fan-out for larger nodes (`553841b`, `3d62f2f`, `92695e8`, `b576bc8`).
  - [x] Add `from_overflow_coordinates` and `validate_decoded_overflow` in `triage.rs`/`algebraic.rs` so overflow buckets $> 32$ decode over the wire, and gate overflow retry on remaining aggregate round capacity (`fd18689`, `4fe8705`, `f65f4ac`).
- [x] Task: Validate multi-round wide-split descendant summaries against parent `NodeSummary` `491bd9e`
  - [x] Retain descendant summaries across rounds in `rezzy-recon/src/client.rs`, compare complete prefix covers against the failed ancestor summary, and ladder-fail on count or digest mismatch (`491bd9e`, `808275b`, `7e81097`).

## History & Audit Traceability

| Commit SHA | Source / Implementation Files | Verification / Test Files | Linked `docs/` Files | Public-Safety Audit Observation (`../../audits/rezzy_docs_public_safety_audit.md`) |
| :--- | :--- | :--- | :--- | :--- |
| `3fe8542`, `b74bda8`, `0616326`, `94dc056`, `f9414ce`, `1728c49` | [`src/merkle.rs`](../../../src/merkle.rs), [`src/cuckoo_verify.rs`](../../../src/cuckoo_verify.rs) | [`tests/unit/test_merkle.rs`](../../../tests/unit/test_merkle.rs), [`tests/unit/test_causal.rs`](../../../tests/unit/test_causal.rs) | [`docs/msc4511_compressed_trie.md`](../../../docs/msc4511_compressed_trie.md) | **Moderate (Crypto Agility)**: MSC4511 v1 uses `saturating_add` and `u32` varints; v2 design specifies checked `u64` addition and explicit `v2` (SHA-256) vs. `v3` (BLAKE3) domain separation tags. |
| `3d5de22`, `f56b068`, `d5f9fca`, `3384611`, `eeb0b90` | [`rezzy-recon/src/pinsketch.rs`](../../../rezzy-recon/src/pinsketch.rs), [`rezzy-recon/src/algebraic.rs`](../../../rezzy-recon/src/algebraic.rs) | [`tests/unit/test_reconcile_algebraic.rs`](../../../tests/unit/test_reconcile_algebraic.rs) | [`docs/gf128_widening_analysis.md`](../../../docs/gf128_widening_analysis.md) | **Moderate (Algebraic Floor)**: Rejects $\text{GF}(2^{128})$ to avoid a $4\text{--}7\times$ CPU DoS multiplier (`MAX_BATCH_FACTOR_WORK` $5.77\times$), documenting the $2^{32}$ `h64` birthday floor and $\sim 2^{37}$ XOR residual bound. |
| `4851086`, `864336f`, `f940966`, `1ced0da`, `553841b`, `b576bc8`, `fd18689`, `4fe8705`, `491bd9e` | [`rezzy-recon/src/client.rs`](../../../rezzy-recon/src/client.rs), [`rezzy-recon/src/triage.rs`](../../../rezzy-recon/src/triage.rs) | [`tests/unit/test_reconcile_e2e.rs`](../../../tests/unit/test_reconcile_e2e.rs) | [`docs/2026-10-12-h64-prefix-grinding.md`](../../../docs/2026-10-12-h64-prefix-grinding.md), [`docs/tech_debt.md`](../../../docs/tech_debt.md) | **High (Liveness / DoS)**: Local no-amplification retry policy eliminates responder bandwidth amplification and validates wide splits (`491bd9e`), but `MAX_BUCKETS_PER_ROUND = 128` queue saturation and terminal `ladder_failed` require bounded caller ID fallback. |
| `04dc560`, `7ad9903`, `045c52f`, `19814bc`, `13d13dc` | [`rezzy-recon/src/bitmap/mod.rs`](../../../rezzy-recon/src/bitmap/mod.rs) | [`rezzy-recon/src/bitmap/mod.rs`](../../../rezzy-recon/src/bitmap/mod.rs) | [`docs/architecture.md`](../../../docs/architecture.md) | Replaces external `roaring` dependency with audited in-tree `u32` bitmap verified by dense linear-oracle tests (`13d13dc`). |
