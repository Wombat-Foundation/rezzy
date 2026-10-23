# Specification: `rezzy-recon` (`MSC4521` $\text{GF}(2^{64})$ PinSketch Reconciliation, `h64` Prefix Grinding & `MSC4511` Causal Tries)

## 1. Overview & Historical Context

- **Epoch**: July 15, 2026 – October 18, 2026 (`v0.5.0` – `0.6.0-rc.2`)
- **Primary Commit Trajectory**: `3fe8542`, `b74bda8`, `3d5de22`, `f011a0a`, `541037d`, `f56b068`, `9d06660`, `d5f9fca`, `3384611`, `09be37c`, `37922e1`, `4851086`, `864336f`, `da3f644`, `134d2ee`, `571c5c2`, `119ca48`, `1ad8fde`, `f7a8f38`, `61ae5a9`, `0616326`, `04dc560`, `045c52f`, `94dc056`, `f9414ce`, `1728c49`, `727333b`, `eeb0b90`, `f940966`, `1ced0da`, `a3925d4`, `7421ebf`, `c503ca4`, `285736c`, `9a939a2`, `1c3a53f`, `553841b`, `3d62f2f`, `92695e8`, `b576bc8`, `fd18689`, `4fe8705`, `13d13dc`, `f65f4ac`, `491bd9e`, `808275b`, `7e81097`
- **Motivation**:
  1. **Bandwidth-Proportional DAG Synchronization (`MSC4521`)**: Traditional Matrix federation backfill walks the DAG edge-by-edge or exchanges full extremity sets. `rezzy-recon` reconciles multi-million-event room populations with bandwidth proportional strictly to the symmetric difference $\Delta$ using $\text{GF}(2^{64})$ BCH/PinSketch syndrome sketches (`SyndromeSketch`), a 32-stratum IBLT/PinSketch size estimator (`ResidentKernel`), and prefix-bucketed trie narrowing (`BucketExchange`).
  2. **Adversarial Verification & Prefix Grinding Defense**: Content-hashed Matrix V3/V4+ event IDs allow an offline attacker to grind colliding `h64` keys ($2^{32}$ birthday bound) or shared `h64` prefixes ($2^k$ hashes for a $k$-bit prefix). Without verification and bounded retry policies, an attacker withholding ground events could force exponential 1-bit bucket split amplification or silent decode corruption.
  3. **Causal Merkle Tries (`MSC4511`) & Cuckoo Attestation**: Provide compact cryptographic inclusion/exclusion proofs over room event sets (`src/merkle.rs`) and anti-Sybil Cuckoo cycle verification (`src/cuckoo_verify.rs`).

## 2. Functional Requirements & Matrix Spec/MSC Mapping

1. **MSC4521 $\text{GF}(2^{64})$ PinSketch Algebra & Wire Format**:
   - Field arithmetic over $\text{GF}(2^{64})$ with irreducible reduction polynomial $x^{64} + x^4 + x^3 + x + 1$ (`rezzy-recon/src/gf64.rs`), accelerated via PCLMULQDQ and AVX-512 `vpclmulqdq` (`rezzy-recon/src/gf64_simd.rs`) and verified against `libminisketch` 64-bit serialization vectors.
   - `ElementHash` derives `h64` from the first non-zero 8-byte big-endian chunk of the 32-byte event digest (fallback `1`) and `h128` from the disjoint trailing half (`bytes 16..32`, commit `d5f9fca`). Rejects legacy V1/V2 sender-chosen event IDs at frame construction (`37922e1`, `134d2ee`).
   - Berlekamp-Massey locator synthesis + Frobenius basis trace splitting (`pinsketch.rs`), enforcing re-encode syndrome verification inside the shared decode path (`119ca48`) and strict work-unit budgets (`MAX_FACTOR_WORK = 16_000_000`, `MAX_BATCH_FACTOR_WORK = 36_700_160`, `MAX_STRATA_FACTOR_WORK = 1_458_176`).
2. **Two-Phase Verified Bucket Exchange & Local No-Amplification Retry Policy (`docs/2026-10-12-h64-prefix-grinding.md`)**:
   - **Per-Node Summaries (`NodeSummary`)**: Every bucket carries a 24-byte `(count: u64, digest: u128)` summary (`4851086`). Parent-child split consistency is checked via `NodeSummary::is_split_of` (`285736c`) and across multi-round wide splits (`491bd9e`).
   - **Two-Phase Verification (`3384611`, `09be37c`)**: Phase 1 verifies decoded candidate roots against local keys; Phase 2 (`verify_follow_up`) verifies opposite-sided `h64` collisions via the `h64 -> h128` residual map and checks `verify_global_residual` against the level-0 XOR accumulator.
   - **No-Amplification Retry Policy (`553841b`, `b576bc8`, `fd18689`, `4fe8705`)**:
     1. *Overflow Decode Small Residuals*: If an undecodable normal bucket passes Phase 1 and the sum of local + remote counts is $\le 256$ (and fits the remaining aggregate round capacity `MAX_BUCKETED_SKETCH_CAPACITY = 4096`), request a single capacity-256 overflow sketch (`from_overflow_coordinates`).
     2. *Wide Multi-Bit Fan-Out*: If a failed node exceeds capacity 256 or fails Phase 1, split immediately by up to 7 prefix bits (up to 128 children) based on returned `NodeSummary` counts, sending up to `MAX_BUCKETS_PER_ROUND = 128` requests per round and queuing the rest.
     3. *Node-Scoped Terminal Fallback*: Expose terminal failures (`MAX_DEPTH = 32`, `571c5c2`, or confirmed `h64` collisions `864336f`) via `ladder_failed` in `ClientAction::ResolveRoots` so the caller performs bounded ID fallback scoped strictly to that node's prefix.
3. **MSC4511 Causal Merkle Trie & v2 Leaf-Compressed Design (`src/merkle.rs`, `docs/msc4511_compressed_trie.md`)**:
   - Domain-separated SHA-256 tags `msc4511:<name>:sha256:v1` (`1728c49`) in `src/merkle.rs`.
   - Specification of MSC4511 v2 leaf-compressed Patricia trie (`0616326`, `docs/msc4511_compressed_trie.md`) replacing 256-deep single-key chains with `Empty` (depth-free), `Leaf(key)`, and `Branch(depth d, left, right)` with checked `u64` count addition, `count(Branch) >= 2`, and 3 proof terminals (`Member`, `Non-member Empty`, `Non-member ForeignLeaf`).
4. **In-Tree `u32` Bitmap Engine (`rezzy-recon/src/bitmap/`)**:
   - Replaces external `roaring` crate (`04dc560`, `045c52f`) with an in-tree `Bitmap` / `Bitmap64` / `Bitmap128` implementation featuring branch-free array intersections, in-place chunk unions, versioned wire codec, and dense linear-oracle tests (`13d13dc`).

## 3. Architectural Decisions & Rejected Alternatives

1. **Rejected Alternative — Widening $\text{GF}(2^{64}) \to \text{GF}(2^{128})$ (`eeb0b90`, `docs/gf128_widening_analysis.md`)**:
   - *Decision*: Retained $\text{GF}(2^{64})$ field arithmetic and rejected widening to $\text{GF}(2^{128})$.
   - *Rationale*:
     - **CPU DoS Multiplier ($4\text{--}7\times$)**: Root finding in `pinsketch.rs` scales as `FIELD_BITS^2 * d` (`frobenius_basis_cost(d) = (F-1)*d^2`, `FACTOR_TRIALS = 8 + F`). Widening $F$ from 64 to 128 increases `single_call_work_ceiling(8)` by $3.43\times$ (wall-clock $\sim 6.85\times$), `single_call_work_ceiling(32)` by $2.89\times$ (wall-clock $\sim 5.77\times$), and `single_call_work_ceiling(256)` to $21,757,952$ units (exceeding `MAX_FACTOR_WORK = 16,000,000`).
     - **Memory & Wire Doubling**: Doubles `ResidentKernel` (2 KiB $\to$ 4 KiB), per-round aggregate sketches (42.7 KiB $\to$ 85.3 KiB), and grows 10M-event `SortedPopulation` from 240 MB to 320 MB (+33%).
     - **Oracle Loss**: Breaks `libminisketch` compatibility (`minisketch_bits_supported` caps at 64 bits).
2. **Rejected Alternative — Session Salts or DAG-Derived Structural Epochs for `h64` (`f940966`, `1ced0da`, `docs/2026-10-12-h64-prefix-grinding.md`)**:
   - *Decision*: Rejected per-session salts, static room keys, and structurally-derived DAG epoch keys in favor of the deterministic local no-amplification retry policy (`553841b`).
   - *Rationale*:
     - Per-session salts break the shared incremental `ResidentKernel`.
     - DAG-derived structural epochs are **plausibly impossible**: (1) the event author chooses `prev_events` and can attach to an old checkpoint with a known key; (2) forcing events onto the "current" checkpoint requires consensus finality that Matrix's eventually-consistent DAG lacks; and (3) a peer missing a remote event cannot know its DAG position to compute a position-dependent `h64` key.
3. **Rejected Alternative — MSC4511 Full Patricia Extension Nodes (`0616326`, `docs/msc4511_compressed_trie.md`)**:
   - *Decision*: Selected Option A (leaf compression only) over Option B (full Patricia with extension nodes).
   - *Rationale*: Because event IDs are cryptographic hashes, residual one-empty-child branch chains above a split are short and bounded by attacker hash work ($2^k$), avoiding a 4th node type and skipped-bit length commitments.

## 4. Non-Functional & Public-Safety Invariants

Cross-referencing [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Rows 1, 6, 11):

1. **High (Liveness / DoS) — Subtree Starvation & 128-Slot Queue Saturation (`docs/2026-10-12-h64-prefix-grinding.md`)**:
   - While the 7-bit fan-out and capacity-256 overflow retry eliminate responder bandwidth amplification, an attacker who grinds deep prefixes across multiple subtrees can saturate `MAX_BUCKETS_PER_ROUND = 128` across `MAX_RECONCILIATION_ROUNDS = 20`, delaying convergence of legitimate prefixes in the `pending_splits` queue and forcing terminal `ladder_failed` ID fallback.
2. **Moderate (Algebraic Floor) — $2^{32}$ Birthday Bound & $\sim 2^{37}$ XOR Residual Forgery (`docs/gf128_widening_analysis.md`)**:
   - Unkeyed 64-bit `h64` keys have a $2^{32}$ offline birthday collision cost, and the 128-bit XOR accumulator (`RoomAccumulator`) has an estimated $\sim 2^{37}$ generalized birthday (Wagner $k$-list) forgery floor when combined with colliding `h64` pairs. Mitigated by two-phase `h128` verification (`verify_follow_up`), which catches accidental collisions and confines an attacker to hiding only their own withheld events.
3. **Moderate (Crypto Agility) — MSC4511 Hash Negotiation & Count Overflow (`docs/msc4511_compressed_trie.md`)**:
   - MSC4511 v1 uses `saturating_add` on counts and `u32` varints in compressed paths; MSC4511 v2 mandates checked `u64` addition and explicit version tags (`msc4511:causal-v2:*` for SHA-256 vs. `causal-v3` for BLAKE3) to prevent count-saturation collisions and cross-algorithm proof confusion.

## 5. Acceptance Criteria & Verification Oracles

1. **PinSketch Cost-Model & `libminisketch` Wire Oracles (`rezzy-recon/src/pinsketch.rs`, `tests/unit/test_reconcile_algebraic.rs`)**:
   - Pinned work-unit ceilings (`single_call_work_ceiling(8) == 45_568`, `ceiling(32) == 286_720`, `ceiling(256) == 10_092_544`, degenerate chain `916_609_400`) and `sketch_wire_format_matches_libminisketch_64_bit_serialization`.
2. **Adversarial Grinding, Overflow Wire Decode & Wide-Split Consistency Oracles (`tests/unit/test_reconcile_e2e.rs`, `rezzy-recon/src/client.rs`)**:
   - E2E tests verify capacity-256 overflow bucket wire round-trips (`fd18689`, `4fe8705`), split-pair collisions passing Phase 1 and failing Phase 2 (`497c5a4`), and multi-round wide-split descendant summary consistency (`491bd9e`).
3. **Bitmap & Cuckoo / Merkle Oracles (`rezzy-recon/src/bitmap/mod.rs`, `tests/unit/test_causal.rs`, `tests/unit/test_merkle.rs`)**:
   - Dense bitmap set operations verified against a linear oracle (`13d13dc`), mined 42-cycle Cuckoo verification with 29-bit node index masking (`f9414ce`, `727333b`), and `msc4511:*:sha256:v1` vector pins (`1728c49`).
