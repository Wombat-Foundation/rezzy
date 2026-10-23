# Specification: MSC4500 Homomorphic LtHash Cryptography, BLAKE3 XOF & AES-CTR Profile (`08_lthash_cryptography_20260705`)

## 1. Overview & Historical Context

Between **July 3, 2026 and October 15, 2026** (spanning `b28ffbb`, `cd46ba2`, `bd3598c`, `8e6f73c`, `6acedab`, `9f152dc`, `36bc9ba`, and `8dcd1c1`), `rezzy` replaced non-cryptographic FNV-1a/Zobrist state hashing with **MSC4500 homomorphic lattice hashing (`LtHash`)** based on Bellare and Micciancio's 1997 paradigm (*"A New Paradigm for Collision-Free Hashing: Incrementality at Reduced Cost"*) and Meta's `folly::crypto::LtHash`.

### Why This Track Was Built
1. **Cryptographic Collision Resistance for State Checkpointing (`b28ffbb`, `41a34cf`, `cd46ba2`, `bd3598c`)**: Early state delta chains (`src/state/delta.rs`) used 64-bit FNV-1a/Zobrist XOR hashes to detect identical state snapshots across DAG forks. In federated Matrix rooms where untrusted servers control `state_key` and content strings, a 64-bit XOR hash is trivially forgeable via birthday collisions or Gaussian elimination ($GF(2)$ linearity). `LtHash` provides $O(1)$ incremental insert/remove/replace updates over $\mathbb{Z}_{2^{16}}^{1024}$ (1024 lanes of 16-bit wrapping integers = 2048 bytes) backed by the hardness of the Shortest Vector Problem (SVP) in lattices (~200-bit collision resistance).
2. **Zero-Allocation Seed Framing & Identical-Fork Fast Path (`91522e0`, `767c876`, `8e6f73c`, `efc06d7`)**: To ensure `LtHash` could run on every state transition without heap allocations, `rezzy` introduced `HashWriter` (`core::fmt::Write`) streaming directly into the XOF state and integrated `resolve_merge_fast_path_hashed` (`src/state/at.rs`) to short-circuit multi-parent merges when all parent forks share an identical state accumulator.
3. **Cryptographic Migration to SIMD `BLAKE3` XOF & `AES-256-CTR` Interoperability (`6acedab`, `9f152dc`, `daa37f0`, `72779f5`, `36bc9ba`, `8dcd1c1`)**: The initial `MSC4500` draft used `SHAKE256` for 2048-byte expansion and `BLAKE2b-256` for digest collapse. In October 2026 (`6acedab`, `9f152dc`), `rezzy` unified both expansion and collapse onto `BLAKE3` (XOF mode for lane expansion and 256-bit hash for collapse), split the generic accumulator into `src/incremental/lthash/` vs. Matrix-specific adapters in `src/state/lthash.rs` (`d5cc8a3`, `72779f5`), and added cross-implementation test vectors and benchmarks for the sibling `gomatrixcrypto` `AES-256-CTR` profile (`9cc147b`, `36bc9ba`, `8dcd1c1`).

---

## 2. Functional Requirements & Matrix Spec/MSC Mapping

### FR-08.1: `LtLattice<const LANES: usize>` & `MSC4500` Homomorphic Accumulator (`src/incremental/lthash/`)
- Implement `LtLattice<const LANES: usize>([u16; LANES])` with default alias `pub type LtHash = LtLattice<1024>` (2048 bytes, 1024 little-endian `u16` lanes).
- Support homomorphic $O(1)$ set updates:
  - `insert(event_type, state_key, event_id)`: $\text{acc}[i] \gets (\text{acc}[i] + \text{seed}[i]) \bmod 2^{16}$.
  - `remove(event_type, state_key, event_id)`: $\text{acc}[i] \gets (\text{acc}[i] - \text{seed}[i]) \bmod 2^{16}$.
  - `replace(event_type, state_key, old_id, new_id)` and `replace_checked`: subtract old seed and add new seed in 8-lane auto-vectorized chunks (`add_lattice`, `sub_lattice`).
- Enforce canonical MSC4500 §1 length-prefixed framing in `seed_lattice`:
  $$\text{input} = \text{DST} \mathbin{\|} \text{u16\_le}(\text{len}(\text{type})) \mathbin{\|} \text{type} \mathbin{\|} \text{u16\_le}(\text{len}(\text{state\_key})) \mathbin{\|} \text{state\_key} \mathbin{\|} \text{event\_id}$$
  truncating oversized malformed strings safely on UTF-8 char boundaries at `u16::MAX` (65,535 bytes) via `truncate_to_u16_limit`.

### FR-08.2: Zero-Allocation `BLAKE3` XOF Expansion & Digest Collapse (`src/incremental/lthash/encoding.rs`)
- Expand each framed element under domain separation tag `b"msc4500:lthash16:blake3:v1"` into $2 \times \text{LANES}$ bytes using `blake3::Hasher::finalize_xof()`, unpacking in fixed 256-byte (128-lane) stack scratch windows (`expand_lanes`) with zero heap allocations.
- Stream `event_id: &(impl core::fmt::Display + ?Sized)` directly into `blake3::Hasher` via `HashWriter` (`907287a`, `767c876`).
- Collapse the 2048-byte lattice into a 32-byte wire digest (`lattice_digest`) via `BLAKE3` over the little-endian byte representation of all 1024 `u16` lanes, encoded on the wire as unpadded `base64url`.

### FR-08.3: `MSC4500` State Adapters: `RedactionOverlay`, `ResolutionInputs` & `PduLtHash` (`src/state/lthash.rs`)
- Extract `LtHash` out of `src/state/delta.rs` into `src/state/lthash.rs` (`cd46ba2`), and subsequently split domain-independent lattice math into `src/incremental/lthash/` (`d5cc8a3`, `72779f5`, `8616b66`).
- Implement `RedactionOverlay` (`DST = b"msc4500:redactions:blake3:v1"`) to track authorized causal redactions applied to selected state events separately from the primary state accumulator.
- Implement `ResolutionInputs` (`daa37f0`, `7d2653a`, `f463203`) and `PduLtHash` / `StateDigest` to commit to the full tuple of state resolution inputs and cross-implementation MSC4500 test vectors.

### FR-08.4: `gomatrixcrypto` `AES-256-CTR` Profile Interoperability (`benches/aesctr_crosscheck.rs`, `docs/gf128_widening_analysis.md`)
- Implement `expand_aes_ctr` (both portable and hardware `AES-NI` paths) in `benches/math/expansion_backends.rs` (`9cc147b`) and cross-check against `gomatrixcrypto`'s `lthash.TestAESCTRVector` (`L5WCOKR7yn1u44_LVhGVrttjSxq5gLCbwWUCs0eq1iQ`) in `benches/aesctr_crosscheck.rs` (`36bc9ba`).
- Document the `gomatrixcrypto` `AES-256-CTR` `LtHash` profile in `docs/gf128_widening_analysis.md` (`8dcd1c1`), clarifying that `rezzy-recon` retains `h128` for PinSketch residual binding while `AES-256-CTR` is available for cross-language `LtHash` benchmarking and interoperability.

---

## 3. Architectural Decisions & Rejected Alternatives

1. **Standard Lattice Collapse vs. Baking Cardinality $N$ into the Collapse Digest (`a6d9580` vs. `3f7383f`)**:
   - *Experiment (`a6d9580`)*: Briefly bound the state cardinality $N$ into the collapse digest per an early reading of MSC4500 §6.
   - *Reversal (`3f7383f`)*: Reverted back to standard pure-lattice collapse (`BLAKE3(LE_bytes(lanes))`) without an $N$-cardinality term baked in, preserving clean homomorphic composition where the digest is strictly a function of the lattice state vector.
2. **Streamlined Zero-Allocation Seed Generation for Arbitrary Event IDs (`91522e0` vs. `767c876`)**:
   - *Experiment (`91522e0`)*: Enforced strict event ID format validation inside `LtHash::seed`.
   - *Pivot (`767c876`)*: Removed syntactic Event ID validation from `LtHash::seed` so custom/integer/legacy event IDs (`impl Display + ?Sized`) hash at zero-allocation speed, documenting that syntactic Event ID validation belongs at the application ingestion boundary.
3. **LtHash Fast Path A (Accepted) vs. Fast Path B (Rejected) (`docs/perf_audits.md`, lines 315–338)**:
   - *Path A (Accepted)*: `resolve_merge_fast_path_hashed` (`src/state/at.rs`) uses `hash == hash` as an $O(1)$ negative filter and `Arc::ptr_eq || ==` as final authority when all parent forks have identical state, maintaining `hash == LtHash(state)` incrementally.
   - *Path B (Rejected)*: Skipping topological sort / iterative auth when two forks "share the same power-level/auth roots" or "differ only on non-power keys" via partial `LtHash` digests was **explicitly rejected**. As documented in `docs/perf_audits.md`, identical power roots do not imply non-interference, and non-power winners depend on `(mainline_pos, origin_server_ts, event_id)` plus iterative auth (where a sender may be banned/demoted mid-phase). Skipping resolution via partial digests is the exact same class of soundness bug as the retired CDO pre-filter.
4. **Migration from `SHAKE256`+`BLAKE2b` to Unified `BLAKE3` XOF (`6acedab`, `9f152dc`, `40416d4`)**:
   - *Decision*: Replaced `sha3` (`SHAKE256`) and `blake2` (`BLAKE2b`) with `blake3` for both 2048-byte XOF expansion and 32-byte digest collapse.
   - *Rationale*: Benchmark sweeps (`40416d4`, `benches/math/lthash_backends.rs`) proved `BLAKE3`+`BLAKE3` with SIMD instruction sets is significantly faster and eliminates two cryptographic crate dependencies (`sha3`, `blake2`).

---

## 4. Non-Functional & Public-Safety Invariants

Cross-referencing [`../../audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md):

- **Public-Safety Audit Finding #8 (`docs/homeserver_utilities.md` — High: Missing Ingestion Validation Guards)**:
  - Because `LtLattice::seed` (`src/incremental/lthash/lattice.rs:77-84`) explicitly omits syntactic validation of `event_id` for performance and truncates `event_type`/`state_key` at `u16::MAX` (`truncate_to_u16_limit`), callers that feed unvalidated network PDUs directly into state accumulators without pre-auth validation (`src/auth/validate.rs`, still unimplemented per Audit #8) risk accumulating malformed state keys.
- **Public-Safety Audit Finding #6 (`docs/gf128_widening_analysis.md` — Moderate: Algebraic & Cryptographic Profile Separation)**:
  - Federation peers must never mix incompatible `LtHash` domain separation tags (`msc4500:lthash16:blake3:v1` vs. legacy `_v1` or `AES-256-CTR` profiles) when verifying state snapshots or MSC4500 resolution-input commitments.
  - In `resolve_merge_fast_path_hashed`, `LtHash` equality is used only as a fast negative filter ahead of structural `ptr_eq || ==` verification, ensuring that even a hypothetical accumulator collision cannot cause a silent state-resolution divergence between emergency dispatch homeservers.

---

## 5. Acceptance Criteria & Verification Oracles

1. **Algebraic Homomorphism, Commutativity & Cancellation Oracles (`src/incremental/lthash/tests.rs`, `src/state/lthash.rs`, `71c596d`)**:
   - Verify commutativity ($H(\{a, b\}) = H(\{b, a\})$), associativity, exact inverse cancellation ($H + \text{seed}(x) - \text{seed}(x) = H$), `replace` equivalence, and 65,535-byte UTF-8 boundary truncation (`truncate_to_u16_limit`).
2. **MSC4500 Resolution-Input & Wire Vector Oracles (`src/state/lthash.rs`, `7d2653a`, `f463203`)**:
   - Verify pinned cross-implementation `MSC4500` state accumulator, `RedactionOverlay`, and `ResolutionInputs` test vectors match byte-for-byte.
3. **Differential Identical-Fork Fast Path Oracle (`tests/unit/test_state_at.rs`, `efc06d7`)**:
   - `test_fast_path_differential_matches_full_resolution_on_identical_forks` verifies `resolve_merge_fast_path_hashed` matches full uncached resolution across multi-fork topologies and detects zero accumulator drift against `LtLattice::from_state`.
4. **`gomatrixcrypto` AES-256-CTR Cross-Check Oracle (`benches/aesctr_crosscheck.rs`, `36bc9ba`)**:
   - `aesctr_digest_matches_gomatrixcrypto_pin` and `aesctr_ni_matches_portable` verify that both portable and `AES-NI` hardware paths produce `"L5WCOKR7yn1u44_LVhGVrttjSxq5gLCbwWUCs0eq1iQ"`.
