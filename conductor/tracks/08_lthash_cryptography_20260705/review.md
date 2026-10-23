# Track 08 Review & 8-Persona Critique: MSC4500 Homomorphic LtHash Cryptography, BLAKE3 XOF & AES-CTR Profile

- **Track ID**: `08_lthash_cryptography_20260705`
- **Commit Range**: `b28ffbb..8dcd1c1` (`2026-07-05` – `2026-08-31`)
- **Review Date**: `2026-10-23`
- **Status**: Completed (Reverse-Engineered Historical Track — Audited for Stage B Remediation)

---

## 1. Conductor Review Summary (`/conductor-review`)

### 1.1 Plan & Spec Compliance Verification
| Phase / Task | Commit(s) | Verification Status | Notes |
| :--- | :--- | :--- | :--- |
| **Phase 1: Core `LtLattice<1024>` & BLAKE3 XOF Framing** | `b28ffbb`, `7233f47`, `b60fa0d`, `bb9c54f`, `7f19c97` | ⚠️ **Implemented with Framing & Truncation Hazards** | `LtLattice<LANES>` ([src/incremental/lthash/lattice.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/lattice.rs#L34-L355)) and `encoding.rs` ([src/incremental/lthash/encoding.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/encoding.rs#L17-L177)) implement $\mathbb{Z}_{2^{16}}^{1024}$ homomorphic updates, but silently truncate strings $> 65,535$ bytes (`truncate_to_u16_limit`) and omit length prefixes on `dst` and `event_id`. |
| **Phase 2: Four-Bucket `PduLtHash`, `StateDigest`, & `HashedState`** | `7233f47`, `7f19c97` | ⚠️ **Implemented with Multiset / Empty-Slice Risks** | `PduLtHash`, `RedactionOverlay`, `ResolutionInputs`, and `StateDigest` ([src/state/lthash.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L42-L376)) work as designed, but `RedactionOverlay::insert` and `ResolutionInputs::insert` lack duplicate-insertion guards, and `resolve_merge_fast_path_hashed_with_cache` panics on empty `prev_states`. |
| **Phase 3: Cross-Implementation AES-CTR Profile & Backend Benchmarks** | `7b6166d`, `2cbbf74`, `8dcd1c1` | ✅ **Verified Against `gomatrixcrypto`** | `benches/aesctr_crosscheck.rs` ([benches/aesctr_crosscheck.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/benches/aesctr_crosscheck.rs#L1-L98)) reproduces `L5WCOKR7yn1u44_LVhGVrttjSxq5gLCbwWUCs0eq1iQ` byte-for-byte, and `benches/math/expansion_backends.rs` documents portable AES T-table timing side-channels. |

### 1.2 Executive Findings Matrix
| ID | Severity | Persona | Location | Summary |
| :--- | :--- | :--- | :--- | :--- |
| **F-08-01** | `[High]` | `critic-formal-crypto` / `critic-redteam-qa` | [src/incremental/lthash/encoding.rs:21-33](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/encoding.rs#L21-L33), [src/state/lthash.rs:147-169](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L147-L169) | `truncate_to_u16_limit` silently truncates `event_type`, `state_key`, and `event_id` inputs $> 65,535$ bytes (`u16::MAX`), allowing deterministic canonical collision of distinct long inputs sharing a 64 KiB prefix. |
| **F-08-02** | `[High]` | `critic-formal-crypto` / `critic-compliance` | [src/incremental/lthash/lattice.rs:149-205](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/lattice.rs#L149-L205), [src/state/lthash.rs:79-89, 196-198](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L79-L89) | **Multiset vs. Set Homomorphism**: $\mathbb{Z}_{2^{16}}^{1024}$ addition is NOT idempotent ($x + x = 2x \neq x$, and $2^{16} \cdot x \equiv 0 \bmod 2^{16}$). Unlike `HashedState::insert`, `RedactionOverlay::insert` and `ResolutionInputs::insert` do not track membership, so replaying a redaction or resolution input corrupts the bucket accumulator! |
| **F-08-03** | `[High]` | `critic-redteam-qa` / `critic-eng-lead` | [src/state/at.rs:2686-2706](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L2686-L2706) | `resolve_merge_fast_path_hashed_with_cache` indexes `&prev_states[0]` unconditionally (`L2697`), panicking on empty `prev_states` (whereas `resolve_merged_parent_states` at `L1520` returns an empty `SharedState::new()`). |
| **F-08-04** | `[Medium]` | `critic-formal-crypto` | [src/incremental/lthash/encoding.rs:67-101](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/encoding.rs#L67-L101), [src/state/lthash.rs:246-254](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L246-L254) | Ambiguous framing for custom `dst` tags (`seed_with_dst` / `PduLtHash::new(dst)`): `dst` has no length prefix or separator before `u16_le(type_len)` (or before `bytes` in `seed_bytes_lattice`), allowing domain collisions if caller-supplied `dst` strings vary in length. |
| **F-08-05** | `[Medium]` | `critic-federation-interop` / `critic-compliance` | [src/incremental/lthash/lattice.rs:68](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/lattice.rs#L68), [benches/aesctr_crosscheck.rs:16](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/benches/aesctr_crosscheck.rs#L16) | Production `LtLattice` hardcodes `msc4500:lthash16:blake3:v1` (`BLAKE3` XOF), while the `gomatrixcrypto` interop vector uses `msc4500:lthash16:aes-ctr:v1` (`SHA-256` + `AES-256-CTR`), which only exists in `benches/aesctr_crosscheck.rs` (`dev-dependencies`). |
| **F-08-06** | `[Medium]` | `critic-perf` / `critic-eng-lead` | [src/state/lthash.rs:297-319](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L297-L319), [src/incremental/lthash/lattice.rs:34](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/lattice.rs#L34) | `PduLtHash` stores four inline `LtHash` instances ($4 \times 2,048\text{ B} = 8,192\text{ B}$ on the stack), and `PduLtHash::checksum()` clones three 2 KiB lattices by value on the stack (`6 KiB` copy) before calling `.digest()`. |
| **F-08-07** | `[Low]` | `critic-formal-crypto` / `critic-eng-lead` | [benches/aesctr_crosscheck.rs:20-29](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/benches/aesctr_crosscheck.rs#L20-L29) | `frame_element` in `benches/aesctr_crosscheck.rs` casts `(event_type.len() as u16).to_le_bytes()` without slicing `event_type`, causing silent `u16` length-prefix wrap-around if tested with inputs $> 65,535$ bytes. |
| **F-08-08** | `[Low]` | `critic-dx-integrator` | [src/incremental/lthash/lattice.rs:335-343](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/lattice.rs#L335-L343), [src/state/at.rs:2704-2706](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L2704-L2706) | `LtLattice::PartialEq` (2,048-byte slice equality) and `StateDigest::PartialEq` (`[u8; 32]` equality) use non-constant-time standard slice comparisons; furthermore, `resolve_merge_fast_path_hashed_with_cache` compares full `2,048`-byte `first.hash == state.hash` yet still immediately verifies `first.state == state.state`. |

---

## 2. Multi-Perspective Critique (8 Specialized Personas)

### 2.1 `critic-pm` (Product Manager — Roadmap, Scope & Public Narrative Coherence)
- **`[Medium]` Dual Profile Story (`blake3:v1` vs. `aes-ctr:v1`) Needs Clear Positioning**:
  - Track 08 implements `msc4500:lthash16:blake3:v1` in the core library ([src/incremental/lthash/lattice.rs:68](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/lattice.rs#L68)) while relegating `msc4500:lthash16:aes-ctr:v1` (the profile used by `gomatrixcrypto`) to benchmark/test files ([benches/aesctr_crosscheck.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/benches/aesctr_crosscheck.rs)). While the benchmark analysis in [benches/math/expansion_backends.rs:30-45](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/benches/math/expansion_backends.rs#L30-L45) provides a compelling security and performance rationale for choosing BLAKE3 XOF (avoiding portable AES T-table cache-timing side-channels on `wasm32`), downstream integrators testing MSC4500 federation with Go homeservers (`dendrite`/`gomatrixcrypto`) cannot opt into `aes-ctr:v1` via a Cargo feature flag in `rezzy`.

### 2.2 `critic-eng-lead` (Engineering Lead — Architecture, `#![no_std]` Hygiene & Tech Debt)
- **`[High]` Inconsistent Empty-Slice Handling in `resolve_merge_fast_path_hashed_with_cache`**:
  - In [src/state/at.rs:1519-1521](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L1519-L1521), `resolve_merged_parent_states` gracefully handles `if prev_states.is_empty() { return SharedState::new(); }`.
  - Immediately comparable in the same module, `resolve_merge_fast_path_hashed_with_cache` ([src/state/at.rs:2696-2698](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L2696-L2698)) checks `if prev_states.len() == 1` and then unconditionally indexes `let first = &prev_states[0];`, panicking with an index-out-of-bounds crash if `prev_states.is_empty()` (e.g., an `m.room.create` root event with zero parent state snapshots).
- **`[Medium]` Stack Footprint of `PduLtHash` & `checksum()`**:
  - `LtLattice<1024>` is `[u16; 1024]` (`2,048` bytes). `PduLtHash` ([src/state/lthash.rs:226-231](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L226-L231)) embeds four `LtHash` fields inline (`8,192` bytes on the stack). In `PduLtHash::checksum(&self)` ([src/state/lthash.rs:307-313](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L307-L313)):
    ```rust
    pub fn checksum(&self) -> [u8; 32] {
        (self.state_events.clone()
            + self.timeline_events.clone()
            + self.redactions.as_lthash().clone()
            + self.resolution_inputs.as_lthash())
        .digest()
    }
    ```
  - This clones three 2 KiB arrays (`6,144` bytes of unnecessary stack copies) instead of accumulating via `add_Assign` (`+=`) into a single `let mut combined = self.state_events.clone();`.

### 2.3 `critic-compliance` (Matrix Spec & MSC Compliance Auditor)
- **`[High]` MSC4500 Input Length Boundaries & Silent Truncation**:
  - Standard Matrix PDU validation limits full event JSON to `65,535` bytes (`64 KiB`), so valid Matrix `event_type`, `state_key`, and `event_id` strings are strictly $< 65,535$ bytes. However, `truncate_to_u16_limit` ([src/incremental/lthash/encoding.rs:21-33](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/encoding.rs#L21-L33)) and `ResolutionInputRecord::encode` ([src/state/lthash.rs:155-156](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L155-L156): `u32::try_from(sorted.len()).unwrap_or(u32::MAX)`) **silently truncate** inputs that exceed `u16::MAX` (or `u32::MAX`) instead of rejecting them or hashing their full length with a `u32`/`u64` prefix. Furthermore, as documented in [src/incremental/lthash/lattice.rs:79-83](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/lattice.rs#L79-L83), `LtLattice::seed` performs no syntactic validation of `event_id` (`$...`), relying entirely on caller validation (which is unimplemented in `rezzy` per Audit #8).

### 2.4 `critic-perf` (Performance & Memory Hierarchy Engineer)
- **`[Medium]` Redundant Full-Map Comparison on `HashedState` Merge Fast Path**:
  - Examine `resolve_merge_fast_path_hashed_with_cache` ([src/state/at.rs:2700-2706](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L2700-L2706)):
    ```rust
    if prev_states.iter().skip(1).all(|state| {
        first.hash == state.hash && (first.state.ptr_eq(&state.state) || first.state == state.state)
    })
    ```
  - Look at the evaluation order when two parent states have identical content but distinct `Arc` root pointers (`!first.state.ptr_eq(&state.state)`):
    1. First it compares `first.hash == state.hash` (`2,048` bytes of `LtHash`).
    2. If `first.hash == state.hash` is `true`, it STILL walks the entire `PersistentOrdMap` (`first.state == state.state`, $O(N)$ key/value equality)!
    3. Conversely, if `first.state.ptr_eq(&state.state)` is `true` (an $O(1)$ 8-byte pointer check!), it STILL compares `2,048` bytes of `first.hash == state.hash` *before* checking `ptr_eq`!
  - Putting `first.state.ptr_eq(&state.state)` **first** avoids the 2,048-byte `LtHash` comparison in the common case where both parents share the same `PersistentOrdMap` root pointer! And when `ptr_eq` is false, `first.hash != state.hash` acts only as a fast negative filter, while `first.hash == state.hash` still falls back to $O(N)$ `first.state == state.state` (guarding against accidental/adversarial state collisions or un-updated `HashedState`).

### 2.5 `critic-formal-crypto` (Formal Methods & Cryptographic Primitives Auditor)
- **`[High]` Multiset Non-Idempotence & $2^{16}$-Order Torsion in `RedactionOverlay` and `ResolutionInputs`**:
  - Mathematically, $(\mathbb{Z}_{2^{16}}^{1024}, +)$ is an abelian group of exponent $2^{16}$, **not** a boolean semilattice:
    $$\forall x \in \mathbb{Z}_{2^{16}}^{1024}, \quad x + x = 2x \not\equiv x \pmod{2^{16}}, \quad \text{and} \quad \sum_{i=1}^{65536} x \equiv 0 \pmod{2^{16}}.$$
  - Consequently, `LtHash` is a **multiset** homomorphic hash, not a set hash. `HashedState::insert` ([src/state/at.rs:2637-2643](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L2637-L2643)) enforces set semantics by inspecting `self.state.get(&key)` and calling `self.hash.replace(event_type, state_key, old_id, &event_id)`.
  - However, `RedactionOverlay` ([src/state/lthash.rs:79-89](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L79-L89)), `ResolutionInputs` ([src/state/lthash.rs:196-198](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L196-L198)), and `PduLtHash::insert_timeline_event` ([src/state/lthash.rs:277-284](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L277-L284)) maintain **only** the `LtHash` accumulator without an underlying deduplicating set!
  - In Matrix federation, the same redaction event (or duplicate redaction PDUs targeting the same `redacts` event ID) frequently arrives multiple times across federation paths or backfill batches. If an integrator calls `RedactionOverlay::insert` or `ResolutionInputs::insert` twice for the same redacted event, the lattice adds $2 \cdot H(e)$ instead of $H(e)$, permanently diverging `PduLtHash` between homeservers that processed the duplicate redaction PDU once vs. twice!
- **`[High]` Prefix-Collision via `truncate_to_u16_limit` (`encoding.rs:21-33`)**:
  - In `seed_lattice` ([src/incremental/lthash/encoding.rs:67-88](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/encoding.rs#L67-L88)):
    ```rust
    let event_type = truncate_to_u16_limit(event_type);
    let state_key = truncate_to_u16_limit(state_key);
    ```
  - For any two distinct strings $s_1 \neq s_2$ with $|s_1|, |s_2| > 65,535$ that share the same first $65,535$ bytes, `truncate_to_u16_limit(s_1) == truncate_to_u16_limit(s_2)`. Thus `LtHash::seed(et, s_1, id) == LtHash::seed(et, s_2, id)` with probability $1$ (a trivial zero-work collision outside standard PDU size limits).
- **`[Medium]` Unprefixed `dst` in `seed_with_dst` and `seed_bytes_lattice`**:
  - In `seed_lattice` ([src/incremental/lthash/encoding.rs:76-83](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/encoding.rs#L76-L83)), the BLAKE3 input stream is:
    $$\text{dst} \;\|\; \text{u16\_le}(|\text{type}|) \;\|\; \text{type} \;\|\; \text{u16\_le}(|\text{state\_key}|) \;\|\; \text{state\_key} \;\|\; \text{event\_id}$$
  - Because `dst` has no length prefix or NUL terminator (and `seed_bytes_lattice` at `L96-101` hashes $\text{dst} \;\|\; \text{bytes}$ directly), domain separation holds *only* if the set of all `dst` strings used across an application is prefix-free. While the built-in constants (`msc4500:lthash16:blake3:v1`, `msc4500:redactions:blake3:v1`, `msc4500:resolution_inputs:blake3:v1`) are prefix-free, `LtLattice::seed_with_dst` (`pub`) and `PduLtHash::new(dst)` (`pub`) accept arbitrary `&[u8]` domain tags without enforcing prefix-freeness or hashing `u16_le(dst.len()) || dst` (or using `blake3::Hasher::new_derive_key`).

### 2.6 `critic-federation-interop` (Federation & Production Operations Architect)
- **`[Medium]` Cross-Server MSC4500 Digest Reconciliation Requires Explicit Deduplication Contracts**:
  - When two homeservers compare `StateDigest` ([src/state/lthash.rs:337-376](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L337-L376)) or `PduLtHash::checksum()` over federation, `DigestAgreement::Diverged` triggers state reconciliation fallback. Because `ResolutionInputRecord::encode` ([src/state/lthash.rs:147-170](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L147-L170)) hashes `state_predecessors`, two homeservers that represent "no previous state event" differently (e.g. omitting the entry vs. passing `""`) or that do not deduplicate `auth_events` (note `sorted.sort_unstable()` at `L155` sorts **without** calling `sorted.dedup()`!) will compute different `ResolutionInputs` digests for the exact same PDU.

### 2.7 `critic-redteam-qa` (Adversarial Security & QA Red-Teamer)
- **`[High]` Crash via Empty `prev_states` in `resolve_merge_fast_path_hashed_with_cache`**:
  - Passing `&[]` to `resolve_merge_fast_path_hashed_with_cache` ([src/state/at.rs:2686-2698](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L2686-L2698)) immediately panics at `let first = &prev_states[0];` (`L2697`). Any state-at-event pipeline that calls `resolve_merge_fast_path_hashed` uniformly across all room events (including root/initial events with `prev_events = []`) will crash the worker thread.
- **`[Medium]` Wagner's Generalized Birthday Attack Parameters & Modulo $2^{16}$ Wrap-Around**:
  - For a 1,024-lane $\mathbb{Z}_{2^{16}}$ lattice ($16,384$ bits), finding a $k$-sum collision in `LtHash` where the attacker controls full inputs requires Wagner's $k$-tree algorithm (infeasible when seeded via BLAKE3 XOF with $\ge 256$-bit security). However, because each lane operates modulo $2^{16}$, an attacker who can cause an unguarded multiset accumulator (`RedactionOverlay`, `ResolutionInputs`, or raw `LtHash::insert`) to accumulate the *same* event $65,536$ times cancels its contribution to `0` across all 1,024 lanes simultaneously ($65,536 \cdot H(e) \equiv 0 \pmod{2^{16}}$).

### 2.8 `critic-dx-integrator` (Homeserver Integrator & Developer Experience)
- **`[Medium]` Sharp Edges on `LtLattice::insert` vs. `HashedState::insert`**:
  - `LtLattice::insert` ([src/incremental/lthash/lattice.rs:149-155](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/lattice.rs#L149-L155)) is named identically to `BTreeSet::insert` / `HashedState::insert`, leading integrators to assume that inserting an existing key overwrites or is a no-op. In reality, calling `LtLattice::insert` for an existing `(event_type, state_key)` without calling `replace(event_type, state_key, old_id, new_id)` corrupts the state hash! The doc comment should prominently warn that `LtLattice::insert` is strictly for **brand-new keys** not previously present in the state snapshot, and `RedactionOverlay`/`ResolutionInputs` should explicitly document their exact-once call contract.

---

## 3. Concrete Stage B Remediation Recommendations

1. **Guard `resolve_merge_fast_path_hashed_with_cache` Against Empty `prev_states` & Optimize Check Order (`[High]` — F-08-03, F-08-08)**:
   - In [src/state/at.rs:2693-2706](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L2693-L2706), add `if prev_states.is_empty() { return HashedState::new(); }` before `if prev_states.len() == 1`.
   - Reorder the fast-path predicate at `L2704` to check `first.state.ptr_eq(&state.state) || (first.hash == state.hash && first.state == state.state)` so pointer-identical parent states skip the 2,048-byte `LtHash` equality check.
2. **Eliminate Silent Truncation in `encoding.rs` and `ResolutionInputRecord` (`[High]` — F-08-01)**:
   - Either widen length prefixes in `seed_lattice` ([src/incremental/lthash/encoding.rs:67-88](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/incremental/lthash/encoding.rs#L67-L88)) or provide a fallible `try_seed` / debug assertion that rejects strings $> 65,535$ bytes rather than silently truncating via `truncate_to_u16_limit`.
   - In `ResolutionInputRecord::encode` ([src/state/lthash.rs:155](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L155)), add `sorted.dedup()` after `sorted.sort_unstable()` so duplicate `auth_events` or `state_predecessors` entries do not cause cross-server digest divergence.
3. **Document / Enforce Set Semantics on `RedactionOverlay` and `ResolutionInputs` (`[High]` — F-08-02)**:
   - Document prominently on `LtLattice::insert`, `RedactionOverlay::insert`, and `ResolutionInputs::insert` that $\mathbb{Z}_{2^{16}}^{1024}$ addition is non-idempotent (`insert` must be called at most once per unique element, and state key updates must use `replace`).
   - Consider offering a tracked `TrackedRedactionOverlay` (or taking `&mut BTreeSet<Id>` witness) so duplicate federation redactions cannot double-add a seed.
4. **Avoid 6 KiB Stack Clones in `PduLtHash::checksum()` (`[Medium]` — F-08-06)**:
   - In [src/state/lthash.rs:307-313](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/lthash.rs#L307-L313), compute `checksum(&self)` by cloning `self.state_events` once into `mut acc` and applying `acc += &self.timeline_events; acc += self.redactions.as_lthash(); acc += self.resolution_inputs.as_lthash(); acc.digest()`.
