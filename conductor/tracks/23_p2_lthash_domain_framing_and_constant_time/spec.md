# Specification: Track 23 — P2 Remediation: `LtHash` Custom DST Length-Prefix Framing, `AES-256-CTR` Profile, Stack Reduction & Constant-Time Equality

- **Track ID**: `23_p2_lthash_domain_framing_and_constant_time`
- **Priority**: `P2`
- **Originating Track**: `08_lthash_cryptography_20260705`
- **Remediated Findings**: `F-08-04`, `F-08-05`, `F-08-06`, `F-08-07`, `F-08-08`

---

## 1. Overview & Finding Traceability Matrix

This track remediates the five P2 cryptographic domain-framing, cross-implementation profile, stack footprint, and constant-time comparison findings identified in the Track 08 review (`F-08-04`, `F-08-05`, `F-08-06`, `F-08-07`, and `F-08-08`).

| Finding ID | Severity | Persona(s) | Source File / Line Range | Root Cause & Impact |
| :--- | :---: | :--- | :--- | :--- |
| **`F-08-04`** | `[Medium]` | `critic-formal-crypto` | [`src/incremental/lthash/encoding.rs:67-101`](../../../src/incremental/lthash/encoding.rs#L67-L101), [`src/state/lthash.rs:246-254`](../../../src/state/lthash.rs#L246-L254) | Ambiguous framing for custom `dst` tags in `LtLattice::seed_with_dst`, `seed_bytes_lattice`, and `PduLtHash::new(dst)`: `dst` is concatenated directly before `u16_le(type_len)` or raw `bytes` without a length prefix or separator, allowing canonical domain collisions if caller-supplied `dst` strings are not prefix-free. |
| **`F-08-05`** | `[Medium]` | `critic-federation-interop`, `critic-compliance` | [`src/incremental/lthash/lattice.rs:68`](../../../src/incremental/lthash/lattice.rs#L68), [`benches/aesctr_crosscheck.rs:16`](../../../benches/aesctr_crosscheck.rs#L16) | Production `LtLattice` hardcodes `msc4500:lthash16:blake3:v1` (`BLAKE3` XOF), whereas `gomatrixcrypto` / Go homeservers use `msc4500:lthash16:aes-ctr:v1` (`SHA-256` + `AES-256-CTR`), which only exists in `benches/aesctr_crosscheck.rs` without a Cargo feature or runtime profile selector in `rezzy`. |
| **`F-08-06`** | `[Medium]` | `critic-perf`, `critic-eng-lead` | [`src/state/lthash.rs:297-319`](../../../src/state/lthash.rs#L297-L319), [`src/incremental/lthash/lattice.rs:34`](../../../src/incremental/lthash/lattice.rs#L34) | `PduLtHash` embeds four inline `LtHash` instances ($4 \times 2,048\text{ B} = 8,192\text{ B}$ on the stack), and `PduLtHash::checksum()` clones three 2 KiB lattices by value on the stack (`6,144` bytes copied) instead of accumulating in-place via `+=` (`AddAssign<&LtLattice>`). |
| **`F-08-07`** | `[Low]` | `critic-formal-crypto`, `critic-eng-lead` | [`benches/aesctr_crosscheck.rs:20-29`](../../../benches/aesctr_crosscheck.rs#L20-L29) | `frame_element` in `benches/aesctr_crosscheck.rs` casts `(event_type.len() as u16).to_le_bytes()` and `(state_key.len() as u16).to_le_bytes()` without checking or slicing inputs to `u16::MAX`, causing silent `u16` wrap-around if tested with inputs $> 65,535$ bytes. |
| **`F-08-08`** | `[Low]` | `critic-dx-integrator`, `critic-perf` | [`src/incremental/lthash/lattice.rs:335-343`](../../../src/incremental/lthash/lattice.rs#L335-L343), [`src/state/at.rs:2704-2706`](../../../src/state/at.rs#L2704-L2706) | `LtLattice::PartialEq` (`[u16; 1024]`) and `StateDigest::PartialEq` (`[u8; 32]`) use standard non-constant-time slice comparison instead of constant-time equality (`subtle::ConstantTimeEq` or constant-time word XOR-accumulation), and `resolve_merge_fast_path_hashed_with_cache` checks `first.hash == state.hash` (`2,048` B) before `first.state.ptr_eq(&state.state)` ($O(1)$ pointer check). |

---

## 2. Functional & Architectural Remediation Requirements

### 2.1 Unambiguous Domain-Separation Framing for Custom `dst` Tags (`F-08-04`)
1. In [`src/incremental/lthash/encoding.rs:67-101`](../../../src/incremental/lthash/encoding.rs#L67-L101) and [`src/state/lthash.rs:246-254`](../../../src/state/lthash.rs#L246-L254):
   - Preserve exact byte-for-byte wire compatibility for the built-in MSC4500 v1 domain tags (`msc4500:lthash16:blake3:v1`, `msc4500:redactions:blake3:v1`, `msc4500:resolution_inputs:blake3:v1`).
   - For custom caller-supplied `dst` tags in `seed_with_dst`, `seed_bytes_lattice`, and `PduLtHash::new(dst)`, enforce unambiguous injective framing by prefixing custom `dst` with `u16_le(dst.len()) || dst || 0x00` (or using `blake3::Hasher::new_derive_key` / rejecting non-canonical custom `dst` strings containing NUL or exceeding `u16::MAX`), so that no two distinct `(dst, payload)` pairs can ever produce identical input byte streams.

### 2.2 First-Class `AES-256-CTR` (`msc4500:lthash16:aes-ctr:v1`) Profile & Safe Frame Helper (`F-08-05`, `F-08-07`)
1. Promote the `msc4500:lthash16:aes-ctr:v1` (`SHA-256` seed + `AES-256-CTR` XOF expansion) profile from `benches/aesctr_crosscheck.rs` into a first-class library profile (`LtHashProfile::Blake3V1` vs. `LtHashProfile::AesCtrV1`, gated behind an optional Cargo feature `lthash-aes-ctr` so default builds remain dependency-lean and free of portable AES T-table timing side-channels on `wasm32`) (`F-08-05`).
2. Replace the ad-hoc `frame_element` in [`benches/aesctr_crosscheck.rs:20-29`](../../../benches/aesctr_crosscheck.rs#L20-L29) with the shared, bounds-checked framing function from `src/incremental/lthash/encoding.rs`, eliminating the unchecked `as u16` length cast (`F-08-07`) while keeping the `gomatrixcrypto` test vector (`L5WCOKR7yn1u44_LVhGVrttjSxq5gLCbwWUCs0eq1iQ`) passing in both unit tests and benchmarks.

### 2.3 In-Place `PduLtHash::checksum()` Accumulation & Stack Footprint Reduction (`F-08-06`)
1. Implement `core::ops::AddAssign<&LtLattice<LANES>>` and `core::ops::SubAssign<&LtLattice<LANES>>` on [`LtLattice`](../../../src/incremental/lthash/lattice.rs#L34) and `LtHash`.
2. Rewrite [`PduLtHash::checksum(&self)`](../../../src/state/lthash.rs#L297-L319) to clone `self.state_events` once into a single `mut combined` accumulator and add `&self.timeline_events`, `self.redactions.as_lthash()`, and `self.resolution_inputs.as_lthash()` in-place via `+=`, eliminating 6,144 bytes of redundant stack copies per checksum call.
3. Provide `PduLtHash::boxed()` / heap-allocated bucket storage or document stack usage clearly for constrained `#![no_std]` call stacks.

### 2.4 Constant-Time Equality & Fast-Path Pointer Check Ordering (`F-08-08`)
1. Update [`LtLattice::PartialEq`](../../../src/incremental/lthash/lattice.rs#L335-L343) and [`StateDigest::PartialEq`](../../../src/state/lthash.rs#L337-L376) to use constant-time comparison (via `subtle::ConstantTimeEq` or volatile/black-boxed bitwise XOR-fold across all 1,024 `u16` lanes / 32 `u8` digest bytes) so digest and lattice verification over federation cannot leak prefix match lengths via timing side-channels.
2. In [`resolve_merge_fast_path_hashed_with_cache`](../../../src/state/at.rs#L2704-L2706), reorder the predicate to check `first.state.ptr_eq(&state.state)` **before** comparing the 2,048-byte `first.hash == state.hash`.

---

## 3. Public-Safety & Consensus Invariants

- **Domain Separation Injectivity (`F-08-04`, `F-08-07`)**: For any two distinct tuples $(\text{dst}_1, \text{type}_1, \text{key}_1, \text{id}_1) \neq (\text{dst}_2, \text{type}_2, \text{key}_2, \text{id}_2)$ within valid Matrix PDU length bounds, the framed XOF seed input MUST be strictly distinct.
- **Cross-Implementation Golden Vector Parity (`F-08-05`)**: Both `Blake3V1` (`msc4500:lthash16:blake3:v1`) and `AesCtrV1` (`msc4500:lthash16:aes-ctr:v1`) MUST reproduce their respective pinned golden digests (`L5WCOKR7yn1u44_LVhGVrttjSxq5gLCbwWUCs0eq1iQ` for `gomatrixcrypto` `aes-ctr:v1`).
- **Constant-Time Verification (`F-08-08`)**: Comparing two `StateDigest` or `LtLattice` values MUST execute in data-independent constant time regardless of the index of the first differing byte/lane.

---

## 4. Acceptance Criteria & Verification Oracles

- [ ] **`F-08-04` Verified**: Unit tests prove that caller-supplied custom `dst` strings with shared prefixes (e.g., `dst = b"app"` + `bytes = b":v1:payload"` vs. `dst = b"app:v1"` + `bytes = b":payload"`) produce distinct `LtLattice` states in `seed_with_dst`, `seed_bytes_lattice`, and `PduLtHash::new`.
- [ ] **`F-08-05` & `F-08-07` Verified**: The `msc4500:lthash16:aes-ctr:v1` profile is selectable in library code (`src/incremental/lthash/`) and `benches/aesctr_crosscheck.rs:20-29` delegates to bounds-checked framing without raw `as u16` truncation.
- [ ] **`F-08-06` Verified**: `PduLtHash::checksum()` (`src/state/lthash.rs:297-319`) uses `+=` by reference (`AddAssign<&LtHash>`), reducing temporary stack clones from 4 lattices (8 KiB) to 1 lattice (2 KiB) while producing identical 32-byte checksums.
- [ ] **`F-08-08` Verified**: `LtLattice::PartialEq` (`src/incremental/lthash/lattice.rs:335-343`) and `StateDigest::PartialEq` execute constant-time comparisons, and `resolve_merge_fast_path_hashed_with_cache` (`src/state/at.rs:2704-2706`) short-circuits on `first.state.ptr_eq(&state.state)` before comparing `first.hash == state.hash`.
