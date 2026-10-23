# Implementation Plan: Track 23 — `LtHash` Custom DST Length-Prefix Framing, `AES-256-CTR` Profile, Stack Reduction & Constant-Time Equality

## Phase 1: Custom `dst` Length-Prefix Framing & `AES-256-CTR` Interop Profile (`F-08-04`, `F-08-05`, `F-08-07`)
- [ ] Task: Enforce injective length-prefixed framing for custom `dst` tags (`F-08-04`, `src/incremental/lthash/encoding.rs:67-101`, `src/state/lthash.rs:246-254`)
  - [ ] Frame custom domain-separation tags in `seed_lattice`, `seed_bytes_lattice` (`src/incremental/lthash/encoding.rs:67-101`), and `PduLtHash::new(dst)` (`src/state/lthash.rs:246-254`) with an explicit length prefix/separator so variable-length `dst` strings cannot collide with payload bytes (`F-08-04`)
  - [ ] Add unit tests verifying domain non-collision across prefix-overlapping custom `dst` values while preserving pinned MSC4500 v1 digests (`F-08-04`)
- [ ] Task: Expose `msc4500:lthash16:aes-ctr:v1` profile in library and remove unchecked `as u16` cast in `benches/aesctr_crosscheck.rs` (`F-08-05`, `F-08-07`, `src/incremental/lthash/lattice.rs:68`, `benches/aesctr_crosscheck.rs:16-29`)
  - [ ] Add optional feature/profile support for `msc4500:lthash16:aes-ctr:v1` (`SHA-256` + `AES-256-CTR`) in `src/incremental/lthash/lattice.rs:68` and `encoding.rs` alongside `msc4500:lthash16:blake3:v1` (`F-08-05`)
  - [ ] Replace unchecked `(event_type.len() as u16).to_le_bytes()` in `frame_element` (`benches/aesctr_crosscheck.rs:20-29`) with the bounds-checked library framing helper and verify the `gomatrixcrypto` golden vector `L5WCOKR7yn1u44_LVhGVrttjSxq5gLCbwWUCs0eq1iQ` (`F-08-05`, `F-08-07`)

## Phase 2: `PduLtHash::checksum()` Stack Reduction & Constant-Time Equality (`F-08-06`, `F-08-08`)
- [ ] Task: Eliminate 6 KiB temporary stack clones in `PduLtHash::checksum()` (`F-08-06`, `src/state/lthash.rs:297-319`, `src/incremental/lthash/lattice.rs:34`)
  - [ ] Implement `AddAssign<&Self>` and `SubAssign<&Self>` for `LtLattice` (`src/incremental/lthash/lattice.rs:34`) and `LtHash` (`F-08-06`)
  - [ ] Refactor `PduLtHash::checksum()` (`src/state/lthash.rs:297-319`) to accumulate `&self.timeline_events`, `self.redactions.as_lthash()`, and `self.resolution_inputs.as_lthash()` in-place via `+=` into a single `LtHash` accumulator (`F-08-06`)
- [ ] Task: Implement constant-time equality for `LtLattice` and `StateDigest` and reorder `HashedState` fast-path pointer check (`F-08-08`, `src/incremental/lthash/lattice.rs:335-343`, `src/state/at.rs:2704-2706`)
  - [ ] Replace standard slice `PartialEq` in `LtLattice` (`src/incremental/lthash/lattice.rs:335-343`) and `StateDigest` (`src/state/lthash.rs:337-376`) with constant-time equality (`subtle::ConstantTimeEq` / bitwise word accumulator) (`F-08-08`)
  - [ ] Reorder `resolve_merge_fast_path_hashed_with_cache` (`src/state/at.rs:2704-2706`) so `first.state.ptr_eq(&state.state)` is evaluated before the 2,048-byte `first.hash == state.hash` comparison (`F-08-08`)
