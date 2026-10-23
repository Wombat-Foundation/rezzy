# Implementation Plan: Track 16 — P0 Mixed-Federation Consensus, Lazy `unconflicted_state` Stop & `LtHash` Guards

## Phase 1: Isolate `V2.1.1` / `V2.2` and Fix Lazy `unconflicted_state` Boundary (`F-05-01`, `F-07-01`)
- [ ] Task: Gate experimental `V2.1.1` / `V2.2` dispatch and fix `resolve_state_maps_lazy_with_diff` (`src/resolve/multi.rs:698-721`)
  - [ ] Fix `resolve_state_maps_lazy_with_diff` fallback BFS (`src/resolve/multi.rs:698-721`) so it stops at `unconflicted_state` ($U$) rather than walking $\text{auth}(C)$ back to `m.room.create` (`F-07-01`)
  - [ ] Replace untrusted wire `ev.depth` heap synchronization in `compute_auth_chain_diff` (`src/state/at.rs:1718-1799`) with topological/BFS set difference (`F-07-03`)
  - [ ] Gate `resolve_semilattice_fold` and `StateResVersion::V2_1_1` / `V2_2` behind explicit experimental room-version checks (`F-05-01`, `F-05-03`)

## Phase 2: Harden `LtHash` Deduplication, Empty `prev_states` Guard & Ed25519 Semantics (`F-08-01`..`F-08-03`)
- [ ] Task: Fix `resolve_merge_fast_path_hashed_with_cache` empty-slice panic and deduplicate `LtHash` multiset inputs
  - [ ] Guard `prev_states.is_empty()` and check $O(1)$ `ptr_eq` before 2 KiB `LtHash` comparison in `src/state/at.rs:2686-2706` (`F-08-03`)
  - [ ] Deduplicate `RedactionOverlay` / `ResolutionInputRecord` inputs (`src/state/lthash.rs:155`) and reject $> 64\text{ KiB}$ keys instead of silently truncating (`F-08-01`, `F-08-02`)
