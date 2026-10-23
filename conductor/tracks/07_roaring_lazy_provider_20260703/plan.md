# Implementation Plan: Roaring Bitmap Auth-Difference, Lazy EventProvider & Homeserver Utilities (`07_roaring_lazy_provider_20260703`)

## Phase 1: Auth-Chain Difference, Roaring `AuthGraph` & State Diff APIs [checkpoint: 3caa4ca]

- [x] Task: Expose `compute_auth_chain_diff`, `AuthGraph::auth_difference`, and `StateDiff` public APIs 3caa4ca
  - [x] Implement `AuthGraph::auth_difference` and `AuthGraph::is_in_auth_chain` in `src/auth/roaring.rs` using topological Kahn sorting and transitive `RoaringBitmap` unions (`3caa4ca`)
  - [x] Expose `compute_auth_chain_diff` in `src/state/at.rs` and implement `compute_state_diff` (`StateDiff`, `StateChange`) in `src/state/diff.rs` (`3caa4ca`)
  - [x] Document the 3-tier synchronous homeserver utility roadmap in `docs/homeserver_utilities.md` and the "I/O Sandwich" transitive closure architecture in `docs/architecture.md` (`3caa4ca`)
- [x] Task: Implement `resolve_state_maps_lazy` and `LeanEventCache` for on-demand event loading 46ea938
  - [x] Define `EventProvider` trait and implement `resolve_state_maps_lazy` / `resolve_state_maps_lazy_with_diff` in `src/resolve/multi.rs` to partition state maps before fetching conflicted events (`46ea938`)
  - [x] Implement `LeanEventCache` in `src/state/cache.rs` with `Arc<LeanEvent>` storage, `RefCell<BTreeMap<u64, Id>>` $O(\log n)$ LRU eviction, and hit/miss/eviction metrics (`46ea938`)
  - [x] Update `docs/homeserver_utilities.md` to mark lazy multi-fork resolution and `LeanEventCache` as implemented (`46ea938`)
- [x] Task: Fix lazy `auth_context` conflicted-event merging and release `v0.5.0` fe881ac
  - [x] Merge fetched conflicted events directly into the lazy `auth_context` map in `src/resolve/multi.rs` so cross-referencing conflicted auth events resolve cleanly (`fe881ac`)
  - [x] Expand unit test coverage for `LeanEventCache` batch-insert cache hits and missing-event branches in `compute_state_at` (`24123de`)
  - [x] Configure package exclusions in `Cargo.toml` and tag release `v0.5.0` (`7e39a14`)

## Phase 2: Streaming State Pipeline, Roaring Forward Extremities & Rust 2024 Upgrade [checkpoint: 82b71e7]

- [x] Task: Harden V2.1 streaming state resolution pipeline and upgrade crate to Rust Edition 2024 7e5ccf2
  - [x] Implement streaming pipeline improvements and V2.1 compliance extensions in `src/state/at.rs` and `src/resolve/iterative.rs` (`efc06d7`)
  - [x] Upgrade `Cargo.toml` and all 32 source and integration test files to Rust Edition 2024 and tag `v0.5.1` (`7e5ccf2`)
- [x] Task: Add `find_forward_extremities_roaring` and gate behind `std` feature flag 1c0c2b0
  - [x] Implement `find_forward_extremities_roaring` in `src/state/at.rs` using bitmap parent-index subtraction (`1c0c2b0`)
  - [x] Gate roaring extremity helper behind `std` feature flag and add unit tests in `tests/test_traversal.rs` (`f538d7f`)
  - [x] Expand forward extremity test coverage for edge-case single-node and multi-head DAGs (`82b71e7`)

## Phase 3: Borrowed `LeanEventView`, Rejection Flag Enforcement & `v0.5.2` Release [checkpoint: 1518ddd]

- [x] Task: Introduce borrowed `LeanEventView` and genericize the auth check boundary bfb121e
  - [x] Add zero-copy borrowed `LeanEventView` in `src/basespec/rezzy_types.rs` and route `__soft_fail` / `__rejected` flags through static string constants (`9a6276d`, `bfb121e`)
  - [x] Check `__rejected` and `__soft_fail` flags first and add `test_lean_event_borrowed_view_accessors` (`2115ff4`)
  - [x] Genericize `src/auth/mod.rs` boundary functions to operate on borrowed event views without cloning `LeanEvent` (`560cd6b`)
- [x] Task: Enforce strict rejection of flagged events in auth checks and tag `v0.5.2` 1518ddd
  - [x] Reject `__rejected` and `__soft_fail` events during event auth checks and auth-state lookups in `src/auth/mod.rs` (`50ac866`, `6d970ca`)
  - [x] Require raw event rejection flags and reject flagged `m.room.join_rules` events during invite authorization (`5909719`, `dbaea94`, `be1f099`)
  - [x] Bump crate version and tag `v0.5.2` (`1518ddd`)

## Phase 4: Zero-Allocation Raw Event Extraction & In-Tree Hybrid Bitmap Engine [checkpoint: 95a8ffb]

- [x] Task: Expose zero-allocation caller-buffered raw Matrix event extraction APIs in `src/raw_event.rs` c89aec4
  - [x] Extract raw event span and selective tokenization helpers from `rezzy-cli/src/utils.rs` into `src/raw_event.rs` (`RawEventSpan`, `ADJACENCY_MASK`) in core `rezzy` (`c89aec4`)
  - [x] Implement `MatrixEventScratch<'a>` and `extract_matrix_event_into` for zero-heap-allocation event extraction from borrowed JSON buffers (`269d94d`, `f87090d`)
  - [x] Decode escaped scalar strings in the zero-alloc path, safely reject escaped reference IDs, and add `OwnedMatrixEvent` / `extract_batch` (`1aaa00c`, `4551a4e`, `8ce5668`)
- [x] Task: Replace external `roaring` crate with in-tree hybrid `Bitmap` and optimize union popcounts 95a8ffb
  - [x] Replace `roaring::RoaringBitmap` with an in-tree `u32` chunked `Bitmap` (`Store::Array` / `Store::Dense`) in `src/bitmap.rs` and `src/auth/roaring.rs`, restoring MSRV 1.87/1.88 (`04dc560`, `cd568c6`)
  - [x] Optimize `Bitmap` union with in-place chunk mutation and eliminate full 1024-word popcounts by counting only newly set bits via `(y & !*x).count_ones()` (`6282cb2`, `95a8ffb`)
  - [x] Add `Bitmap64` and `Bitmap128` wide wrappers and clone-free `&Bitmap & &Bitmap` intersection (`7ad9903`, `60a2b93`)

---

## History & Audit Traceability

| Commit SHA | Date | Subject | Primary Source & Test Files | Linked Docs & Public-Safety Audit Mapping |
| :--- | :--- | :--- | :--- | :--- |
| `3caa4ca` | 2026-07-03 | `feat: expose auth chain diff, roaring auth_difference, and state diff APIs` | `src/auth/roaring.rs`, `src/state/at.rs`, `src/state/diff.rs`, `tests/test_lib.rs` | [`architecture.md`](../../../docs/architecture.md), [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) — **Audit #2 (Critical: OOM / Starvation)** & **Audit #8 (High: Missing Tier-2 Guards)** |
| `46ea938` | 2026-07-03 | `feat: add resolve_state_maps_lazy with EventProvider for on-demand loading` | `src/resolve/multi.rs`, `src/state/cache.rs`, `src/state/diff.rs` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) — Mitigates eager unconflicted state deserialization, but still loads full conflicted auth difference in memory (**Audit #2**). |
| `fe881ac` | 2026-07-03 | `fix: merge conflicted events into lazy auth_context, fix rustdoc links, doc cleanups` | `src/resolve/multi.rs`, `src/state/cache.rs` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) |
| `7e39a14` | 2026-07-06 | `dist: cargo pkg ignore some new config files (for dist) (tag: v0.5.0)` | `Cargo.toml` | Release boundary `v0.5.0` |
| `7e5ccf2` | 2026-07-07 | `chore: bump version v0.5.1, upgrade rust edition 2024 (tag: v0.5.1)` | `Cargo.toml`, `src/state/at.rs`, `src/state/cache.rs`, `tests/test_lib.rs` | Release boundary `v0.5.1` |
| `1c0c2b0` | 2026-07-07 | `feat: Add find_forward_extremities_roaring` | `src/state/at.rs`, `tests/test_traversal.rs` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) |
| `82b71e7` | 2026-07-08 | `fix: cover roaring forward extremities` | `src/state/at.rs`, `tests/test_traversal.rs` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) |
| `bfb121e` | 2026-07-08 | `feat: add borrowed lean event view` | `src/basespec/rezzy_types.rs`, `src/auth/mod.rs` | [`architecture.md`](../../../docs/architecture.md) |
| `560cd6b` | 2026-07-08 | `refactor: genericize auth boundary for borrowed events` | `src/auth/mod.rs`, `src/basespec/rezzy_types.rs` | [`architecture.md`](../../../docs/architecture.md) |
| `1518ddd` | 2026-07-09 | `chore: bump version v0.5.2 (tag: v0.5.2)` | `Cargo.toml`, `src/auth/mod.rs`, `tests/test_auth.rs` | Release boundary `v0.5.2` |
| `c89aec4` | 2026-10-01 | `feat: expose raw event APIs from rezzy` | `src/raw_event.rs`, `src/lib.rs`, `rezzy-cli/src/utils.rs` | [`architecture.md`](../../../docs/architecture.md), [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) — **Audit #8**: Raw extraction ships while `src/auth/validate.rs` remains unimplemented. |
| `04dc560` | 2026-10-09 | `Replace roaring with an in-tree u32 bitmap and restore MSRV 1.88` | `src/bitmap.rs`, `src/auth/roaring.rs` | [`architecture.md`](../../../docs/architecture.md), [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) |
| `95a8ffb` | 2026-10-09 | `Avoid full popcounts in bitmap union` | `src/bitmap.rs` | [`architecture.md`](../../../docs/architecture.md) — Optimizes `AuthGraph` transitive closure union cost. |
| `7ad9903` | 2026-10-09 | `Add Bitmap64 and Bitmap128; build Bitmap & without cloning` | `src/bitmap.rs`, `benches/db/bitmap_vs_roaring.rs` | [`architecture.md`](../../../docs/architecture.md) |

> **Public-Safety Remediation Linkage**: Open findings from [`../../audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #2: OOM/Starvation on unbounded conflicted graphs and unverified transitive bitmap caches; Row #8: Missing Tier-2 `src/auth/validate.rs` and `src/dag/fork.rs` guards) are scheduled for Stage B remediation in Priority P1 Item #5.
