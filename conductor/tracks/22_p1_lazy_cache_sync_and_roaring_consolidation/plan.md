# Implementation Plan: Track 22 — Thread-Safe `LeanEventCache`, Fallible `EventProvider` Error Propagation & `DenseIndex`/Roaring Consolidation

## Phase 1: Thread-Safe `LeanEventCache` & Fallible `EventProvider` Resolution (`F-07-05`, `F-07-06`)
- [ ] Task: Refactor `LeanEventCache` for `Send + Sync` concurrency and $O(1)$ zero-allocation cache hits (`F-07-05`, `src/state/cache.rs:85-163`)
  - [ ] Replace `RefCell<BTreeMap<u64, Id>>` and `Cell<u64>` in `LeanEventCache` (`src/state/cache.rs:85-163`) with `AtomicU64` generation counters on `CacheEntry` and the cache struct so `LeanEventCache<Id, K>: Send + Sync` (`F-07-05`)
  - [ ] Eliminate `bump_entry`'s `BTreeMap::remove` + `insert` + `Id::clone` on cache hits (`src/state/cache.rs:118-163`, `198-206`) and add a multi-threaded `std::thread::scope` + zero-allocation cache-hit regression test (`F-07-05`)
- [ ] Task: Replace unconditional panics and silent missing-ancestor drops with fallible `Result` APIs (`F-07-06`, `src/resolve/multi.rs:677-680`, `src/auth/roaring.rs:81-82`)
  - [ ] Define `LazyResolveError<Id>` and implement `try_resolve_state_maps_lazy` and `try_resolve_state_maps_lazy_with_diff` in `src/resolve/multi.rs:640-750` to return `Err` on missing conflicted or auth events instead of calling `panic!("provider missing conflicted event {id}")` at `src/resolve/multi.rs:677-680` (`F-07-06`)
  - [ ] Add `AuthGraph::try_build` in `src/auth/roaring.rs:43-102` returning `Result<Self, IndexTooLarge>` instead of `.expect("sort_context exceeds u32::MAX events")` at `src/auth/roaring.rs:81-82`, and add unit tests covering missing events and overflow (`F-07-06`)

## Phase 2: Complete `DenseIndex` Consolidation & In-Place Roaring `Chunk::union_assign` (`F-07-08`, `F-07-09`, `F-09-06`)
- [ ] Task: Migrate remaining 3 manual ID-to-`u32` tables to `DenseIndex` (`F-07-08`, `F-09-06`, `src/state/at.rs:2754-2797`, `src/dense_index.rs:103`, `docs/tech_debt.md:36-48`)
  - [ ] Migrate `find_forward_extremities_roaring` (`src/state/at.rs:2754-2797`) from manual `id_map: HashMap<Id, u32>` + `reverse_map: Vec<Id>` to `DenseIndex::try_build` (`F-07-08`, `F-09-06`)
  - [ ] Migrate `collect_ancestor_short_ids_batch` and `index_by_event_id` in `src/state/at.rs` to `DenseIndex`, align `DenseIndex` map builder documentation in `src/dense_index.rs:103`, and update `docs/tech_debt.md:36-48` (`F-09-06`)
- [ ] Task: Optimize `Chunk::union_assign` in `rezzy-recon` bitmap engine (`F-07-09`, `rezzy-recon/src/bitmap/mod.rs:364-366`)
  - [ ] Implement in-place `Store::Array` union and representation demotion/promotion invariants in `Chunk::union_assign` (`rezzy-recon/src/bitmap/mod.rs:320-368`, specifically `364-366`) with property tests verifying cardinality and chunk encoding (`F-07-09`)

## Phase 3: Adversarial Fork-Scale & Roaring Storage Invariant Documentation (`F-07-02`)
- [ ] Task: Update `docs/architecture.md` fork-scale taxonomy and `shorteventid_authchain` immutability contract (`F-07-02`, `docs/architecture.md:202-211`)
  - [ ] Revise the fork-scale table and memory/CPU bounds in `docs/architecture.md:202-211` to reflect $10^4\text{--}10^5$ event netsplit/adversarial forks, `spawn_blocking` isolation requirements, and subgraph cardinality budgets (`F-07-02`)
  - [ ] Document the append-only immutability invariant for persisted `shorteventid_authchain` Roaring bitmaps across database compactions in `docs/architecture.md` and `docs/homeserver_utilities.md` (`F-07-02`)
