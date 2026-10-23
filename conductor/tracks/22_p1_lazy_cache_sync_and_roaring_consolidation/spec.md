# Specification: Track 22 — P1 Remediation: Thread-Safe `LeanEventCache`, Fallible `EventProvider` Error Propagation & `DenseIndex`/Roaring Consolidation

- **Track ID**: `22_p1_lazy_cache_sync_and_roaring_consolidation`
- **Priority**: `P1`
- **Originating Tracks**: `07_roaring_lazy_provider_20260703`, `09_perf_interning_benchmarks_20260920`
- **Remediated Findings**: `F-07-02`, `F-07-05`, `F-07-06`, `F-07-08`, `F-07-09`, `F-09-06`

---

## 1. Overview & Finding Traceability Matrix

This track remediates six operational, concurrency, crash-resilience, and data-structure consolidation defects uncovered during the 8-persona reviews of Tracks 07 and 09 (`F-07-02`, `F-07-05`, `F-07-06`, `F-07-08`, `F-07-09`, and `F-09-06`).

| Finding ID | Severity | Persona(s) | Source File / Line Range | Root Cause & Impact |
| :--- | :---: | :--- | :--- | :--- |
| **`F-07-02`** | `[Critical]` | `critic-federation-interop`, `critic-redteam-qa` | [`docs/architecture.md:202-211`](../../../docs/architecture.md#L202-L211) | **Audit #2**: Classifies a "Catastrophic (netsplit)" fork as 500–700 events fitting in L1/L2 cache (`< 100 KB`), whereas production federation partitions and state-reset attacks reach $10^4\text{--}10^5$ events, risking OOM, Tokio executor starvation without `spawn_blocking`, and silent split-brain if persisted `shorteventid_authchain` Roaring bitmaps are invalidated by DB short-ID compaction. |
| **`F-07-05`** | `[High]` | `critic-dx-integrator`, `critic-perf` | [`src/state/cache.rs:85-163`](../../../src/state/cache.rs#L85-L163) | `LeanEventCache` embeds `RefCell<BTreeMap<u64, Id>>` and `Cell<u64>`, making it `!Sync` (preventing concurrent `Arc<RwLock<LeanEventCache>>` reads across async Tokio workers), and `bump_entry` executes `BTreeMap::remove(&old_gen)` + `insert(gen, entry.event.event_id.clone())` on every cache hit ($O(\log N)$ tree manipulation + heap `Id` clone per hit). |
| **`F-07-06`** | `[High]` | `critic-redteam-qa`, `critic-eng-lead` | [`src/resolve/multi.rs:677-680`](../../../src/resolve/multi.rs#L677-L680), [`src/auth/roaring.rs:81-82`](../../../src/auth/roaring.rs#L81-L82) | Unconditional panics (`panic!("provider missing conflicted event {id}")` and `.expect("sort_context exceeds u32::MAX events")`) in library entry points (`resolve_state_maps_lazy_with_diff` and `AuthGraph::build`), while missing auth ancestors are silently dropped (`if let Some(aev) = provider.get_event(&aid)`), corrupting auth chains instead of returning a typed `Result`. |
| **`F-07-08`** | `[Medium]` | `critic-eng-lead`, `critic-perf` | [`src/state/at.rs:2754-2797`](../../../src/state/at.rs#L2754-L2797) | `find_forward_extremities_roaring` hand-rolls a duplicate `id_map: HashMap<Id, u32>` + `reverse_map: Vec<Id>` with `.expect("event count exceeds u32")` instead of using `DenseIndex<Id>`, and was omitted from `docs/tech_debt.md`. |
| **`F-07-09`** | `[Low]` | `critic-perf` | [`rezzy-recon/src/bitmap/mod.rs:364-366`](../../../rezzy-recon/src/bitmap/mod.rs#L364-L366) | `Chunk::union_assign` mutates `Dense |= Dense` and `Dense |= Array` in-place via `Arc::make_mut`, but falls back to allocating a new `Chunk` (`*self = self.union(other)`) for `Array |= Array` (`Store::Array`), and lacks density demotion checks when mutating `Dense` chunks. |
| **`F-09-06`** | `[Medium]` | `critic-eng-lead` | [`docs/tech_debt.md:36-48`](../../../docs/tech_debt.md#L36-L48), [`src/dense_index.rs:103`](../../../src/dense_index.rs#L103) | `DenseIndex` migration is incomplete across the remaining 3 call sites (`collect_ancestor_short_ids_batch` in `src/state/at.rs`, `index_by_event_id` in `src/state/at.rs`, and `find_forward_extremities_roaring` in `src/state/at.rs`), and `DenseIndex` uses `crate::HashMap` (`SipHash13`) inconsistently relative to its callers. |

---

## 2. Functional & Architectural Remediation Requirements

### 2.1 Operational Fork-Scale Guardrails & `shorteventid_authchain` Immutability (`F-07-02`)
1. Revise [`docs/architecture.md:202-215`](../../../docs/architecture.md#L202-L215) to distinguish routine federation forks ($10^2\text{--}10^3$ events) from adversarial/netsplit forks ($10^4\text{--}10^5$ conflicted events and $> 5 \times 10^4$ auth-diff ancestors).
2. Document mandatory homeserver integration guardrails in `docs/architecture.md` and `docs/homeserver_utilities.md`:
   - Offloading synchronous resolution of large conflicted subgraphs ($|C| > 500$) to `tokio::task::spawn_blocking` to prevent starving federation HTTP/TLS reactors.
   - Enforcing subgraph cardinality budgets and circuit breakers before eager subgraph allocation.
   - Enforcing strict schema immutability invariants on persisted `shorteventid_authchain` Roaring bitmaps: dense `u32` short event IDs mapped into persisted bitmaps MUST be append-only and never compacted or reassigned without atomic cache invalidation.

### 2.2 Thread-Safe (`Send + Sync`), Zero-Allocation-Hit `LeanEventCache` (`F-07-05`)
1. Refactor [`LeanEventCache`](../../../src/state/cache.rs#L85-L163) to eliminate `RefCell<BTreeMap<u64, Id>>` and `Cell<u64>`:
   - Make `LeanEventCache<Id, K>` implement `Send + Sync` (when `Id: Send + Sync`, `K: Send + Sync`) by tracking access recency via `core::sync::atomic::AtomicU64` (per-entry atomic generation stamp or Second-Chance/Clock reference bit) and an atomic global clock counter.
   - Eliminate the $O(\log N)$ `BTreeMap::remove` + `BTreeMap::insert` + `Id::clone()` on every `get` / `EventProvider::get_event` cache hit (`bump_entry`). Cache hits MUST perform zero heap allocations and only an $O(1)$ `Ordering::Relaxed` atomic store on the entry's generation stamp, deferring eviction selection to `insert` when `entries.len() >= capacity`.

### 2.3 Fallible `EventProvider` Resolution & `AuthGraph` Error Propagation (`F-07-06`)
1. Introduce a typed `LazyResolveError<Id>` (or `ProviderError<Id>`) enum covering:
   - `MissingConflictedEvent(Id)` when `provider.get_event(id)` returns `None` for a conflicted event in $C$.
   - `MissingAuthEvent { child: Id, missing_auth_id: Id }` when an auth ancestor required during auth-diff traversal or iterative verification is missing from `provider`.
   - `SubgraphTooLarge { count: usize, max: usize }` when event count exceeds `u32::MAX` or a caller-configured cardinality budget.
2. Add fallible entry points `try_resolve_state_maps_lazy` and `try_resolve_state_maps_lazy_with_diff` in [`src/resolve/multi.rs:640-750`](../../../src/resolve/multi.rs#L640-L750) and `AuthGraph::try_build` in [`src/auth/roaring.rs:43-102`](../../../src/auth/roaring.rs#L43-L102), removing unconditional `panic!` and `.expect(...)` calls from the resolution engine.

### 2.4 `DenseIndex` Consolidation & In-Place `Chunk::union_assign` (`F-07-08`, `F-07-09`, `F-09-06`)
1. Migrate all three remaining manual bidirectional `HashMap<Id, u32>` + `Vec<Id>` index sites in [`src/state/at.rs`](../../../src/state/at.rs) to [`DenseIndex`](../../../src/dense_index.rs) (`F-07-08`, `F-09-06`):
   - `find_forward_extremities_roaring` (`src/state/at.rs:2754-2797`)
   - `collect_ancestor_short_ids_batch` (`src/state/at.rs`)
   - `index_by_event_id` (`src/state/at.rs`)
2. Update [`docs/tech_debt.md:36-48`](../../../docs/tech_debt.md#L36-L48) and [`src/dense_index.rs:103`](../../../src/dense_index.rs#L103) to record 100% completion of the `DenseIndex` migration across all 6 call sites.
3. Optimize [`Chunk::union_assign`](../../../rezzy-recon/src/bitmap/mod.rs#L364-L366) in `rezzy-recon/src/bitmap/mod.rs` so `(Store::Array(a), Store::Array(b))` merges in-place into `a` (converting to `Store::Dense` only when the merged cardinality reaches `ARRAY_LIMIT = 4096`) and ensure `Dense` chunk mutations preserve canonical representation invariants (`F-07-09`).

---

## 3. Public-Safety & Consensus Invariants

- **No Crash-on-Missing-Event in Federation Workers (`F-07-06`)**: A storage corruption, pruned historical event, or oversized subgraph MUST return `Err(LazyResolveError::...)` rather than panicking and tearing down the homeserver worker thread.
- **Zero-Allocation Concurrent Cache Reads (`F-07-05`)**: `Arc<RwLock<LeanEventCache<Id, K>>>` (or `Arc<LeanEventCache<Id, K>>`) MUST be usable concurrently across multi-threaded async workers without `RefCell` borrow panics or per-hit heap allocations.
- **Roaring Short-ID Monotonicity (`F-07-02`)**: Persisted `shorteventid_authchain` Roaring bitmaps are valid if and only if the `EventId <-> u32` mapping is immutable for the lifetime of the cached bitmaps.

---

## 4. Acceptance Criteria & Verification Oracles

- [ ] **`F-07-02` Verified**: `docs/architecture.md:202-215` accurately documents $10^4\text{--}10^5$ adversarial fork scales, `spawn_blocking` isolation, and `shorteventid_authchain` immutability invariants.
- [ ] **`F-07-05` Verified**: Static compile-time assertion `fn assert_sync<T: Send + Sync>() {}` passes for `LeanEventCache<String, String>`, and `test_zero_alloc` / unit tests confirm `LeanEventCache::get` and `EventProvider::get_event` perform zero heap allocations and zero `BTreeMap` mutations on cache hits.
- [ ] **`F-07-06` Verified**: Unit tests confirm `try_resolve_state_maps_lazy_with_diff` returns `Err(LazyResolveError::MissingConflictedEvent(_))` and `Err(LazyResolveError::MissingAuthEvent { .. })` instead of panicking or silently omitting missing auth ancestors, and `AuthGraph::try_build` returns `Result`.
- [ ] **`F-07-08` & `F-09-06` Verified**: `find_forward_extremities_roaring`, `collect_ancestor_short_ids_batch`, and `index_by_event_id` in `src/state/at.rs` use `DenseIndex`, and `docs/tech_debt.md:36-48` reflects all 6 sites migrated.
- [ ] **`F-07-09` Verified**: `Chunk::union_assign` in `rezzy-recon/src/bitmap/mod.rs:364-366` handles `Array |= Array` in-place when unique capacity permits and enforces representation invariants across `Array`/`Dense` transitions.
