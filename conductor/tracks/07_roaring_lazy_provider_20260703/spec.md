# Specification: Roaring Bitmap Auth-Difference, Lazy EventProvider & Homeserver Utilities (`07_roaring_lazy_provider_20260703`)

## 1. Overview & Historical Context

Between **July 3, 2026 and July 9, 2026** (spanning tags `v0.5.0` at `7e39a14`, `v0.5.1` at `7e5ccf2`, and `v0.5.2` at `1518ddd`), and culminating in **October 2026** (`c89aec4` through `95a8ffb`), `rezzy` evolved from a standalone state-resolution kernel into a full-featured synchronous compute engine for Matrix homeservers (such as Tuwunel and Continuwuity).

### Why This Track Was Built
1. **Eliminating Redundant Homeserver Graph Plumbing (`3caa4ca`)**: Every Matrix homeserver integrating `rezzy` previously had to reimplement the bounded dual-heap traversal to compute the **Auth Difference** ($\text{auth}(C) \setminus \text{auth}(U)$), compute incremental state diffs for client `/sync`, and maintain transitive auth-chain bitmaps for full room state rebuilds (`O(F \times D) \to O(V + E + F)`).
2. **Bridging the Synchronous "I/O Sandwich" with On-Demand Loading (`46ea938`, `fe881ac`)**: While `docs/architecture.md` establishes why async state resolution inside the sorting loop causes the N+1 query anti-pattern, homeservers resolving multi-fork merges (`resolve_state_maps`) should not have to eagerly convert every unconflicted state event in the room into a `LeanEvent`. Introducing `EventProvider` (`Fn(&Id) -> Option<LeanEvent>`) and `LeanEventCache` (`src/state/cache.rs`) allowed `resolve_state_maps_lazy` to partition N state maps first and only materialize the conflicted events and their auth chains on demand.
3. **Zero-Allocation Raw Event Ingestion & In-Tree Bitmaps (`bfb121e`, `c89aec4`, `04dc560`, `95a8ffb`)**: To further reduce deserialization and dependency overhead across `v0.5.2` and `0.6.0-rc`, `rezzy` introduced borrowed `LeanEventView` auth boundaries (`bfb121e`, `560cd6b`), exposed caller-buffered zero-allocation JSON field extraction (`src/raw_event.rs` in `c89aec4`, `f87090d`), and replaced the external `roaring` crate with an in-tree hybrid chunked `Bitmap` (`04dc560`) featuring single-instruction `(y & !*x).count_ones()` union popcounts (`95a8ffb`).

---

## 2. Functional Requirements & Matrix Spec/MSC Mapping

### FR-07.1: Synchronous "I/O Sandwich" & Auth Chain Difference (`src/state/at.rs`, `docs/architecture.md`)
- Expose `compute_auth_chain_diff` publicly so homeservers can compute $\text{auth}(C) \setminus \text{auth}(U)$ using `rezzy`'s bounded dual-heap traversal, stopping immediately upon hitting the unconflicted state boundary $U$.
- Support both V1 and V2/V2.1/V2.2 state resolution rules by computing the exact conflicted auth supplement required before entering `resolve_iterative_sort`.

### FR-07.2: Transitive Closure `AuthGraph` & Bitmap Set Difference (`src/auth/roaring.rs`, `src/bitmap/`)
- Construct `AuthGraph<Id>` via topological Kahn sorting over an event context, assigning dense `u32` indices via `DenseIndex<Id>` and computing per-event transitive ancestor bitmaps (`bitmap[i] = \bigcup_{a \in \text{auth}(i)} (\text{bitmap}[a] \cup \{a\})`) in $O(V + E)$ time (`3caa4ca`).
- Provide `AuthGraph::auth_difference(unconflicted_ids, conflicted_ids)` to compute $\bigcup_{c \in C} \text{chain}(c) \setminus \bigcup_{u \in U} \text{chain}(u)$ in $O(|\text{bitmap}|)$ bitwise operations, and `AuthGraph::is_in_auth_chain(ancestor, descendant)` in $O(1)$ time.
- Provide `find_forward_extremities_roaring` (`1c0c2b0`, `f538d7f`, `82b71e7`) to identify DAG forward extremities using bitmap set subtraction.
- Replace the external `roaring` dependency with an in-tree `no_std`-compatible chunked `Bitmap` (`Store::Array` for sparse $<4096$-bit chunks and `Store::Dense` for 1024-word `u64` chunks in `04dc560`), extended with `Bitmap64` and `Bitmap128` (`7ad9903`) and incremental popcount maintenance during union (`95a8ffb`).

### FR-07.3: Lazy On-Demand Multi-Fork Resolution & `LeanEventCache` (`src/resolve/multi.rs`, `src/state/cache.rs`)
- Define the synchronous `EventProvider<Id, C>` trait (implemented for closures `F: Fn(&Id) -> Option<LeanEvent<Id, C>>`, `HashMap<Id, LeanEvent<Id, C>>`, and `LeanEventCache<Id, C>`).
- Implement `resolve_state_maps_lazy` and `resolve_state_maps_lazy_with_diff` (`46ea938`, `fe881ac`) to:
  1. Partition $N$ fork state maps into `unconflicted` ($\bigcap_i S_i$) and `conflicted` ($\bigcup_i S_i \setminus \bigcap_i S_i$) without fetching any event payloads.
  2. Return immediately in $O(1)$ / $O(|S|)$ when `conflicted` is empty (zero `EventProvider` calls).
  3. Walk and fetch only the conflicted events and their transitive auth chains via BFS through `EventProvider`, stopping at `unconflicted` state event IDs.
- Provide `LeanEventCache<Id, C>` (`46ea938`), a fixed-capacity `no_std`-compatible LRU cache storing `Arc<LeanEvent<Id, C>>` with a `RefCell<BTreeMap<u64, Id>>` generation side-index for $O(\log n)$ LRU eviction and interior-mutable hit/miss/eviction telemetry.

### FR-07.4: Typed State Diffs, Borrowed Views & Zero-Allocation Raw Event Extraction (`src/state/diff.rs`, `src/raw_event.rs`)
- Implement `compute_state_diff(before, after)` returning `StateDiff<Id, K>` (`added`, `removed`, `changed: Vec<StateChange<Id>>`, `unchanged_count`) for incremental `/sync` updates and delta validation (`3caa4ca`).
- Introduce `LeanEventView` and genericize the auth check boundary over borrowed event views (`bfb121e`, `2115ff4`, `560cd6b`, `be1f099`), enforcing strict rejection of `__rejected` and `__soft_fail` flagged events in auth state and invite join-rule checks.
- Expose `src/raw_event.rs` (`c89aec4`, `269d94d`, `f87090d`, `8ce5668`) from the core `rezzy` crate with `RawEventSpan`, `ADJACENCY_MASK`, reusable `MatrixEventScratch<'a>`, and `extract_matrix_event_into` for zero-heap-allocation extraction of DAG adjacency and state metadata from raw JSONL byte buffers.

---

## 3. Architectural Decisions & Rejected Alternatives

1. **Synchronous "I/O Sandwich" vs. Async `Future`-Based `EventProvider` (`docs/architecture.md`)**:
   - *Decision*: `resolve_iterative_sort` and `EventProvider::get_event` are strictly synchronous (`# ! [no_std]` compatible).
   - *Rejected Alternative*: Making `resolve_iterative_sort` `async` and `await`ing database fetches per event during topological sort or auth checks. As documented in `docs/architecture.md`, async lazy loading inside the resolution loop causes the **N+1 Query Problem** (50 sequential database round-trips instead of 1–3 batched BFS queries or 1 indexed `RoaringTreemap` read) and couples the CPU algorithm to database driver latency.
2. **Three-Layer Auth Chain Representation (`docs/architecture.md`)**:
   - *Decision*: Separate (1) persistent 1-hop adjacency lists (`shorteventid_shortauthevents`), (2) derived persistent closure caches (`shorteventid_authchain`), and (3) ephemeral in-memory `Vec<Bitmap>` rebuild indices (`AuthGraph::build`).
   - *Rationale*: Computing a throwaway `O(V + E)` bitmap index in RAM from raw JSON (`src/raw_event.rs`) during full room state rebuilds is faster than issuing 60,000 asynchronous DB point lookups.
3. **In-Tree Hybrid `Bitmap` vs. External `roaring` Crate (`04dc560`, `6282cb2`, `95a8ffb`)**:
   - *Decision*: Replace the external `roaring` dependency with an in-tree `u32` `Bitmap` (plus `Bitmap64`/`Bitmap128`) in `rezzy-recon::bitmap` re-exported by `rezzy::bitmap`.
   - *Rationale*: Restored MSRV 1.87/1.88 compatibility (`04dc560`, `cd568c6`), eliminated external dependency bloat, and unlocked custom in-place chunk union optimizations where newly added bits are counted via `(y & !*x).count_ones()` (`95a8ffb`) instead of re-running full 1024-word popcounts after every union.

---

## 4. Non-Functional & Public-Safety Invariants

Cross-referencing [`../../audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md):

- **Public-Safety Audit Finding #2 (`docs/architecture.md` — Critical: OOM / Executor Thread Starvation)**:
  - `docs/architecture.md` ("Typical Working Set Sizes", lines 202–211) assumes catastrophic forks involve only `500–700` total events fitting in L1/L2 cache. In adversarial federation partitions or tactical radio link dropouts, forks can span $10^4\text{--}10^5$ conflicted events.
  - Pre-fetching the entire conflicted graph into a single in-memory `HashMap<EventId, LeanEvent>` risks **Out-Of-Memory (OOM) termination**, while running `resolve_iterative_sort` or `AuthGraph::build` directly on an async executor worker thread without `tokio::task::spawn_blocking` or a bounded event cap causes **executor thread starvation** across the homeserver.
  - Furthermore, `docs/architecture.md` notes that persistent `shorteventid_authchain` roaring caches "can become stale/corrupt; regenerated by `reindex-short`." In a public-safety deployment, a corrupted transitive closure bitmap silently omits auth-chain revocation/ban events during $\text{auth}(C) \setminus \text{auth}(U)$ subtraction, causing a **State Reset / Revocation Bypass**.
- **Public-Safety Audit Finding #8 (`docs/homeserver_utilities.md` — High: Missing Tier-2 Guards)**:
  - `docs/homeserver_utilities.md` marks Tier-1 hot-path APIs (Auth Chain Diff, Roaring Auth Diff, Power Level Queries, State Diff) and Tier-2 Redaction Engine as `✅ Implemented`, but explicitly lists **Item 5: Event Well-Formedness Validation (`src/auth/validate.rs`)** and **Item 7: DAG Health Metrics (`compute_dag_health` / `fork.rs`)** as `❌ Not implemented`.
  - Shipping high-throughput ingestion (`src/raw_event.rs`) and lazy resolution APIs without structural pre-auth validation (`prev_events` non-empty except `m.room.create`, depth monotonicity, `state_key` presence invariants) leaves downstream homeservers exposed to malformed PDUs unless they implement custom pre-ingestion guards.

---

## 5. Acceptance Criteria & Verification Oracles

1. **Bitmap Auth Graph & Set-Difference Oracles (`src/auth/roaring.rs`, `tests/unit/test_lib.rs`, `tests/unit/test_traversal.rs`)**:
   - `test_auth_graph_build`, `test_is_in_auth_chain`, `test_auth_difference_basic`, `test_auth_difference_overlapping`, `test_auth_difference_empty_inputs`, and `test_auth_difference_unknown_ids_ignored` verify topological ordering and exact set difference parity against `compute_auth_chain_diff`.
   - `find_forward_extremities_roaring` unit and integration tests (`1c0c2b0`, `f538d7f`, `82b71e7`) verify extremity detection across branching DAGs.
2. **Lazy `EventProvider` & `LeanEventCache` Oracles (`src/state/cache.rs`, `src/resolve/multi.rs`, `tests/unit/test_lib.rs`)**:
   - Verify `resolve_state_maps_lazy` invokes the `EventProvider` callback *zero* times when state maps agree, fetches only conflicted + auth-diff events when forks diverge, and produces 100% identical resolved state to eager `resolve_state_maps`.
   - Verify `LeanEventCache` $O(\log n)$ `BTreeMap` generation eviction, interior mutability via `&self` in `EventProvider::get_event`, and hit/miss/eviction counters (`24123de`).
3. **Borrowed Event Views & Rejection Flag Oracles (`tests/unit/test_auth.rs`, `tests/unit/test_sanity.rs`)**:
   - Verify `__rejected` and `__soft_fail` events are unconditionally rejected in `check_auth`, auth state loading, and invite join-rule checks (`50ac866`, `6d970ca`, `be1f099`).
4. **Zero-Allocation Raw Event Extraction Oracles (`src/raw_event.rs`)**:
   - Verify `extract_matrix_event_into` with pre-sized `MatrixEventScratch` performs 0 heap allocations per event, decodes escaped scalar strings in-place (`1aaa00c`), and safely rejects escaped reference IDs (`4551a4e`).
