# Track 07 Review & 8-Persona Critique: Roaring Bitmap Auth-Difference, Lazy EventProvider & Homeserver Utilities

- **Track ID**: `07_roaring_lazy_provider_20260703`
- **Commit Range**: `3caa4ca..95a8ffb` (`2026-07-03` – `2026-07-04`)
- **Review Date**: `2026-10-23`
- **Status**: Completed (Reverse-Engineered Historical Track — Audited for Stage B Remediation)

---

## 1. Conductor Review Summary (`/conductor-review`)

### 1.1 Plan & Spec Compliance Verification
| Phase / Task | Commit(s) | Verification Status | Notes |
| :--- | :--- | :--- | :--- |
| **Phase 1: Roaring Bitmap & `AuthGraph`** | `3caa4ca`, `e6e60cf`, `95a8ffb` | ⚠️ **Implemented with Subtle Defects** | `AuthGraph<Id>` ([src/auth/roaring.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/auth/roaring.rs#L24-L169)) and `Bitmap` ([rezzy-recon/src/bitmap/mod.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/rezzy-recon/src/bitmap/mod.rs#L64-L457)) pass unit tests, but `AuthGraph::build` uses non-deterministic `FastMap` iteration order and silently drops cyclic nodes. |
| **Phase 2: Lazy `EventProvider`, `LeanEventCache`, & Partitioning** | `46ea938`, `fe881ac`, `3b5faaa` | ❌ **Critical Spec Violation in Fallback BFS** | `resolve_state_maps_lazy_with_diff` ([src/resolve/multi.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs#L698-L721)) **fails to stop at `unconflicted_state`** when `precomputed_auth_diff` is `None`, walking the entire transitive auth chain $\text{auth}(C)$ to `m.room.create`. |
| **Phase 3: Bounded Dual-Heap & Zero-Copy Raw Event Views** | `eb2ffbc`, `6d1249d`, `df3d277` | ⚠️ **Implemented with Byzantine Depth Hazard** | `compute_auth_chain_diff` ([src/state/at.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L1718-L1799)) synchronizes `u_heap` and `c_heap` using untrusted wire `ev.depth`, which breaks under non-monotonic/spoofed federation depths. |
| **Phase 4: Documentation (`docs/architecture.md`, `docs/homeserver_utilities.md`)** | `eb2ffbc`, `6d1249d` | ❌ **Audit #2 (Critical) & Audit #8 (High) Open** | `docs/architecture.md` understates adversarial fork scale (claiming 500–700 events is "Catastrophic"); `docs/homeserver_utilities.md` leaves `validate.rs` and `fork.rs` (`compute_dag_health`) unimplemented (`❌`). |

### 1.2 Executive Findings Matrix
| ID | Severity | Persona | Location | Summary |
| :--- | :--- | :--- | :--- | :--- |
| **F-07-01** | `[Critical]` | `critic-compliance` / `critic-perf` | [src/resolve/multi.rs:698-721](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs#L698-L721) | `resolve_state_maps_lazy_with_diff` BFS fallback ignores `unconflicted_state` ($U$), loading the entire historical auth chain $\text{auth}(C)$ back to room creation when `precomputed_auth_diff` is `None`. |
| **F-07-02** | `[Critical]` | `critic-federation-interop` / `critic-redteam-qa` | [docs/architecture.md:202-211](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/architecture.md#L202-L211) | **Audit #2**: "Catastrophic" fork scale understated at 500–700 events; real federation partitions/attacks reach $10^4\text{--}10^5$ events, causing OOM, async executor starvation, and `shorteventid_authchain` cache hazards. |
| **F-07-03** | `[High]` | `critic-redteam-qa` / `critic-compliance` | [src/state/at.rs:1718-1799](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L1718-L1799) | `compute_auth_chain_diff` relies on untrusted wire `ev.depth` to synchronize `u_heap` and `c_heap`. Spoofed `depth = 0` on $C$ forces full traversal of $\text{auth}(U)$; spoofed `depth = 0` on $U$ prevents $U$-ancestors from being marked before $C$ pops them. |
| **F-07-04** | `[High]` | `critic-pm` / `critic-dx-integrator` | [docs/homeserver_utilities.md:69-158](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/homeserver_utilities.md#L69-L158) | **Audit #8**: `validate.rs` (structural PDU integrity checks) and `fork.rs` (`compute_dag_health` fork severity detector) are documented as homeserver utilities with `❌ Not implemented` status. |
| **F-07-05** | `[High]` | `critic-dx-integrator` / `critic-perf` | [src/state/cache.rs:85-163](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/cache.rs#L85-L163) | `LeanEventCache` is `!Sync` (`RefCell`/`Cell`), preventing shared `RwLock` read concurrency across async workers, and `bump_entry` performs a `BTreeMap::remove` + `insert` + `Id::clone` on every cache hit. |
| **F-07-06** | `[High]` | `critic-redteam-qa` / `critic-eng-lead` | [src/resolve/multi.rs:677-680](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs#L677-L680), [src/auth/roaring.rs:81-82](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/auth/roaring.rs#L81-L82) | Unconditional panics (`panic!("provider missing conflicted event {id}")`, `.expect(...)`) on library entry points instead of fallible `Result` returns when a DB/provider misses an event or count exceeds `u32`. |
| **F-07-07** | `[Medium]` | `critic-formal-crypto` / `critic-eng-lead` | [src/auth/roaring.rs:43-102](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/auth/roaring.rs#L43-L102) | `AuthGraph::build` iterates `FastMap` (`foldhash`) to seed Kahn's queue (`L61`), producing non-deterministic `DenseIndex` ID assignments and output ordering in `auth_difference`, and silently drops cyclic events if `sorted.len() < sort_context.len()`. |
| **F-07-08** | `[Medium]` | `critic-eng-lead` / `critic-perf` | [src/state/at.rs:2754-2797](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L2754-L2797) | `find_forward_extremities_roaring` hand-rolls a duplicate `id_map: HashMap<Id, u32>` + `reverse_map: Vec<Id>` instead of `DenseIndex<Id>`, and was missed in `docs/tech_debt.md`'s inventory of unmigrated `DenseIndex` call sites. |
| **F-07-09** | `[Low]` | `critic-perf` | [rezzy-recon/src/bitmap/mod.rs:364-366](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/rezzy-recon/src/bitmap/mod.rs#L364-L366) | `Chunk::union_assign` mutates `Dense |= Dense` and `Dense |= Array` in-place via `Arc::make_mut`, but falls back to allocating a new `Chunk` (`*self = self.union(other)`) for `Array |= Array`. |

---

## 2. Multi-Perspective Critique (8 Specialized Personas)

### 2.1 `critic-pm` (Product Manager — Roadmap, Scope & Public Narrative Coherence)
- **`[High]` Incomplete Homeserver Utility Catalog (Audit #8)**:
  - [docs/homeserver_utilities.md:69-98](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/homeserver_utilities.md#L69-L98) and [docs/homeserver_utilities.md:136-158](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/homeserver_utilities.md#L136-L158) advertise two high-value operational modules—PDU structural validation (`src/validate.rs`) and DAG fork health telemetry (`compute_dag_health` in `src/fork.rs`)—with `❌ Not implemented` markers. Presenting unbuilt modules inside a primary integration guide creates scope ambiguity for homeserver adopters evaluating `rezzy` against `ruma-state-res`.
- **`[Medium]` Spec vs. Implementation Drift on Lazy Resolution**:
  -Both [docs/architecture.md:21-23](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/architecture.md#L21-L23) and Track 07's `spec.md` (`FR-07.3`) position `resolve_state_maps_lazy` as fetching *only* the conflicted events and their auth difference relative to `unconflicted_state`. Because the default `resolve_state_maps_lazy` wrapper ([src/resolve/multi.rs:640-646](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs#L640-L646)) passes `None` for `precomputed_auth_diff`, and the `None` branch walks the entire auth chain to room creation, the headline value proposition of `resolve_state_maps_lazy` is broken unless the caller manually precomputes `precomputed_auth_diff`.

### 2.2 `critic-eng-lead` (Engineering Lead — Architecture, `#![no_std]` Hygiene & Tech Debt)
- **`[High]` Unmigrated 6th `DenseIndex` Pattern in `find_forward_extremities_roaring`**:
  - In [src/state/at.rs:2754-2797](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L2754-L2797) (commit `df3d277`), `find_forward_extremities_roaring` constructs `let mut id_map: HashMap<Id, u32>` and `let mut reverse_map: Vec<Id>` with `.expect("event count exceeds u32")` (`L2769`). This is an exact clone of the bidirectional dense-ID mapping abstracted into `DenseIndex<Id>` in Track 09 ([src/dense_index.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/dense_index.rs)), and isn't even listed among the 5 occurrences in [docs/tech_debt.md:36-48](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/tech_debt.md#L36-L48).
- **`[Medium]` Silent Missing-Event Drops vs. Panics in `resolve_state_maps_lazy_with_diff`**:
  - In [src/resolve/multi.rs:677-680](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs#L677-L680), a missing conflicted event in `provider.get_event(id)` triggers an unconditional `panic!("provider missing conflicted event {id}")`. Conversely, in the auth-diff loops ([src/resolve/multi.rs:587](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs#L587), [L687](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs#L687), [L710](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs#L710)), a missing auth ancestor is silently ignored (`if let Some(ev) = provider.get_event(&aid)`), which silently corrupts power-level/mainline ordering and iterative auth checks! A storage-backed `EventProvider` needs a fallible `try_resolve_state_maps_lazy` returning `Result<..., ProviderError>`.

### 2.3 `critic-compliance` (Matrix Spec & MSC Compliance Auditor)
- **`[Critical]` Violation of Matrix State Resolution v2 Auth-Chain Difference Definition (`resolve_state_maps_lazy`)**:
  - Under Matrix v2+ state resolution (Room Versions 2–11 and MSC4297/v12), the conflicted state subgraph $G(C)$ consists of the conflicted set $C$ unioned with the auth-chain difference $\text{auth\_diff}(U, C) = \bigcup_{c \in C} \text{auth}(c) \setminus \bigcup_{u \in U} \text{auth}(u)$ (or under MSC4297, the full conflicted subgraph seeded by $C \cup \text{auth\_diff}(U, C)$).
  - In [src/resolve/multi.rs:698-721](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs#L698-L721), when `precomputed_auth_diff` is `None`:
    ```rust
    while let Some(id) = queue.pop_front() {
        let Some(ev) = events_by_id.get(&id) else { continue };
        let auth_ids: Vec<Id> = ev.auth_events.clone();
        for aid in auth_ids {
            if visited.insert(aid.clone()) {
                if let Some(aev) = provider.get_event(&aid) {
                    if !conflicted_id_set.contains(&aid) {
                        auth_diff_events.push(aev.clone());
                    }
                    events_by_id.insert(aid.clone(), aev);
                    queue.push_back(aid);
                }
            }
        }
    }
    ```
  - Because `unconflicted_state` is never consulted to prune the BFS or exclude $\text{auth}(U)$, `auth_diff_events` accumulates **every ancestor in $\text{auth}(C)$** all the way back to `m.room.create`, including unconflicted power levels, join rules, and room creation events that belong to $\text{auth}(U)$! In `RoomVersionRules::v2_0()` (`include_full_conflicted_subgraph == false`), those extra unconflicted ancestors from $\text{auth}(U)$ are then passed into `resolve_conflicted_Set_with_rules` (`L739-747`), where non-power-level state events in `auth_diff` are fed into Phase 4 (`other_events`) and re-evaluated! Even when they don't change the winning state, they violate the spec definition of `auth_diff` and trigger catastrophic I/O amplification.

### 2.4 `critic-perf` (Performance & Memory Hierarchy Engineer)
- **`[Critical]` Unbounded Database Read Amplification in `resolve_state_maps_lazy` (`precomputed_auth_diff: None`)**:
  - In a long-lived room where two leaf branches disagree on a single member displayname (`|C| = 2`), the true auth difference $|\text{auth}(C) \setminus \text{auth}(U)|$ is `0` events (both events authenticate against the same shared join/PL events in $U$). However, calling `resolve_state_maps_lazy` ([src/resolve/multi.rs:640-646](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs#L640-L646)) walks the entire auth chain of the sender's membership and the room's power-level history back to `m.room.create`, turning 2 expected point lookups into dozens or hundreds of synchronous DB reads.
- **`[High]` `LeanEventCache` BTreeMap Churn on Every Hit**:
  - In [src/state/cache.rs:154-163](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/cache.rs#L154-L163), `LeanEventCache::bump_entry` executes `access.remove(&old_gen)` followed by `access.insert(gen, entry.event.event_id.clone())` on every `get` or `get_event` hit (`L121`, `L203`). Because `alloc::collections::BTreeMap` does not maintain an intrusive node free-list and `entry.event.event_id.clone()` clones `Id` (which for `String` allocates on the heap!), every cache hit incurs heap traffic and $O(\log N)$ tree manipulation.
- **`[Low]` `Chunk::union_assign` Allocation on `Array |= Array`**:
  - Commit `95a8ffb` optimized `Chunk::union_assign` ([rezzy-recon/src/bitmap/mod.rs:320-368](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/rezzy-recon/src/bitmap/mod.rs#L320-L368)) to use `(y & !*x).count_ones()` for `Dense |= Dense`, eliminating a 1,024-word popcount pass. However, for `(Store::Array(_), Store::Array(_))` (`L364-366`), it still executes `*self = self.union(other)`, allocating a brand-new `Vec<u16>` on every sparse bitmap union during `AuthGraph::build` ([src/auth/roaring.rs:92](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/auth/roaring.rs#L92)).

### 2.5 `critic-formal-crypto` (Formal Methods & Determinism Auditor)
- **`[Medium]` Non-Deterministic `DenseIndex` Assignment & Silent Cycle Omission in `AuthGraph::build`**:
  - In [src/auth/roaring.rs:46-79](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/auth/roaring.rs#L46-L79), `in_degree` is a `FastMap<&Id, usize>` (`foldhash`). Line `61` initializes the Kahn `queue` by iterating `&in_degree` in arbitrary `foldhash` bucket order, and `adjacency` lists are populated in slice order. Consequently, `sorted: Vec<Id>` and the resulting `DenseIndex<Id>` assign different `u32` indices across process invocations or architectures.
  - Because `AuthGraph::auth_difference` ([src/auth/roaring.rs:144-153](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/auth/roaring.rs#L144-L153)) returns `diff.iter().filter_map(|idx| self.index.get_id(idx).cloned()).collect()`, the returned `Vec<Id>` order depends directly on `DenseIndex` order. Furthermore, if `sort_context` contains a malformed cycle, Kahn's loop exits with `sorted.len() < sort_context.len()`, silently dropping the cyclic events from `self.index` so `auth_difference` silently ignores them (`L128`, `L137`).
- **`[Medium]` Non-Deterministic `conflicted_ids` Order in `partition_state_maps`**:
  - [src/resolve/multi.rs:141-155](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs#L141-L155) iterates `occurrences: FastMap<...>` to build `conflicted_ids: Vec<Id>`. While downstream `reverse_topological_power_sort` sorts deterministically, exposing a non-deterministically ordered `Vec<Id>` from `partition_state_maps` is an unnecessary determinism hazard for callers or trace logs.

### 2.6 `critic-federation-interop` (Federation & Production Operations Architect)
- **`[Critical]` Understated Adversarial Fork Scale & Storage Pitfalls (Audit #2)**:
  - [docs/architecture.md:202-211](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/architecture.md#L202-L211) classifies a "Catastrophic (netsplit)" fork as 10–50 conflicted keys (`|C| = 30–200`, `|auth_diff| = 100–500`, total subgraph `130–700` events) and concludes: *"Even in a catastrophic netsplit, the conflicted subgraph fits in L1/L2 cache (< 100 KB of event data). State resolution is CPU-bound on topological sorting and auth checks, never memory-bound."*
  - In production Matrix federation (e.g., Matrix.org / modular / tactical edge deployments during multi-day netsplits or asymmetric state-reset spam), conflicted state sets reach $|C| = 10^4\text{--}10^5$ events with $|\text{auth\_diff}| > 5 \times 10^4$. At that scale:
    1. Eager in-memory subgraphs allocate tens to hundreds of megabytes per room resolution task, risking OOM when multiple federated rooms resolve concurrently.
    2. Running synchronous CPU-heavy Kahn sorting and iterative auth checks on an async Tokio worker thread without `spawn_blocking` or cooperative yielding starves the homeserver's federation HTTP/TLS reactor.
    3. Persisting Roaring bitmaps in a homeserver's `shorteventid_authchain` table requires strict schema invariants: if a database compaction or backfill reassigns dense `u32` short event IDs without invalidating cached bitmaps, `AuthGraph::auth_difference` will silently compute garbage auth differences and cause permanent federation split-brain.

### 2.7 `critic-redteam-qa` (Adversarial Security & QA Red-Teamer)
- **`[High]` Byzantine Wire-Depth Manipulation Against `compute_auth_chain_diff`**:
  - [src/state/at.rs:1718-1799](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L1718-L1799) implements the bounded dual-heap auth-chain difference (`compute_auth_chain_diff`) by ordering `u_heap` and `c_heap` by `ev.depth`:
    ```rust
    let c_depth = c_heap.peek().map_or(0, |e| e.depth);
    while let Some(u_top) = u_heap.peek() {
        if u_top.depth < c_depth {
            break;
        }
        ...
    ```
  - In Matrix federation, `depth` is an untrusted `u64` field chosen by the originating homeserver (as `rezzy` itself acknowledges in `find_depth_divergences` at [src/state/at.rs:2164-2177](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L2164-L2177)).
  - **Attack Vector 1 (DoS Amplification)**: A Byzantine server injects a conflicted state event $c \in C$ with `depth = 0` (while its parents have normal depth $10^5$). Because `c_depth` drops to `0`, the `while u_top.depth >= c_depth` loop immediately drains the **entire** `u_heap` all the way to `m.room.create`, defeating the bounded dual-heap optimization and forcing $O(|\text{auth}(U)|)$ traversal on every conflict!
  - **Attack Vector 2 (Over-Approximation / Missed Pruning)**: A Byzantine server crafts an event $u \in U$ with `depth = 0` whose `auth_events` point to high-depth ancestors (`depth = 50,000`). While `c_heap` pops events at `depth = 50,000..1`, `u_top.depth` is stuck at `0 < c_depth`, so $u$ is never popped to mark its high-depth ancestors in `u_visited`! Those shared ancestors are then falsely emitted in `result` as part of $\text{auth}(C) \setminus \text{auth}(U)$.

### 2.8 `critic-dx-integrator` (Homeserver Integrator & Developer Experience)
- **`[High]` `LeanEventCache` Cannot Be Shared Across Threads Without Exclusive Locking**:
  - Homeservers run multi-threaded async executors (`tokio::runtime::Runtime`). Because `LeanEventCache` ([src/state/cache.rs:85-96](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/cache.rs#L85-L96)) uses `RefCell<BTreeMap<u64, Id>>` and `Cell<u64>` to mutate LRU state inside `EventProvider::get_event(&self)` (`L198-206`), `LeanEventCache` is `!Sync`. Integrators cannot wrap it in an `Arc<RwLock<LeanEventCache>>` for concurrent read access; every `get_event` call across the entire homeserver must serialize through a global `Mutex` or instantiate per-task caches.
- **`[Medium]` `ADJACENCY_MASK` Omissions in `src/raw_event.rs`**:
  - [src/raw_event.rs:32-46](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/raw_event.rs#L32-L46) defines `ADJACENCY_MASK` for zero-copy two-phase extraction (`event_id`, `prev_events`, `auth_events`, `type`, `state_key`, `content`, `redacts`, `unsigned`). However, state resolution tie-breaking (`reverse_topological_power_sort` and `mainline_sort`) and auth checks also require `sender`, `origin_server_ts`, and `depth`! An integrator using `MatrixEventView` ([src/raw_event.rs:88-91](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/raw_event.rs#L88-L91)) to feed state resolution cannot extract `sender` or `origin_server_ts` without modifying `ADJACENCY_MASK` or re-scanning the raw JSON bytes.

---

## 3. Concrete Stage B Remediation Recommendations

1. **Fix `resolve_state_maps_lazy_with_diff` Unconflicted Boundary (`[Critical]` — F-07-01)**:
   - When `precomputed_auth_diff` is `None` in [src/resolve/multi.rs:698-721](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs#L698-L721), compute the unconflicted auth chain (either via `compute_auth_chain_diff` over `provider` or by seeding an `unconflicted_visited` set from `unconflicted_state.values()` and walking their `auth_events` alongside `conflicted_events`) so that $\text{auth}(U)$ ancestors are never included in `auth_diff_events`.
   - Add a regression test asserting that `resolve_state_maps_lazy` (`precomputed_auth_diff = None`) produces the exact same `auth_diff_events` set and `provider.get_event` call count as `compute_auth_chain_diff`.
2. **Revise `docs/architecture.md` Fork Scale Claims & Add Operational Guardrails (`[Critical]` — F-07-02 / Audit #2)**:
   - Update [docs/architecture.md:202-215](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/architecture.md#L202-L215) to distinguish routine forks ($10^2\text{--}10^3$ events) from real-world adversarial/netsplit forks ($10^4\text{--}10^5$ events).
   - Document required homeserver mitigation strategies: `spawn_blocking` isolation for large conflicted sets, subgraph cardinality budgets/circuit breakers, and strict immutability invariants for persisted `shorteventid_authchain` Roaring bitmaps.
3. **Harden `compute_auth_chain_diff` Against Non-Monotonic Wire `depth` (`[High]` — F-07-03)**:
   - In [src/state/at.rs:1718-1799](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L1718-L1799), enforce monotonic effective depth on heap push (`effective_depth = child_effective_depth.min(parent.depth)`) or verify at termination that all $U$-ancestors reachable from any lower-depth $U$-node have been subtracted from `result`, and cap maximum visited nodes via a configurable budget.
4. **Reconcile `docs/homeserver_utilities.md` (`[High]` — F-07-04 / Audit #8)**:
   - Either implement `src/validate.rs` and `compute_dag_health` (`src/fork.rs`) or clearly move Sections 3 and 5 of [docs/homeserver_utilities.md](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/homeserver_utilities.md) into a dedicated "Planned / Roadmap Utilities" section so integrators do not mistake them for shipping APIs.
5. **Migrate `find_forward_extremities_roaring` to `DenseIndex` & Make `AuthGraph::build` Deterministic (`[Medium]` — F-07-07, F-07-08)**:
   - Replace the manual `id_map`/`reverse_map` in [src/state/at.rs:2754-2773](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L2754-L2773) with `DenseIndex::try_build`.
   - Sort initial zero-in-degree nodes in `AuthGraph::build` ([src/auth/roaring.rs:61](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/auth/roaring.rs#L61)) and assert/handle `sorted.len() == sort_context.len()` when cycles are present.
