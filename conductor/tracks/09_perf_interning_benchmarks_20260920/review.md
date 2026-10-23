# Track 09 Review & 8-Persona Critique: Performance Audits, StateKey Interning, DenseIndex & Benchmark Suite

- **Track ID**: `09_perf_interning_benchmarks_20260920`
- **Commit Range**: `5384219..0d0a87d` (`2026-09-20` – `2026-10-08`)
- **Review Date**: `2026-10-23`
- **Status**: Completed (Reverse-Engineered Historical Track — Audited for Stage B Remediation)

---

## 1. Conductor Review Summary (`/conductor-review`)

### 1.1 Plan & Spec Compliance Verification
| Phase / Task | Commit(s) | Verification Status | Notes |
| :--- | :--- | :--- | :--- |
| **Phase 1: Core Resolver & Tie-Break Optimizations (`FastMap`, `DenseIndex`, `kahn_order_by`)** | `5384219`, `30d157d`, `a668d21`, `3c123c6`, `09db609`, `7f41793`, `ca861fb`, `09b1a5b` | ⚠️ **Implemented with HashDoS & Bounded-Iterator Bugs** | `FastMap`/`FastSet` ([src/lib.rs:206-213](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/lib.rs#L206-L213)) expose non-cryptographic `foldhash` to untrusted federation keys (**Audit #12 High**); `DenseIndex::try_build_bounded` ([src/dense_index.rs:168-204](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/dense_index.rs#L168-L204)) fails to short-circuit on overflow, consuming the entire iterator into a `HashSet`! |
| **Phase 2: `StateKey` Interning (`InternedKey`, `Interner`, `FastSharedState`)** | `01e1c67`, `a8f0c81`, `2a773c4` | ⚠️ **Implemented with Parallel Regression & `InternId` Bug** | `InternedKey` (`Arc<str>`) regresses by `+3%` to `+16%` at 5,000+ members under `std::thread::scope` (**Audit #16 High**), yet `FastSharedState` rustdoc omits this warning; worse, `InternId<'a>` in [src/basespec/interned_key.rs:155-170](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/basespec/interned_key.rs#L155-L170) implements `Ord` and `Hash` via string dereference instead of $O(1)$ integer rank! |
| **Phase 3: Persistent Tree vs. HAMT Benchmarks & Documentation Audits** | `41eb3e6`, `43de237`, `eb39747`, `0d0a87d` | ⚠️ **Audit #5 (Low), #12 (High), #16 (High) Open** | `docs/perf_audits.md` and `docs/tech_debt.md` are candid and thorough, but `docs/format.sh` lacks strict shell safety and pinned formatter versions (**Audit #5 Low**). |

### 1.2 Executive Findings Matrix
| ID | Severity | Persona | Location | Summary |
| :--- | :--- | :--- | :--- | :--- |
| **F-09-01** | `[High]` | `critic-redteam-qa` / `critic-formal-crypto` | [src/lib.rs:197-213](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/lib.rs#L197-L213), [src/resolve/multi.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs), [src/resolve/iterative.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/iterative.rs) | **Audit #12**: `FastMap` and `pub type FastSet` use `hashbrown::DefaultHashBuilder` (`foldhash`, non-cryptographic) on federation-controlled `EventId`, `state_key`, and `sender` strings, creating a HashDoS collision vector if seed material is leaked or weak on `no_std`/WASM targets. |
| **F-09-02** | `[High]` | `critic-redteam-qa` / `critic-perf` | [src/dense_index.rs:168-204](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/dense_index.rs#L168-L204) | `DenseIndex::try_build_bounded` does **not** short-circuit when `items.len() >= bound`: instead, lines `169-203` allocate a new `post_bound: HashSet<T>` and exhaust the entire remaining iterator just to populate `IndexTooLarge::distinct_count`! |
| **F-09-03** | `[High]` | `critic-perf` / `critic-dx-integrator` | [src/basespec/rezzy_types.rs:2245](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/basespec/rezzy_types.rs#L2245), [src/state/at.rs:363-381](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L363-L381), [docs/tech_debt.md:82-88](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/tech_debt.md#L82-L88) | **Audit #16**: `InternedKey(Arc<str>)` degrades by `+3%` to `+16%` at 5,000+ room members under `std::thread::scope` due to cross-core atomic refcount cache-line bouncing, yet `FastSharedState`'s public rustdoc recommends it unconditionally without warning about parallel contention. |
| **F-09-04** | `[High]` | `critic-eng-lead` / `critic-perf` | [src/basespec/interned_key.rs:110-170](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/basespec/interned_key.rs#L110-L170) | `InternId<'a>` contradicts its own doc comment (`L110`: "`Ord` by rank") and `docs/tech_debt.md:72-81`: its `Ord` (`L155-162`) and `Hash` (`L163-170`) implementations dereference the `Rc<str>` and compare/hash full string bytes (`self.as_ref().cmp(other.as_ref())`) instead of comparing the `u32` rank, and `Interner` uses `Rc<str>` (`!Send`, `!Sync`). |
| **F-09-05** | `[Medium]` | `critic-redteam-qa` / `critic-perf` | [src/state/persistent_ord_map.rs:14-26, 94-98](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/persistent_ord_map.rs#L14-L26) | `PersistentOrdMap::remove` never rebalances under-full non-root nodes (`L14-16`). Adversarial insert+remove churn can leave internal/leaf nodes with 1 entry each, degrading tree height and node memory density. |
| **F-09-06** | `[Medium]` | `critic-eng-lead` | [docs/tech_debt.md:36-48](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/tech_debt.md#L36-L48), [src/dense_index.rs:103](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/dense_index.rs#L103) | `DenseIndex` migration is incomplete (3 call sites remain unmigrated: `collect_ancestor_short_ids_batch`, `index_by_event_id`, and `find_forward_extremities_roaring`), and `DenseIndex` uses `crate::HashMap` (`SipHash13`) while its callers use `FastMap`. |
| **F-09-07** | `[Medium]` | `critic-compliance` / `critic-federation-interop` | [rezzy-cli/src/timeline_order.rs:187-235](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/rezzy-cli/src/timeline_order.rs#L187-L235) | `kahn_order_by` appends cyclic remainder nodes at the end sorted by `(key, id)` (`L228-233`) without signaling to the caller that the timeline DAG contained a cycle. |
| **F-09-08** | `[Low]` | `critic-eng-lead` | [docs/format.sh:1-4](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/format.sh#L1-L4) | **Audit #5**: `docs/format.sh` uses `#!/bin/bash -x` without `set -euo pipefail` and invokes an unpinned global `prettier` binary. |

---

## 2. Multi-Perspective Critique (8 Specialized Personas)

### 2.1 `critic-pm` (Product Manager — Roadmap, Scope & Public Narrative Coherence)
- **`[High]` Contradictory Guidance Between Public Rustdoc (`FastSharedState`) and `docs/tech_debt.md` (Audit #16)**:
  - In [src/state/at.rs:363-381](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L363-L381), the public API documentation for `FastSharedState = SharedState<Arc<str>, InternedKey>` tells homeserver integrators:
    > *"For bulk batch operations, pair with [`intern_events`](crate::intern_events) to deduplicate `event_id` and `state_key` allocations upfront (`~0.56x–0.68x` full resolution time vs `SharedState<String>`)."*
  - Meanwhile, [docs/tech_debt.md:82-88](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/tech_debt.md#L82-L88) and [benches/state/interned_key.rs:28-38](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/benches/state/interned_key.rs#L28-L38) prove that `InternedKey(Arc<str>)` is **3%–16% slower** than plain `String` in parallel `std::thread::scope` resolution at $\ge 5,000$ members! A homeserver developer reading the rustdoc will adopt `FastSharedState` for large parallel rooms and suffer a silent throughput regression.

### 2.2 `critic-eng-lead` (Engineering Lead — Architecture, `#![no_std]` Hygiene & Tech Debt)
- **`[High]` `src/basespec/interned_key.rs` (`InternId<'a>`) Does Not Actually Implement Rank-Based `Ord` or `Hash`**:
  - [docs/tech_debt.md:72-81](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/tech_debt.md#L72-L81) and the doc comment on `InternId<'a>` ([src/basespec/interned_key.rs:107-111](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/basespec/interned_key.rs#L107-L111)) state:
    > *"After [`Interner::seal`], every `InternId<'a>` has a `u32` rank assigned in lexicographic order... `Copy`, `Eq`/`Ord`/`Hash` by rank, `AsRef<str>` via the sealed table."*
  - Now inspect the actual implementation in [src/basespec/interned_key.rs:147-170](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/basespec/interned_key.rs#L147-L170):
    ```rust
    impl PartialOrd for InternId<'_> {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for InternId<'_> {
        fn cmp(&self, other: &Self) -> Ordering {
            self.as_ref().cmp(other.as_ref())
        }
    }
    impl Hash for InternId<'_> {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.as_ref().hash(state);
        }
    }
    ```
  - Despite `Interner::seal` sorting `unique` lexicographically so that `self.rank.cmp(&other.rank)` is order-isomorphic to string comparison, `InternId::cmp` and `InternId::hash` **ignore `self.rank` completely**, chasing two pointers (`self.table[self.rank as usize]` $\to$ `Rc<str>` $\to$ `&str`) and comparing/hashing the full string bytes on every `BTreeMap` lookup!
  - Furthermore, `Interner` ([src/basespec/interned_key.rs:31-34](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/basespec/interned_key.rs#L31-L34)) stores `Vec<Rc<str>>`, making `Interner` and `InternId<'a>` `!Send` and `!Sync`, so they cannot be shared across threads in `std::thread::scope`! (In contrast, the benchmark prototype in [benches/state/interned_key.rs:69](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/benches/state/interned_key.rs#L69) used `#[derive(Ord, Hash)] pub struct InternId(u32)` with zero pointer chasing, which is why the benchmark showed a 13%–21% speedup while the library type in `src/basespec/interned_key.rs` does not!)
- **`[Low]` Shell Script Hygiene in `docs/format.sh` (Audit #5)**:
  - [docs/format.sh:1-4](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/format.sh#L1-L4) uses `#!/bin/bash -x` without `set -euo pipefail` and calls unpinned `prettier --prose-wrap always --print-width 80 --write .`.

### 2.3 `critic-compliance` (Matrix Spec & MSC Compliance Auditor)
- **`[Medium]` Lexicographic Equivalence Required for Custom `StateKey` Types**:
  - Matrix State Resolution v2 (`reverse_topological_power_sort` and `PersistentOrdMap<(EventType, K), Id>`) does not mandate a specific ordering on `(EventType, K)` for Phase 1 partitioning, provided `Eq`/`Ord` define a strict total order. However, any diagnostic or canonical serialization that iterates `(EventType, K)` expects lexicographic `(type, state_key)` order. Because `Interner::seal` ([src/basespec/interned_key.rs:67-89](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/basespec/interned_key.rs#L67-L89)) sorts unique strings lexicographically before assigning `rank: u32`, comparing `self.rank.cmp(&other.rank)` preserves exact lexicographic `str` ordering *provided both `InternId`s originate from the same `Interner` instance*.

### 2.4 `critic-perf` (Performance & Memory Hierarchy Engineer)
- **`[High]` Unbounded Work in `DenseIndex::try_build_bounded` When Bound Is Exceeded**:
  - Look closely at [src/dense_index.rs:164-205](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/dense_index.rs#L164-L205):
    ```rust
    for item in iter {
        if forward.contains_key(&item) {
            continue;
        }
        if items.len() >= bound {
            let mut post_bound: crate::HashSet<T> = crate::HashSet::new();
            post_bound.insert(item);
            for rest in iter {
                if !forward.contains_key(&rest) {
                    post_bound.insert(rest);
                }
            }
            let distinct_count = items.len().saturating_add(post_bound.len());
            return Err(IndexTooLarge { distinct_count, max });
        }
        ...
    ```
  - The entire purpose of a `try_build_bounded(iter, bound)` API is to bound memory and CPU consumption when an input stream contains more than `bound` distinct items. Yet the moment `items.len() >= bound` is reached, `try_build_bounded` **allocates a brand-new `HashSet<T>` (`post_bound`) and consumes the entire rest of the iterator** inserting every remaining distinct element into `post_bound` just to compute `distinct_count` for the error message! If `bound = 256` (`u8`) and an iterator yields $1,000,000$ distinct IDs, `try_build_bounded` allocates a 1,000,000-element `HashSet` before returning `Err`!
- **`[High]` `Arc<str>` Atomic Contention Under `std::thread::scope` (Audit #16)**:
  - Each `PersistentOrdMap` lookup, clone, or node split clones `(EventType, K)`. When `K = InternedKey(Arc<str>)`, all threads resolving chunks in `std::thread::scope` execute `lock xadd` (`fetch_add`/`fetch_sub`) on the shared `ArcInner` header cache line for hot state keys (such as `""` on room-level state events or frequent member IDs). Under MESI/MOESI cache coherency protocols on 8+ cores, this invalidates L1/L2 cache lines across cores on every key clone/drop, explaining the `+3%` to `+16%` slowdown measured in [benches/state/interned_key.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/benches/state/interned_key.rs).

### 2.5 `critic-formal-crypto` (Formal Methods & Hash Security Auditor)
- **`[High]` Non-Cryptographic `foldhash` (`FastMap`/`FastSet`) on Untrusted Federation Inputs (Audit #12)**:
  - [src/lib.rs:197-213](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/lib.rs#L197-L213) defines `FastMap` and `pub type FastSet` using `hashbrown::DefaultHashBuilder` (`foldhash`). The comment at `L197-199` states:
    > *"`foldhash` gives us a fast, minimally DoS-resistant, non-cryptographic default... we do not treat it as a security boundary."*
  - However, `FastMap` and `FastSet` are keyed directly by **adversary-controlled federation strings**:
    1. `sender` and `state_key` (chosen arbitrarily by remote users/homeservers) in `partition_state_maps` ([src/resolve/multi.rs:100](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/multi.rs#L100)) and `apply_events_iteratively` ([src/resolve/iterative.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/iterative.rs)).
    2. `EventId` (`$base64_sha256` in v4+, or arbitrary `$localpart:domain` in legacy v1/v2 or custom test/federation harnesses) in `reverse_topological_power_sort` ([src/resolve/sorting.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/resolve/sorting.rs)), `AuthGraph::build` ([src/auth/roaring.rs:46-47](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/auth/roaring.rs#L46-L47)), and `state/at.rs`.
  - Furthermore, on `#![no_std]` targets (where `default-features = false`), `foldhash` does not have OS randomness to randomize per-process seeds unless explicitly seeded, making `FastMap` bucket collisions completely deterministic and offline-computable!

### 2.6 `critic-federation-interop` (Federation & Production Operations Architect)
- **`[Medium]` Silent Cycle Fallback in `rezzy-cli/src/timeline_order.rs`**:
  - In [rezzy-cli/src/timeline_order.rs:187-235](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/rezzy-cli/src/timeline_order.rs#L187-L235) (commit `7f41793`), `kahn_order_by` resolves ties deterministically via `Reverse((&keys[index], &ids[index], index))`, and if `order.len() < node_count` (`L228`), it sorts the remaining cyclic nodes by `(key, id)` and appends them to `order`. While deterministic, a cycle in `prev_events` or `auth_events` is a critical protocol anomaly in Matrix federation; silently appending cyclic nodes without incrementing a diagnostic counter or logging a warning hides DAG corruption during CLI inspection.

### 2.7 `critic-redteam-qa` (Adversarial Security & QA Red-Teamer)
- **`[High]` CPU/Memory Exhaustion via `DenseIndex::try_build_bounded` Overflow Path**:
  - As detailed in **F-09-02**, an attacker supplying an oversized stream of distinct IDs to a bounded `DenseIndex::try_build_bounded` call bypasses the `bound` memory cap because the error-reporting path (`L169-203`) materializes all remaining distinct items in `post_bound: HashSet<T>`.
- **`[Medium]` Pathological Under-Full Node Chains in `PersistentOrdMap::remove`**:
  - In [src/state/persistent_ord_map.rs:14-16](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/persistent_ord_map.rs#L14-L16), `PersistentOrdMap` documents that `remove` never rebalances under-full non-root nodes (`MAX_FANOUT = 24`). While standard Matrix state events cannot be "deleted" from a room's state map (redacting or leaving overwrites the key with a new event rather than removing the key from `SharedState`), `PersistentOrdMap::remove` is a `pub` API ([src/state/persistent_ord_map.rs:195](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/persistent_ord_map.rs#L195)). If an external consumer uses `PersistentOrdMap::remove` in a workload that repeatedly inserts 24 keys per leaf and deletes 23 of them, the tree degrades to 1 entry per 24-slot node ($4\%$ occupancy) and grows in height without bound (eventually overflowing `height: u8` or exhausting RAM).

### 2.8 `critic-dx-integrator` (Homeserver Integrator & Developer Experience)
- **`[High]` Confusing Overlapping Interning APIs (`InternedKey` vs. `Interner`/`InternId<'a>`)**:
  - `rezzy` currently exposes two incompatible interning mechanisms:
    1. `InternedKey(Arc<str>)` + `intern_events` ([src/basespec/rezzy_types.rs:2245-2385](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/basespec/rezzy_types.rs#L2245-L2385)): `Send + Sync + 'static`, `Ord` by `u64` prefix + string fallback, suffers atomic refcount contention under parallel resolution.
    2. `Interner` + `InternId<'a>` ([src/basespec/interned_key.rs:31-170](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/basespec/interned_key.rs#L31-L170)): `Copy` 12-byte handle (`&'a [Rc<str>]` + `u32`), `!Send + !Sync` due to `Rc<str>`, and accidentally compares/hashes by string dereference instead of `u32` rank!
  - Neither achieves the design goal stated in [docs/tech_debt.md:72-88](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/tech_debt.md#L72-L88): a `Copy + Send + Sync` `u32` rank token backed by a scoped `&[&str]` or `&[Box<str>]` table that compares and hashes in $O(1)$ via its `u32` rank with zero atomic traffic.

---

## 3. Concrete Stage B Remediation Recommendations

1. **Fix `Interner` & `InternId<'a>` to Use `Box<str>` (`Send + Sync`) and $O(1)$ `u32` Rank `Ord`/`Hash` (`[High]` — F-09-03, F-09-04 / Audit #16)**:
   - In [src/basespec/interned_key.rs](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/basespec/interned_key.rs):
     1. Replace `Rc<str>` with `Box<str>` (or `&'a str`) in `Interner`'s sealed table so `Interner` and `InternId<'a>` are `Send + Sync` and work seamlessly inside `std::thread::scope` parallel state resolution!
     2. Change `InternId::cmp` (`L156`) to `debug_assert!(core::ptr::eq(self.table, other.table)); self.rank.cmp(&other.rank)` and `InternId::hash` (`L165`) to `self.rank.hash(state)` (with `PartialEq` comparing `self.rank == other.rank`).
     3. Update the rustdoc on `FastSharedState` ([src/state/at.rs:363-381](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/state/at.rs#L363-L381)) to warn about `Arc<str>` atomic contention at $\ge 5,000$ members under multi-threaded resolution and point parallel callers to scoped `InternId<'a>`.
2. **Mitigate `FastMap`/`FastSet` HashDoS Exposure (`[High]` — F-09-01 / Audit #12)**:
   - Un-export `pub type FastSet` from the public crate root ([src/lib.rs:213](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/lib.rs#L213) $\to$ `pub(crate) type FastSet`), or gate `foldhash` behind an explicit feature/per-process cryptographic seed while defaulting untrusted federation-string maps (`state_key`, `sender`, unvalidated `EventId`) to a DoS-resistant seeded hasher (`SipHash13` or a per-process CSPRNG-seeded `foldhash::quality::RandomState`).
   - For maps keyed by `DenseIndex` `u32` indices or `InternId` `u32` ranks, integer keys need no string hashing at all (or can use `Vec<Option<V>>` / `Bitmap` indexing directly).
3. **Short-Circuit `DenseIndex::try_build_bounded` Immediately on Overflow (`[High]` — F-09-02)**:
   - In [src/dense_index.rs:168-204](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/src/dense_index.rs#L168-L204), remove the `post_bound: HashSet<T>` loop that drains the remainder of `iter`. Return `Err(IndexTooLarge { distinct_count: bound + 1, max })` (or rename the field `min_distinct_count_observed`) immediately in $O(1)$ as soon as the $(bound + 1)$-th distinct item is encountered.
   - Complete the remaining 3 `DenseIndex` migrations (`collect_ancestor_short_ids_batch`, `index_by_event_id`, and `find_forward_extremities_roaring`).
4. **Harden `docs/format.sh` (`[Low]` — F-09-08 / Audit #5)**:
   - Update [docs/format.sh](file:///Users/jonathan/Code/Shane/rezzy.worktrees/conductor-hub/docs/format.sh) to start with `#!/usr/bin/env bash` and `set -euo pipefail`, and pin the `prettier` version (or check for its presence cleanly).
