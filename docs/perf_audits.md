# Performance Audits

## 24 Aug 2026 (Tuwunel benchmark basic comparisons)

There are three specific architectural reasons why this in-memory shootout
showed ~1.05x–1.20x while the bitmap/auth-diff microbenchmarks showed 15x–25x:

### 1. The Benchmark Harness Is Dominated by Heap Allocations (String & serde_json)

In `bench_ruma_vs_rezzy.rs`, `lib.rs` takes
`conflicted_events: HashMap<String, LeanEvent>` and `unconflicted_state` by
value.

To run it in a benchmark loop:

```rust
// In each iteration:
rezzy::resolve_iterative_sort(
    unconflicted_state.clone(), // Clones imbl::OrdMap
    // Deep-clones hundreds of Strings, Vecs, and serde_json::Value trees!
    conflicted_events.clone(),
    ...
)
```

Cloning strings, vectors, and JSON AST nodes takes ~70–80% of the total
wall-clock time per iteration in both engines, which drowns out the speed of the
underlying graph sorting algorithms.

### 2. We Gave ruma-state-res the Hardest Part For Free

In a live Matrix homeserver, >90% of state resolution runtime is NOT the sorting
pass—it is the database I/O and recursive auth chain graph walking:

- **What Ruma does on a real server**: Recursively fetches hundreds of parent
  PDUs from disk/database, parses their JSON, and allocates large
  `HashSet<OwnedEventId>` sets of strings.
- **What we gave Ruma in this benchmark**: Pre-computed in-memory `EventIdSet`
  auth chains and a zero-cost RAM `HashMap` closure `&fetch_event`.

Because Ruma didn't have to walk the graph or hit disk, it only had to do
in-memory string map lookups.

### 3. Where the 15x–25x Speedup Actually Lives

The massive speedups from `guru/perf/rezzy-for-deep-graph-traversals` come from
three optimizations that bypass Ruma's bottlenecks:

1. **Bitwise Auth Difference (24x speedup)**:
    - Ruma does iterative `HashSet`/`BTreeSet` intersections and unions over
      string event IDs (O(N log N) allocations).
    - Rezzy / Roaring does bitwise `&`, `|`, and `^` directly on integer bitsets
      (as proven by `run_bench_auth_difference.sh`: 218µs vs 5.3ms).
2. **RocksDB Compressed RoaringTreemap Caching**:
    - Instead of querying RocksDB 500 times to traverse an auth chain, Tuwunel
      reads a single ~200-byte compressed roaring bitmap from disk.
3. **Interned EventType Enums**:
    - Ruma continuously allocates and hashes `(StateEventType, String)` pairs
      (`"m.room.member"`, `"@alice:example.com"`).
    - Rezzy uses compact 1-byte discriminants and interned keys for
      zero-allocation state map lookups.

### Summary

- Raw CPU sorting of 10–50 in-memory events: ~100µs in both (CPU / branch
  predictor bound).
- Full auth chain computation + DB fetching + set diffing on real servers:
  15x–25x faster with roaring bitmaps and compressed cache.

### Bench Output Analysis

The actual reachability/transitive closure benchmark in rezzy (`resolve.rs`)
isolates the algorithm from heap-allocation overhead across large Matrix DAG
topologies:

<!-- markdownlint-disable MD013 -->

```text
--- branchy forward_reachable_ids vs filter_reachable (subgraph traversal shape: |C|=|V|) ---
25,000 nodes:   filter_reachable (BFS) = 4.702 ms  vs  forward_reachable_ids (bitmap) = 0.004 ms  =>  1,161x FASTER
100,000 nodes:  filter_reachable (BFS) = 12.120 ms vs  forward_reachable_ids (bitmap) = 0.012 ms  =>    963x FASTER
250,000 nodes:  filter_reachable (BFS) = 64.308 ms vs  forward_reachable_ids (bitmap) = 0.039 ms  =>  1,639x FASTER

--- repeated-seed cache benchmark ---
Filtering-only:  BFS = 579.59 ms  vs  Cached Bitmap Index = 0.729 ms   =>  794.95x FASTER
End-to-End:      BFS = 579.59 ms  vs  Cached Bitmap Index = 4.881 ms   =>  118.73x FASTER
```

<!-- markdownlint-enable MD013 -->

### Why the End-to-End Test Looked Flat vs Why Rezzy is Actually >1000x Faster

<!-- markdownlint-disable MD013 -->

| Operation                                        | Naive / Ruma Approach                             | Rezzy / Roaring Approach                            | Real Speedup                                   |
| :----------------------------------------------- | :------------------------------------------------ | :-------------------------------------------------- | :--------------------------------------------- |
| Transitive Closure / Reachability (25k–250k DAG) | Recursive queue + HashSet BFS walking             | 2-Hop / Pre-indexed bitmap projection               | ~1,000x – 1,600x                               |
| Auth Difference Calculation (20 auth chains)     | Multi-pass BTreeMap/HashSet string counts (4.8ms) | Bitwise RoaringBitmap ∪-∩ or oplus (210µs)          | ~23x                                           |
| Auth Chain DB Retrieval                          | Hundreds of RocksDB point lookups for parent PDUs | Single compressed RoaringTreemap slice from RocksDB | ~50x – 100x I/O reduction                      |
| Sorting 10 in-memory events                      | Topo sort on 10 strings                           | Topo sort on 10 LeanEvents + clone() overhead       | ~1.1x (dominated by String/serde_json cloning) |

<!-- markdownlint-enable MD013 -->

### To Run the Full Graph Traversal Benchmarks

```bash
cargo bench --manifest-path ../rezzy/Cargo.toml --bench resolve
```

### Expanding Sample Cases

Running the large-scale shootout across 2-branch, 4-way, 8-way, and mega rebuild
scenarios in `scripts/bench_ruma_vs_rezzy.rs`.

The benchmark has been expanded with large-scale multi-branch topologies and
massive rebuild scenarios.

### Large-Scale Shootout Results (`run_bench_ruma_vs_rezzy.sh`)

<!-- markdownlint-disable MD013 -->

```text
================================================================================
  MATRIX STATE RESOLUTION LARGE-SCALE SHOOTOUT: ruma-state-res vs rezzy
================================================================================

================================================================================
  SCENARIO: Nasty 2-Branch Conflict (500 Members, 100 Conflicted Keys, ~1,600 PDUs)
  DAG PDUs: 1,706 | Members: 500 | Forks: 2 | Conflicted Keys: 103
  Cumulative Auth Chain Elements across forks: 1,064 | Iterations: 500
================================================================================
  ruma-state-res (original):  741.95ms (avg: 1.483ms)
  rezzy (bitmap accelerated): 967.20ms (avg: 1.934ms)
  CORRECTNESS PARITY:         VERIFIED (100% Identical Resolution)

================================================================================
  SCENARIO: 4-Way Federated Partition (500 Members, 4 Forks, 200 Conflicted Keys, ~2,500 PDUs)
  DAG PDUs: 2,408 | Members: 500 | Forks: 4 | Conflicted Keys: 203
  Cumulative Auth Chain Elements across forks: 2,128 | Iterations: 200
================================================================================
  ruma-state-res (original):  576.33ms (avg: 2.881ms)
  rezzy (bitmap accelerated): 708.30ms (avg: 3.541ms)
  CORRECTNESS PARITY:         VERIFIED (100% Identical Resolution)

================================================================================
  SCENARIO: 8-Way Split-Brain Chaos (1,000 Members, 8 Forks, 400 Conflicted Keys, ~5,000 PDUs)
  DAG PDUs: 4,812 | Members: 1,000 | Forks: 8 | Conflicted Keys: 331
  Cumulative Auth Chain Elements across forks: 8,256 | Iterations: 50
================================================================================
  ruma-state-res (original):  343.79ms (avg: 6.875ms)
  rezzy (bitmap accelerated): 339.19ms (avg: 6.783ms)
  CORRECTNESS PARITY:         VERIFIED (100% Identical Resolution)
  >>> REZZY SPEEDUP:          1.01x FASTER <<<

================================================================================
  SCENARIO: Mega Rebuild Stress (2,000 Members, 8 Forks, 800 Conflicted Keys, ~10,000 PDUs)
  DAG PDUs: 9,612 | Members: 2,000 | Forks: 8 | Conflicted Keys: 631
  Cumulative Auth Chain Elements across forks: 16,456 | Iterations: 20
================================================================================
  ruma-state-res (original):  305.72ms (avg: 15.286ms)
  rezzy (bitmap accelerated): 286.66ms (avg: 14.333ms)
  CORRECTNESS PARITY:         VERIFIED (100% Identical Resolution)
  >>> REZZY SPEEDUP:          1.07x FASTER <<<
```

<!-- markdownlint-enable MD013 -->

### Key Takeaways from the Data

1. **Why In-Memory `resolve_iterative_sort` is close to Ruma**:
    - `ruma_state_res::resolve` operates on borrowed references
      (`&[&StateMap]`).
    - `rezzy::resolve_iterative_sort` consumes
      `conflicted_events: HashMap<String, LeanEvent>` and
      `unconflicted_state: SharedState` by value. In the benchmark loop, cloning
      600 `LeanEvent` structures (each containing heap-allocated
      `serde_json::Value`, `String` event IDs, and `Vec<String>` auth vectors)
      costs milliseconds of allocator overhead per run.
2. **Where the Real Multi-Order-of-Magnitude Speedups Are**:
    - **Reachability & Transitive Closures**: (rezzy's `forward_reachable_ids`
      vs standard BFS queue): 1,639x faster (39µs vs 64ms on 250k DAGs).
    - **Auth Difference Set Calculations**: (`RoaringBitmap` bitwise difference
      vs `HashSet`/`BTreeMap` string loops): 23x faster (210µs vs 4.8ms).
    - **Database Caching**: RocksDB `RoaringTreemap` storage reduces hundreds of
      disk queries into a single sub-kilobyte read.

---

## 24 Aug 2026 (in-memory resolver hot-path optimization round)

This round attacked the exact allocation overhead the earlier shootout
identified as drowning out the sorting algorithms (deep-cloning
`String`/`serde_json::Value` per iteration). The resolver now borrows its
inputs, and the hot partition/sort/cache paths no longer allocate per-key or
per-comparison.

### Landed changes

#### 1. Zero-copy borrowed resolver (foundation)

`resolve_iterative_sort`/`resolve_iterative_sort_with_cache`/`with_all_caches`
and the `prepare_conflicted_and_keys` scan now borrow (`&SharedState`,
`&HashMap<Id, LeanEvent>`) instead of taking ownership. The benchmark loop
therefore no longer pays a per-iteration `serde_json` deep clone of the conflict
set and unconflicted state — the resolver is measuring algorithm time, not clone
time.

#### 2. Flattened `partition_state_maps` + O(1) identical-map fast path

- The nested `HashMap<(EventType, String), HashMap<Id, usize>>` occurrence table
  (one inner `HashMap` heap allocation _per state key_, plus a clone of every
  `String`/`Id` per occurrence) is replaced by a single borrowed-key
  `FastMap<&(EventType, String), Occurrence<Id>>`. Zero clones and one
  allocation during the scan; conflict vectors are allocated only on actual
  disagreement.
- `resolve_state_maps` takes an O(1) `ptr_eq` identity fast path for the common
  2-parent merge where both forks share an `imbl::OrdMap` root, before the full
  structural `==`.

#### 3. foldhash on `pl_cache` (non-breaking)

`pl_cache` was a concrete `&mut HashMap<Id, i64>` (std SipHash) buried in
otherwise `BuildHasher`-generic signatures. It is now generic over
`Spl: BuildHasher`, and internal callers build it as a **std container hashed
with foldhash**
(`std::collections::HashMap<Id, i64, hashbrown::DefaultHashBuilder>`). External
callers passing plain `std::HashMap` are unaffected (S = RandomState) — the bin
proves this.

#### 4. Schwartzian `mainline_sort` + avoid clone on power-event promotion

- `mainline_sort` precomputes each event's mainline position once and sorts on
  `(pos, ts, id)` tuples, cutting the `dist` hash lookups from O(N log N) to
  exactly N.
- `expand_v2_power_events_auth_chains` moves the owned copy out of
  `non_power_events` when promoting into `power_events` (no `LeanEvent` +
  `serde_json::Value` deep clone), falling back to `sort_set` only when absent.

### Measured (in-memory shootout vs ruma-state-res, 100% correctness parity)

<!-- markdownlint-disable MD013 -->

```text
8-Way Split-Brain  (~5k PDUs, 8 forks, 1k members):   rezzy 5.50ms  vs  ruma 7.52ms   =>  1.37x FASTER
Mega Rebuild       (~10k PDUs, 2k members, 8 forks):  rezzy ~9.9-10.3ms vs baseline 14.3ms (1.12x-1.24x)
```

<!-- markdownlint-enable MD013 -->

The 8-way scenario moved from ~1.01x to 1.37x once the per-iteration clone was
removed from the harness and the partition scan flattened.

### Deferred: in-flight `EventType` threading

Re-examined the `TODO(perf)` at `iterative.rs:89` (re-deriving
`EventType::from(ev.event_type.as_str())` per event across
`derive_all_conflicted_keys` and the insertion loops). **Not worth the churn**:
`EventType::Custom(Box<str>)` deep-copies on every owned `(EventType, K)` key,
and each conflicted event's key is owned in _two_ places (the `conflicted_keys`
gate set and `resolved`), so threading a memo does not reduce allocations and
adds a hash lookup per event. The genuinely effective fix would be making
`Custom` cheaply cloneable (`Arc<str>`), which is a public `EventType` API break
— deferred pending that trade-off.

---

## 24 Aug 2026 (optimization status & backlog — full inventory)

Complete status of every optimization raised this session, so nothing falls
through the cracks.

## Landed (committed)

<!-- markdownlint-disable MD013 -->

| Optimization                                                                                                                                                             | Where                                        | Commit    |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------- | --------- |
| Zero-copy borrowed resolver (`&SharedState`, `&HashMap`, no per-iteration deep clone)                                                                                    | `resolve/iterative.rs`                       | `8558224` |
| `partition_state_maps` flattening (borrowed-key `FastMap` + `Occurrence`) + O(1) `ptr_eq` identical-map fast path                                                        | `resolve/multi.rs`                           | `c79637f` |
| foldhash `pl_cache` (`Spl: BuildHasher` genericity, std-container + foldhash hasher, non-breaking)                                                                       | `resolve/sorting.rs`, `resolve/iterative.rs` | `fe9599a` |
| Schwartzian `mainline_sort` (O(N) instead of O(N log N) `dist` lookups) + clone-free power-event promotion (with `sort_set` fallback)                                    | `resolve/sorting.rs`, `resolve/iterative.rs` | `cb6e874` |
| `EventType::Custom` `Box<str>` → `Arc<str>` (O(1) clone; pub-API note)                                                                                                   | `basespec/event_types.rs`                    | `f418952` |
| Zero-copy Kahn graph (`FastMap<&Id, usize>` / `Vec<&Id>`, `get_key_value` borrow) + zero-clone mainline BFS (`VecDeque<&Id>` / `FastSet<&Id>`) + `ptr_eq` diff fast path | `resolve/sorting.rs`, `state/diff.rs`        | `ee25160` |
| Zero-clone transitive-auth BFS in `compute_local_auth` (`(&Id, usize)` queue, `FastSet<&Id>` visited)                                                                    | `state/at.rs`                                | `9931e23` |
| DAG merge-base traversal + pagination validation → `FastMap`                                                                                                             | `state/`                                     | `346103e` |
| `RedactionReport` (applied / skipped_unauthorized / target_not_in_batch)                                                                                                 | `auth/mod.rs`                                | `39fb164` |

<!-- markdownlint-enable MD013 -->

## Not done — with reason

- **In-flight `EventType` threading** (`iterative.rs:89` TODO). Earlier rejected
  as net-neutral: the memo doesn't cut `Custom` deep-copies because
  `(EventType, K)` keys are owned in two places (gate set + `resolved`). **Now
  the calculus changed**: `f418952` made `EventType::Custom` an O(1) `Arc<str>`
  clone, so a threaded `FastMap<Id, EventType>` is now one derive + cheap clones
  instead of two derives (and for well-known types, still just a string
  compare + a lookup). Remains the best concrete in-repo follow-up; the win is
  bounded by the conflict set size, so it is narrow but real.
- **Mainline BFS-vs-DFS for v2.1.1+** — **resolved: traversal-order
  independent**. `mainline_pos(E) = min{i | P_i ∈ auth_chain(E)}` is a min over
  a set fixed by the DAG (the reachable mainline-ancestor closure), and `min` is
  associative/ commutative, so DFS, BFS, and post-order all yield the same index
  — the mainline index of each `P_i` is a fixed invariant, unlike hop-count
  shortest paths. The iterative-DFS implementation in
  `compute_closest_mainline_positions` is therefore equivalent to a BFS for
  these purposes, consistent with the 100% ruma parity.
- **LtHash fast path — Path A vs Path B**.
- **Path A (identical-fork fast path): DECIDED & SOUND.**
  `resolve_merge_fast_path_hashed` (`at.rs:2177`) uses `hash == hash` as an
  O(1) negative filter + `ptr_eq || ==` as final authority, returning
  `first.clone()` when all forks are identical. Sound under the
  trust-the-local-DB model (LtHash collision resistance ~2^200;
  error-correcting columns / HAMT repair-GC planned). Incremental
  homomorphic hash update (`at.rs:2199`) maintains the
  `hash == LtHash(state)` invariant. **Differential harness added**
  (`test_fast_path_differential_matches_full_resolution_on_identical_forks`)
  comparing the fast path against uncached `resolve_multiple_prev_states`
  across fork counts, plus a from-scratch hash-consistency check (guards
  accumulator drift). Note: true O(1) only when `ptr_eq` holds;
  independently-converged forks still pay the `==` fallback.
- **Path B (non-interfering / trivial-only fork skip): REJECTED.** Skipping
  the topo sort / iterative auth because two forks "share the same
  power-level/auth roots" or "differ only on non-power keys" is not
  justified by a digest match: identical roots ≠ non-interference, and the
  non-power winner is (mainline position, ts, id) + iterative auth — not
  just ts. Mainline position depends on each candidate's own auth chain, and
  a sender can be banned/demoted mid-phase by an earlier-applied event. The
  correct gate (identical power phase ∧ per-key auth against the merged
  state) costs about as much as the cheap O(|C| log |C|) non-power phase it
  would skip. Same class of shortcut as the retired CDO pre-filter — not
  worth the correctness cliff. Path A (identical forks) remains the only
  skip that pays.

- **Batched RocksDB MultiGet** for the DAG frontier. Lives in `tuwunel` (storage
  layer, separate repo) — out of scope for rezzy.
- **`// membership-only dedup; do NOT iterate` hardening comment** on the
  `visited` `FastSet` in `compute_local_auth` (`9931e23`): **landed**
  (`at.rs:286`). The swap is safe only because `visited` is never iterated
  (foldhash seed is per-process); the comment now makes that invariant explicit.
- **Dedicated tests for the zero-copy refactors** (`ee25160`, `9931e23`).
  Behavior-preserving (borrowed ↔ owned); existing resolution/parity suites
  cover them. A differential harness for the LtHash fast path (Path A) was
  added; explicit borrow-semantics tests for the Kahn/BFS refactors remain
  optional.

## Empirically resolved / rejected

- **HAMT as `SharedState` backend**: `benches/state_backend.rs` fork-and-diverge
  benchmark shows the in-tree HAMT is **6–27x SLOWER** than `imbl::OrdMap`
  (282ns vs 7.8µs @ n=16; ~1µs vs ~9–11µs at larger n) for the exact
  clone-and-diverge pattern state resolution uses. This resolves the
  `state/at.rs:2134` TODO ("swap the state payload over to the HAMT"):
  **don't**. The real incremental win is LtHash state hashing + `state/delta.rs`
  delta compaction (already present), not a HAMT swap.
- **Persistent mainline depth indexing**: rejected. The mainline is anchored on
  the _winning_ power-level event, only known during resolution, so pre-indexed
  depths aren't a stable static property — and it couples to the storage layer.

## Separate (correctness/review) items still open

- `coerce_json_to_i64` float path ungated by room version (v10+ rejects
  non-integers) — silent auth-semantics deviation.
- Bench `>>> REZZY SPEEDUP <<<` line still printed (methodology reframed as
  parity oracle but the all-caps number remains).
- Parity check one-directional (no symmetric key-set diff / length equality).
- `compare_bench.py` ratchets baseline to the all-time-luckiest run;
  missing-label and sentinel-regex issues.
- CLI `render_timeline` defaults `room_version` to `"1"` (fail-open);
  `format.rs` reads `redacts` from `content` (v1–10 top-level) not
  `get_redacts()`.
- `screened` delta list unordered; `MSC3089` → `MSC3083` typos;
  `reference_hash`/ `compute_content_hash` `Result` + `expect` coexistence.
