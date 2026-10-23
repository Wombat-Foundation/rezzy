# Specification: Performance Audits, StateKey Interning, DenseIndex & Benchmark Suite (`09_perf_interning_benchmarks_20260920`)

## 1. Overview & Historical Context

Between **July 2, 2026 and October 18, 2026** (spanning `5384219`, `f2b9efb`, `e74a5e8`, `f56b068`, `6ca3bf9`, `e99e268`, `125cfc6`, `beede91`, `7f41793`, and `0d0a87d`), `rezzy` conducted a systematic series of micro- and macro-benchmark audits (`docs/perf_audits.md`, `benches/`) and architectural refactors (`docs/tech_debt.md`) to eliminate heap-allocation bottlenecks, unify duplicate dense-indexing logic, generalize state resolution over interned keys, and benchmark persistent state backends under both warm in-memory and cold `O_DIRECT` disk conditions.

### Why This Track Was Built
1. **Diagnosing the In-Memory Shootout vs. Production Speedup Gap (`docs/perf_audits.md`)**: Early runs of the in-memory `ruma-state-res` vs. `rezzy` benchmark (`benches/compare_ruma.rs`) showed only a `1.01x–1.07x` speedup despite `rezzy`'s `23x` faster auth-difference and `1,639x` faster reachability closures. The August 24, 2026 audit proved two root causes: (a) `resolve_iterative_sort` consumed `SharedState` and `HashMap<String, LeanEvent>` by value, spending 70–80% of benchmark wall-clock time deep-cloning `String` and JSON AST trees on every loop iteration, and (b) the harness gave `ruma-state-res` pre-computed in-memory auth chains and a zero-cost RAM closure for free.
2. **Eliminating Hot-Path Allocations & SipHash Overhead (`5384219`, `f2b9efb`, `e74a5e8`, `6ca3bf9`)**: Following the audit, `rezzy` refactored power-level user iteration to use a zero-allocation visitor pattern (`visit_user_keys` in `5384219`), switched `resolve_iterative_sort` to borrow `&SharedState` and `&HashMap` (`8558224`), flattened `partition_state_maps` (`c79637f`), adopted `foldhash`-backed `FastMap`/`FastSet` for internal maps (`f2b9efb`, `fe9599a`), implemented Schwartzian `mainline_sort` (`cb6e874`), and shared `Arc<LeanEvent>` in `LocalAuthCache` while generalizing `StateKey` (`K`) across the resolution pipeline (`e74a5e8`, `6ca3bf9`).
3. **Consolidating Technical Debt & Benchmarking Persistent State Backends (`f56b068`, `beede91`, `7f41793`, `0d0a87d`)**: To prevent code drift across 7 independent dense-indexing implementations, `src/dense_index.rs` (`DenseIndex<T, Idx = u32>`) was extracted and wired into `AuthGraph`, `IndexedUniverse`, and `reachability.rs`. Furthermore, `rezzy` replaced external `imbl::OrdMap` with an in-tree `PersistentOrdMap` (`beede91`, `7e49c94`), investigated `Arc<str>` (`InternedKey`) vs. `u32` arena interning (`InternId` in `src/basespec/interned_key.rs`), fixed deterministic Kahn timeline tie-breaking (`7f41793`), and built the Linux `O_DIRECT` cold-disk vs. warm-cache HAMT delta resolution benchmark (`0d0a87d`).

---

## 2. Functional Requirements & Matrix Spec/MSC Mapping

### FR-09.1: Zero-Allocation Visitor Pattern & Borrowed Resolution Pipeline (`src/basespec/rezzy_types.rs`, `src/resolve/`)
- Replace heap-allocating power-level user map iterators with a zero-allocation visitor method `EventContent::visit_user_keys` (`5384219`).
- Borrow `&SharedState` and `&HashMap<Id, LeanEvent>` across `resolve_iterative_sort`, `resolve_iterative_sort_with_cache`, Kahn topological sorting (`FastMap<&Id, usize>`), and mainline BFS (`VecDeque<&Id>`, `FastSet<&Id>`) (`docs/perf_audits.md`).
- Flatten `partition_state_maps` in `src/resolve/multi.rs` to use a single borrowed-key `FastMap<&(EventType, K), Occurrence<Id>>` and an $O(1)$ `Arc::ptr_eq` fast path for identical 2-parent fork roots.
- Precompute mainline positions once per event in `mainline_sort` (Schwartzian transform, cutting hash lookups from $O(N \log N)$ to $N$) and move owned events without deep-cloning during V2 power-event promotion.

### FR-09.2: `EventType` Discriminants, `StateKey` Genericity & Interning Spike (`src/basespec/`, `src/auth/mod.rs`)
- Intern Matrix state event types into a 1-byte discriminant `EventType` enum (`src/basespec/event_types.rs`), using `EventType::Custom(Arc<str>)` for $O(1)$ clones (`f2b9efb`, `f418952`) while preserving byte-identical lexicographic `Ord` with `String`.
- Generalize `SharedState<Id, K>`, `ConflictedKeysInputs`, `StateDelta`, and `LocalAuthCache` (`Arc<LeanEvent>`) over `K: StateKey` (`e74a5e8`, `6ca3bf9`), providing `InternedKey` (`Arc<str>`) and `FastSharedState` (`826cb93`).
- Provide the `Interner`, `InternId<'a>`, and `InternedRoomState` spike (`src/basespec/interned_key.rs`) and benchmark matrix (`benches/state/interned_key.rs`, `791b0f7`) comparing `String`, `InternedKey` (`Arc<str>`), and rank-sorted `InternId` (`u32`).

### FR-09.3: Shared `DenseIndex<T, Idx = u32>` Primitive (`src/dense_index.rs`, `docs/tech_debt.md`)
- Implement `DenseIndex<T, Idx = u32>` in `src/dense_index.rs` with `DenseIndexWidth` (`u8`, `u32`, `usize`) and `Result<Self, IndexTooLarge>` overflow/allocation-failure handling.
- Migrate `AuthGraph` (`src/auth/roaring.rs`), `IndexedUniverse` (`src/hamt/audit.rs`), and `collect_topology` / `build_indexed_children` (`src/resolve/reachability.rs`) onto `DenseIndex`.

### FR-09.4: In-Tree `PersistentOrdMap`, HAMT `O_DIRECT` Benchmarks & Deterministic Tooling (`src/state/persistent_ord_map.rs`, `benches/`, `docs/format.sh`)
- Empirically benchmark `imbl::OrdMap` vs. in-tree `HAMT` (`benches/db/state_backend.rs`, showing HAMT is 6–27x slower for in-memory clone-and-diverge state resolution), and replace `imbl::OrdMap` with an in-tree B-tree `PersistentOrdMap` (`src/state/persistent_ord_map.rs`, `beede91`, `7e49c94`).
- Implement `benches/db/hamt_delta.rs` (`3a30ab0`, `5a0af29`, `41fb17d`, `0d0a87d`) benchmarking HAMT delta resolution across warm in-memory and Linux `libc::O_DIRECT` cold-disk reads by cached layer depth, with 100% parity checks against the in-memory reference.
- Enforce deterministic tie-breaking by Event ID in `rezzy-cli/src/timeline_order.rs` (`kahn_order_by`) and add `RootHandle::to_json`/`from_json` adapters (`7f41793`).
- Maintain `docs/format.sh` (`e99e268`, `125cfc6`) with shellcheck-clean directory resolution (`cd -- "$(dirname -- "${BASH_SOURCE[0]}")" || exit`).

---

## 3. Architectural Decisions & Rejected Alternatives

1. **Rejecting In-Tree `HAMT` as the Live In-Memory `SharedState` Backend (`docs/perf_audits.md`, lines 354–360)**:
   - *Hypothesis (`state/at.rs:2134` TODO)*: Swap `SharedState` from `imbl::OrdMap` to the in-tree cryptographic `HAMT`.
   - *Empirical Rejection*: `benches/db/state_backend.rs` proved that for the clone-and-diverge pattern used during state resolution, the 32-way cryptographic HAMT is **6–27x slower** than an ordered B-tree map (`282ns` vs `7.8µs` at $n=16$; `~1µs` vs `~9–11µs` at larger $n$). Instead, `rezzy` kept HAMT for content-addressed persistence/Merkle proofs and built a dedicated in-tree B-tree `PersistentOrdMap` (`beede91`, `7e49c94`) for `SharedState`.
2. **`InternedKey` (`Arc<str>`) Atomic Contention vs. `InternId<'a>` (`u32`) HRTB Wall (`docs/tech_debt.md`, lines 71–170)**:
   - *Discovery*: Benchmarking `K = InternedKey` (`Arc<str>`) across room sizes 100 / 1,000 / 5,000 (`benches/state/interned_key.rs`) revealed that while `Arc<str>` wins at small $N$ (`-9%` to `-11%`), cross-core atomic refcount cache-line bouncing during parallel `thread::scope` folds **reverses the win at 5,000 members (`+3%` to `+16%` slower than `String`)**.
   - *Alternative Investigated*: A `Copy` `u32` rank-sorted arena index (`InternId`) eliminates atomic refcounting and achieves **`-13%` to `-21%` speedup across all room sizes (100 / 1,000 / 5,000)** with zero reversal. However, wiring borrowing `InternId<'a>` into `compute_state_at` is currently parked on the higher-ranked trait bound `for<'q> (EventType, K): Borrow<dyn StateKeyDyn + 'q>` which forces `K: 'static`.
3. **Rejecting Persistent Mainline Depth Indexing (`docs/perf_audits.md`, lines 361–363)**:
   - *Decision*: Rejected pre-indexing mainline depths in the database because the mainline is anchored on the *winning* power-level event of a specific conflict set, which is only known dynamically during resolution.

---

## 4. Non-Functional & Public-Safety Invariants

Cross-referencing [`../../audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md):

- **Public-Safety Audit Finding #12 (`docs/perf_audits.md` — High: HashDoS & Cold-Deserialization Cliff)**:
  - **HashDoS Risk on `foldhash`**: Switching internal resolution tables (`FastMap`, `FastSet`, and internal `pl_cache`) from SipHash to non-cryptographic `foldhash` (`f2b9efb`, `fe9599a`) drops reachability hashing overhead from ~22% to ~4%, but because those tables index attacker-influenced strings (`event_id`, `state_key`, `sender`), an adversary who learns or grinds per-process `foldhash` seeds can induce $O(N^2)$ hash-table degradation during incident room fork resolution.
  - **Iteration Non-Determinism Guard**: As documented in `docs/perf_audits.md` (`9931e23`, `at.rs:286`), `FastSet` (`foldhash`) must carry `// membership-only dedup; do NOT iterate` whenever iteration order could affect state resolution determinism.
  - **Cold-Deserialization Cliff on `Arc::ptr_eq`**: The $O(1)$ `Arc::ptr_eq` fast paths in `resolve_state_maps` (`c79637f`), `state/diff.rs` (`ee25160`), and `resolve_merge_fast_path_hashed` only trigger when two forks share the exact same in-memory `Arc` allocation. After a homeserver restart or cold database deserialization, independently deserialized identical state trees have distinct heap pointers and fall back to $O(|S|)$ structural comparison (`==`).
- **Public-Safety Audit Finding #16 (`docs/tech_debt.md` — High: Large-Room Degradation & Open Testing Debt)**:
  - Emergency response coordination rooms with 5,000+ responders must **not** default to `InternedKey` (`Arc<str>`) under multi-threaded folds due to the documented `+3%` to `+16%` atomic cache-line contention penalty (`docs/tech_debt.md:82-88`).
  - `docs/tech_debt.md` (lines 253–274) documents that `tests/unit/test_reconcile_e2e.rs` still lacks a deterministic end-to-end test for `retry_or_split_bucket`'s multi-round capacity-then-depth escalation path.
- **Public-Safety Audit Finding #5 (`docs/format.sh` — Low: Tooling Hygiene)**:
  - `docs/format.sh` runs an unpinned global `prettier --prose-wrap always --print-width 80 --write .` across `docs/` without a lockfile or `--check` dry-run mode.

---

## 5. Acceptance Criteria & Verification Oracles

1. **Ruma Parity & Zero-Copy Resolution Oracles (`benches/compare_ruma.rs`, `tests/unit/test_resolve.rs`)**:
   - Verify 100% state-resolution parity between `rezzy` and `ruma-state-res` across 2-branch, 4-way, 8-way split-brain, and 10,000-PDU mega rebuild topologies (`docs/perf_audits.md`), achieving `1.37x` speedup on 8-way split-brain after zero-copy borrowing.
2. **`DenseIndex` Overflow & Allocation-Failure Oracles (`src/dense_index.rs`)**:
   - Verify `DenseIndex::try_build` and `DenseIndex::try_build_bounded` collapse duplicate items onto first-seen indices, return `Err(IndexTooLarge)` on width exhaustion (`u8::MAX`, `u32::MAX`), and cleanly report simulated allocation failures via `set_force_allocation_failure`.
3. **Key Interning & `PersistentOrdMap` Benchmark Oracles (`src/basespec/interned_key.rs`, `benches/state/interned_key.rs`, `benches/db/state_backend.rs`)**:
   - Verify cross-interner equality safety (`core::ptr::eq(self.interner, other.interner)`) and lexicographic `Ord` agreement in `src/basespec/interned_key.rs` unit tests.
   - Verify `PersistentOrdMap` equivalence against `BTreeMap` and `imbl::OrdMap` across random insert/remove/clone-and-diverge sequences (`src/state/persistent_ord_map.rs`).
4. **HAMT Delta Warm vs. Cold `O_DIRECT` Parity Oracles (`benches/db/hamt_delta.rs`)**:
   - Verify every cached-layer depth variant in `benches/db/hamt_delta.rs` asserts exact resolved-state parity against the in-memory reference (`41fb17d`).
