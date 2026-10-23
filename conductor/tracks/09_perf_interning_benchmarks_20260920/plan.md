# Implementation Plan: Performance Audits, StateKey Interning, DenseIndex & Benchmark Suite (`09_perf_interning_benchmarks_20260920`)

## Phase 1: Zero-Allocation Power-Level Visitors, `EventType` Interning & `foldhash` Migration [checkpoint: e74a5e8]

- [x] Task: Refactor power-level user iterators to use a zero-allocation visitor pattern 5384219
  - [x] Replace heap-allocating user power-level iterators with `visit_user_keys` in `src/basespec/rezzy_types.rs` and `src/auth/mod.rs` (`5384219`)
  - [x] Add mock visitor coverage and tombstone authorization tests in `tests/test_tombstone.rs` (`5384219`, `dcbb6a2`)
- [x] Task: Intern `EventType` discriminants, thread `mainline_cache`, and adopt `foldhash` `FastMap`/`FastSet` f2b9efb
  - [x] Implement 1-byte discriminant `EventType` enum in `src/basespec/event_types.rs` with byte-identical `String` ordering and `Borrow<dyn StateKeyDyn>` lookup support (`f2b9efb`)
  - [x] Thread persistent `mainline_cache` through fork-merge loops and replace internal `SipHash` tables with `foldhash`-backed `FastMap`/`FastSet` (`f2b9efb`)
  - [x] Add `state_backend`, `persistence`, `lthash`, `state_groups`, `cumulative_rebuild`, and `mainline_cache` benchmark suites under `benches/` (`f2b9efb`)
- [x] Task: Generalize resolution pipeline over `K: StateKey` and prevent MSC4297 auth-context clobbering e74a5e8
  - [x] Parameterize `SharedState<Id, K>` and core resolution functions over `K: StateKey` while keeping delta compaction bound to `String` wire keys (`e74a5e8`)
  - [x] Gate resolved state insertions to genuinely conflicted keys across V1–V2.2 so MSC4297 auth-context events never clobber unconflicted state (`e74a5e8`)

## Phase 2: In-Memory Resolver Hot-Path Optimizations, `DenseIndex` & Auth Cache Sharing [checkpoint: 6ca3bf9]

- [x] Task: Execute the August 2026 in-memory resolver optimization round and consolidate `DenseIndex<T, u32>` f56b068
  - [x] Convert `resolve_iterative_sort` to borrow `&SharedState` and `&HashMap`, flatten `partition_state_maps`, upgrade `EventType::Custom` to `Arc<str>`, and implement Schwartzian `mainline_sort` as recorded in `docs/perf_audits.md` (`f56b068`)
  - [x] Extract shared `DenseIndex<T, Idx = u32>` primitive in `src/dense_index.rs` with `IndexTooLarge` `Result` overflow handling and migrate `AuthGraph`, `IndexedUniverse`, and `reachability.rs` as documented in `docs/tech_debt.md` (`f56b068`)
  - [x] Prototype `Interner`, `InternId<'a>`, and `InternedRoomState` in `src/basespec/interned_key.rs` and benchmark against `InternedKey` (`Arc<str>`) in `benches/state/interned_key.rs` (`f56b068`)
- [x] Task: Optimize `LocalAuthCache` structural sharing with `Arc<LeanEvent>` and generalize `StateDelta` 6ca3bf9
  - [x] Store `Arc<LeanEvent>` inside `LocalAuthEntry` for zero-clone structural sharing in `LocalAuthCache` (`src/state/at.rs`, `src/auth/mod.rs`) (`6ca3bf9`)
  - [x] Generalize `ConflictedKeysInputs`, `src/resolve/iterative.rs`, `src/resolve/semilattice.rs`, and `StateDelta` (`src/state/delta.rs`) over generic `StateKey` (`6ca3bf9`)

## Phase 3: Tooling Hygiene, In-Tree `PersistentOrdMap` & State Key Representation Matrix [checkpoint: 7f41793]

- [x] Task: Harden `docs/format.sh` with directory resolution and `shellcheck` compliance 125cfc6
  - [x] Update `docs/format.sh` to resolve its own script directory via `cd -- "$(dirname -- "${BASH_SOURCE[0]}")"` before invoking `prettier` (`e99e268`)
  - [x] Add `|| exit` guard to `docs/format.sh` to satisfy `shellcheck` (`SC2164`) (`125cfc6`)
- [x] Task: Replace external `imbl::OrdMap` with in-tree `PersistentOrdMap` and optimize leaf layout 7e49c94
  - [x] Implement in-tree B-tree `PersistentOrdMap` in `src/state/persistent_ord_map.rs` to replace `imbl::OrdMap` as the `SharedState` backend (`3b7c76f`, `beede91`)
  - [x] Optimize `PersistentOrdMap` leaf layout and benchmark against `imbl::OrdMap` and `HAMT` with `Arc`-backed key/value types (`33f3dd6`, `330f2ca`, `7e49c94`)
- [x] Task: Add `intern_events` ingest helper, `FastSharedState`, and key $\times$ event-ID benchmark matrix 826cb93
  - [x] Expand `benches/state/interned_key.rs` and `benches/db/state_key_repr.rs` with a full key (`String` / `InternedKey` / `InternId`) $\times$ event-ID (`String` / `Arc<str>`) representation matrix (`f6245b7`, `791b0f7`)
  - [x] Add `intern_events` ingest helper and `FastSharedState` alias in `src/state/at.rs` (`826cb93`)
- [x] Task: Enforce deterministic Kahn timeline tie-breaking and add `RootHandle` JSON adapters 7f41793
  - [x] Fix `kahn_order_by` in `rezzy-cli/src/timeline_order.rs` to fall back to lexicographic Event ID tie-breaking when primary sort keys compare equal (`7f41793`)
  - [x] Implement `RootHandle::to_json` and `RootHandle::from_json` in `src/hamt/hash.rs` and update `docs/homeserver_utilities.md` (`7f41793`)

## Phase 4: HAMT Delta Cold `O_DIRECT` vs. Warm In-Memory Benchmark Suite [checkpoint: 0d0a87d]

- [x] Task: Implement Linux `O_DIRECT` cold-disk vs. warm-memory HAMT delta resolution benchmark 5a0af29
  - [x] Create `benches/db/hamt_delta.rs` measuring HAMT delta state resolution across warm in-memory and cold `O_DIRECT` disk reads by cached layer depth (`3a30ab0`, `4297aac`)
  - [x] Gate direct-I/O mode to Linux `libc::O_DIRECT`, use unique exclusive node files, probe alignment, and report the median of 5 samples (`5a0af29`)
- [x] Task: Enforce resolved-state parity checks in `hamt_delta` bench and merge `bench/hamt-delta-resolution` 0d0a87d
  - [x] Document benchmark helpers, lazy node handling, and failure conditions in `benches/db/hamt_delta.rs` (`7690126`)
  - [x] Parity-check all cached-depth variants against the in-memory reference resolver and probe `O_DIRECT` before filling the span (`41fb17d`)
  - [x] Merge branch `bench/hamt-delta-resolution` (`0d0a87d`)

---

## History & Audit Traceability

| Commit SHA | Date | Subject | Primary Source & Test Files | Linked Docs & Public-Safety Audit Mapping |
| :--- | :--- | :--- | :--- | :--- |
| `5384219` | 2026-07-02 | `refactor: use visitor pattern for power level iterators to avoid allocations` | `src/basespec/rezzy_types.rs`, `src/auth/mod.rs`, `tests/test_tombstone.rs` | [`spec_audit.md`](../../../docs/spec_audit.md), [`perf_audits.md`](../../../docs/perf_audits.md) |
| `f2b9efb` | 2026-08-19 | `feat: HAMT state helpers. perf: EventType interning, mainline cache, and siphash alternatives (#35)` | `src/basespec/event_types.rs`, `src/resolve/iterative.rs`, `benches/state_backend.rs` | [`perf_audits.md`](../../../docs/perf_audits.md) — **Audit #12 (High: HashDoS on unseeded `foldhash` & Cold Cliff on `ptr_eq`)** |
| `e74a5e8` | 2026-08-21 | `feat(state): generic state-key support and resolution optimizations` | `src/state/at.rs`, `src/resolve/iterative.rs`, `tests/test_state_at.rs` | [`perf_audits.md`](../../../docs/perf_audits.md), [`tech_debt.md`](../../../docs/tech_debt.md) |
| `f56b068` | 2026-09-28 | `merge(dev->master): reconciliation & HAMT hardening, V2.2/V3 state DAG, merkle proofs, perf/tooling (#14)` | `src/dense_index.rs`, `src/basespec/interned_key.rs`, `docs/perf_audits.md`, `docs/tech_debt.md` | [`perf_audits.md`](../../../docs/perf_audits.md), [`tech_debt.md`](../../../docs/tech_debt.md) — **Audit #12 & Audit #16 (High: `InternedKey` +3% to +16% degradation at 5,000 members)** |
| `6ca3bf9` | 2026-10-01 | `perf(state): optimize auth cache sharing and generalize StateKey generics` | `src/auth/mod.rs`, `src/resolve/iterative.rs`, `src/state/at.rs`, `src/state/delta.rs` | [`tech_debt.md`](../../../docs/tech_debt.md) |
| `e99e268` | 2026-10-04 | `Update docs/format.sh` | `docs/format.sh` | [`format.sh`](../../../docs/format.sh) — **Audit #5 (Low: Tooling Hygiene)** |
| `125cfc6` | 2026-10-04 | `chore: shellcheck` | `docs/format.sh` | [`format.sh`](../../../docs/format.sh) — **Audit #5 (Low: Tooling Hygiene)** |
| `beede91` | 2026-10-09 | `replace imbl state backend with persistent map wrapper` | `src/state/persistent_ord_map.rs`, `src/state/at.rs` | [`perf_audits.md`](../../../docs/perf_audits.md) |
| `826cb93` | 2026-10-09 | `Add intern_events ingest helper and FastSharedState alias` | `src/state/at.rs`, `benches/state/interned_key.rs` | [`tech_debt.md`](../../../docs/tech_debt.md) — **Audit #16** |
| `7e49c94` | 2026-10-09 | `Optimize persistent map leaf layout` | `src/state/persistent_ord_map.rs`, `benches/db/state_backend.rs` | [`perf_audits.md`](../../../docs/perf_audits.md) |
| `7f41793` | 2026-10-10 | `fix: deterministic timeline tie-break, RootHandle JSON adapter, docs example` | `rezzy-cli/src/timeline_order.rs`, `src/hamt/hash.rs`, `docs/homeserver_utilities.md` | [`homeserver_utilities.md`](../../../docs/homeserver_utilities.md) |
| `41fb17d` | 2026-10-16 | `bench(hamt_delta): parity-check all variants vs in-memory reference, warm steady-state row, probe O_DIRECT before filling span, checked span size` | `benches/db/hamt_delta.rs` | [`perf_audits.md`](../../../docs/perf_audits.md) |
| `0d0a87d` | 2026-10-18 | `Merge branch 'bench/hamt-delta-resolution'` | `benches/db/hamt_delta.rs`, `tests/unit/test_reconcile_e2e.rs` | [`perf_audits.md`](../../../docs/perf_audits.md), [`tech_debt.md`](../../../docs/tech_debt.md) |

> **Public-Safety Remediation Linkage**: Open findings from [`../../audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #12: HashDoS on unseeded `foldhash` over network-supplied IDs and cold-deserialization cliffs on `Arc::ptr_eq`; Row #16: `+3%` to `+16%` `InternedKey` atomic contention at 5,000+ room members and missing E2E multi-round bucket-split test; Row #5: Unpinned `prettier` in `docs/format.sh`) are scheduled for Stage B remediation in Priority P1 Items #5 and #6.
