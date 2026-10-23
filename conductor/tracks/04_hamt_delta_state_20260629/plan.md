# Implementation Plan: Track 04 — Persistent HAMT Delta State Compression & Live-Frontier Citation GC

## Phase 1: Batch & Streaming `compute_state_at` & Delta Chain Decoupling [checkpoint: 97493b2]

- [x] Task: Implement high-performance batch `compute_state_at` and deduplicate ancestor walk `65b627b`
  - [x] Implement `compute_state_at_batch` in [`src/state/at.rs`](../../../src/state/at.rs) to amortize backward `prev_events` traversal across multiple target events (`65b627b`).
  - [x] Deduplicate the state-after walk between `compute_state_at` and `compute_state_at_batch` into a shared pipeline (`b3dd913`, merged in `6e14836`).
  - [x] Requeue parents in `compute_merge_base` when reachability bitmasks expand across multi-branch junctions (`366d235`).
- [x] Task: Extract `state_delta` module and decouple delta compression from state resolution `098e177`
  - [x] Introduce [`src/state/delta.rs`](../../../src/state/delta.rs) with `StateDelta`, `ResolutionDelta`, `compute_state_delta`, and `compute_delta_chain` (`d94db88`, `29641fe`, `5007d19`).
  - [x] Decouple delta chain generation from `resolve_lean` (`098e177`, PR #11 merge `97493b2`) and deprecate/remove unchecked DAG-traversing delta helpers (`72ab935`, `4a54e26`).
- [x] Task: Harden checkpoint delta reconstruction against hash collisions and forward jumps `fb665e8`
  - [x] Resolve state hash collisions during checkpoint delta reconstruction (`fb665e8`) and defer `base_state` cloning in compacted delta chains (`5bdc821`).
  - [x] Prevent forward-jumps in hash-based parent lookup (`5ab44d4`) and eradicate `hash_to_idx` shadowing in batch reconstruction (`e9d7867`).
- [x] Task: Add bounded-memory `compute_state_at_streaming` and generic ID delta chains `cbe0053`
  - [x] Implement `compute_state_at_streaming` in [`src/state/at.rs`](../../../src/state/at.rs) with streaming parity tests (`cbe0053`, `01e03e4`, `e37e6d9`).
  - [x] Generalize delta chains and soft-fail API over generic `Id: EventId` (`d20c863`, merged in `63a0548`) and avoid dereferencing `EventId` during checkpoint index lookup (`39b4d5c`).

## Phase 2: Persistent Structural Sharing (`imbl::OrdMap` to `#![no_std]` `PersistentOrdMap`) [checkpoint: b9cdeca]

- [x] Task: Migrate `SharedState` to persistent copy-on-write maps to eliminate `O(|V|^2)` cloning `e33cdb5`
  - [x] Adopt `imbl::OrdMap` in `compute_state_at` (`e33cdb5`, PR #12 merge `c4f521b`) and state resolution (`9892b87`) for `O(1)` structural sharing across DAG forks.
  - [x] Ensure `#![no_std]` portability with portable empty `SharedState` construction (`2525886`, `8d510c4`) and boundary optimizations (`85a2086`).
- [x] Task: Replace `imbl::OrdMap` with in-tree `#![no_std]` `PersistentOrdMap` `b9cdeca`
  - [x] Design and implement path-copying [`PersistentOrdMap`](../../../src/state/persistent_ord_map.rs) wrapper and B-tree backend (`3b7c76f`, `beede91`, `b9cdeca`) tuned to fanout 24 (`d4eb8a3`).
  - [x] Benchmark `PersistentOrdMap` against `imbl::OrdMap` and `HamtNode` across `String`, `Arc<str>`, and `InternedKey` representations in [`benches/db/state_backend.rs`](../../../benches/db/state_backend.rs) (`33f3dd6`, `f6245b7`, `330f2ca`).
- [x] Task: Optimize `PersistentOrdMap::diff` lazy traversal and leaf removal `a083674`
  - [x] Make `PersistentOrdMap::diff` lazy (`a083674`) using `Arc::ptr_eq` subtree skipping and remove redundant `contains_key` pre-descent in `PersistentOrdMap::remove` (`decbd8f`).
  - [x] Evaluate and revert split-column leaf layout in `PersistentOrdMap` (`7e49c94`, `b663687`) to preserve interleaved cache locality.

## Phase 3: 32-Way Persistent CHAMP/HAMT Core, Subtree Diffing & Reachability GC [checkpoint: f043fbb]

- [x] Task: Implement generic 32-way CHAMP/HAMT (`src/hamt/`) with `PersistedInternalNode` codec `fbf6b24`
  - [x] Build [`src/hamt/mod.rs`](../../../src/hamt/mod.rs), [`src/hamt/hash.rs`](../../../src/hamt/hash.rs), and [`src/hamt/codec.rs`](../../../src/hamt/codec.rs) supporting 32-bit `data_map`/`node_map` bitmaps, level-synchronous `DescendResult`, and `PersistedInternalNode` binary serialization (`fbf6b24`, PR #31).
  - [x] Add HAMT state helpers (`f2b9efb`, PR #35), generalize `StateKey` support (`e74a5e8`, `6ca3bf9`), and remove the oversized `impl_fixed_hamt_codec!` macro (`66a79e8`).
- [x] Task: Pin `StructuralHash` threat model to `room_id` namespace and implement reachability GC `9ba9548`
  - [x] Pin `StructuralHash` threat model to `room_id`/namespace via the `structural_key` parameter (`9ba9548`, `153ff22`).
  - [x] Implement `diff_hamt_nodes`, `diff_node_hashes`, `isolate_delta`, and `walk_reachable_node_hashes` in [`src/hamt/delta.rs`](../../../src/hamt/delta.rs) (`fbf6b24`, `f56b068`).
  - [x] Implement `node_reachability_audit` and `bitmap_node_reachability_audit` in [`src/hamt/audit.rs`](../../../src/hamt/audit.rs) plus linear-chain refcount GC in [`src/hamt/gc.rs`](../../../src/hamt/gc.rs) (`f043fbb`, `f56b068`).

## Phase 4: Kahn Live-Frontier Citation GC & Cold `O_DIRECT` Benchmarks [checkpoint: 0d0a87d]

- [x] Task: Wire HAMT live walk in `rezzy-cli` with topological Kahn ordering `610b1b5`
  - [x] Wire live event walk with HAMT roots and `--format hamt` output in [`rezzy-cli/src/format.rs`](../../../rezzy-cli/src/format.rs) (`53ff800`).
  - [x] Reorder events via `reorder_by_kahn` prior to the walk and extract HAMT state on demand (`610b1b5`, `1410cc2`).
  - [x] Add lazy fork resolution, incremental HAMT mutation, and filtered auth context during CLI fork merges (`c52e895`, `6f16888`, `dde78df`).
- [x] Task: Implement out-degree `child_citations` refcount GC and document retention bounds `8e8de61`
  - [x] Precompute deduplicated parent out-degrees (`child_citations[P]`), evict `Arc<HamtNode>` from `roots_map` when `child_citations` reaches zero, and gate `PersistedInternalNode` buffering on `OutputFormat::Hamt` (`8e8de61`, `ffadb38`).
  - [x] Author [`docs/hamt_live_frontier_retention.md`](../../../docs/hamt_live_frontier_retention.md) detailing traversal invariants, `O(frontier_width × log₃₂ S)` bounds, and node buffering rules (`6ab9643`).
- [x] Task: Benchmark HAMT delta resolution across in-memory and Linux `O_DIRECT` cold-disk layers `0d0a87d`
  - [x] Implement [`benches/db/hamt_delta.rs`](../../../benches/db/hamt_delta.rs) comparing in-memory vs. cold `O_DIRECT` disk reads by cached layer depth (`3a30ab0`, `4297aac`, `5a0af29`).
  - [x] Document benchmark helpers and failure conditions (`7690126`), parity-check all variants against the in-memory reference (`41fb17d`), and merge `bench/hamt-delta-resolution` (`0d0a87d`).

---

## History & Audit Traceability

| Commit SHA | Date | Source & Test Files Touched | Documentation & Audit Linkage | Public-Safety Audit Observation |
| :--- | :--- | :--- | :--- | :--- |
| `65b627b` / `b3dd913` / `6e14836` | 2026-06-28 | [`src/state/at.rs`](../../../src/state/at.rs), [`tests/unit/test_state_at.rs`](../../../tests/unit/test_state_at.rs) | [`docs/design_notes.md`](../../../docs/design_notes.md) | Batch state-at computation requires bounded ancestor graphs to avoid OOM in adversarial forks. |
| `098e177` / `fb665e8` / `97493b2` / `63a0548` | 2026-06-29 – 2026-07-02 | [`src/state/delta.rs`](../../../src/state/delta.rs), [`tests/unit/test_lib.rs`](../../../tests/unit/test_lib.rs) | [`docs/design_notes.md`](../../../docs/design_notes.md) | Decouples `StateDelta` computation from `resolve_iterative_sort`; prevents hash collision and forward-jump bugs (`fb665e8`, `5ab44d4`). |
| `e33cdb5` / `c4f521b` / `b9cdeca` / `a083674` | 2026-06-29 – 2026-10-09 | [`src/state/persistent_ord_map.rs`](../../../src/state/persistent_ord_map.rs), [`benches/db/state_backend.rs`](../../../benches/db/state_backend.rs) | [`docs/perf_audits.md`](../../../docs/perf_audits.md) | `PersistentOrdMap` `Arc::ptr_eq` fast path degrades to $O(N)$ on cold deserialized snapshots without canonical node sharing. |
| `fbf6b24` / `f2b9efb` / `9ba9548` | 2026-08-13 – 2026-09-20 | [`src/hamt/mod.rs`](../../../src/hamt/mod.rs), [`src/hamt/delta.rs`](../../../src/hamt/delta.rs), [`src/hamt/audit.rs`](../../../src/hamt/audit.rs), [`src/hamt/tests.rs`](../../../src/hamt/tests.rs) | [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) | Keyed `StructuralHash` must bind `room_id` (`structural_key`) to prevent cross-room subtree precomputation. |
| `610b1b5` / `8e8de61` / `6ab9643` | 2026-09-30 | [`rezzy-cli/src/format.rs`](../../../rezzy-cli/src/format.rs) | [`docs/hamt_live_frontier_retention.md`](../../../docs/hamt_live_frontier_retention.md), [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) | **High (RAM Exhaustion):** Adversarial wide "hydra" DAG frontiers hold `child_citations > 0`, pinning `Arc<HamtNode>` trees in RAM. |
| `3a30ab0` / `41fb17d` / `0d0a87d` | 2026-10-16 – 2026-10-18 | [`benches/db/hamt_delta.rs`](../../../benches/db/hamt_delta.rs) | [`docs/hamt_live_frontier_retention.md`](../../../docs/hamt_live_frontier_retention.md) | Validates cold `O_DIRECT` disk-backed HAMT delta resolution parity against warm in-memory resolution. |
