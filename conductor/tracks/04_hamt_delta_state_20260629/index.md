# Track 04: Persistent HAMT Delta State Compression & Live-Frontier Citation GC (`v0.2.0`–`v0.5.2`)

- **Track ID:** `04_hamt_delta_state_20260629`
- **Type:** `architecture`
- **Status:** `completed`
- **Epoch & Commit Range:** `v0.2.0`–`v0.5.2` + Sep/Oct 2026 (`6e14836..0d0a87d`, including `b3dd913`, `97493b2`, `c4f521b`, `63a0548`, `fbf6b24`, `f2b9efb`, `6ab9643`, `b9cdeca`, `0d0a87d`)

## Track Artifacts

- [Specification (`./spec.md`)](./spec.md)
- [Implementation Plan (`./plan.md`)](./plan.md)
- [Track Metadata (`./metadata.json`)](./metadata.json)
- [Public-Safety Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md)

## Linked Repository Documentation & Source Modules

### Documentation (`docs/`)
- [`hamt_live_frontier_retention.md`](../../../docs/hamt_live_frontier_retention.md) — Kahn topological traversal, out-degree `child_citations` refcount GC, and `O(frontier_width × log₃₂ S)` live-frontier bounds.
- [`design_notes.md`](../../../docs/design_notes.md) — Incremental state computation (`compute_state_at`, `compute_state_at_batch`, `compute_state_at_streaming`) and state delta compression architecture.

### Core Source Modules (`src/` & `rezzy-cli/`)
- [`src/hamt/mod.rs`](../../../src/hamt/mod.rs) — 32-way CHAMP/HAMT persistent trie (`HamtNode`, `NodeResolver`, `DescendResult`, `HamtKey`, `HamtValue`).
- [`src/hamt/delta.rs`](../../../src/hamt/delta.rs) — Subtree differencing (`diff_hamt_nodes`, `diff_node_hashes`, `isolate_delta`, `walk_reachable_node_hashes`).
- [`src/hamt/codec.rs`](../../../src/hamt/codec.rs) — Dense on-disk binary framing (`PersistedInternalNode`, `HamtCodec`, `HAMT_WIRE_VERSION`).
- [`src/hamt/hash.rs`](../../../src/hamt/hash.rs) — Keyed structural hashing (`StructuralHash`, `RootHandle`, `StateGroupId`).
- [`src/hamt/audit.rs`](../../../src/hamt/audit.rs) — Storage GC reachability auditing (`node_reachability_audit`, `bitmap_node_reachability_audit`).
- [`src/hamt/gc.rs`](../../../src/hamt/gc.rs) — Experimental incremental refcount bookkeeping (`RefcountTable`, `LinearRootChain`).
- [`src/state/at.rs`](../../../src/state/at.rs) — Incremental DAG state reconstruction (`compute_state_at`, `compute_state_at_batch`, `compute_state_at_streaming`, `SharedState`).
- [`src/state/delta.rs`](../../../src/state/delta.rs) — State delta chains and checkpointing (`StateDelta`, `ResolutionDelta`, `compute_state_delta`, `compute_delta_chain`).
- [`src/state/persistent_ord_map.rs`](../../../src/state/persistent_ord_map.rs) — Custom `#![no_std]` path-copying B-tree (`PersistentOrdMap`, fanout 24) replacing `imbl::OrdMap`.
- [`rezzy-cli/src/format.rs`](../../../rezzy-cli/src/format.rs) — `run_hamt_live_walk`, `reorder_by_kahn`, and out-degree `child_citations` frontier eviction.

### Verification Oracles (`tests/` & `benches/`)
- [`src/hamt/tests.rs`](../../../src/hamt/tests.rs) — Unit and property tests for HAMT insertion, deletion, structural hash determinism, codec roundtrips, and reachability audits.
- [`tests/unit/test_state_at.rs`](../../../tests/unit/test_state_at.rs) — Batch, streaming, and single-target `compute_state_at` equivalence tests.
- [`benches/db/hamt_delta.rs`](../../../benches/db/hamt_delta.rs) — In-memory vs. Linux `O_DIRECT` cold-disk HAMT delta resolution benchmarks across cached layer depths.
- [`benches/db/state_backend.rs`](../../../benches/db/state_backend.rs) — `PersistentOrdMap` vs. `imbl::OrdMap` vs. `HamtNode` comparative benchmarks.
