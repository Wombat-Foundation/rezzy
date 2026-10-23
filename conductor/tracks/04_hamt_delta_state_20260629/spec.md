# Specification: Persistent HAMT Delta State Compression & Live-Frontier Citation GC

## 1. Overview & Historical Context

Between late June 2026 (`v0.2.0`, commits `65b627b` / `6e14836`) and October 2026 (`0d0a87d`), `rezzy` evolved from naive per-event `BTreeMap` cloning into a multi-tiered persistent state storage and delta-compression architecture capable of running in `#![no_std]` (`alloc`) environments:

1. **Batch & Streaming State-At Reconstruction (`65b627b`, `b3dd913`, `6e14836`, `cbe0053`, Jun 28–29, 2026):** Introduced `compute_state_at`, `compute_state_at_batch`, and `compute_state_at_streaming` in [`src/state/at.rs`](../../../src/state/at.rs) to reconstruct room state at arbitrary DAG positions without external database snapshots, amortizing backward DAG walks across batches of target events.
2. **Decoupling State Delta Compression from State Resolution (`d94db88`, `098e177`, `97493b2`, PR #11, Jun 28–29, 2026) & Generic ID Delta Chaining (`d20c863`, `63a0548`, Jul 2, 2026):** Extracted [`src/state/delta.rs`](../../../src/state/delta.rs) (`StateDelta`, `ResolutionDelta`, `compute_state_delta`, `compute_delta_chain`) out of the core state resolution loop and generalized delta chains over `Id: EventId` and `K: StateKey`.
3. **Evolution of Structural Sharing Backends (`e33cdb5`, `c4f521b` PR #12 -> `fbf6b24` PR #31 / `f2b9efb` PR #35 -> `b9cdeca` / `beede91`, Jun–Oct 2026):**
   - Initially replaced `O(|V|^2)` `BTreeMap` clones with `imbl::OrdMap` (`c4f521b`, Jun 29, 2026) for `O(1)` copy-on-write forks.
   - Built a 32-way bitmap-indexed Hash Array Mapped Trie (CHAMP/HAMT) in [`src/hamt/mod.rs`](../../../src/hamt/mod.rs) (`fbf6b24`, `f2b9efb`, Aug 2026) with keyed `StructuralHash` merkle identities, dense binary persistence (`PersistedInternalNode`), subtree differencing (`diff_hamt_nodes`), and storage GC reachability auditing (`node_reachability_audit`, `bitmap_node_reachability_audit`).
   - Replaced the external `imbl` dependency with an in-tree `#![no_std]` path-copying B-tree [`PersistentOrdMap`](../../../src/state/persistent_ord_map.rs) tuned to fanout 24 (`3b7c76f`, `beede91`, `b9cdeca`, `d4eb8a3`, Oct 9, 2026) for in-memory `SharedState`.
4. **Kahn Topological Walk & Out-Degree Citation GC (`53ff800`, `610b1b5`, `8e8de61`, `ffadb38`, `6ab9643`, Sep 30, 2026):** Documented in [`docs/hamt_live_frontier_retention.md`](../../../docs/hamt_live_frontier_retention.md) and implemented in [`rezzy-cli/src/format.rs`](../../../rezzy-cli/src/format.rs) (`run_hamt_live_walk`), bounding live `Arc<HamtNode>` memory retention to `O(frontier_width × log₃₂ S)` via exact parent out-degree reference counting (`child_citations`).
5. **Cold-Disk `O_DIRECT` vs. Warm HAMT Delta Benchmarks (`3a30ab0`..`41fb17d`, `0d0a87d`, Oct 16–18, 2026):** Added [`benches/db/hamt_delta.rs`](../../../benches/db/hamt_delta.rs) to verify parity and measure latency across cached internal-node layer depths using Linux `O_DIRECT` page-aligned reads.

---

## 2. Functional Requirements & Matrix Spec/MSC Mapping

| Requirement ID | Functional Requirement | Implementation Locus | Verification / Spec Mapping |
| :--- | :--- | :--- | :--- |
| **FR-04-01** | **Incremental & Batch State-At Computation:** Compute resolved room state after one or more target events by walking `prev_events` backwards, merging forks via version-aware state resolution, and applying accepted state events. | [`src/state/at.rs`](../../../src/state/at.rs) (`compute_state_at`, `compute_state_at_batch`, `compute_state_at_streaming`) | Matrix Spec Server-Server API §3; [`tests/unit/test_state_at.rs`](../../../tests/unit/test_state_at.rs) |
| **FR-04-02** | **Decoupled State Delta Chains:** Compute per-event [`StateDelta`](../../../src/state/delta.rs) records (additions, modifications, deletions) and compacted checkpoint delta chains over generic `EventId` and `StateKey` types without coupling delta storage to `resolve_iterative_sort`. | [`src/state/delta.rs`](../../../src/state/delta.rs) (`compute_state_delta`, `compute_delta_chain`, `reconstruct_from_delta_chain`) | [`docs/design_notes.md`](../../../docs/design_notes.md); [`tests/unit/test_lib.rs`](../../../tests/unit/test_lib.rs) |
| **FR-04-03** | **32-Way Persistent HAMT with Keyed Structural Hashing:** Provide a persistent `#![no_std]` CHAMP/HAMT (`HamtNode<K, V>`) with 32-bit `data_map` / `node_map` bitmaps, level-synchronous descent (`DescendResult`), keyed `StructuralHash` (domain-separated by `room_id`/namespace), and dense wire serialization (`PersistedInternalNode`). | [`src/hamt/mod.rs`](../../../src/hamt/mod.rs), [`src/hamt/hash.rs`](../../../src/hamt/hash.rs), [`src/hamt/codec.rs`](../../../src/hamt/codec.rs) | [`src/hamt/tests.rs`](../../../src/hamt/tests.rs) |
| **FR-04-04** | **Subtree Delta Isolation & Reachability GC Audit:** Support O(changed-keys × log₃₂ S) subtree diffing between HAMT roots (`diff_hamt_nodes`, `diff_node_hashes`, `isolate_delta`) and multi-root mark-and-sweep reachability auditing (`node_reachability_audit`, `bitmap_node_reachability_audit`). | [`src/hamt/delta.rs`](../../../src/hamt/delta.rs), [`src/hamt/audit.rs`](../../../src/hamt/audit.rs) | [`src/hamt/tests.rs`](../../../src/hamt/tests.rs) |
| **FR-04-05** | **Out-Degree Citation GC in Live HAMT Walk:** Reorder DAG events via Kahn's algorithm (`reorder_by_kahn`), precompute deduplicated parent out-degrees (`child_citations`), retain `Arc<HamtNode>` in `roots_map` only while `child_citations[P] > 0`, and evict to 32-byte `StructuralHash` handles when citations reach zero. | [`rezzy-cli/src/format.rs`](../../../rezzy-cli/src/format.rs) (`run_hamt_live_walk`), [`docs/hamt_live_frontier_retention.md`](../../../docs/hamt_live_frontier_retention.md) | `cargo test -p rezzy-cli` |
| **FR-04-06** | **In-Tree `#![no_std]` `PersistentOrdMap` State Backend:** Provide a zero-external-dependency path-copying ordered map (`PersistentOrdMap<K, V>` with fanout 24 and lazy `diff` iterator) backing `SharedState<Id, K>`. | [`src/state/persistent_ord_map.rs`](../../../src/state/persistent_ord_map.rs) | [`benches/db/state_backend.rs`](../../../benches/db/state_backend.rs) |

---

## 3. Architectural Decisions & Rejected Alternatives

1. **Decoupling Delta Chain Compaction from State Resolution (`098e177`, `72ab935`, `97493b2`):**
   - *Initial Approach:* Early prototypes (`d94db88`, `5007d19`) interleaved DAG traversal and checkpoint delta-chain compaction inside state resolution.
   - *Pivot:* Hash-based parent lookups suffered from forward-jump hazards (`5ab44d4`) and `hash_to_idx` shadowing in batch reconstruction (`e9d7867`). PR #11 (`97493b2`) decoupled `state_delta` from state resolution and deprecated DAG-traversing delta chain functions (`72ab935`) in favor of pure state-snapshot diffing (`compute_state_delta`) and explicit topological streaming (`compute_state_at_streaming`).
2. **Replacing `imbl::OrdMap` with Custom `PersistentOrdMap` (`c4f521b` -> `b9cdeca`):**
   - *Initial Approach:* PR #12 (`c4f521b`) adopted `imbl::OrdMap` to eliminate `O(|V|^2)` `BTreeMap` cloning during fork merges.
   - *Pivot:* To maintain full control over `#![no_std]` allocations, leaf layout, and lazy structural diffing (`Arc::ptr_eq` short-circuiting on shared subtrees), `rezzy` replaced `imbl::OrdMap` with [`PersistentOrdMap`](../../../src/state/persistent_ord_map.rs) (`beede91`, `b9cdeca`) tuned to fanout 24 (`d4eb8a3`) with a lazy `diff` iterator (`a083674`).
   - *Rejected Sub-Optimization:* A split-column leaf layout in `PersistentOrdMap` (`7e49c94`) was benchmarked and reverted (`b663687`) after showing cache-line regressions on interleaved key/value access.
3. **Out-Degree Citation Refcounting vs. Unbounded HAMT Root Caching (`610b1b5`, `8e8de61`, `6ab9643`):**
   - *Problem:* Retaining an `Arc<HamtNode>` for every event in a 100k-event room exhausted memory during CLI `--format hamt` and `--format deltas` runs.
   - *Decision:* Enforce strict Kahn topological ordering (`reorder_by_kahn`) independent of untrusted wire `depth`, precompute `child_citations[P]` over deduplicated `prev_events`, and evict `Arc<HamtNode>` from `roots_map` immediately when the last child consumes parent `P`, keeping only the 32-byte `StructuralHash` in `root_hashes_map`.

---

## 4. Non-Functional & Public-Safety Invariants

Cross-referencing the [Public-Safety Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md):

> [!WARNING]
> **Public-Safety Risk — High (RAM Exhaustion on Adversarial "Hydra" Frontiers):**
> As documented in [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row 7, [`hamt_live_frontier_retention.md`](../../../docs/hamt_live_frontier_retention.md)), `run_hamt_live_walk` bounds live `Arc<HamtNode>` memory to `O(frontier_width × log₃₂ S)` under the assumption that `frontier_width` remains small. However:
> 1. **Unmerged Forward Extremities:** Any terminal forward extremity $E$ with no children has `child_citations[E] == 0` (so its `Arc<HamtNode>` is not inserted into `roots_map` at line 401), **but** in an adversarial "hydra" DAG where an attacker creates thousands of parallel fork branches held open by a deferred merge child at the tail of the stream, `frontier_width` scales to $O(N_{\text{branches}})$, pinning all intermediate spine nodes in RAM simultaneously.
> 2. **Unbounded `root_hashes_map` & `--format hamt` Buffering:** `root_hashes_map` grows linearly with total events $O(N)$, and `--format hamt` buffers all unique `PersistedInternalNode` JSON objects in memory before emission.
> 3. **Keyed `StructuralHash` Namespace Pinning (`9ba9548`, `153ff22`):** HAMT structural hashes must always be keyed with the room's `room_id` (`structural_key`) to prevent cross-room subtree collision or precomputation attacks.

---

## 5. Acceptance Criteria & Verification Oracles

1. **State-At & Streaming Parity:** `compute_state_at`, `compute_state_at_batch`, and `compute_state_at_streaming` produce bit-for-bit identical resolved state maps across forked DAGs in [`tests/unit/test_state_at.rs`](../../../tests/unit/test_state_at.rs).
2. **Delta Chain Roundtrip Integrity:** `compute_delta_chain` and `reconstruct_from_delta_chain` reconstruct exact checkpoint states without hash collisions or forward-jump parent inversions in [`tests/unit/test_lib.rs`](../../../tests/unit/test_lib.rs).
3. **HAMT Structural Hash & Subtree Diff Oracles:** [`src/hamt/tests.rs`](../../../src/hamt/tests.rs) verifies insertion/removal order independence of `StructuralHash`, `PersistedInternalNode` binary codec roundtrips, `diff_hamt_nodes` accuracy against naive map diffs, and `bitmap_node_reachability_audit` garbage collection soundness.
4. **Live-Frontier Citation GC & Cold Disk Parity:** [`rezzy-cli/src/format.rs`](../../../rezzy-cli/src/format.rs) passes all 105+ `rezzy-cli` tests (`ffadb38`), and [`benches/db/hamt_delta.rs`](../../../benches/db/hamt_delta.rs) (`41fb17d`) asserts exact parity between in-memory HAMT delta resolution and cold `O_DIRECT` disk-backed layer resolution.
