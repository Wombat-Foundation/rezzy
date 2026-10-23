# Track 04 Review & Multi-Perspective Critique Report: Persistent HAMT Delta State Compression & Live-Frontier Citation GC

- **Track ID:** `04_hamt_delta_state_20260629`
- **Track Title:** Persistent HAMT Delta State Compression & Live-Frontier Citation GC
- **Epoch & Commit Range:** `v0.2.0`–`v0.5.2` + Sep/Oct 2026 (`6e14836..0d0a87d`)
- **Review Status:** Completed with Actionable Stage B Remediation Items (`High` Public-Safety Risk: Adversarial Hydra Frontier RAM Exhaustion)
- **Primary Audit Reference:** [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Rows 4, 7, 12, 16)

---

## 1. Conductor Review Summary (`/conductor-review` Structure)

### 1.1 Plan & Specification Compliance
| Requirement ID | Requirement Summary | Verification Oracle | Verdict |
| :--- | :--- | :--- | :--- |
| **FR-04-01** | Incremental, batch, and streaming state-at computation (`compute_state_at`, `compute_state_at_batch`, `compute_state_at_streaming`) | [`src/state/at.rs`](../../../src/state/at.rs), [`tests/unit/test_state_at.rs`](../../../tests/unit/test_state_at.rs) | **PASS** (with adversarial wide-frontier memory caveat) |
| **FR-04-02** | Decoupled `StateDelta` / `ResolutionDelta` & checkpoint delta chains (`compute_state_delta`, `compute_delta_chain`) | [`src/state/delta.rs`](../../../src/state/delta.rs), [`tests/unit/test_lib.rs`](../../../tests/unit/test_lib.rs) | **PASS** |
| **FR-04-03** | 32-way `#![no_std]` CHAMP/HAMT (`HamtNode<K, V>`) with keyed `StructuralHash` and `PersistedInternalNode` codec | [`src/hamt/mod.rs`](../../../src/hamt/mod.rs), [`src/hamt/hash.rs`](../../../src/hamt/hash.rs), [`src/hamt/codec.rs`](../../../src/hamt/codec.rs) | **PASS** |
| **FR-04-04** | Subtree delta isolation (`diff_hamt_nodes`) and storage GC reachability audit (`node_reachability_audit`, `bitmap_node_reachability_audit`) | [`src/hamt/delta.rs`](../../../src/hamt/delta.rs), [`src/hamt/audit.rs`](../../../src/hamt/audit.rs), [`src/hamt/tests.rs`](../../../src/hamt/tests.rs) | **PASS** |
| **FR-04-05** | Kahn topological ordering (`reorder_by_kahn`) and out-degree `child_citations` frontier eviction in `run_hamt_live_walk` | [`rezzy-cli/src/format.rs`](../../../rezzy-cli/src/format.rs), [`docs/hamt_live_frontier_retention.md`](../../../docs/hamt_live_frontier_retention.md) | **PASS (Benign DAGs) / AT RISK (Hydra Frontiers)** |
| **FR-04-06** | Zero-external-dependency `#![no_std]` `PersistentOrdMap` (fanout 24, lazy `diff` with `Arc::ptr_eq` skipping) | [`src/state/persistent_ord_map.rs`](../../../src/state/persistent_ord_map.rs), [`benches/db/state_backend.rs`](../../../benches/db/state_backend.rs) | **PASS** |

### 1.2 Executive Findings Matrix
| Finding ID | Severity | Perspective | Location | Summary |
| :--- | :--- | :--- | :--- | :--- |
| **F-04-01** | `[High]` | `critic-perf`, `critic-redteam-qa` | [`rezzy-cli/src/format.rs:397-418`](../../../rezzy-cli/src/format.rs#L397-L418), [`docs/hamt_live_frontier_retention.md:64-72`](../../../docs/hamt_live_frontier_retention.md#L64-L72) | Adversarial "hydra" DAG frontiers hold `child_citations[P] > 0` across thousands of parallel fork branches, pinning $O(W_{\text{hydra}} \times \log_{32} S)$ `Arc<HamtNode>` trees and `SharedStateMap` snapshots in RAM simultaneously. |
| **F-04-02** | `[High]` | `critic-perf`, `critic-eng-lead` | [`rezzy-cli/src/format.rs:153-465`](../../../rezzy-cli/src/format.rs#L153-L465) | Even when `roots_map` evicts `Arc<HamtNode>`, `root_hashes_map`, `roots_json`, `checkpoints`, and (under `--format hamt`) `unique_nodes` / `seen_node_hashes` grow monotonically in RAM as $O(N_{\text{events}} + N_{\text{unique\_nodes}})$. |
| **F-04-03** | `[High]` | `critic-perf` | [`src/state/persistent_ord_map.rs:143-247`](../../../src/state/persistent_ord_map.rs#L143-L247), [`benches/db/hamt_delta.rs:11-95`](../../../benches/db/hamt_delta.rs#L11-L95) | Cold-deserialized state snapshots lose `Arc::ptr_eq` pointer identity on `PersistentOrdMap` and experience an `O_DIRECT` I/O latency cliff on `HamtNode` when cached internal-node layers $L < 2$. |
| **F-04-04** | `[Medium]` | `critic-compliance`, `critic-dx-integrator` | [`rezzy-cli/src/format.rs:306-384`](../../../rezzy-cli/src/format.rs#L306-L384), [`src/state/at.rs:104-220`](../../../src/state/at.rs#L104-L220) | State-at and live HAMT walks invoke `check_auth(..., verifier: None)` and do not enforce `LeanEvent.room_id: Some(RoomId)` unless stamped prior to walk entry, leaving cross-room `auth_events` (`MSC4307` Rule 2.5) opt-in. |
| **F-04-05** | `[Medium]` | `critic-formal-crypto`, `critic-eng-lead` | [`src/hamt/mod.rs:192-213`](../../../src/hamt/mod.rs#L192-L213), [`src/hamt/hash.rs`](../../../src/hamt/hash.rs) | `StructuralHash` relies on caller-supplied `structural_key: &[u8]` for cross-room domain separation; passing an empty or static slice across rooms allows cross-room subtree hash oracle correlation. |
| **F-04-06** | `[Low]` | `critic-pm`, `critic-federation-interop` | [`docs/spec_coverage.csv:1-36`](../../../docs/spec_coverage.csv#L1-L36), [`docs/hamt_live_frontier_retention.md:7-10`](../../../docs/hamt_live_frontier_retention.md#L7-L10) | `spec_coverage.csv` marks 31/35 rows `full` and does not distinguish in-memory state resolution from persistent HAMT storage/GC primitives (`MSC4511` / Sithnapse `mtxdb` integration). |

---

## 2. Multi-Perspective Critiques (All 8 Specialized Personas)

### 2.1 Product Management (`critic-pm`)
- **Matrix Spec Coverage (`spec_coverage.csv` 31/35 `full` Claims vs. Reality):**
  - While [`docs/spec_coverage.csv`](../../../docs/spec_coverage.csv) claims `full` support on 31 of 35 specification rows (including `spec/v1.13§3` Server-Server API State Resolution and `spec/v1.13§3.3` Auth Chain), top-of-file disclaimers in [`docs/spec_audit.md:3-6`](../../../docs/spec_audit.md#L3-L6) and [`docs/rezzy_msc4242_security_comparison.md:3-5`](../../../docs/rezzy_msc4242_security_comparison.md#L3-L5) state that only V1 state resolution is currently in supported shipping scope. Track 04's HAMT (`src/hamt/`) and delta-compression (`src/state/delta.rs`) subsystems are foundational storage primitives for homeserver state-group persistence (`StateGroupId`, `RootHandle`) rather than standalone Matrix wire-spec features, yet their memory-retention guarantees directly govern whether `V1`–`V12` and `MSC4242` rooms survive partition recovery.
- **Room Version Roadmap (`V1`–`V12`, `MSC4242`):**
  - Track 04's `compute_state_at`, `compute_state_at_batch`, and `compute_state_at_streaming` ([`src/state/at.rs`](../../../src/state/at.rs)) accept `StateResVersion` across `V1`, `V2` (Room V2–V11), `V2_1` (Room V12 / `MSC4297`), `V2_1_1`, and `V2_2` (`MSC4242`). However, product documentation should clearly separate **algorithmic state-at parity** (verified in `tests/unit/test_state_at.rs`) from **bounded-memory streaming guarantees**, which only hold when the DAG frontier width is bounded.

### 2.2 Principal Engineering Lead (`critic-eng-lead`)
- **CHAMP/HAMT vs. `PersistentOrdMap` Structural Sharing Architecture:**
  - Track 04 cleanly bifurcates hot in-memory state resolution from content-addressed persistent storage:
    1. **Hot In-Memory Resolution (`SharedState<Id, K>`):** Backed by [`PersistentOrdMap`](../../../src/state/persistent_ord_map.rs#L94-L98) (a path-copying B+tree with `MAX_FANOUT = 24` at line 25, replacing `imbl::OrdMap` in `b9cdeca`). Cloning is $O(1)$ (`Arc::clone`), point updates copy at most $\lceil \log_{24} S \rceil$ nodes via `Arc::make_mut`, and [`PersistentOrdMap::diff`](../../../src/state/persistent_ord_map.rs#L239-L247) skips shared subtrees in $O(1)$ via `Arc::ptr_eq`.
    2. **Content-Addressed Persistence (`HamtNode<K, V>`):** Implemented in [`src/hamt/mod.rs`](../../../src/hamt/mod.rs#L176-L187) as a 32-way bitmap-indexed CHAMP trie (`datamap: u32`, `nodemap: u32`) with cryptographic `StructuralHash` merkle identity and lazy child loading (`NodeRef::Lazy(StructuralHash)` at line 160).
- **Decoupling State Delta Compression from `resolve_iterative_sort` vs. `resolve_lattice_fold`:**
  - Extracting [`src/state/delta.rs`](../../../src/state/delta.rs) (`098e177`, PR #11 `97493b2`) out of `resolve_iterative_sort` was a critical architectural correction. Earlier prototypes (`d94db88`) coupled checkpoint delta calculation with DAG parent hash lookups inside the resolver, causing forward-jump parent inversions (`5ab44d4`) and `hash_to_idx` shadowing (`e9d7867`). Now, both `resolve_iterative_sort` and `resolve_semilattice_fold` operate purely on state maps, while `diff_hamt_nodes` and `compute_state_delta` compute structural deltas orthogonally.
- **`Option<RoomId>` Type Safety & Keyed `StructuralHash`:**
  - In [`rezzy-cli/src/format.rs:299-364`](../../../rezzy-cli/src/format.rs#L299-L364), `persist_mutations` and `persist_mutation` require `structural_key: &[u8]`, which binds the room's identity into `HamtNode::compute_structural_hash` ([`src/hamt/mod.rs:192-213`](../../../src/hamt/mod.rs#L192-L213)). However, `structural_key` is a raw `&[u8]` slice rather than a strongly typed `RoomId` newtype, and `LeanEvent.room_id` remains `Option<RoomId>`, permitting callers to pass unkeyed/empty slices or `room_id: None`.

### 2.3 Public-Safety & C2 Compliance (`critic-compliance`)
- **Opt-In `MSC4307` Rule 2.5 Cross-Room Bypass Risk in State-At Reconstruction:**
  - In public-safety and tactical C2 deployments, `compute_state_at*` ([`src/state/at.rs`](../../../src/state/at.rs)) and `run_hamt_live_walk` ([`rezzy-cli/src/format.rs`](../../../rezzy-cli/src/format.rs)) reconstruct authoritative room state across DAG forks. Because `iterative_auth_ok` ([`src/state/at.rs:181-220`](../../../src/state/at.rs#L181-L220)) delegates to `crate::auth::check_auth(ev, &overlay, version, None)` rather than `check_auth_chain`, and because `LeanEvent.room_id` is `Option<RoomId>` (`None` by default unless stamped at ingest), an attacker who injects a foreign-room event into the `events_map` passed to `compute_state_at` will not trigger `check_foreign_room_citation` (`MSC4307` Rule 2.5).
- **`V2.1.1` `SEND01` Consensus Divergence & `MSC4242` Branch Withholding Impact on HAMT Roots:**
  - Because `HamtNode::structural_hash` commits to every `(event_type, state_key) -> event_id` leaf in the resolved state, any consensus divergence between `StateResVersion::V2_1` (Stock `MSC4297`) and `StateResVersion::V2_1_1` (`12.1` with `has_ban_evasion_hardening()`) at a fork merge ([`rezzy-cli/src/format.rs:281-287`](../../../rezzy-cli/src/format.rs#L281-L287)) produces permanently divergent `StructuralHash` root handles for the same event ID and permanently poisons `fork_cache` (line 344). Similarly, if a peer withholds a concurrent revocation branch (`MSC4242` / `V2.1.1` DAG honesty gap), the computed HAMT root hash for the merge event will reflect the unrevoked state.
- **Room V12 Creator Immunity (`Rules 10.1–10.5`):**
  - When `compute_state_at` resolves forks under `StateResVersion::V2_1` (Room V12), `OverlayState::get_event` ([`src/state/at.rs:161-165`](../../../src/state/at.rs#L161-L165)) falls back to `self.create_ev` when `m.room.create` is omitted from `auth_events` (per Room V12 rules), ensuring V12 creator immunity (`i64::MAX` in `src/auth/user.rs:31-51`) is preserved during incremental HAMT fork merges.

### 2.4 Performance & Adversarial Liveness (`critic-perf`)
- **`[High]` Finding F-04-01 — Unmerged "Hydra" DAG Frontiers Pinning `Arc<HamtNode>` Trees via `child_citations > 0`:**
  - In [`rezzy-cli/src/format.rs:175`](../../../rezzy-cli/src/format.rs#L175) and [`401-418`](../../../rezzy-cli/src/format.rs#L401-L418) (documented in [`docs/hamt_live_frontier_retention.md:28-72`](../../../docs/hamt_live_frontier_retention.md#L28-L72)), `run_hamt_live_walk` precomputes `child_citations[P]` for every parent $P$ in the DAG and keeps both `roots_map[P]` (`Arc<HamtNode>`) and `state_map_cache[P]` (`SharedStateMap`) resident in RAM until `child_citations[P]` decrements to `0`.
  - **Attack Vector:** An adversary constructs a "hydra" DAG with $W$ parallel fork branches (e.g., $W = 10,000$ single-event branches fanning out from early history), each modifying distinct state keys, and places a single chain of merge events at the end of the Kahn order that cites all $W$ branch tips (`prev_events` fanout up to 20 per merge node, requiring only $W / 19 \approx 527$ merge events). Because every branch tip $P_i$ is cited by a tail merge event, `child_citations[P_i] == 1 > 0` throughout the entire walk! Consequently, `roots_map` and `state_map_cache` cannot evict *any* of the $W$ branch roots until the very end of the stream, inflating live memory from $O(\log_{32} S)$ to $O(W \times \log_{32} S)$ and triggering OOM on resource-constrained C2 nodes.
- **`[High]` Finding F-04-02 — Unbounded `root_hashes_map`, `checkpoints`, and `unique_nodes` Accumulation:**
  - Even on a strictly linear DAG ($W = 1$), [`rezzy-cli/src/format.rs:387`](../../../rezzy-cli/src/format.rs#L387), [`420`](../../../rezzy-cli/src/format.rs#L420), and [`460`](../../../rezzy-cli/src/format.rs#L460) push every event's root hash and delta checkpoint into in-memory `root_hashes_map`, `roots_json`, and `checkpoints` vectors before serializing at the end of `run_hamt_live_walk`, and `--format hamt` buffers every unique `PersistedInternalNode` JSON object in `unique_nodes` (line 337).
- **`[High]` Finding F-04-03 — `O_DIRECT` Cold Storage Latency vs. Warm Memory & `Arc::ptr_eq` Loss:**
  - [`benches/db/hamt_delta.rs`](../../../benches/db/hamt_delta.rs#L1-L155) demonstrates that while warm in-memory `diff_hamt_nodes` short-circuits identical subtrees in nanoseconds via `StructuralHash` equality, cold `O_DIRECT` disk-backed resolution with `cache_layers = 0` or `1` incurs a synchronous `pread` + `PersistedInternalNode` decode per traversed level. Likewise, [`PersistentOrdMap::diff`](../../../src/state/persistent_ord_map.rs#L239-L247) relies on `Arc::ptr_eq` (physical pointer identity) rather than a content hash; if two `PersistentOrdMap` instances are deserialized independently from cold storage without canonical node interning, `Arc::ptr_eq` returns `false` on every internal node and `diff` degrades from $O(\Delta \log_{24} S)$ to a full $O(S)$ scan (as noted in [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) Row 12).

### 2.5 Formal Verification & Mathematical Soundness (`critic-formal-crypto`)
- **HAMT Canonical Representation & History Independence:**
  - A persistent search tree used for cryptographic state commitments (`StructuralHash`) must be **history-independent**: any two insertion/deletion sequences producing the same abstract map $M: K \to V$ must yield the exact same `HamtNode` topology and `StructuralHash`.
  - In [`src/hamt/mod.rs`](../../../src/hamt/mod.rs), CHAMP canonicality holds because:
    1. Every key's routing path is determined by `key_path_hash(structural_key, key)` (5 bits per level, `HAMT_BRANCH_BITS = 5` at line 148).
    2. Leaves at each node are stored sorted by their compressed `datamap` bit position, and internal children by `nodemap` bit position.
    3. Node deletion collapses single-leaf internal subtrees back into parent inline leaves (`src/hamt/tests.rs` verifies insertion/deletion permutation invariance).
- **Decoupling from Non-Monotone Auth Rules (`resolve_semilattice_fold` vs. `resolve_iterative_sort`):**
  - Track 04 wisely keeps `HamtNode` and `PersistentOrdMap` purely structural: neither embeds Matrix authorization rules into its merge operator. When merging DAG forks in [`src/state/at.rs`](../../../src/state/at.rs) or [`rezzy-cli/src/format.rs:281`](../../../rezzy-cli/src/format.rs#L281), fork resolution delegates to `resolve_iterative_sort` (not `resolve_semilattice_fold`), preserving full spec compliance on non-monotone auth chains (such as concurrent ban vs. power-level demotion).

### 2.6 Matrix Federation Interop (`critic-federation-interop`)
- **Mixed-Federation Split-Brain Risks in State-Group Hashes:**
  - While `HamtNode` and `PersistedInternalNode` (`HAMT_WIRE_VERSION`) are local storage structures (unless exchanged via experimental `MSC4511` / state reconciliation extensions), the leaf values stored inside the HAMT are resolved Matrix `event_id`s. If a homeserver runs `run_hamt_live_walk` or `compute_state_at` with `StateResVersion::V2_1_1` (`12.1`), its resolved state on progressive-ban (`SEND01`) or transitive-auth forks will differ from Stock `V2.1` (`MSC4297`) peers, resulting in divergent `StructuralHash` state-group commitments.
- **Legacy MXID (`MSC4303`) & Wire Key Encoding in `HamtCodec`:**
  - `HamtCodec` encodes `(EventType, String)` state keys verbatim as length-prefixed UTF-8 byte sequences (`src/hamt/codec.rs`). Because `is_acceptable_historical_mxid` (`src/basespec/rezzy_types.rs:3068-3074`) accepts arbitrary non-NUL Unicode scalar values in historical MXID localparts (`MSC4303`), `HamtCodec` must never assume ASCII-only or NUL-terminated `state_key` strings—and `src/hamt/codec.rs` correctly uses explicit byte-length prefixes rather than C-string delimiters.

### 2.7 Adversarial Red-Team & Verification QA (`critic-redteam-qa`)
- **Missing Adversarial Hydra-Frontier Memory Bound Test:**
  - [`src/hamt/tests.rs`](../../../src/hamt/tests.rs) and [`tests/unit/test_state_at.rs`](../../../tests/unit/test_state_at.rs) thoroughly test functional equivalence, codec roundtrips, and `bitmap_node_reachability_audit`, and `rezzy-cli` has 105+ unit tests (`ffadb38`). However, there is **no red-team test** that constructs a wide "hydra" DAG ($W \ge 1,000$ open branches merged at the tail) and asserts a hard ceiling on `roots_map.len()` or spills unvisited frontier roots to cold `PersistedInternalNode` bytes.
- **Cross-Room Event Injection & Hash Collision Regression Fixtures:**
  - Commit `fb665e8` and `5ab44d4` added regression tests for state hash collisions and forward-jump parent lookups in `compute_delta_chain`, and `9ba9548` added keyed `StructuralHash` tests. Red-team QA should add an explicit test verifying that two rooms with identical `(event_type, state_key, event_id)` tuples but distinct `RoomId`s produce completely disjoint `StructuralHash` values at every internal CHAMP node.

### 2.8 Homeserver Integrator & API Ergonomics (`critic-dx-integrator`)
- **Clarifying `compute_state_at_streaming` vs. `run_hamt_live_walk`:**
  - As noted in [`docs/hamt_live_frontier_retention.md:7-9`](../../../docs/hamt_live_frontier_retention.md#L7-L9), `run_hamt_live_walk` (which lives in `rezzy-cli/src/format.rs`, not in the core `rezzy` library crate!) is completely separate from `rezzy::state::at::compute_state_at_streaming`. Downstream homeserver integrators reading `docs/hamt_live_frontier_retention.md` may expect `run_hamt_live_walk` or out-degree `child_citations` HAMT GC to be an exported `rezzy::hamt` library API, when in fact it is currently embedded inside the CLI binary (`rezzy-cli/src/format.rs:136`).
- **Type-Safe `StructuralKey` / `RoomId` Enforcement:**
  - `HamtNode::get`, `hamt::insert`, `persist_mutation`, and `persist_mutations` take `structural_key: &[u8]`. Wrapping this in a mandatory `RoomId` or `StructuralNamespace<'a>` newtype that rejects empty keys (`b""`) would prevent integrators from accidentally instantiating unkeyed HAMTs.

---

## 3. Actionable Recommendations for Stage B Remediation Tracks

1. **[Stage B — Track 13 / P0 API Hardening] Enforce Non-Empty `RoomId` Namespace on HAMT & State-At Entry Points:**
   - Replace raw `structural_key: &[u8]` in `src/hamt/` public entry points with a validated namespace wrapper (or `RoomId`) that panics or returns `Err` on empty slices, and require `RoomId` in `check_auth_chain` / `ingest_events` so `MSC4307` Rule 2.5 is unconditionally fail-closed.
2. **[Stage B — Track 17 / P1 Liveness & Memory Bounds] Bound Live Hydra Frontiers in `run_hamt_live_walk` & `compute_state_at_streaming`:**
   - Introduce a configurable `max_live_frontier_roots: usize` cap (e.g., `256`) in [`rezzy-cli/src/format.rs`](../../../rezzy-cli/src/format.rs#L397-L418) and `compute_state_at_streaming`. When `roots_map.len() > max_live_frontier_roots`, demote the lowest-priority `Arc<HamtNode>` children to `NodeRef::Lazy(StructuralHash)` backed by an LRU/spill buffer or `NodeResolver` so an adversarial hydra DAG cannot pin $O(W_{\text{hydra}} \times \log_{32} S)$ full trees in RAM.
3. **[Stage B — Track 17 / P1 Streaming CLI Output] Stream `--format deltas` and `--format hamt` Output:**
   - Stream `checkpoints` and `roots_json` records incrementally to `io::Write` during `run_hamt_live_walk` instead of accumulating $O(N)$ `JsonValue` objects in memory until walk completion.
4. **[Stage B — Track 18 / P2 Library Extraction] Promote Kahn Out-Degree Citation Driver from `rezzy-cli` to `rezzy::hamt`:**
   - Extract the generic Kahn out-degree citation state-machine from `rezzy-cli/src/format.rs` into `src/hamt/gc.rs` so downstream homeservers (`mtxdb` / `conduwuit`) can consume frontier-bounded HAMT construction directly from the `#![no_std]` library crate.
