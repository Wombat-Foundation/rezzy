# Track 07: Roaring Bitmap Auth-Difference, Lazy EventProvider & Homeserver Utilities (`07_roaring_lazy_provider_20260703`)

- **Track ID**: `07_roaring_lazy_provider_20260703`
- **Epoch**: `v0.5.0`–`v0.5.2` + Oct 2026 (`2026-07-03` to `2026-10-09`)
- **Commit Range**: `3caa4ca..95a8ffb` (`3caa4ca`, `46ea938`, `fe881ac`, `7e39a14`, `efc06d7`, `7e5ccf2`, `1c0c2b0`, `f538d7f`, `82b71e7`, `bfb121e`, `560cd6b`, `1518ddd`, `c89aec4`, `f87090d`, `04dc560`, `6282cb2`, `95a8ffb`, `7ad9903`)
- **Status**: Completed (`[x]`)

## Track Artifacts

- **[Track Specification (`./spec.md`)](./spec.md)** — Reverse-engineered requirements, synchronous "I/O Sandwich" architecture, `AuthGraph` bitmap set-difference algebra ($\bigcup_i C_i \setminus \bigcap_i C_i$), `EventProvider` & `LeanEventCache` on-demand resolution, zero-allocation `raw_event` extraction, and Public-Safety Audit invariants.
- **[Implementation Plan (`./plan.md`)](./plan.md)** — 4-phase historical execution plan mapping 14 verified git commits across `v0.5.0`–`v0.5.2` and October 2026 bitmap/raw-event evolutions.
- **[Track Metadata (`./metadata.json`)](./metadata.json)** — Machine-readable metadata, commit boundaries, linked documentation, and Public-Safety Audit risk summary.

## Linked Documentation & Public-Safety Audit

- **[`../../../docs/architecture.md`](../../../docs/architecture.md)** — Documents the synchronous "I/O Sandwich" design, the $\text{auth}(C) \setminus \text{auth}(U)$ Auth Difference boundary, bulk-fetch BFS vs. auth-chain indexing, and `O(V + E)` transitive closure roaring bitmap indexing.
- **[`../../../docs/homeserver_utilities.md`](../../../docs/homeserver_utilities.md)** — 3-tier roadmap of synchronous homeserver utility APIs (`compute_auth_chain_diff`, `AuthGraph::auth_difference`, `StateDiff`, `LeanEvent::redacted`, and unimplemented Tier-2 `validate_event_structure` / `compute_dag_health` guards).
- **[`../../audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md)** — Public-Safety Audit rows **#2 (`architecture.md` — Critical: OOM / Starvation)** and **#8 (`homeserver_utilities.md` — High: Missing Guards)**.

## Primary Source & Test Files

- [`../../../src/auth/roaring.rs`](../../../src/auth/roaring.rs) — `AuthGraph<Id>` topological transitive closure builder, `auth_difference`, and `is_in_auth_chain`.
- [`../../../src/bitmap/mod.rs`](../../../src/bitmap/mod.rs) & [`../../../rezzy-recon/src/bitmap/mod.rs`](../../../rezzy-recon/src/bitmap/mod.rs) — In-tree `Bitmap`, `Bitmap64`, and `Bitmap128` chunked hybrid array/dense bitsets replacing external `roaring`.
- [`../../../src/resolve/multi.rs`](../../../src/resolve/multi.rs) — `resolve_state_maps_lazy`, `resolve_state_maps_lazy_with_diff`, and N-way fork partitioning.
- [`../../../src/state/cache.rs`](../../../src/state/cache.rs) — `LeanEventCache` (`Arc<LeanEvent>` + `RefCell<BTreeMap<u64, Id>>` O(log n) LRU eviction implementing `EventProvider`).
- [`../../../src/state/diff.rs`](../../../src/state/diff.rs) & [`../../../src/state/at.rs`](../../../src/state/at.rs) — `compute_state_diff`, `compute_auth_chain_diff`, and `find_forward_extremities_roaring`.
- [`../../../src/raw_event.rs`](../../../src/raw_event.rs) — `RawEventSpan`, `MatrixEventScratch`, `extract_matrix_event_into`, and `OwnedMatrixEvent`.
