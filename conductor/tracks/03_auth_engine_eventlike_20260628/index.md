# Track 03: Version-Aware Auth Engine, `EventLike` Trait & Streaming Auth Cache (`v0.2.0`)

## Conductor Track Handshake

- **Track ID**: `03_auth_engine_eventlike_20260628`
- **Epoch**: `v0.2.0` (May 20–June 30, 2026, plus `EventLike` & trivial-conflict follow-ups `0cce801`–`71e2f3e` through July 2, 2026)
- **Commit Range**: `4abfb43..6268aab` (plus `0cce801`, `a83ec17`, `71e2f3e`)
- **Status**: `completed`

### Track Artifacts
- [Specification (`./spec.md`)](./spec.md)
- [Implementation Plan (`./plan.md`)](./plan.md)
- [Track Metadata (`./metadata.json`)](./metadata.json)
- [Public-Safety Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md)

## Reviews & Critiques
- [Multi-Perspective Architectural Review (`./review.md`)](./review.md) — 8-persona critique covering `critic-pm`, `critic-eng-lead`, `critic-compliance`, `critic-perf`, `critic-formal-crypto`, `critic-federation-interop`, `critic-redteam-qa`, and `critic-dx-integrator`

### Linked Repository Documentation
- [`../../../docs/architecture.md`](../../../docs/architecture.md) — Synchronous "I/O Sandwich" design, Auth Difference formula ($\text{auth}(C) - \text{auth}(U)$), and 3-layer Continuwuity/Synapse auth-chain indexing
- [`../../../docs/design_notes.md`](../../../docs/design_notes.md) — API evolution covering `EventContent`, `EventLike`, `EventId` integer keys, `compute_state_at_batch`, `compute_state_at_streaming`, and `auth_types_for_event`
- [`../../../README.md`](../../../README.md) — Public crate exports and room version matrix

### Linked Source & Verification Modules
- [`../../../src/auth/mod.rs`](../../../src/auth/mod.rs) — Version-aware Matrix PDU authorization engine (`check_auth`, `check_auth_with_context`, `auth_types_for_event`, `StateProvider`)
- [`../../../src/auth/user.rs`](../../../src/auth/user.rs) — User power-level query API (`get_sender_power_level`) with `i64::MAX` creator privilege protection (`MSC4289`)
- [`../../../src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs) — Generic `EventId`, `StateKey`, `EventContent`, `DagNode`, `EventLike`, `RawEvent`, and `ParsedEvent` traits
- [`../../../src/basespec/version_props.rs`](../../../src/basespec/version_props.rs) — Room version property decomposition (`StateResVersion`, `MSC4289` creator semantics, `MSC4297` create omission)
- [`../../../src/state/at.rs`](../../../src/state/at.rs) — `compute_state_at`, `compute_state_at_batch`, `compute_state_at_streaming`, `LocalAuthCache`, and trivial-conflict fast path
- [`../../../src/resolve/sorting.rs`](../../../src/resolve/sorting.rs) — Zero-copy `SortContext` (`KahnSortInputs`) and stack-safe iterative DFS
- [`../../../tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) — Comprehensive PDU authorization, self-ban rejection, `auth_types_for_event`, and `LocalAuthCache` unit tests
- [`../../../tests/unit/test_integer_keys.rs`](../../../tests/unit/test_integer_keys.rs) — Generic `u32`/`u64` `EventId` resolution verification
- [`../../../tests/stress_unredacted_lounge.rs`](../../../tests/stress_unredacted_lounge.rs) — Real-world unredacted lounge DAG partial-join and mismatch subgraph regression tests
