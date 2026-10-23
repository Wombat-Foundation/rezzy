# Implementation Plan: Track 05 — Iterative Sort vs. Lattice Fold (`V2.1.1` & `V2.2` / `MSC4242`) & Security Comparison

## Phase 1: Cycle Detection & `LocalAuthCache` Context Isolation [checkpoint: 60dd404]

- [x] Task: Resolve mainline cycle lock-ups in `build_mainline` and add cycle tests `fa8961f`
  - [x] Detect cycles when walking `m.room.power_levels` auth chains in `build_mainline` ([`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs)) (`fa8961f`).
  - [x] Add regression tests ensuring cyclic power-level chains terminate deterministically (`fa8961f`).
- [x] Task: Fix cycle detection bailout and isolate `LocalAuthCache` across room versions `60dd404`
  - [x] Fix cycle detection bailout and `V2.1.1`/`V2.2`-specific `LocalAuthCache` context leak by scoping cached auth maps to `StateResVersion` (`60dd404`).
  - [x] Hoist `LocalAuthCache` to amortize resolution cost without cross-version contamination (`ab8bf2f`, `8810dbd`).
- [x] Task: Add falsifiable `local_auth` cache-hit and `state/at.rs` branch coverage tests `c9bb62f`
  - [x] Expand unit coverage for `src/state/at.rs` uncovered branches (`fa88ce4`).
  - [x] Strengthen `local_auth` cache-hit tests in [`tests/unit/test_state_at.rs`](../../../tests/unit/test_state_at.rs) to be strictly falsifiable (`c9bb62f`).

## Phase 2: `V2.1.1` Memoized BFS Transitive Auth & Supplemental Merge Isolation [checkpoint: af68182]

- [x] Task: Enable pure memoized BFS for `V2.1.1` transitive auth context `cd0c1b3`
  - [x] Implement pure memoized BFS in `compute_local_auth` ([`src/state/at.rs`](../../../src/state/at.rs)) for `V2.1.1` transitive `auth_events` walks (`cd0c1b3`).
  - [x] Verify `v2_1_vs_v2_1_1_recursive_auth_lookup` and `v2_1_1_xfail_disconnected_auth` in [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) (`cd0c1b3`).
- [x] Task: Eliminate $O(N)$ auth context iteration and unbounded DFS auth walks `58c29ba`
  - [x] Remove $O(N)$ linear scans over `auth_context` and replace unbounded DFS walks in [`src/state/at.rs`](../../../src/state/at.rs) (`58c29ba`).
  - [x] Share iterative cache setup across state resolution entry points (`aa04265`).
- [x] Task: Strictly isolate `V2.1.1+` supplemental merge to power levels and bans `1a22be6`
  - [x] Restrict `V2.1.1+` supplemental merge in [`src/state/at.rs`](../../../src/state/at.rs) to `m.room.power_levels` and `ban` membership events, excluding `m.room.join_rules` (`1a22be6`).
  - [x] Document the exclusion of `join_rules` in `V2.1.1+` supplemental merges (`af68182`) and cover the `V2.1.1` ban supplementation return path (`dd396db`, `24123de`).

## Phase 3: Architectural Split — `resolve_iterative_sort` vs. `resolve_lattice_fold` (`v0.3.0`) [checkpoint: 8370393]

- [x] Task: Harden lattice mainline provider, sentinel clamping, and `#![no_std]` compilation `02d598a`
  - [x] Refactor lattice resolver to use static event type constants (`cced04c`) and address lattice/delta-chain edge cases (`d74155f`).
  - [x] Fix lattice mainline provider lookup, clamp unreachable mainline sentinels, and restore `#![no_std]` build compatibility (`02d598a`).
- [x] Task: Rename resolver entry points to `resolve_iterative_sort` and `resolve_lattice_fold` `8370393`
  - [x] Split and rename core resolution functions to `resolve_iterative_sort` ([`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs)) and `resolve_lattice_fold` / `resolve_semilattice_fold` ([`src/resolve/semilattice.rs`](../../../src/resolve/semilattice.rs)) for tag `v0.3.0` (`8370393`, `b9c2cd6`, `a71f2b4`).
  - [x] Make `SubgraphResult` and `AuthGraph` generic over `Id` (`f56e420`).
- [x] Task: Expand semilattice, multi-state, and `V2.1.1` sorting test suites `60531bc`
  - [x] Add test coverage for `V2.1.1` sorting, `cmp_by_depth`, and lattice + auth-chain rejection paths in [`tests/unit/test_semilattice.rs`](../../../tests/unit/test_semilattice.rs) (`60531bc`, `0e74575`, `edde2fe`).
  - [x] Move multi-state resolution orchestration from CLI binary into the library (`src/resolve/multi.rs`) and integrate `V2.1+` conflicted subgraphs into `resolve_state_maps` (`a5c0607`, `0a99b47`).

## Phase 4: `MSC4242` (`V2.2`) State DAG Validation, Derived Auth & Security Comparison [checkpoint: f56b068]

- [x] Task: Assert concrete `V2.2` event-ID tie-break winner and CDO anomaly documentation `5d01726`
  - [x] Assert concrete `V2.2` event-ID lexicographical last-write-wins tie-break winner (`v2_2_event_id_tiebreak`) in [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) (`5d01726`).
  - [x] Add synthetic Anomaly 17 fixture and document CDO over-restriction (`6937c3d`).
- [x] Task: Implement `MSC4242` State DAG validation and derived auth (`src/state/dag.rs`) `f56b068`
  - [x] Implement [`src/state/dag.rs`](../../../src/state/dag.rs) with `StateDagCompleteness`, `StateDagValidationError`, `validate_state_dag_ancestors`, `compute_state_before_from_dag`, and `derive_auth_events_from_state_dag` (`f56b068`).
  - [x] Add comprehensive `MSC4242` State DAG unit suite in [`tests/unit/test_state_dag.rs`](../../../tests/unit/test_state_dag.rs), including `test_v2_2_derives_auth_from_single_state_parent_citation` (`f56b068`).
  - [x] Author [`docs/rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md) comparing Stock `V2.1`, `V2.1.1`, and `MSC4242` (`V2.2`) Complement scenarios and documenting the "DAG connectivity vs. DAG honesty" boundary (`f56b068`).

---

## History & Audit Traceability

| Commit SHA | Date | Source & Test Files Touched | Documentation & Audit Linkage | Public-Safety Audit Observation |
| :--- | :--- | :--- | :--- | :--- |
| `fa8961f` / `60dd404` / `c9bb62f` | 2026-06-28 – 2026-07-01 | [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs), [`src/state/at.rs`](../../../src/state/at.rs), [`tests/unit/test_state_at.rs`](../../../tests/unit/test_state_at.rs) | [`docs/rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md) | Prevents infinite mainline loops on cyclic `m.room.power_levels` auth chains and isolates `LocalAuthCache` across room versions. |
| `cd0c1b3` / `58c29ba` / `1a22be6` / `af68182` | 2026-06-29 | [`src/state/at.rs`](../../../src/state/at.rs), [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) | [`docs/rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md) | Memoized BFS bounds transitive auth lookup in `V2.1.1`; restricts supplemental merge to PLs and bans (`af68182`). |
| `02d598a` / `8370393` / `60531bc` / `a5c0607` | 2026-06-29 – 2026-07-03 | [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs), [`src/resolve/semilattice.rs`](../../../src/resolve/semilattice.rs), [`tests/unit/test_semilattice.rs`](../../../tests/unit/test_semilattice.rs) | [`docs/architecture.md`](../../../docs/architecture.md) | Separates spec-compliant `resolve_iterative_sort` from exploratory parallel `resolve_semilattice_fold`. |
| `5d01726` / `6937c3d` / `f56b068` | 2026-07-01 – 2026-09-28 | [`src/state/dag.rs`](../../../src/state/dag.rs), [`tests/unit/test_state_dag.rs`](../../../tests/unit/test_state_dag.rs), [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) | [`docs/rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md), [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) | **Critical (DAG Withholding & Mixed-Federation Split-Brain):** `V2.1.1` diverges from Stock `V2.1` on `SEND01`; neither `V2.1.1` nor `V2.2` detects branch withholding by a dishonest peer. |
