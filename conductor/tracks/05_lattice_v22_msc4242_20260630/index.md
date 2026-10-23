# Track 05: Iterative Sort vs. Lattice Fold (`V2.1.1` & `V2.2` / `MSC4242`) & Security Comparison (`v0.3.0`–`v0.4.0`)

- **Track ID:** `05_lattice_v22_msc4242_20260630`
- **Type:** `architecture`
- **Status:** `completed`
- **Epoch & Commit Range:** `v0.3.0`–`v0.4.0` + Sep 2026 (`6268aab..a71f2b4`, `60dd404`, `cd0c1b3`, `1a22be6`, `02d598a`, `8370393`, `b9c2cd6`, `5d01726`, `f56b068`)

## Track Artifacts

- [Specification (`./spec.md`)](./spec.md)
- [Implementation Plan (`./plan.md`)](./plan.md)
- [Track Metadata (`./metadata.json`)](./metadata.json)
- [Public-Safety Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md)

## Linked Repository Documentation & Source Modules

### Documentation (`docs/`)
- [`rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md) — Security comparison matrix between Stock `V2.1` (`MSC4297`), experimental `V2.1.1` (`12.1`), and experimental `V2.2` (`MSC4242` State DAGs), plus the "DAG connectivity vs. DAG honesty" boundary.
- [`cdo_soundness_anomalies.md`](../../../docs/cdo_soundness_anomalies.md) — Retirement of the unsound `V2.1.1` CDO pre-filter in favor of post-power-phase banned-sender screening.

### Core Source Modules (`src/`)
- [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs) — `resolve_iterative_sort` (`V2`, `V2.1`, `V2.1.1`), power-phase Kahn sort, mainline non-power phase, and `has_ban_evasion_hardening()` guards.
- [`src/resolve/semilattice.rs`](../../../src/resolve/semilattice.rs) — `resolve_semilattice_fold` (originally `resolve_lattice_fold`), `is_semilattice_winner_better`, and `route_power_events`.
- [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs) — `build_mainline` with cycle detection bailout (`fa8961f`, `60dd404`) and `compute_closest_mainline_positions`.
- [`src/state/dag.rs`](../../../src/state/dag.rs) — `MSC4242` State DAG primitives (`StateDagCompleteness`, `StateDagValidationError`, `validate_state_dag_ancestors`, `compute_state_before_from_dag`, `derive_auth_events_from_state_dag`).
- [`src/state/at.rs`](../../../src/state/at.rs) — `LocalAuthCache` version-scoping (`60dd404`), pure memoized BFS for `V2.1.1` transitive auth context (`cd0c1b3`), and `OverlayState` supplementation (`1a22be6`).

### Verification Oracles (`tests/`)
- [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) — `V2.1`, `V2.1.1`, and `V2.2` traversal, recursive auth lookup, ban supplementation, and event-ID tie-break tests.
- [`tests/unit/test_state_dag.rs`](../../../tests/unit/test_state_dag.rs) — `MSC4242` State DAG completeness, fanout, ancestor validation, and `test_v2_2_derives_auth_from_single_state_parent_citation`.
- [`tests/unit/test_semilattice.rs`](../../../tests/unit/test_semilattice.rs) — Commutative Least Upper Bound (LUB) join-semilattice fold and mainline coordinatization tests.
