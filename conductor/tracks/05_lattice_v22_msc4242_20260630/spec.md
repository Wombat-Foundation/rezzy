# Specification: Iterative Sort vs. Lattice Fold (`V2.1.1` & `V2.2` / `MSC4242`) & Security Comparison

## 1. Overview & Historical Context

Between `v0.3.0` (`8370393`, Jun 30, 2026), `v0.4.0` (`a71f2b4`, Jun 30, 2026), and the `dev -> master` merge (`f56b068`, PR #14, Sep 28, 2026), `rezzy` formalized the architectural split between two distinct state resolution paradigms and three experimental post-V2.0 room version models:

1. **Architectural Split & Idiomatic Rename (`8370393`, Tag `v0.3.0`, Jun 30, 2026):**
   - Split the monolithic resolver entry points into [`resolve_iterative_sort`](../../../src/resolve/iterative.rs) (sequential reverse-topological power phase followed by mainline-sorted iterative auth checks for `V2`, `V2.1`, and `V2.1.1`) and `resolve_lattice_fold` (later refined to [`resolve_semilattice_fold`](../../../src/resolve/semilattice.rs), replacing sequential non-power mainline sorting with a parallelizable causal coordinatization projection and commutative Least Upper Bound (LUB) join-semilattice fold).
2. **`V2.1.1` Transitive Auth Walk, Cache Isolation & Supplemental Merge Hardening (`60dd404`, `cd0c1b3`, `58c29ba`, `1a22be6`, `af68182`, Jun 29, 2026):**
   - Fixed a cycle-detection bailout bug and a cross-version `LocalAuthCache` context leak between `V2.1` and `V2.1.1`/`V2.2` (`60dd404`).
   - Replaced unbounded DFS auth traversal with a pure memoized BFS for `V2.1.1` transitive `auth_events` context (`cd0c1b3`, `58c29ba`).
   - Strictly isolated `V2.1.1+` power-phase supplemental merge to power levels and bans (`1a22be6`, `af68182`), preventing `join_rules` from leaking across phases before later aligning `OverlayState` to `MSC4297` (`src/state/at.rs`).
3. **`MSC4242` (`V2.2`) State DAG Validation & Derived Auth (`5d01726`, `f56b068`, Jul–Sep 2026):**
   - Implemented [`src/state/dag.rs`](../../../src/state/dag.rs) (`validate_state_dag_ancestors`, `compute_state_before_from_dag`, `derive_auth_events_from_state_dag`) and [`tests/unit/test_state_dag.rs`](../../../tests/unit/test_state_dag.rs) to validate explicit `prev_state_events` graphs (max fanout 20, state-only parents, root termination at `m.room.create`, rejected-ancestor cascade) and derive required `auth_events` directly from deterministic `state_before`.
4. **Security Comparison & Threat Boundary Analysis (`f56b068`, [`docs/rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md)):**
   - Mapped 12 adversarial traversal fixtures in [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) against the Complement `MSC4242` test suite (`STATE03`, `STATE05`, `STATE06`, `STATE07`, `STATE09`, `SEND01`) and documented the fundamental distinction between **DAG connectivity** and **DAG honesty**.

---

## 2. Functional Requirements & Matrix Spec/MSC Mapping

| Requirement ID | Functional Requirement | Implementation Locus | Verification / Spec Mapping |
| :--- | :--- | :--- | :--- |
| **FR-05-01** | **Dual Resolution Engines (`resolve_iterative_sort` & `resolve_semilattice_fold`):** Provide sequential iterative resolution (`src/resolve/iterative.rs`) alongside commutative LUB join-semilattice folding (`src/resolve/semilattice.rs`) over mainline coordinates `(mainline_pos, origin_server_ts, event_id)`. | [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs), [`src/resolve/semilattice.rs`](../../../src/resolve/semilattice.rs) | `MSC1693` (V2), `MSC4297` (V2.1); [`tests/unit/test_semilattice.rs`](../../../tests/unit/test_semilattice.rs) |
| **FR-05-02** | **Cycle-Safe Mainline Construction & Version-Scoped Auth Cache:** Detect cycles in `m.room.power_levels` auth chains during `build_mainline` without infinite loops (`fa8961f`, `60dd404`) and key `LocalAuthCache` by `StateResVersion` to prevent cross-version context pollution (`60dd404`). | [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs), [`src/state/at.rs`](../../../src/state/at.rs) | [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) |
| **FR-05-03** | **Experimental `V2.1.1` Transitive Auth Lookup & Ban-Evasion Hardening:** Support memoized BFS transitive `auth_events` lookup (`cd0c1b3`) and post-power-phase banned-sender screening gated by `StateResVersion::has_ban_evasion_hardening()`. | [`src/state/at.rs`](../../../src/state/at.rs), [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs) | [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) (`v2_1_vs_v2_1_1_recursive_auth_lookup`, `v2_1_flaw_concurrent_ban_evasion`) |
| **FR-05-04** | **`MSC4242` (`V2.2`) State DAG Validation & Auth Derivation:** Validate `prev_state_events` graphs (fanout $\le 20$, `CreateWithPrevStateEvents`, `ReferencedNonStateEvent`, `ReferencedForeignRoom`, `ReferencedRejectedEvent`, `CycleDetected`) and derive required `auth_events` from `compute_state_before_from_dag`. | [`src/state/dag.rs`](../../../src/state/dag.rs) | `MSC4242` (`org.matrix.msc4242.12`); [`tests/unit/test_state_dag.rs`](../../../tests/unit/test_state_dag.rs) |
| **FR-05-05** | **Cross-Suite Security Matrix (`V2.1` vs. `V2.1.1` vs. `MSC4242`):** Maintain an explicit mapping between `rezzy` unit fixtures and Complement `MSC4242` scenarios (`STATE03`–`STATE09`, `SEND01`) in [`docs/rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md). | [`docs/rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md) | [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs), [`tests/unit/test_state_dag.rs`](../../../tests/unit/test_state_dag.rs) |

---

## 3. Architectural Decisions & Rejected Alternatives

1. **Retiring `V2.1.1` CDO Pre-Filtering in Favor of Post-Power-Phase Banned-Sender Screening (`docs/rezzy_msc4242_security_comparison.md`, `docs/cdo_soundness_anomalies.md`):**
   - *Rejected Approach:* Early `V2.1.1` applied a Causal Domination Operator (CDO) before the iterative resolver to drop events causally dominated by administrative actions.
   - *Why Rejected:* As proven by Anomalies 19 and 20 (`tests/critique_data/19_demoted_but_still_authorized.jsonl`, `20_concurrent_ban_still_holds.jsonl`), an auth-invalid forged admin event could erase a valid concurrent event via CDO, causing a federation split-brain. `V2.1.1` retired CDO from the live path and instead checks the resolved banned-sender predicate after the power phase completes.
2. **Isolating Supplemental Merge in `V2.1.1` (`1a22be6`, `af68182`) vs. `MSC4242` Derived Auth (`src/state/dag.rs`):**
   - *Problem:* In `V2.1`, an event whose flat `auth_events` list omits `m.room.join_rules` (`v2_1_strictness_future_v2_2_should_pass`) is rejected, yet blindly supplementing `join_rules` from resolved state during `V2.1.1` caused regressions on concurrent join-rule transitions (`1a22be6`).
   - *Decision:* `V2.1.1` restricts supplemental merges strictly to power levels and bans (`af68182`), whereas `V2.2` (`MSC4242`) eliminates the flat `auth_events` under-population bug class entirely by deriving `auth_events` deterministically from `compute_state_before_from_dag` over `prev_state_events` (`test_v2_2_derives_auth_from_single_state_parent_citation`).
3. **Framing `resolve_semilattice_fold` as an Exploratory Hypothesis (`src/resolve/semilattice.rs`):**
   - While `is_semilattice_winner_better` forms a true commutative, associative join-semilattice over `(mainline_pos, origin_server_ts, event_id)` enabling `std::thread::scope` data parallelism, it approximates sequential state-dependent iterative auth checks against a fixed snapshot. Consequently, `resolve_iterative_sort` remains the canonical spec-compliant resolver.

---

## 4. Non-Functional & Public-Safety Invariants

Cross-referencing the [Public-Safety Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md):

> [!CAUTION]
> **Public-Safety Risk — Critical (DAG Withholding & Mixed-Federation `SEND01` Split-Brain):**
> As audited in [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row 13, [`rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md)):
> 1. **Mixed-Federation Split-Brain (`V2.1.1` is Non-Standard):** `V2.1.1` (`12.1`) is a `rezzy`-private experimental variant with recursive `auth_events` lookup and post-power-phase ban screening (`has_ban_evasion_hardening()`). Mixing `V2.1.1` nodes with Stock `V2.1` (`MSC4297`) homeservers in the same room causes consensus divergence (split-brain) on progressive ban and omitted-direct-citation DAG shapes.
> 2. **DAG Connectivity vs. DAG Honesty (Branch Withholding Attack):** Both `validate_state_dag_ancestors` (`V2.2`) and `compute_local_auth` (`V2.1.1`) validate only that the *supplied local subgraph* is connected back to `m.room.create`. Neither can detect **branch withholding**, where a malicious federation peer omits a concurrent administrative revocation/ban branch entirely so that `state_before` appears complete and connected back to `m.room.create` while excluding the revocation.
> 3. **Current V1 Scope Gate (`aeececf`, `0b6a2bc`):** Both [`docs/rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md) and [`docs/spec_audit.md`](../../../docs/spec_audit.md) explicitly note that `V2.1.1` and `V2.2` are experimental design/test implementations, not shipped production federation room versions.

---

## 5. Acceptance Criteria & Verification Oracles

1. **Traversal Security Matrix Oracles:** All 12 comparative traversal fixtures in [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) (`v2_1_vs_v2_1_1_recursive_auth_lookup`, `v2_1_1_xfail_disconnected_auth`, `v2_1_1_anomaly_02_admin_lockout`, `v2_1_1_anomaly_06b_ghost_moderator`, `v2_1_1_cve_demotion_evasion`, `v2_1_flaw_concurrent_ban_evasion`, `v2_2_event_id_tiebreak`, etc.) pass deterministically.
2. **`MSC4242` State DAG Validation & Auth Derivation Oracles:** [`tests/unit/test_state_dag.rs`](../../../tests/unit/test_state_dag.rs) verifies 20-parent fanout limits, `m.room.create` invariants, foreign-room and rejected-parent cascading rejection, and single-parent derived auth (`test_v2_2_derives_auth_from_single_state_parent_citation`).
3. **Semilattice Commutativity & Parallel Fold Parity:** [`tests/unit/test_semilattice.rs`](../../../tests/unit/test_semilattice.rs) verifies LUB commutativity, associativity, mainline sentinel clamping (`02d598a`), and `resolve_semilattice_fold` determinism.
