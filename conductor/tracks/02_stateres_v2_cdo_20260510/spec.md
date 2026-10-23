# Specification: Core `#![no_std]` State Resolution V1/V2/V2.1 & CDO Soundness Retirement (`v0.1.2`–`v0.1.4`)

## 1. Overview & Historical Context

Track `02_stateres_v2_cdo_20260510` covers the evolution of `rezzy` from an experimental formal-methods prototype into a production-capable `#![no_std]` (`alloc`) Matrix State Resolution engine across releases `v0.1.2` (`3d8ee1c`, `fbb38ff`, May 10, 2026), `v0.1.3` (`c0cb626`, May 11, 2026), and `v0.1.4` (`4abfb43`, May 20, 2026), alongside the complete design, SWAR optimization, adversarial falsification, and retirement lifecycle of the **Causal Domination Operator (CDO)** (`ae41adc`, `34fde0c`, `f56b068`, documented in [`docs/cdo_soundness_anomalies.md`](../../../docs/cdo_soundness_anomalies.md)).

During this epoch, `rezzy` was hardened against real-world Matrix federation rooms (exported via `scripts/export_room_dag.py` and `473f27a`, `a845200`, `145a60c`) and strict cross-implementation oracle validation (`9e1f6a0`). This real-world testing exposed subtle tie-breaking and non-determinism traps (`c08001d`, `4025b36`), prompted the removal of unused cryptographic and ZK-trace dependencies (`013603f`, `2e21db6`), upgraded `#![no_std]` hash maps via `hashbrown` (`fbb38ff`), and led to the crucial security discovery that pre-auth domination heuristics (`src/resolve/cdo.rs`) cause permanent federation split-brain.

---

## 2. Functional Requirements & Matrix Spec/MSC Mapping

| Requirement ID | Matrix Spec / MSC Reference | Functional Description | Implementation & Verification |
| :--- | :--- | :--- | :--- |
| **FR-02.1** | Matrix Room Versions 1–12 Algorithm Dispatch | Automatically select and execute State Resolution V1 (legacy depth ordering), V2 ([MSC1693](https://github.com/matrix-org/matrix-spec-proposals/pull/1693) mainline sort + iterative auth), or V2.1 ([MSC4297](https://github.com/matrix-org/matrix-spec-proposals/pull/4297) conflicted subgraph expansion + empty-state power phase) according to room version. | [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs), [`src/resolve/subgraph.rs`](../../../src/resolve/subgraph.rs) (`b79cf53`, `ae41adc`) |
| **FR-02.2** | `#![no_std]` (`alloc`) Data Structures & `hashbrown` | Provide deterministic `#![no_std]` state maps and fast hash lookups using `hashbrown` without `std::collections::HashMap` random seed drift, dropping unused `ed25519-consensus` dependencies from the core resolution pipeline. | [`Cargo.toml`](../../../Cargo.toml), [`src/lib.rs`](../../../src/lib.rs) (`fbb38ff`, `2e21db6`) |
| **FR-02.3** | Spec-Compliant Timestamp & Depth Tie-Breaking | Enforce "later `origin_server_ts` wins" tie-breaking in V2/V2.1 candidate sorting and deterministic `(depth, event_id)` linear ordering (`cmp_by_depth`) to eliminate `HashMap` iteration non-determinism. | [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs) (`4025b36`, `5900cdb`, `c08001d`, `96e3c55`, `5b25c2f`) |
| **FR-02.4** | Non-State Event Isolation & Multi-DAG Merging | Filter out timeline-only events (`state_key: None`) when constructing resolved state maps, and support merging multiple room DAGs (`--merge`, `dagcmp.py`) for comparative federation forensics. | [`src/resolve/multi.rs`](../../../src/resolve/multi.rs), `scripts/dagcmp.py` (`83b9a17`, `1d03dba`, `9e09cc5`, `1931990`, `28ca517`) |
| **FR-02.5** | Retirement of Pre-Auth CDO & Post-Power Resolved-State Screening | Retire the pre-auth Causal Domination Operator (`src/resolve/cdo.rs`) from `prepare_conflicted_and_keys` and replace it in V2.1.1+ with a sound post-power-phase resolved-state screening pass (`is_sender_banned` in [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs)). | [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs), [`src/resolve/cdo.rs`](../../../src/resolve/cdo.rs), [`docs/cdo_soundness_anomalies.md`](../../../docs/cdo_soundness_anomalies.md), [`tests/unit/test_critique.rs`](../../../tests/unit/test_critique.rs) |

---

## 3. Architectural Decisions & Rejected Alternatives

1. **Retirement of the Causal Domination Operator (CDO) (`src/resolve/cdo.rs`, `docs/cdo_soundness_anomalies.md`)**:
   - *What Was Tried*: The CDO was designed as a V2.1.1 pre-filter (`prepare_conflicted_and_keys`) that used SWAR bit-vector sweeps (`34fde0c`, `c0012d5`) over topologically sorted conflicted events to drop events "causally dominated" on an independent branch by a higher-priority administrative action (`is_ban_or_kick`, `is_demotion`, `is_lockdown`).
   - *Why It Failed (Four Soundness Violations)*:
     1. **Dominator-Validity Gap (Decisive Split-Brain)**: Because CDO ran *before* the power phase (`IterativeAuthChecks`), it trusted the structural shape of a ban/kick/demotion/lockdown without verifying that the dominator itself passed authorization. An unprivileged attacker's forged ban on a concurrent branch caused CDO-enabled servers to erase legitimate memberships while standard V2.1 servers kept them — creating a permanent federation fork.
     2. **Anomaly 19 (`19_demoted_but_still_authorized.jsonl`)**: `is_demotion()` triggered on *any* `m.room.power_levels` event on an independent branch (`$pl_demote_priya`) without checking whether the target event (`$priya_bans_troll`) cited an earlier valid PL grant (`$pl_grant_priya`) in its own `auth_events`. Mitigated in `cdo.rs` via `sender_has_pre_demotion_pl()`, before retiring CDO altogether.
     3. **Join-Rules Lockdown Over-Approximation (`06b` / `17`)**: `is_lockdown()` dropped concurrent joins that already cited valid prior authorization (`join_has_prior_authorization()`).
     4. **Forgeable Priority & Depth**: `sort_cdo_events` ordered dominators using unverified event fields (`power_level`, `depth`) before auth validation.
   - *Sound Replacement*: Disconnected CDO from `prepare_conflicted_and_keys` (`src/resolve/iterative.rs:77-107`) and replaced it with `is_sender_banned`, a linear $O(N)$ screening pass that runs *after* the power phase against the authoritative resolved power state.
2. **Rejection of Insecure Invite Fallback for Missing `m.room.create` (`b79cf53` -> `265a4de`)**:
   - *Context*: In `b79cf53` (`2026-05-10`), an experimental fallback attempted to synthesize missing `m.room.create` metadata from `m.room.member` invite events when resolving partial DAGs.
   - *Decision*: Immediately reverted in `265a4de` on the same day after recognizing that invite events can be crafted by non-creators, creating an authorization spoofing vector if treated as room creation truth.
3. **Correction of V2/V2.1 Timestamp Tie-Break Direction (`71c4590` -> `72d836e`, `4025b36`, `5900cdb`)**:
   - *Context*: Commit `71c4590` (`2026-05-11`) flipped the V2/V2.1 `origin_server_ts` tie-breaker to "earlier-wins".
   - *Decision*: Reverted in `72d836e` and locked down with V2.1 regression tests (`4025b36`) and Lean proof updates (`5900cdb`) after verifying that the Matrix State Resolution v2/v2.1 specification mandates that larger (later) `origin_server_ts` values sort later in the reverse-topological / mainline order and therefore overwrite earlier states during iterative replay.

---

## 4. Non-Functional & Public-Safety Invariants

Cross-referencing [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #3 and P0 Remediation #2):

> [!CAUTION]
> **Critical Public-Safety Audit Finding — Retired `src/resolve/cdo.rs` Still in Production Source Tree**:
> While `prepare_conflicted_and_keys` in [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs) no longer invokes CDO, [`src/resolve/cdo.rs`](../../../src/resolve/cdo.rs) remains compiled inside the production `src/resolve/` module and exports `pub fn filter_dominated_events` and `pub fn is_ancestor`. In public-safety or tactical Matrix deployments, any downstream integrator calling `filter_dominated_events` directly re-introduces the **Dominator-Validity Gap**, allowing an unprivileged adversary to inject an auth-invalid ban event on a fork and cause federation split-brain (consensus divergence).
> - **Remediation Track**: Tracked as **P0 Item #2** in [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (relocate `cdo.rs` out of production `src/resolve/` into `tests/`).

- **Deterministic State Map Convergence (`c08001d`, `5b25c2f`)**:
  - Regardless of hash table bucket ordering or thread scheduling, sorting events by `(depth, event_id)` guarantees a strict `LinearOrder`, preventing consensus divergence across heterogeneous homeserver architectures.

---

## 5. Acceptance Criteria & Verification Oracles

1. **Adversarial Critique & Anomaly Suite (`tests/unit/test_critique.rs`)**:
   - `test_anomaly_19_demoted_but_still_authorized` (`tests/critique_data/19_demoted_but_still_authorized.jsonl`) verifies that Priya's ban of the troll survives Alice's concurrent-branch demotion.
   - `test_anomaly_20_concurrent_ban_still_holds` (`tests/critique_data/20_concurrent_ban_still_holds.jsonl`) verifies that Bob's concurrent ban of Charlie does not survive Alice's ban of Bob under full V2.1 resolution (`resolve_full`).
   - `cdo_dominator_validity_gap_scope_inverted` in [`tests/unit/differential_harness.rs`](../../../tests/unit/differential_harness.rs) proves that unverified dominators cannot erase valid memberships in the live resolution path.
2. **Real-World E2E & Regression Suites (`tests/unit/test_sanity.rs`)**:
   - Regression tests for V2/V2.1 later-timestamp-wins (`4025b36`), deterministic `cmp_by_depth` ordering (`96e3c55`), non-state event exclusion (`28ca517`), and state-key handling (`188fb51`).
