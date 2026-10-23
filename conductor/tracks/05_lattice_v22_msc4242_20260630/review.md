# Track 05 Review & Multi-Perspective Critique Report: Iterative Sort vs. Lattice Fold (`V2.1.1` & `V2.2` / `MSC4242`) & Security Comparison

- **Track ID:** `05_lattice_v22_msc4242_20260630`
- **Track Title:** Iterative Sort vs. Lattice Fold (`V2.1.1` & `V2.2` / `MSC4242`) & Security Comparison
- **Epoch & Commit Range:** `v0.3.0`–`v0.4.0` + Sep 2026 (`60dd404..f56b068`)
- **Review Status:** Completed with Actionable Stage B Remediation Items (`Critical` Public-Safety Risk: DAG Branch Withholding & Mixed-Federation `SEND01` Split-Brain)
- **Primary Audit Reference:** [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Rows 3, 13, 14, 15)

---

## 1. Conductor Review Summary (`/conductor-review` Structure)

### 1.1 Plan & Specification Compliance
| Requirement ID | Requirement Summary | Verification Oracle | Verdict |
| :--- | :--- | :--- | :--- |
| **FR-05-01** | Dual resolution engines (`resolve_iterative_sort` & `resolve_semilattice_fold`) with LUB tie-breaking | [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs), [`src/resolve/semilattice.rs`](../../../src/resolve/semilattice.rs), [`tests/unit/test_semilattice.rs`](../../../tests/unit/test_semilattice.rs) | **PASS** (with non-monotonicity warning on `resolve_semilattice_fold`) |
| **FR-05-02** | Cycle-safe mainline construction (`build_mainline`) & version-scoped `LocalAuthCache` | [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs), [`src/state/at.rs`](../../../src/state/at.rs), [`tests/unit/test_state_at.rs`](../../../tests/unit/test_state_at.rs) | **PASS** |
| **FR-05-03** | Experimental `V2.1.1` memoized BFS transitive auth lookup & `has_ban_evasion_hardening()` post-power-phase screening | [`src/state/at.rs`](../../../src/state/at.rs), [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs), [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) | **PASS (In-Process) / CRITICAL SPLIT-BRAIN RISK if Mixed with Stock V2.1** |
| **FR-05-04** | `MSC4242` (`V2.2`) State DAG validation (`validate_state_dag_ancestors`), `state_before` computation, and derived `auth_events` | [`src/state/dag.rs`](../../../src/state/dag.rs), [`tests/unit/test_state_dag.rs`](../../../tests/unit/test_state_dag.rs) | **PASS (Connectivity) / CRITICAL HONESTY GAP (Branch Withholding)** |
| **FR-05-05** | Cross-suite security comparison (`V2.1` vs. `V2.1.1` vs. `MSC4242` Complement `STATE03`–`STATE09`, `SEND01`) | [`docs/rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md) | **PASS** |

### 1.2 Executive Findings Matrix
| Finding ID | Severity | Perspective | Location | Summary |
| :--- | :--- | :--- | :--- | :--- |
| **F-05-01** | `[Critical]` | `critic-compliance`, `critic-federation-interop` | [`src/basespec/rezzy_types.rs:215-233`](../../../src/basespec/rezzy_types.rs#L215-L233), [`src/state/at.rs:140-158`](../../../src/state/at.rs#L140-L158), [`docs/rezzy_msc4242_security_comparison.md:21-30`](../../../docs/rezzy_msc4242_security_comparison.md#L21-L30) | `StateResVersion::V2_1_1` (`"12.1"`) modifies power-phase `OverlayState` fallback and applies post-power-phase `is_sender_banned` screening (`has_ban_evasion_hardening()`), plus recursive BFS `auth_events` lookup. Mixing `V2.1.1` and Stock `V2.1` (`MSC4297`) servers in the same room causes federation split-brain. |
| **F-05-02** | `[Critical]` | `critic-compliance`, `critic-formal-crypto` | [`src/state/dag.rs:50-90`](../../../src/state/dag.rs#L50-L90), [`docs/rezzy_msc4242_security_comparison.md:122-142`](../../../docs/rezzy_msc4242_security_comparison.md#L122-L142) | Neither `V2.1.1` (`compute_local_auth`) nor `V2.2` (`validate_state_dag_ancestors` / `compute_state_before_from_dag`) can detect **DAG branch withholding** ("DAG honesty"): a malicious peer can omit a concurrent ban/demotion branch while presenting a locally complete, connected subgraph back to `m.room.create`. |
| **F-05-03** | `[High]` | `critic-formal-crypto`, `critic-eng-lead` | [`src/resolve/semilattice.rs:17-52`](../../../src/resolve/semilattice.rs#L17-L52), [`153-202`](../../../src/resolve/semilattice.rs#L153-L202) | `resolve_semilattice_fold` is publicly exported alongside `resolve_iterative_sort` without an `experimental` feature gate, even though its LUB fold evaluates all non-power events against a static `terminal_power_state` snapshot and violates sequential state-dependent Matrix auth semantics (e.g., dependent `m.room.member` invite $\to$ join chains in the non-power phase). |
| **F-05-04** | `[High]` | `critic-eng-lead`, `critic-dx-integrator` | [`src/basespec/rezzy_types.rs:1609-1614`](../../../src/basespec/rezzy_types.rs#L1609-L1614), [`src/auth/mod.rs:690-704`](../../../src/auth/mod.rs#L690-L704) | `LeanEvent` aliases `prev_state_events()` to `&self.auth_events` instead of storing a separate field or enum, requiring subtle version guards (`version != StateResVersion::V2_2`) across `check_auth_with_context` and `DagNode::auth_chain_events` to avoid misinterpreting `prev_state_events` as classic `auth_events`. |
| **F-05-05** | `[High]` | `critic-perf`, `critic-redteam-qa` | [`src/state/dag.rs:76-90`](../../../src/state/dag.rs#L76-L90), [`src/resolve/semilattice.rs:33-37`](../../../src/resolve/semilattice.rs#L33-L37) | `StateDagWalkOptions::default()` caps walks at `max_steps: Some(10_000)` (which can be bypassed if callers pass `None`), and `resolve_semilattice_fold` documents a `# Panics` condition if the resolved mainline does not begin with the resolved `m.room.power_levels` event. |
| **F-05-06** | `[Medium]` | `critic-compliance`, `critic-dx-integrator` | [`src/state/dag.rs:107-113`](../../../src/state/dag.rs#L107-L113), [`src/auth/mod.rs:2100-2130`](../../../src/auth/mod.rs#L2100-L2130) | Cross-room event rejection in `validate_state_dag_ancestors` (`ReferencedForeignRoom`) and `check_auth_chain` (`ForeignRoomEvent`) remains contingent on caller-populated `LeanEvent.room_id: Option<RoomId>`. |

---

## 2. Multi-Perspective Critiques (All 8 Specialized Personas)

### 2.1 Product Management (`critic-pm`)
- **Matrix Spec Coverage (`spec_coverage.csv` 31/35 `full` Claims vs. Reality):**
  - [`docs/spec_coverage.csv`](../../../docs/spec_coverage.csv) rightly marks Row 7 (`MSC4242, State DAGs (v2.2)`) as `experimental`, and Row 4 (`MSC4297, State Resolution v2.1`) explicitly notes that `MSC4297` *"Does NOT specify CDO or ban-evasion hardening -- those are rezzy-internal (V2_1_1), not MSC4297 itself."* However, marking 31/35 rows `full` while [`docs/rezzy_msc4242_security_comparison.md:3-5`](../../../docs/rezzy_msc4242_security_comparison.md#L3-L5) states *"Rezzy currently supports state-resolution V1 only; V2, V2.1.1, and V2.2 are not shipped implementations"* creates a stark contradiction between the CSV matrix and the prose disclaimers.
- **Room Version Roadmap (`V1`–`V12`, `MSC4242`):**
  - Track 05 provides huge product value as an executable specification laboratory comparing Stock `V2.1` (Room V12 / `MSC4297`), `V2.1.1` (`12.1`), `V2.2` (`org.matrix.msc4242.12`), and `V3` (`tk.nutra.cdo.12`). For the Stage B roadmap, product documentation must harmonize the shipping status across `README.md`, `spec_coverage.csv`, `spec_audit.md`, and `rezzy_msc4242_security_comparison.md`.

### 2.2 Principal Engineering Lead (`critic-eng-lead`)
- **`resolve_iterative_sort` vs. `resolve_semilattice_fold` Separation:**
  - Splitting [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs) (`resolve_iterative_sort`) from [`src/resolve/semilattice.rs`](../../../src/resolve/semilattice.rs) (`resolve_semilattice_fold`, renamed from `resolve_lattice_fold` in `8370393` / `b9c2cd6`) cleanly isolated the spec-compliant sequential resolver from the experimental parallel join-semilattice fold.
  - Furthermore, isolating `LocalAuthCache` by `StateResVersion` ([`src/state/at.rs:70-84`](../../../src/state/at.rs#L70-L84), commit `60dd404`) and replacing recursive DFS with memoized BFS in `compute_local_auth` (`cd0c1b3`, `58c29ba`) eliminated both a stack-overflow/exponential-walk vector and a subtle cross-version cache poisoning bug where `V2.1` single-hop `auth_events` lookups polluted `V2.1.1` transitive `auth_events` caches.
- **Field Aliasing Hazard on `LeanEvent` (`auth_events` vs. `prev_state_events`) (`[High]` F-05-04):**
  - In [`src/basespec/rezzy_types.rs:1609-1614`](../../../src/basespec/rezzy_types.rs#L1609-L1614), `LeanEvent::prev_state_events(&self)` returns `&self.auth_events` to avoid adding an extra `Vec<Id>` field to `LeanEvent`. As documented in [`src/auth/mod.rs:690-704`](../../../src/auth/mod.rs#L690-L704), this means calling `event.auth_events()` on a `V2.2` (`MSC4242`) event silently returns its `prev_state_events` (up to 20 arbitrary state events!), which would fail the 10-event limit and `VALID_AUTH_TYPES` whitelist unless every caller remembers to check `version != StateResVersion::V2_2` or call `event.auth_chain_events(version)`.
- **`Option<RoomId>` Type Safety:**
  - Both `src/state/dag.rs` (`validate_state_dag_ancestors`) and `src/auth/mod.rs` (`check_auth_chain`) depend on `LeanEvent.room_id: Option<RoomId>` being populated by the caller to detect `ReferencedForeignRoom` / `ForeignRoomEvent`.

### 2.3 Public-Safety & C2 Compliance (`critic-compliance`)
- **`[Critical]` Finding F-05-01 — `V2.1.1` `SEND01` & Transitive-Auth Consensus Divergence:**
  - `StateResVersion::V2_1_1` (`"12.1"`) differs from Stock `V2.1` (`"12"`, `MSC4297`) in three ways:
    1. **Recursive Transitive `auth_events` Walk (`src/state/at.rs`, `cd0c1b3`):** `V2.1.1` walks `auth_events` transitively via BFS (`v2_1_vs_v2_1_1_recursive_auth_lookup`), whereas Stock `V2.1` inspects only immediate `auth_events` citations.
    2. **Power-Phase Local-Auth Fallback Gating (`src/state/at.rs:140-158`):** Under `has_ban_evasion_hardening()`, `OverlayState::get_event` blocks non-power candidates from falling back to `local_auth` for `m.room.power_levels` and `m.room.join_rules` during the power phase.
    3. **Post-Power-Phase Banned-Sender Screening (`src/resolve/iterative.rs:20-23`, `1a22be6`):** Drops non-power conflicted events whose sender is already banned in the power-phase resolved state before mainline sorting, and excludes `m.room.join_rules` from `route_msc4297_ancestral_power_events` ([`src/resolve/iterative.rs:240-250`](../../../src/resolve/iterative.rs#L240-L250)).
  - **Public-Safety Impact:** If an emergency response federation mixes a `rezzy` homeserver configured with `V2.1.1` and a standard `V2.1` (`MSC4297`) homeserver in the same room, any event that omits a direct auth citation (relying on transitive auth) or triggers the `route_msc4297_ancestral_power_events` `m.room.join_rules` difference will be accepted by one server and rejected by the other—causing an immediate federation split-brain.
- **`[Critical]` Finding F-05-02 — DAG Branch Withholding ("DAG Honesty") in `MSC4242` (`V2.2`) & `V2.1.1`:**
  - As rigorously analyzed in [`docs/rezzy_msc4242_security_comparison.md:122-142`](../../../docs/rezzy_msc4242_security_comparison.md#L122-L142), `MSC4242` (`V2.2`) solves **DAG connectivity** (deriving `auth_events` from deterministic `state_before` over `prev_state_events`, verified by `test_v2_2_derives_auth_from_single_state_parent_citation`), and `STATE05` intentionally preserves actions authorized in `state_before` prior to a concurrent demotion.
  - However, **neither `V2.1.1` nor `V2.2` solves DAG branch withholding**: a compromised C2 homeserver can construct a state event whose `prev_state_events` cites only the pre-revocation branch and omits the concurrent administrative ban/demotion branch. To `validate_state_dag_ancestors` ([`src/state/dag.rs`](../../../src/state/dag.rs)), the subgraph is 100% connected back to `m.room.create` with zero missing references. Detecting branch withholding requires active cross-peer frontier reconciliation (`rezzy-recon` / `MSC4521` / `MSC4511` in Track 11) or certified active-membership witnesses (`V3` / `tk.nutra.cdo.12`).

### 2.4 Performance & Adversarial Liveness (`critic-perf`)
- **Memoized BFS vs. Unbounded DFS (`cd0c1b3`, `58c29ba`):**
  - Replacing unbounded DFS with memoized BFS in `compute_local_auth` and eliminating $O(N)$ linear scans over `auth_context` was a major liveness improvement for deep auth chains.
- **Cycle-Detection Bailout in `build_mainline` (`fa8961f`, `60dd404`):**
  - Before `fa8961f` and `60dd404`, a cyclic `m.room.power_levels` chain in `build_mainline` ([`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs)) caused an infinite loop that froze the resolver thread. The cycle detector now terminates deterministically.
- **Parallel Thread-Scope Contention & Unbounded Walk Options (`[High]` F-05-05):**
  - In [`src/resolve/semilattice.rs:240-250`](../../../src/resolve/semilattice.rs#L240-L250), `compute_lattice_coordinatized_winners` spawns `std::thread::available_parallelism()` OS threads via `std::thread::scope` on every invocation when `feature = "std"` is enabled, regardless of how small `events.len()` is. For small conflicted sets (10–50 events), OS thread spawning overhead exceeds the sequential loop cost, and in an async homeserver (e.g. Tokio) spawning scoped OS threads per room resolution call can cause thread-pool oversubscription.
  - In [`src/state/dag.rs:76-90`](../../../src/state/dag.rs#L76-L90), `StateDagWalkOptions` defaults to `max_steps: Some(10_000)`, which is good defense-in-depth, but callers should be prevented from passing `max_steps: None` on untrusted federation graphs.

### 2.5 Formal Verification & Mathematical Soundness (`critic-formal-crypto`)
- **`[High]` Finding F-05-03 — Non-Monotonicity of Matrix Auth Rules vs. `resolve_semilattice_fold`:**
  - In [`src/resolve/semilattice.rs:63-107`](../../../src/resolve/semilattice.rs#L63-L107), `is_semilattice_winner_better` defines a strict total order (and therefore a valid commutative, associative join-semilattice LUB operator $\sqcup$) over candidate events for a single `(event_type, state_key)` slot using the coordinate tuple:
    $$\text{coord}(e) = (-\text{mainline\_pos}(e),\; \text{origin\_server\_ts}(e),\; \text{event\_id}(e))$$
  - **Mathematical Flaw in Full-Room Resolution:** While the LUB comparator $\sqcup$ over coordinates is associative and commutative, **Matrix non-power state resolution is not a pure per-key semilattice fold because authorization is state-dependent across distinct keys!** Specifically:
    - In `resolve_iterative_sort` (`MSC1693` / `MSC4297`), non-power events are sorted in mainline order and applied *sequentially* to `resolved`. Note that non-power events include `m.room.member` `join` events (when not in the power phase's conflicted auth chain) and state events whose authorization depends on earlier non-power state transitions.
    - In [`src/resolve/semilattice.rs:172-183`](../../../src/resolve/semilattice.rs#L172-L183), `process_lattice_event` evaluates `iterative_auth_ok(ev, ctx.terminal_power_state, ...)` against the **static** `terminal_power_state` snapshot rather than the progressively updated non-power state. Furthermore, if the winning candidate $e_{\max}$ for key $k$ passes auth against `terminal_power_state`, it overwrites $k$, whereas if an event with a higher coordinate failed auth in a naive fold before filtering, it could shadow a valid lower-coordinate event (which `process_lattice_event` avoids by filtering via `iterative_auth_ok` *before* `update_winner_if_better`, but *only* relative to `terminal_power_state`).
  - Therefore, `resolve_semilattice_fold` is a **static-auth approximation**, not an isomorphic re-implementation of `MSC1693` / `MSC4297`. Its module doc (`src/resolve/semilattice.rs:20-21`) acknowledges this (*"an exploratory hypothesis that approximates iterative auth-checks using a fixed terminal snapshot"*), but the function is publicly exported without an `unstable`/`experimental` Cargo feature gate.

### 2.6 Matrix Federation Interop (`critic-federation-interop`)
- **Mixed-Federation Split-Brain (`V2.1.1` vs. Stock `V2.1`):**
  - In [`src/basespec/rezzy_types.rs:187-188`](../../../src/basespec/rezzy_types.rs#L187-L188), `StateResVersion::from_room_version` maps `"12"` to `Self::V2_1` and `"12.1"` to `Self::V2_1_1`. This version string separation is essential and must never be collapsed: a room with `room_version: "12"` MUST always execute `StateResVersion::V2_1` so it stays 100% interop-compatible with Synapse, Conduit/Conduwuit, and Ruma (`MSC4297`).
- **`MSC4242` (`org.matrix.msc4242.12`) Wire Format Interop:**
  - `MSC4242` replaces `auth_events` with `prev_state_events` on the wire and requires preserving `prev_state_events` during redaction ([`src/basespec/rezzy_types.rs:849-851`](../../../src/basespec/rezzy_types.rs#L849-L851), [`1308`](../../../src/basespec/rezzy_types.rs#L1308)). `LeanEvent::from_value` ([`src/basespec/rezzy_types.rs:3500-3505`](../../../src/basespec/rezzy_types.rs#L3500-L3505)) properly rejects `MSC4242` PDUs that still carry `auth_events`.

### 2.7 Adversarial Red-Team & Verification QA (`critic-redteam-qa`)
- **`SEND01` & Traversal Fixture Coverage (`tests/unit/test_traversal.rs`):**
  - Track 05's 12 comparative traversal fixtures in [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) and the Complement cross-reference in [`docs/rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md#L41-L55) are exemplary security engineering: they explicitly test `v2_1_vs_v2_1_1_recursive_auth_lookup`, `v2_1_1_xfail_disconnected_auth`, `v2_1_1_anomaly_02_admin_lockout`, `v2_1_1_anomaly_06b_ghost_moderator`, `v2_1_1_cve_demotion_evasion`, `v2_1_flaw_concurrent_ban_evasion`, and `v2_2_event_id_tiebreak`.
- **Missing Red-Team Tests Identified by Audit:**
  1. **Explicit `V2.1` vs. `V2.1.1` `route_msc4297_ancestral_power_events` Divergence Fixture:** Add a test asserting the exact DAG shape where `V2.1` (which includes `m.room.join_rules` in `route_msc4297_ancestral_power_events` at `src/resolve/iterative.rs:244`) and `V2.1.1` (which excludes it) produce different resolved states, documenting why `"12"` and `"12.1"` cannot be mixed.
  2. **Explicit `MSC4242` Branch Withholding Demonstration Fixture:** Add a unit test in `tests/unit/test_state_dag.rs` showing two federation views of an `MSC4242` room—one where a concurrent ban branch is withheld (passing `validate_state_dag_ancestors` and authorizing the banned user's state event) and one where the full frontier is reconciled via `rezzy-recon`—to concretize the "DAG connectivity vs. DAG honesty" section of `docs/rezzy_msc4242_security_comparison.md`.
  3. **`resolve_semilattice_fold` vs. `resolve_iterative_sort` Differential Fuzzing:** Add a property test / differential fuzzer characterizing the exact multi-key non-power dependency shapes where `resolve_semilattice_fold` diverges from `resolve_iterative_sort`.

### 2.8 Homeserver Integrator & API Ergonomics (`critic-dx-integrator`)
- **Feature-Gating Experimental Resolvers & Room Versions:**
  - Exporting `resolve_semilattice_fold`, `StateResVersion::V2_1_1`, `StateResVersion::V2_2`, and `StateResVersion::V3` in the default public API without an `experimental-algorithms` Cargo feature gate creates a footgun for homeserver integrators who might call `resolve_semilattice_fold` assuming it is a drop-in parallel speedup for `resolve_iterative_sort`.
- **De-Aliasing `prev_state_events` and `auth_events` on `LeanEvent`:**
  - Homeserver integrators implementing or inspecting `LeanEvent` can easily misuse `ev.auth_events` on `V2.2` events because `LeanEvent` stores `prev_state_events` inside `self.auth_events` (`src/basespec/rezzy_types.rs:1609-1614`). Replacing the raw `pub auth_events: Vec<Id>` field access with version-safe accessor methods or an explicit enum `AuthOrStateEdges<Id>` would prevent accidental cross-paradigm misuse.

---

## 3. Actionable Recommendations for Stage B Remediation Tracks

1. **[Stage B — Track 14 / P0 Consensus Safety] Gate `resolve_semilattice_fold` and Private Room Versions Behind `experimental` Feature Flags & Move `cdo.rs` to `tests/`:**
   - Gate `resolve_semilattice_fold` (`src/resolve/semilattice.rs`) behind `#[cfg(feature = "experimental-semilattice")]` (or mark it clearly in type signatures as an approximate resolver), relocate the retired `src/resolve/cdo.rs` into `tests/`, and ensure `StateResVersion::V2_1_1` (`"12.1"`) cannot be accidentally selected for standard Matrix room version `"12"`.
2. **[Stage B — Track 15 / P1 Type Safety] Separate `prev_state_events` from `auth_events` in `LeanEvent` & Require `RoomId`:**
   - Replace the shared `auth_events` storage trick on `LeanEvent` (`src/basespec/rezzy_types.rs:1609-1614`) with distinct fields or a typed `CitationEdges` enum, and require `RoomId` in `validate_state_dag_ancestors` so `ReferencedForeignRoom` is always enforced.
3. **[Stage B — Track 16 / P1 Adversarial Test Expansion] Add Branch-Withholding & `join_rules` Supplementation Divergence Fixtures:**
   - Add the `MSC4242` branch-withholding demonstration test to `tests/unit/test_state_dag.rs` (linking `src/state/dag.rs` to `rezzy-recon` frontier synchronization) and add a minimum-size threshold (`MIN_PARALLEL_EVENTS = 256`) before `resolve_semilattice_fold` spawns OS threads via `std::thread::scope`.
