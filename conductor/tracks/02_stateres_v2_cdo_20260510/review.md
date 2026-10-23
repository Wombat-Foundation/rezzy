# Architectural & Multi-Perspective Review: Track 02 — Core `#![no_std]` State Resolution V1/V2/V2.1 & CDO Soundness Retirement (`v0.1.2`–`v0.1.4`)

## 1. Executive Review Summary (`/conductor-review`)

- **Track ID**: `02_stateres_v2_cdo_20260510`
- **Epoch**: `v0.1.2`–`v0.1.4` (April 12–May 20, 2026, plus CDO soundness lifecycle `ae41adc`, `34fde0c`, `f56b068`)
- **Commit Range**: `5cf21de..4abfb43` (plus `ae41adc`, `34fde0c`, `f56b068`)
- **Review Verdict**: **COMPLETED WITH P0 PUBLIC-SAFETY REMEDIATION REQUIRED**
- **Cross-Referenced Audit**: [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #3 & P0 Item #2), [`docs/cdo_soundness_anomalies.md`](../../../docs/cdo_soundness_anomalies.md), [`TODO.txt`](../../../TODO.txt)

### Plan & Guideline Compliance Checklist
- [x] **Plan Completion**: All 4 phases in [`plan.md`](./plan.md) (`a845200` through `f56b068`) are verified in repository history.
- [x] **State Resolution V1 / V2 / V2.1 (`MSC4297`) Dispatch**: Implemented across [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs) and [`src/resolve/subgraph.rs`](../../../src/resolve/subgraph.rs) (`b79cf53`, `ae41adc`).
- [x] **Pre-Auth CDO Disconnected from Live Path**: Verified in [`src/resolve/iterative.rs:77-107`](../../../src/resolve/iterative.rs#L77-L107) (`prepare_conflicted_and_keys`) and replaced by post-power [`is_sender_banned`](../../../src/resolve/iterative.rs#L508-L536) screening (`f56b068`).
- [ ] **CRITICAL P0 Audit Issue Open**: Retired [`src/resolve/cdo.rs`](../../../src/resolve/cdo.rs) remains compiled inside the production `src/resolve/` module (`pub mod cdo;` in [`src/resolve/mod.rs:3`](../../../src/resolve/mod.rs#L3), re-exported at crate root via `pub use resolve::*;` in [`src/lib.rs:82`](../../../src/lib.rs#L82) as `rezzy::cdo::apply_cdo_filter` and `rezzy::cdo::is_ancestor`).

---

## 2. Multi-Perspective Critique (8 Specialized Personas)

### 2.1 Product Management (`critic-pm`)
- **Matrix Spec Coverage & Release Maturity**: Across `v0.1.2` (`fbb38ff`), `v0.1.3` (`c0cb626`), and `v0.1.4` (`4abfb43`), Track 02 matured `rezzy` from a single-version prototype into a multi-version engine covering Room Versions 1–12 (State Res V1, V2/[MSC1693](https://github.com/matrix-org/matrix-spec-proposals/pull/1693), and V2.1/[MSC4297](https://github.com/matrix-org/matrix-spec-proposals/pull/4297)), backed by real-world Synapse/Ruma room fixtures (`a845200`, `145a60c`) and multi-DAG forensic merging (`9e09cc5`).
- **Finding `[High]` — Non-Standard `StateResVersion::V2_1_1` (`"12.1"`) Divergence Risk**: Track 02 introduced `StateResVersion::V2_1_1` mapped from room version string `"12.1"` ([`src/basespec/rezzy_types.rs:187`](../../../src/basespec/rezzy_types.rs#L187)). While [`src/basespec/rezzy_types.rs:83-101`](../../../src/basespec/rezzy_types.rs#L83-L101) clearly documents that `V2_1_1` is a `rezzy`-internal designation for ban-evasion hardening, product documentation must explicitly warn operators that `V2_1_1` is not a ratified Matrix room version and must never be substituted for stock `V2_1` (`"12"`) in heterogeneous federations (see [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) Row #13 & P0 Item #4).

### 2.2 Principal Engineering Lead (`critic-eng-lead`)
- **`#![no_std]` Data Structures & Determinism**: Upgrading to `hashbrown` (`fbb38ff`), dropping unused `ed25519-consensus` from the core resolver (`2e21db6`), and enforcing `(depth, event_id)` linear ordering (`cmp_by_depth`, `96e3c55`, `5b25c2f`) eliminated hash-iteration non-determinism across platforms.
- **Finding `[Critical]` — Retired `src/resolve/cdo.rs` Remains Exposed in Production Crate Namespace (`P0 #2`)**:
  - In [`src/resolve/mod.rs:3`](../../../src/resolve/mod.rs#L3), `pub mod cdo;` is unconditionally compiled into the production library, and [`src/lib.rs:82`](../../../src/lib.rs#L82) (`pub use resolve::*;`) exposes `rezzy::cdo::apply_cdo_filter` ([`src/resolve/cdo.rs:665-687`](../../../src/resolve/cdo.rs#L665-L687)) and `rezzy::cdo::is_ancestor` ([`src/resolve/cdo.rs:88-130`](../../../src/resolve/cdo.rs#L88-L130)) to all downstream consumers.
  - Even though `src/resolve/mod.rs:12-18` avoids `pub use cdo::*;`, keeping 688 lines of known-unsound pre-auth domination logic inside `src/resolve/cdo.rs` violates production code hygiene, inflates compile/audit surface, and invites accidental invocation by downstream integrators. Per [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (P0 Item #2), `cdo.rs` must be relocated out of `src/` into `tests/` (or gated behind `#[cfg(test)]`).
- **Finding `[Low]` — Duplicate `EventType::from` Allocations in `derive_all_conflicted_keys`**: As noted in the `TODO(perf)` comment at [`src/resolve/iterative.rs:124-135`](../../../src/resolve/iterative.rs#L124-L135), `derive_all_conflicted_keys` constructs `EventType::from(ev.event_type.as_str())` for every conflicted event, and the power/non-power loops reconstruct it again on insertion into `resolved`, causing duplicate `Box<str>` heap allocations for custom state event types (`EventType::Custom`).

### 2.3 Public-Safety & C2 Compliance (`critic-compliance`)
- **Prevention of Federation Split-Brain & Auth Spoofing**:
  - Track 02 caught and retired two existential security flaws before they could corrupt production deployments:
    1. **The CDO Dominator-Validity Gap (`f56b068`)**: Pre-auth CDO (`apply_cdo_filter` in [`src/resolve/cdo.rs:665-687`](../../../src/resolve/cdo.rs#L665-L687)) trusted the structural shape of a ban, kick, PL demotion, or join-rules lockdown on an independent branch without verifying that the dominator itself passed `IterativeAuthChecks`. An unprivileged attacker (`power_level: 0`) injecting a forged ban with an earlier `origin_server_ts` caused CDO servers to drop valid victim joins while stock Synapse/Ruma V2.1 servers kept them — a permanent federation split-brain.
    2. **Insecure Invite Fallback for Missing `m.room.create` (`b79cf53` -> `265a4de`)**: Reverted on the same day after recognizing that synthesizing missing room creation metadata from `m.room.member` invite events allowed non-creator invite senders to spoof room creation authority.
- **Finding `[Critical]` — Public Exposure of `rezzy::cdo::apply_cdo_filter` Enables Trivial Split-Brain & Forgeable Priority Exploits**:
  - Not only does [`apply_cdo_filter`](../../../src/resolve/cdo.rs#L665-L687) suffer from the Dominator-Validity Gap, [`sort_cdo_events`](../../../src/resolve/cdo.rs#L187-L224) orders dominators by `b.power_level.cmp(&a.power_level)` (line 206) — trusting the author-supplied `LeanEvent::power_level` field before auth chain derivation! Any downstream C2 homeserver calling `rezzy::cdo::apply_cdo_filter` as a pre-pass before state resolution is immediately vulnerable to arbitrary membership erasure by unprivileged federation peers.
- **Finding `[High]` — `V2_1_1` Supplemental Power-Event Narrowing Diverges from Stock `MSC4297` on `m.room.join_rules`**:
  - In [`route_msc4297_ancestral_power_events`](../../../src/resolve/iterative.rs#L202-L255), lines 240–249 deliberately exclude ancestral `m.room.join_rules` from `power_events` when `version` is `V2_1_1` or `V2_2` (`let is_join_rules_allowed = ev.event_type == "m.room.join_rules" && version == StateResVersion::V2_1;`), and [`OverlayState::get_event`](../../../src/state/at.rs#L140-L158) narrows the power-phase `local_auth` fallback under `has_ban_evasion_hardening()`. While this mitigates the "Invite Lock" / `SEND01` pathology, it means a server running `V2_1_1` in a standard room version `"12"` room will compute a different resolved state than a stock Synapse/Ruma `V2_1` server on `SEND01`-shaped graphs ([`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) Row #13).

### 2.4 Performance & Adversarial Liveness (`critic-perf`)
- **SWAR Bit-Vector Sweeps vs. Post-Power Linear Screening**:
  - While CDO (`compute_cdo_bit_masks_chunk` in [`src/resolve/cdo.rs:140-185`](../../../src/resolve/cdo.rs#L140-L185)) used 256-bit/512-bit SWAR bitmask sweeps ($O(N \cdot \text{WORDS\_PER\_CHUNK})$), it required building a full Kahn topological sort and adjacency structure over `conflicted_events ∪ auth_context` (`build_adjacency_structures`, lines 239–377) *in addition* to the main resolver's Kahn sort.
  - Replacing pre-auth CDO with post-power [`is_sender_banned`](../../../src/resolve/iterative.rs#L508-L536) is both mathematically sound and algorithmically cheaper: it performs a single $O(1)$ persistent tree lookup (`resolved.get(query).or_else(|| unconflicted_state.get(query))`) per non-power conflicted event.
- **Finding `[Medium]` — Unbounded BFS in `cdo::is_ancestor` Without Depth Pruning**:
  - [`rezzy::cdo::is_ancestor`](../../../src/resolve/cdo.rs#L88-L130) performs an unpruned DFS/BFS over `prev_events.iter().chain(ev.auth_events.iter())` allocating a `BTreeSet` of visited references because `event.depth` cannot be trusted on unverified input. If any caller invokes `is_ancestor` in a loop over a deep DAG ($10^4+$ events), it incurs $O(V(V+E)\log V)$ time. Relocating `cdo.rs` to test-only scope prevents production misuse in hot paths (where `reachability.rs` / `RoaringBitmap` indexes should be used instead).

### 2.5 Formal Verification & Mathematical Soundness (`critic-formal-crypto`)
- **Falsification of Pre-Auth Domination & Proof of `LinearOrder`**:
  - Track 02 formally proved in Lean 4 (`RumaLean/StateRes.lean`, `5b25c2f`) that `(depth, event_id)` and the V2/V2.1 candidate tie-breaker form a strict `LinearOrder`, guaranteeing that state resolution is invariant under `HashMap` bucket permutation (`c08001d`).
  - More importantly, Track 02 established the fundamental soundness theorem documented in [`src/resolve/cdo.rs:38`](../../../src/resolve/cdo.rs#L38):
    $$\text{A pre-sort drop of candidate } e \text{ is sound} \iff \text{IterativeAuthChecks}(e) = \text{reject}.$$
    Because `IterativeAuthChecks` depends on the authoritative `resolved` power state computed at the *end* of Phase 1 (the power phase), no pre-power-phase operator can decide dominator validity without first running Phase 1.
- **Finding `[Low]` — Post-Power Screening Scope (`is_sender_banned`) vs. Under-Powered Senders**:
  - The doc comment on [`StateResVersion::has_ban_evasion_hardening`](../../../src/basespec/rezzy_types.rs#L219-L221) states: *"dropping non-power conflicted events whose sender is already banned/under-powered in the resolved state before mainline sort"*, whereas [`is_sender_banned`](../../../src/resolve/iterative.rs#L508-L536) only checks `m.get_membership() == Some(MEM_BAN)` (not whether the sender's PL in `resolved` is below the required threshold, which is checked immediately afterward during the non-power `event_auth_ok` loop). Since dropping before `mainline_sort` does not change the relative order of surviving events, checking `MEM_BAN` in `is_sender_banned` and checking PL in `event_auth_ok` is completely equivalent in output, but the doc comment at [`src/basespec/rezzy_types.rs:220`](../../../src/basespec/rezzy_types.rs#L220) should be aligned with [`src/resolve/iterative.rs:498-507`](../../../src/resolve/iterative.rs#L498-L507).

### 2.6 Matrix Federation Interop (`critic-federation-interop`)
- **Timestamp Tie-Break & Non-State Isolation Parity**:
  - Commit `72d836e` / `4025b36` fixed a critical V2/V2.1 interop bug (`71c4590`) where `origin_server_ts` tie-breaking had been inverted to "earlier-wins", restoring exact parity with the Matrix specification ("larger/later `origin_server_ts` wins").
  - Commit `1931990` / `28ca517` ensured timeline events (`state_key: None`) are never inserted into resolved state maps.
  - Commit `1ef1301` / `765a956` fixed `derive_all_conflicted_keys` and `conflicted_keys` gating ([`src/resolve/iterative.rs:318-320`](../../../src/resolve/iterative.rs#L318-L320)) so events pulled in purely as supplemental auth-chain context ($\text{auth}(C) \setminus \text{auth}(U)$ or `MSC4297` subgraph expansion) cannot overwrite a state key that all merge parents already agreed upon.
- **Finding `[Medium]` — Conflicted `m.room.create` Slow-Path Tie-Break**:
  - In [`execute_power_phase`](../../../src/resolve/iterative.rs#L481-L492), if `m.room.create` is not in `unconflicted_state`, lines 488–492 select the `m.room.create` event in `conflicted_events` with the lexicographically smallest `event_id` (`min_by_key(|ev| &ev.event_id)`), without checking `!ev.rejected` or `ev.prev_events.is_empty()` first. If an attacker injects a malformed/rejected `m.room.create` with `prev_events` and a smaller `event_id` into `conflicted_events`, `create_ev` could bind to the invalid create event before `check_auth` rejects it. Filtering `.filter(|ev| !ev.rejected && ev.prev_events.is_empty() && ev.event_type == M_ROOM_CREATE)` hardens this slow path.

### 2.7 Adversarial Red-Team & Verification QA (`critic-redteam-qa`)
- **Exemplary Adversarial Fixture & Differential Coverage**:
  - [`tests/unit/test_critique.rs`](../../../tests/unit/test_critique.rs) (Anomalies 01 through 21, including [`test_anomaly_19_demoted_but_still_authorized`](../../../tests/unit/test_critique.rs#L589-L634) and [`test_anomaly_20_concurrent_ban_still_holds`](../../../tests/unit/test_critique.rs#L649-L659)) and [`tests/unit/differential_harness.rs`](../../../tests/unit/differential_harness.rs) ([`dominated_winner_generator`](../../../tests/unit/differential_harness.rs#L665-L703), [`power_phase_fallback_generator`](../../../tests/unit/differential_harness.rs#L716-L734), and [`cdo_dominator_validity_gap_scope_inverted`](../../../tests/unit/differential_harness.rs#L794-L922)) represent best-in-class adversarial verification.
  - Notably, [`test_anomaly_19_demoted_but_still_authorized`](../../../tests/unit/test_critique.rs#L602-L612) explicitly asserts the winning `event_id` (`Some("$priya_bans_troll")`) and asserts that `m.room.power_levels` remains unresolved rather than relying on an ambiguous `0` default from `get_user_power_level`.
- **Finding `[Medium]` — Hardcoded `/tmp/opencode/res_tmp` Path in Ignored Closure Ratio Test**:
  - In [`tests/unit/test_critique.rs:699-715`](../../../tests/unit/test_critique.rs#L699-L715), `test_ip_closure_ratio` references `/tmp/opencode/res_tmp` for large fixtures (`real_dag_52k_room.json`, `realistic_large_room.json`). Parameterizing this via an environment variable (e.g., `REZZY_LARGE_FIXTURES_DIR`) with a fallback to `tests/fixtures/` improves reproducibility across developer machines and CI runners.

### 2.8 Homeserver Integrator & API Ergonomics (`critic-dx-integrator`)
- **API Ergonomics**:
  - [`IterativeInputs`](../../../src/resolve/iterative.rs#L542-L575) and [`ResolveOptions`](../../../src/resolve/iterative.rs#L690-L709) cleanly bundle the 6 required inputs and optional caches (`external_auth_cache`, `conflicted_keys_override`).
- **Finding `[High]` — `resolve_iterative_sort` Default `derive_all_conflicted_keys` Pitfall for Naive Callers**:
  - As documented in [`derive_all_conflicted_keys`](../../../src/resolve/iterative.rs#L109-L123), callers of [`resolve_iterative_sort`](../../../src/resolve/iterative.rs#L667-L686) pass a single flat `conflicted_events` map containing both genuinely conflicted state events *and* supplemental auth-difference / `MSC4297` subgraph events, without passing `conflicted_keys_override`. Consequently, `derive_all_conflicted_keys` treats *every* event in `conflicted_events` (including supplemental auth-diff events!) as eligible to overwrite its own `(event_type, state_key)` in `resolved`. Only callers using [`resolve_state_maps`](../../../src/resolve/multi.rs) or passing [`ResolveOptions::conflicted_keys_override`](../../../src/resolve/iterative.rs#L694) get the narrow pre-supplementation key guard. The doc comment on [`resolve_iterative_sort`](../../../src/resolve/iterative.rs#L578-L665) should prominently warn integrators to either use `resolve_state_maps` or supply `conflicted_keys_override` when `conflicted_events` includes supplemental auth-chain events.

---

## 3. Summary of Findings & Severity Classification

| ID | Severity | Persona | Location | Summary |
| :--- | :---: | :--- | :--- | :--- |
| **F-02.1** | `[Critical]` | `critic-eng-lead`, `critic-compliance` | [`src/resolve/cdo.rs:1-688`](../../../src/resolve/cdo.rs#L1-L688), [`src/resolve/mod.rs:3`](../../../src/resolve/mod.rs#L3) | Retired, unsound `cdo.rs` (`apply_cdo_filter`, `sort_cdo_events`) is still compiled and exported in the production `rezzy::resolve::cdo` / `rezzy::cdo` namespace (`rezzy_docs_public_safety_audit.md` Row #3, P0 #2). |
| **F-02.2** | `[High]` | `critic-pm`, `critic-compliance` | [`src/resolve/iterative.rs:240-249`](../../../src/resolve/iterative.rs#L240-L249), [`src/basespec/rezzy_types.rs:187,230`](../../../src/basespec/rezzy_types.rs#L187) | `StateResVersion::V2_1_1` (`"12.1"`) diverges from stock `MSC4297` (`V2_1`) on `m.room.join_rules` supplementation (`SEND01`) and must not be mixed with stock V2.1 servers (`rezzy_docs_public_safety_audit.md` Row #13, P0 #4). |
| **F-02.3** | `[High]` | `critic-dx-integrator` | [`src/resolve/iterative.rs:109-153,667-686`](../../../src/resolve/iterative.rs#L109-L153) | Calling `resolve_iterative_sort` without `conflicted_keys_override` treats supplemental auth-diff events inside `conflicted_events` as genuinely conflicted keys. |
| **F-02.4** | `[Medium]` | `critic-federation-interop` | [`src/resolve/iterative.rs:487-492`](../../../src/resolve/iterative.rs#L487-L492) | Conflicted `m.room.create` slow-path selection does not filter out `ev.rejected` or `!ev.prev_events.is_empty()` before taking `min_by_key(|ev| &ev.event_id)`. |
| **F-02.5** | `[Medium]` | `critic-perf` | [`src/resolve/cdo.rs:88-130`](../../../src/resolve/cdo.rs#L88-L130) | `rezzy::cdo::is_ancestor` performs unpruned $O(V+E)$ `BTreeSet` traversal per call; keeping it in production `src/` risks hot-path misuse. |
| **F-02.6** | `[Medium]` | `critic-redteam-qa` | [`tests/unit/test_critique.rs:699-715`](../../../tests/unit/test_critique.rs#L699-L715) | `test_ip_closure_ratio` hardcodes `/tmp/opencode/res_tmp` instead of reading an environment variable. |
| **F-02.7** | `[Low]` | `critic-eng-lead` | [`src/resolve/iterative.rs:124-135,309`](../../../src/resolve/iterative.rs#L124-L135) | Duplicate `EventType::from(ev.event_type.as_str())` conversions allocate twice for `EventType::Custom` state events. |

---

## 4. Actionable Recommendations for Stage B Remediation Tracks

1. **P0 Remediation — Relocate `src/resolve/cdo.rs` to `tests/` (Stage B Track 14 / P0 Item #2)**:
   - Remove `pub mod cdo;` from [`src/resolve/mod.rs:3`](../../../src/resolve/mod.rs#L3) and move [`src/resolve/cdo.rs`](../../../src/resolve/cdo.rs) into `tests/support/cdo_retired.rs` (or `tests/unit/`), updating [`tests/unit/differential_harness.rs:676`](../../../tests/unit/differential_harness.rs#L676) and CDO unit tests to import it from the test harness rather than the production library.
2. **P0/P1 Remediation — Guard `execute_power_phase` Create Event Slow Path & Document `conflicted_keys_override` (Stage B Track 16/17)**:
   - In [`src/resolve/iterative.rs:488-492`](../../../src/resolve/iterative.rs#L488-L492), filter `conflicted_events` by `!ev.rejected && ev.prev_events.is_empty() && ev.event_type == M_ROOM_CREATE`.
   - Update [`resolve_iterative_sort`](../../../src/resolve/iterative.rs#L578-L665) rustdoc to explicitly direct callers who merge state maps or widen `conflicted_events` with `MSC4297` subgraphs to pass `ResolveOptions::conflicted_keys_override` (or call `resolve_state_maps`).
