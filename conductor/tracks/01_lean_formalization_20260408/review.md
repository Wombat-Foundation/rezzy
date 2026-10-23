# Architectural & Multi-Perspective Review: Track 01 — Lean 4 Formalization, Kahn Topological Sort & Trace Compiler (`v0.1.0`–`v0.1.1`)

## 1. Executive Review Summary (`/conductor-review`)

- **Track ID**: `01_lean_formalization_20260408`
- **Epoch**: `v0.1.0`–`v0.1.1` (April 8–14, 2026)
- **Commit Range**: `be1774b..5cf21de` (with StarGraph & AIR follow-ups `5817344`, `871a36a`, `0c0ad6e`, `995f139`, `a88b53a`)
- **Review Verdict**: **COMPLETED WITH ACTIONABLE STAGE B REMEDIATIONS**
- **Cross-Referenced Audit**: [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md), [`TODO.txt`](../../../TODO.txt)

### Plan & Guideline Compliance Checklist
- [x] **Plan Completion**: All 4 phases in [`plan.md`](./plan.md) (`be1774b` through `a88b53a`) are verified against repository history.
- [x] **Core `#![no_std]` Portability**: Verified in [`src/lib.rs:1-8`](../../../src/lib.rs#L1-L8) (`5cb5d4a`), with `alloc` support and optional `std` / `cli` gating.
- [x] **Topological & Mainline Ordering**: Reverse topological power sorting (`KahnSortInputs::with_cycle_diagnostics`, `KahnSortInputs::sort`) and mainline ordering (`build_mainline_with_cache`, `mainline_sort`) implemented in [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs).
- [ ] **Open Audit & Verification Debt**: Behavioral proof gap in Lean 4 (`progressiveFold` under V2.1.1 empty-start-state mutual demotion), silent mainline truncation on cycles in [`src/resolve/sorting.rs:293-355`](../../../src/resolve/sorting.rs#L293-L355), and unconditional `std::eprintln!` side-channel pollution in [`src/resolve/sorting.rs:245-246`](../../../src/resolve/sorting.rs#L245-L246) and [`src/resolve/sorting.rs:316-317`](../../../src/resolve/sorting.rs#L316-L317).

---

## 2. Multi-Perspective Critique (8 Specialized Personas)

### 2.1 Product Management (`critic-pm`)
- **Milestone Maturity & Scope Alignment**: Track 01 successfully bootstrapped `rezzy` from a Lean 4 formal specification (`be1774b`) into a dual-licensed (`0c8baa5`, `v0.1.0`) `#![no_std]` crate and CLI (`5cb5d4a`, `v0.1.1`) implementing Matrix State Resolution v2 ([MSC1693](https://github.com/matrix-org/matrix-spec-proposals/pull/1693)) Steps 3 and 4.
- **Finding `[Low]` — Scope Detour into ZK Trace Compilation (`5817344`–`a88b53a`)**: Phase 4 introduced `src/ctopology.rs`, `src/trace_compiler.rs`, and `RumaLean/Arithmetization.lean` to compile state resolution traces over a symmetric StarGraph (`995f139`) into AIR polynomials. As documented in [`TODO.txt:601-626`](../../../TODO.txt#L601-L626), arithmetizing boolean auth branches into finite-field constraints is orders of magnitude slower than native CPU execution and serves succinct verifiability (SNARKs/STARKs) rather than fast homeserver state resolution. Retiring the trace compiler in Track 02 (`013603f`) and moving `RumaLean` into the external `res/` research submodule (`ae41adc`) was the right product call to keep the core crate lean.

### 2.2 Principal Engineering Lead (`critic-eng-lead`)
- **`#![no_std]` Architecture & Trait Hygiene**: Separating `#![no_std]` + `alloc` in [`src/lib.rs:1-54`](../../../src/lib.rs#L1-L54) from CLI I/O (`5cb5d4a`) established a clean architectural boundary early.
- **Finding `[Medium]` — Unconditional `std::eprintln!` Side-Channel in Library Hot Path**: In [`src/resolve/sorting.rs:245-246`](../../../src/resolve/sorting.rs#L245-L246) (`KahnSortInputs::sort`) and [`src/resolve/sorting.rs:316-317`](../../../src/resolve/sorting.rs#L316-L317) (`build_mainline_with_cache`), cycle detection writes directly to `std::eprintln!` whenever `feature = "std"` is enabled (which is a default feature). As analyzed in [`TODO.txt:6-18`](../../../TODO.txt#L6-L18), a core algorithmic library must not write to global `stderr` where callers cannot capture, structured-log, or silence it, especially when [`KahnSortInputs::with_cycle_diagnostics`](../../../src/resolve/sorting.rs#L138-L226) already exposes [`KahnSortResult::CycleDetected { sorted, stuck }`](../../../src/basespec/rezzy_types.rs#L1491-L1498) programmatically.
- **Finding `[Medium]` — Missing Cycle Diagnostic Return Type in `build_mainline_with_cache`**: Unlike `KahnSortInputs::with_cycle_diagnostics`, [`build_mainline_with_cache`](../../../src/resolve/sorting.rs#L293-L355) returns a bare `Vec<Id>`. When a cycle is encountered in `m.room.power_levels` auth chains (`!seen_in_mainline.insert(eid.clone())` at line 315), it breaks and returns a silently truncated mainline vector with no programmatic signal to the caller ([`TODO.txt:13-18`](../../../TODO.txt#L13-L18)).

### 2.3 Public-Safety & C2 Compliance (`critic-compliance`)
- **Liveness Under Malformed / Cyclic Federation Graphs**: In tactical and emergency-response Matrix deployments, a compromised or buggy federation peer injecting cyclic `auth_events` references must never wedge incident dispatch rooms in an infinite loop. Track 01's cycle detector (`b9f48cb`) guarantees termination both in Kahn sorting ([`src/resolve/sorting.rs:210-223`](../../../src/resolve/sorting.rs#L210-L223)) and mainline traversal ([`src/resolve/sorting.rs:315-319`](../../../src/resolve/sorting.rs#L315-L319)).
- **Finding `[High]` — Silent Mainline Truncation Masks Graph Corruption and Weakens Auditability**: When [`build_mainline_with_cache`](../../../src/resolve/sorting.rs#L315-L319) silently truncates a cyclic `m.room.power_levels` chain, all non-power events citing power levels prior to the cycle break are assigned `mainline.len()` (the worst mainline distance) in [`compute_closest_mainline_positions`](../../../src/resolve/sorting.rs#L425-L429). While deterministic across servers sharing the identical corrupted subgraph, the lack of a structured warning or `Result` prevents a public-safety homeserver from quarantining or alerting on a peer injecting cyclic auth chains.
- **Finding `[High]` — Fallback to Author-Supplied `event.power_level()` When PL Auth Edge Is Absent**: In [`get_power_level_from_auth_chain`](../../../src/resolve/sorting.rs#L30-L81), if an event has no `m.room.power_levels` event in its immediate `dag_edges(version)` and the room is V1–V11 (or the sender is not a V12 creator), line 80 falls back to `event.power_level()`. While intended for bootstrap PL events that only cite `$create` and synthetic unit tests, trusting the unverified envelope cache field `event.power_level` if an attacker omits the PL auth event (before auth rejection in Step 3) allows a malformed event to manipulate its Kahn tie-break priority in `SortPriority`. If no PL event is found in `auth_events`, non-creator V1–V11 bootstrap PL fallback should check `$create` creator identity (returning 100) or default to `0`, rather than trusting `event.power_level()`.

### 2.4 Performance & Adversarial Liveness (`critic-perf`)
- **Algorithmic Complexity**:
  - `KahnSortInputs::with_cycle_diagnostics` ([`src/resolve/sorting.rs:138-226`](../../../src/resolve/sorting.rs#L138-L226)) pre-computes sender power levels once into `pl_cache` (lines 167–174) before pushing to the `BinaryHeap`, achieving $O(V \log V + E)$ time complexity without repeated auth-chain lookups inside heap comparisons.
  - `mainline_sort` ([`src/resolve/sorting.rs:451-489`](../../../src/resolve/sorting.rs#L451-L489)) uses a stack-safe iterative DFS (`compute_closest_mainline_positions`, lines 362–437) and a Schwartzian transform (`decorated: Vec<(&E, usize)>`, lines 468–484) to eliminate $O(N \log N)$ hash lookups during comparison.
- **Finding `[Medium]` — Unseeded `FastMap` (`foldhash`) Exposure on Network-Supplied Event IDs**: Both [`with_cycle_diagnostics`](../../../src/resolve/sorting.rs#L148-L149) and [`build_mainline_with_cache`](../../../src/resolve/sorting.rs#L296-L307) use `FastMap` / `FastSet` (`hashbrown` with `foldhash`). As flagged in [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #12 `perf_audits.md` and P1 Item #6), `foldhash` is a non-cryptographic hash function; in rooms with $10^4+$ conflicted events where an adversary controls event IDs (e.g., room v1/v2 or crafted collision sets), unseeded non-cryptographic tables risk quadratic HashDoS degradation unless indexed via `DenseIndex<T, u32>` or CSPRNG-seeded SipHash.

### 2.5 Formal Verification & Mathematical Soundness (`critic-formal-crypto`)
- **Proof-to-Rust Correspondence**: Track 01 established Lean 4 proofs for DAG acyclicity (`RumaLean/DirectedAcyclicGraph.lean`), Kahn topological sorting (`RumaLean/Kahn.lean`), and `LinearOrder` of the candidate tie-breaker (`RumaLean/StateRes.lean`, `904fee0`, `566c810`, `5b25c2f`).
- **Finding `[High]` — Behavioral Proof Gap for Single-Pass `progressiveFold` Under V2.1.1 Mutual Demotion**: As documented in [`TODO.txt:41-70`](../../../TODO.txt#L41-L70) and [`spec.md:47-49`](./spec.md#L47-L49), while the structural sort keys in Lean (`candidateKey`) and Rust (`SortPriority`) match the Matrix v12 specification, the Lean formalization (`FinalPassFixedPoint.lean`, `ProgressiveAuth.lean`, `RevalidationOscillation.lean`) lacks the connecting behavioral theorem proving that single-pass `progressiveFold` terminates with the exact intended winner under V2.1.1's empty-start-state semantics when two admins concurrently demote each other.
- **Finding `[Medium]` — Submodule Isolation Disconnects CI Proof Checking**: Moving `RumaLean` into the private/external `res/` submodule (`ae41adc`) means `cargo test` no longer automatically verifies that changes to [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs) or [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs) preserve correspondence with the Lean 4 theorems.

### 2.6 Matrix Federation Interop (`critic-federation-interop`)
- **Synapse / Ruma / Conduit Parity**:
  - Reverse topological Kahn sort order in [`SortPriority::cmp`](../../../src/basespec/rezzy_types.rs) and [`mainline_sort`](../../../src/resolve/sorting.rs#L451-L489) accurately implements Matrix State Resolution v2 Step 3 and Step 4 tie-breaking: higher power level first (or closer to current mainline PL applied last), then ascending `origin_server_ts` (so later timestamps are applied later and win via last-write-wins), then lexicographical `event_id`.
  - [`compute_closest_mainline_positions`](../../../src/resolve/sorting.rs#L398-L420) strictly follows only the `m.room.power_levels` auth edge (not arbitrary membership auth edges), preventing the state-reset epoch inheritance bug where an old event citing a newer member event inherits a newer mainline position (verified by [`test_closest_mainline_uses_own_pl_edge_not_min_over_edges`](../../../src/resolve/sorting.rs#L654-L679)).
- **Finding `[Low]` — Cycle Tie-Break Order vs. Upstream Implementations**: When `KahnSortInputs::sort` breaks a cycle ([`src/resolve/sorting.rs:247-254`](../../../src/resolve/sorting.rs#L247-L254)), it sorts `stuck` nodes by `(origin_server_ts, event_id)` ascending, omitting `power_level`. Because valid Matrix DAGs are acyclic, this fallback only triggers on corrupted graphs, but including `power_level` (matching `SortPriority`) would make the fallback order consistent with the normal heap order.

### 2.7 Adversarial Red-Team & Verification QA (`critic-redteam-qa`)
- **Verification Coverage**:
  - Shuffled DAG permutation invariance is tested via [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs), [`tests/unit/test_sanity.rs`](../../../tests/unit/test_sanity.rs), and `scripts/e2e_shuffled.py` (`5cb5d4a`).
  - Cycle termination is tested by [`test_build_mainline_cycle_detection`](../../../src/resolve/sorting.rs#L519-L564) and cycle-injection unit tests in [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) (`b9f48cb`).
- **Finding `[Medium]` — Lack of Property-Based Fuzzing for Multi-Component Cyclic + Acyclic Mixed Subgraphs**: Existing cycle tests cover small 2-node and 3-node cycles (`A <-> B`), but lack property-based (`proptest` / `cargo-fuzz`) generators that mix valid high-power descendants, disconnected components, and multi-loop cyclic `auth_events` to verify that `with_cycle_diagnostics` and `compute_closest_mainline_positions` never panic on `unwrap()` (e.g., [`src/resolve/sorting.rs:196-199`](../../../src/resolve/sorting.rs#L196-L199)).

### 2.8 Homeserver Integrator & API Ergonomics (`critic-dx-integrator`)
- **Pit-of-Success API Design**:
  - Bundling Kahn sort parameters into [`KahnSortInputs`](../../../src/resolve/sorting.rs#L87-L98) and exposing both [`with_cycle_diagnostics`](../../../src/resolve/sorting.rs#L138) and [`sort`](../../../src/resolve/sorting.rs#L237) gives integrators a clean choice between explicit cycle inspection and resilient fallback.
- **Finding `[Low]` — `KahnSortResult::into_sorted` Silently Drops Partial Progress on Cycles**: In [`src/basespec/rezzy_types.rs:1503-1509`](../../../src/basespec/rezzy_types.rs#L1503-L1509), `KahnSortResult::into_sorted(self)` returns `Vec::new()` when `CycleDetected` occurs, whereas `KahnSortInputs::sort(self)` returns `sorted` with deterministically tie-broken `stuck` nodes appended. An integrator calling `with_cycle_diagnostics().into_sorted()` expecting the same fallback vector as `sort()` will instead drop all power events on a cycle.

---

## 3. Summary of Findings & Severity Classification

| ID | Severity | Persona | Location | Summary |
| :--- | :---: | :--- | :--- | :--- |
| **F-01.1** | `[High]` | `critic-compliance` | [`src/resolve/sorting.rs:30-81`](../../../src/resolve/sorting.rs#L30-L81) | `get_power_level_from_auth_chain` falls back to unverified `event.power_level()` when no PL event is cited in `dag_edges`. |
| **F-01.2** | `[High]` | `critic-compliance` | [`src/resolve/sorting.rs:293-355`](../../../src/resolve/sorting.rs#L293-L355) | `build_mainline_with_cache` silently truncates the mainline on an `m.room.power_levels` cycle without returning a diagnostic/error. |
| **F-01.3** | `[High]` | `critic-formal-crypto` | [`TODO.txt:41-70`](../../../TODO.txt#L41-L70) | Missing Lean 4 behavioral theorem connecting `FinalPassFixedPoint.lean` and `ProgressiveAuth.lean` for single-pass mutual demotion under V2.1.1. |
| **F-01.4** | `[Medium]` | `critic-eng-lead` | [`src/resolve/sorting.rs:245-246,316-317`](../../../src/resolve/sorting.rs#L245-L246) | Unconditional `std::eprintln!` in library sorting functions pollutes global `stderr` (`TODO.txt:6-18`). |
| **F-01.5** | `[Medium]` | `critic-perf` | [`src/resolve/sorting.rs:148-149,307`](../../../src/resolve/sorting.rs#L148-L149) | Unseeded `FastMap`/`FastSet` (`foldhash`) over caller/network `Id`s in Kahn and mainline walks (`rezzy_docs_public_safety_audit.md` P1 #6). |
| **F-01.6** | `[Medium]` | `critic-redteam-qa` | [`src/resolve/sorting.rs:196-199`](../../../src/resolve/sorting.rs#L196-L199) | Missing fuzz/property tests for complex cyclic + acyclic mixed graphs and `compute_closest_mainline_positions` cycle handling. |
| **F-01.7** | `[Low]` | `critic-dx-integrator` | [`src/basespec/rezzy_types.rs:1503-1509`](../../../src/basespec/rezzy_types.rs#L1503-L1509) | `KahnSortResult::into_sorted()` returns an empty `Vec` on cycles instead of matching `KahnSortInputs::sort()`'s tie-break fallback. |

---

## 4. Actionable Recommendations for Stage B Remediation Tracks

1. **Remove `std::eprintln!` Side-Channel and Surface Mainline Cycle Diagnostics (Stage B Track 17 / `TODO.txt:6-18`)**:
   - Delete `std::eprintln!` from [`KahnSortInputs::sort`](../../../src/resolve/sorting.rs#L245-L246) and [`build_mainline_with_cache`](../../../src/resolve/sorting.rs#L316-L317).
   - Introduce a `MainlineResult<Id>` (or thread a `Warning::MainlineCycleDetected` into `SyntacticWarnings<Id>`) in [`build_mainline_with_cache`](../../../src/resolve/sorting.rs#L293-L355) so callers can detect and log cyclic PL chains via structured telemetry.
2. **Harden Bootstrap Power-Level Fallback in `get_power_level_from_auth_chain` (Stage B Track 13/17)**:
   - In [`src/resolve/sorting.rs:77-80`](../../../src/resolve/sorting.rs#L77-L80), check whether `create_ev` identifies `event.sender()` as the creator (returning `100` for V1–V11) before falling back to `0` (or restrict `event.power_level()` fallback strictly to when `create_ev.is_none()` in synthetic unit tests).
3. **Complete Lean 4 Behavioral Theorem for Single-Pass `progressiveFold` (Stage B Formal Verification Follow-up)**:
   - Prove the unified behavioral theorem in `res/` (`FinalPassFixedPoint.lean` + `ProgressiveAuth.lean`) establishing that single-pass `progressiveFold` over reverse-topologically sorted power events produces the unique intended state for mutual demotions under V2.1.1 empty-start-state semantics ([`TODO.txt:55-70`](../../../TODO.txt#L55-L70)).
