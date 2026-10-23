# Specification: Track 19 — P1 State Resolution Conflicted-Keys Isolation, Cycle Tie-Breaks & Lean 4 Proof Parity

## 1. Overview & Finding Traceability Matrix

Track 19 remediates 9 findings (`F-01.3`, `F-01.5`, `F-01.6`, `F-01.7`, `F-02.2`, `F-02.3`, `F-02.5`, `F-02.6`, `F-02.7`) originating from the multi-perspective architectural reviews of Track 01 ([`../01_lean_formalization_20260408/review.md`](../01_lean_formalization_20260408/review.md)) and Track 02 ([`../02_stateres_v2_cdo_20260510/review.md`](../02_stateres_v2_cdo_20260510/review.md)). It eliminates state-overwrite footguns in `resolve_iterative_sort` (`F-02.3`), hardens `StateResVersion::V2_1_1` interop boundaries (`F-02.2`), closes the Lean 4 formal proof gap for single-pass mutual demotion (`F-01.3`), eliminates unseeded `foldhash` (`FastMap`/`FastSet`) exposure in Kahn/mainline sorting (`F-01.5`), unifies cycle tie-break behavior in `KahnSortResult::into_sorted` (`F-01.7`), bounds or retires `cdo::is_ancestor` (`F-02.5`), eliminates duplicate `EventType::from` allocations (`F-02.7`), parameterizes large-fixture test paths (`F-02.6`), and adds mixed cyclic/acyclic property tests (`F-01.6`).

| Finding ID | Severity | Persona(s) | Source File / Lines | Root Cause & Impact |
| :--- | :---: | :--- | :--- | :--- |
| **`F-01.3`** | `[High]` | `critic-formal-crypto` | [`TODO.txt:41-70`](../../../TODO.txt#L41-L70) | Missing Lean 4 behavioral theorem connecting `FinalPassFixedPoint.lean` and `ProgressiveAuth.lean` proving that single-pass `progressiveFold` terminates with the unique intended winner under V2.1.1 empty-start-state mutual demotion. |
| **`F-01.5`** | `[Medium]` | `critic-perf` | [`src/resolve/sorting.rs:148-149,307`](../../../src/resolve/sorting.rs#L148-L149) | `KahnSortInputs::with_cycle_diagnostics` and `build_mainline_with_cache` use unseeded `FastMap`/`FastSet` (`foldhash`) over caller/network `Id`s, exposing sorting hot paths to quadratic HashDoS on crafted event ID collision sets. |
| **`F-01.6`** | `[Medium]` | `critic-redteam-qa` | [`src/resolve/sorting.rs:196-199`](../../../src/resolve/sorting.rs#L196-L199) | Lack of property-based fuzzing (`proptest`) generating multi-component mixed cyclic + acyclic `auth_events` subgraphs to verify that `with_cycle_diagnostics` and `compute_closest_mainline_positions` never panic. |
| **`F-01.7`** | `[Low]` | `critic-dx-integrator` | [`src/basespec/rezzy_types.rs:1503-1509`](../../../src/basespec/rezzy_types.rs#L1503-L1509) | `KahnSortResult::into_sorted()` returns an empty `Vec::new()` when `CycleDetected { sorted, stuck }` occurs instead of returning the deterministically tie-broken fallback sequence matching `KahnSortInputs::sort()` or forcing caller pattern matching. |
| **`F-02.2`** | `[High]` | `critic-pm`, `critic-compliance` | [`src/resolve/iterative.rs:240-249`](../../../src/resolve/iterative.rs#L240-L249), [`src/basespec/rezzy_types.rs:187,230`](../../../src/basespec/rezzy_types.rs#L187) | `StateResVersion::V2_1_1` (`"12.1"`) excludes ancestral `m.room.join_rules` in `route_msc4297_ancestral_power_events`, diverging from stock `MSC4297` (`V2_1`) on `SEND01`-shaped graphs and causing federation split-brain if mixed with stock `"12"` peers. |
| **`F-02.3`** | `[High]` | `critic-dx-integrator` | [`src/resolve/iterative.rs:109-153,667-686`](../../../src/resolve/iterative.rs#L109-L153) | Calling `resolve_iterative_sort` without `ResolveOptions::conflicted_keys_override` invokes `derive_all_conflicted_keys`, which treats supplemental auth-difference and `MSC4297` subgraph events inside `conflicted_events` as candidate state winners capable of overwriting unconflicted keys (`MSC4297` violation). |
| **`F-02.5`** | `[Medium]` | `critic-perf` | [`src/resolve/cdo.rs:88-130`](../../../src/resolve/cdo.rs#L88-L130) | `rezzy::cdo::is_ancestor` performs an unpruned $O(V+E)$ `BTreeSet` traversal per call; keeping it in production `src/resolve/` risks $O(V(V+E)\log V)$ hot-path misuse instead of `reachability.rs` / `RoaringBitmap` indexes. |
| **`F-02.6`** | `[Medium]` | `critic-redteam-qa` | [`tests/unit/test_critique.rs:699-715`](../../../tests/unit/test_critique.rs#L699-L715) | `test_ip_closure_ratio` hardcodes `/tmp/opencode/res_tmp` for large room fixtures instead of reading an environment variable (`REZZY_LARGE_FIXTURES_DIR`) with a repository fallback. |
| **`F-02.7`** | `[Low]` | `critic-eng-lead` | [`src/resolve/iterative.rs:124-135,309`](../../../src/resolve/iterative.rs#L124-L135) | `derive_all_conflicted_keys` and the iterative resolution loops construct `EventType::from(ev.event_type.as_str())` multiple times per conflicted event, causing duplicate `Box<str>` heap allocations for `EventType::Custom` state events. |

---

## 2. Functional & Architectural Remediation Requirements

### 2.1 Conflicted-Key Isolation, `V2_1_1` Interop Guarding & Zero-Duplicate `EventType` Allocations (`F-02.2`, `F-02.3`, `F-02.7`)
1. **Enforce Explicit Conflicted-Key Isolation in `resolve_iterative_sort` (`F-02.3`)**:
   - Refactor [`src/resolve/iterative.rs:109-153`](../../../src/resolve/iterative.rs#L109-L153) and [`src/resolve/iterative.rs:667-686`](../../../src/resolve/iterative.rs#L667-L686) so callers supplying supplemental auth-difference or `MSC4297` ancestors cannot accidentally allow non-conflicted supplemental state events to overwrite keys already settled in `unconflicted_state`.
   - When `conflicted_keys_override` is `None`, exclude keys that are present in `unconflicted_state` unless explicitly flagged as conflicted or require `IterativeInputs` to carry the conflicted key set / pre-supplementation boundary, and update the rustdoc on `resolve_iterative_sort` and `IterativeInputs` with prominent pit-of-success guidance directing state-map callers to `resolve_state_maps` or `ResolveOptions::conflicted_keys_override`.
2. **Harden `StateResVersion::V2_1_1` (`"12.1"`) Separation & Add `SEND01` Divergence Oracle (`F-02.2`)**:
   - In [`src/resolve/iterative.rs:240-249`](../../../src/resolve/iterative.rs#L240-L249) and [`src/basespec/rezzy_types.rs:187,230`](../../../src/basespec/rezzy_types.rs#L187), enforce strict room-version isolation so standard Matrix room version `"12"` (`StateResVersion::V2_1`) always includes ancestral `m.room.join_rules` in `route_msc4297_ancestral_power_events` per stock `MSC4297`, while `"12.1"` (`StateResVersion::V2_1_1`) is explicitly documented and gated as a non-standard homogeneous-federation profile.
   - Add an explicit comparative test demonstrating the exact `SEND01` `m.room.join_rules` divergence between `V2_1` and `V2_1_1`.
3. **Eliminate Duplicate `EventType::from` Heap Allocations (`F-02.7`)**:
   - In [`src/resolve/iterative.rs:124-135,309`](../../../src/resolve/iterative.rs#L124-L135), cache or borrow the parsed `EventType` (or query `conflicted_keys` via `StateKeyDyn` borrowed `(&str, &K)` lookup before allocating `EventType::from` only once on insertion into `resolved`), eliminating duplicate `Box<str>` allocations for `EventType::Custom`.

### 2.2 Sorting HashDoS Remediation, Cycle Tie-Break Parity & Mixed Cyclic/Acyclic Fuzzing (`F-01.5`, `F-01.6`, `F-01.7`)
1. **Replace Unseeded `FastMap`/`FastSet` Over Network `Id`s in Sorting (`F-01.5`)**:
   - In [`src/resolve/sorting.rs:148-149,307`](../../../src/resolve/sorting.rs#L148-L149), replace unseeded `FastMap` / `FastSet` (`foldhash`) keyed by caller/network `Id`s in `KahnSortInputs::with_cycle_diagnostics` and `build_mainline_with_cache` with `DenseIndex<Id, u32>` (flat `Vec` / bitset indexing) or CSPRNG-seeded DoS-resistant hash tables (`crate::HashMap` / `crate::HashSet`).
2. **Align `KahnSortResult::into_sorted()` with Deterministic Cycle Fallback (`F-01.7`)**:
   - In [`src/basespec/rezzy_types.rs:1503-1509`](../../../src/basespec/rezzy_types.rs#L1503-L1509), update `KahnSortResult::into_sorted(self)` (or replace it with `into_sorted_or_fallback` / `#[must_use]` pattern matching) so callers do not silently drop all `sorted` progress and receive an empty `Vec` when `CycleDetected { sorted, stuck }` occurs, ensuring consistent deterministic tie-breaking with `KahnSortInputs::sort()`.
3. **Property-Based Fuzzing for Multi-Component Cyclic + Acyclic Mixed Graphs (`F-01.6`)**:
   - Add `proptest` suites covering [`src/resolve/sorting.rs:196-199`](../../../src/resolve/sorting.rs#L196-L199) and `compute_closest_mainline_positions` (`src/resolve/sorting.rs:362-437`) across arbitrary mixed cyclic/acyclic multi-component graphs, asserting zero panics, total node conservation, and permutation invariance.

### 2.3 Lean 4 Single-Pass Mutual Demotion Proof, `cdo::is_ancestor` Pruning & Test Path Parameterization (`F-01.3`, `F-02.5`, `F-02.6`)
1. **Complete Lean 4 Behavioral Proof for Single-Pass `progressiveFold` Under V2.1.1 Mutual Demotion (`F-01.3`)**:
   - Resolve [`TODO.txt:41-70`](../../../TODO.txt#L41-L70) by proving the connecting behavioral theorem between `FinalPassFixedPoint.lean` and `ProgressiveAuth.lean` showing that single-pass `progressiveFold` over reverse-topologically sorted power events yields the exact fixed-point winner under V2.1.1 empty-start-state semantics when two admins concurrently demote each other, and mirror the theorem's invariants in Rust unit tests.
2. **Retire or Depth-Prune `cdo::is_ancestor` (`F-02.5`)**:
   - In coordination with moving `src/resolve/cdo.rs` (`lines 88-130`) out of production `src/` into test support, ensure `is_ancestor` is either restricted to test-only scope or bounded with a visited capacity / `RoaringBitmap` reachability index so production code never invokes an unpruned $O(V+E)$ `BTreeSet` walk.
3. **Parameterize `test_ip_closure_ratio` Large Fixture Directory (`F-02.6`)**:
   - In [`tests/unit/test_critique.rs:699-715`](../../../tests/unit/test_critique.rs#L699-L715), replace the hardcoded `/tmp/opencode/res_tmp` path with `std::env::var("REZZY_LARGE_FIXTURES_DIR")` falling back to `tests/fixtures/`, skipping gracefully with an informative message when external multi-gigabyte corpus files are absent.

---

## 3. Public-Safety & Consensus Invariants

1. **Unconflicted Key Immutability (`MSC1693` / `MSC4297`)**: No event introduced solely via the auth difference ($\text{auth}(C) \setminus \text{auth}(U)$) or `MSC4297` ancestral power subgraph may overwrite a `(event_type, state_key)` pair that was not in the conflicted key set (`F-02.3`).
2. **Homogeneous Room Version Consensus (`F-02.2`)**: Room Version `"12"` (`StateResVersion::V2_1`) MUST remain 100% bit-for-bit compatible with stock `MSC4297` (Synapse / Ruma / Conduit), including `m.room.join_rules` supplementation in `route_msc4297_ancestral_power_events`.
3. **Deterministic Termination & HashDoS Immunity (`F-01.5`, `F-01.6`, `F-01.7`)**: Topological and mainline sorting MUST terminate deterministically in $O(V \log V + E)$ without quadratic hash collision degradation or `unwrap()` panics on cyclic or disconnected federation graphs.
4. **Formal Proof Correspondence (`F-01.3`)**: Single-pass `progressiveFold` over `SortPriority`-ordered power events MUST satisfy the Lean 4 fixed-point behavioral theorem under mutual demotion.

---

## 4. Acceptance Criteria & Verification Oracles

- [ ] **`F-01.3`**: Lean 4 theorem connecting `FinalPassFixedPoint.lean` and `ProgressiveAuth.lean` for single-pass `progressiveFold` under mutual demotion is proven and documented in `TODO.txt:41-70` / `docs/`, with a matching Rust property/unit test oracle.
- [ ] **`F-01.5`**: `src/resolve/sorting.rs:148-149,307` no longer uses unseeded `FastMap`/`FastSet` (`foldhash`) over untrusted `Id`s; verified by audit grep and collision-resistance unit tests.
- [ ] **`F-01.6`**: New `proptest` suite in `tests/unit/test_traversal.rs` (or `src/resolve/sorting.rs`) exercises 1,000+ mixed cyclic + acyclic multi-component graphs through `with_cycle_diagnostics` (`src/resolve/sorting.rs:196-199`) and `compute_closest_mainline_positions` without panicking.
- [ ] **`F-01.7`**: `KahnSortResult` (`src/basespec/rezzy_types.rs:1503-1509`) never silently drops `sorted` events into an empty `Vec` on cycles; unit tests verify consistent behavior between `with_cycle_diagnostics` and `sort()`.
- [ ] **`F-02.2`**: Comparative test in `tests/unit/test_traversal.rs` verifies `V2_1` vs. `V2_1_1` behavior on ancestral `m.room.join_rules` (`src/resolve/iterative.rs:240-249`) and documentation in `src/basespec/rezzy_types.rs:187,230` enforces strict `"12"` vs. `"12.1"` separation.
- [ ] **`F-02.3`**: `resolve_iterative_sort` (`src/resolve/iterative.rs:109-153,667-686`) prevents supplemental auth-diff events from overwriting unconflicted state keys; verified by dedicated regression test in `tests/unit/test_critique.rs`.
- [ ] **`F-02.5`**: `cdo::is_ancestor` (`src/resolve/cdo.rs:88-130`) is removed from production `src/` exposure and bounded in test helpers.
- [ ] **`F-02.6`**: `test_ip_closure_ratio` (`tests/unit/test_critique.rs:699-715`) reads `REZZY_LARGE_FIXTURES_DIR` instead of hardcoding `/tmp/opencode/res_tmp`.
- [ ] **`F-02.7`**: `src/resolve/iterative.rs:124-135,309` performs at most one `EventType::from` conversion per inserted custom state event; `TODO(perf)` at line 124 is resolved.
