# Implementation Plan: Track 19 — P1 State Resolution Conflicted-Keys Isolation, Cycle Tie-Breaks & Lean 4 Proof Parity

## Phase 1: Conflicted-Keys Isolation, `V2_1_1` Interop Guarding & Single-Allocation `EventType` (`F-02.2`, `F-02.3`, `F-02.7`)
- [ ] Task: Prevent supplemental auth-diff events from overwriting unconflicted state keys in `resolve_iterative_sort` (`F-02.3`, `F-02.7`)
  - [ ] Refactor `derive_all_conflicted_keys` and `resolve_iterative_sort` in `src/resolve/iterative.rs:109-153,667-686` so supplemental auth-diff / `MSC4297` events inside `conflicted_events` cannot overwrite keys already settled in `unconflicted_state` when `conflicted_keys_override` is `None`, and add prominent rustdoc guidance (`F-02.3`)
  - [ ] Eliminate duplicate `EventType::from(ev.event_type.as_str())` allocations in `src/resolve/iterative.rs:124-135,309` by querying `conflicted_keys` via borrowed `StateKeyDyn` (`(&str, &K)`) and constructing `EventType` once on insertion (`F-02.7`)
  - [ ] Add a regression test in `tests/unit/test_critique.rs` verifying that calling `resolve_iterative_sort` (`src/resolve/iterative.rs:667-686`) with supplemental auth-chain events does not clobber unconflicted state keys (`F-02.3`)
- [ ] Task: Enforce strict `StateResVersion::V2_1` (`"12"`) vs. `V2_1_1` (`"12.1"`) separation on `m.room.join_rules` supplementation (`F-02.2`)
  - [ ] Audit and document `route_msc4297_ancestral_power_events` in `src/resolve/iterative.rs:240-249` and `StateResVersion` in `src/basespec/rezzy_types.rs:187,230` so `"12.1"` (`V2_1_1`) is explicitly marked as a homogeneous-only extension and never applied to standard room version `"12"` (`F-02.2`)
  - [ ] Add an explicit `SEND01` `m.room.join_rules` divergence fixture in `tests/unit/test_traversal.rs` contrasting `StateResVersion::V2_1` and `StateResVersion::V2_1_1` (`src/resolve/iterative.rs:240-249`, `F-02.2`)

## Phase 2: Sorting HashDoS Remediation, Cycle Fallback Parity & Mixed-Graph Property Fuzzing (`F-01.5`, `F-01.6`, `F-01.7`)
- [ ] Task: Replace unseeded `FastMap`/`FastSet` (`foldhash`) in Kahn and mainline sorting and unify `KahnSortResult::into_sorted()` (`F-01.5`, `F-01.7`)
  - [ ] Replace unseeded `FastMap` and `FastSet` over caller/network `Id`s in `KahnSortInputs::with_cycle_diagnostics` (`src/resolve/sorting.rs:148-149`) and `build_mainline_with_cache` (`src/resolve/sorting.rs:307`) with `DenseIndex<Id, u32>` or CSPRNG-seeded `HashMap`/`HashSet` (`F-01.5`)
  - [ ] Fix `KahnSortResult::into_sorted()` in `src/basespec/rezzy_types.rs:1503-1509` so `CycleDetected { sorted, stuck }` preserves partial progress / deterministic tie-break fallback matching `KahnSortInputs::sort()` instead of returning an empty `Vec` (`F-01.7`)
- [ ] Task: Add property-based fuzz tests for mixed cyclic + acyclic multi-component graphs (`F-01.6`)
  - [ ] Implement `proptest` generators in `tests/unit/test_traversal.rs` testing `KahnSortInputs::with_cycle_diagnostics` (`src/resolve/sorting.rs:196-199`) and `compute_closest_mainline_positions` (`src/resolve/sorting.rs:362-437`) on multi-component graphs mixing cycles, self-loops, and valid high-power descendants (`F-01.6`)

## Phase 3: Lean 4 Single-Pass Mutual Demotion Proof, `cdo::is_ancestor` Cleanup & Fixture Env Var (`F-01.3`, `F-02.5`, `F-02.6`)
- [ ] Task: Complete Lean 4 behavioral theorem for single-pass `progressiveFold` under mutual demotion and update `TODO.txt` (`F-01.3`)
  - [ ] Prove the behavioral theorem connecting `FinalPassFixedPoint.lean` and `ProgressiveAuth.lean` for single-pass `progressiveFold` under V2.1.1 empty-start-state mutual demotion, updating `TODO.txt:41-70` and corresponding Rust verification tests (`F-01.3`)
- [ ] Task: Bound/relocate `rezzy::cdo::is_ancestor` and parameterize `test_ip_closure_ratio` fixture path (`F-02.5`, `F-02.6`)
  - [ ] Remove `rezzy::cdo::is_ancestor` (`src/resolve/cdo.rs:88-130`) from the production `src/` namespace (moving to test-only scope with bounded traversal depth) so production code uses `reachability.rs` (`F-02.5`)
  - [ ] Update `test_ip_closure_ratio` in `tests/unit/test_critique.rs:699-715` to read `REZZY_LARGE_FIXTURES_DIR` with a fallback to `tests/fixtures/` instead of hardcoding `/tmp/opencode/res_tmp` (`F-02.6`)
