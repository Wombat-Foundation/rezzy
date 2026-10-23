# Implementation Plan: Track 21 — P1 HAMT Domain Separation, PersistentOrdMap Rebalancing, Cold Snapshot Diffing & MSC4242 State DAG Bounds

## Phase 1: HAMT Domain Separation, CLI Walk Memory Bounds & `PersistentOrdMap` Rebalancing (`F-04-02`, `F-04-03`, `F-04-05`, `F-04-06`, `F-09-05`)
- [ ] Task: Enforce non-empty cross-room domain separation in `StructuralHash` and bound CLI HAMT walk memory (`F-04-02`, `F-04-05`, `F-04-06`)
  - [ ] Enforce non-empty room-bound `structural_key` in `src/hamt/mod.rs:192-213` and `src/hamt/hash.rs` so callers cannot pass `b""` across rooms, and add a cross-room hash-disjointness test (`F-04-05`)
  - [ ] Prune `root_hashes_map` via `child_citations` and stream/bound `roots_json`, `checkpoints`, and `unique_nodes` in `rezzy-cli/src/format.rs:153-465` to eliminate $O(N_{\text{events}} + N_{\text{unique\_nodes}})$ RAM accumulation (`F-04-02`)
  - [ ] Update `docs/spec_coverage.csv:1-36` and `docs/hamt_live_frontier_retention.md:7-10` to distinguish in-memory state resolution from persistent HAMT storage and CLI frontier GC (`F-04-06`)
- [ ] Task: Rebalance under-full nodes in `PersistentOrdMap::remove` and harden cold-snapshot diffing (`F-04-03`, `F-09-05`)
  - [ ] Implement node rebalancing/merging on underflow in `PersistentOrdMap::remove` (`src/state/persistent_ord_map.rs:14-26,94-98`) and add an adversarial insert+remove churn regression test (`F-09-05`)
  - [ ] Harden cold-deserialized state diffing in `src/state/persistent_ord_map.rs:143-247` and configure $L \ge 2$ cached internal HAMT layers in `benches/db/hamt_delta.rs:11-95` to eliminate the `O_DIRECT` cold-storage latency cliff (`F-04-03`)

## Phase 2: `LeanEvent` `prev_state_events` De-Aliasing & Cross-Room State-At / DAG Enforcement (`F-04-04`, `F-05-04`, `F-05-06`)
- [ ] Task: Separate `prev_state_events` from `auth_events` on `LeanEvent` (`F-05-04`)
  - [ ] Replace the `&self.auth_events` alias in `LeanEvent::prev_state_events()` (`src/basespec/rezzy_types.rs:1609-1614` and `src/auth/mod.rs:690-704`) with distinct storage or a typed edge enum so `MSC4242` (`V2.2`) state edges cannot be misinterpreted as classic `auth_events` (`F-05-04`)
- [ ] Task: Enforce `RoomId` and `EventVerifier` checks across State-At, HAMT, and `MSC4242` State DAG walks (`F-04-04`, `F-05-06`)
  - [ ] Thread mandatory `RoomId` and `EventVerifier` support through `src/state/at.rs:104-220` and `rezzy-cli/src/format.rs:306-384` so `MSC4307` Rule 2.5 is enforced during state-at and live HAMT walks (`F-04-04`)
  - [ ] Make cross-room event rejection (`ReferencedForeignRoom` / `ForeignRoomEvent`) unconditionally fail-closed in `validate_state_dag_ancestors` (`src/state/dag.rs:107-113`) and `check_auth_chain` (`src/auth/mod.rs:2100-2130`, `F-05-06`)

## Phase 3: `MSC4242` Branch Withholding Detection & Bounded Walk / Parallel Semilattice Guards (`F-05-02`, `F-05-05`)
- [ ] Task: Add DAG branch withholding ("DAG honesty") detection and frontier reconciliation verification (`F-05-02`)
  - [ ] Implement frontier-completeness / branch-withholding verification in `src/state/dag.rs:50-90`, update `docs/rezzy_msc4242_security_comparison.md:122-142`, and add an adversarial branch-withholding test in `tests/unit/test_state_dag.rs` demonstrating reconciliation of a withheld ban branch (`F-05-02`)
- [ ] Task: Enforce hard `max_steps` ceiling in `StateDagWalkOptions` and parallel threshold in `resolve_semilattice_fold` (`F-05-05`)
  - [ ] Enforce a mandatory step ceiling in `StateDagWalkOptions` (`src/state/dag.rs:76-90`) so callers cannot bypass walk bounds with `max_steps: None` (`F-05-05`)
  - [ ] Add a `MIN_PARALLEL_EVENTS` threshold before `std::thread::scope` spawning and eliminate the mainline head panic risk in `src/resolve/semilattice.rs:33-37` (`F-05-05`)
