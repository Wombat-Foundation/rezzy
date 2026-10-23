# Implementation Plan: Track 14 — P0 Relocate Retired CDO (`src/resolve/cdo.rs`) & Harden Sorting Fallbacks

## Phase 1: Isolate `cdo.rs` into Test Suite & Verify Anomaly Counterexamples
- [ ] Task: Relocate `src/resolve/cdo.rs` into `tests/` and remove `pub mod cdo` from `src/resolve/mod.rs` and `src/lib.rs` (`F-02.1`)
  - [ ] Move `src/resolve/cdo.rs` out of production `src/` into `tests/` and update test imports
  - [ ] Verify Anomalies 19 (`19_demoted_but_still_authorized.jsonl`) and 20 (`20_concurrent_ban_still_holds.jsonl`) regression tests pass

## Phase 2: Harden Sorting & Conflicted `m.room.create` Edge Cases
- [ ] Task: Fix unverified `event.power_level()` fallback (`F-01.1`), silent mainline cycle truncation (`F-01.2`), and `m.room.create` slow-path filtering (`F-02.4`)
  - [ ] Default `get_power_level_from_auth_chain` (`src/resolve/sorting.rs:30-81`) to `0` (or room default) instead of unverified `event.power_level()` when no PL event is found in `dag_edges`
  - [ ] Remove unconditional `std::eprintln!` calls in `src/resolve/sorting.rs:245,316` (`F-01.4`) and filter `ev.rejected` / `!ev.prev_events.is_empty()` in `src/resolve/iterative.rs:487-492` (`F-02.4`)
  - [ ] Run `cargo test --workspace --lib --tests` and `cargo clippy --all-targets --all-features`
