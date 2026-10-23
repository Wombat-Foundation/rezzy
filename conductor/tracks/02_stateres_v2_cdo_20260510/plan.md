# Implementation Plan: Core `#![no_std]` State Resolution V1/V2/V2.1 & CDO Soundness Retirement (`v0.1.2`–`v0.1.4`)

## Phase 1: Real-World Federation Oracles & Canonical Spec Alignment [checkpoint: cf91503]

- [x] Task: Build real-world room DAG exporters and upstream Ruma test fixtures a845200
  - [x] Add upstream Ruma test cases and known hard Matrix rooms (`0bbd21e`, `d6d499f`)
  - [x] Implement synthetic DAG generators and bulk federation pulls from Postgres/Synapse DB or Matrix API (`473f27a`, `a845200`)
- [x] Task: Enforce strict E2E oracle cross-validation and align Rust/Lean state resolution logic 9e1f6a0
  - [x] Commit exported real-world room fixtures and strict oracle cross-validation harnesses (`145a60c`)
  - [x] Fix Rust state resolution edge cases to match real E2E federation data (`9e1f6a0`, `758127d`, `e0ee7a3`, `2f71568`)
- [x] Task: Synchronize Lean 4 `StateRes.lean` with revised Rust canonical sort and remove experimental trace compiler cf91503
  - [x] Update `RumaLean/StateRes.lean` and `RumaLean/Conjectures.lean` to match the revised Rust canonical sort and complete `Event` lexicographical tuple (`cf91503`, `cfb9b90`)
  - [x] Remove obsolete `src/ctopology.rs` and `src/trace_compiler.rs` modules and clean up `Cargo.lock` (`013603f`, `b9cf789`)

## Phase 2: `#![no_std]` `hashbrown` Upgrade, Room Version Dispatch & Determinism Proofs (`v0.1.2`–`v0.1.3`) [checkpoint: c0cb626]

- [x] Task: Implement JSONL auto-detection, room-version algorithm selection, and fail-closed `m.room.create` handling 265a4de
  - [x] Add automatic JSON vs. JSONL input format detection in the CLI (`90604fd`) and bump `v0.1.2` package metadata (`3d8ee1c`, `c145175`)
  - [x] Dispatch the proper state resolution algorithm per room version (`b79cf53`) and immediately revert the insecure invite fallback for missing `m.room.create` events (`265a4de`)
- [x] Task: Upgrade `#![no_std]` `hashbrown` backend and drop unused `ed25519-consensus` crate fbb38ff
  - [x] Fix external federation room queries and environment-specific token variables (`342c330`, `c57ff60`)
  - [x] Upgrade `hashbrown` for `#![no_std]` state maps (`fbb38ff`, tagged `v0.1.2`) and drop unused `ed25519-consensus` from the resolution pipeline (`2e21db6`)
- [x] Task: Verify V2/V2.1 later-timestamp-wins tie-breaker and prove `(depth, event_id)` `LinearOrder` determinism 5b25c2f
  - [x] Test and revert the experimental earlier-wins timestamp change (`71c4590`, `72d836e`), adding V2.1 later-wins regression tests in Rust (`4025b36`) and fixing `RumaLean/StateRes.lean` (`5900cdb`)
  - [x] Eliminate `HashMap` iteration randomness via deterministic `(depth, event_id)` sorting (`c08001d`), extract `cmp_by_depth()` helper (`96e3c55`), and formally prove `LinearOrder` in `RumaLean/StateRes.lean` (`5b25c2f`, tagged `v0.1.3` at `c0cb626`)

## Phase 3: Multi-DAG Merging, `dagcmp.py` Forensics & Non-State Event Isolation (`v0.1.4`) [checkpoint: 4abfb43]

- [x] Task: Implement multi-DAG merge resolution and CLI summary/timeline views 9e09cc5
  - [x] Add multi-DAG merge support (`83b9a17`, `9eb7313`) with integration tests for combined state resolution across divergent room graphs (`1d03dba`)
  - [x] Add CLI summarized output (`53cbaf1`), timeline output format, root event tracking, and `scripts/dagcmp.py` comparison tool (`9e09cc5`)
- [x] Task: Add greedy chain analysis, branching factor metrics, and depth-sorted timeline views 656a00d
  - [x] Enhance `scripts/dagcmp.py` with greedy chain analysis, membership breakdown (`966eea2`), branching factor columns (`b2c1571`), and multi-part domain suffix grouping (`1267c7e`)
  - [x] Enforce proper depth sorting in timeline/events output (`b097221`, `656a00d`) and support multiple input files in `clap` CLI arguments (`7960a64`, tagged `v0.1.4` at `4abfb43`)
- [x] Task: Filter non-state timeline events from state maps and expand state-key test coverage 188fb51
  - [x] Fix Makefile CI aliases for coverage and E2E targets (`3fb56d6`, `b0460cf`) and configure pedantic CI Clippy lints (`97e30e6`)
  - [x] Ignore non-state events (`state_key: None`) when computing state maps (`1931990`) and add integration and state-key regression tests (`28ca517`, `188fb51`)

## Phase 4: Causal Domination Operator (CDO) Lifecycle, Anomalies 19 & 20, and Soundness Retirement [checkpoint: f56b068]

- [x] Task: Implement V2.1 (`MSC4297`) conflicted subgraph expansion and initial CDO SWAR bit-vector filter 34fde0c
  - [x] Implement full `MSC4297` V2.1 state resolution with Step 4 supplementation and `tests/critique.rs` anomaly suite (`ae41adc`)
  - [x] Extract [`src/resolve/cdo.rs`](../../../src/resolve/cdo.rs) with batched SWAR bit-vector matrix sweeps and `roaring` auth integration (`34fde0c`, `c0012d5`, `fbe90d4`, `591ecde`)
- [x] Task: Diagnose CDO Soundness Anomalies 19 & 20 and retire pre-auth CDO in favor of post-power screening f56b068
  - [x] Add adversarial fixtures [`tests/critique_data/19_demoted_but_still_authorized.jsonl`](../../../tests/critique_data/19_demoted_but_still_authorized.jsonl) and [`tests/critique_data/20_concurrent_ban_still_holds.jsonl`](../../../tests/critique_data/20_concurrent_ban_still_holds.jsonl) and implement `sender_has_pre_demotion_pl()` in [`src/resolve/cdo.rs`](../../../src/resolve/cdo.rs) (`f56b068`)
  - [x] Disconnect CDO from `prepare_conflicted_and_keys` in [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs) after proving the **dominator-validity gap** causes federation split-brain, replacing it with post-power `is_sender_banned` screening and documenting the post-mortem in [`docs/cdo_soundness_anomalies.md`](../../../docs/cdo_soundness_anomalies.md) (`f56b068`)

---

## History & Audit Traceability

| Commit SHA | Date | Core Files Modified | Verification / Test Files | Linked Docs & Public-Safety Audit Findings |
| :--- | :--- | :--- | :--- | :--- |
| `9e1f6a0` | 2026-05-03 | [`src/lib.rs`](../../../src/lib.rs) | [`tests/unit/test_sanity.rs`](../../../tests/unit/test_sanity.rs) | Real-world E2E oracle cross-validation (`a845200`, `145a60c`) |
| `cf91503` | 2026-05-03 | `RumaLean/StateRes.lean`, `RumaLean/Conjectures.lean` | `RumaLean/StateRes.lean` | Canonical sort alignment; removal of `trace_compiler.rs` (`013603f`) |
| `265a4de` | 2026-05-10 | `src/main.rs` | [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) | Reverted insecure fallback to invite events for missing `m.room.create` (`b79cf53`) |
| `fbb38ff` | 2026-05-10 | [`Cargo.toml`](../../../Cargo.toml), `Cargo.lock` | [`tests/unit/test_lib.rs`](../../../tests/unit/test_lib.rs) | Tag `v0.1.2`; `#![no_std]` `hashbrown` upgrade; dropped `ed25519-consensus` (`2e21db6`) |
| `4025b36` | 2026-05-11 | [`src/lib.rs`](../../../src/lib.rs), `RumaLean/StateRes.lean` | [`tests/unit/test_sanity.rs`](../../../tests/unit/test_sanity.rs) | V2/V2.1 later-timestamp-wins regression test (`5900cdb`) |
| `5b25c2f` | 2026-05-11 | [`src/lib.rs`](../../../src/lib.rs), `RumaLean/StateRes.lean` | [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) | Deterministic `cmp_by_depth()` (`c08001d`, `96e3c55`) & `LinearOrder` proof (`v0.1.3` at `c0cb626`) |
| `9e09cc5` | 2026-05-12 | `src/main.rs`, `scripts/dagcmp.py` | [`tests/unit/test_lib.rs`](../../../tests/unit/test_lib.rs) | Multi-DAG merge (`1d03dba`), timeline view (`656a00d`), and `dagcmp.py` (`966eea2`, `v0.1.4` at `4abfb43`) |
| `1931990` | 2026-05-20 | `src/main.rs` | [`tests/unit/test_sanity.rs`](../../../tests/unit/test_sanity.rs) | Non-state event filtering (`28ca517`, `188fb51`) |
| `ae41adc` | 2026-06-26 | [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs), [`src/resolve/subgraph.rs`](../../../src/resolve/subgraph.rs) | [`tests/unit/test_critique.rs`](../../../tests/unit/test_critique.rs) | `MSC4297` State Resolution V2.1 compliance & initial anomaly test suite |
| `34fde0c` | 2026-06-27 | [`src/resolve/cdo.rs`](../../../src/resolve/cdo.rs), [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs) | [`tests/unit/test_critique.rs`](../../../tests/unit/test_critique.rs) | SWAR bit-vector CDO implementation (`c0012d5`, `fbe90d4`, `591ecde`) |
| `f56b068` | 2026-09-28 | [`src/resolve/cdo.rs`](../../../src/resolve/cdo.rs), [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs), [`docs/cdo_soundness_anomalies.md`](../../../docs/cdo_soundness_anomalies.md) | [`tests/unit/test_critique.rs`](../../../tests/unit/test_critique.rs), [`tests/unit/differential_harness.rs`](../../../tests/unit/differential_harness.rs) | **Critical (Split-Brain)** in [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #3, P0 #2): CDO retired from live path due to dominator-validity gap & Anomaly 19, but `src/resolve/cdo.rs` still resides in production `src/resolve/` |
