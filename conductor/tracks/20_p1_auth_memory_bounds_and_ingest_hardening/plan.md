# Implementation Plan: Track 20 — P1 I/O Sandwich Subgraph Bounds, LocalAuthCache Zero-Clone, Ingest Hash Verification & Redaction Rule 11

## Phase 1: `LocalAuthCache` Zero-Clone, Capacity Bounds & `compute_merge_bases` Scaling (`F-03.2`, `F-03.5`, `F-03.8`)
- [ ] Task: Eliminate `LeanEvent` deep-clones on `LocalAuthCache` hits and bound `LocalAuthCache` memory (`F-03.2`, `F-03.5`)
  - [ ] Refactor `OverlayState::local_auth` and `compute_local_auth` in `src/state/at.rs:90,267-272,336-341` to borrow `&LocalAuthCacheMap` or store `Arc<LeanEvent<Id, C, K>>` instead of deep-cloning `(*entry.event).clone()` on every cache hit (`F-03.5`)
  - [ ] Add a configurable `max_entries` capacity bound to `LocalAuthCache` in `src/state/at.rs:253-342` and update `docs/architecture.md:67-84,202-211` to document $10^4+$ event adversarial fork bounds and `tokio::task::spawn_blocking` execution requirements (`F-03.2`)
- [ ] Task: Widen `compute_merge_bases` extremity bitmask beyond 8 extremities (`F-03.8`)
  - [ ] Replace the `u8` mask (`assert!(extremities.len() <= 8)`) in `compute_merge_bases` (`src/state/at.rs:788-791`) with a `u64` mask and chunked/dynamic bitset fallback for $>64$ extremities, and add a 16-extremity regression test in `tests/unit/test_state_at.rs` (`F-03.8`)

## Phase 2: Ingest Hash Verification, Non-Panicking Canonical Redaction & Explicit `EventVerifier` (`F-06-03`, `F-06-04`)
- [ ] Task: Enforce mandatory `hashes.sha256` at ingest and eliminate `.expect()` panic in `canonical_redacted_json` (`F-06-03`)
  - [ ] Require `hashes` (`hashes.sha256`) presence in `ingest_events` (`src/basespec/rezzy_types.rs:1457-1462`) so stripped PDUs cannot bypass `verify_content_hash` (`F-06-03`)
  - [ ] Replace `.expect()` in `canonical_redacted_json` (`src/basespec/rezzy_types.rs:1040-1045`) with fallible `try_canonical_redacted_json` error propagation and fix the stale number-tolerance doc comment on `reference_hash` (`src/basespec/rezzy_types.rs:920-960`, `F-06-03`)
- [ ] Task: Remove silent `Ok(())` default bodies from `EventVerifier` (`F-06-04`)
  - [ ] Remove default `Ok(())` method implementations from `EventVerifier` in `src/basespec/rezzy_types.rs:2645-2665`, introduce an explicit `NoopEventVerifier` for test harnesses, and update `validate_forward_extremity` / `check_auth` in `src/auth/mod.rs:491-502,1894-1904` (`F-06-04`)

## Phase 3: Integer-Safe Redaction Rule 11, Zero-Alloc PL Diffing & Documentation Sync (`F-03.6`, `F-03.7`, `F-06-05`, `F-06-06`)
- [ ] Task: Fix Redaction Rule 11 domain check for integer `Id`s and remove temporary `BTreeMap` allocations in `check_power_levels_rules` (`F-03.6`, `F-06-06`)
  - [ ] Refactor Redaction Rule 11 (V1–V2) in `src/auth/mod.rs:676-681` to extract the server domain without `alloc::format!("{}", event.event_id())` so integer `Id`s (`u32`/`u64`) work properly, and add a unit test in `tests/unit/test_integer_keys.rs` (`F-03.6`)
  - [ ] Refactor `check_power_levels_rules` in `src/auth/mod.rs:1076-1140` to validate power-level transitions via direct visitor/lookup passes without allocating 6 intermediate `BTreeMap<&str, i64>` maps (`F-06-06`)
- [ ] Task: Synchronize `docs/design_notes.md`, `docs/spec_coverage.csv`, and `docs/spec_audit.md` (`F-03.7`, `F-06-05`)
  - [ ] Update outdated 6-argument `resolve_iterative_sort` and `compute_state_at_streaming` signatures in `docs/design_notes.md:17,174-190` to `IterativeInputs::new` and `StreamingInputs::try_compute` (`F-03.7`)
  - [ ] Recalibrate `docs/spec_coverage.csv:1-36` and `docs/spec_audit.md:1-6,128-136` to accurately distinguish `full` core CPU checks from `partial`/`delegated` homeserver cryptographic and I/O checks (`F-06-05`)
