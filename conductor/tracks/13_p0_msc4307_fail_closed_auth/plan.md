# Implementation Plan: Track 13 — P0 Unconditional Fail-Closed `MSC4307` Rule 2.5 & Room V12 Creator Fixes

## Phase 1: Red-Phase Adversarial Cross-Room & V12 Rule 10.4 Regression Tests [checkpoint: a1cadf1]
- [x] Task: Add failing regression tests for missing/mismatched `room_id` (`F-03.1`, `F-06-01`) and V12 Rule 10.4 `create_event.sender()` (`F-06-02`) a1cadf1
  - [x] Write unit tests in `src/auth/` asserting that cross-room `auth_events` are rejected across `check_auth`, `check_auth_with_context`, and `check_auth_chain`
  - [x] Add test verifying V12 Rule 10.4 rejects `m.room.power_levels` containing `create_event.sender()` in `users` when `content.creator` is absent (`src/auth/mod.rs:911`)
  - [x] Add test for fail-closed `EventContent` / `EventVerifier<Id>` trait defaults (`F-03.3`, `F-03.4`)

## Phase 2: Fail-Closed `RoomId` Enforcement & V12 Rule 10.4 Fix in `src/auth/` [checkpoint: f5e98bf]
- [x] Task: Make `room_id` verification mandatory across all auth entry points and fix V12 Rule 10.4 creator resolution f5e98bf
  - [x] Wire `check_create_room_id` (Rule 1.2), `check_room_id_matches_accepted_create` (V12 Rule 2), and `check_foreign_room_citation` (`MSC4307` Rule 2.5) into `check_auth_with_context` and fail closed when `room_id` is missing/mismatched (`src/auth/mod.rs:1995-2191`)
  - [x] Fix `src/auth/mod.rs:908-917` to resolve V12 room creator via `create_event.sender()` (and `additional_creators`) rather than legacy `create_content.get_creator()`
  - [x] Align Rule 1.2 MXID check (`src/auth/mod.rs:603`) with `MSC4303` historical MXID policy

## Phase 3: Spec Audit & Coverage Matrix Synchronization [checkpoint: f5e98bf]
- [x] Task: Update `docs/spec_audit.md` and `docs/spec_coverage.csv` to reflect unconditional `MSC4307` enforcement and delegated checks f5e98bf
  - [x] Reclassify partially enforced or caller-delegated rows in `docs/spec_coverage.csv` and update `docs/spec_audit.md`
  - [x] Run `cargo test --workspace --lib --tests` and `cargo clippy --all-targets --all-features`
