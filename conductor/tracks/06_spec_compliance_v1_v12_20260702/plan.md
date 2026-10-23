# Implementation Plan: Track 06 — Matrix Room V1–V12 Spec Compliance, 3PI Delegation, Knocking & PDU Invariants

## Phase 1: Knocking (`MSC2403`), Restricted Joins (`MSC3083`) & Self-Leave Enforcement (`v0.3.1`–`v0.4.0`) [checkpoint: 793b40c]

- [x] Task: Support `restricted` and `knock_restricted` join rules (`MSC3083`) `3d9368b`
  - [x] Implement `restricted` and `knock_restricted` join-rule evaluation in [`src/auth/mod.rs`](../../../src/auth/mod.rs) (`3d9368b`, `a309673`).
  - [x] Verify `join_authorised_via_users_server` authorizer membership and invite PL in [`tests/unit/test_restricted_joins.rs`](../../../tests/unit/test_restricted_joins.rs) (`7cca9d2`, `48626a3`).
- [x] Task: Implement `check_knock_rules` (`MSC2403 §f`) and membership edge-case guards `cadfe0e`
  - [x] Implement `check_knock_rules` and include `m.room.join_rules` in required auth types for `knock` events (`e024576`, `cadfe0e`, `fec0cdb`, merged in `43e6761`).
  - [x] Reject invites when the target is already joined (Rule 5.4.3, `d0417b1`) and reject unknown membership strings with `AuthError::InvalidSyntax` (Rule 5.8, `82b26c2`).
- [x] Task: Enforce strict self-leave rules (Spec Rule 5.5.1) and release `v0.4.0` `793b40c`
  - [x] Update `check_leave_rules` in [`src/auth/mod.rs`](../../../src/auth/mod.rs) so self-leave is only allowed from `invite`, `join`, or `knock` membership states and regenerate test oracle snapshots (`793b40c`).
  - [x] Initialize [`docs/spec_coverage.csv`](../../../docs/spec_coverage.csv) and [`docs/spec_audit.md`](../../../docs/spec_audit.md) traceability tables and tag `v0.4.0` (`1f4ebf0`, `f1e6cb5`, `cb41926`, `a71f2b4`).

## Phase 2: Third-Party Invite (`3PI`) Delegation (Rule 5.4.1 & Rule 7) [checkpoint: 09201ac]

- [x] Task: Implement Third-Party Invite power-level delegation and token validation `b556b21`
  - [x] Implement Spec Rule 5.4.1 3PI token/signature structure validation and issuer PL delegation in `check_invite_rules` (`b556b21`, `6b48061`, `2fb846a`).
  - [x] Add regression tests for third-party invite authorization rules in [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) (`ed2a542`).
- [x] Task: Prioritize 3PI rule over event-specific PL overrides and block banned targets `e952490`
  - [x] Branch on `third_party_invite` field presence (`00eaf0b`) and prioritize 3PI delegation over event-specific PL overrides (`e952490`).
  - [x] Reject banned targets in 3PI invites and fix V12 creator PL in restricted joins (`deaf818`).
- [x] Task: Harden 3PI error variants, `FIELD_*` constants, and `auth/user.rs` extraction `09201ac`
  - [x] Centralize `FIELD_*` and `DEFAULT_PL_*` constants (`fef9704`, `058d735`, `2cf758a`), return `AuthError::InvalidSyntax` for malformed 3PI payloads (`cdc002b`, `3922f6f`), and tighten test assertions (`5a918c4`, `21a861b`, `5a499bf`).
  - [x] Extract public user power-level query API into [`src/auth/user.rs`](../../../src/auth/user.rs) (`6e45f95`, `dcba8ac`) and merge `feat/third-party-invite-rules` (`09201ac`).

## Phase 3: Room Version 12 Creator Immunity (`MSC4289`) & `m.room.power_levels` Rules 10.1–10.10 [checkpoint: ce961eb]

- [x] Task: Implement `MSC4289` V12 creator privileges and pre-V12 creator PL 100 fallback `2ffbf36`
  - [x] Assign `i64::MAX` power level to V12+ room creators and `additional_creators` (`a56a6b8`, `a27bb63`, `5cb835e`, `d7bc756`).
  - [x] Reconcile pre-V12 vs. V12+ creator fallback semantics: restore PL 100 fallback for V1–V11 when no `m.room.power_levels` event exists in state (`004d17c`, `2ffbf36`, `cc1ffc2`).
- [x] Task: Implement Rule 10 `m.room.power_levels` validation (Sub-rules 10.1–10.10) `d15945a`
  - [x] Implement Rule 10.3 (`users` valid MXID keys + integer values) and Rules 10.6–10.10 (scalar, `events`, `notifications`, and `users` diff escalation checks) in [`src/auth/mod.rs`](../../../src/auth/mod.rs) (`c697875`, `3912526`, `b504f97`).
  - [x] Implement Rules 10.1–10.2 (non-integer scalar and map PL rejection) and V12 Rule 10.4 (reject `m.room.create` creator / `additional_creators` in `users` map) with state-resolution tests (`d15945a`, `463cabc`, `724d4be`).
- [x] Task: Gate Rules 10.1–10.4 by room version and optimize PL validation with visitor pattern `82456c9`
  - [x] Gate Rules 10.1–10.2 to V10+, Rule 10.3 to all versions, and Rule 10.4 to V12+, and harden Rule 10 security edge cases (`e489df0`, `82456c9`, merged in `ce961eb`).
  - [x] Refactor power-level map iterators to use a zero-allocation visitor pattern on `EventContent` (`5384219`, `dcbb6a2`, `9596670`) and update [`docs/spec_audit.md`](../../../docs/spec_audit.md) (`fe255aa`, `c26b29d`, `33f15aa`).

## Phase 4: PDU Syntactic Invariants, Redaction Matrix, Hashing & `MSC4303` Legacy MXIDs [checkpoint: 85464d3]

- [x] Task: Implement PDU syntactic invariants, versioned redaction rules, and reference/content hashing `6f5dc64`
  - [x] Implement `redaction_preserved_keys` across V1–V11+ (failing closed with `RedactionRule::None` on unrecognized room versions) and SHA-256 `reference_hash` / `compute_content_hash` (`6f5dc64`, PR #30).
  - [x] Implement `validate_syntactic` (255-byte V11+ hard limits, `MAX_SAFE_JSON_INTEGER` depth bounds, Rule 1.3/1.4 `m.room.create` checks) and Rules 1.2, 2.2 (`IncompleteAuthEvents`), 2.5 (`MSC4307` `ForeignRoomEvent`), 3 (`m.federate`), 4 (`m.room.aliases`), and 11 (`m.room.redaction`) (`6f5dc64`).
- [x] Task: Accept legacy MXIDs (`MSC4303` hotfix) and add `MSC4311` / knock stripped-state filters `85464d3`
  - [x] Downgrade historical uppercase/Unicode MXID localparts in `validate_syntactic` from hard rejection to warn-only while preserving structural MXID validation (`85464d3`, merged in `c7ae9ed`).
  - [x] Add `MSC4311` stripped-state validation for invites (`d59ea84`) and knock stripped-state filtering (`a514b11`).

---

## History & Audit Traceability

| Commit SHA | Date | Source & Test Files Touched | Documentation & Audit Linkage | Public-Safety Audit Observation |
| :--- | :--- | :--- | :--- | :--- |
| `3d9368b` / `cadfe0e` / `43e6761` | 2026-06-30 | [`src/auth/mod.rs`](../../../src/auth/mod.rs), [`tests/unit/test_restricted_joins.rs`](../../../tests/unit/test_restricted_joins.rs) | [`docs/spec_audit.md`](../../../docs/spec_audit.md), [`docs/spec_coverage.csv`](../../../docs/spec_coverage.csv) | Rule 5.2 (`join_authorised_via_users_server` Ed25519 signature verification) is delegated to the homeserver caller. |
| `793b40c` / `d0417b1` / `82b26c2` | 2026-06-30 | [`src/auth/mod.rs`](../../../src/auth/mod.rs), [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) | [`docs/spec_audit.md`](../../../docs/spec_audit.md) | Closes membership state-machine bypasses on self-leave (Rule 5.5.1), already-joined invite (Rule 5.4.3), and unknown membership (Rule 5.8). |
| `b556b21` / `e952490` / `deaf818` / `09201ac` | 2026-06-30 – 2026-07-01 | [`src/auth/mod.rs`](../../../src/auth/mod.rs), [`src/auth/user.rs`](../../../src/auth/user.rs), [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) | [`docs/spec_audit.md`](../../../docs/spec_audit.md), [`docs/spec_coverage.csv`](../../../docs/spec_coverage.csv) | Enforces 3PI token delegation (Rule 5.4.1) and blocks banned users from bypassing bans via 3PI tokens (`deaf818`). |
| `2ffbf36` / `d15945a` / `463cabc` / `e489df0` / `82456c9` | 2026-07-02 | [`src/auth/mod.rs`](../../../src/auth/mod.rs), [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs), [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) | [`docs/spec_audit.md`](../../../docs/spec_audit.md), [`docs/spec_coverage.csv`](../../../docs/spec_coverage.csv) | Enforces V12 creator `i64::MAX` immunity (`MSC4289`) and Rules 10.1–10.10 power-level privilege escalation checks. |
| `6f5dc64` / `85464d3` | 2026-07-28 – 2026-09-29 | [`src/auth/mod.rs`](../../../src/auth/mod.rs), [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs), [`tests/unit/test_hashing.rs`](../../../tests/unit/test_hashing.rs) | [`docs/spec_audit.md`](../../../docs/spec_audit.md), [`docs/spec_coverage.csv`](../../../docs/spec_coverage.csv), [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) | **Critical (Fail-Open API) & Moderate (Overconfidence):** `MSC4307` Rule 2.5 cross-room auth check is opt-in via `Option<RoomId>` (`None` by default); 31/35 rows in `spec_coverage.csv` are marked `full`. |
