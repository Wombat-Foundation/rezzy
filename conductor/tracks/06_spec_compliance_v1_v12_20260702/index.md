# Track 06: Matrix Room V1–V12 Spec Compliance, 3PI Delegation, Knocking & PDU Invariants (`v0.4.0`–`v0.5.0`)

- **Track ID:** `06_spec_compliance_v1_v12_20260702`
- **Type:** `compliance`
- **Status:** `completed`
- **Epoch & Commit Range:** `v0.4.0`–`v0.5.0` + Jul/Sep 2026 (`a71f2b4..7e39a14`, `43e6761`, `793b40c`, `d0417b1`, `b556b21`, `09201ac`, `d15945a`, `463cabc`, `e489df0`, `82456c9`, `c26b29d`, `6f5dc64`, `85464d3`)

## Track Artifacts

- [Specification (`./spec.md`)](./spec.md)
- [Implementation Plan (`./plan.md`)](./plan.md)
- [Track Metadata (`./metadata.json`)](./metadata.json)
- [Public-Safety Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md)

## Linked Repository Documentation & Source Modules

### Documentation (`docs/`)
- [`spec_audit.md`](../../../docs/spec_audit.md) — Comprehensive cross-version authorization rule audit (Room Versions 1–12), `m.room.member` sub-rules 5.1–5.8, `m.room.power_levels` sub-rules 10.1–10.10, redaction preservation matrix, PDU syntactic invariants, and `MSC4307` `Option<RoomId>` trust boundary notes.
- [`spec_coverage.csv`](../../../docs/spec_coverage.csv) — 35-row specification and MSC traceability matrix mapping Matrix v1.13 sections and MSCs (`MSC1693`, `MSC2403`, `MSC4297`, `MSC4307`, `MSC3757`, `MSC4242`, `MSC4289`, `MSC0501`) to `rezzy` support levels.

### Core Source Modules (`src/`)
- [`src/auth/mod.rs`](../../../src/auth/mod.rs) — `check_auth`, `check_auth_with_context`, `check_auth_chain`, `check_knock_rules`, `check_invite_rules`, `check_leave_rules`, `check_power_levels_rules`, and `AuthError` (`IncompleteAuthEvents`, `ForeignRoomEvent`, `RejectedAuthEvent`).
- [`src/auth/user.rs`](../../../src/auth/user.rs) — Version-aware `get_sender_power_level`, creator `i64::MAX` immunity (`MSC4289`), and pre-V12 creator PL 100 fallback (`2ffbf36`, `e489df0`).
- [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs) — `validate_syntactic`, `apply_redaction`, `redaction_preserved_keys`, `is_valid_mxid` (including `MSC4303` historical MXID tolerance `85464d3`), `domain_matches`, and `EventContent` PL validation helpers.
- [`src/basespec/version_props.rs`](../../../src/basespec/version_props.rs) — Room-version property predicates for V1–V12 (`StateResVersion::from_room_version`).

### Verification Oracles (`tests/`)
- [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) — Unit tests for Rules 1–11, 3PI delegation (Rule 5.4.1), self-leave (Rule 5.5.1), knock rules (`MSC2403`), power-level validation (Rules 10.1–10.10), and `MSC4307` foreign-room rejection.
- [`tests/unit/test_restricted_joins.rs`](../../../tests/unit/test_restricted_joins.rs) — `MSC3083` `restricted` and `knock_restricted` join rule and `join_authorised_via_users_server` authorization tests.
- [`tests/unit/test_hashing.rs`](../../../tests/unit/test_hashing.rs) — Reference hash (`event_id`), content hash (`hashes.sha256`), and version-specific redaction key preservation tests (`6f5dc64`).
