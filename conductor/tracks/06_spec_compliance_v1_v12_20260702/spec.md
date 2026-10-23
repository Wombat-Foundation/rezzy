# Specification: Matrix Room V1–V12 Spec Compliance, 3PI Delegation, Knocking & PDU Invariants

## 1. Overview & Historical Context

Spanning `v0.3.1` (`b9c2cd6`, Jun 30, 2026), `v0.4.0` (`a71f2b4`, Jun 30, 2026), `v0.5.0` (`7e39a14`, Jul 6, 2026), PR #30 (`6f5dc64`, Jul 28, 2026), and the `MSC4303` historical MXID hotfix (`85464d3` / `c7ae9ed`, Sep 29, 2026), Track 06 systematically closed every authorization, redaction, and PDU syntactic gap between `rezzy` and the Matrix v1.13 Server-Server specification across Room Versions 1 through 12:

1. **Knocking (`MSC2403`) & Restricted Joins (`MSC3083`) (`3d9368b`, `e024576`, `cadfe0e`, `7cca9d2`, `48626a3`, `fec0cdb`, `d0417b1`, `82b26c2`, `43e6761`, Jun 30, 2026):**
   - Implemented `check_knock_rules` (Rule 5.7.1–5.7.3), added `m.room.join_rules` to `auth_types_for_event` for `knock` events (`fec0cdb`), validated `join_authorised_via_users_server` membership and invite PL for `restricted` / `knock_restricted` joins (`7cca9d2`, `48626a3`), rejected invites when the target is already joined (`d0417b1`, Rule 5.4.3), and rejected unknown membership strings (`82b26c2`, Rule 5.8).
2. **Strict Self-Leave Enforcement (`793b40c`, `cb41926`, Tag `v0.4.0`, Jun 30, 2026):**
   - Enforced Matrix Spec Rule 5.5.1 in `check_leave_rules`: a self-leave is only authorized if the sender's prior membership is `invite`, `join`, or (in V7+) `knock`, regenerating oracle snapshots across the test suite.
3. **Third-Party Invite (`3PI`) Power-Level Delegation (`b556b21`, `ed2a542`, `00eaf0b`, `e952490`, `deaf818`, `09201ac`, Jun 30 – Jul 1, 2026):**
   - Implemented Spec Rule 5.4.1 (`check_invite_rules` 3PI token validation against `m.room.third_party_invite` state events) and Rule 7 (`m.room.third_party_invite` sender PL $\ge$ `invite` level), prioritizing 3PI delegation over event-specific PL overrides while still rejecting banned targets (`deaf818`).
4. **Room Version 12 Creator Immunity (`MSC4289`) & `m.room.power_levels` Rules 10.1–10.10 (`a56a6b8`, `5cb835e`, `2ffbf36`, `c697875`, `d15945a`, `463cabc`, `e489df0`, `82456c9`, `c26b29d`, Jun 29 – Jul 2, 2026):**
   - Assigned V12+ room creators and `additional_creators` `i64::MAX` power level (`a56a6b8`, `5cb835e`), implemented full `m.room.power_levels` validation (Rules 10.1–10.10), gated non-integer scalar/map rejection (Rules 10.1–10.2) to V10+ and creator-in-`users` rejection (Rule 10.4) to V12+ (`d15945a`, `463cabc`, `e489df0`, `82456c9`), and restored the V1–V11 creator PL 100 fallback when no PL event exists (`2ffbf36`, `e489df0`).
5. **PDU Syntactic Invariants, Redaction Rules, Content/Reference Hashing & `MSC4303` Legacy MXIDs (`6f5dc64` PR #30, `85464d3`, Jul 28 – Sep 29, 2026):**
   - Implemented version-aware `redaction_preserved_keys` (V1–V11+ fail-closed on unrecognized room version), reference/content SHA-256 hashing (`reference_hash`, `compute_content_hash`), Rule 1.2/2.2/2.5/3/4/11 auth checks (`6f5dc64`), and downgraded legacy uppercase/Unicode MXID localparts from hard-fail to warn-only (`85464d3`) since strict MXID grammar (`MSC4303`) is not yet adopted in V1–V12.

---

## 2. Functional Requirements & Matrix Spec/MSC Mapping

| Requirement ID | Functional Requirement | Implementation Locus | Verification / Spec Mapping |
| :--- | :--- | :--- | :--- |
| **FR-06-01** | **Knocking (`MSC2403`) & Restricted Joins (`MSC3083`):** Enforce Rule 5.7 (`knock` allowed only on `knock` in V7+ or `knock_restricted` in V10+, `sender == state_key`, prior membership not `ban`/`invite`/`join`) and Rule 5.3.5 (`join_authorised_via_users_server` authorizer joined with PL $\ge$ `invite`). | [`src/auth/mod.rs`](../../../src/auth/mod.rs) (`check_knock_rules`, `check_authorising_user`) | `MSC2403`, `MSC3083`, Spec v1.13 §3.3; [`tests/unit/test_restricted_joins.rs`](../../../tests/unit/test_restricted_joins.rs) |
| **FR-06-02** | **Strict Membership Transition Rules (5.1, 5.4.1, 5.4.3, 5.5.1, 5.8):** Reject missing `state_key`/`membership` (5.1), validate 3PI `third_party_invite.signed` tokens and issuer PL (5.4.1 & Rule 7), reject inviting already-joined or banned users (5.4.3), enforce self-leave only from `invite`/`join`/`knock` (5.5.1), and reject unknown membership values (5.8). | [`src/auth/mod.rs`](../../../src/auth/mod.rs) (`check_invite_rules`, `check_leave_rules`) | Spec v1.13 §3.3 Rules 5.1–5.8, Rule 7; [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) |
| **FR-06-03** | **Room V12 Creator Immunity (`MSC4289`) & Power-Levels Validation (Rule 10.1–10.10):** Enforce V10+ integer type checks on scalar PL fields (10.1) and `events`/`notifications` maps (10.2), `@user:domain` key + integer validation on `users` across all versions (10.3), forbid V12+ `m.room.create` sender and `additional_creators` in `users` (10.4), allow first PL event (10.5), and enforce sender PL ceiling on all scalar/map diffs (10.6–10.10). | [`src/auth/mod.rs`](../../../src/auth/mod.rs) (`check_power_levels_rules`), [`src/auth/user.rs`](../../../src/auth/user.rs), [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs) | `MSC4289`, Spec v1.13 §3.3 Rule 10; [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) |
| **FR-06-04** | **Version-Aware Redaction Algorithm & Content/Reference Hashing:** Preserve exact per-version keys during `apply_redaction` (failing closed with `RedactionRule::None` on unrecognized room versions) and compute V3 standard base64 vs. V4+ URL-safe base64 SHA-256 reference hashes. | [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs), [`rezzy-cli/src/hash.rs`](../../../rezzy-cli/src/hash.rs) | Spec v1.13 Redactions & Signing; [`tests/unit/test_hashing.rs`](../../../tests/unit/test_hashing.rs) |
| **FR-06-05** | **Auth-Events Selection (Rule 2.2), Cross-Room Guard (`MSC4307` Rule 2.5) & PDU Invariants:** Enforce required `auth_events` citations (`IncompleteAuthEvents`), V12 `m.room.create` `room_id`-absence and accepted-create ID matching, `m.federate` (Rule 3), V1–V5 `m.room.aliases` (Rule 4), V1–V2 `m.room.redaction` (Rule 11), and `validate_syntactic` with `MSC4303` historical MXID tolerance. | [`src/auth/mod.rs`](../../../src/auth/mod.rs), [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs) | `MSC4307`, `MSC4303`, [`docs/spec_audit.md`](../../../docs/spec_audit.md), [`docs/spec_coverage.csv`](../../../docs/spec_coverage.csv) |

---

## 3. Architectural Decisions & Rejected Alternatives

1. **Creator Power-Level Fallback Across V1–V11 vs. V12 (`004d17c` -> `2ffbf36` -> `e489df0`):**
   - *Evolution:* Commit `004d17c` removed implicit creator PL 100 for V1–V11 under the assumption that only V12 (`MSC4289`) privileged creators. Immediately afterward (`2ffbf36`, `cc1ffc2`, `e489df0`), testing against the Matrix v1.13 spec confirmed that in V1–V11, when *no* `m.room.power_levels` event exists in state, the `m.room.create` `creator` defaults to PL 100 (whereas in V12+, the `sender` and `additional_creators` of `m.room.create` permanently hold `i64::MAX` immunity and cannot appear in `users`).
2. **Zero-Allocation Visitor Pattern for Power-Level Map Validation (`5384219`):**
   - Rather than allocating intermediate `Vec` or `BTreeMap` collections to inspect `users`, `events`, and `notifications` maps during Rule 10 validation, `EventContent` uses zero-allocation visitor callbacks (`visit_user_keys`, `find_non_integer_scalar_pl`, `find_non_integer_map_pl`).
3. **Warn-Only Historical MXIDs (`85464d3`, `c7ae9ed`):**
   - *Initial Approach:* PR #30 (`6f5dc64`) enforced strict lowercase ASCII MXID localpart grammar in `validate_syntactic`.
   - *Pivot:* Real-world Matrix rooms contain historical uppercase or out-of-range MXIDs permitted by the Matrix Spec's "Historical User IDs" clause; strict MXID grammar (`MSC4303`) is a future room-version feature. Commit `85464d3` downgraded historical localpart characters to a warning while keeping structural breakage (`@` prefix, `:` separator, empty localpart, invalid domain) as hard errors.

---

## 4. Non-Functional & Public-Safety Invariants

Cross-referencing the [Public-Safety Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md):

> [!CAUTION]
> **Public-Safety Risk — Critical (Fail-Open API on `MSC4307` Rule 2.5) & Moderate (Overconfidence in `spec_coverage.csv`):**
> As documented in [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Rows 14 & 15, [`spec_audit.md`](../../../docs/spec_audit.md) & [`spec_coverage.csv`](../../../docs/spec_coverage.csv)):
> 1. **Opt-In `MSC4307` Cross-Room Auth Rejection (`LeanEvent.room_id: Option<RoomId>`):** `MSC4307` (Auth Rule 2.5) requires unconditionally rejecting any event whose `auth_events` belong to a different room. In `rezzy`, `LeanEvent.room_id` defaults to `None` unless the caller explicitly passes a trusted `room_id` to `ingest_events`. If a downstream homeserver integrator forgets to populate `room_id`, `check_auth_chain` silently skips Rule 2.5 and V12 Rule 2 (`check_room_id_matches_accepted_create`), failing open to cross-room state-injection attacks.
> 2. **Externalized Cryptographic Signature Verification (Rule 5.2 & PDU Signatures):** `rezzy` delegates Ed25519 PDU signature verification and V8+ `join_authorised_via_users_server` signature validation (Rule 5.2) to the caller (`EventVerifier` / `ForwardExtremityResult::ValidMaybePendingSigHashVer`, `53928be`).
> 3. **Overconfidence in `spec_coverage.csv`:** 31 of 35 rows in [`docs/spec_coverage.csv`](../../../docs/spec_coverage.csv) are marked `full` even though PDU syntactic validation (`validate_syntactic`), pre-V11 255-byte limits, and signature verification are partial or externalized, and current shipping scope is gated to State Resolution V1 (`0b6a2bc`, `aeececf`).

---

## 5. Acceptance Criteria & Verification Oracles

1. **Cross-Version Authorization Rule Suite (`V1`–`V12`):** [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) and [`tests/unit/test_restricted_joins.rs`](../../../tests/unit/test_restricted_joins.rs) verify every row in [`docs/spec_audit.md`](../../../docs/spec_audit.md), including Rules 1–11, 3PI delegation (5.4.1), self-leave (5.5.1), knock rules (5.7.1–5.7.3), V10+ vs. V12+ power-level rules (10.1–10.10), and `AuthError::ForeignRoomEvent` (`MSC4307`).
2. **Redaction & Cryptographic Hashing Oracles:** [`tests/unit/test_hashing.rs`](../../../tests/unit/test_hashing.rs) verifies `event_id(e) == event_id(redact(e))`, V3 standard vs. V4+ URL-safe base64 reference hashes, and fail-closed `RedactionRule::None` behavior on unknown room versions.
3. **Traceability Audit Sync:** [`docs/spec_audit.md`](../../../docs/spec_audit.md) and [`docs/spec_coverage.csv`](../../../docs/spec_coverage.csv) accurately record the `[~]` partial status of `MSC4307` Rule 2.5 and `spec/v1.13§PDU`.
