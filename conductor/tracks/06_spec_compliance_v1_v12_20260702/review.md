# Track 06 Review & Multi-Perspective Critique Report: Matrix Room V1–V12 Spec Compliance, 3PI Delegation, Knocking & PDU Invariants

- **Track ID:** `06_spec_compliance_v1_v12_20260702`
- **Track Title:** Matrix Room V1–V12 Spec Compliance, 3PI Delegation, Knocking & PDU Invariants
- **Epoch & Commit Range:** `v0.4.0`–`v0.5.0` + Jul/Sep 2026 (`a56a6b8..85464d3`)
- **Review Status:** Completed with Actionable Stage B Remediation Items (`Critical` Public-Safety Risk: Opt-In `MSC4307` Rule 2.5 Fail-Open API & Externalized Signature Verification)
- **Primary Audit Reference:** [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Rows 9, 14, 15)

---

## 1. Conductor Review Summary (`/conductor-review` Structure)

### 1.1 Plan & Specification Compliance
| Requirement ID | Requirement Summary | Verification Oracle | Verdict |
| :--- | :--- | :--- | :--- |
| **FR-06-01** | Knocking (`MSC2403` Rule 5.7) & Restricted Joins (`MSC3083` Rule 5.3.5 `join_authorised_via_users_server`) | [`src/auth/mod.rs:1850-1951`](../../../src/auth/mod.rs#L1850-L1951), [`tests/unit/test_restricted_joins.rs`](../../../tests/unit/test_restricted_joins.rs) | **PASS** (Rule 5.2 signature check delegated to `EventVerifier`) |
| **FR-06-02** | Strict Membership Transition Rules (5.1, 5.4.1 3PI delegation, 5.4.3, 5.5.1 self-leave, 5.8 unknown membership) & Rule 7 | [`src/auth/mod.rs:967-1020`](../../../src/auth/mod.rs#L967-L1020), [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) | **PASS** |
| **FR-06-03** | Room V12 Creator Immunity (`MSC4289` `i64::MAX`) & `m.room.power_levels` Rules 10.1–10.10 | [`src/auth/mod.rs:876-965`](../../../src/auth/mod.rs#L876-L965), [`1028-1193`](../../../src/auth/mod.rs#L1028-L1193), [`src/auth/user.rs:24-77`](../../../src/auth/user.rs#L24-L77) | **PASS** (with subtle V11 vs. V12 `content.creator` vs. `sender` note in Rule 10.4) |
| **FR-06-04** | Version-aware redaction (`redaction_preserved_keys`, `redact_json`) & SHA-256 reference/content hashing | [`src/basespec/rezzy_types.rs:568-1069`](../../../src/basespec/rezzy_types.rs#L568-L1069), [`tests/unit/test_hashing.rs`](../../../tests/unit/test_hashing.rs) | **PASS** (with relaxed number canonicalization caveat on `reference_hash`) |
| **FR-06-05** | Auth-events selection (Rule 2.2), Cross-room guard (`MSC4307` Rule 2.5), PDU syntactic validation & `MSC4303` legacy MXIDs | [`src/auth/mod.rs:690-803`](../../../src/auth/mod.rs#L690-L803), [`1995-2211`](../../../src/auth/mod.rs#L1995-L2211), [`src/basespec/rezzy_types.rs:3035-3327`](../../../src/basespec/rezzy_types.rs#L3035-L3327) | **AT RISK (`MSC4307` Rule 2.5 & V12 Rule 2 are Opt-In via `Option<RoomId>`)** |

### 1.2 Executive Findings Matrix
| Finding ID | Severity | Perspective | Location | Summary |
| :--- | :--- | :--- | :--- | :--- |
| **F-06-01** | `[Critical]` | `critic-compliance`, `critic-dx-integrator` | [`src/auth/mod.rs:80-101`](../../../src/auth/mod.rs#L80-L101), [`2033-2066`](../../../src/auth/mod.rs#L2033-L2066), [`2100-2130`](../../../src/auth/mod.rs#L2100-L2130), [`src/basespec/rezzy_types.rs:1433-1470`](../../../src/basespec/rezzy_types.rs#L1433-L1470) | **Fail-Open `Option<RoomId>` on `MSC4307` Rule 2.5 & V12 Rule 2:** `LeanEvent.room_id` defaults to `None` and `ingest_events` accepts `room_id: Option<&str>`. When `event.room_id` is `None`, both `check_foreign_room_citation` (Rule 2.5) and `check_room_id_matches_accepted_create` (V12 Rule 2) return `Ok(())` immediately without checking anything. Furthermore, neither check runs in `check_auth` or `check_auth_with_context`—only in `check_auth_chain`. |
| **F-06-02** | `[High]` | `critic-compliance`, `critic-formal-crypto` | [`src/auth/mod.rs:907-933`](../../../src/auth/mod.rs#L907-L933) vs. [`src/auth/user.rs:38-49`](../../../src/auth/user.rs#L38-L49) | **V12 Rule 10.4 Creator Check Asymmetry (`content.creator` vs. `event.sender()`):** In Room V12 (`MSC4289`), `m.room.create` uses `event.sender()` (not `content.creator`) as the room creator. `get_sender_power_level` (`src/auth/user.rs:40`) correctly checks `create_event.sender() == sender || create_event.has_additional_creator(sender)`, **but** Rule 10.4 in `check_auth_with_context` (`src/auth/mod.rs:911`) checks `if let Some(creator) = create_content.get_creator()` instead of `create_event.sender()`! If a V12 `m.room.create` event omits the deprecated `content.creator` field (as V11+ specifies), `create_content.get_creator()` returns `None` or falls back depending on `EventContent` implementation. |
| **F-06-03** | `[High]` | `critic-federation-interop`, `critic-formal-crypto` | [`src/basespec/rezzy_types.rs:920-960`](../../../src/basespec/rezzy_types.rs#L920-L960), [`1040-1045`](../../../src/basespec/rezzy_types.rs#L1040-L1045), [`1457-1462`](../../../src/basespec/rezzy_types.rs#L1457-L1462) | **Optional `hashes` Check at Ingest & Panic Risk in `canonical_redacted_json`:** In `ingest_events` (`src/basespec/rezzy_types.rs:1457-1462`), `verify_content_hash` is only called `if pdu.get(FIELD_HASHES).is_some()`, allowing a stripped federation PDU without a `hashes` field to bypass content-hash verification. Additionally, `canonical_redacted_json` (line 1040) panics via `.expect(...)` if given a v6+ event with a fractional or $>2^{53}-1$ number. |
| **F-06-04** | `[High]` | `critic-dx-integrator`, `critic-compliance` | [`src/basespec/rezzy_types.rs:2645-2665`](../../../src/basespec/rezzy_types.rs#L2645-L2665), [`src/auth/mod.rs:491-502`](../../../src/auth/mod.rs#L491-L502), [`1894-1904`](../../../src/auth/mod.rs#L1894-L1904) | **Silent No-Op Default on `EventVerifier` & Second Pass of `validate_forward_extremity`:** `EventVerifier` trait methods default to returning `Ok(())`, and `check_auth` takes `verifier: Option<&dyn EventVerifier>`. Even if an integrator implements `EventVerifier` without overriding every method, unimplemented signature checks silently pass. |
| **F-06-05** | `[Medium]` | `critic-pm`, `critic-compliance` | [`docs/spec_coverage.csv:1-36`](../../../docs/spec_coverage.csv#L1-L36), [`docs/spec_audit.md:1-6`](../../../docs/spec_audit.md#L1-L6), [`128-136`](../../../docs/spec_audit.md#L128-L136) | **Traceability Overconfidence in `spec_coverage.csv`:** 31 of 35 rows in `spec_coverage.csv` are marked `full` despite: (a) top-of-file disclaimer in `spec_audit.md` stating only V1 state resolution is supported, (b) `spec/v1.13§3.3` Restricted Join Rules (Row 23) delegating Rule 5.2 signature verification to the caller, and (c) `validate_syntactic` leaving `content`/`hashes`/`signatures`/`room_id` presence as a `# TODO(compliance)` (`src/basespec/rezzy_types.rs:3128-3136`). |
| **F-06-06** | `[Low]` | `critic-perf` | [`src/auth/mod.rs:1076-1140`](../../../src/auth/mod.rs#L1076-L1140) | **Intermediate `BTreeMap` Allocations in `check_power_levels_rules`:** While `EventContent` uses zero-allocation visitors (`visit_event_power_levels`, `visit_notification_power_levels`, `visit_user_power_levels`), `check_power_levels_rules` immediately collects all 6 visitor passes into 6 heap-allocated `BTreeMap<&str, i64>` instances on every `m.room.power_levels` auth check. |

---

## 2. Multi-Perspective Critiques (All 8 Specialized Personas)

### 2.1 Product Management (`critic-pm`)
- **Matrix Spec Coverage (`spec_coverage.csv` 31/35 `full` Claims vs. Reality) (`[Medium]` F-06-05):**
  - Auditing [`docs/spec_coverage.csv`](../../../docs/spec_coverage.csv) line-by-line reveals 31 rows marked `full`, 2 marked `partial` (`MSC4307` and `spec/v1.13§PDU`), 1 marked `experimental` (`MSC4242`), and 1 marked `none` (`MSC3757`).
  - While Track 06 achieved an extraordinary leap in Matrix v1.13 authorization compliance (closing knocking `MSC2403`, restricted joins `MSC3083`, 3PI delegation Rule 5.4.1 & Rule 7, self-leave Rule 5.5.1, V12 creator immunity `MSC4289`, Rules 10.1–10.10, and V1–V12 redaction preservation), marking 31/35 rows `full` overstates readiness for a turnkey homeserver integrator:
    1. **Row 23 (`Restricted Join Rules` — marked `full`):** Rule 5.2 (`join_authorised_via_users_server` Ed25519 signature verification) is marked `[o]` (externalized to HS) in [`docs/spec_audit.md:60`](../../../docs/spec_audit.md#L60) and only runs if the caller passes `Some(verifier)` to `check_auth`.
    2. **Rows 9–20 (`Room Version 1` through `Room Version 12` — all marked `full`):** Contradicts [`docs/spec_audit.md:3-6`](../../../docs/spec_audit.md#L3-L6) (*"Rezzy currently supports state-resolution V1 only"*), and V12 Rule 2 (`check_room_id_matches_accepted_create`) is opt-in on `LeanEvent.room_id` being `Some`, identical to `MSC4307` (which is rightly marked `partial` in Row 5).
    3. **Row 31 (`MSC0501` — marked `full`):** Notes *"homeserver HTTP route wiring is out of scope"*, yet marks support `full`.
- **Room Version Roadmap (`V1`–`V12`, `MSC4242`):**
  - Track 06's `RoomVersionFormat` capability layer ([`src/basespec/rezzy_types.rs:305-384`](../../../src/basespec/rezzy_types.rs#L305-L384)) is a major improvement over collapsing Room V2–V11 into `StateResVersion::V2`, as it cleanly distinguishes V1–V2 opaque event IDs, V3 standard-base64 reference hashes, V4+ URL-safe base64 reference hashes, V6+ strict canonical numbers, V8+ restricted joins, V10+ integer power-level checks, V11+ redaction rules, and V12+ creator immunity.

### 2.2 Principal Engineering Lead (`critic-eng-lead`)
- **`Option<RoomId>` Type Safety & Architectural Split Between `check_auth_with_context` and `check_auth_chain` (`[Critical]` F-06-01):**
  - Looking closely at [`src/auth/mod.rs:1995-2130`](../../../src/auth/mod.rs#L1995-L2130) and [`2177-2191`](../../../src/auth/mod.rs#L2177-L2191), three critical room-identity checks—`check_create_room_id` (Rule 1.2), `check_room_id_matches_accepted_create` (V12 Rule 2), and `check_foreign_room_citation` (`MSC4307` Rule 2.5)—are implemented **only inside `check_auth_chain`**, NOT inside `check_auth` or `check_auth_with_context`!
  - Why? As [`docs/spec_audit.md:30`](../../../docs/spec_audit.md#L30) notes, `room_id` was added as `pub room_id: Option<RoomId>` on the concrete `LeanEvent` struct rather than exposed on the [`EventLike`](../../../src/basespec/rezzy_types.rs#L1662-L1750) trait. Consequently:
    1. Any caller invoking `check_auth`, `check_auth_with_context`, `validate_forward_extremity` ([`src/auth/mod.rs:482-502`](../../../src/auth/mod.rs#L482-L502)), `iterative_auth_ok` (`src/state/at.rs:181-220`), or `resolve_iterative_sort` (`src/resolve/iterative.rs`) **never executes `check_create_room_id`, `check_room_id_matches_accepted_create`, or `check_foreign_room_citation` at all**, even if `LeanEvent.room_id` is `Some(...)`!
    2. Even when calling `check_auth_chain`, if `event.room_id` is `None` (the default on `LeanEvent::default()` and `LeanEvent::from_value`), all three functions (`src/auth/mod.rs:2013`, `2047`, `2109`) hit `let Some(...) = &event.room_id else { return Ok(()); }` and silently pass!
- **CHAMP/HAMT & `PersistentOrdMap` Integration with Auth Rules:**
  - The introduction of [`StateKeyDyn`](../../../src/auth/mod.rs#L196-L267) (`Borrow<dyn StateKeyDyn>` implemented for `(EventType, K)` and `(String, K)`) allows `check_auth` to query `SharedState` (`PersistentOrdMap<(EventType, K), Id>`) using borrowed `(&str, &str)` tuples with zero heap allocations on state lookups.

### 2.3 Public-Safety & C2 Compliance (`critic-compliance`)
- **`[Critical]` Finding F-06-01 — Cross-Room State Injection via Opt-In `MSC4307` Rule 2.5:**
  - In a tactical C2 homeserver, an attacker in low-security Room B (`!roomB:c2.gov`) who knows the `event_id` of an administrative `m.room.power_levels` or `m.room.member` event in Room A (`!roomA:c2.gov`) or vice versa may attempt to cite a foreign-room event in `auth_events` (`MSC4307`).
  - Because `check_foreign_room_citation` only runs inside `check_auth_chain` AND only when `event.room_id` is `Some(expected)`, any PDU validation pipeline that uses `validate_forward_extremity` (`src/auth/mod.rs:482`) or forgets to pass `Some(trusted_room_id)` to `ingest_events` (`src/basespec/rezzy_types.rs:1436`) is completely unprotected against cross-room `auth_events` citations and V12 fake-`room_id` injection.
- **`[High]` Finding F-06-02 — Room V12 Creator Immunity (`Rules 10.1–10.5`) & `content.creator` vs. `event.sender()` Check in Rule 10.4:**
  - Let's inspect [`src/auth/mod.rs:907-933`](../../../src/auth/mod.rs#L907-L933) (Rule 10.4 for V12+):
    ```rust
    if is_v12_plus {
        if let Some(create_event) = state.get_event(M_ROOM_CREATE, "") {
            let create_content = create_event.content();
            if let Some(creator) = create_content.get_creator() {
                if new_content.has_user_in_users(creator) {
                    return Err(AuthError::InvalidSyntax(...));
                }
            }
    ```
  - Now compare how `EventContent::get_creator()` is implemented on `Value` vs. custom `EventContent` implementations, and how [`src/auth/user.rs:38-41`](../../../src/auth/user.rs#L38-L41) checks V12 creator status:
    - In `src/auth/user.rs:40`: `let is_creator = create_event.sender() == sender || create_event.has_additional_creator(sender);`
    - In Matrix Room V11 and V12 (`MSC4289`), `m.room.create` **removed** the `content.creator` property; the primary room creator is defined exclusively as the `sender` of the `m.room.create` event (`create_event.sender()`), plus `content.additional_creators`!
    - If a V12 `m.room.create` event has no `"creator"` key in `content` (which is standard for V11/V12!), `create_content.get_creator()` returns `None`! Thus, in [`src/auth/mod.rs:911`](../../../src/auth/mod.rs#L911), `if let Some(creator) = create_content.get_creator()` is **`None`**, and a V12 `m.room.power_levels` event that lists `create_event.sender()` in `content.users` will **bypass Rule 10.4** unless `create_event.sender()` is checked directly!
    - **Remediation:** Line 911 of `src/auth/mod.rs` MUST check `create_event.sender()` (i.e. `let creator = create_event.sender(); if new_content.has_user_in_users(creator) { return Err(...); }`) in addition to `create_content.get_creator()`!

### 2.4 Performance & Adversarial Liveness (`critic-perf`)
- **Power-Level Map Validation Allocations (`[Low]` F-06-06):**
  - Commit `5384219` refactored `EventContent` (`src/basespec/rezzy_types.rs:2604-2638`) to expose zero-allocation visitor callbacks (`visit_event_power_levels`, `visit_user_power_levels`, `visit_notification_power_levels`). However, [`check_power_levels_rules`](../../../src/auth/mod.rs#L1075-L1140) still allocates 6 temporary `BTreeMap<&str, i64>` maps (`old_events`, `new_events`, `old_notifications`, `new_notifications`, `old_users`, `new_users`) on every `m.room.power_levels` validation. For a 10,000-entry `users` or `events` map during a state-resolution power phase, building two 10,000-node `BTreeMap`s per PL event adds avoidable allocator pressure when the underlying `crate::json::Object` is already a sorted `BTreeMap` that can be diffed via a two-pointer merge iterator in $O(N)$ with zero heap allocations.
- **255-Byte PDU Field Limits (`src/basespec/rezzy_types.rs:3273-3327`):**
  - Enforcing hard 255-byte limits on `event_id`, `sender`, `event_type`, and `state_key` for V11+ (`validate_field_lengths`) bounds per-key hashing and comparison cost on modern rooms.

### 2.5 Formal Verification & Mathematical Soundness (`critic-formal-crypto`)
- **Redaction Idempotence & Reference Hash Commutativity (`event_id(e) == event_id(redact(e))`):**
  - For Matrix room versions 3+, the reference hash (`event_id`) is defined as $\text{SHA-256}(\text{CanonicalJSON}(\text{Redact}(e)))$. Soundness requires that redaction is an **idempotent projection** ($\text{Redact}(\text{Redact}(e)) = \text{Redact}(e)$) and that the streaming writer `write_redacted_canonical` ([`src/basespec/rezzy_types.rs:1259-1338`](../../../src/basespec/rezzy_types.rs#L1259-L1338)) is bit-for-bit equivalent to materializing `redact_json(e, v)` followed by canonical serialization.
  - Track 06 carefully preserves this invariant, including synthesizing `"content":{}` in canonical key order when `content` is absent (lines 1287–1295, 1329–1335) and preserving `prev_state_events` for `MSC4242` (line 1308).
- **Canonical JSON Number Validation in `reference_hash` vs. `rezzy-json` (`[High]` F-06-03):**
  - Notice the doc comment on [`reference_hash` (`src/basespec/rezzy_types.rs:920-924`)](../../../src/basespec/rezzy_types.rs#L920-L924): *"Canonicalization is tolerant of out-of-range integers (like Synapse's `relaxed` mode): the JSON writer serializes whatever numbers are present rather than rejecting them."* Yet inside `write_redacted_canonical` (line 1278), `let strict_numbers = room_version_is_v6_or_later(room_version);` is passed to `write_json_value`, which calls `validate_canonical_number` (lines 1144–1161) and **rejects** numbers outside $\pm(2^{53}-1)$ for v6+! Thus, the doc comment on `reference_hash` is stale and contradicts its actual v6+ strict implementation, while in `rezzy-json` (audited in Row 9 of `rezzy_docs_public_safety_audit.md`) permissive canonical writers remain exposed.

### 2.6 Matrix Federation Interop (`critic-federation-interop`)
- **Legacy MXIDs (`MSC4303` Hotfix `85464d3`):**
  - Downgrading historical uppercase/Unicode MXID localparts in `validate_mxid` ([`src/basespec/rezzy_types.rs:3218-3244`](../../../src/basespec/rezzy_types.rs#L3218-L3244)) from a hard error to `Warning::CompatibilityMxid` via `is_acceptable_historical_mxid` (lines 3068–3074) prevented federation split-brains on long-lived V1–V12 rooms with legacy Matrix accounts, while still enforcing `@` prefix, `:` separator, non-empty domain, and no NUL bytes.
  - **Subtle Interop Edge Case in `check_auth` Rule 1.2 (`src/auth/mod.rs:603`):** While `LeanEvent::validate_syntactic` uses `is_acceptable_historical_mxid` (allowing historical uppercase MXIDs with a warning), [`check_auth_with_context` at `src/auth/mod.rs:603`](../../../src/auth/mod.rs#L603) still calls strict `if !is_valid_mxid(event.sender())` on `m.room.create`! If a legacy room's `m.room.create` event has a historical uppercase MXID `sender` (e.g. `@Alice:example.com`), `validate_syntactic` accepts it with `Warning::CompatibilityMxid`, **but `check_auth` hard-rejects the `m.room.create` event at line 603!**
- **ZIP-215 vs. Strict RFC 8032 Ed25519 Signature Verification:**
  - Because `rezzy` delegates Ed25519 verification via `EventVerifier` (`src/basespec/rezzy_types.rs:2645`), downstream homeservers must be warned in `EventVerifier`'s rustdoc that all federation peers in a room version must use identical Ed25519 validation semantics (e.g., not mixing ZIP-215 `ed25519-consensus` cofactor-accepting verifiers with strict RFC 8032 `ed25519-dalek` verifiers on malleable small-order points).

### 2.7 Adversarial Red-Team & Verification QA (`critic-redteam-qa`)
- **Red-Team Finding 1 — V12 Creator in `users` Map When `content.creator` is Omitted (`F-06-02`):**
  - In [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs), existing V12 Rule 10.4 tests populate `"creator"` or `"additional_creators"` in `m.room.create`. If a red-team test constructs a spec-compliant Room V12 `m.room.create` event with `sender: "@founder:example.com"` and `content: {"room_version": "12"}` (no `"creator"` key in `content`, as required by V11/V12!), and then submits an `m.room.power_levels` event containing `"users": {"@founder:example.com": 50}`, [`src/auth/mod.rs:911`](../../../src/auth/mod.rs#L911) (`if let Some(creator) = create_content.get_creator()`) fails to catch it!
- **Red-Team Finding 2 — Cross-Room Event Injection via `validate_forward_extremity` / `check_auth_with_context` (`F-06-01`):**
  - If a test calls `validate_forward_extremity` or `check_auth_with_context` (instead of `check_auth_chain`) with an event that has `room_id: Some("!roomA:example.org")` and cites an `auth_event` with `room_id: Some("!roomB:example.org")`, it passes because `check_foreign_room_citation` is only wired into `check_auth_chain` (`src/auth/mod.rs:2183`).
- **Red-Team Finding 3 — Historical MXID on `m.room.create` (`src/auth/mod.rs:603`):**
  - Add a regression test where `m.room.create` has `sender: "@Alice:example.com"` (uppercase localpart) to verify consistency between `validate_syntactic` (`is_acceptable_historical_mxid`) and `check_auth` Rule 1.2 (`src/auth/mod.rs:603`).

### 2.8 Homeserver Integrator & API Ergonomics (`critic-dx-integrator`)
- **Eliminating `room_id: Option<RoomId>` Fail-Open Defaults (`[Critical]` F-06-01):**
  - The current design where `LeanEvent.room_id` is `Option<RoomId>` and `ingest_events(pdus, room_version, room_id: Option<&str>)` takes an optional `room_id` violates the principle of *secure-by-default API design*. A homeserver always knows which room an ingest batch or auth check is executing for (or in V12, derives `!{create_event_hash}` from the room's accepted `m.room.create` event).
  - Making `room_id: &RoomId` mandatory on `ingest_events` and exposing `fn room_id(&self) -> Option<&str>` on `EventLike` so `check_auth_with_context` itself enforces Rule 1.2, V12 Rule 2, and `MSC4307` Rule 2.5 eliminates the fail-open trap entirely.
- **Clarifying Delegated Signature & PDU Checks in Rustdoc (`[High]` F-06-04):**
  - `EventVerifier` (`src/basespec/rezzy_types.rs:2645`) has default `Ok(())` implementations on all methods (`verify_event_id_hash`, `verify_signatures`, `verify_content_hash`, `verify_third_party_invite`, `verify_join_authorised_via_users_server`). Removing the default `Ok(())` bodies on `EventVerifier` so implementors must explicitly write `Ok(())` when opting out of a check prevents silent omission of Rule 5.2 (`verify_join_authorised_via_users_server`) or 3PI signature verification.

---

## 3. Actionable Recommendations for Stage B Remediation Tracks

1. **[Stage B — Track 13 / P0 Critical Auth Hardening] Make `MSC4307` Rule 2.5 and V12 Rule 2 Unconditionally Fail-Closed Across All Auth Entry Points:**
   - Require `room_id: &str` (not `Option<&str>`) in `ingest_events` ([`src/basespec/rezzy_types.rs:1433`](../../../src/basespec/rezzy_types.rs#L1433)), add `fn room_id(&self) -> Option<&str>` to `EventLike`, and move `check_create_room_id`, `check_room_id_matches_accepted_create`, and `check_foreign_room_citation` into `check_auth_with_context` so `validate_forward_extremity` and single-event auth checks cannot bypass `MSC4307`.
2. **[Stage B — Track 13 / P0 Critical V12 Rule 10.4 Fix] Check `create_event.sender()` in V12 Rule 10.4 (`src/auth/mod.rs:908-917`):**
   - In [`src/auth/mod.rs:908-917`](../../../src/auth/mod.rs#L908-L917), check `new_content.has_user_in_users(create_event.sender())` in addition to `create_content.get_creator()` so V12 `m.room.create` events that omit the deprecated `content.creator` field still forbid the room creator from appearing in `m.room.power_levels` `content.users`.
3. **[Stage B — Track 13 / P1 MXID & `EventVerifier` Consistency] Align `check_auth` Rule 1.2 with `is_acceptable_historical_mxid` and Remove Default `Ok(())` from `EventVerifier`:**
   - Update [`src/auth/mod.rs:603`](../../../src/auth/mod.rs#L603) and [`944`](../../../src/auth/mod.rs#L944) to use consistent MXID validation (`is_acceptable_historical_mxid` for V1–V12 historical events), require `hashes.sha256` on federation PDU ingest, and remove default `Ok(())` method bodies from `EventVerifier` (`src/basespec/rezzy_types.rs:2650`).
4. **[Stage B — Track 15 / P2 Documentation & Traceability Sync] Audit and Recalibrate `docs/spec_coverage.csv`:**
   - Update [`docs/spec_coverage.csv`](../../../docs/spec_coverage.csv) to distinguish `full (core CPU)` from `delegated (HS I/O / crypto)` on Row 23 (Restricted Join Rules Rule 5.2) and Row 31 (`MSC0501`), and reconcile the top-of-file V1 scope banner in `docs/spec_audit.md`.
