# Auth Rules Audit — rezzy vs Matrix Spec

> **Implementation scope:** Rezzy currently supports state-resolution V1 only.
> The later Matrix room-version rows below document the specification and
> ongoing design/test coverage; they do not mean that V2, V2.1, V2.2, or V3
> state resolution is currently shipped or supported.

Cross-version compliance audit of rezzy's `check_auth` against the Matrix spec
authorization rules. Three distinct rule sets exist:

- **v1**: Room versions 1–2 (`v1-auth-rules.txt`)
- **v3**: Room versions 3–5 (`v3-auth-rules.txt`) — removes `m.room.redaction`
  auth rule; `m.room.aliases` (Rule 4) still applies
- **v6**: Room versions 6–7 (`v3-auth-rules.txt`, unchanged otherwise) — removes
  `m.room.aliases` (Rule 4)
- **v8**: Room versions 8–11 (`v8-auth-rules.txt`) — adds knock, restricted
  joins, `join_authorised_via_users_server`
- **v12**: Room version 12 (`v12.txt`) — removes `m.room.create` from
  auth_events, adds creators, adds knock_restricted to knock rule, PL validation
  changes

## Auth Rule Compliance Matrix

<!-- markdownlint-disable MD013 -->

| #          | Rule                                                                                                  | Versions | rezzy | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ---------- | ----------------------------------------------------------------------------------------------------- | -------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1          | **m.room.create**: reject if `prev_events` present                                                    | all      | [x]   | `CreateWithPrevEvents`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| 1.2        | **m.room.create**: `sender` MXID domain validity                                                      | V1–V11   | [x]   | `is_acceptable_historical_mxid` validates sender MXID syntax/domain per MSC4303 historical user ID rules; `domain_matches` handles domain comparisons                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 1.2        | **m.room.create**: reject if event has `room_id` (V12: room_id is event_id with `!`)                  | V12      | [x]   | `check_create_room_id`: generic over `EventLike::room_id` and enforced in `check_auth`, `check_auth_with_context`, `validate_forward_extremity`, and `check_auth_chain`. Unconditional rejection when a V12+ `m.room.create` carries a `room_id`, since a V12+ create event's room ID is derived from its own event ID and cannot be declared on the create PDU itself.                                                                                                                                                                                                                |
| 1.3        | **m.room.create**: reject unrecognised `content.room_version`                                         | all      | [x]   | `validate_syntactic`, via `StateResVersion::from_room_version`; absent value defaults to v1 per spec                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 1.4        | **m.room.create**: reject if no `creator` property in content                                         | V1–V11   | [x]   | `validate_syntactic`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 1.4        | **m.room.create**: reject invalid `additional_creators`                                               | V12      | [x]   | `validate_syntactic` via `additional_creators_are_valid` / `is_valid_mxid`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 2.1        | **auth_events**: reject duplicate (type, state_key) pairs                                             | all      | [x]   | Checked via `auth_context` in `check_auth`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 2.2        | **auth_events**: entries must match auth events selection algorithm                                   | all      | [x]   | `required_auth_types_for` re-derives the version-aware selection-algorithm set (create/sender-member/PL/target-member/join_rules/3pid) and `check_auth_with_context` hard-rejects (`AuthError::IncompleteAuthEvents`) any omitted citation whose type/state_key already exists in the room's current state; required-but-absent-from-state entries (e.g. no PL event set yet) are correctly not demanded                                                                                                                                                                               |
| 2.3        | **auth_events**: reject if any auth event was itself rejected                                         | all      | [x]   | Tracked at DAG level in `check_auth_chain` and via `auth_context`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 2.4        | **auth_events**: reject if no `m.room.create` among entries                                           | V1–V11   | [x]   | Hard-failed via `auth_context` in `check_auth`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| 2.5        | **auth_events**: reject if any auth event has wrong `room_id` ([MSC4307], unconditional per its text) | all      | [x]   | `check_foreign_room_citation`: generic over `EventLike::room_id` and enforced across `check_auth`, `check_auth_with_context`, `validate_forward_extremity`, and `check_auth_chain`. Fails closed (`AuthError::ForeignRoomEvent`) whenever either the citing event or any cited auth event carries a `room_id` that is missing or mismatched on the counterpart.                                                                                                                                                                                                                            |
| 2 (V12)    | Reject if `room_id` is not an accepted `m.room.create` event ID                                       | V12      | [x]   | `check_room_id_matches_accepted_create`: generic over `EventLike::room_id` and enforced in `check_auth`, `check_auth_with_context`, `validate_forward_extremity`, and `check_auth_chain`. Compares an event's declared `room_id` (`!`-prefixed) against the accepted `m.room.create` event's ID (`$`-prefixed) under V12+.                                                                                                                                                                                                                                                              |
| 3          | **m.federate**: reject cross-domain if `m.federate` is false                                          | all      | [x]   | Checked via `domain_matches` and `get_m_federate` against `m.room.create` sender                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 4 (V1–V5)  | **m.room.aliases**: reject if no `state_key` or domain mismatch                                       | V1–V5    | [x]   | Checked via `domain_matches` in `check_auth` for V1–V5                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| —          | **m.room.member** rules (see below)                                                                   | all      | [x]   | Detailed breakdown below                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| 6          | Sender must be joined (non-member events)                                                             | all      | [x]   | `NotMember` error                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 7          | **m.room.third_party_invite**: sender PL ≥ invite level                                               | all      | [x]   | `get_required_power_level` returns invite level                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 8          | Event type required PL check                                                                          | all      | [x]   | `get_required_power_level`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 9          | **State key starts with `@`**: must match sender                                                      | all      | [x]   | Implemented via exact match check                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 10         | **m.room.power_levels** validation (see below)                                                        | all      | [x]   | Completed coverage                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| 11 (V1–V2) | **m.room.redaction**: PL ≥ redact level, or same domain                                               | V1–V2    | [x]   | Checked via `get_redact_power_level`/`domain_matches` in `check_auth`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 11         | Otherwise, allow                                                                                      | V3+      | [x]   | Implicit                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |

<!-- markdownlint-enable MD013 -->

## m.room.member Rules

<!-- markdownlint-disable MD013 -->

| #     | Sub-rule                                                         | Versions | rezzy | Notes                                                 |
| ----- | ---------------------------------------------------------------- | -------- | ----- | ----------------------------------------------------- |
| 5.1   | Reject if no `state_key` or no `membership` in content           | all      | [x]   | `InvalidSyntax`                                       |
| 5.2   | `join_authorised_via_users_server` signature check               | V8+      | [o]   | Signature validation is HS-side, not rezzy            |
| 5.3.1 | **join**: creator can always join (first event is create)        | all      | [x]   | `is_creator` check                                    |
| 5.3.2 | **join**: sender must match state_key                            | all      | [x]   | `InvalidStateKey`                                     |
| 5.3.3 | **join**: reject if sender banned                                | all      | [x]   | `BannedUser`                                          |
| 5.3.4 | **join (invite)**: allow if membership is invite or join         | V1–V7    | [x]   | `RULE_INVITE` path                                    |
| 5.3.4 | **join (invite/knock)**: allow if invite or join                 | V8+      | [x]   | `RULE_INVITE \|\| RULE_KNOCK`                         |
| 5.3.5 | **join (restricted)**: allow if invite/join, or valid authoriser | V8+      | [x]   | `check_authorising_user`                              |
| 5.3.5 | **join (knock_restricted)**: same as restricted                  | V10+     | [x]   | `RULE_KNOCK_RESTRICTED`                               |
| 5.3.6 | **join (public)**: allow                                         | all      | [x]   | `RULE_PUBLIC` path                                    |
| 5.3.7 | **join**: otherwise reject                                       | all      | [x]   | `NotMember`                                           |
| 5.4.1 | **invite (3pi)**: full third-party invite validation             | all      | [x]   | `check_invite_rules` 3PI token validation             |
| 5.4.2 | **invite**: sender must be joined                                | all      | [x]   | Checked in rule 6                                     |
| 5.4.3 | **invite**: reject if target is joined or banned                 | all      | [x]   | Added this session                                    |
| 5.4.4 | **invite**: sender PL ≥ invite level                             | all      | [x]   | `InsufficientPowerLevel`                              |
| 5.5.1 | **leave (self)**: allow if invite, join, or knock                | all      | [x]   | `check_leave_rules`                                   |
| 5.5.2 | **leave**: sender must be joined                                 | all      | [x]   | Checked in rule 6                                     |
| 5.5.3 | **leave**: can't unban without ban PL                            | all      | [x]   | `check_leave_rules`                                   |
| 5.5.4 | **leave (kick)**: sender PL ≥ kick level, > target PL            | all      | [x]   | `check_membership_pl_hierarchies`                     |
| 5.6.1 | **ban**: sender must be joined                                   | all      | [x]   | Checked in rule 6                                     |
| 5.6.2 | **ban**: sender PL ≥ ban level, > target PL                      | all      | [x]   | `check_ban_rules` + `check_membership_pl_hierarchies` |
| 5.7.1 | **knock**: join_rule must be `knock`                             | V7       | [x]   | `check_knock_rules`                                   |
| 5.7.1 | **knock**: join_rule must be `knock` or `knock_restricted`       | V10+     | [x]   | `check_knock_rules`                                   |
| 5.7.2 | **knock**: sender must match state_key                           | V7+      | [x]   | `InvalidStateKey`                                     |
| 5.7.3 | **knock**: allow if NOT ban/invite/join                          | V7+      | [x]   | `check_knock_rules`                                   |
| 5.8   | Unknown membership: reject                                       | all      | [x]   | `InvalidSyntax` — was `_ => {}`, now rejects          |

<!-- markdownlint-enable MD013 -->

## m.room.power_levels Validation (Rule 10)

<!-- markdownlint-disable MD013 -->

| #     | Sub-rule                                                      | Versions | rezzy | Notes                                                |
| ----- | ------------------------------------------------------------- | -------- | ----- | ---------------------------------------------------- |
| 10.1  | Validate scalar PL properties are integers                    | V10+     | [x]   | `find_non_integer_scalar_pl` on EventContent         |
| 10.2  | Validate `events`/`notifications` are objects with int values | V10+     | [x]   | `find_non_integer_map_pl` on EventContent            |
| 10.3  | `users` must be object with valid user ID keys + int values   | all      | [x]   | `check_power_levels_rules` validates `@` + `:`       |
| 10.4  | Reject if `users` contains creator IDs                        | V12+     | [x]   | `has_user_in_users` (resolves V12 creator via `create_event.sender()` when `content.creator` is absent; default trait implementation delegates to `visit_user_keys`) + `has_additional_creator` check |
| 10.5  | Allow if no previous PL event                                 | all      | [x]   | `is_first_pl` skip logic                             |
| 10.6  | Validate PL property changes don't exceed sender PL           | all      | [x]   | `check_scalar_pl` helper — old/new > sender rejected |
| 10.7  | Validate `events`/`notifications` changes                     | all      | [x]   | Events map diff — old value > sender PL rejected     |
| 10.8  | Validate `events`/`notifications` additions                   | all      | [x]   | Events map diff — new value > sender PL rejected     |
| 10.9  | Validate `users` removals/changes                             | all      | [x]   | Users map diff — old value >= sender PL rejected     |
| 10.10 | Validate `users` additions                                    | all      | [x]   | Users map diff — new value > sender PL rejected      |

<!-- markdownlint-enable MD013 -->

## Redaction Algorithm (`redaction_preserved_keys`)

<!-- markdownlint-disable MD013 -->

| Event type                  | Versions | rezzy | Notes                                                                                                                 |
| --------------------------- | -------- | ----- | --------------------------------------------------------------------------------------------------------------------- |
| `m.room.create`             | all      | [x]   | v11+: all content keys preserved; v1–v10: preserves `creator`                                                         |
| `m.room.member`             | all      | [x]   | v11+ adds `third_party_invite.signed`; v9+ adds `join_authorised_via_users_server`; v1–v8 preserves `membership` only |
| `m.room.power_levels`       | all      | [x]   | v11+ adds `invite` to preserved keys                                                                                  |
| `m.room.join_rules`         | all      | [x]   | v9+ adds `allow`                                                                                                      |
| `m.room.history_visibility` | all      | [x]   | preserves `history_visibility`                                                                                        |
| `m.room.aliases`            | V1–V5    | [x]   | preserves `aliases`; removed entirely v6+ (`RedactionRule::None`)                                                     |
| `m.room.redaction`          | V11+     | [x]   | preserves `redacts` (moved into `content` in v11); none pre-v11                                                       |
| Unrecognized `room_version` | —        | [x]   | Fails closed: `RedactionRule::None` rather than guessing a fallback rule set                                          |

<!-- markdownlint-enable MD013 -->

## PDU Syntactic Invariants (`validate_syntactic`)

<!-- markdownlint-disable MD013 -->

| Check                                                             | Versions | rezzy | Notes                                                                                   |
| ----------------------------------------------------------------- | -------- | ----- | --------------------------------------------------------------------------------------- |
| `event_id` must be `$`-prefixed                                   | all      | [x]   | `InvalidSyntax`                                                                         |
| `sender` MXID localpart charset                                   | all      | [~]   | Warn only for historical (uppercase/Unicode) IDs; hard-fail only on structural breakage |
| `depth` bounds (`MAX_SAFE_JSON_INTEGER`)                          | all      | [x]   | 2^53−1 accepted as valid ceiling                                                        |
| 255-byte hard limit: `event_id`/`sender`/`event_type`/`state_key` | V11+     | [x]   | Synapse parity (`strict_event_byte_limits_room_versions`)                               |
| 255-byte limit pre-v11                                            | V1–V10   | [~]   | Warn only (`eprintln!`, `std` feature only), never hard-fails                           |
| Reject unrecognised `content.room_version` (m.room.create only)   | all      | [x]   | Fixed — see audit rule 1.3 above                                                        |

<!-- markdownlint-enable MD013 -->

## Key Gaps (Prioritized)

### Critical (affects authorization correctness)

1. ~~**Rule 5.8**: Unknown membership should reject, not allow~~ — FIXED
2. ~~**Rule 5.4.1**: Third-party invite validation not implemented~~ — FIXED
3. ~~**Rule 7**: `m.room.third_party_invite` PL check missing~~ — FIXED
4. ~~**Rule 10.x**: Power level event validation mostly missing (10.1–10.4,
   10.6–10.10)~~ — ALL FIXED

### Medium (federation/integrity concerns, not core auth)

1. ~~**Rule 1.2 / 3 / 4**: no domain-parsing utility, so room_id↔sender domain
   match, `m.federate`, and `m.room.aliases` domain checks are unimplemented~~ —
   FIXED
2. ~~**Rule 1.3**: unrecognised `content.room_version` not rejected~~ — FIXED
3. ~~**Rule 1.4**: missing `creator` / invalid `additional_creators` on
   `m.room.create` not checked~~ — FIXED
4. ~~**Rule 2.1 / 2.3 / 2.4**: `auth_events` duplicate-pair, rejected-ancestor,
   and missing-`m.room.create` checks~~ — ALL FIXED
5. ~~**Rule 5.1**: Missing state_key/membership presence check~~ — FIXED

### Low (version-specific, rarely triggered)

1. ~~**Rule 4 (V1–V5)** and **Rule 11 (V1–V2)**: `m.room.aliases` validation and
   the `m.room.redaction` auth rule~~ — FIXED / obsolete rule sets handled.

## Notes

- **Domain parsing**: Utilities `extract_domain` and `domain_matches` handle
  domain comparison for `m.federate` (Rule 3) and `m.room.aliases` (Rule 4).
- **Signature verification**: Rule 5.2 (`join_authorised_via_users_server`
  signature check) is a homeserver networking/key-fetching concern delegated to
  the caller via `EventVerifier`. `validate_forward_extremity` invokes the
  caller-supplied `EventVerifier` on both the initial `auth_events` pass and
  the post-state-resolution `check_auth` pass so custom verifiers cannot be
  bypassed on state-resolved re-verification.
- **room_id checks**: `EventLike::room_id(&self) -> Option<&str>` (and
  `RawEvent::raw_room_id`) exposes `room_id` across `LeanEvent`, `LeanEventRef`,
  and `ParsedEvent`. `check_create_room_id` (Rule 1.2 V12+),
  `check_room_id_matches_accepted_create` (V12 Rule 2), and
  `check_foreign_room_citation` ([MSC4307] Rule 2.5) run in
  `check_auth_with_context` (and therefore across `check_auth`,
  `validate_forward_extremity`, and `check_auth_chain`). Rule 2.5 fails closed
  (`AuthError::ForeignRoomEvent`) whenever either the citing event or any cited
  auth event carries a `room_id` that does not match its counterpart (including
  one-sided `(Some, None)` or `(None, Some)` pairings). `LeanEvent.room_id` is
  stamped from trusted caller/ingest context rather than trusting an
  unverified self-reported wire field on `m.room.create`.
