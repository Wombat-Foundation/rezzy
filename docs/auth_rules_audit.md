# Auth Rules Audit — rezzy vs Matrix Spec

Cross-version compliance audit of rezzy's `check_auth` against the Matrix spec
authorization rules. Three distinct rule sets exist:

- **v1**: Room versions 1–2 (`v1-auth-rules.txt`)
- **v3**: Room versions 3–7 (`v3-auth-rules.txt`) — removes `m.room.aliases`, removes `m.room.redaction` auth rule
- **v8**: Room versions 8–11 (`v8-auth-rules.txt`) — adds knock, restricted joins, `join_authorised_via_users_server`
- **v12**: Room version 12 (`v12.txt`) — removes `m.room.create` from auth_events, adds creators, adds knock_restricted to knock rule, PL validation changes

## Auth Rule Compliance Matrix

| #          | Rule                                                                                 | Versions | rezzy | Notes                                                        |
| ---------- | ------------------------------------------------------------------------------------ | -------- | ----- | ------------------------------------------------------------ |
| 1          | **m.room.create**: reject if `prev_events` present                                   | all      | [x]   | `CreateWithPrevEvents`                                       |
| 1.2        | **m.room.create**: `room_id` domain must match `sender` domain                       | V1–V11   | [ ]   | Not checked — rezzy has no domain parsing                    |
| 1.2        | **m.room.create**: reject if event has `room_id` (V12: room_id is event_id with `!`) | V12      | [ ]   | Not checked                                                  |
| 1.3        | **m.room.create**: reject unrecognised `content.room_version`                        | all      | [ ]   | Not checked                                                  |
| 1.4        | **m.room.create**: reject if no `creator` property in content                        | V1–V11   | [ ]   | Not checked                                                  |
| 1.4        | **m.room.create**: reject invalid `additional_creators`                              | V12      | [ ]   | Not checked                                                  |
| 2.1        | **auth_events**: reject duplicate (type, state_key) pairs                            | all      | [ ]   | Not checked                                                  |
| 2.2        | **auth_events**: entries must match auth events selection algorithm                  | all      | [~]   | Soft-checked via `warn_unexpected_auth_events` (stderr only) |
| 2.3        | **auth_events**: reject if any auth event was itself rejected                        | all      | [ ]   | Requires rejected-event tracking                             |
| 2.4        | **auth_events**: reject if no `m.room.create` among entries                          | V1–V11   | [ ]   | Not checked                                                  |
| 2.5        | **auth_events**: reject if any auth event has wrong `room_id`                        | all      | [ ]   | Not checked                                                  |
| 2 (V12)    | Reject if `room_id` is not an accepted `m.room.create` event ID                      | V12      | [ ]   | Not checked                                                  |
| 3          | **m.federate**: reject cross-domain if `m.federate` is false                         | all      | [ ]   | Not checked — rezzy has no domain parsing                    |
| 4 (V1–V3)  | **m.room.aliases**: reject if no `state_key` or domain mismatch                      | V1–V7    | [ ]   | Removed in V8+; not implemented                              |
| —          | **m.room.member** rules (see below)                                                  | all      | [x]   | Detailed breakdown below                                     |
| 6          | Sender must be joined (non-member events)                                            | all      | [x]   | `NotMember` error                                            |
| 7          | **m.room.third_party_invite**: sender PL ≥ invite level                              | all      | [ ]   | Not checked                                                  |
| 8          | Event type required PL check                                                         | all      | [x]   | `get_required_power_level`                                   |
| 9          | **State key starts with `@`**: must match sender                                     | all      | [x]   | Added this session                                           |
| 10         | **m.room.power_levels** validation (see below)                                       | all      | [~]   | Partial — see breakdown                                      |
| 11 (V1–V2) | **m.room.redaction**: PL ≥ redact level, or same domain                              | V1–V2    | [ ]   | Not checked                                                  |
| 11         | Otherwise, allow                                                                     | V3+      | [x]   | Implicit                                                     |

## m.room.member Rules

| #     | Sub-rule                                                         | Versions | rezzy | Notes                                                 |
| ----- | ---------------------------------------------------------------- | -------- | ----- | ----------------------------------------------------- |
| 5.1   | Reject if no `state_key` or no `membership` in content           | all      | [ ]   | Not explicitly checked                                |
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

## m.room.power_levels Validation (Rule 10)

| #     | Sub-rule                                                      | Versions | rezzy | Notes       |
| ----- | ------------------------------------------------------------- | -------- | ----- | ----------- |
| 10.1  | Validate scalar PL properties are integers                    | V12      | [ ]   | Not checked |
| 10.2  | Validate `events`/`notifications` are objects with int values | V12      | [ ]   | Not checked |
| 10.3  | `users` must be object with valid user ID keys + int values   | all      | [ ]   | Not checked |
| 10.4  | Reject if `users` contains creator IDs                        | V12      | [ ]   | Not checked |
| 10.5  | Allow if no previous PL event                                 | all      | [ ]   | Not checked |
| 10.6  | Validate PL property changes don't exceed sender PL           | all      | [ ]   | Not checked |
| 10.7  | Validate `events`/`notifications` changes                     | V8+      | [ ]   | Not checked |
| 10.8  | Validate `events`/`notifications` additions                   | V8+      | [ ]   | Not checked |
| 10.9  | Validate `users` removals/changes                             | all      | [ ]   | Not checked |
| 10.10 | Validate `users` additions                                    | all      | [ ]   | Not checked |

## Key Gaps (Prioritized)

### Critical (affects authorization correctness)

1. ~~**Rule 5.8**: Unknown membership should reject, not allow~~ — FIXED
2. ~~**Rule 5.4.1**: Third-party invite validation not implemented~~ — FIXED
3. ~~**Rule 7**: `m.room.third_party_invite` PL check missing~~ — FIXED
4. **Rule 10.x**: Power level event validation entirely missing

### Medium (federation/integrity concerns, not core auth)

5. **Rule 2.x**: auth_events validation (duplicates, wrong types, wrong room_id)
6. **Rule 3**: `m.federate` enforcement
7. **Rule 1.2–1.4**: m.room.create content validation
8. **Rule 5.1**: Missing state_key/membership presence check

### Low (version-specific, rarely triggered)

9. **Rule 4 (V1–V7)**: `m.room.aliases` validation (deprecated)
10. **Rule 11 (V1–V2)**: `m.room.redaction` auth rule (obsolete)

## Notes

- **Domain parsing**: Multiple rules require extracting the domain from user/room IDs.
  rezzy currently has no domain parsing utility. Adding one would unblock rules 1.2, 3, and 4.
- **Signature verification**: Rule 5.2 (`join_authorised_via_users_server` signature check)
  is a homeserver networking concern, not a state resolution concern. Correctly excluded.
- **Rejected event tracking**: Rule 2.3 requires knowing which events were previously
  rejected. This is homeserver state, not available to rezzy.
