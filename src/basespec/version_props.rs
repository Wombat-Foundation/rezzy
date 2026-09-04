//! Room version property index.
//!
//! Each room version introduces or modifies specific behaviors. This used to
//! be a list of TODOs proposing a future queryable table -- it wasn't one:
//! every property below already has a single authoritative implementation
//! elsewhere in the crate, just not centralized under one name. Building a
//! second table here would risk exactly the drift bug a single source of
//! truth per capability is meant to prevent (two answers to "does v11 use
//! strict redaction rules," one here and one at the real call site, able to
//! disagree). So this module stays documentation-only: an index pointing at
//! where each property actually lives, kept accurate rather than aspirational.
//!
//! Reference: <https://spec.matrix.org/latest/rooms/>

// Event ID format
//   - V1-V2: server-assigned (`$localpart:domain`)
//   - V3:    URL-safe base64 SHA-256 of canonical JSON (reference hash)
//   - V4+:   same as V3 but with `$` prefix only (no domain)
// Authoritative: `RoomVersionFormat::uses_reference_hash_event_ids` (v1/v2
// vs. v3+) in `rezzy_types.rs`; the v3-vs-v4+ base64 padding/charset split
// is `reconcile::algebraic::EventIdFormat` (`Legacy`/`V3`/`V4Plus`).

// Room ID format
//   - V1-V11: server-assigned (`!localpart:domain`)
//   - V12:    derived from the `m.room.create` event's own event ID
// Authoritative: `RoomVersionFormat::uses_v12_create_rules` gates the
// derivation; `auth::check_create_room_id` (Rule 1.2) and
// `auth::check_room_id_matches_accepted_create` (Rule 2, V12+) enforce it.
// See `docs/spec_audit.md` rows 1.2 and "2 (V12)".

// State resolution algorithm
//   - V1:  State Resolution v1
//   - V2+: State Resolution v2 (power events, mainline ordering, auth diff)
// Authoritative: `StateResVersion::from_room_version` -- the crate's central
// version-to-algorithm mapping; everything in `resolve/` branches on its
// output, not on a raw version string/number.

// Creator privileges
//   - V1-V11: creator is `sender` of `m.room.create` (or legacy `creator` field)
//   - V12:    creator has infinite power level (i64::MAX), cannot be demoted;
//             `additional_creators` array in `m.room.create` content is recognized
// Authoritative: `RoomVersionFormat::uses_v12_create_rules`; the i64::MAX
// power-level override and `additional_creators` handling live in
// `auth::user` and the `StateResVersion::V2_1`-and-later branches of
// `check_auth_with_context`'s power-levels validation (auth/mod.rs).

// Redaction algorithm
//   - V1-V10: original redaction rules
//   - V11:    clarified redaction algorithm
//   - V12:    `m.room.redaction` events are subject to auth rules via
//             `events` / `events_default` in `m.room.power_levels`
// Authoritative: `RoomVersionFormat::uses_v11_redaction_rules`;
// `split_redaction_content`/`redaction_preserved_keys` in `rezzy_types.rs`
// apply the per-version key tables.

// Knocking
//   - V1-V6:  not supported
//   - V7+:    `knock` join rule supported
// Authoritative: `auth::check_knock_rules` and the `RULE_KNOCK` branch of
// join-rule validation in `check_auth_with_context`.

// Restricted join rules
//   - V1-V7:  not supported
//   - V8+:    `restricted` join rule (join via another room)
//   - V10+:   `knock_restricted` join rule
// Authoritative: `auth::room_version_at_least(state, 8 | 10)`, gating the
// `RULE_RESTRICTED`/`RULE_KNOCK_RESTRICTED` branches directly at their call
// sites in `check_auth_with_context` and `check_knock_rules`.

// Auth rules changes
//   - V6: updated authorization rules for events
//   - V12: `m.room.create` is no longer allowed/required in auth events (V2.1+ state res)
// Authoritative: `StateResVersion::from_room_version` for the V6 boundary
// (folded into the `V2` variant); the V12 auth_events change is
// `StateResVersion::V2_1`-and-later behavior in `resolve/`'s auth-diff and
// mainline construction.

// Canonical JSON
//   - V1-V5:  lenient JSON parsing
//   - V6+:    strict canonical JSON required for hashing and signatures
// Authoritative: `RoomVersionFormat::requires_strict_canonical_numbers`,
// enforced by `canonical_redacted_json`'s number-encoding path
// (`CanonicalizationError`) in `rezzy_types.rs`.
