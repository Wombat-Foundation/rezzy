//! Room version property matrix.
//!
//! Each room version introduces or modifies specific behaviors. This module
//! should eventually encode these properties as a queryable table so the rest
//! of the crate can branch on version without hard-coded comparisons.
//!
//! Reference: <https://spec.matrix.org/latest/rooms/>

// TODO: Event ID format
//   - V1–V2: server-assigned (`$localpart:domain`)
//   - V3:    URL-safe base64 SHA-256 of canonical JSON (reference hash)
//   - V4+:   same as V3 but with `$` prefix only (no domain)

// TODO: Room ID format
//   - V1–V11: server-assigned (`!localpart:domain`)
//   - V12:    SHA-256 hash of the `m.room.create` event (content-derived)

// TODO: State resolution algorithm
//   - V1:  State Resolution v1
//   - V2+: State Resolution v2 (power events, mainline ordering, auth diff)

// TODO: Creator privileges
//   - V1–V11: creator is `sender` of `m.room.create` (or legacy `creator` field)
//   - V12:    creator has infinite power level (i64::MAX), cannot be demoted;
//             `additional_creators` array in `m.room.create` content is recognized

// TODO: Redaction algorithm
//   - V1–V10: original redaction rules
//   - V11:    clarified redaction algorithm
//   - V12:    `m.room.redaction` events are subject to auth rules via
//             `events` / `events_default` in `m.room.power_levels`

// TODO: Knocking
//   - V1–V6:  not supported
//   - V7+:    `knock` join rule supported

// TODO: Restricted join rules
//   - V1–V7:  not supported
//   - V8+:    `restricted` join rule (join via another room)
//   - V10+:   `knock_restricted` join rule

// TODO: Auth rules changes
//   - V6: updated authorization rules for events
//   - V12: `m.room.create` is no longer allowed/required in auth events (V2.1+ state res)

// TODO: Canonical JSON
//   - V1–V5:  lenient JSON parsing
//   - V6+:    strict canonical JSON required for hashing and signatures
