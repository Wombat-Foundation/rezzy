// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Core data types for Matrix state resolution.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::cmp::Ordering;
use serde::Deserialize;
use serde_json::Value;

use crate::basespec::event_types::{MAX_POWER_LEVEL_JSON, MAX_SAFE_JSON_INTEGER, M_ROOM_REDACTION};

/// Trait alias for types that can serve as event identifiers.
///
/// Any type that is `Clone + Eq + Hash + Ord + Debug + Display` automatically
/// implements this trait via a blanket impl. In practice, this is either
/// `String` (for human-readable event IDs like `$abc123:example.com`) or
/// `u32`/`u64` (for integer-interned short IDs used by homeservers).
///
/// # `Display` contract
///
/// The [`Display`](core::fmt::Display) implementation **must** output the
/// canonical wire-format representation of the event ID. This is relied upon
/// by `LtHash::seed()` in [`crate::state::lthash`] for
/// content-addressed state hashing — if two implementations produce different
/// `Display` output for the same logical event ID, state hashes will diverge
/// across homeservers.
pub trait EventId:
    Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug + core::fmt::Display
{
}
impl<T: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug + core::fmt::Display> EventId for T {}

/// Trait alias for types that can serve as the "key" half of a Matrix state
/// tuple `(event_type, state_key)`.
///
/// Any type that is `Clone + Eq + Hash + Ord + AsRef<str>` automatically
/// implements this trait via a blanket impl. In practice, this is `String`
/// (the default everywhere in this crate), but it can be substituted with a
/// lighter interned/`Arc<str>`-style key by downstream homeservers -- including
/// a *borrowing* key tied to a `&'a` interner arena, which is why this trait
/// no longer requires `Default` or `'static`: neither can be produced from
/// nothing by a key that borrows from an arena the caller owns. Callers that
/// need "the empty state key" (e.g. to look up `m.room.create`) now pass one
/// explicitly (see `empty_key` parameters on the resolution entry points)
/// instead of relying on `K::default()`.
///
/// **Contract:**
/// - Any implementor's `Ord` ordering **must** match the lexicographic byte ordering of
///   its `AsRef<str>` representation. This contract is required for `Borrow`-based
///   `BTreeMap` lookups to function correctly.
pub trait StateKey: Clone + Eq + core::hash::Hash + Ord + AsRef<str> {}
impl<T: Clone + Eq + core::hash::Hash + Ord + AsRef<str>> StateKey for T {}

/// Selects which state resolution algorithm to use.
///
/// Only [`V1`](Self::V1), [`V2`](Self::V2), and [`V2_1`](Self::V2_1) correspond
/// to actual Matrix spec / MSC content. [`V2_1_1`](Self::V2_1_1) and
/// [`V2_2`](Self::V2_2) are rezzy-internal designations for hardening beyond
/// what MSC4297 itself specifies -- MSC4297's text covers only two changes
/// (starting iterative auth checks from an empty state map, and widening the
/// full conflicted set to include the conflicted-state subgraph) and
/// explicitly does not touch the iterative auth checks or event sorting
/// themselves; it says nothing about CDO, power-phase local-auth fallback
/// gating, or ban-evasion screening. Those are rezzy's own choices, encoded
/// as separate variants specifically because they are *not* uniformly part
/// of stock V2.1:
///
/// | Variant | Room Versions | Key Change |
/// |---------|:---:|---|
/// | [`V1`](Self::V1) | 1 | Depth-based topological sort, all `m.room.member` events are power events. |
/// | [`V2`](Self::V2) | 2–11 | Reverse topological power ordering via Kahn's algorithm, mainline sort. |
/// | [`V2_1`](Self::V2_1) | 12+ ([MSC4297]) | Empty initial state for iterative auth checks; full conflicted set widened to include the conflicted state subgraph. |
/// | [`V2_1_1`](Self::V2_1_1) | — (rezzy-internal) | Ban evasion fix: resolved-state screening pass + power-phase local-auth gating, beyond what V2.1/MSC4297 itself specifies. |
/// | [`V2_2`](Self::V2_2) | — (rezzy-internal) | Reserved for State DAGs ([MSC4242]). |
///
/// [MSC4297]: https://github.com/matrix-org/matrix-spec-proposals/pull/4297
/// [MSC4242]: https://github.com/matrix-org/matrix-spec-proposals/pull/4242
///
/// ## Redaction preserved keys
///
/// The spec defines which content keys survive redaction per event type,
/// evolving across room versions:
///
/// | Fragment | Room Versions | Delta from previous |
/// |----------|:---:|---|
/// | `v1-redactions.txt` | 1–5 | Baseline. PL: `ban`, `events`, `events_default`, `kick`, `redact`, `state_default`, `users`, `users_default`. Member: `membership`. |
/// | `v6-redactions.txt` | 6–8 | Removes `m.room.aliases`. |
/// | `v9-redactions.txt` | 9–10 | Member: adds `join_authorised_via_users_server`. Join rules: adds `allow`. |
/// | `v11-redactions.txt` | 11+ | PL: adds `invite`. Create: allows ALL keys. Member: adds `third_party_invite.signed`. Drops top-level `prev_state`, `origin`, `membership`. Adds `m.room.redaction` preserving `redacts`. |
///
/// **Key invariant:** `users` in `m.room.power_levels` is preserved on redaction
/// in ALL versions. Redaction alone cannot cause the PL wipeout vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[allow(non_camel_case_types)]
pub enum StateResVersion {
    /// State Resolution V1 (room version 1).
    V1,
    /// State Resolution V2 (room versions 2–11).
    V2,
    /// State Resolution V2.1 — [MSC4297](https://github.com/matrix-org/matrix-spec-proposals/pull/4297) (room version 12+).
    V2_1,
    /// State Resolution V2.1.1 — experimental algo (restricts power-phase supplementation).
    V2_1_1,
    /// State Resolution V2.2 — reserved for State DAGs ([MSC4242](https://github.com/matrix-org/matrix-spec-proposals/pull/4242)).
    V2_2,
}

impl StateResVersion {
    /// Map a Matrix room version string (e.g. `"10"`, `"12"`) to the corresponding
    /// state resolution algorithm version.
    ///
    /// Returns `None` for unrecognized room versions.
    #[must_use]
    pub fn from_room_version(ver: &str) -> Option<Self> {
        match ver {
            "1" => Some(Self::V1),
            "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10" | "11" => Some(Self::V2),
            "12" => Some(Self::V2_1),
            "12.1" => Some(Self::V2_1_1),
            "org.matrix.msc4242.12" => Some(Self::V2_2),
            _ => None,
        }
    }

    /// Returns `true` for V2.1 and above (MSC4297+).
    ///
    /// Use this instead of manually matching `V2_1 | V2_1_1 | V2_2`. This is
    /// for MSC4297-scoped behavior (empty initial state, ban/kick
    /// supplementation direction, rule 2.4's create-citation exemption,
    /// v12+ create/`auth_events` rules, ...) that genuinely applies starting
    /// at stock V2.1. For rezzy-internal hardening that V2.1 predates, use
    /// [`Self::has_ban_evasion_hardening`] instead -- conflating the two is
    /// exactly the bug class this distinction exists to prevent (see
    /// `docs/tech_debt.md` / the `state/at.rs` and `resolve/iterative.rs`
    /// commits that fixed a silent merge widening the latter to match the
    /// former).
    #[must_use]
    pub const fn is_v2_1_plus(&self) -> bool {
        matches!(self, Self::V2_1 | Self::V2_1_1 | Self::V2_2)
    }

    /// Returns `true` for V2.1.1 and above.
    ///
    /// This is **not** an MSC4297 requirement -- "V2.1.1" is a rezzy-internal
    /// designation (it appears nowhere in the Matrix spec) for hardening
    /// beyond what stock V2.1 does: dropping non-power conflicted events
    /// whose sender is already banned/under-powered in the resolved state
    /// before mainline sort (the sound replacement for the retired CDO
    /// pre-filter, which itself was gated `== V2_1_1` strictly, never
    /// `V2_1`), and narrowing `OverlayState::get_event`'s power-phase
    /// local-auth fallback. `V2_1` and `V2_1_1` are separate enum variants
    /// specifically because `V2_1_1` does this and `V2_1` doesn't -- every
    /// call site gating this behavior must go through this one function
    /// (not its own `matches!`/`is_v2_1_plus` copy) so there is exactly one
    /// place a future merge (or anyone) can get this polarity wrong, and one
    /// place a test pins it. See `has_ban_evasion_hardening_table` below.
    #[must_use]
    pub const fn has_ban_evasion_hardening(&self) -> bool {
        matches!(self, Self::V2_1_1 | Self::V2_2)
    }

    /// Returns `true` for room versions that support the
    /// `join_authorised_via_users_server` restricted-join field (MSC3089, room
    /// version 8+).
    ///
    /// The enum collapses room versions 2–11 into [`Self::V2`], so "v8+"
    /// cannot be expressed precisely here: this returns `true` for every `V2`
    /// and above. That is safe in practice because pre-v8 members of `V2`
    /// never carry the field (it did not exist before v8), so the field's
    /// presence is an additional guard on top of this predicate.
    #[must_use]
    pub const fn has_join_authorised_via_users_server(&self) -> bool {
        !matches!(self, Self::V1)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod state_res_version_gate_tests {
    use super::StateResVersion;

    /// Pins the gate-polarity table for every `StateResVersion` variant, for
    /// both `is_v2_1_plus` (real MSC4297 scope) and
    /// `has_ban_evasion_hardening` (rezzy-internal scope). This is the
    /// safeguard `docs/tech_debt.md` calls for: a silent 3-way merge that
    /// widens/narrows either gate's scope (no conflict marker raised,
    /// because the changed side hadn't touched those exact lines) fails this
    /// test immediately, whether or not the change is otherwise observable
    /// in any behavioral test's output -- which a purely optimization-scoped
    /// gate (like `has_ban_evasion_hardening`'s use in the resolved-state
    /// screening pass) never is.
    #[test]
    fn test_gate_polarity_table() {
        let table = [
            // (version, is_v2_1_plus, has_ban_evasion_hardening,
            //  has_join_authorised_via_users_server)
            (StateResVersion::V1, false, false, false),
            (StateResVersion::V2, false, false, true),
            (StateResVersion::V2_1, true, false, true),
            (StateResVersion::V2_1_1, true, true, true),
            (StateResVersion::V2_2, true, true, true),
        ];
        for (version, expect_v2_1_plus, expect_ban_evasion, expect_join_authorised) in table {
            assert_eq!(
                version.is_v2_1_plus(),
                expect_v2_1_plus,
                "{version:?}.is_v2_1_plus() polarity changed"
            );
            assert_eq!(
                version.has_ban_evasion_hardening(),
                expect_ban_evasion,
                "{version:?}.has_ban_evasion_hardening() polarity changed"
            );
            assert_eq!(
                version.has_join_authorised_via_users_server(),
                expect_join_authorised,
                "{version:?}.has_join_authorised_via_users_server() polarity changed"
            );
        }
    }
}

/// The set of `content` keys preserved for an event type upon redaction.
///
/// A flat key list cannot distinguish "preserve everything" from "preserve
/// nothing" (both would otherwise be represented as an empty slice), so this
/// is an explicit tri-state. Keys may use a dotted path (e.g.
/// `"third_party_invite.signed"`) to denote a nested field that survives
/// redaction even though its parent object does not survive verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionRule {
    /// No keys in `content` survive redaction.
    None,
    /// All of `content` survives redaction untouched (e.g. `m.room.create` in v11+).
    All,
    /// Only the listed keys (or dotted nested paths) survive redaction.
    Keys(&'static [&'static str]),
}

/// Returns the redaction rule for an event type according to the specified
/// Matrix room version (v1 through v12; v12 inherits v11's rules).
/// Unknown/malformed versions fail closed.
#[must_use]
pub fn redaction_preserved_keys(event_type: &str, room_version: &str) -> RedactionRule {
    // Explicitly recognized room versions only: an unsupported or malformed
    // version ID must NOT silently fall back to v1 rules. Failing closed
    // (preserving nothing) is safer than guessing a permissive rule set.
    let ver_num: u32 = match room_version {
        "1" => 1,
        "2" => 2,
        "3" => 3,
        "4" => 4,
        "5" => 5,
        "6" => 6,
        "7" => 7,
        "8" => 8,
        "9" => 9,
        "10" => 10,
        // v12 inherits v11's redaction rules verbatim (v12.txt includes the
        // v11-redactions spec fragment rather than defining its own).
        "11" | "12" | "12.1" | "org.matrix.msc4242.12" => 11,
        _ => return RedactionRule::None,
    };
    match event_type {
        crate::basespec::event_types::M_ROOM_CREATE => {
            if ver_num >= 11 {
                RedactionRule::All
            } else {
                RedactionRule::Keys(&["creator"])
            }
        }
        crate::basespec::event_types::M_ROOM_MEMBER => {
            if ver_num >= 11 {
                RedactionRule::Keys(&[
                    "membership",
                    "join_authorised_via_users_server",
                    "third_party_invite.signed",
                ])
            } else if ver_num >= 9 {
                RedactionRule::Keys(&["membership", "join_authorised_via_users_server"])
            } else {
                RedactionRule::Keys(&["membership"])
            }
        }
        crate::basespec::event_types::M_ROOM_POWER_LEVELS => {
            if ver_num >= 11 {
                RedactionRule::Keys(&[
                    "ban",
                    "events",
                    "events_default",
                    "invite",
                    "kick",
                    "redact",
                    "state_default",
                    "users",
                    "users_default",
                ])
            } else {
                RedactionRule::Keys(&[
                    "ban",
                    "events",
                    "events_default",
                    "kick",
                    "redact",
                    "state_default",
                    "users",
                    "users_default",
                ])
            }
        }
        crate::basespec::event_types::M_ROOM_JOIN_RULES => {
            if ver_num >= 9 {
                RedactionRule::Keys(&["join_rule", "allow"])
            } else {
                RedactionRule::Keys(&["join_rule"])
            }
        }
        crate::basespec::event_types::M_ROOM_HISTORY_VISIBILITY => {
            RedactionRule::Keys(&["history_visibility"])
        }
        crate::basespec::event_types::M_ROOM_ALIASES => {
            if ver_num <= 5 {
                RedactionRule::Keys(&["aliases"])
            } else {
                RedactionRule::None // removed starting with v6-redactions.txt
            }
        }
        crate::basespec::event_types::M_ROOM_REDACTION => {
            if ver_num >= 11 {
                RedactionRule::Keys(&["redacts"]) // `redacts` only moved into `content` in v11+
            } else {
                RedactionRule::None
            }
        }
        _ => RedactionRule::None,
    }
}

/// Splits `content` into MSC4511's `redacted_content` (the fields this room
/// version's redaction algorithm preserves) and `redactable_content` (every
/// remaining field, i.e. what redaction strips), for the given event type and
/// room version. `redacted_content` is exactly the output of the internal
/// `redact_content` helper;
/// `redactable_content` is the complement needed to recover `content` from the
/// two pieces.
#[must_use]
pub fn split_redaction_content(
    content: &Value,
    event_type: &str,
    room_version: &str,
) -> (Value, Value) {
    let rule = redaction_preserved_keys(event_type, room_version);
    let redacted = redact_content(content, rule);
    let redactable = redactable_content_remainder(content, &redacted);
    (redacted, redactable)
}

/// Returns the content present in `content` but not preserved in `redacted`,
/// recursing one level for the `third_party_invite`-shaped nested-path case.
fn redactable_content_remainder(content: &Value, redacted: &Value) -> Value {
    let Value::Object(content_obj) = content else {
        return Value::Object(serde_json::Map::default());
    };
    let empty = serde_json::Map::default();
    let redacted_obj = match redacted {
        Value::Object(m) => m,
        _ => &empty,
    };
    let mut out = serde_json::Map::new();
    for (key, value) in content_obj {
        match (redacted_obj.get(key), value) {
            (Some(preserved), _) if preserved == value => {}
            (Some(Value::Object(preserved_inner)), Value::Object(full_inner)) => {
                let mut remainder = serde_json::Map::new();
                for (inner_key, inner_value) in full_inner {
                    if preserved_inner.get(inner_key) != Some(inner_value) {
                        remainder.insert(inner_key.clone(), inner_value.clone());
                    }
                }
                if !remainder.is_empty() {
                    out.insert(key.clone(), Value::Object(remainder));
                }
            }
            _ => {
                out.insert(key.clone(), value.clone());
            }
        }
    }
    Value::Object(out)
}

/// Filters `content` down to exactly the keys a redaction preserves, per the
/// given rule. Top-level keys are copied as-is; dotted paths (e.g.
/// `third_party_invite.signed`) keep only the nested key under the parent
/// object. `RedactionRule::All` returns the content untouched; `None` yields
/// an empty object.
fn redact_content(content: &Value, rule: RedactionRule) -> Value {
    match rule {
        RedactionRule::None => Value::Object(serde_json::Map::default()),
        RedactionRule::All => content.clone(),
        RedactionRule::Keys(paths) => {
            let mut out = serde_json::Map::new();
            for path in paths {
                if let Some((top, rest)) = path.split_once('.') {
                    if let Some(Value::Object(inner)) = content.get(top) {
                        if let Some(v) = inner.get(rest) {
                            // Accumulate into the existing parent so paths sharing
                            // a parent (e.g. `a.b` and `a.c`) both survive.
                            if let Some(Value::Object(parent)) = out.get_mut(top) {
                                parent.insert(rest.to_string(), v.clone());
                            } else {
                                let mut parent = serde_json::Map::new();
                                parent.insert(rest.to_string(), v.clone());
                                out.insert(top.to_string(), Value::Object(parent));
                            }
                        }
                    }
                } else if let Some(v) = content.get(*path) {
                    out.insert((*path).to_string(), v.clone());
                }
            }
            Value::Object(out)
        }
    }
}

/// The top-level PDU keys a redaction preserves, per room version.
///
/// Content is stripped separately by [`redact_content`]; this is the second
/// half of the spec's redaction algorithm. v11+ no longer protects
/// `origin`/`membership`/`prev_state` at the top level; pre-v11 versions keep
/// them. v12+ (MSC4291) drops `room_id` on `m.room.create` (the room ID is
/// derived from the event ID, so the create carries none).
///
/// The unstable-version deviations are intentionally not modeled — rezzy
/// handles the stable v1-v12 set, and their redaction identifiers
/// (`org.matrix.msc3389.10` preserving `m.relates_to.{rel_type,event_id}`)
/// are unrecognized and fail closed. `org.matrix.msc4242.12`'s swap of
/// `auth_events` for `prev_state_events` is modeled in `redact_top_level`:
/// the swapped-in field is preserved alongside `auth_events`.
#[must_use]
fn redact_top_level(value: &Value, room_version: &str) -> serde_json::Map<String, Value> {
    use crate::basespec::event_types::{
        FIELD_AUTH_EVENTS, FIELD_CONTENT, FIELD_DEPTH, FIELD_EVENT_ID, FIELD_HASHES,
        FIELD_ORIGIN_SERVER_TS, FIELD_PREV_EVENTS, FIELD_SENDER, FIELD_SIGNATURES, FIELD_STATE_KEY,
        FIELD_TYPE,
    };
    let Value::Object(obj) = value else {
        return serde_json::Map::new();
    };
    // MSC4291 (room IDs as hashes, room v12+): the create event carries no
    // room_id, so it must not be preserved on redaction.
    let is_v12_create = obj.get(FIELD_TYPE).and_then(Value::as_str)
        == Some(crate::basespec::event_types::M_ROOM_CREATE)
        && room_version_is_v12_or_later(room_version);
    let mut out = serde_json::Map::new();
    let take = |key: &str, out: &mut serde_json::Map<String, Value>| {
        if let Some(v) = obj.get(key) {
            out.insert(String::from(key), v.clone());
        }
    };
    take(FIELD_EVENT_ID, &mut out);
    take(FIELD_TYPE, &mut out);
    if !is_v12_create {
        take("room_id", &mut out);
    }
    take(FIELD_SENDER, &mut out);
    take(FIELD_STATE_KEY, &mut out);
    take(FIELD_CONTENT, &mut out);
    take(FIELD_HASHES, &mut out);
    take(FIELD_SIGNATURES, &mut out);
    take(FIELD_DEPTH, &mut out);
    take(FIELD_PREV_EVENTS, &mut out);
    take(FIELD_AUTH_EVENTS, &mut out);
    take(FIELD_ORIGIN_SERVER_TS, &mut out);
    // MSC4242 (org.matrix.msc4242.12, room v11+/v12) swaps `auth_events`
    // for `prev_state_events`. Preserve the swapped-in field so events signed
    // under that format survive redaction with their hashes/signatures intact.
    // `take` is a no-op when the field is absent, so stable v11/v12 events
    // (which never carry it) are unaffected.
    if is_msc4242_room_version(room_version) {
        take("prev_state_events", &mut out);
    }
    if !is_msc4242_room_version(room_version) {
        take("origin", &mut out);
        take("membership", &mut out);
        take("prev_state", &mut out);
    }
    out
}
/// The base64 engine used for Matrix hash encodings, derived from the room
/// version. Room v3 uses the STANDARD alphabet; room v4+ uses URL-safe. Both
/// are unpadded. Mirrors Synapse's Rust (`ROOM_V3 -> STANDARD`, else
/// `URL_SAFE`) and its `unpaddedbase64.encode_base64` (default STANDARD).
#[must_use]
fn hash_base64_engine(room_version: &str) -> base64::engine::GeneralPurpose {
    use base64::engine::{general_purpose::NO_PAD, GeneralPurpose};
    let is_v3 = room_version
        .split('.')
        .next()
        .and_then(|major| major.parse::<u32>().ok())
        .is_some_and(|major| major == 3);
    let alphabet = if is_v3 {
        &base64::alphabet::STANDARD
    } else {
        &base64::alphabet::URL_SAFE
    };
    GeneralPurpose::new(alphabet, NO_PAD)
}

/// The Matrix redaction algorithm applied to a raw PDU `Value`, both halves:
///
/// 1. Drop every top-level key outside the preserved whitelist (see the
///    private `redact_top_level` helper below).
/// 2. Strip `content` down to the keys [`redaction_preserved_keys`] preserves
///    for `room_version`.
///
/// This is the primitive the reference-hash (event ID for room v4+) path and
/// the lean-model [`LeanEvent::redacted`] both build on.
#[must_use]
pub fn redact_json(value: &Value, room_version: &str) -> Value {
    let event_type = value
        .get(crate::basespec::event_types::FIELD_TYPE)
        .and_then(Value::as_str)
        .unwrap_or("");
    let rule = redaction_preserved_keys(event_type, room_version);
    let mut out = redact_top_level(value, room_version);
    let content = out
        .get(crate::basespec::event_types::FIELD_CONTENT)
        .map_or_else(
            || Value::Object(serde_json::Map::default()),
            |c| redact_content(c, rule),
        );
    out.insert(
        String::from(crate::basespec::event_types::FIELD_CONTENT),
        content,
    );
    Value::Object(out)
}

/// Computes the Matrix **reference hash** of a PDU `Value` — the event ID for
/// room versions 4+: SHA-256 of the canonical JSON of the *redacted* event
/// (with `signatures`/`unsigned`/legacy `age_ts` removed; `hashes` is
/// retained), encoded with the room version's base64 alphabet (STANDARD for
/// v3, URL-safe for v4+; no `$` prefix).
///
/// Canonicalization is tolerant of out-of-range integers (like Synapse's
/// `relaxed` mode): `serde_json::to_string` serializes whatever numbers are
/// present rather than rejecting them. Keys are already lexicographically
/// sorted because `serde_json::Map` is a `BTreeMap`.
///
/// # Errors
/// Returns `Err` when the room version has no reference hash (v1/v2, whose
/// event IDs are opaque server-assigned strings, not hashes).
///
/// # Panics
/// Panics if the canonical JSON cannot be serialized. This is unreachable in
/// practice: a `serde_json::Value` serializes infallibly (a safe `Value`
/// cannot hold a non-finite number), so `expect` is used instead of a
/// recoverable `?` to keep the error branch out of the coverage report.
pub fn reference_hash(
    value: &Value,
    room_version: &str,
) -> Result<alloc::string::String, alloc::string::String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let major = room_version
        .split('.')
        .next()
        .and_then(|m| m.parse::<u32>().ok());
    if major.is_some_and(|m| m <= 2) {
        return Err(alloc::format!(
            "no reference hash for room version {room_version}: v1/v2 event IDs are opaque server-assigned strings, not hashes"
        ));
    }

    if StateResVersion::from_room_version(room_version).is_none() {
        return Err(alloc::format!(
            "no reference hash for unsupported room version {room_version}: its event ID hash rules are undefined"
        ));
    }

    let mut hasher = Sha256::new();
    {
        let mut w = ShaWriter(&mut hasher);
        write_redacted_canonical(&mut w, value, room_version)
            .expect("writing canonical JSON into the hasher is infallible");
    }
    Ok(hash_base64_engine(room_version).encode(hasher.finalize()))
}

/// Computes the Matrix **content hash** of a PDU `Value` (`hashes.sha256`):
/// SHA-256 of the canonical JSON of the *unredacted* event with `unsigned`,
/// `signatures`, and `hashes` removed, encoded with standard unpadded base64
/// for every room version.
///
/// # Errors
/// Always returns `Ok`. The `Result` return type is retained for API symmetry
/// with [`reference_hash`]; a `serde_json::Value` serializes infallibly (a safe
/// `Value` cannot hold a non-finite number), so the serialize call uses
/// `expect` rather than a recoverable `?`.
///
/// # Panics
/// Panics only if the canonical JSON cannot be serialized, which is unreachable
/// for the reason above.
pub fn compute_content_hash(
    value: &Value,
    _room_version: &str,
) -> Result<alloc::string::String, alloc::string::String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    {
        let mut w = ShaWriter(&mut hasher);
        write_content_hash_canonical(&mut w, value)
            .expect("writing canonical JSON into the hasher is infallible");
    }
    Ok(base64::engine::general_purpose::STANDARD_NO_PAD.encode(hasher.finalize()))
}

/// Verifies a raw PDU `Value`'s `hashes.sha256` against its recomputed content
/// hash. This is a PDU-boundary check: it must run on the raw, unredacted
/// event (the content hash covers the unredacted content), before the event is
/// converted into a lean form that drops the hashed content.
///
/// # Errors
/// Returns `Err` when `hashes.sha256` is missing/not a string, or when the
/// recomputed content hash does not match.
pub fn verify_content_hash(value: &Value, room_version: &str) -> Result<(), alloc::string::String> {
    let Some(expected) = value
        .get(crate::basespec::event_types::FIELD_HASHES)
        .and_then(|h| h.get("sha256"))
        .and_then(Value::as_str)
    else {
        return Err(alloc::string::String::from(
            "hashes.sha256 is missing or not a string",
        ));
    };
    let computed = compute_content_hash(value, room_version)?;
    if computed != expected {
        return Err(alloc::format!(
            "content hash mismatch: hashes.sha256={expected}, computed={computed}"
        ));
    }
    Ok(())
}

/// Produces the canonical JSON bytes an ed25519 PDU signature covers: the
/// redacted event with `unsigned` and `signatures` stripped and object keys
/// recursively sorted (the Matrix "Signing Events" canonicalization).
///
/// This is the string that [`reference_hash`] hashes to form an event ID and
/// that signature verification signs — so it must be redacted first, otherwise
/// a redaction-vs-signer mismatch (like the MSC4242 `prev_state_events` bug)
/// makes verification fail.
///
/// # Errors
/// Returns `Err` when the redacted `Value` cannot be serialized (unreachable
/// for a safe `Value`), or when `room_version` is unsupported and `redact_json`
/// fails closed to an empty object.
///
/// # Panics
/// Panics only if the canonical JSON cannot be serialized, which is unreachable
/// for a `serde_json::Value` (a safe `Value` cannot hold a non-finite number).
#[must_use]
pub fn canonical_redacted_json(value: &Value, room_version: &str) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    write_redacted_canonical(&mut out, value, room_version)
        .expect("writing canonical JSON into a String is infallible");
    out
}

// ---------------------------------------------------------------------------
// Zero-copy canonical JSON writer.
//
// `serde_json::Map` is a `BTreeMap`, so object keys are already sorted. This
// writer emits canonical JSON by descending the tree directly into a
// `core::fmt::Write` sink — skipping the intermediate `Value` clone + re-sort
// that `redact_json`/`value.clone()` + `serde_json::to_string` would pay, and
// feeding bytes straight into the hasher or a `String`.
//
// Byte-parity with `serde_json` is load-bearing (hashes/signatures cover these
// exact bytes), so it is pinned by `canonical_parity_tests` and every
// reference-hash vector. Number formatting is delegated to
// `serde_json::Number::to_string` (identical to what serde_json emits, incl.
// ryu float formatting), which removes any float/`-0`/exponent divergence risk.
// ---------------------------------------------------------------------------

/// A `core::fmt::Write` sink that feeds bytes straight into a SHA-256 hasher.
struct ShaWriter<'a>(&'a mut sha2::Sha256);

impl core::fmt::Write for ShaWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        use sha2::Digest as _;
        self.0.update(s.as_bytes());
        Ok(())
    }
}

/// Writes a JSON string with `serde_json`-identical escaping.
///
/// Non-special runs are emitted in bulk (one `write_str` per escaped char
/// boundary) instead of per character, matching `serde_json`'s fragment
/// batching.
fn write_json_string<W: core::fmt::Write>(out: &mut W, s: &str) -> core::fmt::Result {
    out.write_str("\"")?;
    let bytes = s.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let escape = matches!(b, b'"' | b'\\' | 0x00..=0x1f);
        if !escape {
            i = i.saturating_add(1);
            continue;
        }
        if i > start {
            // ASCII bytes (the only escaped ones) never occur inside a UTF-8
            // multibyte sequence, so this is a valid char boundary.
            out.write_str(&s[start..i])?;
        }
        match b {
            b'"' => out.write_str("\\\"")?,
            b'\\' => out.write_str("\\\\")?,
            0x08 => out.write_str("\\b")?,
            0x09 => out.write_str("\\t")?,
            0x0a => out.write_str("\\n")?,
            0x0c => out.write_str("\\f")?,
            0x0d => out.write_str("\\r")?,
            _ => write!(out, "\\u{b:04x}")?,
        }
        i = i.saturating_add(1);
        start = i;
    }
    if start < bytes.len() {
        out.write_str(&s[start..])?;
    }
    out.write_str("\"")
}

/// Recursively writes a JSON value in canonical (key-sorted) form.
fn write_json_value<W: core::fmt::Write>(out: &mut W, v: &Value) -> core::fmt::Result {
    match v {
        Value::Null => out.write_str("null"),
        Value::Bool(true) => out.write_str("true"),
        Value::Bool(false) => out.write_str("false"),
        Value::Number(n) => out.write_str(&n.to_string()),
        Value::String(s) => write_json_string(out, s),
        Value::Array(items) => {
            out.write_str("[")?;
            let mut first = true;
            for item in items {
                if !first {
                    out.write_str(",")?;
                }
                first = false;
                write_json_value(out, item)?;
            }
            out.write_str("]")
        }
        Value::Object(map) => {
            out.write_str("{")?;
            let mut first = true;
            for (k, val) in map {
                if !first {
                    out.write_str(",")?;
                }
                first = false;
                write_json_string(out, k)?;
                out.write_str(":")?;
                write_json_value(out, val)?;
            }
            out.write_str("}")
        }
    }
}

/// Writes the canonical JSON of an **unredacted** event with the top-level
/// `unsigned`, `signatures`, and `hashes` keys omitted — the content-hash input.
fn write_content_hash_canonical<W: core::fmt::Write>(
    out: &mut W,
    value: &Value,
) -> core::fmt::Result {
    let Value::Object(obj) = value else {
        return out.write_str("{}");
    };
    out.write_str("{")?;
    let mut first = true;
    for (key, v) in obj {
        if matches!(key.as_str(), "unsigned" | "signatures" | "hashes") {
            continue;
        }
        if !first {
            out.write_str(",")?;
        }
        first = false;
        write_json_string(out, key)?;
        out.write_str(":")?;
        write_json_value(out, v)?;
    }
    out.write_str("}")
}

/// Writes the canonical JSON of a redacted event with `unsigned`/`signatures`
/// omitted — the reference-hash and PDU-signature input. Mirrors
/// [`redact_top_level`] + [`redact_content`] exactly, emitting only preserved
/// keys in `BTreeMap` (sorted) order without building an intermediate `Value`.
fn write_redacted_canonical<W: core::fmt::Write>(
    out: &mut W,
    value: &Value,
    room_version: &str,
) -> core::fmt::Result {
    use crate::basespec::event_types::{
        FIELD_AUTH_EVENTS, FIELD_CONTENT, FIELD_DEPTH, FIELD_EVENT_ID, FIELD_HASHES,
        FIELD_ORIGIN_SERVER_TS, FIELD_PREV_EVENTS, FIELD_SENDER, FIELD_STATE_KEY, FIELD_TYPE,
        M_ROOM_CREATE,
    };

    let Value::Object(obj) = value else {
        return out.write_str("{}");
    };
    let event_type = obj.get(FIELD_TYPE).and_then(Value::as_str).unwrap_or("");
    let rule = redaction_preserved_keys(event_type, room_version);
    let is_v12_create = event_type == M_ROOM_CREATE && room_version_is_v12_or_later(room_version);
    let msc4242 = is_msc4242_room_version(room_version);

    out.write_str("{")?;
    let mut first = true;
    let mut content_written = false;
    for (key, v) in obj {
        // `redact_json` always materializes an empty `content` object, even
        // when the input omitted the field. Insert it before the first later
        // key so the streaming output remains in canonical key order.
        if !content_written && key.as_str() > FIELD_CONTENT {
            if !first {
                out.write_str(",")?;
            }
            first = false;
            write_json_string(out, FIELD_CONTENT)?;
            out.write_str(":{}")?;
            content_written = true;
        }
        let keep = match key.as_str() {
            FIELD_EVENT_ID
            | FIELD_TYPE
            | FIELD_SENDER
            | FIELD_STATE_KEY
            | FIELD_HASHES
            | FIELD_DEPTH
            | FIELD_PREV_EVENTS
            | FIELD_AUTH_EVENTS
            | FIELD_ORIGIN_SERVER_TS
            | FIELD_CONTENT => true,
            "room_id" => !is_v12_create,
            "prev_state_events" => msc4242,
            "origin" | "membership" | "prev_state" => !msc4242,
            // `unsigned`, `signatures`, and any unrecognized key are dropped.
            _ => false,
        };
        if !keep {
            continue;
        }
        if !first {
            out.write_str(",")?;
        }
        first = false;
        write_json_string(out, key)?;
        out.write_str(":")?;
        if key == FIELD_CONTENT {
            write_json_value(out, &redact_content(v, rule))?;
            content_written = true;
        } else {
            write_json_value(out, v)?;
        }
    }
    if !content_written {
        if !first {
            out.write_str(",")?;
        }
        write_json_string(out, FIELD_CONTENT)?;
        out.write_str(":{}")?;
    }
    out.write_str("}")
}

impl<Id: Clone, K: Clone> LeanEvent<Id, Value, K> {
    /// Returns a redacted copy of this event: `content` is stripped down to the
    /// keys preserved by [`redaction_preserved_keys`] for `room_version`.
    /// The event envelope (`event_id`, `sender`, `type`, `state_key`,
    /// `origin_server_ts`, `prev_events`, `auth_events`, `depth`) is untouched.
    #[must_use]
    pub fn redacted(&self, room_version: &str) -> LeanEvent<Id, Value, K> {
        let rule = redaction_preserved_keys(&self.event_type, room_version);
        LeanEvent {
            event_id: self.event_id.clone(),
            event_type: self.event_type.clone(),
            state_key: self.state_key.clone(),
            power_level: self.power_level,
            origin_server_ts: self.origin_server_ts,
            sender: self.sender.clone(),
            content: redact_content(&self.content, rule),
            prev_events: self.prev_events.clone(),
            auth_events: self.auth_events.clone(),
            depth: self.depth,
            rejected: self.rejected,
            soft_fail: self.soft_fail,
            room_id: self.room_id.clone(),
        }
    }
}

/// Applies `redaction` to `target`, returning the redacted event.
///
/// Returns `None` when the redaction does not actually target `target` (its
/// `redacts` does not equal `target.event_id`). `m.room.create` is redactable
/// like any other event — the spec does not forbid it; its content is simply
/// preserved by [`redaction_preserved_keys`] (all keys in v11+, `creator`
/// before that). The caller is responsible for having already auth-checked
/// `redaction` (see [`crate::auth::check_auth`]) — this function performs the
/// structural application only.
///
/// `room_version` selects the preserved-key rule; obtain it from the room's
/// `m.room.create` content (`get_room_version`).
#[must_use]
pub fn apply_redaction<Id: Clone + core::fmt::Display, K: Clone>(
    target: &LeanEvent<Id, Value, K>,
    redaction: &LeanEvent<Id, Value, K>,
    room_version: &str,
) -> Option<LeanEvent<Id, Value, K>> {
    if !redaction
        .get_redacts()
        .is_some_and(|target_id| target_id == target.event_id.to_string())
    {
        return None;
    }
    Some(target.redacted(room_version))
}

/// Ingest path: turns a batch of raw PDUs into lean events ready for state
/// resolution, wiring the PDU-boundary checks a homeserver performs on receipt.
///
/// For each PDU, in order:
///
/// 1. **Content-hash verification** — if the PDU carries a `hashes` dict,
///    [`verify_content_hash`] is run against it (the unredacted content hash,
///    `hashes.sha256`). Events without a `hashes` dict are skipped (not every
///    caller feeds full signed PDUs).
/// 2. **Parsing** — each PDU is converted to a [`LeanEvent`] with
///    [`LeanEvent::from_value`], deriving a missing `event_id` from the room
///    version's reference hash.
///
/// This function does **not** apply redactions. Applying a redaction requires
/// authorization against the room's resolved state (the redact power level and
/// the target's sender), which does not exist at ingest time. Callers that want
/// in-batch redaction applied must run
/// [`crate::auth::apply_authorized_redactions`] once they hold the resolved
/// state.
///
/// # Errors
/// Returns `Err` if a PDU fails content-hash verification, or cannot be parsed
/// to a `LeanEvent` (including a missing `event_id` for a room version with no
/// reference hash, i.e. v1/v2).
pub fn ingest_events(
    pdus: &[Value],
    room_version: &str,
) -> Result<Vec<LeanEvent<String, Value, String>>, alloc::string::String> {
    for pdu in pdus {
        if pdu
            .get(crate::basespec::event_types::FIELD_HASHES)
            .is_some()
        {
            verify_content_hash(pdu, room_version)?;
        }
    }

    let mut events: Vec<LeanEvent<String, Value, String>> = Vec::with_capacity(pdus.len());
    for pdu in pdus {
        // TODO: `?` here is reachable (malformed PDU) — candidate to soften
        // into a `Warning` + skip rather than abort the whole batch.
        events.push(LeanEvent::from_value(pdu, Some(room_version)).map_err(|e| e.to_string())?);
    }

    Ok(events)
}

impl serde::Serialize for StateResVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            StateResVersion::V1 => "V1",
            StateResVersion::V2 => "V2",
            StateResVersion::V2_1 => "V2_1",
            StateResVersion::V2_1_1 => "V2_1_1",
            StateResVersion::V2_2 => "V2_2",
        };
        serializer.serialize_str(s)
    }
}

impl<'de> serde::Deserialize<'de> for StateResVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StateResVersionVisitor;

        impl serde::de::Visitor<'_> for StateResVersionVisitor {
            type Value = StateResVersion;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a StateResVersion string")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value {
                    "V1" => Ok(StateResVersion::V1),
                    "V2" => Ok(StateResVersion::V2),
                    "V2_1" => Ok(StateResVersion::V2_1),
                    "V2_1_1" => Ok(StateResVersion::V2_1_1),
                    "V2_2" => Ok(StateResVersion::V2_2),
                    _ => Err(E::custom(alloc::format!("unknown variant `{value}`"))),
                }
            }
        }

        deserializer.deserialize_str(StateResVersionVisitor)
    }
}

/// Result of Kahn's topological sort with diagnostic information.
#[derive(Debug, Clone)]
pub enum KahnSortResult<Id = String> {
    /// All events were successfully sorted.
    Ok(Vec<Id>),
    /// A cycle was detected. `sorted` contains the partial ordering of events
    /// that could be processed, `stuck` contains events that could not reach
    /// in-degree 0 (involved in cycles).
    CycleDetected { sorted: Vec<Id>, stuck: Vec<Id> },
}

impl<Id> KahnSortResult<Id> {
    /// Returns the sorted event IDs, or an empty vec if a cycle was detected.
    /// This preserves backward compatibility with the old API.
    #[must_use]
    pub fn into_sorted(self) -> Vec<Id> {
        match self {
            KahnSortResult::Ok(v) => v,
            KahnSortResult::CycleDetected { .. } => Vec::new(),
        }
    }

    /// Returns true if sorting completed without cycles.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, KahnSortResult::Ok(_))
    }
}

/// A generic interface for graph nodes required by topological algorithms
/// (e.g., `compute_merge_base`). This allows consumers like `conduwuit` to
/// pass their own lightweight `EventMeta` tuples without allocating dummy JSON structs.
///
/// # Relationship to [`EventLike`]
///
/// `DagNode` is a supertrait of [`EventLike`]. Implementors who only need
/// topological traversal (e.g. LCA / merge-base computation) can implement
/// `DagNode` alone without the full suite of auth-related accessors.
pub trait DagNode {
    /// The event identifier type (e.g. `String`, `u32`).
    type Id: EventId;

    /// Returns a reference to this event's unique identifier.
    fn event_id(&self) -> &Self::Id;

    /// DAG depth (distance from the root `m.room.create` event).
    fn depth(&self) -> u64;

    /// Event IDs of this event's parents in the timeline DAG.
    fn prev_events(&self) -> &[Self::Id];

    /// Event IDs of the authorization events for this event.
    fn auth_events(&self) -> &[Self::Id];

    /// Event IDs of the previous state events in the state DAG (MSC4242).
    fn prev_state_events(&self) -> &[Self::Id] {
        &[]
    }
}

impl<Id: EventId, C, K> DagNode for LeanEvent<Id, C, K> {
    type Id = Id;

    fn event_id(&self) -> &Id {
        &self.event_id
    }
    fn depth(&self) -> u64 {
        self.depth
    }
    fn prev_events(&self) -> &[Id] {
        &self.prev_events
    }
    fn auth_events(&self) -> &[Id] {
        &self.auth_events
    }
    fn prev_state_events(&self) -> &[Id] {
        // MSC4242 replaces the wire-level auth_events list with
        // prev_state_events. LeanEvent stores that shared list in auth_events;
        // callers select its meaning by room version.
        &self.auth_events
    }
}

/// Unified trait for Matrix events used by the auth and resolution engines.
///
/// `EventLike` extends [`DagNode`] with the full set of envelope fields
/// (sender, event type, state key, etc.) and content accessors (membership,
/// power levels, join rules, etc.) needed for authorization checks.
///
/// # For downstream homeservers
///
/// The recommended path is [`RawEvent`] + [`ParsedEvent`], which gives you
/// `DagNode + EventLike` for free with a small set of one-liner field accessors.
///
/// If you need full control (e.g. typed content without JSON parsing),
/// implement `EventLike` directly with a [`Content`](Self::Content) type
/// that implements [`EventContent`].
///
/// # Example
///
/// ```rust,no_run
/// use std::borrow::Cow;
/// use rezzy::{DagNode, EventLike};
///
/// struct MyEvent {
///     event_id: String,
///     sender: String,
///     parsed_content: serde_json::Value,
/// }
///
/// impl DagNode for MyEvent {
///     type Id = String;
///     fn event_id(&self) -> &String { &self.event_id }
///     fn depth(&self) -> u64 { 0 }
///     fn prev_events(&self) -> &[String] { &[] }
///     fn auth_events(&self) -> &[String] { &[] }
/// }
///
/// impl EventLike for MyEvent {
///     type Content = serde_json::Value;
///     fn event_type(&self) -> Cow<'_, str> { Cow::Borrowed("m.room.message") }
///     fn sender(&self) -> &str { &self.sender }
///     fn state_key(&self) -> Option<&str> { None }
///     fn power_level(&self) -> i64 { 0 }
///     fn origin_server_ts(&self) -> u64 { 0 }
///     fn content(&self) -> &serde_json::Value { &self.parsed_content }
/// }
/// ```
pub trait EventLike: DagNode {
    /// The content type (e.g. `serde_json::Value` or a typed struct).
    type Content: EventContent;

    /// Matrix event type (e.g. `m.room.member`, `m.room.power_levels`).
    ///
    /// Returns `Cow::Borrowed` when the type string is stored inline (e.g. `LeanEvent`),
    /// or `Cow::Owned`/`Cow::Borrowed` from a typed enum (e.g. ruma `TimelineEventType`).
    fn event_type(&self) -> alloc::borrow::Cow<'_, str>;

    /// The MXID of the user who sent the event.
    fn sender(&self) -> &str;

    /// State key for state events; `None` for timeline (non-state) events.
    fn state_key(&self) -> Option<&str>;

    /// Sender's cached power level at the time of the event.
    fn power_level(&self) -> i64;

    /// Origin server timestamp in milliseconds since Unix epoch.
    fn origin_server_ts(&self) -> u64;

    /// Access the event content (parsed or stored).
    fn content(&self) -> &Self::Content;

    /// Whether this event was rejected by the homeserver.
    fn rejected(&self) -> bool {
        false
    }

    /// Whether this event was soft-failed by the homeserver.
    fn soft_fail(&self) -> bool {
        false
    }

    // === Content accessors — default impls delegate to self.content() ===

    /// Returns the `membership` field from event content.
    fn get_membership(&self) -> Option<&str> {
        self.content().get_membership()
    }

    /// Returns the `join_rule` field from event content.
    fn get_join_rule(&self) -> Option<&str> {
        self.content().get_join_rule()
    }

    /// Returns the power level for a specific user from `content.users`.
    fn get_user_power_level(&self, user: &str) -> Option<i64> {
        self.content().get_user_power_level(user)
    }

    /// Returns the required power level for a specific event type from `content.events`.
    fn get_event_power_level(&self, event_type: &str) -> Option<i64> {
        self.content().get_event_power_level(event_type)
    }

    /// Returns the `users_default` power level.
    fn get_users_default(&self) -> Option<i64> {
        self.content().get_users_default()
    }

    /// Returns the `events_default` power level.
    fn get_events_default(&self) -> Option<i64> {
        self.content().get_events_default()
    }

    /// Returns the `state_default` power level.
    fn get_state_default(&self) -> Option<i64> {
        self.content().get_state_default()
    }

    /// Returns the `ban` power level threshold.
    fn get_ban(&self) -> Option<i64> {
        self.content().get_ban()
    }

    /// Returns the `kick` power level threshold.
    fn get_kick(&self) -> Option<i64> {
        self.content().get_kick()
    }

    /// Returns the `invite` power level threshold.
    fn get_invite(&self) -> Option<i64> {
        self.content().get_invite()
    }

    /// Returns the `redact` power level threshold.
    fn get_redact(&self) -> Option<i64> {
        self.content().get_redact()
    }

    /// Returns the `creator` field from `m.room.create` content.
    fn get_creator(&self) -> Option<&str> {
        self.content().get_creator()
    }

    /// Returns the `room_version` field from `m.room.create` content.
    fn get_room_version(&self) -> Option<&str> {
        self.content().get_room_version()
    }

    /// Returns the `redacts` field (event ID being redacted) for
    /// `m.room.redaction` events.
    fn get_redacts(&self) -> Option<&str> {
        self.content().get_redacts()
    }

    /// Returns true if `sender` is listed in the V12+ `additional_creators` array.
    fn has_additional_creator(&self, sender: &str) -> bool {
        self.content().has_additional_creator(sender)
    }

    /// Returns the `join_authorised_via_users_server` field, if present.
    fn get_join_authorised_via_users_server(&self) -> Option<&str> {
        self.content().get_join_authorised_via_users_server()
    }

    /// Returns whether a `third_party_invite` field is present.
    fn has_third_party_invite(&self) -> bool {
        self.content().has_third_party_invite()
    }

    /// Returns the signed token from `third_party_invite.signed.token`.
    fn get_third_party_invite_token(&self) -> Option<&str> {
        self.content().get_third_party_invite_token()
    }

    /// Returns the mxid from `third_party_invite.signed.mxid`.
    fn get_third_party_invite_mxid(&self) -> Option<&str> {
        self.content().get_third_party_invite_mxid()
    }

    /// Returns whether `third_party_invite.signed.signatures` is present and non-empty.
    fn has_third_party_invite_signatures(&self) -> bool {
        self.content().has_third_party_invite_signatures()
    }
}

impl<Id: EventId, C: EventContent, K: AsRef<str>> EventLike for LeanEvent<Id, C, K> {
    type Content = C;

    fn event_type(&self) -> alloc::borrow::Cow<'_, str> {
        alloc::borrow::Cow::Borrowed(&self.event_type)
    }
    fn sender(&self) -> &str {
        &self.sender
    }
    fn state_key(&self) -> Option<&str> {
        self.state_key.as_ref().map(AsRef::as_ref)
    }
    fn power_level(&self) -> i64 {
        self.power_level
    }
    fn origin_server_ts(&self) -> u64 {
        self.origin_server_ts
    }
    fn content(&self) -> &C {
        &self.content
    }

    fn rejected(&self) -> bool {
        self.rejected
    }

    fn soft_fail(&self) -> bool {
        self.soft_fail
    }
}

// ── RawEvent + ParsedEvent: zero-boilerplate adapter ────────────────

/// Trait for external event types that store content as raw JSON.
///
/// Implement this on your native PDU type (~9 one-liner field accessors),
/// then wrap with [`ParsedEvent`] to get [`DagNode`] + [`EventLike`] for free.
/// Content is parsed once from raw JSON at [`ParsedEvent::new`] time; all
/// 20 content accessors (`get_membership`, `get_join_rule`, etc.) are
/// inherited automatically.
///
/// # Example
///
/// ```rust,no_run
/// use std::borrow::Cow;
/// use rezzy::{RawEvent, ParsedEvent};
///
/// struct Pdu {
///     event_id: String,
///     sender: String,
///     kind: String,
///     state_key: Option<String>,
///     content: String,
///     prev_events: Vec<String>,
///     auth_events: Vec<String>,
///     depth: u64,
///     origin_server_ts: u64,
///     rejected: bool,
///     soft_fail: bool,
/// }
///
/// impl RawEvent for Pdu {
///     type Id = String;
///
///     fn raw_event_id(&self) -> &String { &self.event_id }
///     fn raw_event_type(&self) -> Cow<'_, str> { Cow::Borrowed(&self.kind) }
///     fn raw_sender(&self) -> &str { &self.sender }
///     fn raw_state_key(&self) -> Option<&str> { self.state_key.as_deref() }
///     fn raw_content_json(&self) -> &str { &self.content }
///     fn raw_prev_events(&self) -> &[String] { &self.prev_events }
///     fn raw_auth_events(&self) -> &[String] { &self.auth_events }
///     fn raw_depth(&self) -> u64 { self.depth }
///     fn raw_origin_server_ts(&self) -> u64 { self.origin_server_ts }
///     fn raw_rejected(&self) -> bool { self.rejected }
///     fn raw_soft_fail(&self) -> bool { self.soft_fail }
/// }
///
/// let pdu = Pdu {
///     event_id: "$abc:example.com".into(),
///     sender: "@alice:example.com".into(),
///     kind: "m.room.message".into(),
///     state_key: None,
///     content: "{}".into(),
///     prev_events: vec![],
///     auth_events: vec![],
///     depth: 1,
///     origin_server_ts: 1000,
///     rejected: false,
///     soft_fail: false,
/// };
/// let _event = ParsedEvent::new(&pdu);
/// ```
pub trait RawEvent {
    /// The event ID type (e.g. `OwnedEventId`, `String`).
    type Id: EventId;

    /// The event's unique identifier.
    fn raw_event_id(&self) -> &Self::Id;

    /// The Matrix event type as a string (e.g. `"m.room.member"`).
    fn raw_event_type(&self) -> alloc::borrow::Cow<'_, str>;

    /// The sender's MXID as a string slice.
    fn raw_sender(&self) -> &str;

    /// The state key, if this is a state event.
    fn raw_state_key(&self) -> Option<&str>;

    /// The raw JSON content of the event.
    fn raw_content_json(&self) -> &str;

    /// References to parent event IDs in the DAG.
    fn raw_prev_events(&self) -> &[Self::Id];

    /// References to auth event IDs.
    fn raw_auth_events(&self) -> &[Self::Id];

    /// References to previous state event IDs in the state DAG (MSC4242).
    fn raw_prev_state_events(&self) -> &[Self::Id] {
        &[]
    }

    /// DAG depth.
    fn raw_depth(&self) -> u64;

    /// Origin server timestamp in milliseconds since Unix epoch.
    fn raw_origin_server_ts(&self) -> u64;

    /// Cached power level (used for state resolution sort priority).
    /// Defaults to `0` — override if your type caches this.
    fn raw_power_level(&self) -> i64 {
        0
    }

    /// Whether this event was rejected by the homeserver.
    fn raw_rejected(&self) -> bool;

    /// Whether this event was soft-failed by the homeserver.
    fn raw_soft_fail(&self) -> bool;
}

/// Wraps a `&T` (where `T: RawEvent`) with a cached parsed
/// `serde_json::Value` content, providing [`DagNode`] + [`EventLike`]
/// for free.
///
/// Content is parsed once at construction from [`RawEvent::raw_content_json`].
pub struct ParsedEvent<'a, T: RawEvent> {
    raw: &'a T,
    content: serde_json::Value,
}

impl<'a, T: RawEvent> ParsedEvent<'a, T> {
    /// Create a new `ParsedEvent`, parsing the raw JSON content once.
    ///
    /// Returns an error if `raw_content_json()` is not valid JSON.
    /// Prefer this over [`new`](Self::new) when you want to surface
    /// parse failures instead of silently falling back to empty content.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if the raw content string is not valid JSON.
    pub fn try_new(event: &'a T) -> Result<Self, serde_json::Error> {
        let content = serde_json::from_str(event.raw_content_json())?;
        Ok(Self {
            raw: event,
            content,
        })
    }

    /// Create a new `ParsedEvent`, parsing the raw JSON content once.
    ///
    /// If the content JSON is malformed, falls back to `Value::Null`
    /// (all content accessors will return `None`/defaults).
    /// Use [`try_new`](Self::try_new) for strict error handling.
    #[must_use]
    pub fn new(event: &'a T) -> Self {
        let content = serde_json::from_str(event.raw_content_json()).unwrap_or_default();
        Self {
            raw: event,
            content,
        }
    }
}

impl<T: RawEvent> DagNode for ParsedEvent<'_, T> {
    type Id = T::Id;

    fn event_id(&self) -> &T::Id {
        self.raw.raw_event_id()
    }

    fn depth(&self) -> u64 {
        self.raw.raw_depth()
    }

    fn prev_events(&self) -> &[T::Id] {
        self.raw.raw_prev_events()
    }

    fn auth_events(&self) -> &[T::Id] {
        self.raw.raw_auth_events()
    }

    fn prev_state_events(&self) -> &[T::Id] {
        self.raw.raw_prev_state_events()
    }
}

impl<T: RawEvent> EventLike for ParsedEvent<'_, T> {
    type Content = serde_json::Value;

    fn event_type(&self) -> alloc::borrow::Cow<'_, str> {
        self.raw.raw_event_type()
    }

    fn sender(&self) -> &str {
        self.raw.raw_sender()
    }

    fn state_key(&self) -> Option<&str> {
        self.raw.raw_state_key()
    }

    fn power_level(&self) -> i64 {
        self.raw.raw_power_level()
    }

    fn origin_server_ts(&self) -> u64 {
        self.raw.raw_origin_server_ts()
    }

    fn content(&self) -> &serde_json::Value {
        &self.content
    }

    fn rejected(&self) -> bool {
        self.raw.raw_rejected()
    }

    fn soft_fail(&self) -> bool {
        self.raw.raw_soft_fail()
    }
}

/// A lightweight Matrix event representation optimized for state resolution.
///
/// `LeanEvent` strips away fields irrelevant to state resolution (e.g. `unsigned`,
/// `signatures`, `hashes`) and retains only the fields needed for topological
/// sorting, power-level lookups, and auth checks.
///
/// The generic `Id` parameter defaults to `String` but can be substituted with
/// `u32` or `u64` for integer-interned resolution (see [`EventId`]).
///
/// # Deserialization
///
/// `LeanEvent<String>` implements `Deserialize` with the following behaviors:
/// - `event_id`: Required. `Deserialize` parses without a `room_version`, so an
///   absent `event_id` is an error (no reference/content hash is derived; use
///   [`LeanEvent::from_value`] with a `room_version` to derive one).
/// - `power_level`: Accepts integers, unsigned integers, or string-encoded
///   integers, clamped to [`MAX_POWER_LEVEL_JSON`].
/// - `typed_content`: Populated from `content` for auth-relevant events.
/// - All other fields default to empty/zero if absent.
///
/// # Note on Room ID
///
/// `LeanEvent` carries `room_id` as an optional, cheaply-shared [`RoomId`]
/// (see [`Self::room_id`]) rather than requiring it. `rezzy` remains a
/// specialized algorithmic engine that expects the host homeserver (e.g.,
/// Synapse, Conduit) to perform initial database-level filtering by room --
/// this field is defense-in-depth for [`check_auth_chain`](crate::auth::check_auth_chain),
/// not a replacement for that filtering, and every existing caller that
/// leaves it `None` behaves exactly as before (the field is additive and
/// opts out of the check entirely when absent on either side of a
/// comparison — see [`Self::room_id`]'s docs).
#[derive(Debug, Clone, Default)]
pub struct LeanEvent<Id = String, C = Value, K = String> {
    /// Unique event identifier (e.g. `$abc123:example.com`).
    pub event_id: Id,
    /// Matrix event type (e.g. `m.room.member`, `m.room.power_levels`).
    pub event_type: String,
    /// State key for state events; `None` for timeline (non-state) events.
    /// For `m.room.member` events this is the target user's MXID. Generic
    /// over `K` (defaults to `String`) so downstream homeservers may use a
    /// lighter interned key type; see [`StateKey`].
    pub state_key: Option<K>,
    /// Sender's power level at the time of the event, used for sort priority.
    /// This is a pre-computed cache — the authoritative PL is derived from the
    /// auth chain during resolution.
    pub power_level: i64,
    /// Origin server timestamp in milliseconds since Unix epoch.
    /// Used as a tie-breaker in V2+ topological sort ordering.
    pub origin_server_ts: u64,
    /// The MXID of the user who sent the event.
    pub sender: String,
    /// The event's content field (membership, power levels, join rules, etc.).
    pub content: C,
    /// Event IDs of this event's parents in the DAG (timeline graph).
    pub prev_events: Vec<Id>,
    /// Event IDs of the authorization events for this event (auth DAG).
    pub auth_events: Vec<Id>,
    /// DAG depth (distance from the root). Required for V1 sort ordering.
    pub depth: u64,
    /// Whether this event was rejected by the homeserver (e.g., due to failing auth).
    /// Rejected events are ignored during state resolution and will not be admitted to the resolved state.
    /// TODO: Implement and test edge cases where rejected events might need special handling during outlier fetching or soft-fail resolution.
    pub rejected: bool,
    /// Whether this event was soft-failed.
    /// TODO: Add dedicated test coverage for soft-failed events to ensure they are handled according to spec (especially vs rejected).
    pub soft_fail: bool,
    /// The room this event belongs to, if the caller populated it.
    ///
    /// When populated, every event ingested together in one call shares the
    /// *same* `RoomId` allocation via `Arc::clone` -- one string, cheaply
    /// refcounted across however many events are in the batch, not duplicated
    /// per event.
    ///
    /// `None` is the default and means the foreign-room check is *not*
    /// exercised from this event's side: [`check_auth_chain`](crate::auth::check_auth_chain)
    /// only inspects room IDs on an event that itself carries `Some`. A caller
    /// that never populates the field gets identical behavior to before it
    /// existed.
    ///
    /// Once a citing event carries `Some`, *every* event it cites must also
    /// carry `Some` with the same value: a cited auth event with a different
    /// `Some`, or with `None` at all, is a `ForeignRoomEvent` rejection. A
    /// `None` on the *cited* side is not a free pass -- it is exactly the
    /// "untagged" leak rule 2.5 exists to catch. So the field is opt-in on the
    /// citing side, but it is not additive to the cited side.
    ///
    /// Note that [`ingest_events`] does **not** populate this field -- it has
    /// no room ID parameter, so events it returns always carry `None`. A
    /// caller that wants the foreign-room check in
    /// [`check_auth_chain`](crate::auth::check_auth_chain) to fire must set
    /// `room_id` on the citing event itself after ingest, and must populate it
    /// on every cited auth event too (or those citations are rejected).
    pub room_id: Option<RoomId>,
}

/// A room identifier, cheaply shared across every [`LeanEvent`] from the same
/// ingest batch.
///
/// Wraps `Arc<str>` rather than `String` (one allocation, `Arc::clone` is a
/// refcount bump, not a copy) and rather than `Rc<str>` (this crate uses
/// `std::thread::scope` for parallel resolution, so anything shared across
/// events must be `Send + Sync`, which `Rc` is not). Compares by string
/// value (via `Deref`), not pointer identity, so two `RoomId`s built from
/// separate allocations still compare equal if their content matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RoomId(alloc::sync::Arc<str>);

impl RoomId {
    /// Builds a `RoomId` from any string-like value, allocating once.
    #[must_use]
    pub fn new(id: impl AsRef<str>) -> Self {
        Self(alloc::sync::Arc::from(id.as_ref()))
    }
}

impl AsRef<str> for RoomId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl core::ops::Deref for RoomId {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for RoomId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for RoomId {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

impl From<String> for RoomId {
    fn from(id: String) -> Self {
        Self(alloc::sync::Arc::from(id.as_str()))
    }
}

// TODO: this is a standalone opt-in type, not yet the default `K` anywhere,
// nor threaded through resolution/HAMT/auth call sites or exposed via any
// crate convenience alias. Circle back for the full generic refactor: wire
// this (or something like it) through as an actual default/recommended `K`
// for callers that want it, add conversions to/from the plain-`String` wire
// format at the ingest/checkpoint boundary, and benchmark the win before
// recommending it broadly -- see the `StateKey` trait docs above for the
// contract any replacement `K` must uphold.
/// A lighter-weight, cheaply-cloneable [`StateKey`] for the `state_key` half
/// of a Matrix `(event_type, state_key)` tuple, for callers who want to avoid
/// `String`'s per-clone allocation.
///
/// Same rationale and tradeoffs as [`RoomId`] (`Arc<str>` over `String` for
/// O(1) clones, over `Rc<str>` for `Send + Sync` under `std::thread::scope`
/// parallel resolution) -- see its docs for the full explanation. Unlike
/// `RoomId`, this is meant to be used as the `K` type parameter of
/// [`LeanEvent`] itself (`LeanEvent<Id, C, InternedKey>`), not as a
/// standalone field.
///
/// This is *not* the same kind of interning [`crate::basespec::event_types::EventType`]
/// does: `EventType` is a small, closed, compile-time-known set, so its
/// `as_str()` returns `&'static str` constants with zero allocation and no
/// shared pool. `state_key` values (MXIDs, server names, arbitrary strings)
/// are open-ended, so there is no fixed enum to match on here -- this only
/// gets you a single shared allocation per distinct key value (via `Arc`'s
/// refcount), not a flat integer id backed by a shared intern pool. A true
/// numeric intern id would need a shared table threaded through every call
/// site (since `AsRef<str>` takes no external context to resolve an id back
/// to its string), which is real new plumbing, not a drop-in type swap.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InternedKey(alloc::sync::Arc<str>);

impl InternedKey {
    /// Builds an `InternedKey` from any string-like value, allocating once.
    #[must_use]
    pub fn new(key: impl AsRef<str>) -> Self {
        Self(alloc::sync::Arc::from(key.as_ref()))
    }
}

impl Default for InternedKey {
    /// The empty key, matching `StateKey`'s `K::default().as_ref() == ""` contract.
    fn default() -> Self {
        Self(alloc::sync::Arc::from(""))
    }
}

impl AsRef<str> for InternedKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl core::ops::Deref for InternedKey {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for InternedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for InternedKey {
    fn from(key: &str) -> Self {
        Self::new(key)
    }
}

impl From<String> for InternedKey {
    fn from(key: String) -> Self {
        Self(alloc::sync::Arc::from(key.as_str()))
    }
}

impl<Id, C> LeanEvent<Id, C, String> {
    /// Converts this event's `state_key` half to an [`InternedKey`], yielding a
    /// `LeanEvent` that is usable as `K = InternedKey` in the resolution
    /// pipeline (`compute_state_at` / `SharedState<Id, InternedKey>`).
    ///
    /// This is the ingest-boundary bridge between the plain-`String` wire
    /// format and the interned representation: `state_key` is rebuilt once via
    /// [`InternedKey::from`], so repeated clones during resolution share a
    /// single `Arc` allocation instead of copying the string. Every other field
    /// is moved through unchanged, so the conversion is a pure type change with
    /// no behavioral difference.
    #[must_use]
    pub fn into_interned_state_key(self) -> LeanEvent<Id, C, InternedKey> {
        LeanEvent {
            event_id: self.event_id,
            event_type: self.event_type,
            state_key: self.state_key.map(InternedKey::from),
            power_level: self.power_level,
            origin_server_ts: self.origin_server_ts,
            sender: self.sender,
            content: self.content,
            prev_events: self.prev_events,
            auth_events: self.auth_events,
            depth: self.depth,
            rejected: self.rejected,
            soft_fail: self.soft_fail,
            room_id: self.room_id,
        }
    }
}

/// Borrowed view over a [`LeanEvent`] that avoids cloning event envelopes.
///
/// This is useful for host adapters that already own native event storage and
/// want to expose event data to rezzy without materializing a fresh owned
/// `LeanEvent` up front.
#[derive(Debug, Clone, Copy)]
pub struct LeanEventRef<'a, Id = String, C = Value, K = String> {
    pub event_id: &'a Id,
    pub event_type: &'a str,
    pub state_key: Option<&'a K>,
    pub power_level: i64,
    pub origin_server_ts: u64,
    pub sender: &'a str,
    pub content: &'a C,
    pub prev_events: &'a [Id],
    pub auth_events: &'a [Id],
    pub depth: u64,
    pub room_id: Option<&'a RoomId>,
    pub rejected: bool,
    pub soft_fail: bool,
}

impl<Id: EventId, C, K> LeanEventRef<'_, Id, C, K> {
    /// Materializes an owned [`LeanEvent`] from this borrowed view.
    #[must_use]
    pub fn to_owned(&self) -> LeanEvent<Id, C, K>
    where
        Id: Clone,
        C: Clone,
        K: Clone,
    {
        LeanEvent {
            event_id: self.event_id.clone(),
            event_type: String::from(self.event_type),
            state_key: self.state_key.cloned(),
            power_level: self.power_level,
            origin_server_ts: self.origin_server_ts,
            sender: String::from(self.sender),
            content: self.content.clone(),
            prev_events: self.prev_events.to_vec(),
            auth_events: self.auth_events.to_vec(),
            depth: self.depth,
            rejected: self.rejected,
            soft_fail: self.soft_fail,
            room_id: self.room_id.cloned(),
        }
    }
}

impl<Id, C, K> LeanEvent<Id, C, K> {
    /// Returns a borrowed view of this event without cloning.
    #[must_use]
    pub fn as_ref(&self) -> LeanEventRef<'_, Id, C, K> {
        LeanEventRef {
            event_id: &self.event_id,
            event_type: &self.event_type,
            state_key: self.state_key.as_ref(),
            power_level: self.power_level,
            origin_server_ts: self.origin_server_ts,
            sender: &self.sender,
            content: &self.content,
            prev_events: &self.prev_events,
            auth_events: &self.auth_events,
            depth: self.depth,
            rejected: self.rejected,
            soft_fail: self.soft_fail,
            room_id: self.room_id.as_ref(),
        }
    }
}

impl<Id: EventId, C: EventContent, K> DagNode for LeanEventRef<'_, Id, C, K> {
    type Id = Id;

    fn event_id(&self) -> &Id {
        self.event_id
    }
    fn depth(&self) -> u64 {
        self.depth
    }
    fn prev_events(&self) -> &[Id] {
        self.prev_events
    }
    fn auth_events(&self) -> &[Id] {
        self.auth_events
    }
    fn prev_state_events(&self) -> &[Id] {
        // See LeanEvent::prev_state_events: this borrowed view uses the same
        // compatibility storage for the MSC4242 replacement field.
        self.auth_events
    }
}

impl<Id: EventId, C: EventContent, K: AsRef<str>> EventLike for LeanEventRef<'_, Id, C, K> {
    type Content = C;

    fn event_type(&self) -> alloc::borrow::Cow<'_, str> {
        alloc::borrow::Cow::Borrowed(self.event_type)
    }
    fn sender(&self) -> &str {
        self.sender
    }
    fn state_key(&self) -> Option<&str> {
        self.state_key.map(AsRef::as_ref)
    }
    fn power_level(&self) -> i64 {
        self.power_level
    }
    fn origin_server_ts(&self) -> u64 {
        self.origin_server_ts
    }
    fn content(&self) -> &C {
        self.content
    }

    fn rejected(&self) -> bool {
        self.rejected
    }

    fn soft_fail(&self) -> bool {
        self.soft_fail
    }
}

impl<Id: serde::Serialize, C: serde::Serialize, K: AsRef<str>> serde::Serialize
    for LeanEvent<Id, C, K>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use crate::basespec::event_types::{
            FIELD_AUTH_EVENTS, FIELD_CONTENT, FIELD_DEPTH, FIELD_EVENT_ID, FIELD_ORIGIN_SERVER_TS,
            FIELD_POWER_LEVEL, FIELD_PREV_EVENTS, FIELD_REJECTED, FIELD_SENDER, FIELD_SOFT_FAIL,
            FIELD_STATE_KEY, FIELD_TYPE,
        };
        use serde::ser::SerializeStruct;
        // TODO: trait forces `Result` here, so `?` shows as dead coverage; see
        // docs/tech_debt.md for the refactor investigation.
        let mut state = serializer.serialize_struct("LeanEvent", 13)?;
        state.serialize_field(FIELD_EVENT_ID, &self.event_id)?;
        state.serialize_field(FIELD_TYPE, &self.event_type)?;
        if let Some(ref sk) = self.state_key {
            state.serialize_field(FIELD_STATE_KEY, sk.as_ref())?;
        }
        state.serialize_field(FIELD_POWER_LEVEL, &self.power_level)?;
        state.serialize_field(FIELD_ORIGIN_SERVER_TS, &self.origin_server_ts)?;
        state.serialize_field(FIELD_SENDER, &self.sender)?;
        state.serialize_field(FIELD_CONTENT, &self.content)?;
        state.serialize_field(FIELD_PREV_EVENTS, &self.prev_events)?;
        state.serialize_field(FIELD_AUTH_EVENTS, &self.auth_events)?;
        state.serialize_field(
            crate::basespec::event_types::FIELD_PREV_STATE_EVENTS,
            &self.auth_events,
        )?;
        state.serialize_field(FIELD_DEPTH, &self.depth)?;
        state.serialize_field(FIELD_REJECTED, &self.rejected)?;
        state.serialize_field(FIELD_SOFT_FAIL, &self.soft_fail)?;
        state.end()
    }
}

/// Trait abstracting event content access for state resolution.
///
/// Implement this for custom content types to avoid `serde_json::Value` overhead.
/// The default `Value` implementation preserves full backwards compatibility.
pub trait EventContent: Clone + core::fmt::Debug + Default {
    fn get_membership(&self) -> Option<&str>;
    fn get_join_rule(&self) -> Option<&str>;
    fn get_user_power_level(&self, user: &str) -> Option<i64>;
    fn get_event_power_level(&self, event_type: &str) -> Option<i64>;
    fn get_users_default(&self) -> Option<i64>;
    fn get_events_default(&self) -> Option<i64>;
    fn get_state_default(&self) -> Option<i64>;
    fn get_ban(&self) -> Option<i64>;
    fn get_kick(&self) -> Option<i64>;
    fn get_invite(&self) -> Option<i64>;
    fn get_redact(&self) -> Option<i64>;
    fn get_creator(&self) -> Option<&str>;
    /// Returns the `room_version` field from `m.room.create` content.
    fn get_room_version(&self) -> Option<&str> {
        None
    }
    /// Returns the `m.federate` field from `m.room.create` content, if present.
    fn get_m_federate(&self) -> Option<bool> {
        None
    }
    /// Returns the event ID of the event being redacted (the `redacts`
    /// field), for `m.room.redaction` events. Moved into `content` in v11+;
    /// pre-v11 callers are expected to surface it the same way since
    /// `LeanEvent` has no dedicated top-level `redacts` field.
    fn get_redacts(&self) -> Option<&str> {
        None
    }
    /// Specific to V12+ rooms.
    fn has_additional_creator(&self, sender: &str) -> bool;
    /// Returns `true` if `additional_creators` is absent, or present as an
    /// array of strings each passing the same MXID grammar as `sender`
    /// (rule 1.4, V12+). Defaults to permissive (`true`) for content types
    /// that don't expose the raw array.
    fn additional_creators_are_valid(&self) -> bool {
        true
    }
    /// Returns the `join_authorised_via_users_server` field, if present.
    /// Used for `restricted`/`knock_restricted` join rules (room version 8+).
    fn get_join_authorised_via_users_server(&self) -> Option<&str>;

    /// Returns whether a `third_party_invite` field is present.
    fn has_third_party_invite(&self) -> bool {
        false
    }

    /// Returns the signed token from the `third_party_invite` field, if present.
    fn get_third_party_invite_token(&self) -> Option<&str> {
        None
    }

    /// Returns the mxid from the `third_party_invite` field, if present.
    fn get_third_party_invite_mxid(&self) -> Option<&str> {
        None
    }

    /// Check if signatures block exists in `third_party_invite.signed`.
    fn has_third_party_invite_signatures(&self) -> bool {
        false
    }

    /// Iterate over `(event_type, power_level)` entries in the `events` map.
    /// Used by Rule 10 PL validation to compare old vs new `events` entries.
    ///
    /// # Safety of empty default
    ///
    /// Returning an empty vec means "no entries exist" — the Rule 10 diff sees
    /// no changes and no escalation, so validation passes without bypassing
    /// anything.  The only production impl (`serde_json::Value`) overrides this.
    /// Custom implementations **must** override this for PL map validation to
    /// detect escalation in the `events` map.
    /// Visit `(event_type, power_level)` entries in the `events` map.
    /// Used by Rule 10 PL validation to compare old vs new `events` entries.
    fn visit_event_power_levels<'a>(&'a self, visitor: &mut dyn FnMut(&'a str, i64));

    /// Visit `(user_id, power_level)` entries in the `users` map.
    /// Used by Rule 10 PL validation to compare old vs new `users` entries.
    fn visit_user_power_levels<'a>(&'a self, visitor: &mut dyn FnMut(&'a str, i64));

    /// Visit `(key, power_level)` entries in the `notifications` map.
    /// Used by Rule 10.7–10.8 PL validation to compare old vs new `notifications`.
    fn visit_notification_power_levels<'a>(&'a self, visitor: &mut dyn FnMut(&'a str, i64));

    /// Rule 10.1 (V10+): Returns the name of any scalar PL property that is
    /// present but not an integer (or integer-coercible string).
    fn find_non_integer_scalar_pl(&self) -> Option<&'static str> {
        None
    }

    /// Rule 10.2 (V10+): Returns true if `events` or `notifications` is present
    /// but is not an object, or contains any non-integer values.
    fn find_non_integer_map_pl(&self) -> Option<&'static str> {
        None
    }

    /// Rule 10.3: Returns true if `users` is present but is not an object,
    /// or contains any non-integer values.  Unlike `find_non_integer_map_pl`,
    /// this applies to **all** room versions, not just V10+.
    fn has_non_integer_users_pl(&self, strict: bool) -> bool {
        let _ = strict;
        false
    }

    /// Visit all keys in the `users` map, regardless of value type.
    /// Used by Rule 10.4 to detect `additional_creators` even when their
    /// PL value is non-integer (and would be filtered by `visit_user_power_levels`).
    fn visit_user_keys<'a>(&'a self, visitor: &mut dyn FnMut(&'a str));

    /// Rule 10.4 (V12): Returns true if the `users` map contains the given user ID.
    fn has_user_in_users(&self, _user_id: &str) -> bool {
        false
    }
}

/// Caller-provided event verification pipeline.
///
/// Rezzy invokes these methods at the right points during auth checking.
/// The caller holds raw JSON, server keys, and crypto — rezzy holds none.
///
/// **Default impls return `Ok(())`** (skip verification). Override individual
/// methods to enable specific verification steps. Pass `None` instead of a
/// verifier to skip all verification entirely (e.g. during state resolution).
///
/// # Verification Steps
///
/// | Step | Method | What it verifies |
/// |------|--------|-----------------|
/// | 1 | [`verify_event_id_hash`](Self::verify_event_id_hash) | Event ID = SHA256(canonical JSON) (room v4+) |
/// | 2 | [`verify_signatures`](Self::verify_signatures) | Server ed25519 signatures on the PDU |
/// | 3 | [`verify_content_hash`](Self::verify_content_hash) | `hashes.sha256` matches canonical JSON hash |
/// | 4 | [`verify_third_party_invite`](Self::verify_third_party_invite) | 3PI `signed.signatures` against TPI public keys |
pub trait EventVerifier<Id> {
    /// Step 1: Verify event ID matches the SHA256 hash of the canonical JSON
    /// (with `signatures` and `unsigned` stripped). For room versions 4+.
    ///
    /// # Errors
    /// Return `Err(reason)` to reject the event.
    fn verify_event_id_hash(&self, _event_id: &Id) -> Result<(), alloc::string::String> {
        Ok(())
    }

    /// Step 2: Verify the event's server signatures against the origin server's
    /// ed25519 public keys.
    ///
    /// # Errors
    /// Return `Err(reason)` to reject the event.
    fn verify_signatures(&self, _event_id: &Id) -> Result<(), alloc::string::String> {
        Ok(())
    }

    /// Step 3: Verify the content hash (`hashes.sha256`) matches the computed
    /// hash of the canonical JSON.
    ///
    /// # Errors
    /// Return `Err(reason)` to reject the event.
    fn verify_content_hash(&self, _event_id: &Id) -> Result<(), alloc::string::String> {
        Ok(())
    }

    /// Step 4: Verify third-party invite signatures against the public keys
    /// from the referenced `m.room.third_party_invite` event.
    ///
    /// # Errors
    /// Return `Err(reason)` to reject the event.
    fn verify_third_party_invite(
        &self,
        _event_id: &Id,
        _tpi_token: &str,
    ) -> Result<(), alloc::string::String> {
        Ok(())
    }
}

impl EventContent for Value {
    fn get_membership(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_MEMBERSHIP)?
            .as_str()
    }

    fn get_join_rule(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_JOIN_RULE)?
            .as_str()
    }

    fn get_user_power_level(&self, user: &str) -> Option<i64> {
        let users = self
            .get(crate::basespec::event_types::FIELD_USERS)?
            .as_object()?;
        coerce_json_to_i64(users.get(user)?).map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_event_power_level(&self, event_type: &str) -> Option<i64> {
        let events = self
            .get(crate::basespec::event_types::FIELD_EVENTS)?
            .as_object()?;
        coerce_json_to_i64(events.get(event_type)?).map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_users_default(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_USERS_DEFAULT)?)
            .map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_events_default(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_EVENTS_DEFAULT)?)
            .map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_state_default(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_STATE_DEFAULT)?)
            .map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_ban(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_BAN)?)
            .map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_kick(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_KICK)?)
            .map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_invite(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_INVITE)?)
            .map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_redact(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_REDACT)?)
    }

    fn get_creator(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_CREATOR)?
            .as_str()
    }

    fn get_room_version(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_ROOM_VERSION)?
            .as_str()
    }

    fn get_m_federate(&self) -> Option<bool> {
        self.get("m.federate")?.as_bool()
    }

    fn get_redacts(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_REDACTS)?
            .as_str()
    }

    fn has_additional_creator(&self, sender: &str) -> bool {
        self.get(crate::basespec::event_types::FIELD_ADDITIONAL_CREATORS)
            .and_then(|v| v.as_array())
            .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some(sender)))
    }

    fn additional_creators_are_valid(&self) -> bool {
        match self.get(crate::basespec::event_types::FIELD_ADDITIONAL_CREATORS) {
            None => true,
            Some(v) => v.as_array().is_some_and(|arr| {
                arr.iter()
                    .all(|entry| entry.as_str().is_some_and(is_valid_mxid))
            }),
        }
    }

    fn get_join_authorised_via_users_server(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_JOIN_AUTHORISED_VIA_USERS_SERVER)?
            .as_str()
    }

    fn has_third_party_invite(&self) -> bool {
        self.get(crate::basespec::event_types::FIELD_THIRD_PARTY_INVITE)
            .is_some()
    }

    fn get_third_party_invite_token(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_THIRD_PARTY_INVITE)?
            .get(crate::basespec::event_types::FIELD_SIGNED)?
            .get(crate::basespec::event_types::FIELD_TOKEN)?
            .as_str()
    }

    fn get_third_party_invite_mxid(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_THIRD_PARTY_INVITE)?
            .get(crate::basespec::event_types::FIELD_SIGNED)?
            .get(crate::basespec::event_types::FIELD_MXID)?
            .as_str()
    }

    fn has_third_party_invite_signatures(&self) -> bool {
        self.get(crate::basespec::event_types::FIELD_THIRD_PARTY_INVITE)
            .and_then(|tpi| tpi.get(crate::basespec::event_types::FIELD_SIGNED))
            .and_then(|signed| signed.get(crate::basespec::event_types::FIELD_SIGNATURES))
            .and_then(|s| s.as_object())
            .is_some_and(|m| !m.is_empty())
    }

    fn visit_event_power_levels<'a>(&'a self, visitor: &mut dyn FnMut(&'a str, i64)) {
        if let Some(obj) = self
            .get(crate::basespec::event_types::FIELD_EVENTS)
            .and_then(|v| v.as_object())
        {
            for (k, v) in obj {
                if let Some(pl) = coerce_json_to_i64(v) {
                    visitor(k.as_str(), pl.min(MAX_POWER_LEVEL_JSON));
                }
            }
        }
    }

    fn visit_user_power_levels<'a>(&'a self, visitor: &mut dyn FnMut(&'a str, i64)) {
        if let Some(obj) = self
            .get(crate::basespec::event_types::FIELD_USERS)
            .and_then(|v| v.as_object())
        {
            for (k, v) in obj {
                if let Some(pl) = coerce_json_to_i64(v) {
                    visitor(k.as_str(), pl.min(MAX_POWER_LEVEL_JSON));
                }
            }
        }
    }

    fn visit_notification_power_levels<'a>(&'a self, visitor: &mut dyn FnMut(&'a str, i64)) {
        if let Some(obj) = self
            .get(crate::basespec::event_types::FIELD_NOTIFICATIONS)
            .and_then(|v| v.as_object())
        {
            for (k, v) in obj {
                if let Some(pl) = coerce_json_to_i64(v) {
                    visitor(k.as_str(), pl.min(MAX_POWER_LEVEL_JSON));
                }
            }
        }
    }

    fn find_non_integer_scalar_pl(&self) -> Option<&'static str> {
        use crate::basespec::event_types::{
            FIELD_BAN, FIELD_EVENTS_DEFAULT, FIELD_INVITE, FIELD_KICK, FIELD_REDACT,
            FIELD_STATE_DEFAULT, FIELD_USERS_DEFAULT,
        };
        let scalars: &[(&str, &'static str)] = &[
            (FIELD_USERS_DEFAULT, "users_default"),
            (FIELD_EVENTS_DEFAULT, "events_default"),
            (FIELD_STATE_DEFAULT, "state_default"),
            (FIELD_BAN, "ban"),
            (FIELD_REDACT, "redact"),
            (FIELD_KICK, "kick"),
            (FIELD_INVITE, "invite"),
        ];
        for &(field, label) in scalars {
            if let Some(val) = self.get(field) {
                // V10+ strict integer checking (forbids strings/floats)
                if !val.is_i64() && !val.is_u64() {
                    return Some(label);
                }
            }
        }
        None
    }

    fn find_non_integer_map_pl(&self) -> Option<&'static str> {
        use crate::basespec::event_types::{FIELD_EVENTS, FIELD_NOTIFICATIONS};
        let maps: &[(&str, &'static str)] = &[
            (FIELD_EVENTS, "events"),
            (FIELD_NOTIFICATIONS, "notifications"),
        ];
        for &(field, label) in maps {
            if let Some(val) = self.get(field) {
                let Some(obj) = val.as_object() else {
                    return Some(label);
                };

                for v in obj.values() {
                    // V10+ strict integer checking
                    if !v.is_i64() && !v.is_u64() {
                        return Some(label);
                    }
                }
            }
        }
        None
    }

    fn has_non_integer_users_pl(&self, strict: bool) -> bool {
        use crate::basespec::event_types::FIELD_USERS;
        if let Some(val) = self.get(FIELD_USERS) {
            if let Some(obj) = val.as_object() {
                for v in obj.values() {
                    if strict {
                        // V10+ strict integer checking
                        if !v.is_i64() && !v.is_u64() {
                            return true;
                        }
                    } else if coerce_json_to_i64(v).is_none() {
                        // V1-V9 allows coercible strings
                        return true;
                    }
                }
            } else {
                // `users` present but not an object
                return true;
            }
        }
        false
    }

    fn visit_user_keys<'a>(&'a self, visitor: &mut dyn FnMut(&'a str)) {
        if let Some(obj) = self
            .get(crate::basespec::event_types::FIELD_USERS)
            .and_then(|v| v.as_object())
        {
            for k in obj.keys() {
                visitor(k.as_str());
            }
        }
    }

    fn has_user_in_users(&self, user_id: &str) -> bool {
        self.get(crate::basespec::event_types::FIELD_USERS)
            .and_then(|v| v.as_object())
            .is_some_and(|obj| obj.contains_key(user_id))
    }
}

/// Returns `true` if `room_version`'s major version is 11 or later.
///
/// Mirrors Synapse's `strict_event_byte_limits_room_versions` flag
/// (`rust/src/room_versions.rs`): versions 1-10 inherit `false`, only v11
/// (and everything derived from it, e.g. v12) sets it `true`. Handles
/// dotted identifiers like `"12.1"` by comparing the leading major version.
/// Malformed/unparseable input is treated as pre-v11 (i.e. not strict) for
/// this byte-limit decision, but callers may still reject an unsupported
/// `room_version` before reaching this helper.
fn room_version_is_v11_or_later(room_version: &str) -> bool {
    room_version
        .split('.')
        .next()
        .and_then(|major| major.parse::<u32>().ok())
        .is_some_and(|major| major >= 11)
        || StateResVersion::from_room_version(room_version).is_some_and(|v| v.is_v2_1_plus())
}

fn is_msc4242_room_version(room_version: &str) -> bool {
    room_version == "org.matrix.msc4242.12"
}

/// Returns `true` if `room_version`'s major version is 12 or later (the
/// `org.matrix.hydra.11`/v12 event format where room IDs are hashes, MSC4291).
fn room_version_is_v12_or_later(room_version: &str) -> bool {
    room_version
        .split('.')
        .next()
        .and_then(|major| major.parse::<u32>().ok())
        .is_some_and(|major| major >= 12)
        || StateResVersion::from_room_version(room_version).is_some_and(|v| v.is_v2_1_plus())
}

/// Returns `true` if `id` is a syntactically valid Matrix user ID: `@` prefix,
/// a `:` separating localpart from domain, a non-empty localpart drawn from
/// the restricted charset (`a-z`, `0-9`, `.`, `_`, `=`, `-`, `/`, `+`), and a
/// non-empty domain.
///
/// Shared by the `sender` check and, for V12+ rooms, `additional_creators`
/// entries — both are held to the same grammar per MSC4289.
pub(crate) fn is_valid_mxid(id: &str) -> bool {
    let Some((localpart, domain)) = id.strip_prefix('@').and_then(|rest| rest.split_once(':'))
    else {
        return false;
    };
    !localpart.is_empty()
        && !domain.is_empty()
        && localpart.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'_' | b'=' | b'-' | b'/' | b'+')
        })
}

/// Extracts the domain (server name) portion of a Matrix identifier (e.g. `@user:example.com` -> `example.com`,
/// `!room:example.com:8448` -> `example.com:8448`).
///
/// Returns `None` if there is no `:` in the identifier.
#[must_use]
pub fn extract_domain(id: &str) -> Option<&str> {
    id.split_once(':').map(|(_, domain)| domain)
}

/// Assign every event a dense `usize` index keyed by its `event_id`, in
/// iteration order.
///
/// Shared by the CLI formatter and the stress tests, which previously
/// copy-pasted this exact loop. Indices are assigned in iteration order, so a
/// caller that also collects the same events in the same order can address the
/// events directly by index.
#[must_use]
pub fn index_by_event_id<'a>(
    events: impl IntoIterator<Item = &'a LeanEvent>,
) -> crate::HashMap<&'a str, usize> {
    let iter = events.into_iter();
    let mut index = crate::HashMap::with_capacity(iter.size_hint().0);
    for (i, ev) in iter.enumerate() {
        index.insert(ev.event_id.as_str(), i);
    }
    index
}

/// Returns `true` if `id1` and `id2` have matching domains (ASCII case-insensitive match).
///
/// If a string lacks a `:` prefix (e.g. `"example.com"` as in `m.room.aliases` state keys),
/// it is treated directly as the domain.
#[must_use]
pub fn domain_matches(id1: &str, id2: &str) -> bool {
    let d1 = extract_domain(id1).unwrap_or(id1);
    let d2 = extract_domain(id2).unwrap_or(id2);
    !d1.is_empty() && !d2.is_empty() && d1.eq_ignore_ascii_case(d2)
}

impl<Id, C, K> LeanEvent<Id, C, K> {
    /// Validates basic syntactic limits (`prev_events`, `auth_events` array sizes).
    ///
    /// NOTE: Event types are NOT whitelisted — the spec does not restrict types at the auth level.
    /// Any event type is valid as long as the sender has sufficient PL.
    ///
    /// Per Synapse parity, the 255-byte length limits on `event_id`/`sender`/
    /// `event_type`/`state_key` are only hard-enforced for room version 11+
    /// (`strict_event_byte_limits_room_versions`); for earlier versions a
    /// violation is logged (via `eprintln!`, `std` feature only) rather than
    /// rejected, to avoid breaking pre-existing rooms with legacy oversized
    /// fields.
    ///
    /// # TODO(compliance): PDU structural invariants not yet enforced
    ///
    /// - `content` is required (must be present, even if `{}`)
    /// - `hashes` is required (sha256 content hash)
    /// - `signatures` is required
    /// - `room_id` is version-dependent (present in v1-v11, omitted from create in v12+);
    ///   `LeanEvent` has no `room_id` field, so its length limit isn't checked here
    ///
    /// These should be validated and tested per room version.
    ///
    /// # Errors
    /// Returns an error if the event violates spec invariants (e.g. >20 `prev_events`).
    ///
    /// The `Ok` side carries a [`crate::warnings::Outcome`] rather than a
    /// bare `()`: the pre-v11 byte-limit case below is not itself a spec
    /// violation (Synapse only warns pre-v11 too, deliberately, to avoid
    /// splitting the DAG against legacy oversized fields already baked into
    /// existing room history) -- it's a condition the caller may want to
    /// know about and apply its own policy to, not one rezzy hard-fails on.
    /// See [`crate::warnings`]'s module docs for the full rationale.
    pub fn validate_syntactic(
        &self,
        room_version: &str,
    ) -> Result<crate::warnings::Outcome<(), Id>, &'static str>
    where
        Id: core::fmt::Display + Clone,
        C: EventContent,
        K: AsRef<str>,
    {
        let mut warnings = alloc::vec::Vec::new();
        if StateResVersion::from_room_version(room_version).is_none() {
            return Err("unsupported room_version");
        }
        if self.prev_events.len() > 20 {
            return Err("prev_events exceeds maximum allowed length of 20");
        }
        let is_msc4242 = matches!(
            StateResVersion::from_room_version(room_version),
            Some(StateResVersion::V2_2)
        );
        if !is_msc4242 && self.auth_events.len() > 10 {
            return Err("auth_events exceeds maximum allowed length of 10");
        }
        if is_msc4242
            && self.auth_events.len() > crate::basespec::event_types::MAX_PREV_STATE_EVENTS
        {
            return Err("prev_state_events exceeds maximum allowed length of 20");
        }
        if self.event_type.is_empty() {
            return Err("event_type cannot be empty");
        }
        // Rule 1.3: an `m.room.create` event must not declare an unrecognised
        // `content.room_version`. Absent room_version defaults to "1" per spec,
        // so only a *present but unrecognised* value is rejected here.
        if self.event_type == crate::basespec::event_types::M_ROOM_CREATE {
            if let Some(v) = self.content.get_room_version() {
                if StateResVersion::from_room_version(v).is_none() {
                    return Err(
                        "m.room.create content.room_version is not a recognised room version",
                    );
                }
            }
        }
        let id_str = alloc::format!("{}", self.event_id);
        if id_str.is_empty() || !id_str.starts_with('$') {
            return Err("event_id must start with '$'");
        }
        if !is_valid_mxid(&self.sender) {
            return Err(
                "sender must be a valid MXID: '@' prefix, ':' separator, non-empty domain, and a localpart of only a-z, 0-9, '.', '_', '=', '-', '/', '+'",
            );
        }
        // Rule 1.4: pre-v12 m.room.create must declare a `creator`; v12+
        // instead derives creators from `sender` + `additional_creators`,
        // and validates any `additional_creators` entries against the same
        // MXID grammar as `sender`.
        if self.event_type == crate::basespec::event_types::M_ROOM_CREATE {
            let is_v12_plus =
                StateResVersion::from_room_version(room_version).is_some_and(|v| v.is_v2_1_plus());
            if is_v12_plus {
                if !self.content.additional_creators_are_valid() {
                    return Err(
                        "m.room.create content.additional_creators must be an array of valid MXID strings",
                    );
                }
            } else {
                let Some(creator) = self.content.get_creator() else {
                    return Err("m.room.create content must have a 'creator' property");
                };
                if !is_valid_mxid(creator) {
                    return Err("m.room.create content.creator must be a valid MXID string");
                }
            }
        }
        if self.depth > MAX_SAFE_JSON_INTEGER {
            return Err("depth exceeds maximum allowed value");
        }

        let strict_length_limits = room_version_is_v11_or_later(room_version);
        macro_rules! check_length {
            ($field:expr, $name:literal) => {
                let len = $field.len();
                if len > 255 {
                    if strict_length_limits {
                        return Err(concat!(
                            $name,
                            " exceeds maximum allowed length of 255 bytes"
                        ));
                    }
                    warnings.push(crate::warnings::Warning::OversizedFieldPreV11 {
                        event_id: self.event_id.clone(),
                        field: $name,
                        len,
                        limit: 255,
                    });
                }
            };
        }
        check_length!(id_str, "event_id");
        check_length!(self.sender, "sender");
        check_length!(self.event_type, "event_type");
        // NOTE: For Synapse parity, v11+ hard-enforces this the same as the other
        // fields above; state_key is optional (only present on state events), so
        // this branch is skipped entirely for non-state events.
        if let Some(ref state_key) = self.state_key {
            check_length!(state_key.as_ref(), "state_key");
        }

        Ok(crate::warnings::Outcome::with_warnings((), warnings))
    }

    // --- Typed Content Accessors (delegate to EventContent) ---

    /// Get the membership state of this event.
    pub fn get_membership(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_membership()
    }

    /// Get the join rule of this event.
    pub fn get_join_rule(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_join_rule()
    }

    /// Get the authorized via users server for a join rule.
    pub fn get_join_authorised_via_users_server(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_join_authorised_via_users_server()
    }

    /// Get the power level of a specific user.
    pub fn get_user_power_level(&self, user: &str) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_user_power_level(user)
    }

    /// Get the power level requirement for a specific event type.
    pub fn get_event_power_level(&self, event_type: &str) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_event_power_level(event_type)
    }

    /// Get the default power level for users.
    pub fn get_users_default(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_users_default()
    }

    /// Get the default power level for events.
    pub fn get_events_default(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_events_default()
    }

    /// Get the default power level for state events.
    pub fn get_state_default(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_state_default()
    }

    /// Get the power level required to ban.
    pub fn get_ban(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_ban()
    }

    /// Get the power level required to kick.
    pub fn get_kick(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_kick()
    }

    /// Get the power level required to invite.
    pub fn get_invite(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_invite()
    }

    /// Get the power level required to redact.
    pub fn get_redact(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_redact()
    }

    /// Get the creator of the room.
    pub fn get_creator(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_creator()
    }

    /// Get the room version.
    pub fn get_room_version(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_room_version()
    }

    /// Get the event ID this event redacts.
    pub fn get_redacts(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_redacts()
    }

    /// Whether this event is an `m.room.redaction` carrying a `redacts` field.
    ///
    /// Callers can use this to cheaply detect that a batch contains redaction
    /// work before deciding whether to run
    /// [`crate::auth::apply_authorized_redactions`] against the resolved state.
    pub fn is_redaction(&self) -> bool
    where
        C: EventContent,
    {
        self.event_type == M_ROOM_REDACTION && self.get_redacts().is_some()
    }

    /// Check if the sender is an additional creator.
    pub fn has_additional_creator(&self, sender: &str) -> bool
    where
        C: EventContent,
    {
        self.content.has_additional_creator(sender)
    }
}

impl LeanEvent<String, Value, String> {
    /// Parses a lean event from a raw PDU `Value`, optionally deriving a
    /// missing `event_id` from the room version's reference hash (see
    /// [`reference_hash`]).
    ///
    /// This performs **parsing only — not content-hash/signature verification**.
    /// Verification is a homeserver ingest responsibility, invoked via
    /// [`verify_content_hash`] (or the [`EventVerifier`] hook) on the raw PDU
    /// *before* calling this; `from_value` does not auto-verify so it remains
    /// usable on partial PDUs and after the homeserver has already checked.
    ///
    /// # Errors
    /// Returns `Err` when `event_type` is empty/missing, `power_level` has an
    /// unsupported type, `depth` is invalid, an `m.room.redaction` has a
    /// malformed/mismatched `redacts`, or an `event_id` is absent while no
    /// `room_version` is given (or the reference hash cannot be computed).
    #[allow(clippy::too_many_lines)]
    pub fn from_value(
        value: &Value,
        room_version: Option<&str>,
    ) -> Result<LeanEvent<String, Value, String>, serde_json::Error> {
        use crate::basespec::event_types::{
            FIELD_AUTH_EVENTS, FIELD_CONTENT, FIELD_DEPTH, FIELD_EVENT_ID, FIELD_ORIGIN_SERVER_TS,
            FIELD_POWER_LEVEL, FIELD_PREV_EVENTS, FIELD_REDACTS, FIELD_REJECTED, FIELD_SENDER,
            FIELD_SOFT_FAIL, FIELD_STATE_KEY, FIELD_TYPE, M_ROOM_REDACTION,
        };

        let event_id = if let Some(id) = value.get(FIELD_EVENT_ID).and_then(|v| v.as_str()) {
            String::from(id)
        } else if let Some(ver) = room_version {
            let rh = reference_hash(value, ver).map_err(serde::de::Error::custom)?;
            alloc::format!("${rh}")
        } else {
            return Err(serde::de::Error::custom(
                "event_id is required; pass `room_version` to `from_value` to derive it via the reference hash",
            ));
        };

        let event_type: String = value
            .get(FIELD_TYPE)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into();

        if event_type.is_empty() {
            return Err(serde::de::Error::custom(
                "event_type cannot be missing or empty",
            ));
        }
        let state_key = value
            .get(FIELD_STATE_KEY)
            .and_then(|v| v.as_str())
            .map(String::from);

        let power_level = match value.get(FIELD_POWER_LEVEL) {
            Some(pl) => {
                if let Some(i) = pl.as_i64() {
                    i.min(MAX_POWER_LEVEL_JSON)
                } else if let Some(u) = pl.as_u64() {
                    let i = i64::try_from(u).unwrap_or(MAX_POWER_LEVEL_JSON);
                    i.min(MAX_POWER_LEVEL_JSON)
                } else if let Some(s) = pl.as_str() {
                    if let Ok(i) = s.parse::<i64>() {
                        i.min(MAX_POWER_LEVEL_JSON)
                    } else {
                        0
                    }
                } else {
                    return Err(serde::de::Error::custom("invalid power_level type"));
                }
            }
            None => 0,
        };

        let origin_server_ts = match value.get(FIELD_ORIGIN_SERVER_TS) {
            Some(ts) => ts.as_u64().unwrap_or(0),
            None => 0,
        };

        let sender = value
            .get(FIELD_SENDER)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into();
        let mut content = value.get(FIELD_CONTENT).cloned().unwrap_or(Value::Null);

        if event_type == M_ROOM_REDACTION {
            let top_level_redacts = match value.get(FIELD_REDACTS) {
                Some(redacts) => Some(redacts.as_str().ok_or_else(|| {
                    serde::de::Error::custom("m.room.redaction redacts must be a string")
                })?),
                None => None,
            };

            match &mut content {
                Value::Object(obj) => {
                    if let Some(existing_redacts) = obj.get(FIELD_REDACTS) {
                        let existing_redacts = existing_redacts.as_str().ok_or_else(|| {
                            serde::de::Error::custom(
                                "m.room.redaction content.redacts must be a string",
                            )
                        })?;
                        if let Some(top_level_redacts) = top_level_redacts {
                            if existing_redacts != top_level_redacts {
                                return Err(serde::de::Error::custom(
                                    "m.room.redaction redacts mismatch between top-level field and content",
                                ));
                            }
                        }
                    } else if let Some(top_level_redacts) = top_level_redacts {
                        obj.insert(
                            String::from(FIELD_REDACTS),
                            Value::String(String::from(top_level_redacts)),
                        );
                    }
                }
                Value::Null => {
                    if let Some(top_level_redacts) = top_level_redacts {
                        let mut obj = serde_json::Map::new();
                        obj.insert(
                            String::from(FIELD_REDACTS),
                            Value::String(String::from(top_level_redacts)),
                        );
                        content = Value::Object(obj);
                    }
                }
                _ => {
                    return Err(serde::de::Error::custom(
                        "m.room.redaction content must be an object or null",
                    ));
                }
            }
        }

        let parse_string_array = |key: &str| -> Vec<String> {
            value
                .get(key)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };

        let prev_events = parse_string_array(FIELD_PREV_EVENTS);
        let auth_events = value
            .get(FIELD_AUTH_EVENTS)
            .map(|_| parse_string_array(FIELD_AUTH_EVENTS))
            .or_else(|| {
                room_version
                    .filter(|version| is_msc4242_room_version(version))
                    .map(|_| {
                        parse_string_array(crate::basespec::event_types::FIELD_PREV_STATE_EVENTS)
                    })
            })
            .unwrap_or_default();
        let depth = match value.get(FIELD_DEPTH) {
            Some(depth) => depth
                .as_u64()
                .ok_or_else(|| serde::de::Error::custom("invalid depth value"))?,
            None => 0,
        };

        let rejected = value
            .get(FIELD_REJECTED)
            .or_else(|| value.get("rejected"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let soft_fail = value
            .get(FIELD_SOFT_FAIL)
            .or_else(|| value.get("soft_fail"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        Ok(LeanEvent {
            event_id,
            event_type,
            state_key,
            power_level,
            origin_server_ts,
            sender,
            content,
            prev_events,
            auth_events,
            depth,
            rejected,
            soft_fail,
            // Deliberately not read from `value`: the whole point of
            // `room_id` is to check an event against a room the *caller*
            // already knows and trusts, not to trust whatever room a raw
            // PDU JSON claims for itself -- deriving it from the same
            // untrusted payload it's meant to validate would defeat that.
            // Callers that want it populated do so explicitly (e.g.
            // `ingest_events`), after this deserialize step.
            room_id: None,
        })
    }
}

impl<'de> Deserialize<'de> for LeanEvent<String, Value, String> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        LeanEvent::from_value(&value, None).map_err(serde::de::Error::custom)
    }
}

impl<Id: PartialEq, C, K> PartialEq for LeanEvent<Id, C, K> {
    fn eq(&self, other: &Self) -> bool {
        self.event_id == other.event_id
    }
}

impl<Id: Eq, C, K> Eq for LeanEvent<Id, C, K> {}

impl<Id: Ord, C, K> Ord for LeanEvent<Id, C, K> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.event_id.cmp(&other.event_id)
    }
}

impl<Id: Ord, C, K> PartialOrd for LeanEvent<Id, C, K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<Id, C: EventContent, K: AsRef<str>> LeanEvent<Id, C, K> {
    /// Returns `true` if this event is a ban (`membership: "ban"`) or a kick
    /// (`membership: "leave"` where `state_key ≠ sender`).
    ///
    /// Self-leaves (where the user removes themselves) return `false`.
    #[must_use]
    pub fn is_ban_or_kick(&self) -> bool {
        if self.event_type == crate::basespec::event_types::M_ROOM_MEMBER {
            if let Some(membership) = self.get_membership() {
                if membership == crate::basespec::event_types::MEM_BAN
                    || membership == crate::basespec::event_types::MEM_LEAVE
                {
                    if let Some(ref state_key) = self.state_key {
                        return state_key.as_ref() != self.sender.as_str();
                    }
                }
            }
        }
        false
    }

    /// Returns `true` if this event is a "power event" — one that affects the
    /// room's administrative state and must go through the full power-phase
    /// resolution pipeline.
    ///
    /// Power events are:
    /// - `m.room.create`
    /// - `m.room.power_levels`
    /// - `m.room.join_rules`
    /// - `m.room.member` events that are bans or kicks (V2.1+), or
    ///   **all** member events (V2 and below)
    #[must_use]
    pub fn is_power_event(&self, version: crate::basespec::rezzy_types::StateResVersion) -> bool {
        self.event_type == crate::basespec::event_types::M_ROOM_CREATE
            || self.event_type == crate::basespec::event_types::M_ROOM_POWER_LEVELS
            || self.event_type == crate::basespec::event_types::M_ROOM_JOIN_RULES
            || if matches!(
                version,
                crate::basespec::rezzy_types::StateResVersion::V2_1
                    | crate::basespec::rezzy_types::StateResVersion::V2_1_1
                    | crate::basespec::rezzy_types::StateResVersion::V2_2
            ) {
                self.is_ban_or_kick()
            } else {
                self.event_type == crate::basespec::event_types::M_ROOM_MEMBER
            }
    }

    /// Returns `true` if this is a `m.room.power_levels` event (a potential demotion).
    #[must_use]
    pub fn is_demotion(&self) -> bool {
        self.event_type == crate::basespec::event_types::M_ROOM_POWER_LEVELS
    }

    /// Returns `true` if this is a `m.room.join_rules` event setting the room to invite-only.
    #[must_use]
    pub fn is_lockdown(&self) -> bool {
        self.event_type == crate::basespec::event_types::M_ROOM_JOIN_RULES
            && self
                .get_join_rule()
                .is_some_and(|rule| rule == crate::basespec::event_types::RULE_INVITE)
    }

    /// Returns `true` if this event restricts the given `sender` — either by
    /// banning/kicking them or by demoting their power level to zero.
    #[must_use]
    pub fn restricts_sender(&self, sender: &str) -> bool {
        if self.is_ban_or_kick() {
            return self.state_key.as_ref().map(AsRef::as_ref) == Some(sender);
        }
        if self.is_demotion() {
            return self.get_user_power_level(sender) == Some(0);
        }
        false
    }

    /// Returns `true` if this administrative event causally restricts `other`.
    ///
    /// Checks whether `self` is a ban/kick/demotion targeting `other`'s sender,
    /// or a join-rules lockdown that blocks `other`'s join attempt.
    #[must_use]
    pub fn restricts_event(&self, other: &LeanEvent<Id, C, K>) -> bool {
        if self.is_ban_or_kick() || self.is_demotion() {
            return self.restricts_sender(&other.sender);
        }
        self.is_lockdown()
            && other.event_type == crate::basespec::event_types::M_ROOM_MEMBER
            && other
                .get_membership()
                .is_some_and(|m| m == crate::basespec::event_types::MEM_JOIN)
    }
}

impl<Id: Ord, C, K> LeanEvent<Id, C, K> {
    /// Deterministic ordering: depth ascending, then `event_id` ascending.
    /// Use this instead of `sort_by_key(|ev| ev.depth)` to avoid
    /// non-determinism from `HashMap` iteration order on equal depths.
    #[must_use]
    pub fn cmp_by_depth(&self, other: &Self) -> Ordering {
        self.depth
            .cmp(&other.depth)
            .then(self.event_id.cmp(&other.event_id))
    }
}

/// A priority wrapper for [`BinaryHeap`](alloc::collections::BinaryHeap)-based
/// topological sorting of events.
///
/// Rust's `BinaryHeap` is a **max-heap** — the element with the greatest `Ord`
/// value is popped first. In state resolution, the *worst* (lowest-priority)
/// event must be applied first so that better events overwrite it via
/// last-write-wins. Therefore:
///
/// - **V1**: Greater = deeper depth (applied first -> loses).
/// - **V2+**: Greater = higher PL (applied first -> sets auth context, then
///   lower-PL events overwrite for same-key conflicts).
///
/// See the [`Ord`] implementation for the full tie-breaking cascade.
#[derive(Debug)]
pub struct SortPriority<'a, E = LeanEvent<String, Value>> {
    /// Reference to the event being sorted.
    pub event: &'a E,
    /// The sender's power level, derived from the auth chain (not `event.power_level`).
    pub power_level: i64,
    /// The resolution version, which selects the comparison strategy.
    pub version: StateResVersion,
}

impl<E> Clone for SortPriority<'_, E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E> Copy for SortPriority<'_, E> {}

impl<E: EventLike> PartialEq for SortPriority<'_, E> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<E: EventLike> Eq for SortPriority<'_, E> {}

impl<E: EventLike> Ord for SortPriority<'_, E> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.version != other.version {
            return self.version.cmp(&other.version);
        }

        match self.version {
            StateResVersion::V1 => {
                // Matrix Spec - State Resolution v1:
                // "First we resolve conflicts between m.room.power_levels events...
                //  If there is a tie, we resolve it by comparing the events' depths
                //  and then their event IDs."
                //
                // In Rust's Max-Heap BinaryHeap, "greater" elements are popped first.
                // We want deeper events to pop FIRST, so they must be "greater".
                // NOTE: This is a defense-in-depth vulnerability, which V2 fixes.
                match self.event.depth().cmp(&other.event.depth()) {
                    Ordering::Equal => self.event.event_id().cmp(other.event.event_id()),
                    ord => ord,
                }
            }
            StateResVersion::V2
            | StateResVersion::V2_1
            | StateResVersion::V2_1_1
            | StateResVersion::V2_2 => {
                // V2 reverse topological power ordering: worst events pop FIRST.
                //
                // Ruma uses Reverse(TieBreaker) on a BinaryHeap where TieBreaker.cmp is:
                //   other.pl.cmp(&self.pl)  -> higher PL = smaller TieBreaker -> larger Reverse -> pops first
                //   self.ts.cmp(&other.ts)  -> earlier ts = smaller TieBreaker -> larger Reverse -> pops first
                //   self.id.cmp(&other.id)  -> smaller id = smaller TieBreaker -> larger Reverse -> pops first
                //
                // In our direct max-heap (no Reverse) we invert each: Greater = pops first.
                //   higher PL -> Greater  -> use self.pl.cmp(&other.pl)
                //   earlier ts -> Greater -> use other.ts.cmp(&self.ts)
                //   smaller id -> Greater -> use other.id.cmp(&self.id)
                //
                // Net result: high-PL events pop first (losing for same-key conflicts but
                // setting auth context before lower-PL events are checked — this is what
                // makes Alice's ban appear before Bob's concurrent PL change).
                match self.power_level.cmp(&other.power_level) {
                    Ordering::Equal => {
                        match other
                            .event
                            .origin_server_ts()
                            .cmp(&self.event.origin_server_ts())
                        {
                            Ordering::Equal => other.event.event_id().cmp(self.event.event_id()),
                            ord => ord,
                        }
                    }
                    ord => ord,
                }
            }
        }
    }
}

impl<E: EventLike> PartialOrd for SortPriority<'_, E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Coerces JSON values to `i64` (accepts `ints`, `uints`, or string-encoded ints).
///
/// Returns `None` if the value cannot be interpreted as an integer.
/// This three-way coercion handles the real-world inconsistency where some
/// homeservers encode power levels as strings in their JSON.
///
/// FUN FACT: Room versions 1-9 actually allowed power levels to be floats
/// and strings in the JSON, which is why `rezzy` has this `coerce_json_to_i64`
/// function in the first place!
#[must_use]
// Truncating a legacy float power level toward zero is intentional, and Rust's
// `f64 as i64` is saturating (no UB out of range), so the casts are deliberate.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
pub fn coerce_json_to_i64(pl: &Value) -> Option<i64> {
    let val = pl
        .as_i64()
        .or_else(|| pl.as_u64().map(|u| i64::try_from(u).unwrap_or(i64::MAX)))
        // Legacy float power levels (e.g. 50.0) — truncate toward zero.
        .or_else(|| {
            pl.as_f64().and_then(|f| {
                // `Number::from_f64(...).as_i64()` can't be used here: serde_json
                // returns `None` for float-backed numbers. Truncate the f64 and
                // range-check before casting instead.
                let t = f.trunc();
                (t >= i64::MIN as f64 && t <= i64::MAX as f64).then_some(t as i64)
            })
        })
        .or_else(|| pl.as_str().and_then(|s| s.parse::<i64>().ok()));
    // Matrix Spec (Client-Server API) — m.room.power_levels:
    // "The power level ... must be an integer between -2^53 + 1 and 2^53 - 1."
    val.map(|v| v.clamp(-MAX_POWER_LEVEL_JSON, MAX_POWER_LEVEL_JSON))
}

/// Lookup trait for retrieving events by ID during sorting and auth checks.
pub trait EventProvider<Id, C, E = LeanEvent<Id, C>> {
    fn get_event(&self, id: &Id) -> Option<&E>;
}

impl<
        Id: core::hash::Hash + Eq,
        C,
        E: EventLike<Id = Id, Content = C>,
        S: core::hash::BuildHasher,
    > EventProvider<Id, C, E> for crate::HashMap<Id, E, S>
{
    fn get_event(&self, id: &Id) -> Option<&E> {
        self.get(id)
    }
}

impl<Id: core::hash::Hash + Eq + Ord, C, E: EventLike<Id = Id, Content = C>> EventProvider<Id, C, E>
    for alloc::collections::BTreeMap<Id, E>
{
    fn get_event(&self, id: &Id) -> Option<&E> {
        self.get(id)
    }
}

/// Merged event lookup across the conflicted set and auth context.
pub struct SortContext<'a, Id, C, S1, S2, E = LeanEvent<Id, C>> {
    pub primary: &'a crate::HashMap<Id, E, S1>,
    pub secondary: &'a crate::HashMap<Id, E, S2>,
    pub _marker: core::marker::PhantomData<C>,
}

impl<
        Id: core::hash::Hash + Eq,
        C,
        S1: core::hash::BuildHasher,
        S2: core::hash::BuildHasher,
        E: EventLike<Id = Id, Content = C>,
    > EventProvider<Id, C, E> for SortContext<'_, Id, C, S1, S2, E>
{
    fn get_event(&self, id: &Id) -> Option<&E> {
        self.primary.get(id).or_else(|| self.secondary.get(id))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod redaction_preserved_keys_tests {
    use super::{redaction_preserved_keys, RedactionRule};

    /// `org.matrix.msc4242.12` is one of the unstable room-version identifiers
    /// recognized by [`RoomVersion::from_str`] (mapped to `V2_2`, whose
    /// serialization format is v12's). Its redaction rules must therefore
    /// match v12's (i.e. v11's, verbatim) rather than falling through to the
    /// fail-closed `RedactionRule::None` default for unrecognized versions.
    #[test]
    fn test_redaction_preserved_keys_recognizes_msc4242_12_as_v11_rules() {
        assert_eq!(
            redaction_preserved_keys(
                crate::basespec::event_types::M_ROOM_CREATE,
                "org.matrix.msc4242.12"
            ),
            RedactionRule::All
        );
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod redact_content_tests {
    use super::{redact_content, RedactionRule};
    use serde_json::json;

    /// Coverage for `redact_content`'s "existing parent" accumulation branch
    /// (a second dotted-path key merging into a parent object already
    /// populated by an earlier one): no real `redaction_preserved_keys`
    /// rule table has two dotted paths sharing a parent today (`Keys`
    /// exercised through `redact_json` -- see `test_redact_json_preserves_dotted_nested_key`
    /// in `tests/unit/test_hashing.rs` -- only ever has one:
    /// `third_party_invite.signed`), so this branch is unreachable through
    /// the public API. `redact_content` is private but its accumulation
    /// logic is real, general-purpose behavior independent of what today's
    /// rule tables happen to use -- exercised directly here with a synthetic
    /// two-key rule instead of leaving it permanently uncovered.
    #[test]
    fn test_coverage_redact_content_accumulates_multiple_dotted_keys_under_one_parent() {
        let content = json!({
            "parent": {
                "a": 1,
                "b": 2,
                "c": 3,
            }
        });
        let rule = RedactionRule::Keys(&["parent.a", "parent.b"]);
        let redacted = redact_content(&content, rule);
        assert_eq!(redacted, json!({ "parent": { "a": 1, "b": 2 } }));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod redact_top_level_tests {
    use super::redact_top_level;
    use serde_json::json;

    /// MSC4242's unstable `org.matrix.msc4242.12` room version swaps
    /// `auth_events` for `prev_state_events`. Redaction must preserve the
    /// swapped-in field so events signed under that format keep their
    /// hashes/signatures valid; stable v11/v12 events (which never carry it)
    /// must remain unaffected.
    #[test]
    fn preserves_prev_state_events_for_msc4242_room_version() {
        let ev = json!({
            "type": "m.room.message",
            "content": { "body": "hi" },
            "auth_events": ["$A"],
            "prev_state_events": ["$B"],
            "depth": 5,
            "foo": "dropped",
        });
        let redacted = redact_top_level(&ev, "org.matrix.msc4242.12");
        assert_eq!(redacted.get("prev_state_events"), Some(&json!(["$B"])));
        assert_eq!(redacted.get("auth_events"), Some(&json!(["$A"])));
        assert!(redacted.get("foo").is_none());
    }

    #[test]
    fn stable_v12_events_are_unaffected() {
        let ev = json!({
            "type": "m.room.message",
            "content": { "body": "hi" },
            "auth_events": ["$A"],
            "foo": "dropped",
        });
        let redacted = redact_top_level(&ev, "12");
        assert_eq!(redacted.get("auth_events"), Some(&json!(["$A"])));
        assert!(redacted.get("prev_state_events").is_none());
        assert!(redacted.get("foo").is_none());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod index_by_event_id_tests {
    use super::*;

    /// `index_by_event_id` assigns indices in iteration order, keyed by each
    /// event's `event_id`.
    #[test]
    fn test_index_by_event_id_assigns_indices_in_iteration_order() {
        let events = [
            LeanEvent {
                event_id: "$c:example".into(),
                ..Default::default()
            },
            LeanEvent {
                event_id: "$a:example".into(),
                ..Default::default()
            },
            LeanEvent {
                event_id: "$b:example".into(),
                ..Default::default()
            },
        ];
        let index = index_by_event_id(events.iter());
        assert_eq!(index.len(), 3);
        assert_eq!(index.get("$c:example"), Some(&0));
        assert_eq!(index.get("$a:example"), Some(&1));
        assert_eq!(index.get("$b:example"), Some(&2));
    }

    /// Duplicate `event_id`s collapse: the later occurrence wins, matching
    /// the insert-based build the formatter and stress test rely on.
    #[test]
    fn test_index_by_event_id_keeps_last_duplicate_index() {
        let events = [
            LeanEvent {
                event_id: "$a:example".into(),
                ..Default::default()
            },
            LeanEvent {
                event_id: "$a:example".into(),
                ..Default::default()
            },
            LeanEvent {
                event_id: "$b:example".into(),
                ..Default::default()
            },
        ];
        let index = index_by_event_id(events.iter());
        assert_eq!(index.len(), 2);
        assert_eq!(index.get("$a:example"), Some(&1));
        assert_eq!(index.get("$b:example"), Some(&2));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod canonical_parity_tests {
    use super::*;
    use alloc::string::String;
    use serde_json::json;

    fn content_hash_writer(v: &Value) -> String {
        let mut out = String::new();
        write_content_hash_canonical(&mut out, v).expect("infallible");
        out
    }

    fn content_hash_serde(v: &Value) -> String {
        let mut c = v.clone();
        if let Some(o) = c.as_object_mut() {
            o.remove("unsigned");
            o.remove("signatures");
            o.remove("hashes");
        }
        serde_json::to_string(&c).expect("infallible")
    }

    fn redacted_writer(v: &Value, rv: &str) -> String {
        let mut out = String::new();
        write_redacted_canonical(&mut out, v, rv).expect("infallible");
        out
    }

    fn redacted_serde(v: &Value, rv: &str) -> String {
        let mut r = redact_json(v, rv);
        if let Some(o) = r.as_object_mut() {
            o.remove("unsigned");
            o.remove("signatures");
        }
        serde_json::to_string(&r).expect("infallible")
    }

    /// The zero-copy writers must be byte-identical to what `serde_json` emits
    /// for the same logical canonical form — hashes/signatures cover these exact
    /// bytes, so any divergence is a federation-breaking bug.
    #[test]
    fn content_hash_writer_is_byte_identical_to_serde() {
        let cases = [
            json!({ "type":"m.room.message","room_id":"!r:x","sender":"@a:x","origin_server_ts":1,"content":{"body":"hi"},"hashes":{"sha256":"abc"},"unsigned":{"age_ts":5},"signatures":{"x":{"ed25519:0":"sig"}} }),
            json!({ "a":1,"b":{"c":[1,2,3],"d":"x\ny\tz\u{0001}\u{000c}\u{000d}"},"e":1.5,"f":null,"g":true }),
            json!({ "s":"unicode \u{e9}\u{fc} \u{1F600}","ctrl":"\u{0000}\u{001f}","q":"\"quoted\"","bs":"a\\b" }),
            json!({ "negative":-42,"big":9_007_199_254_740_993_u64,"float":-0.0,"arr":[true,false,null,1] }),
        ];
        for c in cases {
            assert_eq!(content_hash_writer(&c), content_hash_serde(&c), "case: {c}");
        }

        let mut output = String::new();
        write_content_hash_canonical(&mut output, &json!(null)).unwrap();
        assert_eq!(output, "{}");
        output.clear();
        write_redacted_canonical(&mut output, &json!(["non-object content"]), "11").unwrap();
        assert_eq!(output, "{}");
    }

    #[test]
    fn redacted_writer_is_byte_identical_to_serde() {
        let cases = [
            (
                json!({ "type":"m.room.message","room_id":"!r:x","sender":"@a:x","origin_server_ts":1,"content":{"body":"hi","extra":"x"},"hashes":{"sha256":"abc"},"unsigned":{"age_ts":5},"signatures":{"x":{"ed25519:0":"sig"}},"unknown_key":9 }),
                "10",
            ),
            (
                json!({ "type":"m.room.member","sender":"@a:x","state_key":"@a:x","content":{"membership":"join","foo":"bar","third_party_invite":{"signed":{"x":1}}},"membership":"top" }),
                "10",
            ),
            (
                json!({ "type":"m.room.create","room_id":"!r:x","sender":"@a:x","content":{"creator":"@a:x","x":1} }),
                "11",
            ),
            (
                json!({ "type":"m.room.join_rules","content":{"join_rule":"invite","allow":[]} }),
                "9",
            ),
            (
                json!({ "type":"m.room.message","sender":"@a:x","depth":1 }),
                "10",
            ),
            (
                json!({ "type":"m.room.power_levels","content":{"users":{"@a:x":100},"ban":50,"extra":1} }),
                "11",
            ),
            (
                json!({ "type":"m.room.message","prev_state_events":["$B"],"auth_events":["$A"],"content":{} }),
                "org.matrix.msc4242.12",
            ),
            (
                json!({ "type":"m.room.message","origin":"x","membership":"join","prev_state":["$P"],"content":{} }),
                "5",
            ),
            (
                json!({ "type":"m.room.redaction","content":{"redacts":"$X"},"sender":"@a:x" }),
                "11",
            ),
        ];
        for (c, rv) in cases {
            assert_eq!(
                redacted_writer(&c, rv),
                redacted_serde(&c, rv),
                "case: {c} rv={rv}"
            );
        }
    }
}

#[cfg(test)]
mod canonical_redacted_json_tests {
    use super::{canonical_redacted_json, redactable_content_remainder, split_redaction_content};
    use serde_json::json;

    #[test]
    fn canonical_redacted_json_returns_redacted_canonical_bytes() {
        let event = json!({
            "type": "m.room.member",
            "sender": "@alice:example.org",
            "state_key": "@bob:example.org",
            "content": {"membership": "join", "not_preserved": true},
            "signatures": {"example.org": {"ed25519:0": "ignored"}},
            "unsigned": {"age": 1}
        });

        assert_eq!(
            canonical_redacted_json(&event, "10"),
            r#"{"content":{"membership":"join"},"sender":"@alice:example.org","state_key":"@bob:example.org","type":"m.room.member"}"#
        );

        let escaped = json!({
            "type": "m.room.member",
            "content": {"membership": "\u{0008}"}
        });
        assert!(canonical_redacted_json(&escaped, "10").contains(r"\b"));
    }

    #[test]
    fn redaction_remainder_handles_non_object_inputs() {
        assert_eq!(
            split_redaction_content(&json!(null), "m.room.message", "10"),
            (json!({}), json!({}))
        );
        assert_eq!(
            redactable_content_remainder(&json!({"extra": 1}), &json!(null)),
            json!({"extra": 1})
        );
    }
}
