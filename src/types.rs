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
//!
//! This module defines the fundamental types used across all resolution algorithms:
//!
//! - [`LeanEvent`] — a lightweight, serializable Matrix event representation.
//! - [`StateResVersion`] — selects the resolution algorithm variant.
//! - [`SortPriority`] — a `BinaryHeap` wrapper encoding the V1/V2 sort semantics.
//! - [`KahnSortResult`] — the result of topological sorting, with cycle diagnostics.
//! - [`DagNode`] — a trait for generic topological traversal without requiring `LeanEvent`.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use serde::Deserialize;
use serde_json::Value;

/// Trait alias for types that can serve as event identifiers.
///
/// Any type that is `Clone + Eq + Hash + Ord + Debug` automatically implements
/// this trait via a blanket impl. In practice, this is either `String` (for
/// human-readable event IDs like `$abc123:example.com`) or `u32`/`u64` (for
/// integer-interned short IDs used by homeservers).
pub trait EventId: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug {}
impl<T: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug> EventId for T {}

/// Maximum safe power level value: 2^53 − 1 (the JavaScript `Number.MAX_SAFE_INTEGER`).
///
/// The Matrix spec constrains power levels to this bound because clients and
/// servers in the ecosystem use JSON numbers, which are IEEE 754 doubles.
/// Values above this lose integer precision.
pub const MAX_POWER_LEVEL: i64 = 9_007_199_254_740_991; // 2^53 - 1

/// Selects which state resolution algorithm to use.
///
/// Each variant corresponds to a set of Matrix room versions and spec behaviors:
///
/// | Variant | Room Versions | Key Change |
/// |---------|:---:|---|
/// | [`V1`](Self::V1) | 1 | Depth-based topological sort, all `m.room.member` events are power events. |
/// | [`V2`](Self::V2) | 2–11 | Reverse topological power ordering via Kahn's algorithm, mainline sort. |
/// | [`V2_1`](Self::V2_1) | 12+ ([MSC4297]) | Empty initial state, conflicted subgraph extraction, CDO filtering. |
/// | [`V2_1_1`](Self::V2_1_1) | — | Ban evasion fix: restricts power-phase state supplementation. |
/// | [`V2_2`](Self::V2_2) | — | Reserved for State DAGs ([MSC4242]). |
///
/// [MSC4297]: https://github.com/matrix-org/matrix-spec-proposals/pull/4297
/// [MSC4242]: https://github.com/matrix-org/matrix-spec-proposals/pull/4242
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[allow(non_camel_case_types)]
pub enum StateResVersion {
    /// State Resolution V1 (room version 1).
    V1,
    /// State Resolution V2 (room versions 2–11).
    V2,
    /// State Resolution V2.1 — [MSC4297](https://github.com/matrix-org/matrix-spec-proposals/pull/4297) (room version 12+).
    V2_1,
    /// State Resolution V2.1.1 — ban evasion fix (restricts power-phase supplementation).
    V2_1_1,
    /// State Resolution V2.2 — reserved for State DAGs ([MSC4242](https://github.com/matrix-org/matrix-spec-proposals/pull/4242)).
    V2_2,
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
pub trait DagNode<Id> {
    fn depth(&self) -> u64;
    fn prev_events(&self) -> &[Id];
    fn auth_events(&self) -> &[Id];
}

impl<Id, C> DagNode<Id> for LeanEvent<Id, C> {
    fn depth(&self) -> u64 {
        self.depth
    }
    fn prev_events(&self) -> &[Id] {
        &self.prev_events
    }
    fn auth_events(&self) -> &[Id] {
        &self.auth_events
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
/// - `event_id`: If absent and the `hashing` feature is enabled, a SHA-256
///   content hash is computed and used as the ID.
/// - `power_level`: Accepts integers, unsigned integers, or string-encoded
///   integers, clamped to [`MAX_POWER_LEVEL`].
/// - `typed_content`: Populated from `content` for auth-relevant events.
/// - All other fields default to empty/zero if absent.
#[derive(Debug, Clone, Default)]
pub struct LeanEvent<Id = String, C = Value> {
    /// Unique event identifier (e.g. `$abc123:example.com`).
    pub event_id: Id,
    /// Matrix event type (e.g. `m.room.member`, `m.room.power_levels`).
    pub event_type: String,
    /// State key for state events; `None` for timeline (non-state) events.
    /// For `m.room.member` events this is the target user's MXID.
    pub state_key: Option<String>,
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
}

impl<Id: serde::Serialize, C: serde::Serialize> serde::Serialize for LeanEvent<Id, C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("LeanEvent", 10)?;
        state.serialize_field("event_id", &self.event_id)?;
        state.serialize_field("type", &self.event_type)?;
        if let Some(ref sk) = self.state_key {
            state.serialize_field("state_key", sk)?;
        }
        state.serialize_field("power_level", &self.power_level)?;
        state.serialize_field("origin_server_ts", &self.origin_server_ts)?;
        state.serialize_field("sender", &self.sender)?;
        state.serialize_field("content", &self.content)?;
        state.serialize_field("prev_events", &self.prev_events)?;
        state.serialize_field("auth_events", &self.auth_events)?;
        state.serialize_field("depth", &self.depth)?;
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
    fn has_room_creator(&self, sender: &str) -> bool;
    fn has_additional_creator(&self, sender: &str) -> bool;
}

impl EventContent for Value {
    fn get_membership(&self) -> Option<&str> {
        self.get(crate::event_types::FIELD_MEMBERSHIP)?.as_str()
    }

    fn get_join_rule(&self) -> Option<&str> {
        self.get(crate::event_types::FIELD_JOIN_RULE)?.as_str()
    }

    fn get_user_power_level(&self, user: &str) -> Option<i64> {
        let users = self.get(crate::event_types::FIELD_USERS)?.as_object()?;
        coerce_json_to_i64(users.get(user)?).map(|i| i.min(crate::types::MAX_POWER_LEVEL))
    }

    fn get_event_power_level(&self, event_type: &str) -> Option<i64> {
        let events = self.get(crate::event_types::FIELD_EVENTS)?.as_object()?;
        coerce_json_to_i64(events.get(event_type)?).map(|i| i.min(crate::types::MAX_POWER_LEVEL))
    }

    fn get_users_default(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::event_types::FIELD_USERS_DEFAULT)?)
            .map(|i| i.min(crate::types::MAX_POWER_LEVEL))
    }

    fn get_events_default(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::event_types::FIELD_EVENTS_DEFAULT)?)
            .map(|i| i.min(crate::types::MAX_POWER_LEVEL))
    }

    fn get_state_default(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::event_types::FIELD_STATE_DEFAULT)?)
            .map(|i| i.min(crate::types::MAX_POWER_LEVEL))
    }

    fn get_ban(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::event_types::FIELD_BAN)?)
            .map(|i| i.min(crate::types::MAX_POWER_LEVEL))
    }

    fn get_kick(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::event_types::FIELD_KICK)?)
            .map(|i| i.min(crate::types::MAX_POWER_LEVEL))
    }

    fn get_invite(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::event_types::FIELD_INVITE)?)
            .map(|i| i.min(crate::types::MAX_POWER_LEVEL))
    }

    fn get_redact(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::event_types::FIELD_REDACT)?)
    }

    fn get_creator(&self) -> Option<&str> {
        self.get(crate::event_types::FIELD_CREATOR)?.as_str()
    }

    fn has_room_creator(&self, sender: &str) -> bool {
        self.get(crate::event_types::FIELD_ROOM_CREATORS)
            .and_then(|v| v.as_array())
            .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some(sender)))
    }

    fn has_additional_creator(&self, sender: &str) -> bool {
        self.get(crate::event_types::FIELD_ADDITIONAL_CREATORS)
            .and_then(|v| v.as_array())
            .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some(sender)))
    }
}

impl<Id, C> LeanEvent<Id, C> {
    /// Validates basic syntactic limits (`prev_events`, `auth_events` array sizes).
    ///
    /// NOTE: Event types are NOT whitelisted — the spec does not restrict types at the auth level.
    /// Any event type is valid as long as the sender has sufficient PL.
    ///
    /// # Errors
    ///
    /// Returns static string error if structural limits are exceeded.
    pub fn validate_syntactic(&self) -> Result<(), &'static str> {
        if self.prev_events.len() > 20 {
            return Err("prev_events exceeds maximum allowed length of 20");
        }
        if self.auth_events.len() > 10 {
            return Err("auth_events exceeds maximum allowed length of 10");
        }
        if self.event_type.is_empty() {
            return Err("event_type cannot be empty");
        }

        Ok(())
    }

    // --- Typed Content Accessors (delegate to EventContent) ---

    pub fn get_membership(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_membership()
    }

    pub fn get_join_rule(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_join_rule()
    }

    pub fn get_user_power_level(&self, user: &str) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_user_power_level(user)
    }

    pub fn get_event_power_level(&self, event_type: &str) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_event_power_level(event_type)
    }

    pub fn get_users_default(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_users_default()
    }

    pub fn get_events_default(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_events_default()
    }

    pub fn get_state_default(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_state_default()
    }

    pub fn get_ban(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_ban()
    }

    pub fn get_kick(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_kick()
    }

    pub fn get_invite(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_invite()
    }

    pub fn get_redact(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_redact()
    }

    pub fn get_creator(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_creator()
    }

    pub fn has_room_creator(&self, sender: &str) -> bool
    where
        C: EventContent,
    {
        self.content.has_room_creator(sender)
    }

    pub fn has_additional_creator(&self, sender: &str) -> bool
    where
        C: EventContent,
    {
        self.content.has_additional_creator(sender)
    }
}

#[cfg(feature = "hashing")]
fn sort_json_value_keys(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let mut sorted = alloc::collections::BTreeMap::new();
            let taken = core::mem::take(map);
            for (k, mut v) in taken {
                sort_json_value_keys(&mut v);
                sorted.insert(k, v);
            }
            for (k, v) in sorted {
                map.insert(k, v);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                sort_json_value_keys(v);
            }
        }
        _ => {}
    }
}

impl<'de> Deserialize<'de> for LeanEvent<String, Value> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;

        let event_id = if let Some(id) = value.get("event_id").and_then(|v| v.as_str()) {
            String::from(id)
        } else {
            #[cfg(feature = "hashing")]
            {
                use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
                use sha2::{Digest, Sha256};

                let mut hash_value = value.clone();
                if let Some(obj) = hash_value.as_object_mut() {
                    obj.remove("unsigned");
                    obj.remove("signatures");
                }
                sort_json_value_keys(&mut hash_value);

                let canonical_json =
                    serde_json::to_string(&hash_value).map_err(serde::de::Error::custom)?;
                let mut hasher = Sha256::new();
                hasher.update(canonical_json.as_bytes());
                let hash = hasher.finalize();

                alloc::format!("${}", URL_SAFE_NO_PAD.encode(hash))
            }
            #[cfg(not(feature = "hashing"))]
            {
                return Err(serde::de::Error::custom(
                    "event_id is missing and 'hashing' feature is disabled",
                ));
            }
        };

        let event_type: String = value
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into();

        if event_type.is_empty() {
            return Err(serde::de::Error::custom(
                "event_type cannot be missing or empty",
            ));
        }
        let state_key = value
            .get("state_key")
            .and_then(|v| v.as_str())
            .map(String::from);

        let power_level = match value.get("power_level") {
            Some(pl) => {
                if let Some(i) = pl.as_i64() {
                    i.min(MAX_POWER_LEVEL)
                } else if let Some(u) = pl.as_u64() {
                    let i = i64::try_from(u).unwrap_or(MAX_POWER_LEVEL);
                    i.min(MAX_POWER_LEVEL)
                } else if let Some(s) = pl.as_str() {
                    if let Ok(i) = s.parse::<i64>() {
                        i.min(MAX_POWER_LEVEL)
                    } else {
                        0
                    }
                } else {
                    return Err(serde::de::Error::custom("invalid power_level type"));
                }
            }
            None => 0,
        };

        let origin_server_ts = match value.get("origin_server_ts") {
            Some(ts) => ts.as_u64().unwrap_or(0),
            None => 0,
        };

        let sender = value
            .get("sender")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into();
        let content = value.get("content").cloned().unwrap_or(Value::Null);

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

        let prev_events = parse_string_array("prev_events");
        let auth_events = parse_string_array("auth_events");
        let depth = value
            .get("depth")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);

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
        })
    }
}

impl<Id: PartialEq, C> PartialEq for LeanEvent<Id, C> {
    fn eq(&self, other: &Self) -> bool {
        self.event_id == other.event_id
    }
}

impl<Id: Eq, C> Eq for LeanEvent<Id, C> {}

impl<Id: Ord, C> Ord for LeanEvent<Id, C> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.event_id.cmp(&other.event_id)
    }
}

impl<Id: Ord, C> PartialOrd for LeanEvent<Id, C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<Id, C: EventContent> LeanEvent<Id, C> {
    /// Returns `true` if this event is a ban (`membership: "ban"`) or a kick
    /// (`membership: "leave"` where `state_key ≠ sender`).
    ///
    /// Self-leaves (where the user removes themselves) return `false`.
    #[must_use]
    pub fn is_ban_or_kick(&self) -> bool {
        if self.event_type == crate::event_types::M_ROOM_MEMBER {
            if let Some(membership) = self.get_membership() {
                if membership == crate::event_types::MEM_BAN
                    || membership == crate::event_types::MEM_LEAVE
                {
                    if let Some(ref state_key) = self.state_key {
                        return state_key != &self.sender;
                    }
                }
            }
        }
        false
    }

    /// Returns `true` if this is a `m.room.power_levels` event (a potential demotion).
    #[must_use]
    pub fn is_demotion(&self) -> bool {
        self.event_type == crate::event_types::M_ROOM_POWER_LEVELS
    }

    /// Returns `true` if this is a `m.room.join_rules` event setting the room to invite-only.
    #[must_use]
    pub fn is_lockdown(&self) -> bool {
        if self.event_type == crate::event_types::M_ROOM_JOIN_RULES {
            if let Some(rule) = self.get_join_rule() {
                return rule == crate::event_types::RULE_INVITE;
            }
        }
        false
    }

    /// Returns `true` if this event restricts the given `sender` — either by
    /// banning/kicking them or by demoting their power level to zero.
    #[must_use]
    pub fn restricts_sender(&self, sender: &str) -> bool {
        if self.is_ban_or_kick() {
            if let Some(ref state_key) = self.state_key {
                return state_key == sender;
            }
        }
        if self.is_demotion() {
            if let Some(pl_int) = self.get_user_power_level(sender) {
                return pl_int == 0;
            }
        }
        false
    }

    /// Returns `true` if this administrative event causally restricts `other`.
    ///
    /// Checks whether `self` is a ban/kick/demotion targeting `other`'s sender,
    /// or a join-rules lockdown that blocks `other`'s join attempt.
    #[must_use]
    pub fn restricts_event(&self, other: &LeanEvent<Id, C>) -> bool {
        if self.is_ban_or_kick() || self.is_demotion() {
            return self.restricts_sender(&other.sender);
        }
        if self.is_lockdown() && other.event_type == crate::event_types::M_ROOM_MEMBER {
            if let Some(membership) = other.get_membership() {
                return membership == crate::event_types::MEM_JOIN;
            }
        }
        false
    }
}

impl<Id: Ord, C> LeanEvent<Id, C> {
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
pub struct SortPriority<'a, Id = String, C = Value> {
    /// Reference to the event being sorted.
    pub event: &'a LeanEvent<Id, C>,
    /// The sender's power level, derived from the auth chain (not `event.power_level`).
    pub power_level: i64,
    /// Shortest auth-chain distance to the `m.room.create` event (V2.2 only).
    pub auth_chain_distance: u64,
    /// The resolution version, which selects the comparison strategy.
    pub version: StateResVersion,
}

impl<Id, C> Clone for SortPriority<'_, Id, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Id, C> Copy for SortPriority<'_, Id, C> {}

impl<Id: Eq, C> PartialEq for SortPriority<'_, Id, C> {
    fn eq(&self, other: &Self) -> bool {
        self.power_level == other.power_level
            && self.event.origin_server_ts == other.event.origin_server_ts
            && self.event.event_id == other.event.event_id
    }
}

impl<Id: Eq, C> Eq for SortPriority<'_, Id, C> {}

impl<Id: Ord, C> Ord for SortPriority<'_, Id, C> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.version {
            StateResVersion::V1 => {
                // Matrix Spec - State Resolution v1:
                // "First we resolve conflicts between m.room.power_levels events...
                //  If there is a tie, we resolve it by comparing the events' depths
                //  and then their event IDs."
                //
                // In Rust's Max-Heap BinaryHeap, "greater" elements are popped first.
                // We want deeper events to pop FIRST, so they must be "greater".
                match self.event.depth.cmp(&other.event.depth) {
                    Ordering::Equal => self.event.event_id.cmp(&other.event.event_id),
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
                        // V2.1.1 Invite-lock fix: prioritize topological depth over `origin_server_ts`.
                        // Smaller Depth -> Greater TieBreaker -> Pops First -> Loses.
                        // Larger Depth -> Smaller TieBreaker -> Pops Last -> Wins.
                        if self.version == StateResVersion::V2_1_1
                            || self.version == StateResVersion::V2_2
                        {
                            match other.auth_chain_distance.cmp(&self.auth_chain_distance) {
                                Ordering::Equal => {}
                                ord => return ord,
                            }
                        }

                        match other
                            .event
                            .origin_server_ts
                            .cmp(&self.event.origin_server_ts)
                        {
                            Ordering::Equal => other.event.event_id.cmp(&self.event.event_id),
                            ord => ord,
                        }
                    }
                    ord => ord,
                }
            }
        }
    }
}

impl<Id: Ord, C> PartialOrd for SortPriority<'_, Id, C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Coerces a JSON value to `i64`, accepting integers, unsigned integers, or
/// string-encoded integers.
///
/// Returns `None` if the value cannot be interpreted as an integer.
/// This three-way coercion handles the real-world inconsistency where some
/// homeservers encode power levels as strings in their JSON.
///
/// FUN FACT: Room versions 1-9 actually allowed power levels to be floats
/// and strings in the JSON, which is why `rezzy` has this `coerce_json_to_i64`
/// function in the first place!
#[must_use]
pub fn coerce_json_to_i64(pl: &Value) -> Option<i64> {
    let val = if let Some(i) = pl.as_i64() {
        Some(i)
    } else if let Some(u) = pl.as_u64() {
        Some(i64::try_from(u).unwrap_or(i64::MAX))
    } else if let Some(f) = pl.as_f64() {
        // Legacy float power levels (e.g. 50.0) — truncate toward zero,
        // then convert via serde_json::Number to avoid lossy `as` casts.
        serde_json::Number::from_f64(f.trunc()).and_then(|n| n.as_i64())
    } else if let Some(s) = pl.as_str() {
        s.parse::<i64>().ok()
    } else {
        None
    };
    // Matrix Spec (Client-Server API) — m.room.power_levels:
    // "The power level ... must be an integer between -2^53 + 1 and 2^53 - 1."
    val.map(|v| v.clamp(-MAX_POWER_LEVEL, MAX_POWER_LEVEL))
}

/// Finds the `m.room.create` event deterministically across the auth context and sort set.
///
/// If multiple create events exist (which would be a protocol violation), the
/// one with the lexicographically smallest `event_id` is chosen to ensure
/// deterministic behavior across all implementations.
pub fn find_deterministic_create_event<
    'a,
    Id: Ord + Eq + core::hash::Hash,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    C: EventContent,
>(
    auth_context: &'a crate::HashMap<Id, LeanEvent<Id, C>, S1>,
    sort_set: &'a crate::HashMap<Id, LeanEvent<Id, C>, S2>,
) -> Option<&'a LeanEvent<Id, C>> {
    let mut create_events: alloc::vec::Vec<&LeanEvent<Id, C>> = auth_context
        .values()
        .chain(sort_set.values())
        .filter(|ev| ev.event_type == crate::event_types::M_ROOM_CREATE)
        .collect();

    if create_events.is_empty() {
        return None;
    }

    create_events.sort_by(|a, b| a.event_id.cmp(&b.event_id));
    create_events.first().copied()
}

pub trait EventProvider<Id, C> {
    fn get_event(&self, id: &Id) -> Option<&LeanEvent<Id, C>>;
}

impl<Id: core::hash::Hash + Eq, C, S: core::hash::BuildHasher> EventProvider<Id, C>
    for crate::HashMap<Id, LeanEvent<Id, C>, S>
{
    fn get_event(&self, id: &Id) -> Option<&LeanEvent<Id, C>> {
        self.get(id)
    }
}

impl<Id: core::hash::Hash + Eq + Ord, C> EventProvider<Id, C>
    for alloc::collections::BTreeMap<Id, LeanEvent<Id, C>>
{
    fn get_event(&self, id: &Id) -> Option<&LeanEvent<Id, C>> {
        self.get(id)
    }
}

pub struct SortContext<'a, Id, C, S1, S2> {
    pub primary: &'a crate::HashMap<Id, LeanEvent<Id, C>, S1>,
    pub secondary: &'a crate::HashMap<Id, LeanEvent<Id, C>, S2>,
}

impl<Id: core::hash::Hash + Eq, C, S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>
    EventProvider<Id, C> for SortContext<'_, Id, C, S1, S2>
{
    fn get_event(&self, id: &Id) -> Option<&LeanEvent<Id, C>> {
        self.primary.get(id).or_else(|| self.secondary.get(id))
    }
}
