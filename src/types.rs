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

use crate::HashMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use serde::Deserialize;
use serde_json::Value;

pub trait EventId: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug {}
impl<T: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug> EventId for T {}

pub const MAX_POWER_LEVEL: i64 = 9_007_199_254_740_991; // 2^53 - 1

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[allow(non_camel_case_types)]
pub enum StateResVersion {
    V1,
    V2,
    V2_1,
    V2_1_1, // The V3 / Ban Evasion Fix
    V2_2,   // Reserved for State DAGs (MSC4242)
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

/// A lightweight Matrix Event representation for Lean-equivalent resolution.
#[derive(Debug, Clone, Default)]
pub struct LeanEvent<Id = String> {
    pub event_id: Id,
    pub event_type: String,
    pub state_key: Option<String>,
    pub power_level: i64,
    pub origin_server_ts: u64,
    pub sender: String,
    pub content: Value,
    pub prev_events: Vec<Id>,
    pub auth_events: Vec<Id>,
    pub depth: u64, // Required for V1
}

impl<Id: serde::Serialize> serde::Serialize for LeanEvent<Id> {
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

impl<Id> LeanEvent<Id> {
    /// Validates basic syntactic limits and strict event whitelists as defined by the custom subset.
    ///
    /// # Errors
    ///
    /// Returns static string error if syntactic checks fail.
    pub fn validate_syntactic(&self) -> Result<(), &'static str> {
        const ALLOWED_EVENT_TYPES: &[&str] = &[
            "m.room.create",
            "m.room.join_rules",
            "m.room.power_levels",
            "m.room.member",
            "m.room.name",
            "m.room.topic",
            "m.room.avatar",
            "m.room.canonical_alias",
            "m.room.history_visibility",
            "m.room.guest_access",
            "m.room.server_acl",
            "m.room.tombstone",
            "m.room.encryption",
            "m.room.pinned_events",
            "m.room.message",
            "m.room.redaction",
            "m.space.child",
            "m.space.parent",
        ];

        if self.prev_events.len() > 20 {
            return Err("prev_events exceeds maximum allowed length of 20");
        }
        if self.auth_events.len() > 10 {
            return Err("auth_events exceeds maximum allowed length of 10");
        }

        if !ALLOWED_EVENT_TYPES.contains(&self.event_type.as_str()) {
            return Err("event_type is not a recognized Matrix specification event");
        }

        Ok(())
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

impl<'de> Deserialize<'de> for LeanEvent<String> {
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

        let event_type = value
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into();
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

impl<Id: PartialEq> PartialEq for LeanEvent<Id> {
    fn eq(&self, other: &Self) -> bool {
        self.event_id == other.event_id
    }
}

impl<Id: Eq> Eq for LeanEvent<Id> {}

impl<Id: Ord> Ord for LeanEvent<Id> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.event_id.cmp(&other.event_id)
    }
}

impl<Id: Ord> PartialOrd for LeanEvent<Id> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<Id> LeanEvent<Id> {
    #[must_use]
    pub fn is_ban_or_kick(&self) -> bool {
        if self.event_type == "m.room.member" {
            if let Some(membership) = self.content.get("membership").and_then(|v| v.as_str()) {
                if membership == "ban" {
                    return true;
                }
                if membership == "leave" {
                    if let Some(ref state_key) = self.state_key {
                        return state_key != &self.sender;
                    }
                }
            }
        }
        false
    }

    #[must_use]
    pub fn is_demotion(&self) -> bool {
        self.event_type == "m.room.power_levels"
    }

    #[must_use]
    pub fn is_lockdown(&self) -> bool {
        if self.event_type == "m.room.join_rules" {
            if let Some(rule) = self.content.get("join_rule").and_then(|v| v.as_str()) {
                return rule == "invite";
            }
        }
        false
    }

    #[must_use]
    pub fn restricts_sender(&self, sender: &str) -> bool {
        if self.is_ban_or_kick() {
            if let Some(ref state_key) = self.state_key {
                return state_key == sender;
            }
        }
        if self.is_demotion() {
            if let Some(users) = self.content.get("users").and_then(|u| u.as_object()) {
                if let Some(pl) = users.get(sender) {
                    if let Some(pl_int) = coerce_json_to_i64(pl) {
                        return pl_int == 0;
                    }
                }
            }
        }
        false
    }

    #[must_use]
    pub fn restricts_event(&self, other: &LeanEvent<Id>) -> bool {
        if self.is_ban_or_kick() || self.is_demotion() {
            return self.restricts_sender(&other.sender);
        }
        if self.is_lockdown() && other.event_type == "m.room.member" {
            if let Some(membership) = other.content.get("membership").and_then(|v| v.as_str()) {
                return membership == "join";
            }
        }
        false
    }
}

impl<Id: Ord> LeanEvent<Id> {
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

/// A wrapper to ensure `BinaryHeap` pops the "Best" event FIRST.
#[derive(Debug)]
pub struct SortPriority<'a, Id = String> {
    pub event: &'a LeanEvent<Id>,
    pub power_level: i64,
    pub auth_chain_distance: u64,
    pub version: StateResVersion,
}

impl<Id> Clone for SortPriority<'_, Id> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Id> Copy for SortPriority<'_, Id> {}

impl<Id: Eq> PartialEq for SortPriority<'_, Id> {
    fn eq(&self, other: &Self) -> bool {
        self.power_level == other.power_level
            && self.event.origin_server_ts == other.event.origin_server_ts
            && self.event.event_id == other.event.event_id
    }
}

impl<Id: Eq> Eq for SortPriority<'_, Id> {}

impl<Id: Ord> Ord for SortPriority<'_, Id> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.version {
            StateResVersion::V1 => {
                // V1 tie-breaking: depth (asc) -> event_id (asc)
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
                //   other.pl.cmp(&self.pl)  → higher PL = smaller TieBreaker → larger Reverse → pops first
                //   self.ts.cmp(&other.ts)  → earlier ts = smaller TieBreaker → larger Reverse → pops first
                //   self.id.cmp(&other.id)  → smaller id = smaller TieBreaker → larger Reverse → pops first
                //
                // In our direct max-heap (no Reverse) we invert each: Greater = pops first.
                //   higher PL → Greater  → use self.pl.cmp(&other.pl)
                //   earlier ts → Greater → use other.ts.cmp(&self.ts)
                //   smaller id → Greater → use other.id.cmp(&self.id)
                //
                // Net result: high-PL events pop first (losing for same-key conflicts but
                // setting auth context before lower-PL events are checked — this is what
                // makes Alice's ban appear before Bob's concurrent PL change).
                match self.power_level.cmp(&other.power_level) {
                    Ordering::Equal => {
                        // V2.2 Invite-Lock Fix: prioritize topological depth over origin_server_ts.
                        // Smaller Depth -> Greater TieBreaker -> Pops First -> Loses.
                        // Larger Depth -> Smaller TieBreaker -> Pops Last -> Wins.
                        if self.version == StateResVersion::V2_2
                            || self.version == StateResVersion::V2_1_1
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

impl<Id: Ord> PartialOrd for SortPriority<'_, Id> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[must_use]
pub fn coerce_json_to_i64(pl: &Value) -> Option<i64> {
    if let Some(i) = pl.as_i64() {
        return Some(i);
    }
    if let Some(u) = pl.as_u64() {
        return Some(i64::try_from(u).unwrap_or(i64::MAX));
    }
    if let Some(s) = pl.as_str() {
        if let Ok(i) = s.parse::<i64>() {
            return Some(i);
        }
    }
    None
}

pub fn find_deterministic_create_event<
    'a,
    Id: Ord + Eq + core::hash::Hash,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    auth_context: &'a HashMap<Id, LeanEvent<Id>, S1>,
    sort_set: &'a HashMap<Id, LeanEvent<Id>, S2>,
) -> Option<&'a LeanEvent<Id>> {
    let mut create_events: Vec<&LeanEvent<Id>> = auth_context
        .values()
        .chain(sort_set.values())
        .filter(|ev| ev.event_type == "m.room.create")
        .collect();
    create_events.sort_by(|a, b| a.event_id.cmp(&b.event_id));
    create_events.first().copied()
}
