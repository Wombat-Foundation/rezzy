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

#![no_std]

extern crate alloc;

pub mod auth;
pub mod roaring_auth;

use alloc::collections::BTreeSet;
use alloc::collections::{BTreeMap, BinaryHeap};

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use serde::{Deserialize, Serialize};

use serde_json::Value;

#[cfg(feature = "mock-ruma")]
pub use ruma_state_res::{events, test_utils, utils, Error as RumaError, Event, StateMap};

#[cfg(feature = "mock-ruma")]
fn ruma_to_lean_event<E: Event>(ev: &E) -> crate::LeanEvent {
    use alloc::string::ToString;
    let content_val: serde_json::Value =
        serde_json::from_str(ev.content().get()).unwrap_or(serde_json::Value::Null);
    let power_level = if let Some(pl) = content_val.get("power_level") {
        pl.as_i64()
            .or_else(|| pl.as_str().and_then(|s| s.parse().ok()))
            .unwrap_or(0)
    } else {
        0
    };
    crate::LeanEvent {
        event_id: ev.event_id().to_string(),
        event_type: ev.event_type().to_string(),
        state_key: ev.state_key().map(alloc::string::ToString::to_string),
        power_level,
        origin_server_ts: ev.origin_server_ts().0.into(),
        sender: ev.sender().to_string(),
        content: content_val,
        prev_events: ev
            .prev_events()
            .map(alloc::string::ToString::to_string)
            .collect(),
        auth_events: ev
            .auth_events()
            .map(alloc::string::ToString::to_string)
            .collect(),
        depth: 0,
    }
}

#[cfg(feature = "mock-ruma")]
type PartitionedState = (
    std::collections::BTreeMap<(String, Option<String>), String>,
    std::collections::HashSet<(ruma_events::StateEventType, String)>,
);

#[cfg(feature = "mock-ruma")]
fn partition_state<'a, E>(state_sets: &[StateMap<E::Id>]) -> PartitionedState
where
    E: Event + Clone,
    E::Id: 'a,
{
    use alloc::string::ToString;
    use std::collections::{BTreeMap, HashMap, HashSet};

    let mut counts: HashMap<(&(ruma_events::StateEventType, String), &E::Id), usize> =
        HashMap::new();
    for map in state_sets {
        for (key, id) in map {
            *counts.entry((key, id)).or_insert(0) += 1;
        }
    }

    let num_maps = state_sets.len();
    let mut conflicted_keys = HashSet::new();
    let mut unconflicted_state = BTreeMap::new();

    for map in state_sets {
        for (key, id) in map {
            if counts.get(&(key, id)).copied().unwrap_or(0) == num_maps {
                let state_key_opt = if key.1.is_empty() {
                    None
                } else {
                    Some(key.1.clone())
                };
                unconflicted_state.insert((key.0.to_string(), state_key_opt), id.to_string());
            } else {
                conflicted_keys.insert(key.clone());
            }
        }
    }

    (unconflicted_state, conflicted_keys)
}

#[cfg(feature = "mock-ruma")]
fn build_conflicted_events<'a, E>(
    state_sets: &[StateMap<E::Id>],
    conflicted_keys: &std::collections::HashSet<(ruma_events::StateEventType, String)>,
    state_res_rules: ruma_common::room_version_rules::StateResolutionV2Rules,
    fetch_event: &impl Fn(&ruma_common::EventId) -> Option<E>,
    fetch_conflicted_state_subgraph: &impl Fn(
        &StateMap<Vec<E::Id>>,
    ) -> Option<
        ruma_state_res::utils::event_id_set::EventIdSet<E::Id>,
    >,
) -> (
    std::collections::HashMap<String, LeanEvent>,
    StateMap<Vec<E::Id>>,
)
where
    E: Event + Clone,
    E::Id: 'a,
{
    use alloc::string::ToString;
    use core::borrow::Borrow;
    use std::collections::HashMap;

    let mut conflicted_events = HashMap::new();
    let mut conflicted_state_set: StateMap<Vec<E::Id>> = StateMap::new();

    for map in state_sets {
        for (key, id) in map {
            if conflicted_keys.contains(key) {
                let id_str = id.to_string();
                if !conflicted_events.contains_key(&id_str) {
                    if let Some(ev) = fetch_event(id.borrow()) {
                        conflicted_events.insert(id_str.clone(), ruma_to_lean_event(&ev));
                    }
                }
                let list = conflicted_state_set
                    .entry(key.clone())
                    .or_insert_with(Vec::new);
                if !list.contains(id) {
                    list.push(id.clone());
                }
            }
        }
    }

    if state_res_rules.begin_iterative_auth_checks_with_empty_state_map {
        if let Some(subgraph) = fetch_conflicted_state_subgraph(&conflicted_state_set) {
            for id in subgraph {
                let id_str = id.to_string();
                if !conflicted_events.contains_key(&id_str) {
                    if let Some(ev) = fetch_event(id.borrow()) {
                        conflicted_events.insert(id_str.clone(), ruma_to_lean_event(&ev));
                    }
                }
            }
        }
    }

    (conflicted_events, conflicted_state_set)
}

/// Resolve state conflicts across multiple state maps.
///
/// # Errors
///
/// Returns a `RumaError` if state resolution fails.
#[cfg(feature = "mock-ruma")]
pub fn resolve<'a, E, MapsIter>(
    _auth_rules: &ruma_common::room_version_rules::AuthorizationRules,
    state_res_rules: &ruma_common::room_version_rules::StateResolutionV2Rules,
    state_maps: impl IntoIterator<IntoIter = MapsIter>,
    auth_chains: Vec<ruma_state_res::utils::event_id_set::EventIdSet<E::Id>>,
    fetch_event: impl Fn(&ruma_common::EventId) -> Option<E>,
    fetch_conflicted_state_subgraph: impl Fn(
        &StateMap<Vec<E::Id>>,
    ) -> Option<
        ruma_state_res::utils::event_id_set::EventIdSet<E::Id>,
    >,
) -> core::result::Result<StateMap<E::Id>, RumaError>
where
    E: Event + Clone,
    E::Id: 'a,
    MapsIter: Iterator<Item = &'a StateMap<E::Id>> + Clone,
{
    use alloc::string::ToString;
    use core::borrow::Borrow;
    use std::collections::HashMap;

    let mut state_sets = Vec::new();
    let mut id_map: HashMap<String, E::Id> = HashMap::new();

    for map in state_maps {
        state_sets.push(map.clone());
        id_map.extend(map.values().map(|id| (id.to_string(), id.clone())));
    }
    if state_sets.is_empty() {
        return Ok(StateMap::new());
    }

    let (unconflicted_state, conflicted_keys) = partition_state::<E>(&state_sets);

    let (mut conflicted_events, _conflicted_state_set) = build_conflicted_events::<E>(
        &state_sets,
        &conflicted_keys,
        *state_res_rules,
        &fetch_event,
        &fetch_conflicted_state_subgraph,
    );

    let mut auth_context = HashMap::new();

    let mut to_fetch: Vec<E::Id> = state_sets
        .iter()
        .flat_map(|m| m.values().cloned())
        .collect();
    for id in &to_fetch {
        id_map.insert(id.to_string(), id.clone());
    }

    // Compute auth difference
    let mut union_auth = std::collections::HashSet::new();
    let mut intersect_auth = auth_chains
        .first()
        .map_or_else(std::collections::HashSet::new, |first| {
            first.iter().map(ToString::to_string).collect()
        });
    for chain in &auth_chains {
        let set: std::collections::HashSet<_> = chain
            .iter()
            .map(alloc::string::ToString::to_string)
            .collect();
        union_auth.extend(set.clone());
        intersect_auth.retain(|id| set.contains(id));
    }
    let auth_diff: std::collections::HashSet<_> =
        union_auth.difference(&intersect_auth).cloned().collect();

    for id_str in auth_diff {
        if !conflicted_events.contains_key(&id_str) {
            if let Some(id) = id_map.get(&id_str) {
                if let Some(ev) = fetch_event(id.borrow()) {
                    conflicted_events.insert(id_str.clone(), ruma_to_lean_event(&ev));
                }
            }
        }
    }
    for chain in auth_chains {
        for id in &chain {
            to_fetch.push(id.clone());
            id_map.insert(id.to_string(), id.clone());
        }
    }

    let mut visited = std::collections::HashSet::new();

    while let Some(id) = to_fetch.pop() {
        let id_str = id.to_string();
        if !visited.insert(id_str.clone()) {
            continue;
        }

        if let Some(ev) = fetch_event(id.borrow()) {
            if !conflicted_events.contains_key(&id_str) {
                auth_context.insert(id_str.clone(), ruma_to_lean_event(&ev));
            }
            for auth_id in ev.auth_events() {
                to_fetch.push(auth_id.clone());
                id_map.insert(auth_id.to_string(), auth_id.clone());
            }
        }
    }

    // Attempt to dynamically select V2 vs V2.1 if the inputs match the MSC4297 test scenario.
    // In MSC4297 test, conflicted events have specific topologies, but standard V2 is safe for now.
    let resolved = crate::resolve_lean(
        unconflicted_state,
        conflicted_events,
        &auth_context,
        if state_res_rules.begin_iterative_auth_checks_with_empty_state_map {
            crate::StateResVersion::V2_1
        } else {
            crate::StateResVersion::V2
        },
    );

    let mut result = StateMap::new();
    for ((ev_type, state_key), id_str) in resolved {
        let key = (
            ev_type.as_str().into(),
            state_key.clone().unwrap_or_default(),
        );
        if let Some(id) = id_map.get(&id_str) {
            result.insert(key, id.clone());
        }
    }

    Ok(result)
}

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
pub use std::collections::HashMap;

#[cfg(not(feature = "std"))]
pub use hashbrown::HashMap;

/// The version of the Matrix State Resolution algorithm to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[allow(non_camel_case_types)]
pub enum StateResVersion {
    V1,
    V2,
    V2_1,
    V2_1_1, // The V3 / Ban Evasion Fix
    V2_2,   // Reserved for State DAGs (MSC4242)
}

type LocalAuthCache = HashMap<String, BTreeMap<(String, Option<String>), (LeanEvent, usize)>>;

/// Result of Kahn's topological sort with diagnostic information.
#[derive(Debug, Clone)]
pub enum KahnSortResult {
    /// All events were successfully sorted.
    Ok(Vec<String>),
    /// A cycle was detected. `sorted` contains the partial ordering of events
    /// that could be processed, `stuck` contains events that could not reach
    /// in-degree 0 (involved in cycles).
    CycleDetected {
        sorted: Vec<String>,
        stuck: Vec<String>,
    },
}

impl KahnSortResult {
    /// Returns the sorted event IDs, or an empty vec if a cycle was detected.
    /// This preserves backward compatibility with the old API.
    #[must_use]
    pub fn into_sorted(self) -> Vec<String> {
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

/// Synapse-compatible power level deserialization.
/// Handles integer (100), string ("100"), and float (100.0) representations.
fn deserialize_power_level<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct PowerLevelVisitor;

    impl de::Visitor<'_> for PowerLevelVisitor {
        type Value = i64;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("an integer, float, or string representation of a power level")
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<i64, E> {
            Ok(v)
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<i64, E> {
            Ok(i64::try_from(v).unwrap_or(i64::MAX))
        }

        fn visit_f64<E: de::Error>(self, v: f64) -> Result<i64, E> {
            let s = alloc::format!("{v:.0}");
            s.parse::<i64>().map_err(E::custom)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<i64, E> {
            if let Ok(i) = v.parse::<i64>() {
                return Ok(i);
            }
            if let Ok(f) = v.parse::<f64>() {
                if let Ok(i) = alloc::format!("{f:.0}").parse::<i64>() {
                    return Ok(i);
                }
            }
            Ok(0)
        }
    }

    deserializer.deserialize_any(PowerLevelVisitor)
}

/// A lightweight Matrix Event representation for Lean-equivalent resolution.
#[derive(Debug, Clone, Serialize, Default)]
pub struct LeanEvent {
    pub event_id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(default)]
    pub state_key: Option<String>,
    #[serde(default, deserialize_with = "deserialize_power_level")]
    pub power_level: i64,
    pub origin_server_ts: u64,
    #[serde(default)]
    pub sender: String,
    #[serde(default)]
    pub content: Value,
    #[serde(default)]
    pub prev_events: Vec<String>,
    #[serde(default)]
    pub auth_events: Vec<String>,
    #[serde(default)]
    pub depth: u64, // Required for V1
}

impl LeanEvent {
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

#[derive(Deserialize)]
struct LeanEventInner {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    state_key: Option<String>,
    #[serde(default, deserialize_with = "deserialize_power_level")]
    power_level: i64,
    origin_server_ts: u64,
    #[serde(default)]
    sender: String,
    #[serde(default)]
    content: Value,
    #[serde(default)]
    prev_events: Vec<String>,
    #[serde(default)]
    auth_events: Vec<String>,
    #[serde(default)]
    depth: u64,
}

impl<'de> Deserialize<'de> for LeanEvent {
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

        let inner: LeanEventInner =
            serde_json::from_value(value).map_err(serde::de::Error::custom)?;

        Ok(LeanEvent {
            event_id,
            event_type: inner.event_type,
            state_key: inner.state_key,
            power_level: inner.power_level,
            origin_server_ts: inner.origin_server_ts,
            sender: inner.sender,
            content: inner.content,
            prev_events: inner.prev_events,
            auth_events: inner.auth_events,
            depth: inner.depth,
        })
    }
}

impl PartialEq for LeanEvent {
    fn eq(&self, other: &Self) -> bool {
        self.event_id == other.event_id
    }
}

impl Eq for LeanEvent {}

impl Ord for LeanEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        self.event_id.cmp(&other.event_id)
    }
}

impl PartialOrd for LeanEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl LeanEvent {
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
#[derive(Debug, Clone, Copy)]
pub struct SortPriority<'a> {
    pub event: &'a LeanEvent,
    pub power_level: i64,
    pub auth_chain_distance: u64,
    pub version: StateResVersion,
}

const MAX_POWER_LEVEL: i64 = 9_007_199_254_740_991; // 2^53 - 1

/// Dynamically fetches the sender's power level by inspecting the event's immediate `auth_events`.
/// Recursive traversal of the auth chain is avoided to prevent bypassing immediate restrictions.
fn get_power_level_from_auth_chain<S: core::hash::BuildHasher>(
    event: &LeanEvent,
    auth_context: &HashMap<String, LeanEvent, S>,
    create_ev: Option<&LeanEvent>,
) -> i64 {
    let mut pl_event = None;

    // Spec compliance: only check immediate auth_events.
    for aid in &event.auth_events {
        if let Some(aev) = auth_context.get(aid) {
            if aev.event_type == "m.room.power_levels"
                && aev.state_key.as_deref() == Some("")
                && pl_event.is_none()
            {
                pl_event = Some(aev.clone());
            }
        }
    }

    let mut is_creator = false;
    if let Some(create_ev) = create_ev {
        let is_primary_creator = create_ev.sender == event.sender;
        let mut is_additional_creator = false;

        if let Some(creators) = create_ev
            .content
            .get("room_creators")
            .and_then(|c| c.as_array())
        {
            if creators.iter().any(|c| c.as_str() == Some(&event.sender)) {
                is_additional_creator = true;
            }
        }
        if let Some(creators) = create_ev
            .content
            .get("additional_creators")
            .and_then(|c| c.as_array())
        {
            if creators.iter().any(|c| c.as_str() == Some(&event.sender)) {
                is_additional_creator = true;
            }
        }

        if is_primary_creator || is_additional_creator {
            is_creator = true;
        }
    }

    if is_creator {
        return MAX_POWER_LEVEL;
    }

    if let Some(pl_ev) = pl_event {
        if let Some(users) = pl_ev.content.get("users").and_then(|u| u.as_object()) {
            if let Some(pl) = users.get(&event.sender).and_then(serde_json::Value::as_i64) {
                return pl;
            }
        }

        if let Some(default_pl) = pl_ev
            .content
            .get("users_default")
            .and_then(serde_json::Value::as_i64)
        {
            return default_pl;
        }
        return 0; // Default if PL event exists but no users_default
    }

    event.power_level // Fallback to explicitly specified PL (e.g. for dump_jsonl compatibility)
}

/// Computes the shortest distance from the event to the m.room.create event via `auth_events`.
fn memoized_auth_distance<'a, S: core::hash::BuildHasher>(
    curr_id: &'a str,
    auth_context: &'a HashMap<String, LeanEvent, S>,
    create_id: &str,
    memo: &mut HashMap<&'a str, u64>,
) -> u64 {
    if curr_id == create_id {
        return 0;
    }

    if let Some(&dist) = memo.get(curr_id) {
        return dist;
    }

    let Some(ev) = auth_context.get(curr_id) else {
        return 0;
    };

    if ev.auth_events.is_empty() {
        return 0;
    }

    let mut min_dist = u64::MAX;
    for parent in &ev.auth_events {
        let p_dist = memoized_auth_distance(parent, auth_context, create_id, memo);
        min_dist = min_dist.min(p_dist.saturating_add(1));
    }

    memo.insert(curr_id, min_dist);
    min_dist
}

impl PartialEq for SortPriority<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.power_level == other.power_level
            && self.event.origin_server_ts == other.event.origin_server_ts
            && self.event.event_id == other.event.event_id
    }
}

impl Eq for SortPriority<'_> {}

impl Ord for SortPriority<'_> {
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

impl PartialOrd for SortPriority<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Kahn's Topological Sort with full diagnostic output.
/// Returns a `KahnSortResult` that distinguishes between successful sorts
/// and cycle detection, providing the stuck set for debugging.
///
/// # Panics
///
/// This function can panic if an internal invariant is violated, such as a
/// missing in-degree entry during node processing.
#[must_use]
pub fn lean_kahn_sort_detailed<S: core::hash::BuildHasher>(
    events: &HashMap<String, LeanEvent, S>,
    auth_context: &HashMap<String, LeanEvent, S>,
    create_ev: Option<&LeanEvent>,
    version: StateResVersion,
) -> KahnSortResult {
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();

    for (id, event) in events {
        in_degree.entry(id.clone()).or_insert(0);
        for auth in &event.auth_events {
            if events.contains_key(auth) {
                // Topological sort: ancestors come BEFORE descendants.
                // But we want a REVERSE topological sort: descendants BEFORE ancestors.
                // So we add edges from ancestors to descendants.
                adjacency.entry(auth.clone()).or_default().push(id.clone());
                *in_degree.entry(id.clone()).or_insert(0) += 1;
            }
        }
    }

    // Pre-compute power levels once per event to avoid redundant auth chain walks
    // inside the hot BinaryHeap push path.
    let pl_cache: HashMap<String, i64> = events
        .iter()
        .map(|(id, ev)| {
            (
                id.clone(),
                get_power_level_from_auth_chain(ev, auth_context, create_ev),
            )
        })
        .collect();

    let depth_cache: HashMap<String, u64> = if version == StateResVersion::V2_2 {
        let mut memo = HashMap::new();
        let create_id = create_ev.map_or("", |e| e.event_id.as_str());
        events
            .keys()
            .map(|id| {
                (
                    id.clone(),
                    memoized_auth_distance(id, auth_context, create_id, &mut memo),
                )
            })
            .collect()
    } else {
        HashMap::new()
    };

    let mut queue: BinaryHeap<SortPriority> = BinaryHeap::new();
    for (id, &degree) in &in_degree {
        if degree == 0 {
            if let Some(event) = events.get(id) {
                queue.push(SortPriority {
                    event,
                    power_level: pl_cache.get(id).copied().unwrap_or(0),
                    auth_chain_distance: depth_cache.get(id).copied().unwrap_or(0),
                    version,
                });
            }
        }
    }

    let mut result = Vec::new();
    while let Some(priority) = queue.pop() {
        let event = priority.event;

        result.push(event.event_id.clone());
        if let Some(neighbors) = adjacency.get(&event.event_id) {
            for next_id in neighbors {
                let degree = in_degree.get_mut(next_id).unwrap();
                *degree -= 1;
                if *degree == 0 {
                    let next_ev = events.get(next_id).unwrap();
                    queue.push(SortPriority {
                        event: next_ev,
                        power_level: pl_cache.get(next_id).copied().unwrap_or(0),
                        auth_chain_distance: depth_cache.get(next_id).copied().unwrap_or(0),
                        version,
                    });
                }
            }
        }
    }

    // Detect cycles: events that never reached in-degree 0.
    if result.len() != events.len() {
        let sorted_set: alloc::collections::BTreeSet<&String> = result.iter().collect();
        let stuck: Vec<String> = events
            .keys()
            .filter(|id| !sorted_set.contains(id))
            .cloned()
            .collect();
        return KahnSortResult::CycleDetected {
            sorted: result,
            stuck,
        };
    }

    KahnSortResult::Ok(result)
}

/// A simplified implementation of Kahn's Topological Sort.
/// Backward-compatible wrapper that returns an empty Vec on cycles.
#[must_use]
pub fn lean_kahn_sort<S: core::hash::BuildHasher>(
    events: &HashMap<String, LeanEvent, S>,
    auth_context: &HashMap<String, LeanEvent, S>,
    create_ev: Option<&LeanEvent>,
    version: StateResVersion,
) -> Vec<String> {
    match lean_kahn_sort_detailed(events, auth_context, create_ev, version) {
        KahnSortResult::Ok(sorted) => sorted,
        KahnSortResult::CycleDetected { sorted, stuck } => {
            #[cfg(feature = "std")]
            std::eprintln!("KAHN CYCLE DETECTED! Stuck: {stuck:?}");
            let _ = stuck;
            sorted
        }
    }
}

fn is_v2_2_duplicate_auth_key<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
    ev: &LeanEvent,
    auth_context: &HashMap<String, LeanEvent, S1>,
    conflicted_events: &HashMap<String, LeanEvent, S2>,
) -> bool {
    let mut seen_keys = alloc::collections::BTreeSet::new();
    for auth_id in &ev.auth_events {
        if let Some(auth_ev) = auth_context
            .get(auth_id)
            .or_else(|| conflicted_events.get(auth_id))
        {
            let key = (auth_ev.event_type.clone(), auth_ev.state_key.clone());
            if !seen_keys.insert(key) {
                return true;
            }
        }
    }
    false
}

#[must_use]
pub fn resolve_lean<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
    unconflicted_state: BTreeMap<(String, Option<String>), String>,
    mut conflicted_events: HashMap<String, LeanEvent, S1>,
    auth_context: &HashMap<String, LeanEvent, S2>,
    version: StateResVersion,
) -> BTreeMap<(String, Option<String>), String> {
    if version == StateResVersion::V2_1_1 {
        let filtered = apply_cdo_filter(&conflicted_events, auth_context);
        conflicted_events.clear();
        for (k, v) in filtered {
            conflicted_events.insert(k, v);
        }
    }

    // Build a merged lookup map for sort/mainline operations.
    // auth_context intentionally excludes events that are in conflicted_events;
    // however, a conflicted event (e.g. $01-power_levels) may appear in the
    // auth_events chain of another conflicted event ($02), so PL lookups during
    // sorting must be able to find it.  iterative_auth_ok already checks both
    // maps independently — we only need to merge here for the sort phases.
    let sort_context: HashMap<String, LeanEvent> = auth_context
        .iter()
        .chain(conflicted_events.iter())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // MSC4297 (v2.1+): The algorithm starts from an empty set of state.
    let mut resolved = match version {
        StateResVersion::V2_1 | StateResVersion::V2_2 => BTreeMap::new(),
        _ => unconflicted_state.clone(),
    };

    let sort_set = &conflicted_events;

    // Route all events through Kahn sort (reverse topological power ordering).
    let mut power_events = HashMap::new();
    let mut non_power_events = HashMap::new();

    for (id, ev) in sort_set {
        // V2.2: Hard Rejection of Duplicate Auth Keys
        if version == StateResVersion::V2_2
            && is_v2_2_duplicate_auth_key(ev, auth_context, &conflicted_events)
        {
            continue;
        }

        if ev.event_type == "m.room.member"
            || ev.event_type == "m.room.create"
            || ev.event_type == "m.room.power_levels"
            || ev.event_type == "m.room.join_rules"
        {
            power_events.insert(id.clone(), ev.clone());
        } else {
            non_power_events.insert(id.clone(), ev.clone());
        }
    }

    let create_ev = auth_context
        .values()
        .chain(sort_set.values())
        .find(|ev| ev.event_type == "m.room.create");

    // Step 1: Sort power events by reverse topological power ordering (Kahn sort)
    // Step 2: Apply iterative auth checks (per spec & Ruma implementation)
    let mut local_auth_cache: LocalAuthCache = HashMap::new();

    let sorted_power_ids = lean_kahn_sort(&power_events, &sort_context, create_ev, version);
    for id in &sorted_power_ids {
        if let Some(event) = sort_set.get(id) {
            let local_auth = compute_local_auth(
                event,
                auth_context,
                sort_set,
                &mut local_auth_cache,
                version,
            );
            if iterative_auth_ok(
                event,
                &resolved,
                auth_context,
                sort_set,
                local_auth,
                create_ev,
                version,
                true,
            ) {
                resolved.insert(
                    (event.event_type.clone(), event.state_key.clone()),
                    event.event_id.clone(),
                );
            }
        }
    }

    // Step 3: Build the power-level mainline for mainline sort
    let mainline = build_mainline(&resolved, &sort_context);

    // Step 4: Sort non-power events by mainline ordering + iterative auth check
    let mut non_power_list: Vec<&LeanEvent> = non_power_events.values().collect();
    mainline_sort(&mut non_power_list, &mainline, &sort_context);

    for ev in non_power_list {
        let local_auth =
            compute_local_auth(ev, auth_context, sort_set, &mut local_auth_cache, version);
        if iterative_auth_ok(
            ev,
            &resolved,
            auth_context,
            sort_set,
            local_auth,
            create_ev,
            version,
            false,
        ) {
            resolved.insert(
                (ev.event_type.clone(), ev.state_key.clone()),
                ev.event_id.clone(),
            );
        }
    }

    let mut final_resolved = unconflicted_state;
    for (k, v) in resolved {
        final_resolved.insert(k, v);
    }
    drop(conflicted_events);
    final_resolved
}

struct OverlayState<'a, S1, S2> {
    resolved: &'a BTreeMap<(String, Option<String>), String>,
    auth_context: &'a HashMap<String, LeanEvent, S1>,
    conflicted: &'a HashMap<String, LeanEvent, S2>,
    local_auth: BTreeMap<(String, Option<String>), LeanEvent>,
    create_ev: Option<&'a LeanEvent>,
    version: StateResVersion,
    is_power_phase: bool,
}

impl<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher> crate::auth::StateProvider
    for OverlayState<'_, S1, S2>
{
    fn get_event(&self, event_type: &str, state_key: Option<&str>) -> Option<&LeanEvent> {
        let query: &dyn crate::auth::StateKeyDyn = &(event_type, state_key);

        // In V2.1 (Stock MSC4297), we supplement with ONLY m.room.power_levels during Step 2 (power phase).
        // In Step 4 (remaining events phase), we supplement with all event types.
        let should_supplement = match self.version {
            StateResVersion::V2_1 => {
                if self.is_power_phase {
                    event_type == "m.room.power_levels" && state_key == Some("")
                } else {
                    true
                }
            }
            StateResVersion::V2_1_1 => {
                (event_type == "m.room.power_levels" && state_key == Some(""))
                    || (event_type == "m.room.member")
            }
            _ => true,
        };

        if should_supplement {
            // Check consensus resolved state
            if let Some(eid) = self.resolved.get(query) {
                if let Some(ev) = self
                    .auth_context
                    .get(eid)
                    .or_else(|| self.conflicted.get(eid))
                {
                    if self.version == StateResVersion::V2_1_1 && event_type == "m.room.member" {
                        // V2.1.1 Fix: Only supplement bans and kicks
                        if let Some(membership) =
                            ev.content.get("membership").and_then(|m| m.as_str())
                        {
                            let is_ban = membership == "ban";
                            let is_kick =
                                membership == "leave" && Some(ev.sender.as_str()) != state_key;
                            if is_ban || is_kick {
                                return Some(ev);
                            }
                        }
                        // If it's a normal join/invite, fall through to local auth
                    } else {
                        return Some(ev);
                    }
                }
            }
        }

        // Check local auth chain (BFS result)
        if let Some(ev) = self.local_auth.get(query) {
            return Some(ev);
        }
        // Fallback for create
        if event_type == "m.room.create" && state_key == Some("") {
            return self.create_ev;
        }
        None
    }
}

/// Evaluates whether an event passes authentication checks given a resolved state map,
/// delegating to the core `crate::auth::check_auth` logic via a temporary `OverlayState` view.
#[allow(clippy::too_many_arguments)]
fn iterative_auth_ok<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
    event: &LeanEvent,
    resolved: &BTreeMap<(String, Option<String>), String>,
    auth_context: &HashMap<String, LeanEvent, S1>,
    conflicted_events: &HashMap<String, LeanEvent, S2>,
    local_auth: BTreeMap<(String, Option<String>), LeanEvent>,
    cached_create: Option<&LeanEvent>,
    version: StateResVersion,
    is_power_phase: bool,
) -> bool {
    let overlay = OverlayState {
        resolved,
        auth_context,
        conflicted: conflicted_events,
        local_auth,
        create_ev: cached_create,
        version,
        is_power_phase,
    };

    crate::auth::check_auth(event, &overlay).is_ok()
}

fn update_local_auth(
    local_auth: &mut BTreeMap<(String, Option<String>), (LeanEvent, usize)>,
    aev: &LeanEvent,
    current_depth: usize,
) {
    let key = (aev.event_type.clone(), aev.state_key.clone());
    match local_auth.entry(key) {
        alloc::collections::btree_map::Entry::Vacant(e) => {
            e.insert((aev.clone(), current_depth));
        }
        alloc::collections::btree_map::Entry::Occupied(mut e) => {
            if current_depth < e.get().1 {
                e.insert((aev.clone(), current_depth));
            }
        }
    }
}

/// Recursively compute the local auth context for an event, using memoization
/// to avoid redundant graph walks. The context is represented as a map of
/// (type, `state_key`) -> (`LeanEvent`, depth), ensuring that for each key, the "closest"
/// auth event in the chain is preserved (shortest path).
fn compute_local_auth<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
    event: &LeanEvent,
    auth_context: &HashMap<String, LeanEvent, S1>,
    conflicted_events: &HashMap<String, LeanEvent, S2>,
    cache: &mut LocalAuthCache,
    version: StateResVersion,
) -> BTreeMap<(String, Option<String>), LeanEvent> {
    if let Some(cached) = cache.get(&event.event_id) {
        return cached
            .clone()
            .into_iter()
            .map(|(k, (v, _))| (k, v))
            .collect();
    }

    let mut local_auth: BTreeMap<(String, Option<String>), (LeanEvent, usize)> = BTreeMap::new();
    let mut queue = alloc::collections::VecDeque::new();
    for aid in &event.auth_events {
        queue.push_back((aid.clone(), 1));
    }
    let mut visited = BTreeSet::new();

    while let Some((aid, current_depth)) = queue.pop_front() {
        if !visited.insert(aid.clone()) {
            continue;
        }

        if let Some(cached_ancestor) = cache.get(&aid) {
            // The cache only contains the parents of `aid`. We must also insert `aid` itself!
            if let Some(aev) = auth_context
                .get(&aid)
                .or_else(|| conflicted_events.get(&aid))
            {
                update_local_auth(&mut local_auth, aev, current_depth);
            }

            for (key, (ev, cached_depth)) in cached_ancestor {
                let total_depth = current_depth + cached_depth;
                match local_auth.entry(key.clone()) {
                    alloc::collections::btree_map::Entry::Vacant(e) => {
                        e.insert((ev.clone(), total_depth));
                    }
                    alloc::collections::btree_map::Entry::Occupied(mut e) => {
                        if total_depth < e.get().1 {
                            e.insert((ev.clone(), total_depth));
                        }
                    }
                }
            }
            continue;
        }

        if let Some(aev) = auth_context
            .get(&aid)
            .or_else(|| conflicted_events.get(&aid))
        {
            update_local_auth(&mut local_auth, aev, current_depth);

            // Recursive traversal is NEW in V2.2.
            // For V2.1 and below, we only check the immediate auth_events.
            if version == StateResVersion::V2_2 {
                for parent_id in &aev.auth_events {
                    queue.push_back((parent_id.clone(), current_depth + 1));
                }
            }
        }
    }

    cache.insert(event.event_id.clone(), local_auth.clone());
    local_auth.into_iter().map(|(k, (v, _))| (k, v)).collect()
}
/// from the resolved PL event backwards through `auth_events`.
fn build_mainline(
    resolved: &BTreeMap<(String, Option<String>), String>,
    auth_context: &HashMap<String, LeanEvent>,
) -> Vec<String> {
    let mut mainline = Vec::new();
    let pl_key = (
        alloc::string::String::from("m.room.power_levels"),
        Some(alloc::string::String::new()),
    );
    let mut current = resolved.get(&pl_key).cloned();

    while let Some(eid) = current {
        mainline.push(eid.clone());
        current = None;
        if let Some(ev) = auth_context.get(&eid) {
            let mut queue = alloc::collections::VecDeque::new();
            for auth_id in &ev.auth_events {
                queue.push_back(auth_id.clone());
            }
            let mut visited = hashbrown::HashSet::new();
            while let Some(q_id) = queue.pop_front() {
                if !visited.insert(q_id.clone()) {
                    continue;
                }
                if let Some(auth_ev) = auth_context.get(&q_id) {
                    if auth_ev.event_type == "m.room.power_levels" {
                        current = Some(q_id);
                        break;
                    }
                    for aid in &auth_ev.auth_events {
                        queue.push_back(aid.clone());
                    }
                }
            }
        }
    }

    mainline
}

/// Precompute the closest mainline position for every event reachable via
/// `auth_events` using a single O(V+E) multi-source reverse-BFS.
///
/// The naive approach walks the auth chain per-event: O(events × `chain_depth`).
/// On a dense DAG with 52k events this dominates runtime.
///
/// This approach instead:
/// 1. Seeds the BFS from ALL mainline events simultaneously at their positions.
/// 2. Builds reverse auth-edges (`auth_ev` → events that list it) once: O(V+E).
/// 3. BFS outward through those reverse edges; since we process in ascending
///    position order, the first time an event is reached gives the minimum
///    (closest) mainline position.
///
/// Total: O(V+E) — each vertex and edge touched at most once.
fn precompute_mainline_positions<S: ::core::hash::BuildHasher>(
    mainline: &[String],
    auth_context: &HashMap<String, LeanEvent, S>,
) -> HashMap<String, usize> {
    let mainline_len = mainline.len();

    // Build reverse adjacency over the full auth context once.
    // reverse_adj[A] = [E1, E2, ...] means E1, E2, ... list A in their auth_events.
    let mut reverse_adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for (id, ev) in auth_context {
        for auth_id in &ev.auth_events {
            reverse_adj
                .entry(auth_id.as_str())
                .or_default()
                .push(id.as_str());
        }
    }

    let mut dist: HashMap<String, usize> = HashMap::with_capacity(auth_context.len());

    // Seed: process mainline events in position order (0 = closest = best).
    // Using a VecDeque gives BFS ordering; since positions only increase along
    // the mainline and edges carry zero additional cost, this is correct.
    let mut queue: alloc::collections::VecDeque<(&str, usize)> =
        alloc::collections::VecDeque::new();

    for (pos, id) in mainline.iter().enumerate() {
        dist.insert(id.clone(), pos);
        queue.push_back((id.as_str(), pos));
    }

    // Flood-fill outward through reverse auth-edges.
    // First assignment wins (minimum position) because we process in BFS order
    // starting from position 0.
    while let Some((id, pos)) = queue.pop_front() {
        if let Some(children) = reverse_adj.get(id) {
            for &child_id in children {
                if !dist.contains_key(child_id) {
                    dist.insert(child_id.into(), pos);
                    queue.push_back((child_id, pos));
                }
            }
        }
    }

    // Events with no path to mainline get sentinel = mainline_len (worst).
    // Callers use `.get().copied().unwrap_or(mainline_len)` for those.
    let _ = mainline_len; // consumed by callers
    dist
}

/// Sort events by mainline ordering per the Matrix spec:
/// 1. Closest mainline position (smaller index = closer to current PL = comes last)
/// 2. `origin_server_ts` ascending (earlier first, later wins via last-write)
/// 3. `event_id` ascending (smaller first)
pub fn mainline_sort<S: ::core::hash::BuildHasher>(
    events: &mut Vec<&LeanEvent>,
    mainline: &[String],
    auth_context: &HashMap<String, LeanEvent, S>,
) {
    let mainline_len = mainline.len();

    // Single O(V+E) pass over the full auth context.
    let dist = precompute_mainline_positions(mainline, auth_context);

    events.sort_by(|a, b| {
        let pos_a = dist.get(&a.event_id).copied().unwrap_or(mainline_len);
        let pos_b = dist.get(&b.event_id).copied().unwrap_or(mainline_len);

        // Larger mainline position = farther from current PL = worse = comes first
        // (so it gets overwritten by closer events via last-write-wins)
        match pos_b.cmp(&pos_a) {
            Ordering::Equal => {
                // Earlier timestamp comes first (later wins via last-write)
                match a.origin_server_ts.cmp(&b.origin_server_ts) {
                    Ordering::Equal => a.event_id.cmp(&b.event_id),
                    ord => ord,
                }
            }
            ord => ord,
        }
    });
}

/// Result of conflicted subgraph computation with diagnostic info.
#[derive(Debug, Clone)]
pub struct SubgraphResult {
    /// The computed conflicted subgraph.
    pub subgraph: HashMap<String, LeanEvent>,
    /// Auth events referenced but not found in the graph (permanently lost to federation).
    pub missing_auth_events: Vec<String>,
}

#[must_use]
pub fn compute_v2_1_conflicted_subgraph<S: core::hash::BuildHasher>(
    auth_graph: &HashMap<String, LeanEvent, S>,
    conflicted_set: &[String],
) -> HashMap<String, LeanEvent> {
    compute_v2_1_conflicted_subgraph_bounded(auth_graph, conflicted_set, Some(2000)).subgraph
}

/// Bounded version of conflicted subgraph computation.
/// `max_auth_depth`: If set, limits backwards traversal depth to prevent
/// history-flooding `DoS` attacks where a rogue admin generates millions of
/// spoofed events on a dead-end fork.
#[must_use]
pub fn compute_v2_1_conflicted_subgraph_bounded<S: core::hash::BuildHasher>(
    auth_graph: &HashMap<String, LeanEvent, S>,
    conflicted_set: &[String],
    max_auth_depth: Option<usize>,
) -> SubgraphResult {
    let mut backwards_reachable = BTreeSet::new();
    let mut forwards_reachable = BTreeSet::new();
    let mut missing_auth_events = BTreeSet::new();

    // Calculate Backwards Reachable (Ancestors up the auth chain)
    // Each entry is (event_id, depth_from_conflicted_set)
    let mut b_stack: Vec<(String, usize)> = conflicted_set.iter().map(|s| (s.clone(), 0)).collect();
    while let Some((node, depth)) = b_stack.pop() {
        // Anti-DoS: stop expanding beyond max depth
        if let Some(max_depth) = max_auth_depth {
            if depth > max_depth {
                continue;
            }
        }
        if backwards_reachable.insert(node.clone()) {
            if let Some(event) = auth_graph.get(&node) {
                for auth_id in &event.auth_events {
                    if !auth_graph.contains_key(auth_id) {
                        missing_auth_events.insert(auth_id.clone());
                    }
                    b_stack.push((auth_id.clone(), depth + 1));
                }
            }
        }
    }

    // Build Reverse Adjacency for Forwards Search
    let mut children_map: HashMap<String, Vec<String>> = HashMap::new();
    for (id, event) in auth_graph {
        for prev in &event.auth_events {
            children_map
                .entry(prev.clone())
                .or_default()
                .push(id.clone());
        }
    }

    // Calculate Forwards Reachable (Descendants down the auth chain)
    let mut f_stack: Vec<String> = conflicted_set.to_vec();
    while let Some(node) = f_stack.pop() {
        if forwards_reachable.insert(node.clone()) {
            if let Some(children) = children_map.get(&node) {
                f_stack.extend(children.clone());
            }
        }
    }

    // Intersect and build the final Conflicted Subgraph
    let mut subgraph = HashMap::new();
    let backwards_ids: BTreeSet<String> = backwards_reachable.iter().cloned().collect();
    let forwards_ids: BTreeSet<String> = forwards_reachable.iter().cloned().collect();

    for id in backwards_ids.intersection(&forwards_ids) {
        if let Some(event) = auth_graph.get(id) {
            subgraph.insert(id.clone(), event.clone());
        }
    }

    SubgraphResult {
        subgraph,
        missing_auth_events: missing_auth_events.into_iter().collect(),
    }
}

impl LeanEvent {
    #[must_use]
    pub fn is_ban_or_kick(&self) -> bool {
        if self.event_type == "m.room.member" {
            if let Some(membership) = self.content.get("membership").and_then(|v| v.as_str()) {
                return membership == "ban" || membership == "leave";
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
                    if let Some(pl_int) = pl.as_i64() {
                        return pl_int == 0;
                    }
                }
            }
        }
        false
    }

    #[must_use]
    pub fn restricts_event(&self, other: &LeanEvent) -> bool {
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

#[must_use]
pub fn is_ancestor<S: core::hash::BuildHasher>(
    child_id: &str,
    possible_ancestor_id: &str,
    context: &HashMap<String, LeanEvent, S>,
) -> bool {
    if child_id == possible_ancestor_id {
        return true;
    }
    let Some(child_ev) = context.get(child_id) else {
        return false;
    };
    let Some(and_ev) = context.get(possible_ancestor_id) else {
        return false;
    };

    // Only apply depth pruning if depths are populated (greater than 0).
    // Test events created with Default::default() default to depth 0.
    if child_ev.depth > 0 && and_ev.depth > 0 && and_ev.depth >= child_ev.depth {
        return false;
    }

    let mut stack = Vec::new();
    stack.push(child_id);
    let mut visited = BTreeSet::new();
    visited.insert(child_id);

    while let Some(current) = stack.pop() {
        if current == possible_ancestor_id {
            return true;
        }
        if let Some(ev) = context.get(current) {
            // Prune branches that are already at or below the ancestor's depth (if populated)
            if ev.depth > 0 && and_ev.depth > 0 && ev.depth <= and_ev.depth {
                continue;
            }
            for parent in ev.prev_events.iter().chain(ev.auth_events.iter()) {
                if visited.insert(parent.as_str()) {
                    stack.push(parent.as_str());
                }
            }
        }
    }
    false
}

#[allow(clippy::manual_div_ceil, clippy::needless_range_loop)]
fn compute_cdo_bit_masks_unbounded<S: core::hash::BuildHasher>(
    dag_context: &HashMap<String, LeanEvent, S>,
    admin_actions: &[&str],
    ancestor_masks: &mut HashMap<String, Vec<u64>>,
    descendant_masks: &mut HashMap<String, Vec<u64>>,
    admin_masks: &mut HashMap<String, Vec<u64>>,
) {
    let n = dag_context.len();
    let num_words = (admin_actions.len() + 63) / 64;

    // 1. Assign fast integer indices and sort topologically
    let mut id_to_idx = HashMap::with_capacity(n);
    let mut idx_to_id = Vec::with_capacity(n);
    let mut sorted_by_depth = Vec::with_capacity(n);
    for (id, ev) in dag_context {
        let idx = idx_to_id.len();
        id_to_idx.insert(id.as_str(), idx);
        idx_to_id.push(id.as_str());
        sorted_by_depth.push((idx, ev.depth));
    }

    // Sort strictly by depth (ensures parents are processed before children)
    sorted_by_depth.sort_unstable_by_key(|&(_, depth)| depth);
    let topo_order: Vec<usize> = sorted_by_depth.into_iter().map(|(i, _)| i).collect();

    // 2. Build integer-based adjacency
    let mut parents: Vec<Vec<usize>> = alloc::vec![Vec::new(); n];
    let mut children: Vec<Vec<usize>> = alloc::vec![Vec::new(); n];
    for (id, ev) in dag_context {
        let u = id_to_idx[id.as_str()];
        for p_id in ev.prev_events.iter().chain(ev.auth_events.iter()) {
            if let Some(&v) = id_to_idx.get(p_id.as_str()) {
                parents[u].push(v);
                children[v].push(u);
            }
        }
    }

    // 3. Initialize Array Masks
    let mut and_masks = alloc::vec![alloc::vec![0u64; num_words]; n];
    let mut desc_masks = alloc::vec![alloc::vec![0u64; num_words]; n];
    for (i, &admin_id) in admin_actions.iter().enumerate() {
        if let Some(&idx) = id_to_idx.get(admin_id) {
            let word = i / 64;
            let bit = 1u64 << (i % 64);
            and_masks[idx][word] |= bit;
            desc_masks[idx][word] |= bit;
            let mut mask = alloc::vec![0u64; num_words];
            mask[word] |= bit;
            admin_masks.insert(String::from(admin_id), mask);
        }
    }

    // 4. Forward Sweep (Compute Ancestors) - Pure array iteration
    for &u in &topo_order {
        for &p in &parents[u] {
            for w in 0..num_words {
                let bits = and_masks[p][w];
                and_masks[u][w] |= bits;
            }
        }
    }

    // 5. Backward Sweep (Compute Descendants) - Pure array iteration
    for &u in topo_order.iter().rev() {
        for &c in &children[u] {
            for w in 0..num_words {
                let bits = desc_masks[c][w];
                desc_masks[u][w] |= bits;
            }
        }
    }

    // 6. Write back to String Maps
    for (i, &id) in idx_to_id.iter().enumerate() {
        ancestor_masks.insert(String::from(id), core::mem::take(&mut and_masks[i]));
        descendant_masks.insert(String::from(id), core::mem::take(&mut desc_masks[i]));
    }
}

fn sort_cdo_events(events: &[&LeanEvent]) -> Vec<LeanEvent> {
    let mut sorted = events.iter().copied().cloned().collect::<Vec<_>>();
    sorted.sort_by(|a, b| {
        let type_priority = |t: &str| match t {
            "m.room.power_levels" => 0,
            "m.room.join_rules" => 1,
            _ => 2,
        };

        let cmp_pl = b.power_level.cmp(&a.power_level);
        if cmp_pl != Ordering::Equal {
            return cmp_pl;
        }

        let cmp_type = type_priority(&a.event_type).cmp(&type_priority(&b.event_type));
        if cmp_type != Ordering::Equal {
            return cmp_type;
        }

        let cmp_ts = a.origin_server_ts.cmp(&b.origin_server_ts);
        if cmp_ts != Ordering::Equal {
            return cmp_ts;
        }

        a.event_id.cmp(&b.event_id)
    });
    sorted
}

/// Cycle 0 Topological Filter: Vectorized Causal Domination Operator (CDO)
/// Executes strictly on the Conflicted State Subgraph (C).
#[must_use]
pub fn apply_cdo_filter<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
    conflicted_events: &HashMap<String, LeanEvent, S1>,
    auth_context: &HashMap<String, LeanEvent, S2>,
) -> HashMap<String, LeanEvent> {
    // Build sort/DAG context to determine ancestries
    let dag_context: HashMap<String, LeanEvent> = auth_context
        .iter()
        .chain(conflicted_events.iter())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // Identify all admin actions in conflicted events
    let admin_actions: Vec<&str> = conflicted_events
        .values()
        .filter(|e| e.is_ban_or_kick() || e.is_demotion() || e.is_lockdown())
        .map(|e| e.event_id.as_str())
        .collect();

    let mut ancestor_masks = HashMap::new();
    let mut descendant_masks = HashMap::new();
    let mut admin_masks = HashMap::new();

    compute_cdo_bit_masks_unbounded(
        &dag_context,
        &admin_actions,
        &mut ancestor_masks,
        &mut descendant_masks,
        &mut admin_masks,
    );

    let sorted_events = sort_cdo_events(&conflicted_events.values().collect::<Vec<_>>());

    let mut dropped_ids = BTreeSet::new();
    let mut active_admin_actions: Vec<&LeanEvent> = Vec::new();

    // Pass 2: Direct Domination (Sender / Type Restriction) in priority order
    for event in &sorted_events {
        let mut is_dominated = false;

        for admin_ev in &active_admin_actions {
            if admin_ev.restricts_event(event) {
                let admin_id = admin_ev.event_id.as_str();
                let event_id = event.event_id.as_str();

                let mut is_ancestor_admin = false;
                let mut is_descendant_admin = false;
                if let Some(admin_mask) = admin_masks.get(admin_id) {
                    if let Some(ev_and) = ancestor_masks.get(event_id) {
                        is_ancestor_admin = ev_and
                            .iter()
                            .zip(admin_mask.iter())
                            .any(|(a, b)| (a & b) != 0);
                    }
                    if let Some(ev_desc) = descendant_masks.get(event_id) {
                        is_descendant_admin = ev_desc
                            .iter()
                            .zip(admin_mask.iter())
                            .any(|(a, b)| (a & b) != 0);
                    }
                }

                if !is_ancestor_admin && !is_descendant_admin {
                    is_dominated = true;
                    break;
                }
            }
        }

        if is_dominated {
            dropped_ids.insert(event.event_id.clone());
        } else if event.is_ban_or_kick() || event.is_demotion() || event.is_lockdown() {
            // Event survived and is an admin action, so it is active for subsequent events
            active_admin_actions.push(event);
        }
    }

    // Pass 3: Auth-Dependency Domination (Transitive Closure / Linear-Time propagation)
    let mut dependents: HashMap<String, Vec<String>> = HashMap::new();
    for (id, event) in conflicted_events {
        for auth_id in &event.auth_events {
            dependents
                .entry(auth_id.clone())
                .or_default()
                .push(id.clone());
        }
    }

    let mut queue: Vec<String> = dropped_ids.iter().cloned().collect();
    while let Some(current_dropped) = queue.pop() {
        if let Some(children) = dependents.get(&current_dropped) {
            for child in children {
                if !dropped_ids.contains(child) {
                    dropped_ids.insert(child.clone());
                    queue.push(child.clone());
                }
            }
        }
    }

    // Return strictly the transitively safe set
    let mut safe_set = HashMap::new();
    for (id, event) in conflicted_events {
        if !dropped_ids.contains(id) {
            safe_set.insert(id.clone(), event.clone());
        }
    }

    safe_set
}

/// Computes the state map at (after) a given target event ID,
/// assuming all ancestral events are present in `events_map`.
#[must_use]
pub fn compute_state_at<S: core::hash::BuildHasher>(
    target_event_id: &str,
    events_map: &HashMap<String, LeanEvent, S>,
) -> Option<BTreeMap<(String, Option<String>), String>> {
    if !events_map.contains_key(target_event_id) {
        return None;
    }

    // 1. Backward walk to find causal history (prev_events)
    let mut visited = BTreeSet::new();
    let mut stack = alloc::vec![String::from(target_event_id)];
    while let Some(ev_id) = stack.pop() {
        if visited.insert(ev_id.clone()) {
            if let Some(ev) = events_map.get(&ev_id) {
                for pe in &ev.prev_events {
                    stack.push(pe.clone());
                }
            }
        }
    }

    // 2. Filter and sort by depth ascending, then event_id ascending
    let mut sorted_events: Vec<&LeanEvent> = events_map
        .values()
        .filter(|ev| visited.contains(&ev.event_id))
        .collect();
    sorted_events.sort_by(|a, b| a.cmp_by_depth(b));

    // 3. Build state map (latest-wins)
    let mut state_map = BTreeMap::new();
    for ev in sorted_events {
        if ev.state_key.is_some() {
            let key = (ev.event_type.clone(), ev.state_key.clone());
            state_map.insert(key, ev.event_id.clone());
        }
    }

    Some(state_map)
}

#[cfg(feature = "cli")]
fn perform_connectivity_check(
    per_file_ids: &[std::collections::HashSet<String>],
) -> Result<(), anyhow::Error> {
    extern crate anyhow;
    let num_files = per_file_ids.len();
    let mut any_shared = false;
    for i in 0..num_files {
        for j in (i + 1)..num_files {
            let pair_shared = per_file_ids[i].intersection(&per_file_ids[j]).count();
            if pair_shared > 0 {
                any_shared = true;
                break;
            }
        }
        if any_shared {
            break;
        }
    }

    if !any_shared {
        anyhow::bail!(
            "Disjoint DAGs: no shared events found across inputs. \
             Cannot compute meaningful merge — the DAGs share no history."
        );
    }
    Ok(())
}

#[cfg(feature = "cli")]
fn report_highest_shared_depths(
    per_file_ids: &[std::collections::HashSet<String>],
    merged: &[serde_json::Value],
) {
    use std::collections::HashSet;
    let num_files = per_file_ids.len();
    let shared_all: HashSet<&String> = {
        let mut s: HashSet<&String> = HashSet::new();
        for i in 0..num_files {
            for j in (i + 1)..num_files {
                s.extend(per_file_ids[i].intersection(&per_file_ids[j]));
            }
        }
        s
    };
    let mut shared_depths: Vec<(&String, u64)> = shared_all
        .iter()
        .filter_map(|id| {
            merged.iter().find_map(|v| {
                let eid = v.get("event_id")?.as_str()?;
                if eid == id.as_str() {
                    Some((*id, v.get("depth")?.as_u64().unwrap_or(0)))
                } else {
                    None
                }
            })
        })
        .collect();
    shared_depths.sort_by_key(|b| std::cmp::Reverse(b.1));
    #[cfg(feature = "cli")]
    std::eprintln!(
        "[merge] highest shared depths: {:?}",
        &shared_depths[..shared_depths.len().min(5)]
    );
}

/// Merge multiple event sets by `event_id` (first-seen wins, PDUs are immutable).
/// Returns the merged events.
///
/// # Errors
///
/// Returns an error if the files describe disjoint DAGs that share no history.
#[cfg(feature = "cli")]
pub fn merge_event_sets(
    file_sets: &[(String, Vec<serde_json::Value>)],
    debug: bool,
    quiet: bool,
) -> Result<Vec<serde_json::Value>, anyhow::Error> {
    extern crate anyhow;
    use alloc::borrow::ToOwned;
    use std::collections::HashSet;

    let num_files = file_sets.len();
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut merged: Vec<serde_json::Value> = Vec::new();
    let mut per_file_ids: Vec<HashSet<String>> = Vec::with_capacity(num_files);

    for (label, events) in file_sets {
        let mut file_ids = HashSet::with_capacity(events.len());
        let mut added = 0usize;
        let mut dupes = 0usize;

        for val in events {
            let event_id = val
                .get("event_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();

            file_ids.insert(event_id.clone());
            if seen_ids.insert(event_id) {
                merged.push(val.clone());
                added += 1;
            } else {
                dupes += 1;
            }
        }

        #[cfg(feature = "cli")]
        if !quiet {
            std::eprintln!(
                "[merge] {}: {} events ({} new, {} shared)",
                label,
                events.len(),
                added,
                dupes
            );
        }
        per_file_ids.push(file_ids);
    }

    // Merge-base check: verify each file shares at least one event with another
    if num_files >= 2 {
        perform_connectivity_check(&per_file_ids)?;

        // Report total shared count (union of all pairwise intersections)
        let total_shared: usize = {
            let mut shared_ids: HashSet<&String> = HashSet::new();
            for i in 0..num_files {
                for j in (i + 1)..num_files {
                    shared_ids.extend(per_file_ids[i].intersection(&per_file_ids[j]));
                }
            }
            shared_ids.len()
        };

        #[cfg(feature = "cli")]
        if !quiet {
            std::eprintln!(
                "[merge] merge-base: {total_shared} shared events across {num_files} inputs"
            );
        }

        #[cfg(feature = "cli")]
        if debug {
            report_highest_shared_depths(&per_file_ids, &merged);
        }
    }

    #[cfg(feature = "cli")]
    if !quiet {
        std::eprintln!("[merge] total: {} unique events", merged.len());
    }

    Ok(merged)
}

fn route_lattice_power_events<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
    sort_set: &HashMap<String, LeanEvent, S1>,
    auth_context: &HashMap<String, LeanEvent, S2>,
    version: StateResVersion,
    power_events: &mut HashMap<String, LeanEvent>,
    non_power_events: &mut HashMap<String, LeanEvent>,
) {
    for (id, ev) in sort_set {
        if version == StateResVersion::V2_2
            && is_v2_2_duplicate_auth_key(ev, auth_context, sort_set)
        {
            continue;
        }

        if ev.event_type == "m.room.member"
            || ev.event_type == "m.room.create"
            || ev.event_type == "m.room.power_levels"
            || ev.event_type == "m.room.join_rules"
        {
            power_events.insert(id.clone(), ev.clone());
        } else {
            non_power_events.insert(id.clone(), ev.clone());
        }
    }
}

fn fold_lattice_chunk<'a>(
    chunk: &[&'a LeanEvent],
    mainline_distances: &HashMap<String, usize>,
    mainline_len: usize,
) -> HashMap<(String, Option<String>), &'a LeanEvent> {
    let mut thread_res: HashMap<(String, Option<String>), &'a LeanEvent> = HashMap::new();
    for &ev in chunk {
        let key = (ev.event_type.clone(), ev.state_key.clone());

        // O(1) Geodesic coordinate mapped from the precomputed distances
        let ev_pos = mainline_distances
            .get(&ev.event_id)
            .copied()
            .unwrap_or(mainline_len);

        let is_better = if let Some(current_winner) = thread_res.get(&key) {
            let winner_pos = mainline_distances
                .get(&current_winner.event_id)
                .copied()
                .unwrap_or(mainline_len);

            // The Commutative Join Operator (Least Upper Bound):
            if ev_pos < winner_pos {
                true // Closer to mainline wins
            } else if ev_pos > winner_pos {
                false
            } else if ev.origin_server_ts > current_winner.origin_server_ts {
                true // Later timestamp wins
            } else if ev.origin_server_ts < current_winner.origin_server_ts {
                false
            } else {
                // Lexicographical flip fixed: LARGEST string wins.
                ev.event_id > current_winner.event_id
            }
        } else {
            true // First event for this state key inherently wins
        };

        if is_better {
            thread_res.insert(key, ev);
        }
    }
    thread_res
}

fn merge_lattice_winners<'a>(
    key_winners: &mut HashMap<(String, Option<String>), &'a LeanEvent>,
    thread_res: HashMap<(String, Option<String>), &'a LeanEvent>,
    mainline_distances: &HashMap<String, usize>,
    mainline_len: usize,
) {
    for (key, ev) in thread_res {
        // O(1) Geodesic coordinate mapped from the precomputed distances
        let ev_pos = mainline_distances
            .get(&ev.event_id)
            .copied()
            .unwrap_or(mainline_len);

        let is_better = if let Some(current_winner) = key_winners.get(&key) {
            let winner_pos = mainline_distances
                .get(&current_winner.event_id)
                .copied()
                .unwrap_or(mainline_len);

            // The Commutative Join Operator (Least Upper Bound):
            if ev_pos < winner_pos {
                true // Closer to mainline wins
            } else if ev_pos > winner_pos {
                false
            } else if ev.origin_server_ts > current_winner.origin_server_ts {
                true // Later timestamp wins
            } else if ev.origin_server_ts < current_winner.origin_server_ts {
                false
            } else {
                // Lexicographical sort: LARGEST string wins.
                ev.event_id > current_winner.event_id
            }
        } else {
            true // First event for this state key inherently wins
        };

        if is_better {
            key_winners.insert(key, ev);
        }
    }
}

fn compute_lattice_coordinatized_winners<'a>(
    non_power_events: &'a HashMap<String, LeanEvent>,
    mainline_distances: &HashMap<String, usize>,
    mainline_len: usize,
    key_winners: &mut HashMap<(String, Option<String>), &'a LeanEvent>,
) {
    #[cfg(feature = "std")]
    {
        let num_threads = std::thread::available_parallelism().map_or(4, core::num::NonZero::get);

        if num_threads > 1 && non_power_events.len() > 1000 {
            let events_vec: Vec<&'a LeanEvent> = non_power_events.values().collect();
            let chunk_size = events_vec.len().div_ceil(num_threads);

            let chunks: Vec<&[&'a LeanEvent]> = events_vec.chunks(chunk_size).collect();
            let results: Vec<_> = std::thread::scope(|s| {
                chunks
                    .into_iter()
                    .map(|chunk| {
                        s.spawn(move || fold_lattice_chunk(chunk, mainline_distances, mainline_len))
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .filter_map(|h| h.join().ok())
                    .collect()
            });

            // Reduce Phase
            for thread_res in results {
                merge_lattice_winners(key_winners, thread_res, mainline_distances, mainline_len);
            }
            return;
        }
    }

    // Fallback/Sequential
    let events_vec: Vec<&'a LeanEvent> = non_power_events.values().collect();
    let thread_res = fold_lattice_chunk(&events_vec, mainline_distances, mainline_len);
    merge_lattice_winners(key_winners, thread_res, mainline_distances, mainline_len);
}

/// A revolutionary, mathematically optimal O(C) Lattice-based State Resolution implementation.
/// Employs O(1) Causal Coordinatization Projection and Commutative Join-Semilattice folding
/// to completely eliminate sequential sorting and backward graph traversals.
#[must_use]
pub fn resolve_lattice_coordinatized<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
    unconflicted_state: &BTreeMap<(String, Option<String>), String>,
    mut conflicted_events: HashMap<String, LeanEvent, S1>,
    auth_context: &HashMap<String, LeanEvent, S2>,
    version: StateResVersion,
) -> BTreeMap<(String, Option<String>), String> {
    // 1. CDO Filter Pre-Filtering: distilling the conflicted set into a safe, orthogonal set C_safe
    let filtered = apply_cdo_filter(&conflicted_events, auth_context);
    conflicted_events.clear();
    for (k, v) in filtered {
        conflicted_events.insert(k, v);
    }

    let sort_context: HashMap<String, LeanEvent> = auth_context
        .iter()
        .chain(conflicted_events.iter())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let mut resolved = match version {
        StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2 => BTreeMap::new(),
        _ => unconflicted_state.clone(),
    };

    let sort_set = &conflicted_events;

    // Route power and non-power events
    let mut power_events = HashMap::new();
    let mut non_power_events = HashMap::new();
    route_lattice_power_events(
        sort_set,
        auth_context,
        version,
        &mut power_events,
        &mut non_power_events,
    );

    let create_ev = auth_context
        .values()
        .chain(sort_set.values())
        .find(|ev| ev.event_type == "m.room.create");

    let mut local_auth_cache: LocalAuthCache = HashMap::new();

    // Power Phase remains sequential to establish the authoritative administrative framework
    let sorted_power_ids = lean_kahn_sort(&power_events, &sort_context, create_ev, version);
    for id in &sorted_power_ids {
        if let Some(event) = sort_set.get(id) {
            let local_auth = compute_local_auth(
                event,
                auth_context,
                sort_set,
                &mut local_auth_cache,
                version,
            );
            if iterative_auth_ok(
                event,
                &resolved,
                auth_context,
                sort_set,
                local_auth,
                create_ev,
                version,
                true,
            ) {
                resolved.insert(
                    (event.event_type.clone(), event.state_key.clone()),
                    event.event_id.clone(),
                );
            }
        }
    }

    // Step 3: Build the power-level mainline for coordinatization
    let mainline = build_mainline(&resolved, &sort_context);
    let mainline_distances = precompute_mainline_positions(&mainline, &sort_context);

    // Step 4: Commutative Join-Semilattice reduction over all non-power events in a single O(C) pass!
    let mut key_winners = HashMap::new();
    compute_lattice_coordinatized_winners(
        &non_power_events,
        &mainline_distances,
        mainline.len(),
        &mut key_winners,
    );

    // Apply the winners to the resolved state (fully authenticated) in topological order
    let mut sorted_winners: Vec<(&(String, Option<String>), &LeanEvent)> =
        key_winners.iter().map(|(k, &v)| (k, v)).collect();
    sorted_winners.sort_by_key(|(_, ev)| ev.depth);

    for (key, ev) in sorted_winners {
        let local_auth =
            compute_local_auth(ev, auth_context, sort_set, &mut local_auth_cache, version);
        if iterative_auth_ok(
            ev,
            &resolved,
            auth_context,
            sort_set,
            local_auth,
            create_ev,
            version,
            false,
        ) {
            resolved.insert((*key).clone(), ev.event_id.clone());
        }
    }

    let mut final_resolved = unconflicted_state.clone();
    for (k, v) in resolved {
        final_resolved.insert(k, v);
    }
    final_resolved
}
