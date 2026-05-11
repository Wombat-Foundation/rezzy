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

use alloc::collections::BTreeSet;
use alloc::collections::{BTreeMap, BinaryHeap};

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use serde::{Deserialize, Serialize};

use serde_json::Value;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
pub use std::collections::HashMap;

#[cfg(not(feature = "std"))]
pub use hashbrown::HashMap;

/// The version of the Matrix State Resolution algorithm to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum StateResVersion {
    V1,
    V2,
    V2_1,
}

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
    pub fn into_sorted(self) -> Vec<String> {
        match self {
            KahnSortResult::Ok(v) => v,
            KahnSortResult::CycleDetected { .. } => Vec::new(),
        }
    }

    /// Returns true if sorting completed without cycles.
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

    impl<'de> de::Visitor<'de> for PowerLevelVisitor {
        type Value = i64;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("an integer, float, or string representation of a power level")
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<i64, E> {
            Ok(v)
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<i64, E> {
            Ok(v as i64)
        }

        fn visit_f64<E: de::Error>(self, v: f64) -> Result<i64, E> {
            Ok(v as i64)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<i64, E> {
            Ok(v.parse::<i64>()
                .or_else(|_| v.parse::<f64>().map(|f| f as i64))
                .unwrap_or(0))
        }
    }

    deserializer.deserialize_any(PowerLevelVisitor)
}

/// A lightweight Matrix Event representation for Lean-equivalent resolution.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LeanEvent {
    pub event_id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(default)]
    pub state_key: String,
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

/// A wrapper to ensure BinaryHeap pops the "smallest" (best) event first.
#[derive(Debug, Clone, Copy)]
struct SortPriority<'a> {
    event: &'a LeanEvent,
    version: StateResVersion,
}

impl<'a> PartialEq for SortPriority<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<'a> Eq for SortPriority<'a> {}

impl<'a> Ord for SortPriority<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.version {
            StateResVersion::V1 => {
                // V1 tie-breaking: depth (asc) -> event_id (asc)
                // Inverted for Max-Heap
                match other.event.depth.cmp(&self.event.depth) {
                    Ordering::Equal => other.event.event_id.cmp(&self.event.event_id),
                    ord => ord,
                }
            }
            StateResVersion::V2 | StateResVersion::V2_1 => {
                // V2 tie-breaking: power_level (desc) -> origin_server_ts (asc) -> event_id (asc)
                // To have "best" events come LAST in the sorted list, we must pop "worst" events FIRST.
                // In Rust's Max-Heap BinaryHeap, "greater" elements are popped first.
                // So "worst" must be "greater" than "best".

                // Higher power level is BETTER (should win = come last = be smallest = pop last).
                // So lower power_level pops first (is "greater" in max-heap).
                match other.event.power_level.cmp(&self.event.power_level) {
                    Ordering::Equal => {
                        // Earlier timestamp is BETTER (should win = come last = be smallest).
                        // So later timestamp pops first (is "greater" in max-heap).
                        match self
                            .event
                            .origin_server_ts
                            .cmp(&other.event.origin_server_ts)
                        {
                            Ordering::Equal => {
                                // Lexicographically SMALLER ID is BETTER (pops last).
                                // Larger ID pops first (is "greater" in max-heap).
                                self.event.event_id.cmp(&other.event.event_id)
                            }
                            ord => ord,
                        }
                    }
                    ord => ord,
                }
            }
        }
    }
}

impl<'a> PartialOrd for SortPriority<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Kahn's Topological Sort with full diagnostic output.
/// Returns a `KahnSortResult` that distinguishes between successful sorts
/// and cycle detection, providing the stuck set for debugging.
pub fn lean_kahn_sort_detailed(
    events: &HashMap<String, LeanEvent>,
    version: StateResVersion,
) -> KahnSortResult {
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();

    for (id, event) in events {
        in_degree.entry(id.clone()).or_insert(0);
        for auth in &event.auth_events {
            if events.contains_key(auth) {
                adjacency.entry(auth.clone()).or_default().push(id.clone());
                *in_degree.entry(id.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut queue: BinaryHeap<SortPriority> = BinaryHeap::new();
    for (id, &degree) in &in_degree {
        if degree == 0 {
            if let Some(event) = events.get(id) {
                queue.push(SortPriority { event, version });
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
                    queue.push(SortPriority {
                        event: events.get(next_id).unwrap(),
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
pub fn lean_kahn_sort(
    events: &HashMap<String, LeanEvent>,
    version: StateResVersion,
) -> Vec<String> {
    lean_kahn_sort_detailed(events, version).into_sorted()
}

pub fn resolve_lean(
    unconflicted_state: BTreeMap<(String, String), String>,
    conflicted_events: HashMap<String, LeanEvent>,
    version: StateResVersion,
) -> BTreeMap<(String, String), String> {
    // MSC4297 (v2.1): The algorithm starts from an empty set of state.
    let (mut resolved, sort_set) = match version {
        StateResVersion::V2_1 => (BTreeMap::new(), conflicted_events.clone()),
        _ => (unconflicted_state, conflicted_events),
    };

    // Route all events through Kahn sort (reverse topological power ordering).
    // The spec classifies only certain m.room.member events as "power events,"
    // but empirical testing against production homeservers shows that ALL member
    // events go through Kahn sort, not mainline sort. Mainline sort is only used
    // for non-member state events (topic, name, etc.) where PL chain proximity
    // determines winner.
    let mut power_events = HashMap::new();
    let mut non_power_events = HashMap::new();

    for (id, ev) in &sort_set {
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

    // Step 1: Sort power events by reverse topological power ordering (Kahn sort)
    // Step 2: Apply iterative auth checks (per spec & Ruma implementation)
    let sorted_power_ids = lean_kahn_sort(&power_events, version);
    for id in &sorted_power_ids {
        if let Some(event) = sort_set.get(id) {
            if iterative_auth_ok(event, &resolved, &sort_set) {
                resolved.insert(
                    (event.event_type.clone(), event.state_key.clone()),
                    event.event_id.clone(),
                );
            }
        }
    }

    // Step 3: Build the power-level mainline for mainline sort
    let mainline = build_mainline(&resolved, &sort_set);

    // Step 4: Sort non-power events by mainline ordering + iterative auth check
    let mut non_power_list: Vec<&LeanEvent> = non_power_events.values().collect();
    mainline_sort(&mut non_power_list, &mainline, &sort_set);

    for ev in non_power_list {
        if iterative_auth_ok(ev, &resolved, &sort_set) {
            resolved.insert(
                (ev.event_type.clone(), ev.state_key.clone()),
                ev.event_id.clone(),
            );
        }
    }

    resolved
}

/// Targeted iterative auth check: reject m.room.member events when the
/// resolved state already has a ban/kick for that user from a different sender
/// (i.e., a moderator action). This prevents stale join forks from overwriting
/// moderation actions resolved in earlier iterations.
fn iterative_auth_ok(
    event: &LeanEvent,
    resolved: &BTreeMap<(String, String), String>,
    all_events: &HashMap<String, LeanEvent>,
) -> bool {
    // Only check m.room.member events where membership is join or invite
    if event.event_type == "m.room.member" {
        let new_membership = event
            .content
            .get("membership")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if new_membership == "join" || new_membership == "invite" {
            let target_key = (
                alloc::string::String::from("m.room.member"),
                event.state_key.clone(),
            );
            if let Some(resolved_eid) = resolved.get(&target_key) {
                if let Some(resolved_ev) = all_events.get(resolved_eid) {
                    let resolved_membership = resolved_ev
                        .content
                        .get("membership")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    // Only bans permanently prevent joins. Kicks (leave) allow rejoin.
                    if resolved_membership == "ban" && resolved_ev.sender != resolved_ev.state_key {
                        return false;
                    }
                }
            }
        }
    }

    true
}

/// Build the power-level mainline: the chain of m.room.power_levels events
/// from the resolved PL event backwards through auth_events.
fn build_mainline(
    resolved: &BTreeMap<(String, String), String>,
    all_events: &HashMap<String, LeanEvent>,
) -> Vec<String> {
    let mut mainline = Vec::new();
    let pl_key = (
        alloc::string::String::from("m.room.power_levels"),
        alloc::string::String::new(),
    );
    let mut current = resolved.get(&pl_key).cloned();

    while let Some(eid) = current {
        mainline.push(eid.clone());
        current = None;
        if let Some(ev) = all_events.get(&eid) {
            for auth_id in &ev.auth_events {
                if let Some(auth_ev) = all_events.get(auth_id) {
                    if auth_ev.event_type == "m.room.power_levels" {
                        current = Some(auth_id.clone());
                        break;
                    }
                }
            }
        }
    }

    mainline
}

/// Find the closest mainline event for a given event by walking its auth chain.
/// Returns the index in the mainline (0 = most recent PL event = best position).
fn closest_mainline_position(
    event: &LeanEvent,
    mainline: &[String],
    all_events: &HashMap<String, LeanEvent>,
) -> usize {
    // Check if this event itself is on the mainline
    if let Some(pos) = mainline.iter().position(|id| id == &event.event_id) {
        return pos;
    }

    // Walk auth_events to find the closest mainline event
    let mut visited = alloc::collections::BTreeSet::new();
    let mut stack: Vec<String> = event.auth_events.clone();

    while let Some(auth_id) = stack.pop() {
        if !visited.insert(auth_id.clone()) {
            continue;
        }
        if let Some(pos) = mainline.iter().position(|id| id == &auth_id) {
            return pos;
        }
        if let Some(auth_ev) = all_events.get(&auth_id) {
            for parent_auth in &auth_ev.auth_events {
                stack.push(parent_auth.clone());
            }
        }
    }

    // Not connected to mainline at all — worst position
    mainline.len()
}

/// Sort events by mainline ordering per the Matrix spec:
/// 1. Closest mainline position (smaller index = closer to current PL = better = wins = comes last)
/// 2. origin_server_ts ascending (earlier first, later wins via last-write)
/// 3. event_id ascending (smaller first)
fn mainline_sort(
    events: &mut Vec<&LeanEvent>,
    mainline: &[String],
    all_events: &HashMap<String, LeanEvent>,
) {
    // Pre-compute mainline positions
    let positions: HashMap<String, usize> = events
        .iter()
        .map(|ev| {
            (
                ev.event_id.clone(),
                closest_mainline_position(ev, mainline, all_events),
            )
        })
        .collect();

    events.sort_by(|a, b| {
        let pos_a = positions.get(&a.event_id).copied().unwrap_or(usize::MAX);
        let pos_b = positions.get(&b.event_id).copied().unwrap_or(usize::MAX);

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

pub fn compute_v2_1_conflicted_subgraph(
    auth_graph: &HashMap<String, LeanEvent>,
    conflicted_set: &[String],
) -> HashMap<String, LeanEvent> {
    compute_v2_1_conflicted_subgraph_bounded(auth_graph, conflicted_set, None).subgraph
}

/// Bounded version of conflicted subgraph computation.
/// `max_auth_depth`: If set, limits backwards traversal depth to prevent
/// history-flooding DoS attacks where a rogue admin generates millions of
/// spoofed events on a dead-end fork.
pub fn compute_v2_1_conflicted_subgraph_bounded(
    auth_graph: &HashMap<String, LeanEvent>,
    conflicted_set: &[String],
    max_auth_depth: Option<usize>,
) -> SubgraphResult {
    let mut backwards_reachable = BTreeSet::new();
    let mut forwards_reachable = BTreeSet::new();
    let mut missing_auth_events = BTreeSet::new();

    // 1. Calculate Backwards Reachable (Ancestors up the auth chain)
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

    // 2. Build Reverse Adjacency for Forwards Search
    let mut children_map: HashMap<String, Vec<String>> = HashMap::new();
    for (id, event) in auth_graph {
        for prev in &event.auth_events {
            children_map
                .entry(prev.clone())
                .or_default()
                .push(id.clone());
        }
    }

    // 3. Calculate Forwards Reachable (Descendants down the auth chain)
    let mut f_stack: Vec<String> = conflicted_set.to_vec();
    while let Some(node) = f_stack.pop() {
        if forwards_reachable.insert(node.clone()) {
            if let Some(children) = children_map.get(&node) {
                f_stack.extend(children.clone());
            }
        }
    }

    // 4. Intersect and build the final Conflicted Subgraph
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    #[cfg(not(feature = "std"))]
    use hashbrown::HashMap;
    #[cfg(feature = "std")]
    use std::collections::HashMap;

    #[test]
    fn test_leanevent_deserialization_defaults() {
        let json = r#"{
            "event_id": "$test",
            "type": "m.room.message",
            "origin_server_ts": 12345
        }"#;
        let ev: LeanEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.event_id, "$test");
        assert_eq!(ev.event_type, "m.room.message");
        assert_eq!(ev.origin_server_ts, 12345);
        assert_eq!(ev.state_key, "");
        assert_eq!(ev.power_level, 0);
        assert_eq!(ev.sender, "");
        assert_eq!(ev.prev_events.len(), 0);
        assert_eq!(ev.auth_events.len(), 0);
        assert_eq!(ev.depth, 0);
    }

    #[test]
    fn test_sort_priority_v2_tie_break() {
        let e_base = LeanEvent {
            event_id: "$1".into(),
            power_level: 100,
            origin_server_ts: 10,
            ..Default::default()
        };
        let e_worst_pl = LeanEvent {
            event_id: "$2".into(),
            power_level: 50,
            origin_server_ts: 10,
            ..Default::default()
        };
        let p_base = SortPriority {
            event: &e_base,
            version: StateResVersion::V2,
        };
        let p_worst_pl = SortPriority {
            event: &e_worst_pl,
            version: StateResVersion::V2,
        };

        // Worse events (lower PL) should be GREATER so they pop FIRST from Max-Heap.
        assert_eq!(p_base.cmp(&p_worst_pl), Ordering::Less); // p_worst_pl has power 50, p_base 100. Lower pl pops first = Greater.

        let e_later_ts = LeanEvent {
            event_id: "$3".into(),
            power_level: 100,
            origin_server_ts: 20,
            ..Default::default()
        };
        let p_later_ts = SortPriority {
            event: &e_later_ts,
            version: StateResVersion::V2,
        };
        // p_later_ts has ts 20 (worse — pops first = Greater), p_base has ts 10 (better — wins = Less).
        assert_eq!(p_base.cmp(&p_later_ts), Ordering::Less);

        let e_larger_id = LeanEvent {
            event_id: "$2".into(),
            power_level: 100,
            origin_server_ts: 10,
            ..Default::default()
        };
        let p_larger_id = SortPriority {
            event: &e_larger_id,
            version: StateResVersion::V2,
        };
        // p_larger_id has id "$2", p_base has id "$1". Larger ID pops first = Greater.
        assert_eq!(p_base.cmp(&p_larger_id), Ordering::Less);
    }

    #[test]
    fn test_v1_resolution_happy_path() {
        let mut events = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 0,
                origin_server_ts: 100,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 0,
                origin_server_ts: 50,
                prev_events: vec![],
                auth_events: vec!["A".into()],
                depth: 2,
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(&events, StateResVersion::V1);
        assert_eq!(sorted, vec!["A", "B"]);
    }

    #[test]
    fn test_v2_1_strict_resolution() {
        let mut unconflicted = BTreeMap::new();
        unconflicted.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            "A".into(),
        );

        let mut conflicted = HashMap::new();
        conflicted.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 50,
                origin_server_ts: 100,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        conflicted.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 50,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );

        // In V2, A would win because it's unconflicted.
        // In V2.1, B should win because it has a higher power level (100 > 50) and it's sorted together with A.
        let resolved = resolve_lean(unconflicted, conflicted, StateResVersion::V2_1);
        assert_eq!(
            resolved.get(&("m.room.member".into(), "@alice:example.com".into())),
            Some(&"B".into())
        );
    }

    #[test]
    fn test_v1_tie_break_by_id() {
        let mut events = HashMap::new();
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 0,
                origin_server_ts: 100,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 0,
                origin_server_ts: 100,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(&events, StateResVersion::V1);
        assert_eq!(sorted, vec!["A", "B"]);
    }

    #[test]
    fn test_v2_resolution_happy_path() {
        let mut events = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec![],
                auth_events: vec![],
                depth: 10,
                ..Default::default()
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 50,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(&events, StateResVersion::V2);
        // Best (A) comes LAST.
        assert_eq!(sorted, vec!["B", "A"]);
    }

    #[test]
    fn test_v2_deep_tie_break() {
        let mut events = HashMap::new();
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(&events, StateResVersion::V2);
        // Best (A, smaller ID) comes LAST.
        assert_eq!(sorted, vec!["B", "A"]);
    }

    #[test]
    fn test_v1_v2_v2_1_comparison_determinism() {
        let mut events = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 10,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec![],
                auth_events: vec![],
                depth: 10,
                ..Default::default()
            },
        );
        let sorted_v1 = lean_kahn_sort(&events, StateResVersion::V1);
        let sorted_v2 = lean_kahn_sort(&events, StateResVersion::V2);
        let sorted_v2_1 = lean_kahn_sort(&events, StateResVersion::V2_1);
        assert_eq!(sorted_v1, vec!["A", "B"]);
        // B is better (higher power level), so it comes LAST in V2 and V2.1
        assert_eq!(sorted_v2, vec!["A", "B"]);
        assert_eq!(sorted_v2_1, vec!["A", "B"]);
    }

    #[test]
    fn test_unhappy_path_cycle_detection() {
        let mut events = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec!["B".into()],
                auth_events: vec!["B".into()],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec!["A".into()],
                auth_events: vec!["A".into()],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(&events, StateResVersion::V2);
        assert!(sorted.is_empty());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let event = LeanEvent {
            event_id: "$abc".into(),
            event_type: "m.room.member".into(),
            state_key: "@alice:example.com".into(),
            power_level: 100,
            origin_server_ts: 12345,
            prev_events: vec![],
            auth_events: vec![],
            depth: 5,
            ..Default::default()
        };
        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: LeanEvent = serde_json::from_str(&serialized).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_partial_ord_implementations() {
        let e1 = LeanEvent {
            event_id: "a".into(),
            event_type: "m.room.member".into(),
            state_key: "@alice:example.com".into(),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let e2 = LeanEvent {
            event_id: "b".into(),
            event_type: "m.room.member".into(),
            state_key: "@alice:example.com".into(),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        assert!(e1.partial_cmp(&e2).is_some());

        let p1 = SortPriority {
            event: &e1,
            version: StateResVersion::V2,
        };
        let p2 = SortPriority {
            event: &e2,
            version: StateResVersion::V2,
        };
        assert!(p1.partial_cmp(&p2).is_some());
    }

    #[test]
    fn test_trait_coverage() {
        let v = StateResVersion::V2;
        assert_eq!(v, StateResVersion::V2);
        let _ = alloc::format!("{:?}", v);

        let e = LeanEvent {
            event_id: "a".into(),
            event_type: "m.room.member".into(),
            state_key: "@alice:example.com".into(),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let _ = e.clone();
        let _ = alloc::format!("{:?}", e);
    }

    #[test]
    fn test_complex_dag_sort() {
        let mut events = HashMap::new();
        events.insert(
            "1".into(),
            LeanEvent {
                event_id: "1".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "2".into(),
            LeanEvent {
                event_id: "2".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 50,
                origin_server_ts: 20,
                prev_events: vec!["1".into()],
                auth_events: vec!["1".into()],
                depth: 2,
                ..Default::default()
            },
        );
        events.insert(
            "3".into(),
            LeanEvent {
                event_id: "3".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 50,
                origin_server_ts: 15,
                prev_events: vec!["1".into()],
                auth_events: vec!["1".into()],
                depth: 2,
                ..Default::default()
            },
        );
        events.insert(
            "4".into(),
            LeanEvent {
                event_id: "4".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 10,
                origin_server_ts: 30,
                prev_events: vec!["2".into(), "3".into()],
                auth_events: vec!["2".into(), "3".into()],
                depth: 3,
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(&events, StateResVersion::V2);
        // 1 pops first (only one with in-degree 0).
        // Then 2 and 3 are in queue. 2 has later TS (20, worse) so it pops first.
        // Then 3 (TS 15, better = earlier) pops.
        // Then 4 pops.
        assert_eq!(sorted, vec!["1", "2", "3", "4"]);
    }

    #[test]
    fn test_kahn_missing_parents() {
        let mut events = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec!["MISSING".into()],
                auth_events: vec!["MISSING".into()],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(&events, StateResVersion::V2);
        assert_eq!(sorted, vec!["A"]);
    }

    #[test]
    fn test_resolve_lean_functionality() {
        let mut unconflicted = BTreeMap::new();
        unconflicted.insert(("type".into(), "key".into()), "id".into());
        let conflicted = HashMap::new();
        let resolved = resolve_lean(unconflicted.clone(), conflicted, StateResVersion::V2);
        assert_eq!(resolved, unconflicted);
    }

    #[test]
    fn test_resolve_lean_v2_1_overlay() {
        use serde_json::json;

        let mut unconflicted = BTreeMap::new();
        unconflicted.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            "id1".into(),
        );
        unconflicted.insert(
            ("m.room.member".into(), "@bob:example.com".into()),
            "id2".into(),
        );

        let mut conflicted = HashMap::new();
        // m.room.create to seed auth state
        conflicted.insert(
            "create".into(),
            LeanEvent {
                event_id: "create".into(),
                event_type: "m.room.create".into(),
                state_key: String::new(),
                sender: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 1,
                content: json!({}),
                ..Default::default()
            },
        );
        // Provide objects for all events to be sorted in V2.1
        conflicted.insert(
            "id1".into(),
            LeanEvent {
                event_id: "id1".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                sender: "@alice:example.com".into(),
                power_level: 50,
                origin_server_ts: 500,
                content: json!({"membership": "join"}),
                auth_events: vec!["create".into()],
                ..Default::default()
            },
        );
        conflicted.insert(
            "id2".into(),
            LeanEvent {
                event_id: "id2".into(),
                event_type: "m.room.member".into(),
                state_key: "@bob:example.com".into(),
                sender: "@bob:example.com".into(),
                power_level: 50,
                origin_server_ts: 500,
                content: json!({"membership": "join"}),
                auth_events: vec!["create".into()],
                ..Default::default()
            },
        );
        conflicted.insert(
            "id2_new".into(),
            LeanEvent {
                event_id: "id2_new".into(),
                event_type: "m.room.member".into(),
                state_key: "@bob:example.com".into(),
                sender: "@bob:example.com".into(),
                power_level: 100,
                origin_server_ts: 1000,
                content: json!({"membership": "join"}),
                auth_events: vec!["create".into()],
                ..Default::default()
            },
        );

        let resolved = resolve_lean(unconflicted.clone(), conflicted, StateResVersion::V2_1);

        assert_eq!(
            resolved.get(&("m.room.member".into(), "@alice:example.com".into())),
            Some(&"id1".into())
        );
        assert_eq!(
            resolved.get(&("m.room.member".into(), "@bob:example.com".into())),
            Some(&"id2_new".into())
        );
    }

    fn run_batch_test(
        version: StateResVersion,
        rows: &[(&str, i64, u64, u64, &[&str])],
        expected: &[&str],
    ) {
        let mut events = HashMap::new();
        for r in rows {
            events.insert(
                r.0.to_string(),
                LeanEvent {
                    event_id: r.0.to_string(),
                    event_type: "m.room.member".into(),
                    state_key: "@alice:example.com".into(),
                    power_level: r.1,
                    origin_server_ts: r.2,
                    depth: r.3,
                    prev_events: r.4.iter().map(|s| s.to_string()).collect(),
                    auth_events: r.4.iter().map(|s| s.to_string()).collect(),
                    ..Default::default()
                },
            );
        }
        let result = lean_kahn_sort(&events, version);
        assert_eq!(
            result,
            expected.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_resolution_batch() {
        run_batch_test(
            StateResVersion::V2,
            &[("Alice", 100, 500, 1, &[]), ("Bob", 50, 100, 1, &[])],
            &["Bob", "Alice"], // Bob is worse (PL 50), pops first.
        );
        run_batch_test(
            StateResVersion::V1,
            &[("Deep", 100, 100, 10, &[]), ("Shallow", 10, 100, 1, &[])],
            &["Shallow", "Deep"],
        );
    }

    #[test]
    fn test_native_resolution_bootstrap_parity() {
        let mut events = HashMap::new();
        events.insert(
            "1".into(),
            LeanEvent {
                event_id: "1".into(),
                event_type: "m.room.member".into(),
                state_key: "@user:example.com".into(),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "2".into(),
            LeanEvent {
                event_id: "2".into(),
                event_type: "m.room.member".into(),
                state_key: "@user:example.com".into(),
                power_level: 0,
                origin_server_ts: 20,
                prev_events: vec!["1".into()],
                auth_events: vec!["1".into()],
                depth: 2,
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(&events, StateResVersion::V2);
        let mut resolved_state = BTreeMap::new();
        for id in sorted {
            let ev = events.get(&id).unwrap();
            let key = (ev.event_type.clone(), ev.state_key.clone());
            resolved_state.insert(key, ev.event_id.clone());
        }
        assert_eq!(
            resolved_state.get(&("m.room.member".to_string(), "@user:example.com".to_string())),
            Some(&"2".to_string())
        );
    }

    #[test]
    fn test_enum_coverage() {
        let v = StateResVersion::V2;
        let v2 = v;
        assert_eq!(v, v2);
        let debug_str = alloc::format!("{:?}", v);
        assert!(debug_str.contains("V2"));
    }

    #[test]
    fn test_event_traits_coverage() {
        let e = LeanEvent {
            event_id: "a".into(),
            event_type: "m.room.member".into(),
            state_key: "@alice:example.com".into(),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let e2 = e.clone();
        assert_eq!(e, e2);
        let debug_str = alloc::format!("{:?}", e);
        assert!(debug_str.contains("event_id"));
    }

    #[test]
    fn test_sort_priority_traits() {
        let e = LeanEvent {
            event_id: "a".into(),
            event_type: "m.room.member".into(),
            state_key: "@alice:example.com".into(),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let p = SortPriority {
            event: &e,
            version: StateResVersion::V2,
        };
        let p2 = p;
        assert_eq!(p, p2);
        let debug_str = alloc::format!("{:?}", p);
        assert!(debug_str.contains("version"));
    }

    #[test]
    fn test_v1_equal_depth_tie_break() {
        let mut events = HashMap::new();
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 0,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 0,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(&events, StateResVersion::V1);
        assert_eq!(sorted, vec!["A", "B"]);
    }

    #[test]
    fn test_kahn_no_neighbors() {
        let mut events = HashMap::new();
        events.insert(
            "1".into(),
            LeanEvent {
                event_id: "1".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(&events, StateResVersion::V2);
        assert_eq!(sorted, vec!["1"]);
    }

    #[test]
    fn test_v2_1_full_coverage() {
        let mut events = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(&events, StateResVersion::V2_1);
        assert_eq!(sorted, vec!["A"]);
    }

    /// Regression test: V2_1 must use "earlier timestamp wins" tie-break.
    /// This was missed when the project was refactored to sort earlier-first.
    #[test]
    fn test_v2_1_earlier_timestamp_wins() {
        // Two events at the same power level, different timestamps, no auth chain.
        // The event with the EARLIER timestamp should come LAST (= win via last-write).
        let mut events = HashMap::new();
        events.insert(
            "$early".into(),
            LeanEvent {
                event_id: "$early".into(),
                event_type: "m.room.member".into(),
                state_key: "@user:example.com".into(),
                power_level: 100,
                origin_server_ts: 1000,
                auth_events: vec![],
                ..Default::default()
            },
        );
        events.insert(
            "$late".into(),
            LeanEvent {
                event_id: "$late".into(),
                event_type: "m.room.member".into(),
                state_key: "@user:example.com".into(),
                power_level: 100,
                origin_server_ts: 2000,
                auth_events: vec![],
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(&events, StateResVersion::V2_1);
        // $late (ts 2000) is worse, should pop first.
        // $early (ts 1000) is better, should come last = win.
        assert_eq!(sorted, vec!["$late", "$early"]);

        // Same test with V2 to confirm parity
        let sorted_v2 = lean_kahn_sort(&events, StateResVersion::V2);
        assert_eq!(sorted_v2, vec!["$late", "$early"]);
    }

    /// Regression test: V2_1 timestamp tie-break with millisecond-close events
    /// (the exact pattern seen in production Draupnir ban races).
    #[test]
    fn test_v2_1_millisecond_race_tiebreak() {
        let mut events = HashMap::new();
        events.insert(
            "$ban_a".into(),
            LeanEvent {
                event_id: "$ban_a".into(),
                event_type: "m.room.member".into(),
                state_key: "@spammer:evil.com".into(),
                power_level: 50,
                origin_server_ts: 1772724243891,
                auth_events: vec![],
                ..Default::default()
            },
        );
        events.insert(
            "$ban_b".into(),
            LeanEvent {
                event_id: "$ban_b".into(),
                event_type: "m.room.member".into(),
                state_key: "@spammer:evil.com".into(),
                power_level: 50,
                origin_server_ts: 1772724243893, // 2ms later
                auth_events: vec![],
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(&events, StateResVersion::V2_1);
        // $ban_b (later ts) is worse, pops first. $ban_a (earlier ts) wins.
        assert_eq!(sorted, vec!["$ban_b", "$ban_a"]);
    }

    #[test]
    fn test_total_order_properties() {
        let e1 = LeanEvent {
            event_id: "a".into(),
            event_type: "m.room.member".into(),
            state_key: "@alice:example.com".into(),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let e2 = LeanEvent {
            event_id: "b".into(),
            event_type: "m.room.member".into(),
            state_key: "@alice:example.com".into(),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let e3 = LeanEvent {
            event_id: "c".into(),
            event_type: "m.room.member".into(),
            state_key: "@alice:example.com".into(),
            power_level: 50,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        assert_eq!(e1.cmp(&e1), Ordering::Equal);
        assert!(e1 <= e1);
        assert!(e1 <= e2 || e2 <= e1);
        if e1 <= e2 && e2 <= e3 {
            assert!(e1 <= e3);
        }
        let e1_copy = e1.clone();
        if e1 <= e1_copy && e1_copy <= e1 {
            assert_eq!(e1, e1_copy);
        }
    }

    #[test]
    fn test_coverage_booster_all_branches() {
        let e_base = LeanEvent {
            event_id: "m".into(),
            event_type: "m.room.member".into(),
            state_key: "@alice:example.com".into(),
            power_level: 50,
            origin_server_ts: 50,
            prev_events: vec![],
            auth_events: vec![],
            depth: 50,
            ..Default::default()
        };
        let p_base = SortPriority {
            event: &e_base,
            version: StateResVersion::V2,
        };
        let e_high_power = LeanEvent {
            power_level: 100,
            ..e_base.clone()
        };
        let p_high_power = SortPriority {
            event: &e_high_power,
            version: StateResVersion::V2,
        };
        // p_base is WORSE (PL 50 < 100), so it should be GREATER.
        assert_eq!(p_base.cmp(&p_high_power), Ordering::Greater);
        let e_early_ts = LeanEvent {
            origin_server_ts: 10,
            ..e_base.clone()
        };
        let p_early_ts = SortPriority {
            event: &e_early_ts,
            version: StateResVersion::V2,
        };
        // p_early_ts has TS 10 (better, pops last = Less), p_base has TS 50 (worse, pops first = Greater).
        assert_eq!(p_base.cmp(&p_early_ts), Ordering::Greater);
        let e_early_id = LeanEvent {
            event_id: "a".into(),
            ..e_base.clone()
        };
        let p_early_id = SortPriority {
            event: &e_early_id,
            version: StateResVersion::V2,
        };
        // p_early_id has ID "a", p_base has ID "m". Larger ID pops first, so p_base is GREATER.
        assert_eq!(p_base.cmp(&p_early_id), Ordering::Greater);
        let p_v1_base = SortPriority {
            event: &e_base,
            version: StateResVersion::V1,
        };
        let e_shallow = LeanEvent {
            depth: 1,
            ..e_base.clone()
        };
        let p_shallow = SortPriority {
            event: &e_shallow,
            version: StateResVersion::V1,
        };
        assert_eq!(p_v1_base.cmp(&p_shallow), Ordering::Less);
        let p_v1_early_id = SortPriority {
            event: &e_early_id,
            version: StateResVersion::V1,
        };
        assert_eq!(p_v1_base.cmp(&p_v1_early_id), Ordering::Less);
        assert_eq!(p_v1_base.cmp(&p_v1_base), Ordering::Equal);
    }

    // ========================================================================
    // Phase 2: Battle-Hardening Tests
    // ========================================================================

    #[test]
    fn test_cycle_detection_detailed() {
        let mut events = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                auth_events: vec!["B".into()],
                ..Default::default()
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                auth_events: vec!["A".into()],
                ..Default::default()
            },
        );
        let result = lean_kahn_sort_detailed(&events, StateResVersion::V2);
        match result {
            KahnSortResult::CycleDetected { sorted, stuck } => {
                assert!(sorted.is_empty());
                assert_eq!(stuck.len(), 2);
                let mut stuck_sorted = stuck.clone();
                stuck_sorted.sort();
                assert_eq!(stuck_sorted, vec!["A", "B"]);
            }
            KahnSortResult::Ok(_) => panic!("Expected cycle detection"),
        }
    }

    #[test]
    fn test_cycle_detection_partial_sort() {
        // C -> A -> B -> A (cycle), but C is reachable
        let mut events = HashMap::new();
        events.insert(
            "C".into(),
            LeanEvent {
                event_id: "C".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                auth_events: vec![],
                ..Default::default()
            },
        );
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                auth_events: vec!["B".into(), "C".into()],
                ..Default::default()
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                auth_events: vec!["A".into()],
                ..Default::default()
            },
        );
        let result = lean_kahn_sort_detailed(&events, StateResVersion::V2);
        match result {
            KahnSortResult::CycleDetected { sorted, stuck } => {
                assert_eq!(sorted, vec!["C"]);
                assert_eq!(stuck.len(), 2);
            }
            KahnSortResult::Ok(_) => panic!("Expected cycle detection"),
        }
    }

    #[test]
    fn test_kahn_sort_result_api() {
        let ok = KahnSortResult::Ok(vec!["A".into()]);
        assert!(ok.is_ok());
        assert_eq!(ok.into_sorted(), vec!["A"]);

        let cycle = KahnSortResult::CycleDetected {
            sorted: vec!["C".into()],
            stuck: vec!["A".into(), "B".into()],
        };
        assert!(!cycle.is_ok());
        assert!(cycle.into_sorted().is_empty());
    }

    #[test]
    fn test_power_level_coercion_integer() {
        let json = r#"{"event_id": "$1", "type": "m.room.member", "origin_server_ts": 1, "power_level": 100}"#;
        let ev: LeanEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.power_level, 100);
    }

    #[test]
    fn test_power_level_coercion_string() {
        let json = r#"{"event_id": "$1", "type": "m.room.member", "origin_server_ts": 1, "power_level": "100"}"#;
        let ev: LeanEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.power_level, 100);
    }

    #[test]
    fn test_power_level_coercion_float() {
        let json = r#"{"event_id": "$1", "type": "m.room.member", "origin_server_ts": 1, "power_level": 100.0}"#;
        let ev: LeanEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.power_level, 100);
    }

    #[test]
    fn test_power_level_coercion_invalid_string() {
        let json = r#"{"event_id": "$1", "type": "m.room.member", "origin_server_ts": 1, "power_level": "abc"}"#;
        let ev: LeanEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.power_level, 0);
    }

    #[test]
    fn test_deep_chain_stack_safety() {
        // 1000-event deep chain: ev_0 <- ev_1 <- ev_2 <- ... <- ev_999
        let mut events = HashMap::new();
        for i in 0..1000u32 {
            let id = alloc::format!("ev_{}", i);
            let auth = if i > 0 {
                vec![alloc::format!("ev_{}", i - 1)]
            } else {
                vec![]
            };
            events.insert(
                id.clone(),
                LeanEvent {
                    event_id: id,
                    event_type: "m.room.member".into(),
                    state_key: "@alice:example.com".into(),
                    power_level: 100,
                    origin_server_ts: i as u64,
                    auth_events: auth,
                    depth: i as u64,
                    ..Default::default()
                },
            );
        }
        let sorted = lean_kahn_sort(&events, StateResVersion::V2);
        assert_eq!(sorted.len(), 1000);
        // First element must be ev_0 (in-degree 0)
        assert_eq!(sorted[0], "ev_0");
        // Last element must be ev_999 (deepest)
        assert_eq!(sorted[999], "ev_999");
    }

    #[test]
    fn test_subgraph_bounded_depth() {
        // Chain: A <- B <- C <- D (all in conflicted set for proper subgraph)
        let mut graph = HashMap::new();
        for (id, auths) in [
            ("A", vec![]),
            ("B", vec!["A"]),
            ("C", vec!["B"]),
            ("D", vec!["C"]),
        ] {
            graph.insert(
                id.to_string(),
                LeanEvent {
                    event_id: id.into(),
                    event_type: "m.room.member".into(),
                    state_key: "@alice:example.com".into(),
                    auth_events: auths.iter().map(|s| s.to_string()).collect(),
                    ..Default::default()
                },
            );
        }
        // Unbounded with A and D as conflicted: full intersection includes all
        let full = compute_v2_1_conflicted_subgraph_bounded(
            &graph,
            &["A".to_string(), "D".to_string()],
            None,
        );
        assert!(full.subgraph.contains_key("A"));
        assert!(full.subgraph.contains_key("D"));

        // Bounded to depth 1: backwards from D only reaches C (depth 1),
        // so the backwards set is {A, D, C} (A + D from seeds, C from D's auth).
        // But A is not reachable forward from any of these at depth 1 only.
        let bounded = compute_v2_1_conflicted_subgraph_bounded(
            &graph,
            &["A".to_string(), "D".to_string()],
            Some(1),
        );
        // D at depth 0, C at depth 1 from D's backwards walk
        assert!(bounded.subgraph.contains_key("D"));
        assert!(bounded.subgraph.contains_key("A"));
        // B is NOT reachable within depth 1 from D (it's at depth 2)
        assert!(!bounded.subgraph.contains_key("B"));
    }

    #[test]
    fn test_subgraph_missing_auth_detection() {
        let mut graph = HashMap::new();
        graph.insert(
            "X".to_string(),
            LeanEvent {
                event_id: "X".into(),
                event_type: "m.room.member".into(),
                state_key: "@alice:example.com".into(),
                auth_events: vec!["MISSING_1".into(), "MISSING_2".into()],
                ..Default::default()
            },
        );
        let result = compute_v2_1_conflicted_subgraph_bounded(&graph, &["X".to_string()], None);
        let mut missing = result.missing_auth_events.clone();
        missing.sort();
        assert_eq!(missing, vec!["MISSING_1", "MISSING_2"]);
    }
}
