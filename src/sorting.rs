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

use alloc::collections::{BTreeMap, BinaryHeap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::types::{KahnSortResult, LeanEvent, SortPriority, StateResVersion, MAX_POWER_LEVEL};
use crate::HashMap;

/// Dynamically fetches the sender's power level by inspecting the event's immediate `auth_events`.
/// Recursive traversal of the auth chain is avoided to prevent bypassing immediate restrictions.
pub(crate) fn get_power_level_from_auth_chain<S: core::hash::BuildHasher>(
    event: &LeanEvent,
    auth_context: &HashMap<String, LeanEvent, S>,
    create_ev: Option<&LeanEvent>,
    version: StateResVersion,
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
        match version {
            StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2 => {
                return MAX_POWER_LEVEL
            }
            _ => return 100,
        }
    }

    if let Some(pl_ev) = pl_event {
        if let Some(users) = pl_ev.content.get("users").and_then(|u| u.as_object()) {
            if let Some(pl_val) = users.get(&event.sender) {
                if let Some(pl) = crate::types::coerce_json_to_i64(pl_val) {
                    return pl;
                }
            }
        }

        if let Some(default_pl_val) = pl_ev.content.get("users_default") {
            if let Some(default_pl) = crate::types::coerce_json_to_i64(default_pl_val) {
                return default_pl;
            }
        }
        return 0; // Default if PL event exists but no users_default
    }

    if event.auth_events.is_empty() {
        return event.power_level; // Fallback for simple unit-test/mock events that don't have an auth chain
    }
    0
}

/// Computes the shortest distance from the event to the m.room.create event via `auth_events`.
pub(crate) fn memoized_auth_distance<'a, S: core::hash::BuildHasher>(
    curr_id: &'a str,
    auth_context: &'a HashMap<String, LeanEvent, S>,
    create_id: &str,
    memo: &mut HashMap<&'a str, u64>,
    in_progress: &mut alloc::collections::BTreeSet<&'a str>,
) -> u64 {
    if curr_id == create_id {
        return 0;
    }

    if let Some(&dist) = memo.get(curr_id) {
        return dist;
    }

    if !in_progress.insert(curr_id) {
        return u64::MAX;
    }

    let Some(ev) = auth_context.get(curr_id) else {
        in_progress.remove(curr_id);
        return u64::MAX;
    };

    if ev.auth_events.is_empty() {
        in_progress.remove(curr_id);
        return u64::MAX;
    }

    let mut min_dist = u64::MAX;
    for parent in &ev.auth_events {
        let p_dist = memoized_auth_distance(parent, auth_context, create_id, memo, in_progress);
        min_dist = min_dist.min(p_dist.saturating_add(1));
    }

    in_progress.remove(curr_id);
    memo.insert(curr_id, min_dist);
    min_dist
}

/// Detailed Kahn's Topological Sort algorithm for event power resolution.
///
/// This function performs a reverse topological sort on a set of events, placing
/// descendants before their ancestors. It returns diagnostic details about any cycles
/// if they are detected.
///
/// # Panics
///
/// Will panic if graph invariants are violated during topological sorting (specifically, if
/// the in-degree map lacks an entry for a child event during the queue processing phase).
pub fn lean_kahn_sort_detailed<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
    events: &HashMap<String, LeanEvent, S1>,
    auth_context: &HashMap<String, LeanEvent, S2>,
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
                let val = in_degree.entry(id.clone()).or_insert(0);
                *val = val.saturating_add(1);
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
                get_power_level_from_auth_chain(ev, auth_context, create_ev, version),
            )
        })
        .collect();

    let depth_cache: HashMap<String, u64> = if version == StateResVersion::V2_2 {
        let mut memo = HashMap::new();
        let create_id = create_ev.map_or("", |e| e.event_id.as_str());
        events
            .keys()
            .map(|id| {
                let mut in_progress = alloc::collections::BTreeSet::new();
                (
                    id.clone(),
                    memoized_auth_distance(
                        id,
                        auth_context,
                        create_id,
                        &mut memo,
                        &mut in_progress,
                    ),
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
                *degree = degree.saturating_sub(1);
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
/// Backward-compatible wrapper that falls back to standard tie-breaking on cycles.
///
/// # Panics
///
/// Will panic if graph invariants are violated (specifically, if an event returned
/// in the cycle-breaking list of stuck nodes is missing from the input `events` map).
// jscpd:ignore-start
#[must_use]
pub fn lean_kahn_sort<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
    events: &HashMap<String, LeanEvent, S1>,
    auth_context: &HashMap<String, LeanEvent, S2>,
    create_ev: Option<&LeanEvent>,
    version: StateResVersion,
) -> Vec<String> {
    // jscpd:ignore-end
    match lean_kahn_sort_detailed(events, auth_context, create_ev, version) {
        KahnSortResult::Ok(sorted) => sorted,
        KahnSortResult::CycleDetected {
            mut sorted,
            mut stuck,
        } => {
            #[cfg(feature = "std")]
            std::eprintln!("KAHN CYCLE DETECTED! Stuck: {stuck:?}");
            stuck.sort_by(|a, b| {
                let ev_a = events.get(a).unwrap();
                let ev_b = events.get(b).unwrap();
                // Standard tie-breaking fallback (origin_server_ts ascending, then event_id ascending)
                ev_a.origin_server_ts
                    .cmp(&ev_b.origin_server_ts)
                    .then_with(|| a.cmp(b))
            });
            sorted.append(&mut stuck);
            sorted
        }
    }
}

pub(crate) fn build_mainline(
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
            let mut queue = VecDeque::new();
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
pub(crate) fn precompute_mainline_positions<S: ::core::hash::BuildHasher>(
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
    let mut queue: VecDeque<(&str, usize)> = VecDeque::new();

    for (pos, id) in mainline.iter().enumerate() {
        dist.insert(id.clone(), pos);
        queue.push_back((id.as_str(), pos));
    }

    // Flood-fill outward through reverse auth-edges.
    // Since positions can be updated if a smaller/closer mainline index is found,
    // we allow re-queuing children when a better position propagates.
    while let Some((id, pos)) = queue.pop_front() {
        if let Some(&current_best) = dist.get(id) {
            if pos > current_best {
                continue;
            }
        }
        if let Some(children) = reverse_adj.get(id) {
            for &child_id in children {
                let current_child_best = dist.get(child_id).copied();
                if current_child_best.is_none() || pos < current_child_best.unwrap() {
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
