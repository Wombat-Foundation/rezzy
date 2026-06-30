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

//! Topological and mainline sorting for Matrix state resolution.
use alloc::collections::{BinaryHeap, VecDeque};
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::basespec::rezzy_types::{
    KahnSortResult, LeanEvent, SortPriority, StateResVersion, MAX_POWER_LEVEL,
};
use crate::HashMap;

/// Dynamically fetches the sender's power level by inspecting the event's immediate `auth_events`.
/// Recursive traversal of the auth chain is avoided to prevent bypassing immediate restrictions.
pub(crate) fn get_power_level_from_auth_chain<Id, C>(
    event: &LeanEvent<Id, C>,
    auth_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C>,
    create_ev: Option<&LeanEvent<Id, C>>,
    version: StateResVersion,
) -> i64
where
    Id: Clone + Eq + core::hash::Hash,
    C: crate::basespec::rezzy_types::EventContent,
{
    let mut pl_event = None;

    // Spec compliance: only check immediate auth_events.
    for aid in &event.auth_events {
        if let Some(aev) = auth_context.get_event(aid) {
            if aev.event_type == "m.room.power_levels"
                && aev.state_key.as_deref() == Some("")
                && pl_event.is_none()
            {
                pl_event = Some(aev.clone());
            }
        }
    }

    let is_creator = create_ev.is_some_and(|ev| {
        ev.sender == event.sender
            || matches!(
                version,
                StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2
            ) && ev.content.has_additional_creator(&event.sender)
    });

    if is_creator {
        match version {
            StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2 => {
                return MAX_POWER_LEVEL
            }
            _ => return 100,
        }
    }

    if let Some(pl_ev) = pl_event {
        if let Some(pl) = pl_ev.get_user_power_level(&event.sender) {
            return pl;
        }

        if let Some(default_pl) = pl_ev.get_users_default() {
            return default_pl;
        }
        return 0; // Default if PL event exists but no users_default
    }

    if event.auth_events.is_empty() {
        return event.power_level; // Fallback for simple unit-test/mock events that don't have an auth chain
    }
    0
}

/// Computes the shortest distance from the event to the m.room.create event via `auth_events`.
/// Safely avoids stack overflow on deep DAGs using an iterative post-order traversal with memoization.
pub(crate) fn compute_auth_distance_iterative<'a, Id, C>(
    curr_id: &'a Id,
    auth_context: &'a impl crate::basespec::rezzy_types::EventProvider<Id, C>,
    create_id: Option<&'a Id>,
    memo: &mut HashMap<&'a Id, u64>,
) -> u64
where
    Id: Clone + Eq + core::hash::Hash + Ord + 'a,
    C: 'a,
{
    if Some(curr_id) == create_id {
        return 0;
    }
    if let Some(&dist) = memo.get(curr_id) {
        if dist != u64::MAX - 1 {
            return dist;
        }
    }

    let mut stack = Vec::new();
    stack.push(curr_id);

    while let Some(&top) = stack.last() {
        if Some(top) == create_id {
            memo.insert(top, 0);
            stack.pop();
            continue;
        }
        if let Some(&dist) = memo.get(top) {
            if dist != u64::MAX - 1 {
                stack.pop();
                continue;
            }
        } else {
            memo.insert(top, u64::MAX - 1);
        }

        let mut all_children_done = true;
        let mut min_dist = u64::MAX;

        if let Some(ev) = auth_context.get_event(top) {
            if !ev.auth_events.is_empty() {
                for aid in &ev.auth_events {
                    if Some(aid) == create_id {
                        min_dist = min_dist.min(1);
                    } else if let Some(&c_dist) = memo.get(aid) {
                        if c_dist != u64::MAX - 1 {
                            min_dist = min_dist.min(c_dist.saturating_add(1));
                        }
                    } else {
                        all_children_done = false;
                        stack.push(aid);
                    }
                }
            }
        }

        if all_children_done {
            memo.insert(top, min_dist);
            stack.pop();
        }
    }

    memo.get(curr_id).copied().unwrap_or(u64::MAX)
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
pub fn lean_kahn_sort_with_cycle_diagnostics<Id, C, S1>(
    events: &HashMap<Id, LeanEvent<Id, C>, S1>,
    sort_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C>,
    create_ev: Option<&LeanEvent<Id, C>>,
    version: StateResVersion,
) -> KahnSortResult<Id>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    S1: core::hash::BuildHasher,
    C: Clone + crate::basespec::rezzy_types::EventContent,
{
    let mut in_degree: HashMap<Id, usize> = HashMap::new();
    let mut adjacency: HashMap<Id, Vec<Id>> = HashMap::new();

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
    let pl_cache: HashMap<Id, i64> = events
        .iter()
        .map(|(id, ev)| {
            (
                id.clone(),
                get_power_level_from_auth_chain(ev, sort_context, create_ev, version),
            )
        })
        .collect();

    let depth_cache: HashMap<Id, u64> = if version == StateResVersion::V2_2 {
        let mut memo = HashMap::new();
        let create_id = create_ev.map(|e| &e.event_id);
        events
            .keys()
            .map(|id| {
                (
                    id.clone(),
                    compute_auth_distance_iterative(id, sort_context, create_id, &mut memo),
                )
            })
            .collect()
    } else {
        HashMap::new()
    };

    let mut queue: BinaryHeap<SortPriority<'_, Id, C>> = BinaryHeap::new();
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
        let sorted_set: alloc::collections::BTreeSet<&Id> = result.iter().collect();
        let stuck: Vec<Id> = events
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
pub fn lean_kahn_sort<Id, C, S1>(
    events: &HashMap<Id, LeanEvent<Id, C>, S1>,
    sort_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C>,
    create_ev: Option<&LeanEvent<Id, C>>,
    version: StateResVersion,
) -> Vec<Id>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    S1: core::hash::BuildHasher,
    C: Clone + crate::basespec::rezzy_types::EventContent,
{
    // jscpd:ignore-end
    match lean_kahn_sort_with_cycle_diagnostics(events, sort_context, create_ev, version) {
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

pub(crate) fn build_mainline<Id, C>(
    resolved: &crate::state::at::SharedState<Id>,
    auth_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C>,
) -> Vec<Id>
where
    Id: Clone + Eq + core::hash::Hash,
    C: Clone + crate::basespec::rezzy_types::EventContent,
{
    let mut mainline = Vec::new();
    let mut seen_in_mainline = hashbrown::HashSet::new();
    let pl_key = (
        alloc::string::String::from("m.room.power_levels"),
        Some(alloc::string::String::new()),
    );
    let mut current = resolved.get(&pl_key).cloned();

    while let Some(eid) = current {
        if !seen_in_mainline.insert(eid.clone()) {
            #[cfg(feature = "std")]
            std::eprintln!("REZZY_WARN: MAINLINE CYCLE DETECTED!");
            break; // Cycle detected in the power-levels mainline!
        }
        mainline.push(eid.clone());
        current = None;
        if let Some(ev) = auth_context.get_event(&eid) {
            let mut queue = VecDeque::new();
            for auth_id in &ev.auth_events {
                queue.push_back(auth_id.clone());
            }
            let mut visited = hashbrown::HashSet::new();
            while let Some(q_id) = queue.pop_front() {
                if !visited.insert(q_id.clone()) {
                    continue;
                }
                if let Some(auth_ev) = auth_context.get_event(&q_id) {
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

/// Precompute the closest mainline position for every target event reachable via
/// `auth_events` using a stack-safe O(V+E) iterative DFS upward search.
///
/// This entirely avoids `O(N)` cloning of the DAG, and prevents stack overflow
/// by using an explicit stack to simulate recursion while memoizing distances.
pub(crate) fn compute_closest_mainline_positions<Id, C>(
    events: &mut [&LeanEvent<Id, C>],
    mainline: &[Id],
    auth_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C>,
) -> HashMap<Id, usize>
where
    Id: Clone + Eq + core::hash::Hash + Ord,
    C: Clone + crate::basespec::rezzy_types::EventContent,
{
    let mut memo = HashMap::new();

    // Pre-populate mainline events with their exact index position
    for (pos, id) in mainline.iter().enumerate() {
        memo.insert(id.clone(), pos);
    }

    let mut stack = Vec::new();

    for ev in events.iter() {
        stack.push(&ev.event_id);

        while let Some(&top) = stack.last() {
            if let Some(&val) = memo.get(top) {
                if val != usize::MAX - 1 {
                    stack.pop();
                    continue;
                }
            } else {
                memo.insert(top.clone(), usize::MAX - 1);
            }

            let mut all_children_done = true;
            let mut min_pos = usize::MAX;

            if let Some(node) = auth_context.get_event(top) {
                for aid in &node.auth_events {
                    if let Some(&child_pos) = memo.get(aid) {
                        if child_pos != usize::MAX - 1 {
                            min_pos = min_pos.min(child_pos);
                        }
                    } else {
                        all_children_done = false;
                        stack.push(aid);
                    }
                }
            }

            if all_children_done {
                // Clamp "no path found" to mainline.len() so callers
                // don't see a raw usize::MAX leaking into comparisons.
                let resolved_pos = if min_pos == usize::MAX {
                    mainline.len()
                } else {
                    min_pos
                };
                memo.insert(top.clone(), resolved_pos);
                stack.pop();
            }
        }
    }

    memo
}

/// Sorts non-power events by mainline ordering per the Matrix spec.
///
/// The mainline is the chain of `m.room.power_levels` events reachable from
/// the currently resolved PL state. Each event's "mainline position" is the
/// closest PL event in its auth chain. The sort order is:
///
/// 1. **Mainline position** descending (farther = worse = applied first).
/// 2. **`origin_server_ts`** ascending (earlier = applied first, later wins).
/// 3. **`event_id`** ascending (lexicographic tie-break).
///
/// Events closer to the current power-levels event are applied **last**
/// and therefore win for same-key conflicts (last-write-wins).
pub fn mainline_sort<Id, C>(
    events: &mut [&LeanEvent<Id, C>],
    mainline: &[Id],
    auth_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C>,
) where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    C: Clone + crate::basespec::rezzy_types::EventContent,
{
    #[cfg(all(debug_assertions, not(test)))]
    std::eprintln!(
        "[DEBUG] mainline_sort: sorting {} non-power events against mainline of length {}",
        events.len(),
        mainline.len()
    );
    // O(V+E) iterative DFS to find the closest mainline index for all non-power events
    let dist = compute_closest_mainline_positions(events, mainline, auth_context);

    events.sort_by(|a, b| {
        // Hopefully safe to unwrap. DFS guarantees all events are in `dist`.
        let pos_a = dist[&a.event_id];
        let pos_b = dist[&b.event_id];

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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::String, vec::Vec};

    #[test]
    fn test_build_mainline_cycle_detection() {
        // A and B both claim to be m.room.power_levels, and auth against each other, forming a cycle.
        let a = LeanEvent::<String> {
            event_id: alloc::string::String::from("A"),
            event_type: alloc::string::String::from("m.room.power_levels"),
            auth_events: alloc::vec![alloc::string::String::from("B")],
            ..Default::default()
        };
        let b = LeanEvent::<String> {
            event_id: alloc::string::String::from("B"),
            event_type: alloc::string::String::from("m.room.power_levels"),
            auth_events: alloc::vec![alloc::string::String::from("A")],
            ..Default::default()
        };

        let mut auth_context = HashMap::new();
        auth_context.insert(alloc::string::String::from("A"), a);
        auth_context.insert(alloc::string::String::from("B"), b);

        // Initial state sets A as the power levels event.
        let mut resolved = imbl::OrdMap::new();
        resolved.insert(
            (
                alloc::string::String::from("m.room.power_levels"),
                Some(alloc::string::String::new()),
            ),
            alloc::string::String::from("A"),
        );

        // Before the fix, this would infinite loop!
        let mainline = build_mainline(&resolved, &auth_context);

        // A and B should both be in the mainline exactly once.
        assert_eq!(
            mainline.len(),
            2,
            "Mainline should break the cycle safely after picking up both events"
        );
        assert_eq!(mainline[0], "A");
        assert_eq!(mainline[1], "B");
    }

    /// Events with no auth chain to a mainline event get clamped to `mainline.len()`.
    #[test]
    fn test_closest_mainline_no_path_clamps_to_len() {
        let ev = LeanEvent::<String> {
            event_id: "orphan".into(),
            event_type: "m.room.topic".into(),
            auth_events: alloc::vec![],
            ..Default::default()
        };
        let auth_ctx: HashMap<String, LeanEvent<String>> = HashMap::new();
        let mainline: Vec<String> = alloc::vec!["pl0".into()];
        let mut events = alloc::vec![&ev];
        let dist = compute_closest_mainline_positions(&mut events, &mainline, &auth_ctx);
        // No path found → clamped to mainline.len() = 1, not usize::MAX
        assert_eq!(dist["orphan"], 1);
    }

    /// An event whose auth chain leads directly to a mainline event gets that position.
    #[test]
    fn test_closest_mainline_direct_hit() {
        let pl = LeanEvent::<String> {
            event_id: "pl0".into(),
            event_type: "m.room.power_levels".into(),
            auth_events: alloc::vec![],
            ..Default::default()
        };
        let ev = LeanEvent::<String> {
            event_id: "msg".into(),
            event_type: "m.room.message".into(),
            auth_events: alloc::vec!["pl0".into()],
            ..Default::default()
        };
        let mut auth_ctx: HashMap<String, LeanEvent<String>> = HashMap::new();
        auth_ctx.insert("pl0".into(), pl);
        auth_ctx.insert("msg".into(), ev.clone());

        let mainline = alloc::vec!["pl0".into()];
        let mut events = alloc::vec![&ev];
        let dist = compute_closest_mainline_positions(&mut events, &mainline, &auth_ctx);
        assert_eq!(dist["msg"], 0);
    }

    /// Deep auth chain: event → intermediate → mainline event.
    #[test]
    fn test_closest_mainline_deep_chain() {
        let pl = LeanEvent::<String> {
            event_id: "pl0".into(),
            event_type: "m.room.power_levels".into(),
            auth_events: alloc::vec![],
            ..Default::default()
        };
        let mid = LeanEvent::<String> {
            event_id: "mid".into(),
            event_type: "m.room.member".into(),
            auth_events: alloc::vec!["pl0".into()],
            ..Default::default()
        };
        let leaf = LeanEvent::<String> {
            event_id: "leaf".into(),
            event_type: "m.room.topic".into(),
            auth_events: alloc::vec!["mid".into()],
            ..Default::default()
        };
        let mut ctx: HashMap<String, LeanEvent<String>> = HashMap::new();
        ctx.insert("pl0".into(), pl);
        ctx.insert("mid".into(), mid);
        ctx.insert("leaf".into(), leaf.clone());

        let mainline = alloc::vec!["pl0".into()];
        let mut events = alloc::vec![&leaf];
        let dist = compute_closest_mainline_positions(&mut events, &mainline, &ctx);
        assert_eq!(dist["leaf"], 0);
    }

    /// Empty mainline: all events should clamp to 0 (`mainline.len()`).
    #[test]
    fn test_closest_mainline_empty_mainline() {
        let ev = LeanEvent::<String> {
            event_id: "x".into(),
            event_type: "m.room.topic".into(),
            auth_events: alloc::vec![],
            ..Default::default()
        };
        let ctx: HashMap<String, LeanEvent<String>> = HashMap::new();
        let mainline: Vec<String> = alloc::vec![];
        let mut events = alloc::vec![&ev];
        let dist = compute_closest_mainline_positions(&mut events, &mainline, &ctx);
        assert_eq!(dist["x"], 0);
    }

    /// `SortContext` merged provider correctly finds events across both maps.
    #[test]
    fn test_sort_context_merged_lookup() {
        use crate::basespec::rezzy_types::SortContext;

        let pl = LeanEvent::<String> {
            event_id: "pl0".into(),
            event_type: "m.room.power_levels".into(),
            auth_events: alloc::vec![],
            ..Default::default()
        };
        let topic = LeanEvent::<String> {
            event_id: "topic".into(),
            event_type: "m.room.topic".into(),
            auth_events: alloc::vec!["pl0".into()],
            ..Default::default()
        };

        // pl0 in primary (auth_context), topic in secondary (conflicted)
        let mut primary: HashMap<String, LeanEvent<String>> = HashMap::new();
        primary.insert("pl0".into(), pl);
        let mut secondary: HashMap<String, LeanEvent<String>> = HashMap::new();
        secondary.insert("topic".into(), topic.clone());

        let sort_ctx = SortContext {
            primary: &primary,
            secondary: &secondary,
        };

        let mainline = alloc::vec!["pl0".into()];
        let mut events = alloc::vec![&topic];
        let dist = compute_closest_mainline_positions(&mut events, &mainline, &sort_ctx);
        // topic's auth chain → pl0 (position 0)
        assert_eq!(dist["topic"], 0);
    }
}
