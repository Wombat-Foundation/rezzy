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

use crate::basespec::event_types::{MAX_POWER_LEVEL_RUST, M_ROOM_POWER_LEVELS};
#[cfg(test)]
use crate::basespec::rezzy_types::LeanEvent;
use crate::basespec::rezzy_types::{EventLike, KahnSortResult, SortPriority, StateResVersion};
use crate::HashMap;

/// Dynamically fetches the sender's power level by inspecting the event's immediate `auth_events`.
/// Recursive traversal of the auth chain is avoided to prevent bypassing immediate restrictions.
pub(crate) fn get_power_level_from_auth_chain<Id, C, E>(
    event: &E,
    auth_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C, E>,
    create_ev: Option<&E>,
    version: StateResVersion,
) -> i64
where
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
{
    let mut pl_event = None;

    // Spec compliance: only check immediate auth_events.
    for aid in event.auth_events() {
        if let Some(aev) = auth_context.get_event(aid) {
            if aev.event_type().as_ref() == M_ROOM_POWER_LEVELS && aev.state_key() == Some("") {
                pl_event = Some(aev);
                break;
            }
        }
    }

    // V12+ (MSC4289): creators have spec-mandated infinite power level.
    if matches!(
        version,
        StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2
    ) {
        let is_creator = create_ev.is_some_and(|ev| {
            ev.sender() == event.sender() || ev.content().has_additional_creator(event.sender())
        });
        if is_creator {
            return MAX_POWER_LEVEL_RUST;
        }
    }

    if let Some(pl_ev) = pl_event {
        if let Some(pl) = pl_ev.get_user_power_level(event.sender()) {
            return pl;
        }

        if let Some(default_pl) = pl_ev.get_users_default() {
            return default_pl;
        }
        return 0; // Default if PL event exists but no users_default
    }

    // No PL event in the auth chain — fall back to the pre-computed
    // power_level field. This handles the bootstrap PL event (which only
    // auths against $create) and simple unit-test events.
    event.power_level()
}

/// Computes the shortest distance from the event to the m.room.create event via `auth_events`.
/// Safely avoids stack overflow on deep DAGs using an iterative post-order traversal with memoization.
pub(crate) fn compute_auth_distance_iterative<'a, Id, C, E>(
    curr_id: &'a Id,
    auth_context: &'a impl crate::basespec::rezzy_types::EventProvider<Id, C, E>,
    create_id: Option<&'a Id>,
    memo: &mut HashMap<&'a Id, u64>,
) -> u64
where
    Id: crate::basespec::rezzy_types::EventId + 'a,
    C: 'a,
    E: EventLike<Id = Id, Content = C> + 'a,
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
            if !ev.auth_events().is_empty() {
                for aid in ev.auth_events() {
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
#[allow(clippy::implicit_hasher)]
pub fn lean_kahn_sort_with_cycle_diagnostics<Id, C, E, S1>(
    events: &HashMap<Id, E, S1>,
    sort_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C, E>,
    create_ev: Option<&E>,
    version: StateResVersion,
    pl_cache: &mut HashMap<Id, i64>,
) -> KahnSortResult<Id>
where
    Id: crate::basespec::rezzy_types::EventId,
    S1: core::hash::BuildHasher,
    C: Clone + crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
{
    pl_cache.clear();

    let mut in_degree: HashMap<Id, usize> = HashMap::new();
    let mut adjacency: HashMap<Id, Vec<Id>> = HashMap::new();

    for (id, event) in events {
        in_degree.entry(id.clone()).or_insert(0);
        for auth in event.auth_events() {
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
    for (id, ev) in events {
        if !pl_cache.contains_key(id) {
            pl_cache.insert(
                id.clone(),
                get_power_level_from_auth_chain(ev, sort_context, create_ev, version),
            );
        }
    }

    let depth_cache: HashMap<Id, u64> = if version == StateResVersion::V2_2 {
        let mut memo = HashMap::new();
        let create_id = create_ev.map(super::super::basespec::rezzy_types::DagNode::event_id);
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

    let mut queue: BinaryHeap<SortPriority<'_, E>> = BinaryHeap::new();
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

        result.push(event.event_id().clone());
        if let Some(neighbors) = adjacency.get(event.event_id()) {
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
#[allow(clippy::implicit_hasher)]
pub fn lean_kahn_sort<Id, C, E, S1>(
    events: &HashMap<Id, E, S1>,
    sort_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C, E>,
    create_ev: Option<&E>,
    version: StateResVersion,
    pl_cache: &mut HashMap<Id, i64>,
) -> Vec<Id>
where
    Id: crate::basespec::rezzy_types::EventId,
    S1: core::hash::BuildHasher,
    C: Clone + crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
{
    // jscpd:ignore-end
    match lean_kahn_sort_with_cycle_diagnostics(events, sort_context, create_ev, version, pl_cache)
    {
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
                ev_a.origin_server_ts()
                    .cmp(&ev_b.origin_server_ts())
                    .then_with(|| a.cmp(b))
            });
            sorted.append(&mut stuck);
            sorted
        }
    }
}

pub(crate) fn build_mainline<Id, C, E, K>(
    resolved: &crate::state::at::SharedState<Id, K>,
    auth_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C, E>,
) -> Vec<Id>
where
    Id: crate::basespec::rezzy_types::EventId,
    C: Clone + crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
    K: Ord + Clone + Default,
{
    // TODO: Thread a persistent cache through callers that invoke build_mainline
    // repeatedly (e.g., the delta loop in compute_state_at, lattice fold checkpoints).
    // Currently each call starts with a fresh cache, so the memoization never hits
    // in production — only the unit test exercises the cache-hit path.
    build_mainline_with_cache(resolved, auth_context, &mut HashMap::new())
}

/// Like [`build_mainline`], but populates a `pl_parent_cache` mapping each
/// event ID to its nearest `m.room.power_levels` ancestor in the auth chain.
///
/// Subsequent calls sharing the same cache skip BFS entirely for events
/// already resolved, turning the mainline walk from `O(M × B)` (M = mainline
/// length, B = auth chain breadth) to `O(M)` on cache hits.
pub(crate) fn build_mainline_with_cache<Id, C, E, K>(
    resolved: &crate::state::at::SharedState<Id, K>,
    auth_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C, E>,
    pl_parent_cache: &mut HashMap<Id, Option<Id>>,
) -> Vec<Id>
where
    Id: crate::basespec::rezzy_types::EventId,
    C: Clone + crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
    K: Ord + Clone + Default,
{
    let mut mainline = Vec::new();
    let mut seen_in_mainline = hashbrown::HashSet::new();
    let pl_key = (
        alloc::string::String::from(M_ROOM_POWER_LEVELS),
        K::default(),
    );
    let mut current = resolved.get(&pl_key).cloned();

    while let Some(eid) = current {
        if !seen_in_mainline.insert(eid.clone()) {
            #[cfg(feature = "std")]
            std::eprintln!("REZZY_WARN: MAINLINE CYCLE DETECTED!");
            break; // Cycle detected in the power-levels mainline!
        }
        mainline.push(eid.clone());

        // Check cache first
        if let Some(cached) = pl_parent_cache.get(&eid) {
            current = None;
            current.clone_from(cached);
            continue;
        }

        // BFS to find the nearest PL ancestor
        let mut found = None;
        if let Some(ev) = auth_context.get_event(&eid) {
            let mut queue = VecDeque::new();
            for auth_id in ev.auth_events() {
                queue.push_back(auth_id.clone());
            }
            let mut visited = hashbrown::HashSet::new();
            while let Some(q_id) = queue.pop_front() {
                if !visited.insert(q_id.clone()) {
                    continue;
                }
                if let Some(auth_ev) = auth_context.get_event(&q_id) {
                    if auth_ev.event_type().as_ref() == M_ROOM_POWER_LEVELS {
                        found = Some(q_id);
                        break;
                    }
                    for aid in auth_ev.auth_events() {
                        queue.push_back(aid.clone());
                    }
                }
            }
        }

        pl_parent_cache.insert(eid, found.clone());
        current = found;
    }

    mainline
}

/// Precompute the closest mainline position for every target event reachable via
/// `auth_events` using a stack-safe O(V+E) iterative DFS upward search.
///
/// This entirely avoids `O(N)` cloning of the DAG, and prevents stack overflow
/// by using an explicit stack to simulate recursion while memoizing distances.
pub(crate) fn compute_closest_mainline_positions<Id, C, E>(
    events: &mut [&E],
    mainline: &[Id],
    auth_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C, E>,
) -> HashMap<Id, usize>
where
    Id: crate::basespec::rezzy_types::EventId,
    C: Clone + crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
{
    let mut memo = HashMap::new();

    // Pre-populate mainline events with their exact index position
    for (pos, id) in mainline.iter().enumerate() {
        memo.insert(id.clone(), pos);
    }

    let mut stack = Vec::new();

    for ev in events.iter() {
        stack.push(ev.event_id());

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
                for aid in node.auth_events() {
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
pub fn mainline_sort<Id, C, E>(
    events: &mut [&E],
    mainline: &[Id],
    auth_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C, E>,
) where
    Id: crate::basespec::rezzy_types::EventId,
    C: Clone + crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
{
    #[cfg(all(feature = "std", debug_assertions, not(test)))]
    std::eprintln!(
        "[DEBUG] mainline_sort: sorting {} non-power events against mainline of length {}",
        events.len(),
        mainline.len()
    );
    // O(V+E) iterative DFS to find the closest mainline index for all non-power events
    let dist = compute_closest_mainline_positions(events, mainline, auth_context);

    events.sort_by(|a, b| {
        // Hopefully safe to unwrap. DFS guarantees all events are in `dist`.
        let pos_a = dist[a.event_id()];
        let pos_b = dist[b.event_id()];

        // Larger mainline position = farther from current PL = worse = comes first
        // (so it gets overwritten by closer events via last-write-wins)
        match pos_b.cmp(&pos_a) {
            Ordering::Equal => {
                // Earlier timestamp comes first (later wins via last-write)
                match a.origin_server_ts().cmp(&b.origin_server_ts()) {
                    Ordering::Equal => a.event_id().cmp(b.event_id()),
                    ord => ord,
                }
            }
            ord => ord,
        }
    });
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
                alloc::string::String::new(),
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
            _marker: core::marker::PhantomData,
        };

        let mainline = alloc::vec!["pl0".into()];
        let mut events = alloc::vec![&topic];
        let dist = compute_closest_mainline_positions(&mut events, &mainline, &sort_ctx);
        // topic's auth chain → pl0 (position 0)
        assert_eq!(dist["topic"], 0);
    }

    /// Coverage: `compute_auth_distance_iterative`
    /// Creates a 3-hop auth chain and verifies the iterative DFS + memoization.
    #[test]
    fn test_auth_distance_iterative_deep_chain() {
        use crate::basespec::rezzy_types::SortContext;

        let create = LeanEvent::<String> {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            auth_events: alloc::vec![],
            ..Default::default()
        };
        let pl = LeanEvent::<String> {
            event_id: "$pl".into(),
            event_type: "m.room.power_levels".into(),
            auth_events: alloc::vec!["$create".into()],
            ..Default::default()
        };
        let join = LeanEvent::<String> {
            event_id: "$join".into(),
            event_type: "m.room.member".into(),
            auth_events: alloc::vec!["$create".into(), "$pl".into()],
            ..Default::default()
        };
        let topic = LeanEvent::<String> {
            event_id: "$topic".into(),
            event_type: "m.room.topic".into(),
            auth_events: alloc::vec!["$create".into(), "$pl".into(), "$join".into()],
            ..Default::default()
        };

        let mut primary: HashMap<String, LeanEvent<String>> = HashMap::new();
        primary.insert("$create".into(), create.clone());
        primary.insert("$pl".into(), pl);
        primary.insert("$join".into(), join);
        primary.insert("$topic".into(), topic);

        let secondary: HashMap<String, LeanEvent<String>> = HashMap::new();
        let sort_ctx = SortContext {
            primary: &primary,
            secondary: &secondary,
            _marker: core::marker::PhantomData,
        };

        let mut memo = HashMap::new();
        let topic_id: String = "$topic".into();
        let create_id: String = "$create".into();
        let pl_id: String = "$pl".into();
        let join_id: String = "$join".into();

        // First call: triggers iterative traversal through auth chain
        // $topic → $join(dist=2), $pl(dist=1), $create(dist=0) → min = 1
        let dist =
            compute_auth_distance_iterative(&topic_id, &sort_ctx, Some(&create_id), &mut memo);
        assert_eq!(
            dist, 1,
            "$topic should be distance 1 from $create (direct auth)"
        );

        // Second call: hits memoization early return (line 96)
        let dist2 =
            compute_auth_distance_iterative(&topic_id, &sort_ctx, Some(&create_id), &mut memo);
        assert_eq!(dist2, dist, "Memoized result must match");

        // Verify intermediate memos were populated
        assert_eq!(
            memo.get(&pl_id),
            Some(&1),
            "$pl should be distance 1 from $create"
        );
        assert_eq!(
            memo.get(&join_id),
            Some(&1),
            "$join has $create in auth → distance 1"
        );
    }

    /// Coverage: `build_mainline_with_cache` cache hit path (sorting.rs:355-361).
    ///
    /// Calling `build_mainline_with_cache` twice with the same cache: the first
    /// call populates the cache for each PL event, and the second call hits the
    /// cache early, skipping the BFS entirely.
    #[test]
    fn test_build_mainline_cache_hit() {
        // Chain: PL2 → (auth) → PL1 → (auth) → PL0
        let pl0 = LeanEvent::<String> {
            event_id: "PL0".into(),
            event_type: "m.room.power_levels".into(),
            auth_events: alloc::vec![],
            ..Default::default()
        };
        let pl1 = LeanEvent::<String> {
            event_id: "PL1".into(),
            event_type: "m.room.power_levels".into(),
            auth_events: alloc::vec!["PL0".into()],
            ..Default::default()
        };
        let pl2 = LeanEvent::<String> {
            event_id: "PL2".into(),
            event_type: "m.room.power_levels".into(),
            auth_events: alloc::vec!["PL1".into()],
            ..Default::default()
        };

        let mut ctx = HashMap::new();
        ctx.insert("PL0".into(), pl0);
        ctx.insert("PL1".into(), pl1);
        ctx.insert("PL2".into(), pl2);

        let mut resolved = imbl::OrdMap::new();
        resolved.insert(("m.room.power_levels".into(), String::new()), "PL2".into());

        // First call: populates cache for PL2 → Some(PL1), PL1 → Some(PL0), PL0 → None
        let mut cache = HashMap::new();
        let ml1 = build_mainline_with_cache(&resolved, &ctx, &mut cache);
        assert_eq!(ml1, alloc::vec!["PL2", "PL1", "PL0"]);
        assert_eq!(cache.len(), 3, "all 3 PL events must be cached");

        // Second call: hits cache immediately for PL2 → skips BFS
        let ml2 = build_mainline_with_cache(&resolved, &ctx, &mut cache);
        assert_eq!(ml2, ml1, "cached mainline must match original");
    }

    #[test]
    fn test_lean_kahn_sort_clears_reused_cache() {
        let first = LeanEvent::<String> {
            event_id: "$first".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@alice:x".into(),
            origin_server_ts: 1,
            power_level: 10,
            ..Default::default()
        };
        let second = LeanEvent::<String> {
            event_id: "$second".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@alice:x".into(),
            origin_server_ts: 1,
            power_level: 0,
            ..Default::default()
        };

        let mut events = HashMap::new();
        events.insert(first.event_id.clone(), first.clone());
        events.insert(second.event_id.clone(), second.clone());

        let mut cache = HashMap::new();

        let first_sort = lean_kahn_sort(&events, &events, None, StateResVersion::V2, &mut cache);
        assert_eq!(first_sort[0], "$first");

        let mut mutated_events = events.clone();
        mutated_events.get_mut("$first").unwrap().power_level = 0;
        mutated_events.get_mut("$second").unwrap().power_level = 10;

        let second_sort = lean_kahn_sort(
            &mutated_events,
            &mutated_events,
            None,
            StateResVersion::V2,
            &mut cache,
        );
        assert_eq!(second_sort[0], "$second");
    }

    #[test]
    fn test_lean_kahn_sort_accepts_borrowed_event_views() {
        use crate::basespec::rezzy_types::LeanEventRef;

        let pl = LeanEvent::<String> {
            event_id: "$pl".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@alice:x".into(),
            power_level: 10,
            ..Default::default()
        };
        let msg = LeanEvent::<String> {
            event_id: "$msg".into(),
            event_type: "m.room.message".into(),
            sender: "@alice:x".into(),
            auth_events: alloc::vec!["$pl".into()],
            ..Default::default()
        };

        let pl_ref: LeanEventRef<'_, String> = pl.as_ref();
        let msg_ref: LeanEventRef<'_, String> = msg.as_ref();

        let mut events = HashMap::new();
        events.insert(pl.event_id.clone(), pl_ref);
        events.insert(msg.event_id.clone(), msg_ref);

        let sorted = lean_kahn_sort(
            &events,
            &events,
            None::<&LeanEventRef<'_, String>>,
            StateResVersion::V2,
            &mut HashMap::new(),
        );

        assert_eq!(
            sorted,
            alloc::vec![
                alloc::string::String::from("$pl"),
                alloc::string::String::from("$msg")
            ]
        );
    }
}
