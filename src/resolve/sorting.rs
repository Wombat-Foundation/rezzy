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
use core::cmp::Ordering;
use std::collections::{BinaryHeap, VecDeque};
use std::vec::Vec;

use crate::basespec::event_types::{MAX_POWER_LEVEL_RUST, M_ROOM_POWER_LEVELS};
use crate::basespec::rezzy_types::{
    EventContent, EventId, EventLike, EventProvider, KahnSortResult, SortPriority, StateResVersion,
};
use crate::state::at::SharedState;
use crate::{FastMap, HashMap};
use core::hash::BuildHasher;

/// Dynamically fetches the sender's power level by inspecting the event's immediate `auth_events`.
/// Recursive traversal of the auth chain is avoided to prevent bypassing immediate restrictions.
pub(crate) fn get_power_level_from_auth_chain<Id, C, E>(
    event: &E,
    auth_context: &impl EventProvider<Id, C, E>,
    create_ev: Option<&E>,
    version: StateResVersion,
) -> i64
where
    Id: EventId,
    C: EventContent,
    E: EventLike<Id = Id, Content = C>,
{
    let mut pl_event = None;

    // Spec compliance: only check immediate auth_events (or prev_state_events for V2.2).
    for aid in event.dag_edges(version) {
        if let Some(aev) = auth_context.get_event(aid) {
            if aev.event_type() == M_ROOM_POWER_LEVELS && aev.state_key() == Some("") {
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

/// Bundled inputs for Kahn's topological sort over event power resolution.
///
/// Held as one value so the diagnostic and fallback entry points share a single
/// bound set instead of re-declaring the same five parameters.
pub struct KahnSortInputs<'a, Id, E, P, S1, Spl> {
    /// Events to sort, keyed by id.
    pub events: &'a HashMap<Id, E, S1>,
    /// Provides `auth_events` lookups for power-level resolution.
    pub sort_context: &'a P,
    /// Optional creator event used for V12+ infinite-power semantics.
    pub create_ev: Option<&'a E>,
    /// Room version selecting the auth rules.
    pub version: StateResVersion,
    /// Scratch cache of per-event power levels, reused across sort passes.
    pub pl_cache: &'a mut HashMap<Id, i64, Spl>,
}

impl<'a, Id, E, P, S1, Spl> KahnSortInputs<'a, Id, E, P, S1, Spl>
where
    Id: EventId,
    S1: BuildHasher,
    Spl: BuildHasher,
    E: EventLike<Id = Id>,
    P: EventProvider<Id, E::Content, E>,
{
    /// Bundles the inputs accepted by the sort entry points.
    #[must_use]
    pub fn new(
        events: &'a HashMap<Id, E, S1>,
        sort_context: &'a P,
        create_ev: Option<&'a E>,
        version: StateResVersion,
        pl_cache: &'a mut HashMap<Id, i64, Spl>,
    ) -> Self {
        Self {
            events,
            sort_context,
            create_ev,
            version,
            pl_cache,
        }
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
    #[must_use]
    #[allow(clippy::implicit_hasher)]
    pub fn with_cycle_diagnostics(self) -> KahnSortResult<Id> {
        let Self {
            events,
            sort_context,
            create_ev,
            version,
            pl_cache,
        } = self;
        pl_cache.clear();

        let mut in_degree: FastMap<&Id, usize> = FastMap::default();
        let mut adjacency: FastMap<&Id, Vec<&Id>> = FastMap::default();

        for (id, event) in events {
            in_degree.entry(id).or_insert(0);
            for auth in event.dag_edges(version) {
                if let Some((auth_key, _)) = events.get_key_value(auth) {
                    // Topological sort: ancestors come BEFORE descendants.
                    // But we want a REVERSE topological sort: descendants BEFORE ancestors.
                    // So we add edges from ancestors to descendants.
                    adjacency.entry(auth_key).or_default().push(id);
                    let val = in_degree.entry(id).or_insert(0);
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

        let mut queue: BinaryHeap<SortPriority<'_, E>> = BinaryHeap::new();
        for (id, &degree) in &in_degree {
            if degree == 0 {
                if let Some(event) = events.get(*id) {
                    queue.push(SortPriority {
                        event,
                        power_level: pl_cache.get(*id).copied().unwrap_or(0),
                        version,
                    });
                }
            }
        }

        let mut result = Vec::with_capacity(events.len());
        while let Some(priority) = queue.pop() {
            let event = priority.event;

            result.push(event.event_id().clone());
            if let Some(neighbors) = adjacency.get(event.event_id()) {
                for &next_id in neighbors {
                    let degree = in_degree.get_mut(next_id).unwrap();
                    *degree = degree.saturating_sub(1);
                    if *degree == 0 {
                        let next_ev = events.get(next_id).unwrap();
                        queue.push(SortPriority {
                            event: next_ev,
                            power_level: pl_cache.get(next_id).copied().unwrap_or(0),
                            version,
                        });
                    }
                }
            }
        }

        // Detect cycles: events that never reached in-degree 0.
        if result.len() != events.len() {
            let sorted_set: crate::FastSet<&Id> = result.iter().collect();
            let stuck: Vec<Id> = events
                .keys()
                .filter(|id| !sorted_set.contains(id))
                .cloned()
                .collect();
            drop(sorted_set);
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
    #[must_use]
    #[allow(clippy::implicit_hasher)]
    pub fn sort(self) -> Vec<Id> {
        let events = self.events;
        match self.with_cycle_diagnostics() {
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
}

pub(crate) fn build_mainline<Id, C, E, K>(
    resolved: &SharedState<Id, K>,
    auth_context: &impl EventProvider<Id, C, E>,
    empty_key: &K,
    version: StateResVersion,
) -> Vec<Id>
where
    Id: EventId,
    C: Clone + EventContent,
    E: EventLike<Id = Id, Content = C>,
    K: Ord + Clone,
{
    // The hot path (compute_state_at's fork-merge loop) now threads a persistent
    // cache through `resolve_iterative_sort_with_all_caches`, so this fresh-cache
    // fallback only matters for one-shot callers (e.g. resolve_semilattice_fold's V2
    // path, which calls build_mainline exactly once per resolution).
    build_mainline_with_cache(
        resolved,
        auth_context,
        &mut FastMap::default(),
        empty_key,
        version,
    )
}

/// Like [`build_mainline`], but populates a `pl_parent_cache` mapping each
/// event ID to its nearest `m.room.power_levels` ancestor in the auth chain.
///
/// Subsequent calls sharing the same cache skip BFS entirely for events
/// already resolved, turning the mainline walk from `O(M × B)` (M = mainline
/// length, B = auth chain breadth) to `O(M)` on cache hits.
pub(crate) fn build_mainline_with_cache<Id, C, E, K>(
    resolved: &SharedState<Id, K>,
    auth_context: &impl EventProvider<Id, C, E>,
    pl_parent_cache: &mut FastMap<Id, Option<Id>>,
    empty_key: &K,
    version: StateResVersion,
) -> Vec<Id>
where
    Id: EventId,
    C: Clone + EventContent,
    E: EventLike<Id = Id, Content = C>,
    K: Ord + Clone,
{
    let mut mainline = Vec::new();
    let mut seen_in_mainline = crate::FastSet::default();
    let pl_key = (
        crate::basespec::event_types::EventType::from(M_ROOM_POWER_LEVELS),
        empty_key.clone(),
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
            let mut queue: VecDeque<&Id> = ev.dag_edges(version).iter().collect();
            let mut visited = crate::FastSet::default();
            while let Some(q_id) = queue.pop_front() {
                if !visited.insert(q_id) {
                    continue;
                }
                if let Some(auth_ev) = auth_context.get_event(q_id) {
                    if auth_ev.event_type() == M_ROOM_POWER_LEVELS {
                        found = Some(q_id.clone());
                        break;
                    }
                    for aid in auth_ev.dag_edges(version) {
                        queue.push_back(aid);
                    }
                }
            }
        }

        pl_parent_cache.insert(eid, found.clone());
        current = found;
    }

    mainline
}

/// Precompute the closest mainline position for every target event, following
/// only each event's `m.room.power_levels` auth edge, using a stack-safe O(V+E) iterative DFS upward search.
///
/// This entirely avoids `O(N)` cloning of the DAG, and prevents stack overflow
/// by using an explicit stack to simulate recursion while memoizing distances.
pub(crate) fn compute_closest_mainline_positions<Id, C, E>(
    events: &mut [&E],
    mainline: &[Id],
    auth_context: &impl EventProvider<Id, C, E>,
    version: StateResVersion,
) -> HashMap<Id, usize>
where
    Id: EventId,
    C: Clone + EventContent,
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

            // Spec (V2/V2.1): an event's mainline position is found by
            // repeatedly following only its `m.room.power_levels` auth event
            // (the first one listed), NOT every auth edge. Taking the min over
            // all edges lets an event that cites a newer-epoch membership
            // inherit that epoch. An event with no PL auth edge (create, early
            // joins) has no mainline ancestor and clamps to `mainline.len()`.
            if let Some(node) = auth_context.get_event(top) {
                let pl_edge = node.dag_edges(version).iter().find(|aid| {
                    auth_context
                        .get_event(aid)
                        .is_some_and(|a| a.event_type().as_ref() == M_ROOM_POWER_LEVELS)
                });
                if let Some(aid) = pl_edge {
                    if let Some(&child_pos) = memo.get(aid) {
                        if child_pos != usize::MAX - 1 {
                            min_pos = child_pos;
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
/// closest mainline PL event reached via its power-levels auth link. The sort order is:
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
    auth_context: &impl EventProvider<Id, C, E>,
    version: StateResVersion,
) where
    Id: EventId,
    C: Clone + EventContent,
    E: EventLike<Id = Id, Content = C>,
{
    // O(V+E) iterative DFS to find the closest mainline index for all non-power events
    let dist = compute_closest_mainline_positions(events, mainline, auth_context, version);

    // Schwartzian transform: decorate each event with its precomputed mainline
    // position so the comparator performs zero hash lookups. This cuts the
    // `dist` hash lookups from O(N log N) (two per comparison) down to exactly
    // N. The comparator order is identical to the pre-decoration version.
    let mut decorated: Vec<(&E, usize)> = events
        .iter()
        .map(|&ev| (ev, *dist.get(ev.event_id()).unwrap_or(&mainline.len())))
        .collect();

    // Larger mainline position = farther from current PL = worse = comes first
    // (so it gets overwritten by closer events via last-write-wins)
    decorated.sort_by(|(a, pos_a), (b, pos_b)| match pos_b.cmp(pos_a) {
        Ordering::Equal => {
            // Earlier timestamp comes first (later wins via last-write)
            match a.origin_server_ts().cmp(&b.origin_server_ts()) {
                Ordering::Equal => a.event_id().cmp(b.event_id()),
                ord => ord,
            }
        }
        ord => ord,
    });

    for (i, (ev, _)) in decorated.into_iter().enumerate() {
        events[i] = ev;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::basespec::rezzy_types::LeanEvent;
    use std::{string::String, vec::Vec};

    fn pl_event(event_id: &str) -> LeanEvent<String> {
        LeanEvent::<String> {
            event_id: event_id.into(),
            event_type: "m.room.power_levels".into(),
            auth_events: vec![],
            ..Default::default()
        }
    }

    /// Computes mainline positions for `ev` against `auth_ctx` with the
    /// standard single-entry `pl0` mainline.
    fn closest_position(
        ev: &LeanEvent<String>,
        auth_ctx: &HashMap<String, LeanEvent<String>>,
    ) -> HashMap<String, usize> {
        let mainline: Vec<String> = vec!["pl0".into()];
        let mut events = vec![ev];
        compute_closest_mainline_positions(&mut events, &mainline, auth_ctx, StateResVersion::V2)
    }

    #[test]
    fn test_build_mainline_cycle_detection() {
        // A and B both claim to be m.room.power_levels, and auth against each other, forming a cycle.
        let a = LeanEvent::<String> {
            event_id: std::string::String::from("A"),
            event_type: std::string::String::from("m.room.power_levels"),
            auth_events: vec![std::string::String::from("B")],
            ..Default::default()
        };
        let b = LeanEvent::<String> {
            event_id: std::string::String::from("B"),
            event_type: std::string::String::from("m.room.power_levels"),
            auth_events: vec![std::string::String::from("A")],
            ..Default::default()
        };

        let mut auth_context = HashMap::new();
        auth_context.insert(std::string::String::from("A"), a);
        auth_context.insert(std::string::String::from("B"), b);

        // Initial state sets A as the power levels event.
        let mut resolved = SharedState::new();
        resolved.insert(
            (
                crate::basespec::event_types::EventType::from("m.room.power_levels"),
                std::string::String::new(),
            ),
            std::string::String::from("A"),
        );

        // Before the fix, this would infinite loop!
        let mainline = build_mainline(
            &resolved,
            &auth_context,
            &std::string::String::new(),
            StateResVersion::V2,
        );

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
            auth_events: vec![],
            ..Default::default()
        };
        let auth_ctx: HashMap<String, LeanEvent<String>> = HashMap::new();
        let dist = closest_position(&ev, &auth_ctx);
        // No path found → clamped to mainline.len() = 1, not usize::MAX
        assert_eq!(dist["orphan"], 1);
    }

    /// An event whose auth chain leads directly to a mainline event gets that position.
    #[test]
    fn test_closest_mainline_direct_hit() {
        let pl = pl_event("pl0");
        let ev = LeanEvent::<String> {
            event_id: "msg".into(),
            event_type: "m.room.message".into(),
            auth_events: vec!["pl0".into()],
            ..Default::default()
        };
        let mut auth_ctx: HashMap<String, LeanEvent<String>> = HashMap::new();
        auth_ctx.insert("pl0".into(), pl);
        auth_ctx.insert("msg".into(), ev.clone());

        let dist = closest_position(&ev, &auth_ctx);
        assert_eq!(dist["msg"], 0);
    }

    /// Per spec only the `power_levels` auth edge is followed: leaf → mid → pl0
    /// has no PL edge on `leaf`, so it has no mainline ancestor.
    #[test]
    fn test_closest_mainline_ignores_non_pl_edges() {
        let pl = pl_event("pl0");
        let mid = LeanEvent::<String> {
            event_id: "mid".into(),
            event_type: "m.room.member".into(),
            auth_events: vec!["pl0".into()],
            ..Default::default()
        };
        let leaf = LeanEvent::<String> {
            event_id: "leaf".into(),
            event_type: "m.room.topic".into(),
            auth_events: vec!["mid".into()],
            ..Default::default()
        };
        let mut ctx: HashMap<String, LeanEvent<String>> = HashMap::new();
        ctx.insert("pl0".into(), pl);
        ctx.insert("mid".into(), mid);
        ctx.insert("leaf".into(), leaf.clone());

        let dist = closest_position(&leaf, &ctx);
        assert_eq!(dist["leaf"], 1, "no PL edge => mainline.len()");
    }

    /// A PL auth id that is absent from `auth_context` is not recognised as a
    /// PL edge, and must not make the event inherit a position via other edges.
    #[test]
    fn test_closest_mainline_missing_pl_event_clamps_to_len() {
        let mainline: Vec<String> = alloc::vec!["pl0".into()];
        let mem = LeanEvent::<String> {
            event_id: "mem".into(),
            event_type: "m.room.member".into(),
            auth_events: alloc::vec![],
            ..Default::default()
        };
        let ev = LeanEvent::<String> {
            event_id: "ev".into(),
            event_type: "m.room.topic".into(),
            auth_events: alloc::vec!["pl_missing".into(), "mem".into()],
            ..Default::default()
        };
        let mut ctx: HashMap<String, LeanEvent<String>> = HashMap::new();
        ctx.insert("mem".into(), mem);
        ctx.insert("ev".into(), ev.clone());
        let mut events = alloc::vec![&ev];
        let dist =
            compute_closest_mainline_positions(&mut events, &mainline, &ctx, StateResVersion::V2_1);
        assert_eq!(dist["ev"], 1);
    }

    /// An event citing old PL directly plus a member event whose own PL is
    /// newer must take the OLD PL's position (the V2.1 state-reset scenario).
    #[test]
    fn test_closest_mainline_uses_own_pl_edge_not_min_over_edges() {
        let mainline: Vec<String> = alloc::vec!["pl_new".into(), "pl_old".into()];
        let pl_old = pl_event("pl_old");
        let pl_new = pl_event("pl_new");
        let mem_new = LeanEvent::<String> {
            event_id: "mem_new".into(),
            event_type: "m.room.member".into(),
            auth_events: alloc::vec!["pl_new".into()],
            ..Default::default()
        };
        let mem_old = LeanEvent::<String> {
            event_id: "mem_old".into(),
            event_type: "m.room.member".into(),
            auth_events: alloc::vec!["pl_old".into(), "mem_new".into()],
            ..Default::default()
        };
        let mut ctx: HashMap<String, LeanEvent<String>> = HashMap::new();
        for e in [&pl_old, &pl_new, &mem_new, &mem_old] {
            ctx.insert(e.event_id.clone(), e.clone());
        }
        let mut events = alloc::vec![&mem_old, &mem_new];
        let dist =
            compute_closest_mainline_positions(&mut events, &mainline, &ctx, StateResVersion::V2_1);
        assert_eq!(dist["mem_new"], 0);
        assert_eq!(dist["mem_old"], 1);
    }

    /// `mainline_sort` must order events by mainline position (descending),
    /// then `origin_server_ts` (ascending), then `event_id`. The Schwartzian
    /// transform must preserve this exact order.
    #[test]
    fn test_mainline_sort_orders_by_position_then_time_then_id() {
        let pl0 = LeanEvent::<String> {
            event_id: "pl0".into(),
            event_type: "m.room.power_levels".into(),
            auth_events: vec![],
            ..Default::default()
        };
        let pl1 = LeanEvent::<String> {
            event_id: "pl1".into(),
            event_type: "m.room.power_levels".into(),
            auth_events: vec!["pl0".into()],
            ..Default::default()
        };
        // near: auth chain hits mainline at index 1 (newest) -> position 1.
        let near = LeanEvent::<String> {
            event_id: "near".into(),
            event_type: "m.room.topic".into(),
            origin_server_ts: 100,
            auth_events: vec!["pl1".into()],
            ..Default::default()
        };
        // far_early and far both hit mainline at index 0 -> position 0; tie on
        // position is broken by earlier timestamp, then by event_id.
        let far_early = LeanEvent::<String> {
            event_id: "far_early".into(),
            event_type: "m.room.topic".into(),
            origin_server_ts: 50,
            auth_events: vec!["pl0".into()],
            ..Default::default()
        };
        let far = LeanEvent::<String> {
            event_id: "far".into(),
            event_type: "m.room.topic".into(),
            origin_server_ts: 200,
            auth_events: vec!["pl0".into()],
            ..Default::default()
        };
        let mut ctx: HashMap<String, LeanEvent<String>> = HashMap::new();
        ctx.insert("pl0".into(), pl0);
        ctx.insert("pl1".into(), pl1);
        ctx.insert("near".into(), near.clone());
        ctx.insert("far_early".into(), far_early.clone());
        ctx.insert("far".into(), far.clone());

        let mainline = vec!["pl0".into(), "pl1".into()];
        let mut events = vec![&far, &far_early, &near];
        mainline_sort(&mut events, &mainline, &ctx, StateResVersion::V2);

        // Larger mainline position comes first: near (1), then far_early (ts
        // 50) before far (ts 200).
        assert_eq!(events[0].event_id, "near");
        assert_eq!(events[1].event_id, "far_early");
        assert_eq!(events[2].event_id, "far");
    }

    /// Empty mainline: all events should clamp to 0 (`mainline.len()`).
    #[test]
    fn test_closest_mainline_empty_mainline() {
        let ev = LeanEvent::<String> {
            event_id: "x".into(),
            event_type: "m.room.topic".into(),
            auth_events: vec![],
            ..Default::default()
        };
        let ctx: HashMap<String, LeanEvent<String>> = HashMap::new();
        let mainline: Vec<String> = vec![];
        let mut events = vec![&ev];
        let dist =
            compute_closest_mainline_positions(&mut events, &mainline, &ctx, StateResVersion::V2);
        assert_eq!(dist["x"], 0);
    }

    /// `SortContext` merged provider correctly finds events across both maps.
    #[test]
    fn test_sort_context_merged_lookup() {
        use crate::basespec::rezzy_types::SortContext;

        let pl = LeanEvent::<String> {
            event_id: "pl0".into(),
            event_type: "m.room.power_levels".into(),
            auth_events: vec![],
            ..Default::default()
        };
        let topic = LeanEvent::<String> {
            event_id: "topic".into(),
            event_type: "m.room.topic".into(),
            auth_events: vec!["pl0".into()],
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

        let mainline = vec!["pl0".into()];
        let mut events = vec![&topic];
        let dist = compute_closest_mainline_positions(
            &mut events,
            &mainline,
            &sort_ctx,
            StateResVersion::V2,
        );
        // topic's auth chain → pl0 (position 0)
        assert_eq!(dist["topic"], 0);
    }

    /// call populates the cache for each PL event, and the second call hits the
    /// cache early, skipping the BFS entirely.
    #[test]
    fn test_build_mainline_cache_hit() {
        // Chain: PL2 → (auth) → PL1 → (auth) → PL0
        let pl0 = LeanEvent::<String> {
            event_id: "PL0".into(),
            event_type: "m.room.power_levels".into(),
            auth_events: vec![],
            ..Default::default()
        };
        let pl1 = LeanEvent::<String> {
            event_id: "PL1".into(),
            event_type: "m.room.power_levels".into(),
            auth_events: vec!["PL0".into()],
            ..Default::default()
        };
        let pl2 = LeanEvent::<String> {
            event_id: "PL2".into(),
            event_type: "m.room.power_levels".into(),
            auth_events: vec!["PL1".into()],
            ..Default::default()
        };

        let mut ctx = HashMap::new();
        ctx.insert("PL0".into(), pl0);
        ctx.insert("PL1".into(), pl1);
        ctx.insert("PL2".into(), pl2);

        let mut resolved = SharedState::new();
        resolved.insert(("m.room.power_levels".into(), String::new()), "PL2".into());

        // First call: populates cache for PL2 → Some(PL1), PL1 → Some(PL0), PL0 → None
        let mut cache = FastMap::default();
        let ml1 = build_mainline_with_cache(
            &resolved,
            &ctx,
            &mut cache,
            &String::new(),
            StateResVersion::V2,
        );
        assert_eq!(ml1, vec!["PL2", "PL1", "PL0"]);
        assert_eq!(cache.len(), 3, "all 3 PL events must be cached");

        // Second call: hits cache immediately for PL2 → skips BFS
        let ml2 = build_mainline_with_cache(
            &resolved,
            &ctx,
            &mut cache,
            &String::new(),
            StateResVersion::V2,
        );
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

        let first_sort =
            KahnSortInputs::new(&events, &events, None, StateResVersion::V2, &mut cache).sort();
        assert_eq!(first_sort[0], "$first");

        let mut mutated_events = events.clone();
        mutated_events.get_mut("$first").unwrap().power_level = 0;
        mutated_events.get_mut("$second").unwrap().power_level = 10;

        let second_sort = KahnSortInputs::new(
            &mutated_events,
            &mutated_events,
            None,
            StateResVersion::V2,
            &mut cache,
        )
        .sort();
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
            auth_events: vec!["$pl".into()],
            ..Default::default()
        };

        let pl_ref: LeanEventRef<'_, String> = pl.as_ref();
        let msg_ref: LeanEventRef<'_, String> = msg.as_ref();

        let mut events = HashMap::new();
        events.insert(pl.event_id.clone(), pl_ref);
        events.insert(msg.event_id.clone(), msg_ref);

        let sorted = KahnSortInputs::new(
            &events,
            &events,
            None::<&LeanEventRef<'_, String>>,
            StateResVersion::V2,
            &mut HashMap::new(),
        )
        .sort();

        assert_eq!(
            sorted,
            vec![
                std::string::String::from("$pl"),
                std::string::String::from("$msg")
            ]
        );
    }
}
