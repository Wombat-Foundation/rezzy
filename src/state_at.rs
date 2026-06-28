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

//! Incremental state computation — room state at arbitrary DAG positions.
//!
//! This module computes the resolved room state *after* any given event in the
//! DAG, without requiring external state snapshots. It walks the `prev_events`
//! graph backwards, builds the state at each ancestor, and merges fork points
//! via [`crate::resolve::resolve_lean`].
//!
//! Key optimizations:
//!
//! - **`Arc`-based structural sharing**: parent states are shared via
//!   `Arc<BTreeMap>` and cloned only when modified (copy-on-write).
//! - **Pointer-equality fast path**: when all parents share the same `Arc`,
//!   no merge is needed.
//! - **Batch mode** ([`compute_state_at_batch`]): computes state at multiple
//!   targets in a single topological pass, amortizing the cost of shared ancestors.

use crate::types::{LeanEvent, StateResVersion};
use crate::HashMap;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

/// An entry in the local auth cache, pairing an event with its discovery depth.
///
/// The `depth` field tracks how many hops through `auth_events` it took to
/// reach this event. When the same `(type, state_key)` is found at multiple
/// depths, the shallowest (closest) entry wins.
#[derive(Debug, Clone)]
pub struct LocalAuthEntry<Id> {
    /// The auth event itself.
    pub event: LeanEvent<Id>,
    /// Number of auth-chain hops from the original event to this one.
    pub depth: usize,
}

/// Memoization cache for local auth context computation.
///
/// Maps `event_id → BTreeMap<(type, state_key) → LocalAuthEntry>`, allowing
/// the local auth context to be computed once and reused for all events that
/// share auth chain prefixes.
pub type LocalAuthCache<Id = String> =
    HashMap<Id, BTreeMap<(String, Option<String>), LocalAuthEntry<Id>>>;

pub(crate) struct OverlayState<'a, Id, S1, S2> {
    pub(crate) resolved: &'a BTreeMap<(String, Option<String>), Id>,
    pub(crate) auth_context: &'a HashMap<Id, LeanEvent<Id>, S1>,
    pub(crate) conflicted: &'a HashMap<Id, LeanEvent<Id>, S2>,
    pub(crate) local_auth: BTreeMap<(String, Option<String>), LeanEvent<Id>>,
    pub(crate) create_ev: Option<&'a LeanEvent<Id>>,
    pub(crate) version: StateResVersion,
    pub(crate) is_power_phase: bool,
}

impl<
        Id: Clone + Eq + core::hash::Hash,
        S1: core::hash::BuildHasher,
        S2: core::hash::BuildHasher,
    > crate::auth::StateProvider<Id> for OverlayState<'_, Id, S1, S2>
{
    fn get_event(&self, event_type: &str, state_key: Option<&str>) -> Option<&LeanEvent<Id>> {
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
                    if self.version == StateResVersion::V2_1_1
                        && self.is_power_phase
                        && event_type == "m.room.member"
                    {
                        // V2.1.1 Fix: Only supplement bans and kicks in power phase
                        if let Some(membership) =
                            ev.content.get("membership").and_then(|m| m.as_str())
                        {
                            let is_ban = membership == "ban";
                            let is_kick = membership == "leave"
                                && state_key.is_some()
                                && Some(ev.sender.as_str()) != state_key;
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

        // Check local auth chain (BFS result) second!
        if let Some(ev) = self.local_auth.get(query) {
            // Under Matrix State Resolution, during the power phase, a required auth event in the conflicted set
            // can ONLY be used if it has been successfully authorized and resolved
            // (i.e. is present in the resolved state).
            let is_required_type =
                event_type == "m.room.power_levels" || event_type == "m.room.join_rules";

            let is_v2_1_or_above = self.version == StateResVersion::V2_1
                || self.version == StateResVersion::V2_1_1
                || self.version == StateResVersion::V2_2;

            if self.is_power_phase
                && is_v2_1_or_above
                && is_required_type
                && self.conflicted.contains_key(&ev.event_id)
            {
                if let Some(resolved_id) = self.resolved.get(query) {
                    if let Some(resolved_ev) = self
                        .auth_context
                        .get(resolved_id)
                        .or_else(|| self.conflicted.get(resolved_id))
                    {
                        return Some(resolved_ev);
                    }
                }
                None
            } else {
                Some(ev)
            }
        } else {
            // Fallback for create
            if event_type == "m.room.create" && state_key == Some("") {
                return self.create_ev;
            }
            None
        }
    }
}

/// Evaluates whether an event passes authentication checks given a resolved state map,
/// delegating to the core `crate::auth::check_auth` logic via a temporary `OverlayState` view.
///
/// NOTE: In V2.1/MSC4297, progressive state starts empty. The first event's sender membership
/// check must use its own `auth_events` (via `local_auth` / `OverlayState` fallback), not the
/// empty state. This is critical for competing bans where both senders need membership validation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn iterative_auth_ok<
    Id: Clone + Eq + core::hash::Hash,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    event: &LeanEvent<Id>,
    resolved: &BTreeMap<(String, Option<String>), Id>,
    auth_context: &HashMap<Id, LeanEvent<Id>, S1>,
    conflicted_events: &HashMap<Id, LeanEvent<Id>, S2>,
    local_auth: BTreeMap<(String, Option<String>), LeanEvent<Id>>,
    cached_create: Option<&LeanEvent<Id>>,
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

pub(crate) fn update_local_auth<Id: Clone>(
    local_auth: &mut BTreeMap<(String, Option<String>), LocalAuthEntry<Id>>,
    aev: &LeanEvent<Id>,
    current_depth: usize,
) {
    let key = (aev.event_type.clone(), aev.state_key.clone());
    match local_auth.entry(key) {
        alloc::collections::btree_map::Entry::Vacant(e) => {
            e.insert(LocalAuthEntry {
                event: aev.clone(),
                depth: current_depth,
            });
        }
        alloc::collections::btree_map::Entry::Occupied(mut e) => {
            if current_depth < e.get().depth {
                e.insert(LocalAuthEntry {
                    event: aev.clone(),
                    depth: current_depth,
                });
            }
        }
    }
}

/// Recursively compute the local auth context for an event, using memoization
/// to avoid redundant graph walks. The context is represented as a map of
/// (type, `state_key`) -> (`LeanEvent`, depth), ensuring that for each key, the "closest"
/// auth event in the chain is preserved (shortest path).
pub(crate) fn compute_local_auth<
    Id: Clone + Eq + core::hash::Hash + Ord,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    event: &LeanEvent<Id>,
    auth_context: &HashMap<Id, LeanEvent<Id>, S1>,
    conflicted_events: &HashMap<Id, LeanEvent<Id>, S2>,
    cache: &mut LocalAuthCache<Id>,
    version: StateResVersion,
) -> BTreeMap<(String, Option<String>), LeanEvent<Id>> {
    if let Some(cached) = cache.get(&event.event_id) {
        return cached
            .clone()
            .into_iter()
            .map(|(k, entry)| (k, entry.event))
            .collect();
    }

    let mut local_auth: BTreeMap<(String, Option<String>), LocalAuthEntry<Id>> = BTreeMap::new();
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

            for (key, entry) in cached_ancestor {
                let total_depth = current_depth.saturating_add(entry.depth);
                match local_auth.entry(key.clone()) {
                    alloc::collections::btree_map::Entry::Vacant(e) => {
                        e.insert(LocalAuthEntry {
                            event: entry.event.clone(),
                            depth: total_depth,
                        });
                    }
                    alloc::collections::btree_map::Entry::Occupied(mut e) => {
                        if total_depth < e.get().depth {
                            e.insert(LocalAuthEntry {
                                event: entry.event.clone(),
                                depth: total_depth,
                            });
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
                    queue.push_back((parent_id.clone(), current_depth.saturating_add(1)));
                }
            }
        }
    }

    cache.insert(event.event_id.clone(), local_auth.clone());
    local_auth
        .into_iter()
        .map(|(k, entry)| (k, entry.event))
        .collect()
}

type SharedState<Id = String> = alloc::sync::Arc<BTreeMap<(String, Option<String>), Id>>;

/// Computes the resolved room state *after* a given event.
///
/// This walks the `prev_events` graph backwards from `target_event_id`,
/// topologically sorts all reachable ancestors, and incrementally builds
/// the state by applying each state event in order. Fork points are resolved
/// via [`crate::resolve::resolve_lean`] with V2 semantics.
///
/// Returns `None` if `target_event_id` is not found in `events_map`.
///
/// # Panics
///
/// Will panic if graph invariants are violated (specifically, if an ancestor event
/// present in the reachable subgraph is missing from `events_map` during topological processing).
#[must_use]
pub fn compute_state_at<Id, Q, S>(
    target_event_id: &Q,
    events_map: &HashMap<Id, LeanEvent<Id>, S>,
) -> Option<BTreeMap<(String, Option<String>), Id>>
where
    Id: Clone + Eq + Ord + core::fmt::Debug + core::hash::Hash + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + Ord + core::hash::Hash,
    S: core::hash::BuildHasher,
{
    let actual_target_id = events_map.get_key_value(target_event_id).map(|(k, _)| k)?;

    let (id_to_index, index_to_id) = collect_ancestor_short_ids(actual_target_id, events_map);
    let target_array = [actual_target_id];
    let mut state_after_map =
        run_state_pipeline(&index_to_id, &id_to_index, &target_array, events_map);

    let target_idx = id_to_index[actual_target_id];
    state_after_map[target_idx].take().map(|arc| {
        alloc::sync::Arc::try_unwrap(arc).unwrap_or_else(|failed_arc| (*failed_arc).clone())
    })
}

/// Computes the resolved room state at multiple target events in a single pass.
///
/// This is the batch variant of [`compute_state_at`]. It shares the topological
/// sort and ancestor traversal across all targets, which is significantly faster
/// than calling `compute_state_at` in a loop when the targets share ancestors.
///
/// Returns a map from each found target event ID to its resolved state.
/// Target IDs not found in `events_map` are silently skipped.
///
/// # Panics
///
/// Will panic if graph invariants are violated (specifically, if an ancestor event
/// present in the reachable subgraph is missing from `events_map` during topological processing).
#[must_use]
pub fn compute_state_at_batch<Id, Q, S>(
    target_event_ids: &[&Q],
    events_map: &HashMap<Id, LeanEvent<Id>, S>,
) -> HashMap<Id, BTreeMap<(String, Option<String>), Id>>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
    S: core::hash::BuildHasher,
{
    let mut actual_target_ids = Vec::new();
    let mut seen = alloc::collections::BTreeSet::new();
    for &tid in target_event_ids {
        if let Some((k, _)) = events_map.get_key_value(tid) {
            if seen.insert(k) {
                actual_target_ids.push(k);
            }
        }
    }

    if actual_target_ids.is_empty() {
        return HashMap::new();
    }

    let (id_to_index, index_to_id) =
        collect_ancestor_short_ids_batch(&actual_target_ids, events_map);
    let mut state_after_map =
        run_state_pipeline(&index_to_id, &id_to_index, &actual_target_ids, events_map);

    let mut results = HashMap::with_capacity(actual_target_ids.len());
    for &actual_tid in &actual_target_ids {
        if let Some(&target_idx) = id_to_index.get(actual_tid) {
            if let Some(shared_state) = state_after_map[target_idx].take() {
                let btree =
                    alloc::sync::Arc::try_unwrap(shared_state).unwrap_or_else(|arc| (*arc).clone());
                results.insert(actual_tid.clone(), btree);
            }
        }
    }

    results
}

/// Shared method for `compute_state_at` and `compute_state_at_batch`.
fn run_state_pipeline<'a, Id, S>(
    index_to_id: &[&'a Id],
    id_to_index: &HashMap<&'a Id, usize>,
    target_event_ids: &[&'a Id],
    events_map: &HashMap<Id, LeanEvent<Id>, S>,
) -> Vec<Option<SharedState<Id>>>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    S: core::hash::BuildHasher,
{
    let (sorted_ancestors, mut out_degree) =
        topological_sort_short_ids(index_to_id, id_to_index, events_map);

    // Artificially increment the out_degree of final target events by 1
    // to ensure they are never consumed and remain in state_after_map.
    for &tid in target_event_ids {
        if let Some(&target_idx) = id_to_index.get(tid) {
            out_degree[target_idx] = out_degree[target_idx].saturating_add(1);
        }
    }

    let mut state_after_map: Vec<Option<SharedState<Id>>> = core::iter::repeat_with(|| None)
        .take(index_to_id.len())
        .collect();

    for idx in sorted_ancestors {
        let id_val = index_to_id[idx];
        let ev = events_map.get(id_val).unwrap();

        let mut prev_states = Vec::with_capacity(ev.prev_events.len());
        for pe in &ev.prev_events {
            if let Some(&pe_idx) = id_to_index.get(pe) {
                if out_degree[pe_idx] > 0 {
                    out_degree[pe_idx] = out_degree[pe_idx].saturating_sub(1);
                    if out_degree[pe_idx] == 0 {
                        if let Some(pe_state) = state_after_map[pe_idx].take() {
                            prev_states.push(pe_state);
                        }
                    } else if let Some(ref pe_state) = state_after_map[pe_idx] {
                        prev_states.push(alloc::sync::Arc::clone(pe_state));
                    }
                }
            }
        }

        let mut state_before: SharedState<Id> = if prev_states.is_empty() {
            alloc::sync::Arc::new(BTreeMap::new())
        } else if prev_states.len() == 1 {
            prev_states.into_iter().next().unwrap()
        } else {
            resolve_merge_fast_path(&prev_states, events_map)
        };

        if ev.state_key.is_some() {
            let mut_state = alloc::sync::Arc::make_mut(&mut state_before);
            mut_state.insert(
                (ev.event_type.clone(), ev.state_key.clone()),
                ev.event_id.clone(),
            );
        }

        state_after_map[idx] = Some(state_before);
    }

    state_after_map
}

fn collect_ancestor_short_ids_batch<'a, Id, S>(
    target_event_ids: &[&'a Id],
    events_map: &'a HashMap<Id, LeanEvent<Id>, S>,
) -> (HashMap<&'a Id, usize>, Vec<&'a Id>)
where
    Id: Clone + Eq + core::hash::Hash,
    S: core::hash::BuildHasher,
{
    let mut id_to_index: HashMap<&Id, usize> = HashMap::new();
    let mut index_to_id: Vec<&Id> = Vec::new();
    let mut queue = Vec::new();

    for &tid in target_event_ids {
        if !id_to_index.contains_key(tid) {
            let next_idx = index_to_id.len();
            id_to_index.insert(tid, next_idx);
            index_to_id.push(tid);
            queue.push(tid);
        }
    }

    let mut head = 0;
    while head < queue.len() {
        let current_id = queue[head];
        head = head.saturating_add(1);

        if let Some(ev) = events_map.get(current_id) {
            for pe in &ev.prev_events {
                if events_map.contains_key(pe) && !id_to_index.contains_key(pe) {
                    let next_idx = index_to_id.len();
                    id_to_index.insert(pe, next_idx);
                    index_to_id.push(pe);
                    queue.push(pe);
                }
            }
        }
    }

    (id_to_index, index_to_id)
}

fn collect_ancestor_short_ids<'a, Id, S>(
    target_event_id: &'a Id,
    events_map: &'a HashMap<Id, LeanEvent<Id>, S>,
) -> (HashMap<&'a Id, usize>, Vec<&'a Id>)
where
    Id: Clone + Eq + core::hash::Hash,
    S: core::hash::BuildHasher,
{
    collect_ancestor_short_ids_batch(&[target_event_id], events_map)
}

fn topological_sort_short_ids<Id, S>(
    index_to_id: &[&Id],
    id_to_index: &HashMap<&Id, usize>,
    events_map: &HashMap<Id, LeanEvent<Id>, S>,
) -> (Vec<usize>, Vec<usize>)
where
    Id: Clone + Eq + core::hash::Hash,
    S: core::hash::BuildHasher,
{
    let num_reachable = index_to_id.len();
    let mut in_degree = alloc::vec![0usize; num_reachable];
    let mut adjacency = alloc::vec![Vec::new(); num_reachable];
    let mut out_degree = alloc::vec![0usize; num_reachable];

    for (i, id) in index_to_id.iter().enumerate() {
        if let Some(ev) = events_map.get(*id) {
            for parent in &ev.prev_events {
                if let Some(&parent_idx) = id_to_index.get(parent) {
                    in_degree[i] = in_degree[i].saturating_add(1);
                    adjacency[parent_idx].push(i);
                    out_degree[parent_idx] = out_degree[parent_idx].saturating_add(1);
                }
            }
        }
    }

    let mut topo_queue = alloc::collections::VecDeque::new();
    for (i, &deg) in in_degree.iter().enumerate() {
        if deg == 0 {
            topo_queue.push_back(i);
        }
    }

    let mut sorted_ancestors = Vec::with_capacity(num_reachable);
    while let Some(idx) = topo_queue.pop_front() {
        sorted_ancestors.push(idx);
        for &child_idx in &adjacency[idx] {
            in_degree[child_idx] = in_degree[child_idx].saturating_sub(1);
            if in_degree[child_idx] == 0 {
                topo_queue.push_back(child_idx);
            }
        }
    }

    (sorted_ancestors, out_degree)
}

fn resolve_merge_fast_path<Id, S>(
    prev_states: &[SharedState<Id>],
    events_map: &HashMap<Id, LeanEvent<Id>, S>,
) -> SharedState<Id>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    S: core::hash::BuildHasher,
{
    let mut all_match = true;
    let first = &prev_states[0];
    for state in &prev_states[1..] {
        if !alloc::sync::Arc::ptr_eq(first, state) && **first != **state {
            all_match = false;
            break;
        }
    }

    if all_match {
        alloc::sync::Arc::clone(first)
    } else {
        alloc::sync::Arc::new(resolve_multiple_prev_states(prev_states, events_map))
    }
}

fn resolve_multiple_prev_states<Id, S>(
    prev_states: &[SharedState<Id>],
    events_map: &HashMap<Id, LeanEvent<Id>, S>,
) -> BTreeMap<(String, Option<String>), Id>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    S: core::hash::BuildHasher,
{
    let mut occurrences: HashMap<(String, Option<String>), HashMap<Id, usize>> = HashMap::new();
    let num_sets = prev_states.len();
    for map in prev_states {
        for (key, val) in map.iter() {
            let val_entry = occurrences
                .entry(key.clone())
                .or_default()
                .entry(val.clone())
                .or_insert(0);
            *val_entry = val_entry.saturating_add(1);
        }
    }

    let mut unconflicted_state = BTreeMap::new();
    let mut conflicted_state_set = std::collections::HashSet::new();

    for (key, ids) in occurrences {
        if ids.len() == 1 && ids.values().next().unwrap() == &num_sets {
            let id_val = ids.keys().next().unwrap();
            unconflicted_state.insert(key, id_val.clone());
        } else {
            for id_val in ids.keys() {
                conflicted_state_set.insert(id_val.clone());
            }
        }
    }

    let mut conflicted_events = HashMap::new();
    for id_val in &conflicted_state_set {
        if let Some(event) = events_map.get(id_val) {
            conflicted_events.insert(id_val.clone(), event.clone());
        }
    }

    let mut auth_chain_ids = std::collections::HashSet::new();
    let mut b_stack: Vec<Id> = conflicted_state_set.into_iter().collect();
    while let Some(node) = b_stack.pop() {
        if auth_chain_ids.insert(node.clone()) {
            if let Some(event) = events_map.get(&node) {
                for auth_id in &event.auth_events {
                    b_stack.push(auth_id.clone());
                }
            }
        }
    }

    for id_val in auth_chain_ids {
        if let Some(event) = events_map.get(&id_val) {
            conflicted_events.insert(id_val, event.clone());
        }
    }

    crate::resolve::resolve_lean(
        unconflicted_state,
        conflicted_events,
        events_map,
        StateResVersion::V2,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use serde_json::json;

    #[test]
    fn test_conflicted_auth_event_validation_in_power_phase() {
        // Create a minimal room context
        let create_ev = LeanEvent {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            sender: "@admin:example.com".into(),
            content: json!({ "room_version": "11" }),
            ..Default::default()
        };

        // A conflicted power level event where @bot has PL 100
        let pl_bot = LeanEvent {
            event_id: "$pl_bot".into(),
            event_type: "m.room.power_levels".into(),
            sender: "@admin:example.com".into(),
            content: json!({ "users": { "@bot:example.com": 100 } }),
            prev_events: vec!["$create".to_string()],
            auth_events: vec!["$create".to_string()],
            ..Default::default()
        };

        // A conflicted join event of the sender (@bot)
        let bot_join = LeanEvent {
            event_id: "$bot_join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bot:example.com".into()),
            sender: "@bot:example.com".into(),
            content: json!({ "membership": "join" }),
            prev_events: vec!["$pl_bot".to_string()],
            auth_events: vec!["$create".to_string(), "$pl_bot".to_string()],
            ..Default::default()
        };

        // A state event (m.room.topic) sent by @bot (which requires PL 50 if no power levels event is resolved)
        let bot_msg = LeanEvent {
            event_id: "$bot_msg".into(),
            event_type: "m.room.topic".into(),
            state_key: Some(String::new()),
            sender: "@bot:example.com".into(),
            content: json!({ "topic": "hello" }),
            prev_events: vec!["$bot_join".to_string()],
            auth_events: vec![
                "$create".to_string(),
                "$pl_bot".to_string(),
                "$bot_join".to_string(),
            ],
            ..Default::default()
        };

        let mut auth_context = HashMap::new();
        auth_context.insert("$create".to_string(), create_ev.clone());
        auth_context.insert("$pl_bot".to_string(), pl_bot.clone());
        auth_context.insert("$bot_join".to_string(), bot_join.clone());
        auth_context.insert("$bot_msg".to_string(), bot_msg.clone());

        let mut conflicted = HashMap::new();
        // Mark the power levels event as conflicted
        conflicted.insert("$pl_bot".to_string(), pl_bot.clone());

        // Create a resolved map where $pl_bot is NOT resolved yet (empty resolved map)
        let resolved = BTreeMap::new();

        let local_auth = vec![
            (
                ("m.room.create".to_string(), Some(String::new())),
                create_ev.clone(),
            ),
            (
                ("m.room.power_levels".to_string(), Some(String::new())),
                pl_bot.clone(),
            ),
            (
                (
                    "m.room.member".to_string(),
                    Some("@bot:example.com".to_string()),
                ),
                bot_join.clone(),
            ),
        ]
        .into_iter()
        .collect();

        // Under V2.1.1, during the power phase, a conflicted required auth event ($pl_bot)
        // that is NOT in resolved MUST be rejected!
        let is_ok = iterative_auth_ok(
            &bot_msg,
            &resolved,
            &auth_context,
            &conflicted,
            local_auth,
            Some(&create_ev),
            StateResVersion::V2_1_1,
            true, // is_power_phase
        );

        assert!(
            !is_ok,
            "The message must be rejected because the conflicted power levels event was not resolved!"
        );
    }
}
