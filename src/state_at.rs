use crate::types::{LeanEvent, StateResVersion};
use crate::HashMap;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

pub type LocalAuthCache = HashMap<String, BTreeMap<(String, Option<String>), (LeanEvent, usize)>>;

pub(crate) struct OverlayState<'a, S1, S2> {
    pub(crate) resolved: &'a BTreeMap<(String, Option<String>), String>,
    pub(crate) auth_context: &'a HashMap<String, LeanEvent, S1>,
    pub(crate) conflicted: &'a HashMap<String, LeanEvent, S2>,
    pub(crate) local_auth: BTreeMap<(String, Option<String>), LeanEvent>,
    pub(crate) create_ev: Option<&'a LeanEvent>,
    pub(crate) version: StateResVersion,
    pub(crate) is_power_phase: bool,
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
pub(crate) fn iterative_auth_ok<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
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

pub(crate) fn update_local_auth(
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
pub(crate) fn compute_local_auth<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
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
                let total_depth = current_depth.saturating_add(*cached_depth);
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
                    queue.push_back((parent_id.clone(), current_depth.saturating_add(1)));
                }
            }
        }
    }

    cache.insert(event.event_id.clone(), local_auth.clone());
    local_auth.into_iter().map(|(k, (v, _))| (k, v)).collect()
}

type SharedState = alloc::sync::Arc<BTreeMap<(String, Option<String>), String>>;

/// Computes the state map at (after) a given target event ID,
/// assuming all ancestral events are present in `events_map`.
///
/// # Panics
///
/// Will panic if graph invariants are violated (specifically, if an ancestor event
/// present in the reachable subgraph is missing from `events_map` during topological processing).
#[must_use]
pub fn compute_state_at<S: core::hash::BuildHasher>(
    target_event_id: &str,
    events_map: &HashMap<String, LeanEvent, S>,
) -> Option<BTreeMap<(String, Option<String>), String>> {
    if !events_map.contains_key(target_event_id) {
        return None;
    }

    let (id_to_index, index_to_id) = collect_ancestor_short_ids(target_event_id, events_map);
    let sorted_ancestors = topological_sort_short_ids(&index_to_id, &id_to_index, events_map);

    let mut state_after_map: Vec<Option<SharedState>> = alloc::vec![None; index_to_id.len()];

    for idx in sorted_ancestors {
        let id_str = index_to_id[idx];
        let ev = events_map.get(id_str).unwrap();

        let mut prev_states: Vec<&SharedState> = Vec::with_capacity(ev.prev_events.len());
        for pe in &ev.prev_events {
            if let Some(&pe_idx) = id_to_index.get(pe.as_str()) {
                if let Some(ref pe_state) = state_after_map[pe_idx] {
                    prev_states.push(pe_state);
                }
            }
        }

        let mut state_before: SharedState = if prev_states.is_empty() {
            alloc::sync::Arc::new(BTreeMap::new())
        } else if prev_states.len() == 1 {
            alloc::sync::Arc::clone(prev_states[0])
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

    let target_idx = id_to_index[target_event_id];
    state_after_map[target_idx].take().map(|arc| {
        let cloned_arc = arc.clone();
        alloc::sync::Arc::into_inner(arc).unwrap_or_else(|| (*cloned_arc).clone())
    })
}

fn collect_ancestor_short_ids<'a, S: core::hash::BuildHasher>(
    target_event_id: &'a str,
    events_map: &'a HashMap<String, LeanEvent, S>,
) -> (HashMap<&'a str, usize>, Vec<&'a str>) {
    let mut id_to_index: HashMap<&str, usize> = HashMap::new();
    let mut index_to_id: Vec<&str> = Vec::new();
    let mut queue = alloc::vec![target_event_id];
    let mut head = 0;

    id_to_index.insert(target_event_id, 0);
    index_to_id.push(target_event_id);

    while head < queue.len() {
        let current_id = queue[head];
        head = head.saturating_add(1);

        if let Some(ev) = events_map.get(current_id) {
            for pe in &ev.prev_events {
                let pe_str = pe.as_str();
                if events_map.contains_key(pe_str) && !id_to_index.contains_key(pe_str) {
                    let next_idx = index_to_id.len();
                    id_to_index.insert(pe_str, next_idx);
                    index_to_id.push(pe_str);
                    queue.push(pe_str);
                }
            }
        }
    }

    (id_to_index, index_to_id)
}

fn topological_sort_short_ids<S: core::hash::BuildHasher>(
    index_to_id: &[&str],
    id_to_index: &HashMap<&str, usize>,
    events_map: &HashMap<String, LeanEvent, S>,
) -> Vec<usize> {
    let num_reachable = index_to_id.len();
    let mut in_degree = alloc::vec![0usize; num_reachable];
    let mut adjacency = alloc::vec![Vec::new(); num_reachable];

    for (i, id) in index_to_id.iter().enumerate() {
        if let Some(ev) = events_map.get(*id) {
            for parent in &ev.prev_events {
                if let Some(&parent_idx) = id_to_index.get(parent.as_str()) {
                    in_degree[i] = in_degree[i].saturating_add(1);
                    adjacency[parent_idx].push(i);
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

    sorted_ancestors
}

fn resolve_merge_fast_path<S: core::hash::BuildHasher>(
    prev_states: &[&SharedState],
    events_map: &HashMap<String, LeanEvent, S>,
) -> SharedState {
    let mut all_match = true;
    let first = prev_states[0];
    for state in &prev_states[1..] {
        if !alloc::sync::Arc::ptr_eq(first, state) && **first != ***state {
            all_match = false;
            break;
        }
    }

    if all_match {
        alloc::sync::Arc::clone(first)
    } else {
        let unwrapped_prev_states: Vec<BTreeMap<_, _>> =
            prev_states.iter().map(|&arc| (**arc).clone()).collect();
        alloc::sync::Arc::new(resolve_multiple_prev_states(
            &unwrapped_prev_states,
            events_map,
        ))
    }
}

fn resolve_multiple_prev_states<S: core::hash::BuildHasher>(
    prev_states: &[BTreeMap<(String, Option<String>), String>],
    events_map: &HashMap<String, LeanEvent, S>,
) -> BTreeMap<(String, Option<String>), String> {
    let mut occurrences: HashMap<(String, Option<String>), HashMap<String, usize>> = HashMap::new();
    let num_sets = prev_states.len();
    for map in prev_states {
        for (key, val) in map {
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
    let mut b_stack: Vec<String> = conflicted_state_set.into_iter().collect();
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
