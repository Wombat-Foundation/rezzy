#![cfg(feature = "mock-ruma")]
extern crate alloc;
extern crate ruma_state_res as original_ruma;
use alloc::string::String;
use alloc::vec::Vec;
pub use original_ruma::events::RoomCreateEvent;
pub use original_ruma::utils::event_id_map::EventIdMap;
pub use original_ruma::utils::event_id_set::EventIdSet;
pub use original_ruma::{Error as RumaError, Event, StateMap};

use rezzy::LeanEvent;

fn ruma_to_lean_event<E: Event>(ev: &E) -> LeanEvent {
    use alloc::string::ToString;
    let content_val: serde_json::Value =
        serde_json::from_str(ev.content().get()).unwrap_or(serde_json::Value::Null);
    let power_level = content_val
        .get("power_level")
        .and_then(rezzy::basespec::rezzy_types::coerce_json_to_i64)
        .unwrap_or(0);
    LeanEvent {
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

type PartitionedState = (
    imbl::OrdMap<(String, String), String>,
    std::collections::HashSet<(ruma_events::StateEventType, String)>,
);

fn partition_state<'a, E>(state_sets: &[StateMap<E::Id>]) -> PartitionedState
where
    E: Event + Clone,
    E::Id: 'a,
{
    use alloc::string::ToString;
    use std::collections::{HashMap, HashSet};

    let mut counts: HashMap<(&(ruma_events::StateEventType, String), &E::Id), usize> =
        HashMap::new();
    for map in state_sets {
        for (key, id) in map {
            let val = counts.entry((key, id)).or_insert(0);
            *val = val.wrapping_add(1);
        }
    }

    let num_maps = state_sets.len();
    let mut conflicted_keys = HashSet::new();
    let mut unconflicted_state = imbl::OrdMap::new();

    for map in state_sets {
        for (key, id) in map {
            if counts.get(&(key, id)).copied().unwrap_or(0) == num_maps {
                unconflicted_state.insert((key.0.to_string(), key.1.clone()), id.to_string());
            } else {
                conflicted_keys.insert(key.clone());
            }
        }
    }

    (unconflicted_state, conflicted_keys)
}

fn build_conflicted_events<'a, E>(
    state_sets: &[StateMap<E::Id>],
    conflicted_keys: &std::collections::HashSet<(ruma_events::StateEventType, String)>,
    state_res_rules: ruma_common::room_version_rules::StateResolutionV2Rules,
    fetch_event: &impl Fn(&ruma_common::EventId) -> Option<E>,
    fetch_conflicted_state_subgraph: &impl Fn(
        &StateMap<Vec<E::Id>>,
    ) -> Option<
        original_ruma::utils::event_id_set::EventIdSet<E::Id>,
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

    let mut insert_if_missing = |id: &E::Id| {
        let id_str = id.to_string();
        if !conflicted_events.contains_key(&id_str) {
            if let Some(ev) = fetch_event(id.borrow()) {
                conflicted_events.insert(id_str.clone(), ruma_to_lean_event(&ev));
            }
        }
    };

    for map in state_sets {
        for (key, id) in map {
            if conflicted_keys.contains(key) {
                insert_if_missing(id);
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
                insert_if_missing(&id);
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
#[allow(clippy::trivially_copy_pass_by_ref, clippy::unnecessary_wraps)]
pub fn resolve<'a, E, MapsIter>(
    _auth_rules: &ruma_common::room_version_rules::AuthorizationRules,
    state_res_rules: &ruma_common::room_version_rules::StateResolutionV2Rules,
    state_maps: impl IntoIterator<IntoIter = MapsIter>,
    auth_chains: Vec<original_ruma::utils::event_id_set::EventIdSet<E::Id>>,
    fetch_event: impl Fn(&ruma_common::EventId) -> Option<E>,
    fetch_conflicted_state_subgraph: impl Fn(
        &StateMap<Vec<E::Id>>,
    ) -> Option<
        original_ruma::utils::event_id_set::EventIdSet<E::Id>,
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

    for chain in &auth_chains {
        for id in chain {
            to_fetch.push(id.clone());
            id_map.insert(id.to_string(), id.clone());
        }
    }

    // Compute auth difference
    let mut union_auth = std::collections::HashSet::new();
    let mut intersect_auth = auth_chains
        .first()
        .map_or_else(std::collections::HashSet::new, |first| {
            first.iter().map(ToString::to_string).collect()
        });
    for chain in auth_chains {
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
    let resolved = rezzy::resolve_lean(
        unconflicted_state,
        conflicted_events,
        &auth_context,
        if state_res_rules.begin_iterative_auth_checks_with_empty_state_map {
            rezzy::StateResVersion::V2_1
        } else {
            rezzy::StateResVersion::V2
        },
    );

    let mut result = StateMap::new();
    for ((ev_type, state_key), id_str) in resolved {
        let key = (ev_type.as_str().into(), state_key.clone());
        if let Some(id) = id_map.get(&id_str) {
            result.insert(key, id.clone());
        }
    }

    Ok(result)
}
