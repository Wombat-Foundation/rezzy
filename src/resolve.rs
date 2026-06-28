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

use crate::cdo::apply_cdo_filter;
use crate::sorting::{build_mainline, lean_kahn_sort, mainline_sort};
use crate::state_at::{compute_local_auth, iterative_auth_ok, LocalAuthCache};
use crate::types::{LeanEvent, StateResVersion};
use crate::HashMap;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Prepares the conflicted events map and tracks original conflicted keys before CDO pre-filtering.
pub(crate) fn prepare_conflicted_and_keys<
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    conflicted_events: &mut HashMap<Id, LeanEvent<Id>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id>, S2>,
    version: StateResVersion,
) -> alloc::collections::BTreeSet<Id> {
    let original_conflicted_keys = conflicted_events.keys().cloned().collect();
    if version == StateResVersion::V2_1_1 {
        let filtered = apply_cdo_filter(conflicted_events, auth_context);
        conflicted_events.clear();
        for (k, v) in filtered {
            conflicted_events.insert(k, v);
        }
    }
    original_conflicted_keys
}

// jscpd:ignore-start
/// Builds a merged lookup map (`sort_context`) for sorting and mainline operations.
pub(crate) fn build_sort_context<
    Id: Clone + Eq + core::hash::Hash,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    conflicted_events: &HashMap<Id, LeanEvent<Id>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id>, S2>,
    // jscpd:ignore-end
) -> HashMap<Id, LeanEvent<Id>> {
    auth_context
        .iter()
        .chain(conflicted_events.iter())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// MSC4297 (v2.1+): Routes administrative ancestral power events from `auth_context` into `power_events`.
pub(crate) fn route_msc4297_ancestral_power_events<
    Id: Clone + Eq + core::hash::Hash + Ord,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    power_events: &mut HashMap<Id, LeanEvent<Id>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id>, S2>,
    original_conflicted_keys: &alloc::collections::BTreeSet<Id>,
    version: StateResVersion,
) {
    if matches!(
        version,
        StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2
    ) {
        let mut conflicted_power_ancestry = alloc::collections::BTreeSet::new();
        let mut queue = alloc::collections::VecDeque::new();
        for ev in power_events.values() {
            for aid in &ev.auth_events {
                queue.push_back(aid.clone());
            }
        }
        while let Some(aid) = queue.pop_front() {
            if conflicted_power_ancestry.insert(aid.clone()) {
                if let Some(aev) = auth_context.get(&aid) {
                    for parent_id in &aev.auth_events {
                        queue.push_back(parent_id.clone());
                    }
                }
            }
        }

        for (id, ev) in auth_context {
            if !original_conflicted_keys.contains(id)
                && conflicted_power_ancestry.contains(id)
                && (ev.event_type == "m.room.power_levels"
                    || ev.event_type == "m.room.create"
                    || ev.event_type == "m.room.join_rules")
            {
                power_events.insert(id.clone(), ev.clone());
            }
        }
    }
}

/// Runs the sequential power phase iterative auth checks to establish the authoritative administrative framework.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_power_phase_iterative_checks<
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    S3: core::hash::BuildHasher,
    S4: core::hash::BuildHasher,
>(
    resolved: &mut BTreeMap<(String, Option<String>), Id>,
    power_events: &HashMap<Id, LeanEvent<Id>, S4>,
    sort_context: &HashMap<Id, LeanEvent<Id>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id>, S2>,
    sort_set: &HashMap<Id, LeanEvent<Id>, S3>,
    create_ev: Option<&LeanEvent<Id>>,
    local_auth_cache: &mut LocalAuthCache<Id>,
    version: StateResVersion,
) {
    let sorted_power_ids = lean_kahn_sort(power_events, sort_context, create_ev, version);
    for id in &sorted_power_ids {
        if let Some(event) = sort_set.get(id).or_else(|| auth_context.get(id)) {
            let local_auth =
                compute_local_auth(event, auth_context, sort_set, local_auth_cache, version);
            if iterative_auth_ok(
                event,
                resolved,
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
}

pub(crate) fn get_initial_resolved_state<Id: Clone>(
    unconflicted_state: &BTreeMap<(String, Option<String>), Id>,
    version: StateResVersion,
) -> BTreeMap<(String, Option<String>), Id> {
    match version {
        StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2 => BTreeMap::new(),
        _ => unconflicted_state.clone(),
    }
}

#[must_use]
pub fn resolve_lean<Id, S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
    unconflicted_state: BTreeMap<(String, Option<String>), Id>,
    mut conflicted_events: HashMap<Id, LeanEvent<Id>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id>, S2>,
    version: StateResVersion,
) -> BTreeMap<(String, Option<String>), Id>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
{
    let original_conflicted_keys =
        prepare_conflicted_and_keys(&mut conflicted_events, auth_context, version);
    let sort_context = build_sort_context(&conflicted_events, auth_context);

    // MSC4297 (v2.1+): The algorithm starts from an empty set of state.
    let mut resolved = get_initial_resolved_state(&unconflicted_state, version);

    let sort_set = &conflicted_events;

    // Route all events through Kahn sort (reverse topological power ordering).
    let mut power_events = HashMap::new();
    let mut non_power_events = HashMap::new();
    crate::lattice::route_power_events(sort_set, &mut power_events, &mut non_power_events);

    route_msc4297_ancestral_power_events(
        &mut power_events,
        auth_context,
        &original_conflicted_keys,
        version,
    );

    let create_ev = crate::types::find_deterministic_create_event(auth_context, sort_set);

    // Step 1: Sort power events by reverse topological power ordering (Kahn sort)
    // Step 2: Apply iterative auth checks (per spec & Ruma implementation)
    let mut local_auth_cache: LocalAuthCache<Id> = HashMap::new();

    run_power_phase_iterative_checks(
        &mut resolved,
        &power_events,
        &sort_context,
        auth_context,
        sort_set,
        create_ev,
        &mut local_auth_cache,
        version,
    );

    // Step 3: Build the power-level mainline for mainline sort
    let mainline = build_mainline(&resolved, &sort_context);

    // Step 4: Sort non-power events by mainline ordering + iterative auth check
    let mut non_power_list: Vec<&LeanEvent<Id>> = non_power_events.values().collect();
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
