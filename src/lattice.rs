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

use crate::sorting::{build_mainline, precompute_mainline_positions};
use crate::state_at::{compute_local_auth, iterative_auth_ok, LocalAuthCache};
use crate::types::{find_deterministic_create_event, LeanEvent, StateResVersion};
use crate::HashMap;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

#[must_use]
pub fn is_lattice_winner_better<S: core::hash::BuildHasher>(
    ev: &LeanEvent,
    current_winner: &LeanEvent,
    mainline_distances: &HashMap<String, usize, S>,
    mainline_len: usize,
) -> bool {
    let ev_pos = mainline_distances
        .get(&ev.event_id)
        .copied()
        .unwrap_or(mainline_len);
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
}

fn update_winner_if_better<'a>(
    winners: &mut HashMap<(String, Option<String>), &'a LeanEvent>,
    key: (String, Option<String>),
    ev: &'a LeanEvent,
    mainline_distances: &HashMap<String, usize>,
    mainline_len: usize,
) {
    let is_better = if let Some(current_winner) = winners.get(&key) {
        is_lattice_winner_better(ev, current_winner, mainline_distances, mainline_len)
    } else {
        true // First event for this state key inherently wins
    };

    if is_better {
        winners.insert(key, ev);
    }
}

#[allow(clippy::too_many_arguments)]
fn fold_lattice_chunk<'a, S2: core::hash::BuildHasher, S3: core::hash::BuildHasher>(
    // jscpd:ignore-start
    chunk: &[&'a LeanEvent],
    mainline_distances: &HashMap<String, usize>,
    mainline_len: usize,
    terminal_power_state: &BTreeMap<(String, Option<String>), String>,
    auth_context: &HashMap<String, LeanEvent, S2>,
    sort_set: &HashMap<String, LeanEvent, S3>,
    version: StateResVersion,
    create_ev: Option<&LeanEvent>,
    // jscpd:ignore-end
) -> HashMap<(String, Option<String>), &'a LeanEvent> {
    let mut thread_res: HashMap<(String, Option<String>), &'a LeanEvent> = HashMap::new();
    let mut local_auth_cache = HashMap::new();

    for &ev in chunk {
        // 1. VALIDATE FIRST (Filters out Byzantine garbage/Supremum Deletion attacks)
        let local_auth =
            compute_local_auth(ev, auth_context, sort_set, &mut local_auth_cache, version);
        if !iterative_auth_ok(
            ev,
            terminal_power_state,
            auth_context,
            sort_set,
            local_auth,
            create_ev,
            version,
            false,
        ) {
            continue; // Drop unauthorized events before they can compete for the LUB!
        }

        // 2. NOW COMPETE FOR LUB
        let key = (ev.event_type.clone(), ev.state_key.clone());
        update_winner_if_better(&mut thread_res, key, ev, mainline_distances, mainline_len);
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
        update_winner_if_better(key_winners, key, ev, mainline_distances, mainline_len);
    }
}

#[allow(clippy::too_many_arguments)]
fn compute_lattice_coordinatized_winners<
    'a,
    S1: core::hash::BuildHasher + Sync + Send,
    S2: core::hash::BuildHasher + Sync + Send,
    S3: core::hash::BuildHasher + Sync + Send,
>(
    // jscpd:ignore-start
    non_power_events: &'a HashMap<String, LeanEvent, S1>,
    mainline_distances: &HashMap<String, usize>,
    mainline_len: usize,
    terminal_power_state: &BTreeMap<(String, Option<String>), String>,
    auth_context: &HashMap<String, LeanEvent, S2>,
    sort_set: &HashMap<String, LeanEvent, S3>,
    version: StateResVersion,
    create_ev: Option<&LeanEvent>,
    // jscpd:ignore-end
    key_winners: &mut HashMap<(String, Option<String>), &'a LeanEvent>,
) {
    let v: Vec<&'a LeanEvent> = non_power_events.values().collect();

    #[cfg(feature = "std")]
    {
        let num_threads = std::thread::available_parallelism().map_or(4, core::num::NonZero::get);
        let chunks: Vec<&[&'a LeanEvent]> = v
            .chunks(
                (non_power_events
                    .len()
                    .saturating_add(num_threads)
                    .saturating_sub(1))
                .max(1),
            )
            .collect();

        let winners = std::sync::Mutex::new(HashMap::new());
        std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(chunks.len());
            for chunk in chunks {
                let handle = s.spawn(|| {
                    fold_lattice_chunk(
                        chunk,
                        mainline_distances,
                        mainline_len,
                        terminal_power_state,
                        auth_context,
                        sort_set,
                        version,
                        create_ev,
                    )
                });
                handles.push(handle);
            }
            for handle in handles {
                let thread_res = handle.join().unwrap();
                let mut guard = winners.lock().unwrap();
                merge_lattice_winners(&mut guard, thread_res, mainline_distances, mainline_len);
            }
        });
        *key_winners = winners.into_inner().unwrap();
    }
    #[cfg(not(feature = "std"))]
    {
        *key_winners = fold_lattice_chunk(
            &v,
            mainline_distances,
            mainline_len,
            terminal_power_state,
            auth_context,
            sort_set,
            version,
            create_ev,
        );
    }
}

pub fn route_power_events<
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    S3: core::hash::BuildHasher,
>(
    sort_set: &HashMap<String, LeanEvent, S1>,
    power_events: &mut HashMap<String, LeanEvent, S2>,
    non_power_events: &mut HashMap<String, LeanEvent, S3>,
) {
    for (id, ev) in sort_set {
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

/// Employs O(1) Causal Coordinatization Projection and Commutative Join-Semilattice folding
/// to completely eliminate sequential sorting and backward graph traversals.
// jscpd:ignore-start
#[must_use]
pub fn resolve_lattice_coordinatized<
    S1: core::hash::BuildHasher + Sync + Send,
    S2: core::hash::BuildHasher + Sync + Send,
>(
    unconflicted_state: BTreeMap<(String, Option<String>), String>,
    mut conflicted_events: HashMap<String, LeanEvent, S1>,
    auth_context: &HashMap<String, LeanEvent, S2>,
    version: StateResVersion,
) -> BTreeMap<(String, Option<String>), String> {
    // jscpd:ignore-end
    let original_conflicted_keys =
        crate::resolve::prepare_conflicted_and_keys(&mut conflicted_events, auth_context, version);
    let sort_context = crate::resolve::build_sort_context(&conflicted_events, auth_context);

    let mut resolved = crate::resolve::get_initial_resolved_state(&unconflicted_state, version);

    let sort_set = &conflicted_events;

    // Route power and non-power events
    let mut power_events = HashMap::new();
    let mut non_power_events = HashMap::new();
    route_power_events(sort_set, &mut power_events, &mut non_power_events);

    crate::resolve::route_msc4297_ancestral_power_events(
        &mut power_events,
        auth_context,
        &original_conflicted_keys,
        version,
    );

    let create_ev = find_deterministic_create_event(auth_context, sort_set);

    let mut local_auth_cache: LocalAuthCache = HashMap::new();

    // Power Phase remains sequential to establish the authoritative administrative framework
    crate::resolve::run_power_phase_iterative_checks(
        &mut resolved,
        &power_events,
        &sort_context,
        auth_context,
        sort_set,
        create_ev,
        &mut local_auth_cache,
        version,
    );

    // Step 3: Build the power-level mainline for coordinatization
    let mainline = build_mainline(&resolved, &sort_context);
    let mainline_distances = precompute_mainline_positions(&mainline, &sort_context);

    // Step 4: Commutative Join-Semilattice reduction over all non-power events in a single O(C) pass!
    let mut key_winners = HashMap::new();
    compute_lattice_coordinatized_winners(
        &non_power_events,
        &mainline_distances,
        mainline.len(),
        &resolved,
        auth_context,
        sort_set,
        version,
        create_ev,
        &mut key_winners,
    );

    let mut final_resolved = unconflicted_state;
    for (k, ev) in key_winners {
        final_resolved.insert(k, ev.event_id.clone());
    }
    for (k, v) in resolved {
        final_resolved.insert(k, v);
    }
    drop(conflicted_events);
    final_resolved
}
