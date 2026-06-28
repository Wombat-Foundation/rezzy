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

use crate::{
    sorting::{build_mainline, precompute_mainline_positions},
    state_at::{compute_local_auth, iterative_auth_ok},
    types::{LeanEvent, StateResVersion},
    HashMap,
};
use alloc::{collections::BTreeMap, string::String, vec::Vec};

#[must_use]
pub fn is_lattice_winner_better<Id, S: core::hash::BuildHasher>(
    ev: &LeanEvent<Id>,
    current_winner: &LeanEvent<Id>,
    mainline_distances: &HashMap<Id, usize, S>,
    mainline_len: usize,
) -> bool
where
    Id: Clone + Eq + core::hash::Hash + Ord,
{
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

fn update_winner_if_better<'a, Id>(
    winners: &mut HashMap<(String, Option<String>), &'a LeanEvent<Id>>,
    key: (String, Option<String>),
    ev: &'a LeanEvent<Id>,
    mainline_distances: &HashMap<Id, usize>,
    mainline_len: usize,
) where
    Id: Clone + Eq + core::hash::Hash + Ord,
{
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
fn fold_lattice_chunk<'a, Id, S2: core::hash::BuildHasher, S3: core::hash::BuildHasher>(
    // jscpd:ignore-start
    chunk: &[&'a LeanEvent<Id>],
    mainline_distances: &HashMap<Id, usize>,
    mainline_len: usize,
    terminal_power_state: &BTreeMap<(String, Option<String>), Id>,
    auth_context: &HashMap<Id, LeanEvent<Id>, S2>,
    sort_set: &HashMap<Id, LeanEvent<Id>, S3>,
    version: StateResVersion,
    create_ev: Option<&LeanEvent<Id>>,
    // jscpd:ignore-end
) -> HashMap<(String, Option<String>), &'a LeanEvent<Id>>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
{
    let mut thread_res: HashMap<(String, Option<String>), &'a LeanEvent<Id>> = HashMap::new();
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

fn merge_lattice_winners<'a, Id>(
    key_winners: &mut HashMap<(String, Option<String>), &'a LeanEvent<Id>>,
    thread_res: HashMap<(String, Option<String>), &'a LeanEvent<Id>>,
    mainline_distances: &HashMap<Id, usize>,
    mainline_len: usize,
) where
    Id: Clone + Eq + core::hash::Hash + Ord,
{
    for (key, ev) in thread_res {
        update_winner_if_better(key_winners, key, ev, mainline_distances, mainline_len);
    }
}

#[allow(clippy::too_many_arguments)]
fn compute_lattice_coordinatized_winners<
    'a,
    Id,
    S1: core::hash::BuildHasher + Sync + Send,
    S2: core::hash::BuildHasher + Sync + Send,
    S3: core::hash::BuildHasher + Sync + Send,
>(
    // jscpd:ignore-start
    non_power_events: &'a HashMap<Id, LeanEvent<Id>, S1>,
    mainline_distances: &HashMap<Id, usize>,
    mainline_len: usize,
    terminal_power_state: &BTreeMap<(String, Option<String>), Id>,
    auth_context: &HashMap<Id, LeanEvent<Id>, S2>,
    sort_set: &HashMap<Id, LeanEvent<Id>, S3>,
    version: StateResVersion,
    create_ev: Option<&LeanEvent<Id>>,
    // jscpd:ignore-end
    key_winners: &mut HashMap<(String, Option<String>), &'a LeanEvent<Id>>,
) where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug + Sync + Send,
{
    let v: Vec<&'a LeanEvent<Id>> = non_power_events.values().collect();

    #[cfg(feature = "std")]
    {
        let num_threads = std::thread::available_parallelism().map_or(4, core::num::NonZero::get);
        let chunks: Vec<&[&'a LeanEvent<Id>]> = v
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
    Id: Clone + Eq + core::hash::Hash,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    S3: core::hash::BuildHasher,
>(
    sort_set: &HashMap<Id, LeanEvent<Id>, S1>,
    power_events: &mut HashMap<Id, LeanEvent<Id>, S2>,
    non_power_events: &mut HashMap<Id, LeanEvent<Id>, S3>,
    version: crate::StateResVersion,
) {
    for (id, ev) in sort_set {
        let is_power = ev.event_type == "m.room.create"
            || ev.event_type == "m.room.power_levels"
            || ev.event_type == "m.room.join_rules"
            || if matches!(
                version,
                crate::StateResVersion::V2_1
                    | crate::StateResVersion::V2_1_1
                    | crate::StateResVersion::V2_2
            ) {
                ev.is_ban_or_kick()
            } else {
                ev.event_type == "m.room.member"
            };

        if is_power {
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
    Id,
    S1: core::hash::BuildHasher + Sync + Send,
    S2: core::hash::BuildHasher + Sync + Send,
>(
    unconflicted_state: BTreeMap<(String, Option<String>), Id>,
    mut conflicted_events: HashMap<Id, LeanEvent<Id>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id>, S2>,
    version: StateResVersion,
) -> BTreeMap<(String, Option<String>), Id>
where
    Id: crate::types::EventId + Sync + Send,
{
    // jscpd:ignore-end
    let original_conflicted_keys =
        crate::resolve::prepare_conflicted_and_keys(&mut conflicted_events, auth_context, version);

    let mut resolved = crate::resolve::get_initial_resolved_state(&unconflicted_state, version);

    let (sort_context, _power_events, non_power_events, mut _local_auth_cache, create_ev) =
        crate::resolve::execute_power_phase(
            &conflicted_events,
            auth_context,
            &original_conflicted_keys,
            &mut resolved,
            version,
        );

    let sort_set = &conflicted_events;

    // Coordinate Projection Phase (Mainline distance mapping)
    let mainline = build_mainline(&resolved, &sort_context);
    let mainline_distances = precompute_mainline_positions(&mainline, &sort_context);
    let mainline_len = mainline.len();

    // Semilattice Fold Phase
    let mut key_winners = HashMap::new();
    compute_lattice_coordinatized_winners(
        &non_power_events,
        &mainline_distances,
        mainline_len,
        &resolved,
        auth_context,
        sort_set,
        version,
        create_ev,
        &mut key_winners,
    );

    // Merge Winners into Final Resolved State
    let mut final_resolved = unconflicted_state;
    for (k, v) in resolved {
        final_resolved.insert(k, v);
    }
    for (k, ev) in key_winners {
        final_resolved.insert(k, ev.event_id.clone());
    }

    drop(conflicted_events);
    final_resolved
}
