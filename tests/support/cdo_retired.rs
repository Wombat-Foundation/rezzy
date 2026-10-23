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

//! Causal Domination Operator (CDO) — vectorized conflicted-event filter.
//! **Retired from the live path and retained in the test suite as design history.**
//!
//! This module is no longer compiled into `librezzy` or called by resolution:
//! the V2.1.1 pre-filter was removed from `prepare_conflicted_and_keys`
//! because it was unsound. It is kept in `tests/support/cdo_retired.rs` so that
//! historical counterexample regression tests (Anomalies 19 & 20 and the
//! differential harness) can continue exercising it without exposing an unsound
//! operator in the production crate namespace (`F-02.1`).

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::cmp::Ordering;
use core::hash::BuildHasher;
use rezzy::basespec::event_types::{
    MEM_INVITE, MEM_JOIN, M_ROOM_JOIN_RULES, M_ROOM_MEMBER, M_ROOM_POWER_LEVELS,
    M_ROOM_THIRD_PARTY_INVITE,
};
use rezzy::basespec::rezzy_types::{EventContent, EventId, EventLike, LeanEvent};
use rezzy::HashMap;

/// Required power level for `event_type` under a specific `m.room.power_levels`
/// event (`events.{type}` -> `state_default` -> `events_default`).
fn pl_threshold_for_event<Id: EventId, C: EventContent, E: EventLike<Id = Id, Content = C>>(
    pl_event: &E,
    event_type: &str,
    state_key: Option<&str>,
) -> i64 {
    if event_type == M_ROOM_THIRD_PARTY_INVITE {
        return pl_event.get_invite().unwrap_or(0);
    }
    if let Some(pl) = pl_event.get_event_power_level(event_type) {
        return pl;
    }
    if state_key.is_some() {
        return pl_event.get_state_default().unwrap_or(50);
    }
    pl_event.get_events_default().unwrap_or(0)
}

/// Returns `true` if `possible_ancestor_id` is an ancestor of `child_id`.
///
/// Missing event IDs in the lookup context return `false`, except when
/// `child_id == possible_ancestor_id`, which is `true` regardless of
/// context membership.
#[must_use]
pub fn is_ancestor<Id, C: Clone, Q, S: BuildHasher, K>(
    child_id: &Q,
    possible_ancestor_id: &Q,
    context: &HashMap<Id, LeanEvent<Id, C, K>, S>,
) -> bool
where
    Id: EventId + Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
{
    if child_id == possible_ancestor_id {
        return true;
    }
    let Some((actual_child, _)) = context.get_key_value(child_id) else {
        return false;
    };
    let Some((actual_ancestor, _)) = context.get_key_value(possible_ancestor_id) else {
        return false;
    };

    let mut stack = Vec::new();
    stack.push(actual_child);
    let mut visited = BTreeSet::new();
    visited.insert(actual_child);

    while let Some(current) = stack.pop() {
        if current == actual_ancestor {
            return true;
        }
        if let Some(ev) = context.get(current.borrow()) {
            for parent in ev.prev_events.iter().chain(ev.auth_events.iter()) {
                if visited.insert(parent) {
                    stack.push(parent);
                }
            }
        }
    }
    false
}

/// Number of `u64` words per bitmask chunk (8 × 64 = 512 bits on AVX-512).
#[cfg(target_feature = "avx512f")]
const WORDS_PER_CHUNK: usize = 8;

/// Number of `u64` words per bitmask chunk (4 × 64 = 256 bits on AVX2/NEON).
#[cfg(not(target_feature = "avx512f"))]
const WORDS_PER_CHUNK: usize = 4;

fn compute_cdo_bit_masks_chunk<Id, C, S: BuildHasher, K>(
    admin_chunk: &[Id],
    id_to_idx: &HashMap<Id, usize, S>,
    sorted_events: &[(usize, &LeanEvent<Id, C, K>)],
    parents: &[Vec<usize>],
    children: &[Vec<usize>],
    and_masks: &mut [u64],
    desc_masks: &mut [u64],
) where
    Id: EventId,
{
    and_masks.fill(0);
    desc_masks.fill(0);

    for (i, admin_id) in admin_chunk.iter().enumerate() {
        if let Some(&idx) = id_to_idx.get(admin_id) {
            let word = i >> 6;
            let bit = 1u64 << (i & 63);
            let target_idx = idx.saturating_mul(WORDS_PER_CHUNK).saturating_add(word);
            and_masks[target_idx] |= bit;
            desc_masks[target_idx] |= bit;
        }
    }

    // Forward Sweep (Ancestors) - Pure array iteration
    for &(u, _) in sorted_events {
        let u_base = u.saturating_mul(WORDS_PER_CHUNK);
        for &p in &parents[u] {
            let p_base = p.saturating_mul(WORDS_PER_CHUNK);
            for w in 0..WORDS_PER_CHUNK {
                and_masks[u_base.saturating_add(w)] |= and_masks[p_base.saturating_add(w)];
            }
        }
    }

    // Backward Sweep (Descendants) - Pure array iteration
    for &(u, _) in sorted_events.iter().rev() {
        let u_base = u.saturating_mul(WORDS_PER_CHUNK);
        for &c in &children[u] {
            let c_base = c.saturating_mul(WORDS_PER_CHUNK);
            for w in 0..WORDS_PER_CHUNK {
                desc_masks[u_base.saturating_add(w)] |= desc_masks[c_base.saturating_add(w)];
            }
        }
    }
}

fn sort_cdo_events<'a, Id: Ord + Clone, C: Clone, K>(
    events: &[&'a LeanEvent<Id, C, K>],
) -> Vec<&'a LeanEvent<Id, C, K>> {
    let mut sorted = events.to_vec();
    sorted.sort_by(|a, b| {
        let type_priority = |t: &str| match t {
            M_ROOM_POWER_LEVELS => 0,
            M_ROOM_JOIN_RULES => 1,
            _ => 2,
        };

        let cmp_pl = b.power_level.cmp(&a.power_level);
        if cmp_pl != Ordering::Equal {
            return cmp_pl;
        }

        let cmp_type = type_priority(&a.event_type).cmp(&type_priority(&b.event_type));
        if cmp_type != Ordering::Equal {
            return cmp_type;
        }

        let cmp_ts = a.origin_server_ts.cmp(&b.origin_server_ts);
        if cmp_ts != Ordering::Equal {
            return cmp_ts;
        }

        a.event_id.cmp(&b.event_id)
    });
    sorted
}

struct AdjacencyStructures<'a, Id, C, K> {
    id_to_idx: HashMap<Id, usize>,
    sorted_events: Vec<(usize, &'a LeanEvent<Id, C, K>)>,
    parents: Vec<Vec<usize>>,
    children: Vec<Vec<usize>>,
    unordered_ids: BTreeSet<Id>,
}

/// Builds the adjacency lists and rank maps used by the domination sweep.
fn build_adjacency_structures<'a, Id, C: Clone, S1, S2, K>(
    conflicted_events: &'a HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &'a HashMap<Id, LeanEvent<Id, C, K>, S2>,
) -> AdjacencyStructures<'a, Id, C, K>
where
    Id: EventId,
    S1: BuildHasher,
    S2: BuildHasher,
{
    let mut relevant_ids = rezzy::FastSet::default();
    let mut visited = rezzy::FastSet::default();
    let mut queue = alloc::collections::VecDeque::new();
    let event = |id: &Id| conflicted_events.get(id).or_else(|| auth_context.get(id));

    for (id, ev) in conflicted_events {
        relevant_ids.insert(id.clone());
        visited.insert(id.clone());
        for aid in ev.prev_events.iter().chain(ev.auth_events.iter()) {
            if visited.insert(aid.clone()) {
                queue.push_back(aid.clone());
            }
        }
    }

    while let Some(aid) = queue.pop_front() {
        if let Some(aev) = auth_context.get(&aid) {
            relevant_ids.insert(aid.clone());
            for parent_id in aev.prev_events.iter().chain(aev.auth_events.iter()) {
                if visited.insert(parent_id.clone()) {
                    queue.push_back(parent_id.clone());
                }
            }
        }
    }

    let mut in_degree: HashMap<Id, usize> = HashMap::with_capacity(relevant_ids.len());
    let mut children_of: HashMap<Id, Vec<Id>> = HashMap::with_capacity(relevant_ids.len());
    for id in &relevant_ids {
        in_degree.insert(id.clone(), 0);
    }
    for id in &relevant_ids {
        let ev = event(id).expect("relevant event must be present in an input map");
        for parent_id in ev.prev_events.iter().chain(ev.auth_events.iter()) {
            if relevant_ids.contains(parent_id) {
                if let Some(deg) = in_degree.get_mut(id) {
                    *deg = deg.saturating_add(1);
                }
                children_of
                    .entry(parent_id.clone())
                    .or_default()
                    .push(id.clone());
            }
        }
    }

    let mut ready: BTreeSet<Id> = in_degree
        .iter()
        .filter(|&(_, &deg)| deg == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut sorted_ids: Vec<Id> = Vec::with_capacity(relevant_ids.len());
    let mut included: BTreeSet<Id> = BTreeSet::new();
    while let Some(id) = ready.iter().next().cloned() {
        ready.remove(&id);
        included.insert(id.clone());
        if let Some(children) = children_of.get(&id) {
            for child in children {
                if let Some(deg) = in_degree.get_mut(child) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        ready.insert(child.clone());
                    }
                }
            }
        }
        sorted_ids.push(id);
    }

    let mut unordered_ids = BTreeSet::new();
    if sorted_ids.len() < relevant_ids.len() {
        let mut leftover: Vec<Id> = relevant_ids
            .iter()
            .filter(|id| !included.contains(*id))
            .cloned()
            .collect();
        leftover.sort();
        unordered_ids.extend(leftover.iter().cloned());
        sorted_ids.extend(leftover);
    }

    let n = relevant_ids.len();
    let mut id_to_idx = HashMap::with_capacity(n);
    let mut sorted_events = Vec::with_capacity(n);
    for (i, id) in sorted_ids.into_iter().enumerate() {
        let ev = event(&id).expect("relevant event must be present in an input map");
        id_to_idx.insert(id, i);
        sorted_events.push((i, ev));
    }

    let mut parents = alloc::vec![Vec::new(); sorted_events.len()];
    let mut children = alloc::vec![Vec::new(); sorted_events.len()];

    for (child_idx, ev) in &sorted_events {
        for parent_id in ev.prev_events.iter().chain(ev.auth_events.iter()) {
            if let Some(&parent_idx) = id_to_idx.get(parent_id) {
                parents[*child_idx].push(parent_idx);
                children[parent_idx].push(*child_idx);
            }
        }
    }

    AdjacencyStructures {
        id_to_idx,
        sorted_events,
        parents,
        children,
        unordered_ids,
    }
}

struct PrioritizedEvents<Id> {
    admin_actions: Vec<Id>,
    priority_pos: HashMap<Id, usize>,
}

fn prioritize_events<Id, C: EventContent + Clone, S1, K>(
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S1>,
) -> PrioritizedEvents<Id>
where
    Id: EventId,
    S1: BuildHasher,
    K: AsRef<str>,
{
    let admin_events_to_sort: Vec<&LeanEvent<Id, C, K>> = conflicted_events
        .values()
        .filter(|e| e.is_ban_or_kick() || e.is_demotion() || e.is_lockdown())
        .collect();

    let sorted_admin_events = sort_cdo_events(&admin_events_to_sort);
    let mut admin_actions = Vec::with_capacity(sorted_admin_events.len());
    for ev in sorted_admin_events {
        admin_actions.push(ev.event_id.clone());
    }

    let all_sorted = sort_cdo_events(&conflicted_events.values().collect::<Vec<_>>());
    let mut priority_pos = HashMap::with_capacity(all_sorted.len());
    for (pos, ev) in all_sorted.into_iter().enumerate() {
        priority_pos.insert(ev.event_id.clone(), pos);
    }

    PrioritizedEvents {
        admin_actions,
        priority_pos,
    }
}

struct AuthLookups<'a, Id, C, K, S1, S2> {
    conflicted_events: &'a HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &'a HashMap<Id, LeanEvent<Id, C, K>, S2>,
}

fn cited_auth_events<'a, Id, C, K, S1, S2>(
    auth_events: &'a [Id],
    conflicted_events: &'a HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &'a HashMap<Id, LeanEvent<Id, C, K>, S2>,
) -> impl Iterator<Item = &'a LeanEvent<Id, C, K>> + 'a
where
    Id: Eq + core::hash::Hash + 'a,
    S1: BuildHasher + 'a,
    S2: BuildHasher + 'a,
    C: 'a,
    K: 'a,
{
    auth_events
        .iter()
        .filter_map(move |aid| conflicted_events.get(aid).or_else(|| auth_context.get(aid)))
}

fn join_has_prior_authorization<Id, C, K, S1, S2>(
    join_ev: &LeanEvent<Id, C, K>,
    lookups: &AuthLookups<'_, Id, C, K, S1, S2>,
) -> bool
where
    Id: EventId,
    C: EventContent,
    K: AsRef<str>,
    S1: BuildHasher,
    S2: BuildHasher,
{
    cited_auth_events(
        &join_ev.auth_events,
        lookups.conflicted_events,
        lookups.auth_context,
    )
    .any(|ev| {
        let cites_prior_membership = ev.event_type == M_ROOM_MEMBER
            && ev.state_key.as_ref().map(K::as_ref) == Some(join_ev.sender.as_str())
            && matches!(ev.get_membership(), Some(MEM_INVITE | MEM_JOIN));
        let cites_non_lockdown_join_rules = ev.event_type == M_ROOM_JOIN_RULES && !ev.is_lockdown();
        cites_prior_membership || cites_non_lockdown_join_rules
    })
}

fn sender_has_pre_demotion_pl<Id, C, K, S1, S2>(
    target_ev: &LeanEvent<Id, C, K>,
    lookups: &AuthLookups<'_, Id, C, K, S1, S2>,
) -> bool
where
    Id: EventId,
    C: EventContent,
    K: AsRef<str>,
    S1: BuildHasher,
    S2: BuildHasher,
{
    cited_auth_events(
        &target_ev.auth_events,
        lookups.conflicted_events,
        lookups.auth_context,
    )
    .any(|ev| {
        if ev.event_type != M_ROOM_POWER_LEVELS {
            return false;
        }
        let explicit = ev.get_user_power_level(target_ev.sender.as_str());
        let effective = explicit.or_else(|| ev.get_users_default()).unwrap_or(0);

        let required = pl_threshold_for_event(
            ev,
            &target_ev.event_type,
            target_ev
                .state_key
                .as_ref()
                .map(core::convert::AsRef::as_ref),
        );

        effective >= required
    })
}

fn process_direct_domination_chunks<
    Id,
    C: EventContent + Clone,
    S1: BuildHasher,
    S2: BuildHasher,
    K,
>(
    adj: &AdjacencyStructures<'_, Id, C, K>,
    prioritized: &PrioritizedEvents<Id>,
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
) -> BTreeSet<Id>
where
    Id: EventId,
    K: AsRef<str>,
{
    let n = adj.sorted_events.len();
    let mut dropped_ids = BTreeSet::new();

    let mut and_masks = alloc::vec![0u64; n.saturating_mul(WORDS_PER_CHUNK)];
    let mut desc_masks = alloc::vec![0u64; n.saturating_mul(WORDS_PER_CHUNK)];

    let chunk_size = WORDS_PER_CHUNK.saturating_mul(64);

    let mut priority_ordered_ids: Vec<&Id> = prioritized.priority_pos.keys().collect();
    priority_ordered_ids.sort_by_key(|id| prioritized.priority_pos.get(*id));

    for chunk in prioritized.admin_actions.chunks(chunk_size) {
        compute_cdo_bit_masks_chunk(
            chunk,
            &adj.id_to_idx,
            &adj.sorted_events,
            &adj.parents,
            &adj.children,
            &mut and_masks,
            &mut desc_masks,
        );

        let mut chunk_admin_to_pos = HashMap::new();
        for (i, admin_id) in chunk.iter().enumerate() {
            if !dropped_ids.contains(admin_id) && !adj.unordered_ids.contains(admin_id) {
                chunk_admin_to_pos.insert(admin_id, i);
            }
        }

        for event_id in &priority_ordered_ids {
            if dropped_ids.contains(*event_id) || adj.unordered_ids.contains(*event_id) {
                continue;
            }

            if let Some(&ev_idx) = adj.id_to_idx.get(*event_id) {
                for (&admin_id, &orig_idx) in &chunk_admin_to_pos {
                    if dropped_ids.contains(admin_id) {
                        continue;
                    }
                    if let Some(&admin_pos) = prioritized.priority_pos.get(admin_id) {
                        if let Some(&event_pos) = prioritized.priority_pos.get(*event_id) {
                            if admin_pos >= event_pos {
                                continue;
                            }
                        }
                    }

                    let word = orig_idx >> 6;
                    let bit = 1u64 << (orig_idx & 63);

                    let target_idx = ev_idx.saturating_mul(WORDS_PER_CHUNK).saturating_add(word);
                    let is_ancestor_admin = (and_masks[target_idx] & bit) != 0;
                    let is_descendant_admin = (desc_masks[target_idx] & bit) != 0;

                    if !is_ancestor_admin && !is_descendant_admin {
                        if let Some(admin_ev) = conflicted_events.get(admin_id) {
                            if let Some(target_ev) = conflicted_events.get(*event_id) {
                                let dominates = admin_ev.restricts_event(target_ev)
                                    && !(admin_ev.is_lockdown()
                                        && join_has_prior_authorization(
                                            target_ev,
                                            &AuthLookups {
                                                conflicted_events,
                                                auth_context,
                                            },
                                        ))
                                    && !(admin_ev.is_demotion()
                                        && sender_has_pre_demotion_pl(
                                            target_ev,
                                            &AuthLookups {
                                                conflicted_events,
                                                auth_context,
                                            },
                                        ));
                                if dominates {
                                    dropped_ids.insert((*event_id).clone());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    dropped_ids
}

/// Cycle-0 Topological Filter: Vectorized Causal Domination Operator (CDO).
#[must_use]
pub fn apply_cdo_filter<Id, C: EventContent + Clone, S1: BuildHasher, S2: BuildHasher, K>(
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
) -> HashMap<Id, LeanEvent<Id, C, K>>
where
    Id: EventId,
    K: AsRef<str> + Clone,
{
    let adj = build_adjacency_structures(conflicted_events, auth_context);
    let prioritized = prioritize_events(conflicted_events);
    let dropped_ids =
        process_direct_domination_chunks(&adj, &prioritized, conflicted_events, auth_context);

    let mut safe_set = HashMap::new();
    for (id, event) in conflicted_events {
        if !dropped_ids.contains(id) {
            safe_set.insert(id.clone(), event.clone());
        }
    }

    safe_set
}
