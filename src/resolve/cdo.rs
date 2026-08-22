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

//! Causal Domination Operator (CDO) — vectorized pre-filter for conflicted events.
//!
//! The CDO is a V2.1.1 optimization that runs *before* the main resolution
//! algorithm. It identifies conflicted events that are **causally dominated**
//! by a higher-priority administrative action (ban, kick, PL demotion, or
//! join-rules lockdown) and removes them from the conflicted set entirely.
//!
//! An event is "causally dominated" if:
//! 1. A higher-priority admin action *restricts* it (see [`LeanEvent::restricts_event`]).
//! 2. The admin action is **not** an ancestor or descendant of the event
//!    (i.e. they are on independent causal branches).
//!
//! ## Implementation
//!
//! Ancestor/descendant relationships are computed via SWAR (SIMD-within-a-register)
//! bitmask sweeps over a topologically-sorted event array. The chunk size is
//! auto-selected at compile time: 512 bits on AVX-512, 256 bits otherwise.
//!
//! ## Soundness: domination must never diverge from full resolution
//!
//! An independent-branch admin action must never dominate a target event
//! that already carries its own, separate authorization for the state the
//! admin action would otherwise contest — see `join_has_prior_authorization`
//! and `sender_has_pre_demotion_pl` below, both fixes for cases where the
//! `restricts_event`/`restricts_sender` structural check fired without
//! verifying the target was actually unauthorized. Two related classes of
//! this were audited and found *not* to need a fix:
//! - **`is_ban_or_kick()` domination**: unlike `is_lockdown()`/`is_demotion()`,
//!   its structural check (`state_key == sender`) is already exact, not a
//!   coarse over-approximation, so it did not reproduce a divergence from
//!   full V2.1 resolution in either of two structurally distinct topologies
//!   tested (see `test_anomaly_20_concurrent_ban_still_holds` — `MEM_BAN`,
//!   type-priority tiebreak — and `test_anomaly_21_concurrent_kick_still_holds`
//!   — `MEM_LEAVE`-as-kick, real differing `power_level`-driven priority —
//!   both in `tests/test_critique.rs`).
//! - **Restricted/knock-restricted `join_rules`**: `is_lockdown()` only fires
//!   for `join_rule == "invite"`, so those never enter `admin_actions` at
//!   all and always fall through to full resolution, which already models
//!   `join_authorised_via_users_server` correctly.

use crate::basespec::event_types::{
    MEM_INVITE, MEM_JOIN, M_ROOM_JOIN_RULES, M_ROOM_MEMBER, M_ROOM_POWER_LEVELS,
};
use crate::basespec::rezzy_types::LeanEvent;
use crate::HashMap;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::cmp::Ordering;

/// Returns `true` if `possible_ancestor_id` is an ancestor of `child_id`.
///
/// # Panics
///
/// Will panic if `child_id` or `possible_ancestor_id` are found in the context's key-value entries
/// but their corresponding values are missing from the context map (violating graph integrity).
#[must_use]
pub fn is_ancestor<Id, C: Clone, Q, S: core::hash::BuildHasher, K>(
    child_id: &Q,
    possible_ancestor_id: &Q,
    context: &HashMap<Id, LeanEvent<Id, C, K>, S>,
) -> bool
where
    Id: crate::basespec::rezzy_types::EventId + core::borrow::Borrow<Q>,
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

    // No pruning on `depth` here: it is an author-supplied field on the
    // event, not verified against the graph before this runs, so a forged
    // depth (e.g. an ancestor claiming a depth >= the child's) could make a
    // real ancestor relationship come back `false`. Correctness over the
    // pruning shortcut — walk the actual prev_events/auth_events edges.
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

#[cfg(target_feature = "avx512f")]
/// Number of `u64` words per bitmask chunk (8 × 64 = 512 bits on AVX-512).
const WORDS_PER_CHUNK: usize = 8;

#[cfg(not(target_feature = "avx512f"))]
/// Number of `u64` words per bitmask chunk (4 × 64 = 256 bits on AVX2/NEON).
const WORDS_PER_CHUNK: usize = 4;

fn compute_cdo_bit_masks_chunk<Id, C, S: core::hash::BuildHasher, K>(
    admin_chunk: &[Id],
    id_to_idx: &HashMap<Id, usize, S>,
    sorted_events: &[(usize, &LeanEvent<Id, C, K>)],
    parents: &[Vec<usize>],
    children: &[Vec<usize>],
    and_masks: &mut [u64],
    desc_masks: &mut [u64],
) where
    Id: crate::basespec::rezzy_types::EventId,
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
    /// IDs appended after Kahn's algorithm failed to reach in-degree zero
    /// (i.e. the input contained a cycle). These have no true topological
    /// position, so the SWAR ancestor/descendant bitmasks are unreliable for
    /// them; domination decisions must not be made from their ordering.
    unordered_ids: BTreeSet<Id>,
}

fn build_adjacency_structures<'a, Id, C: Clone, S1, S2, K>(
    conflicted_events: &'a HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &'a HashMap<Id, LeanEvent<Id, C, K>, S2>,
) -> AdjacencyStructures<'a, Id, C, K>
where
    Id: crate::basespec::rezzy_types::EventId,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
{
    let mut relevant_events = HashMap::new();
    let mut visited = BTreeSet::new();
    let mut queue = alloc::collections::VecDeque::new();

    for (id, ev) in conflicted_events {
        relevant_events.insert(id.clone(), ev);
        visited.insert(id.clone());
        for aid in ev.prev_events.iter().chain(ev.auth_events.iter()) {
            if visited.insert(aid.clone()) {
                queue.push_back(aid.clone());
            }
        }
    }

    while let Some(aid) = queue.pop_front() {
        if let Some(aev) = auth_context.get(&aid) {
            relevant_events.insert(aid.clone(), aev);
            for parent_id in aev.prev_events.iter().chain(aev.auth_events.iter()) {
                if visited.insert(parent_id.clone()) {
                    queue.push_back(parent_id.clone());
                }
            }
        }
    }

    // Topologically order `relevant_events` via Kahn's algorithm over the
    // actual prev_events/auth_events edges, so the SWAR sweeps below
    // (`compute_cdo_bit_masks_chunk`) can rely on every parent sitting at a
    // strictly lower array index than every child. Do not sort by
    // `event.depth` here: `depth` is an author-supplied field that is not
    // verified against the graph before this filter runs, so a forged depth
    // can desynchronize array order from true causal order. The forward and
    // backward sweeps are each a single O(N) pass that accumulates
    // transitive ancestor/descendant bitmasks assuming strict topological
    // order; a desynchronized order corrupts those bitmasks silently
    // instead of erroring.
    let mut in_degree: HashMap<Id, usize> = HashMap::with_capacity(relevant_events.len());
    let mut children_of: HashMap<Id, Vec<Id>> = HashMap::with_capacity(relevant_events.len());
    for id in relevant_events.keys() {
        in_degree.insert(id.clone(), 0);
    }
    for (id, &ev) in &relevant_events {
        for parent_id in ev.prev_events.iter().chain(ev.auth_events.iter()) {
            if relevant_events.contains_key(parent_id) {
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

    // Deterministic Kahn's algorithm: always expand the lexicographically
    // smallest ready id first, so output order stays reproducible across
    // identical inputs (matching the previous sort's event_id tie-break).
    let mut ready: BTreeSet<Id> = in_degree
        .iter()
        .filter(|&(_, &deg)| deg == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut sorted_ids: Vec<Id> = Vec::with_capacity(relevant_events.len());
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
    // Defensive fallback: a genuine event DAG cannot contain a cycle, but if
    // referential integrity is somehow violated (e.g. a maliciously crafted
    // cycle) and some ids never reach in-degree zero, append them in a
    // deterministic order rather than silently dropping them from the sweep.
    // Track them as `unordered_ids`: their array position is not a real
    // topological order, so the domination sweeps must not draw conclusions
    // from it (they treat them as neither dominator nor dominatee).
    let mut unordered_ids = BTreeSet::new();
    if sorted_ids.len() < relevant_events.len() {
        let mut leftover: Vec<Id> = relevant_events
            .keys()
            .filter(|id| !included.contains(*id))
            .cloned()
            .collect();
        leftover.sort();
        unordered_ids.extend(leftover.iter().cloned());
        sorted_ids.extend(leftover);
    }

    let n = relevant_events.len();
    let mut id_to_idx = HashMap::with_capacity(n);
    let mut sorted_events = Vec::with_capacity(n);
    for (i, id) in sorted_ids.into_iter().enumerate() {
        let ev = relevant_events[&id];
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

fn prioritize_events<Id, C: crate::basespec::rezzy_types::EventContent + Clone, S1, K>(
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S1>,
) -> PrioritizedEvents<Id>
where
    Id: crate::basespec::rezzy_types::EventId,
    S1: core::hash::BuildHasher,
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

/// Returns `true` if `join_ev` (an `m.room.member` join) already carries its
/// own authorization, independent of whatever `join_rules` state exists on
/// an unrelated causal branch. Either of:
/// - its `auth_events` cite a prior membership event for the same sender
///   with membership `invite` or `join` (a returning/already-invited
///   member), or
/// - its `auth_events` cite a `m.room.join_rules` event that was *not*
///   itself a lockdown (e.g. `public`) — the `join_rules` state the join
///   was actually authorized against.
///
/// A CDO join-rules lockdown must not dominate a join that already has
/// either of these: per the Matrix auth rules, a join authorized against a
/// non-invite-only state (or a prior invite) remains valid even if a
/// join-rules lockdown was concurrently, and causally independently,
/// applied on another branch. Without this check, `restricts_event`'s
/// lockdown case would drop *any* structurally-matching join regardless of
/// whether the joiner actually lacked authorization — see
/// `test_anomaly_17_sliced_dag_membership_desync` (an invited join dropped
/// by an unrelated lockdown) and `test_anomaly_06b_mod_membership_evaporation`
/// (a join into a still-public room dropped by a later, independent-branch
/// lockdown, cascading to drop everything auth'd through that join).
fn join_has_prior_authorization<Id, C, K, S1, S2>(
    join_ev: &LeanEvent<Id, C, K>,
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
) -> bool
where
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    K: AsRef<str>,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
{
    join_ev.auth_events.iter().any(|aid| {
        conflicted_events
            .get(aid)
            .or_else(|| auth_context.get(aid))
            .is_some_and(|ev| {
                let cites_prior_membership = ev.event_type == M_ROOM_MEMBER
                    && ev.state_key.as_ref().map(K::as_ref) == Some(join_ev.sender.as_str())
                    && matches!(ev.get_membership(), Some(MEM_INVITE | MEM_JOIN));
                let cites_non_lockdown_join_rules =
                    ev.event_type == M_ROOM_JOIN_RULES && !ev.is_lockdown();
                cites_prior_membership || cites_non_lockdown_join_rules
            })
    })
}

/// Returns `true` if `target_ev` cites, in its own `auth_events`, a
/// `power_levels` event under which its sender was *not* at PL 0.
///
/// `is_demotion()` treats *any* `m.room.power_levels` event as a demotion
/// (it does not check whether anyone was actually demoted), so
/// `restricts_sender`'s domination check fires for every PL event on an
/// independent branch, regardless of whether the target's own authorization
/// predates it. This mirrors `join_has_prior_authorization`: an independent
/// branch's demotion must not retroactively invalidate an action the sender
/// took while validly empowered, if that empowerment is what the action's
/// own `auth_events` actually cite. See
/// `test_cdo_demotion_does_not_dominate_pre_demotion_authorized_action`.
fn sender_has_pre_demotion_pl<Id, C, K, S1, S2>(
    target_ev: &LeanEvent<Id, C, K>,
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
) -> bool
where
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    K: AsRef<str>,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
{
    target_ev.auth_events.iter().any(|aid| {
        conflicted_events
            .get(aid)
            .or_else(|| auth_context.get(aid))
            .is_some_and(|ev| {
                if ev.event_type != M_ROOM_POWER_LEVELS {
                    return false;
                }
                // Effective PL: explicit `users[sender]` wins; else
                // `users_default`; else 0. Only a strictly-positive level
                // counts as a pre-demotion grant -- an absent entry falls
                // through to `users_default` (usually 0), not empowerment.
                let explicit = ev.get_user_power_level(target_ev.sender.as_str());
                let effective = explicit.or_else(|| ev.get_users_default()).unwrap_or(0);
                effective > 0
            })
    })
}

fn process_direct_domination_chunks<
    Id,
    C: crate::basespec::rezzy_types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    K,
>(
    adj: &AdjacencyStructures<'_, Id, C, K>,
    prioritized: &PrioritizedEvents<Id>,
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
) -> BTreeSet<Id>
where
    Id: crate::basespec::rezzy_types::EventId,
    K: AsRef<str>,
{
    let n = adj.sorted_events.len();
    let mut dropped_ids = BTreeSet::new();

    // Allocate a strict O(N * WORDS_PER_CHUNK) matrix once, reused forever across passes
    let mut and_masks = alloc::vec![0u64; n.saturating_mul(WORDS_PER_CHUNK)];
    let mut desc_masks = alloc::vec![0u64; n.saturating_mul(WORDS_PER_CHUNK)];

    let chunk_size = WORDS_PER_CHUNK.saturating_mul(64);

    // Collect priority-sorted event IDs for iteration (positions only, no cloning events)
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

        // Build a map of active admin actions in this chunk to their relative index within the chunk
        let mut chunk_admin_to_pos = HashMap::new();
        for (i, admin_id) in chunk.iter().enumerate() {
            if !dropped_ids.contains(admin_id) && !adj.unordered_ids.contains(admin_id) {
                chunk_admin_to_pos.insert(admin_id, i);
            }
        }

        // Check for direct domination against all non-dropped events
        for event_id in &priority_ordered_ids {
            if dropped_ids.contains(*event_id) || adj.unordered_ids.contains(*event_id) {
                continue;
            }

            if let Some(&ev_idx) = adj.id_to_idx.get(*event_id) {
                for (&admin_id, &orig_idx) in &chunk_admin_to_pos {
                    if dropped_ids.contains(admin_id) {
                        continue;
                    }
                    // Only higher-priority admin actions (occurring earlier in the sorted list) can dominate
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

                    // Fast-path bitwise check first!
                    if !is_ancestor_admin && !is_descendant_admin {
                        if let Some(admin_ev) = conflicted_events.get(admin_id) {
                            if let Some(target_ev) = conflicted_events.get(*event_id) {
                                let dominates = admin_ev.restricts_event(target_ev)
                                    && !(admin_ev.is_lockdown()
                                        && join_has_prior_authorization(
                                            target_ev,
                                            conflicted_events,
                                            auth_context,
                                        ))
                                    && !(admin_ev.is_demotion()
                                        && sender_has_pre_demotion_pl(
                                            target_ev,
                                            conflicted_events,
                                            auth_context,
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

/// Transitively propagate a drop to an event only when the drop truly
/// invalidates it: an event `F` is dropped only if **all** of its
/// `auth_events` are themselves dropped. Citing a dropped event is a
/// *replacement*, not a drop, when `F` has a surviving auth event (an
/// unconflicted event, or a kept candidate) it could be authorized through —
/// dropping `F` then would over-drop an event full resolution might accept.
/// Only when no auth path survives is the drop genuinely propagated.
///
/// This is a fixpoint: dropping one event can push a dependent over the
/// all-auth-dropped threshold on the next pass.
fn propagate_transitive_dependencies<Id, C: Clone, S1: core::hash::BuildHasher, K>(
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S1>,
    mut dropped_ids: BTreeSet<Id>,
) -> BTreeSet<Id>
where
    Id: crate::basespec::rezzy_types::EventId,
{
    loop {
        let mut changed = false;
        for (id, event) in conflicted_events {
            if dropped_ids.contains(id) {
                continue;
            }
            // An event with no auth_events is authorized by default and must
            // never be dropped. Otherwise it is dropped only when every auth
            // path it cites is gone.
            if !event.auth_events.is_empty()
                && event
                    .auth_events
                    .iter()
                    .all(|auth_id| dropped_ids.contains(auth_id))
            {
                dropped_ids.insert(id.clone());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    dropped_ids
}

/// Cycle-0 Topological Filter: Vectorized Causal Domination Operator (CDO).
///
/// Executes strictly on the conflicted state subgraph. Returns the **safe set**
/// of events that survived CDO filtering — i.e. events that are *not* causally
/// dominated by any higher-priority administrative action.
///
/// The pipeline is:
/// 1. **Build adjacency** — merge conflicted + auth context into a single DAG.
/// 2. **Prioritize** — identify admin actions (bans, kicks, demotions, lockdowns)
///    and sort all events by priority.
/// 3. **Chunk-process** — compute ancestor/descendant bitmasks in SWAR chunks
///    and mark dominated events.
/// 4. **Propagate** — transitively drop any event whose auth dependency was dropped.
// jscpd:ignore-start
#[must_use]
pub fn apply_cdo_filter<
    Id,
    C: crate::basespec::rezzy_types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    K,
>(
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
) -> HashMap<Id, LeanEvent<Id, C, K>>
where
    Id: crate::basespec::rezzy_types::EventId,
    K: AsRef<str> + Clone,
{
    // jscpd:ignore-end
    let adj = build_adjacency_structures(conflicted_events, auth_context);
    let prioritized = prioritize_events(conflicted_events);
    let dropped_ids =
        process_direct_domination_chunks(&adj, &prioritized, conflicted_events, auth_context);
    let final_dropped_ids = propagate_transitive_dependencies(conflicted_events, dropped_ids);

    // Return strictly the transitively safe set
    let mut safe_set = HashMap::new();
    for (id, event) in conflicted_events {
        if !final_dropped_ids.contains(id) {
            safe_set.insert(id.clone(), event.clone());
        }
    }

    safe_set
}
