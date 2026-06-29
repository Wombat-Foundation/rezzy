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

use crate::types::LeanEvent;
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
pub fn is_ancestor<Id, C: Clone, Q, S: core::hash::BuildHasher>(
    child_id: &Q,
    possible_ancestor_id: &Q,
    context: &HashMap<Id, LeanEvent<Id, C>, S>,
) -> bool
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::borrow::Borrow<Q>,
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

    let child_ev = context.get(actual_child.borrow()).unwrap();
    let and_ev = context.get(actual_ancestor.borrow()).unwrap();

    // Only apply depth pruning if depths are populated (greater than 0).
    // Test events created with Default::default() default to depth 0.
    if child_ev.depth > 0 && and_ev.depth > 0 && and_ev.depth >= child_ev.depth {
        return false;
    }

    let mut stack = Vec::new();
    stack.push(actual_child);
    let mut visited = BTreeSet::new();
    visited.insert(actual_child);

    while let Some(current) = stack.pop() {
        if current == actual_ancestor {
            return true;
        }
        if let Some(ev) = context.get(current.borrow()) {
            // Prune branches that are already at or below the ancestor's depth (if populated)
            if ev.depth > 0 && and_ev.depth > 0 && ev.depth <= and_ev.depth {
                continue;
            }
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

fn compute_cdo_bit_masks_chunk<Id, C: Clone, S: core::hash::BuildHasher>(
    admin_chunk: &[Id],
    id_to_idx: &HashMap<Id, usize, S>,
    sorted_events: &[(usize, &LeanEvent<Id, C>)],
    parents: &[Vec<usize>],
    children: &[Vec<usize>],
    and_masks: &mut [u64],
    desc_masks: &mut [u64],
) where
    Id: Clone + Eq + core::hash::Hash,
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

fn sort_cdo_events<Id: Ord + Clone, C: Clone>(
    events: &[&LeanEvent<Id, C>],
) -> Vec<LeanEvent<Id, C>> {
    let mut sorted = events.iter().map(|&ev| (*ev).clone()).collect::<Vec<_>>();
    sorted.sort_by(|a, b| {
        let type_priority = |t: &str| match t {
            "m.room.power_levels" => 0,
            "m.room.join_rules" => 1,
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

struct AdjacencyStructures<Id, C> {
    dag_context: HashMap<Id, LeanEvent<Id, C>>,
    id_to_idx: HashMap<Id, usize>,
    sorted_events: Vec<(usize, LeanEvent<Id, C>)>,
    parents: Vec<Vec<usize>>,
    children: Vec<Vec<usize>>,
}

fn build_adjacency_structures<
    Id,
    C: Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    conflicted_events: &HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
) -> AdjacencyStructures<Id, C>
where
    Id: Clone + Eq + core::hash::Hash + Ord,
{
    let mut dag_context =
        HashMap::with_capacity(auth_context.len().saturating_add(conflicted_events.len()));
    for (k, v) in auth_context.iter().chain(conflicted_events.iter()) {
        dag_context.insert(k.clone(), v.clone());
    }

    let n = dag_context.len();
    let mut id_to_idx = HashMap::with_capacity(n);
    let mut sorted_events = Vec::with_capacity(n);

    for (id, ev) in &dag_context {
        let idx = id_to_idx.len();
        id_to_idx.insert(id.clone(), idx);
        sorted_events.push((idx, ev.clone()));
    }
    sorted_events.sort_unstable_by(|(_, a), (_, b)| {
        a.depth
            .cmp(&b.depth)
            .then_with(|| a.event_id.cmp(&b.event_id))
    });

    let mut parents = alloc::vec![Vec::new(); n];
    let mut children = alloc::vec![Vec::new(); n];
    for &(u, ref ev) in &sorted_events {
        for p_id in ev.prev_events.iter().chain(ev.auth_events.iter()) {
            if let Some(&v) = id_to_idx.get(p_id) {
                parents[u].push(v);
                children[v].push(u);
            }
        }
    }

    AdjacencyStructures {
        dag_context,
        id_to_idx,
        sorted_events,
        parents,
        children,
    }
}

struct PrioritizedEvents<Id, C> {
    admin_actions: Vec<Id>,
    sorted_events_by_priority: Vec<LeanEvent<Id, C>>,
    priority_pos: HashMap<Id, usize>,
}

fn prioritize_events<Id, C: crate::types::EventContent + Clone, S1: core::hash::BuildHasher>(
    conflicted_events: &HashMap<Id, LeanEvent<Id, C>, S1>,
) -> PrioritizedEvents<Id, C>
where
    Id: Clone + Eq + core::hash::Hash + Ord,
{
    let admin_events_to_sort: Vec<&LeanEvent<Id, C>> = conflicted_events
        .values()
        .filter(|e| e.is_ban_or_kick() || e.is_demotion() || e.is_lockdown())
        .collect();
    let sorted_admin_events = sort_cdo_events(&admin_events_to_sort);
    let admin_actions: Vec<Id> = sorted_admin_events
        .iter()
        .map(|e| e.event_id.clone())
        .collect();

    let sorted_events_by_priority =
        sort_cdo_events(&conflicted_events.values().collect::<Vec<_>>());

    let mut priority_pos = HashMap::with_capacity(sorted_events_by_priority.len());
    for (pos, ev) in sorted_events_by_priority.iter().enumerate() {
        priority_pos.insert(ev.event_id.clone(), pos);
    }

    PrioritizedEvents {
        admin_actions,
        sorted_events_by_priority,
        priority_pos,
    }
}

fn process_direct_domination_chunks<
    Id,
    C: crate::types::EventContent + Clone,
    S1: core::hash::BuildHasher,
>(
    adj: &AdjacencyStructures<Id, C>,
    prioritized: &PrioritizedEvents<Id, C>,
    conflicted_events: &HashMap<Id, LeanEvent<Id, C>, S1>,
) -> BTreeSet<Id>
where
    Id: Clone + Eq + core::hash::Hash + Ord,
{
    let n = adj.dag_context.len();
    let mut dropped_ids = BTreeSet::new();

    // Allocate a strict O(N * WORDS_PER_CHUNK) matrix once, reused forever across passes
    let mut and_masks = alloc::vec![0u64; n.saturating_mul(WORDS_PER_CHUNK)];
    let mut desc_masks = alloc::vec![0u64; n.saturating_mul(WORDS_PER_CHUNK)];

    let chunk_size = WORDS_PER_CHUNK.saturating_mul(64);

    // Helper references to map inputs to compute_cdo_bit_masks_chunk
    let sorted_events_refs: Vec<(usize, &LeanEvent<Id, C>)> = adj
        .sorted_events
        .iter()
        .map(|&(idx, ref ev)| (idx, ev))
        .collect();

    for chunk in prioritized.admin_actions.chunks(chunk_size) {
        compute_cdo_bit_masks_chunk(
            chunk,
            &adj.id_to_idx,
            &sorted_events_refs,
            &adj.parents,
            &adj.children,
            &mut and_masks,
            &mut desc_masks,
        );

        // Build a map of active admin actions in this chunk to their relative index within the chunk
        let mut chunk_admin_to_pos = HashMap::new();
        for (i, admin_id) in chunk.iter().enumerate() {
            if !dropped_ids.contains(admin_id) {
                chunk_admin_to_pos.insert(admin_id, i);
            }
        }

        // Check for direct domination against all non-dropped events
        for event in &prioritized.sorted_events_by_priority {
            let event_id = &event.event_id;
            if dropped_ids.contains(event_id) {
                continue;
            }

            if let Some(&ev_idx) = adj.id_to_idx.get(event_id) {
                for (&admin_id, &orig_idx) in &chunk_admin_to_pos {
                    if dropped_ids.contains(admin_id) {
                        continue;
                    }
                    // Only higher-priority admin actions (occurring earlier in the sorted list) can dominate
                    if let Some(&admin_pos) = prioritized.priority_pos.get(admin_id) {
                        if let Some(&event_pos) = prioritized.priority_pos.get(event_id) {
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
                            if admin_ev.restricts_event(event) {
                                dropped_ids.insert(event.event_id.clone());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    dropped_ids
}

fn propagate_transitive_dependencies<Id, C: Clone, S1: core::hash::BuildHasher>(
    conflicted_events: &HashMap<Id, LeanEvent<Id, C>, S1>,
    mut dropped_ids: BTreeSet<Id>,
) -> BTreeSet<Id>
where
    Id: Clone + Eq + core::hash::Hash + Ord,
{
    let mut dependents: HashMap<Id, Vec<Id>> = HashMap::new();
    for (id, event) in conflicted_events {
        for auth_id in &event.auth_events {
            dependents
                .entry(auth_id.clone())
                .or_default()
                .push(id.clone());
        }
    }

    let mut queue: Vec<Id> = dropped_ids.iter().cloned().collect();
    while let Some(current_dropped) = queue.pop() {
        if let Some(children) = dependents.get(&current_dropped) {
            for child in children {
                if !dropped_ids.contains(child) {
                    dropped_ids.insert(child.clone());
                    queue.push(child.clone());
                }
            }
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
    C: crate::types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    conflicted_events: &HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
) -> HashMap<Id, LeanEvent<Id, C>>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
{
    // jscpd:ignore-end
    let adj = build_adjacency_structures(conflicted_events, auth_context);
    let prioritized = prioritize_events(conflicted_events);
    let dropped_ids = process_direct_domination_chunks(&adj, &prioritized, conflicted_events);
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
