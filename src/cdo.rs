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

use crate::types::LeanEvent;
use crate::HashMap;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

#[must_use]
pub fn is_ancestor<S: core::hash::BuildHasher>(
    child_id: &str,
    possible_ancestor_id: &str,
    context: &HashMap<String, LeanEvent, S>,
) -> bool {
    if child_id == possible_ancestor_id {
        return true;
    }
    let Some(child_ev) = context.get(child_id) else {
        return false;
    };
    let Some(and_ev) = context.get(possible_ancestor_id) else {
        return false;
    };

    // Only apply depth pruning if depths are populated (greater than 0).
    // Test events created with Default::default() default to depth 0.
    if child_ev.depth > 0 && and_ev.depth > 0 && and_ev.depth >= child_ev.depth {
        return false;
    }

    let mut stack = Vec::new();
    stack.push(child_id);
    let mut visited = BTreeSet::new();
    visited.insert(child_id);

    while let Some(current) = stack.pop() {
        if current == possible_ancestor_id {
            return true;
        }
        if let Some(ev) = context.get(current) {
            // Prune branches that are already at or below the ancestor's depth (if populated)
            if ev.depth > 0 && and_ev.depth > 0 && ev.depth <= and_ev.depth {
                continue;
            }
            for parent in ev.prev_events.iter().chain(ev.auth_events.iter()) {
                if visited.insert(parent.as_str()) {
                    stack.push(parent.as_str());
                }
            }
        }
    }
    false
}

#[cfg(target_feature = "avx512f")]
const WORDS_PER_CHUNK: usize = 8; // 512 bits (Matches 64-byte cache line)

#[cfg(not(target_feature = "avx512f"))]
const WORDS_PER_CHUNK: usize = 4; // 256 bits (AVX2 / unrolled NEON baseline)

fn compute_cdo_bit_masks_chunk<'a, S: core::hash::BuildHasher>(
    admin_chunk: &[&'a str],
    id_to_idx: &HashMap<&'a str, usize, S>,
    sorted_events: &[(usize, &LeanEvent)],
    parents: &[Vec<usize>],
    children: &[Vec<usize>],
    and_masks: &mut [u64],
    desc_masks: &mut [u64],
) {
    and_masks.fill(0);
    desc_masks.fill(0);

    for (i, &admin_id) in admin_chunk.iter().enumerate() {
        if let Some(&idx) = id_to_idx.get(admin_id) {
            let word = i / 64;
            let bit = 1u64 << (i % 64);
            let pos = idx.wrapping_mul(WORDS_PER_CHUNK).wrapping_add(word);
            and_masks[pos] |= bit;
            desc_masks[pos] |= bit;
        }
    }

    // Forward Sweep (Ancestors) - Pure array iteration
    for &(u, _) in sorted_events {
        let u_base = u.wrapping_mul(WORDS_PER_CHUNK);
        for &p in &parents[u] {
            let p_base = p.wrapping_mul(WORDS_PER_CHUNK);
            for w in 0..WORDS_PER_CHUNK {
                let u_pos = u_base.wrapping_add(w);
                let p_pos = p_base.wrapping_add(w);
                and_masks[u_pos] |= and_masks[p_pos];
            }
        }
    }

    // Backward Sweep (Descendants) - Pure array iteration
    for &(u, _) in sorted_events.iter().rev() {
        let u_base = u.wrapping_mul(WORDS_PER_CHUNK);
        for &c in &children[u] {
            let c_base = c.wrapping_mul(WORDS_PER_CHUNK);
            for w in 0..WORDS_PER_CHUNK {
                let u_pos = u_base.wrapping_add(w);
                let c_pos = c_base.wrapping_add(w);
                desc_masks[u_pos] |= desc_masks[c_pos];
            }
        }
    }
}

fn sort_cdo_events(events: &[&LeanEvent]) -> Vec<LeanEvent> {
    let mut sorted = events.iter().copied().cloned().collect::<Vec<_>>();
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

struct AdjacencyStructures {
    dag_context: HashMap<String, LeanEvent>,
    id_to_idx: HashMap<String, usize>,
    sorted_events: Vec<(usize, LeanEvent)>,
    parents: Vec<Vec<usize>>,
    children: Vec<Vec<usize>>,
}

fn build_adjacency_structures<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
    conflicted_events: &HashMap<String, LeanEvent, S1>,
    auth_context: &HashMap<String, LeanEvent, S2>,
) -> AdjacencyStructures {
    let dag_context = crate::resolve::build_sort_context(conflicted_events, auth_context);

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

struct PrioritizedEvents {
    admin_actions: Vec<String>,
    sorted_events_by_priority: Vec<LeanEvent>,
    priority_pos: HashMap<String, usize>,
}

fn prioritize_events<S1: core::hash::BuildHasher>(
    conflicted_events: &HashMap<String, LeanEvent, S1>,
) -> PrioritizedEvents {
    let admin_events_to_sort: Vec<&LeanEvent> = conflicted_events
        .values()
        .filter(|e| e.is_ban_or_kick() || e.is_demotion() || e.is_lockdown())
        .collect();
    let sorted_admin_events = sort_cdo_events(&admin_events_to_sort);
    let admin_actions: Vec<String> = sorted_admin_events
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

fn process_direct_domination_chunks<S1: core::hash::BuildHasher>(
    adj: &AdjacencyStructures,
    prioritized: &PrioritizedEvents,
    conflicted_events: &HashMap<String, LeanEvent, S1>,
) -> BTreeSet<String> {
    let n = adj.dag_context.len();
    let mut dropped_ids = BTreeSet::new();

    // Allocate a strict O(N * WORDS_PER_CHUNK) matrix once, reused forever across passes
    let mut and_masks = alloc::vec![0u64; n.wrapping_mul(WORDS_PER_CHUNK)];
    let mut desc_masks = alloc::vec![0u64; n.wrapping_mul(WORDS_PER_CHUNK)];

    let chunk_size = WORDS_PER_CHUNK * 64; // 256 actions per pass

    // Helper references to map inputs to compute_cdo_bit_masks_chunk
    let sorted_events_refs: Vec<(usize, &LeanEvent)> = adj
        .sorted_events
        .iter()
        .map(|&(idx, ref ev)| (idx, ev))
        .collect();

    // Convert id_to_idx keys to match the &str representation expected by helper (stable across chunks)
    let id_to_idx_refs: HashMap<&str, usize> = adj
        .id_to_idx
        .iter()
        .map(|(k, &v)| (k.as_str(), v))
        .collect();

    for chunk in prioritized.admin_actions.chunks(chunk_size) {
        let chunk_refs: Vec<&str> = chunk.iter().map(alloc::string::String::as_str).collect();

        compute_cdo_bit_masks_chunk(
            &chunk_refs,
            &id_to_idx_refs,
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
                chunk_admin_to_pos.insert(admin_id.as_str(), i);
            }
        }

        // Check for direct domination against all non-dropped events
        for event in &prioritized.sorted_events_by_priority {
            let event_id = event.event_id.as_str();
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

                    let word = orig_idx / 64;
                    let bit = 1u64 << (orig_idx % 64);

                    let pos = ev_idx.wrapping_mul(WORDS_PER_CHUNK).wrapping_add(word);
                    let is_ancestor_admin = (and_masks[pos] & bit) != 0;
                    let is_descendant_admin = (desc_masks[pos] & bit) != 0;

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

fn propagate_transitive_dependencies<S1: core::hash::BuildHasher>(
    conflicted_events: &HashMap<String, LeanEvent, S1>,
    mut dropped_ids: BTreeSet<String>,
) -> BTreeSet<String> {
    let mut dependents: HashMap<String, Vec<String>> = HashMap::new();
    for (id, event) in conflicted_events {
        for auth_id in &event.auth_events {
            dependents
                .entry(auth_id.clone())
                .or_default()
                .push(id.clone());
        }
    }

    let mut queue: Vec<String> = dropped_ids.iter().cloned().collect();
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

/// Cycle 0 Topological Filter: Vectorized Causal Domination Operator (CDO)
/// Executes strictly on the Conflicted State Subgraph (C).
// jscpd:ignore-start
#[must_use]
pub fn apply_cdo_filter<S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>(
    conflicted_events: &HashMap<String, LeanEvent, S1>,
    auth_context: &HashMap<String, LeanEvent, S2>,
    // jscpd:ignore-end
) -> HashMap<String, LeanEvent> {
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
