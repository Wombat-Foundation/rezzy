//! Conflicted subgraph extraction for MSC4297 (V2.1+).
//!
//! When resolving state under V2.1+, the algorithm needs the **conflicted
//! subgraph** — the intersection of events reachable *backwards* (ancestors)
//! and *forwards* (descendants) from the conflicted set through the auth DAG.
//!
//! This ensures that only events causally relevant to the conflict are
//! considered, preventing unrelated auth chain history from influencing
//! the outcome.

use crate::types::LeanEvent;
use crate::HashMap;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

/// Result of conflicted subgraph computation.
#[derive(Debug, Clone)]
pub struct SubgraphResult {
    /// The computed conflicted subgraph — events at the intersection of
    /// backwards-reachable (ancestors) and forwards-reachable (descendants)
    /// sets from the conflicted event IDs.
    pub subgraph: HashMap<String, LeanEvent>,
    /// Auth event IDs that were referenced but not found in the input graph.
    /// These represent events permanently lost to federation gaps.
    pub missing_auth_events: Vec<String>,
}

/// Computes the V2.1+ conflicted subgraph without a depth bound.
///
/// This is a convenience wrapper around [`compute_v2_1_conflicted_subgraph_bounded`]
/// with `max_auth_depth = None`.
#[must_use]
pub fn compute_v2_1_conflicted_subgraph<S: core::hash::BuildHasher>(
    auth_graph: &HashMap<String, LeanEvent, S>,
    conflicted_set: &[String],
) -> HashMap<String, LeanEvent> {
    compute_v2_1_conflicted_subgraph_bounded(auth_graph, conflicted_set, None).subgraph
}

/// Computes the V2.1+ conflicted subgraph with an optional depth bound.
///
/// The algorithm:
/// 1. **Backwards pass**: BFS up the `auth_events` from the conflicted set,
///    collecting all ancestor event IDs.
/// 2. **Forwards pass**: BFS down through reverse auth edges from the
///    conflicted set, collecting all descendant event IDs.
/// 3. **Intersect**: the subgraph is the set of events in *both* the
///    backwards-reachable and forwards-reachable sets.
///
/// `max_auth_depth`: If `Some(n)`, limits the backwards traversal to `n` hops.
/// This prevents history-flooding `DoS` attacks where a rogue admin generates
/// millions of spoofed events on a dead-end fork.
#[must_use]
pub fn compute_v2_1_conflicted_subgraph_bounded<S: core::hash::BuildHasher>(
    auth_graph: &HashMap<String, LeanEvent, S>,
    conflicted_set: &[String],
    max_auth_depth: Option<usize>,
) -> SubgraphResult {
    if conflicted_set.is_empty() {
        return SubgraphResult {
            subgraph: HashMap::new(),
            missing_auth_events: Vec::new(),
        };
    }

    let mut backwards_reachable = BTreeSet::new();
    let mut forwards_reachable = BTreeSet::new();
    let mut missing_auth_events = BTreeSet::new();

    // Calculate Backwards Reachable (Ancestors up the auth chain)
    // Each entry is (event_id, depth_from_conflicted_set)
    let mut b_stack: Vec<(String, usize)> = conflicted_set.iter().map(|s| (s.clone(), 0)).collect();
    while let Some((node, depth)) = b_stack.pop() {
        if backwards_reachable.insert(node.clone()) {
            if let Some(max_depth) = max_auth_depth {
                if depth >= max_depth {
                    continue;
                }
            }
            if let Some(event) = auth_graph.get(&node) {
                for auth_id in &event.auth_events {
                    if !auth_graph.contains_key(auth_id) {
                        missing_auth_events.insert(auth_id.clone());
                    }
                    b_stack.push((auth_id.clone(), depth.saturating_add(1)));
                }
            }
        }
    }

    // Build Reverse Adjacency for Forwards Search
    let mut children_map: HashMap<String, Vec<String>> = HashMap::new();
    for (id, event) in auth_graph {
        for prev in &event.auth_events {
            children_map
                .entry(prev.clone())
                .or_default()
                .push(id.clone());
        }
    }

    // Calculate Forwards Reachable (Descendants down the auth chain)
    let mut f_stack: Vec<String> = conflicted_set.to_vec();
    while let Some(node) = f_stack.pop() {
        if forwards_reachable.insert(node.clone()) {
            if let Some(children) = children_map.get(&node) {
                for child in children {
                    f_stack.push(child.clone());
                }
            }
        }
    }

    // Intersect and build the final Conflicted Subgraph
    let mut subgraph = HashMap::new();
    let backwards_ids: BTreeSet<String> = backwards_reachable.iter().cloned().collect();
    let forwards_ids: BTreeSet<String> = forwards_reachable.iter().cloned().collect();

    for id in backwards_ids.intersection(&forwards_ids) {
        if let Some(event) = auth_graph.get(id) {
            subgraph.insert(id.clone(), event.clone());
        }
    }

    SubgraphResult {
        subgraph,
        missing_auth_events: missing_auth_events.into_iter().collect(),
    }
}
