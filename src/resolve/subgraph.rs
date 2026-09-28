//! Conflicted subgraph extraction for MSC4297 (V2.1+).
//!
//! When resolving state under V2.1+, the algorithm needs the **conflicted
//! subgraph** — the intersection of events reachable *backwards* (ancestors)
//! and *forwards* (descendants) from the conflicted set through the auth DAG.
//!
//! This ensures that only events causally relevant to the conflict are
//! considered, preventing unrelated auth chain history from influencing
//! the outcome.

use super::RangePrefilterReachability;
use crate::basespec::rezzy_types::LeanEvent;
use crate::HashMap;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

/// Result of conflicted subgraph computation.
#[derive(Debug, Clone)]
pub struct SubgraphResult<Id = String> {
    /// The computed conflicted subgraph — events at the intersection of
    /// backwards-reachable (ancestors) and forwards-reachable (descendants)
    /// sets from the conflicted event IDs.
    pub subgraph: HashMap<Id, LeanEvent<Id>>,
    /// Auth event IDs that were referenced but not found in the input graph.
    /// These represent events permanently lost to federation gaps.
    pub missing_auth_events: Vec<Id>,
}

/// Computes the V2.1+ conflicted subgraph without a depth bound.
///
/// This is a convenience wrapper around [`compute_v2_1_conflicted_subgraph_bounded`]
/// with `max_auth_depth = None`.
#[must_use]
pub fn compute_v2_1_conflicted_subgraph<Id, S>(
    auth_graph: &HashMap<Id, LeanEvent<Id>, S>,
    conflicted_set: &[Id],
) -> HashMap<Id, LeanEvent<Id>>
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
{
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
///
/// # ⚠️ Federating servers MUST agree on the same bound
///
/// A non-`None` bound truncates the backwards pass: ancestors more than `n`
/// hops from the conflicted set are silently excluded from
/// [`SubgraphResult::subgraph`]. If two homeservers federating the same room
/// resolve with *different* bounds, a truncated ancestor that would have
/// decided a conflict on one server is absent on the other, so the two can
/// compute **divergent resolved state and silently partition the room** —
/// the depth-exceeded truncation is not guaranteed to terminate identically
/// for every participant.
///
/// Because of this, any `Some(n)` must be a **federation-agreed protocol
/// constant**, not a per-deployment tuning knob: every server in the room
/// must use the identical value, and it must be set so generously that it can
/// never truncate a legitimate (non-adversarial) room history. Contrast this
/// with `HAMT_MAX_DEPTH` elsewhere in the crate, which is a fixed crate
/// constant every build shares automatically.
///
/// In practice, no caller inside this crate passes a real bound: both
/// production entry points go through [`compute_v2_1_conflicted_subgraph`]
/// (always `None`). Prefer that unless you have specifically audited the
/// cross-server agreement requirement above.
#[must_use]
pub fn compute_v2_1_conflicted_subgraph_bounded<Id, S>(
    auth_graph: &HashMap<Id, LeanEvent<Id>, S>,
    conflicted_set: &[Id],
    max_auth_depth: Option<usize>,
) -> SubgraphResult<Id>
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
{
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
    let mut b_stack: Vec<(Id, usize)> = conflicted_set.iter().map(|s| (s.clone(), 0)).collect();
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

    // Forward-reachability fast path: build a compact exact accelerator once,
    // then enumerate the forward-reachable set directly (no candidate-list
    // indirection — every node in auth_graph is a candidate here anyway).
    let reachability = RangePrefilterReachability::build(auth_graph);
    for id in reachability.forward_reachable_ids(conflicted_set.iter()) {
        forwards_reachable.insert(id.clone());
    }

    // Intersect and build the final Conflicted Subgraph
    let mut subgraph = HashMap::new();
    let (smaller, larger) = if backwards_reachable.len() <= forwards_reachable.len() {
        (&backwards_reachable, &forwards_reachable)
    } else {
        (&forwards_reachable, &backwards_reachable)
    };
    for id in smaller {
        if !larger.contains(id) {
            continue;
        }
        let Some(event) = auth_graph.get(id) else {
            continue;
        };
        subgraph.insert(id.clone(), event.clone());
    }

    SubgraphResult {
        subgraph,
        missing_auth_events: missing_auth_events.into_iter().collect(),
    }
}
