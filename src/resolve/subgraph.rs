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

    let (backwards_reachable, missing_auth_events) =
        collect_backwards_reachable(auth_graph, conflicted_set, max_auth_depth);

    // Forward-reachability fast path: build a compact exact accelerator once,
    // then enumerate the forward-reachable set directly (no candidate-list
    // indirection — every node in auth_graph is a candidate here anyway).
    let reachability = RangePrefilterReachability::build(auth_graph);
    let forwards_reachable = collect_forwards_reachable(auth_graph, &reachability, conflicted_set);

    // Intersect and build the final Conflicted Subgraph
    let mut subgraph = HashMap::new();
    for id in intersect_sets(&backwards_reachable, &forwards_reachable) {
        if let Some(event) = auth_graph.get(&id) {
            subgraph.insert(id, event.clone());
        }
    }

    SubgraphResult {
        subgraph,
        missing_auth_events: missing_auth_events.into_iter().collect(),
    }
}

/// Like [`compute_v2_1_conflicted_subgraph_bounded`], but reuses a
/// caller-supplied [`RangePrefilterReachability`] index instead of rebuilding
/// one per call, and returns only the subgraph event IDs.
///
/// `reachability` may be built over a superset of `event_context` (e.g. the
/// whole room). Restricting the forward-reachable set to `event_context`'s keys
/// is equivalent to building an index over `event_context` itself whenever
/// `event_context` is transitively closed under `auth_events` — every auth path
/// between two of its nodes stays inside it — which is exactly the auth-closure
/// shape an incremental fork walk passes here.
#[must_use]
pub fn conflicted_subgraph_ids_with_index<Id, C, S, K>(
    event_context: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    reachability: &RangePrefilterReachability<Id>,
    conflicted_set: &[Id],
    max_auth_depth: Option<usize>,
) -> Vec<Id>
where
    Id: crate::basespec::rezzy_types::EventId + Ord,
    S: core::hash::BuildHasher,
{
    if conflicted_set.is_empty() {
        return Vec::new();
    }
    let (backwards_reachable, _missing_auth_events) =
        collect_backwards_reachable(event_context, conflicted_set, max_auth_depth);
    // The subgraph is backwards ∩ forwards. Rather than enumerate the entire
    // forward closure (which can be the whole room when the conflicted set is
    // near the root) and intersect afterwards, ask which of the
    // backward-reachable ancestors are reachable from the conflicted set. The
    // backward set is frontier-sized, so the accelerator can prune the
    // traversal to it. Exact: same intersection, fewer visited nodes.
    let candidates: Vec<&Id> = backwards_reachable.iter().collect();
    reachability
        .filter_reachable(conflicted_set.iter(), candidates.iter().copied())
        .into_iter()
        .map(|position| (*candidates[position]).clone())
        .collect()
}

/// Ancestors (up the `auth_events` chain) of `conflicted_set`, with an optional
/// depth bound, plus any referenced auth events absent from `events`.
fn collect_backwards_reachable<Id, C, S, K>(
    events: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    conflicted_set: &[Id],
    max_auth_depth: Option<usize>,
) -> (BTreeSet<Id>, BTreeSet<Id>)
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
{
    let mut backwards = BTreeSet::new();
    let mut missing = BTreeSet::new();
    // Each stack entry is (event_id, depth_from_conflicted_set).
    let mut stack: Vec<(Id, usize)> = conflicted_set.iter().map(|s| (s.clone(), 0)).collect();
    while let Some((node, depth)) = stack.pop() {
        if backwards.insert(node.clone()) {
            if let Some(max_depth) = max_auth_depth {
                if depth >= max_depth {
                    continue;
                }
            }
            if let Some(event) = events.get(&node) {
                for auth_id in &event.auth_events {
                    if !events.contains_key(auth_id) {
                        missing.insert(auth_id.clone());
                    }
                    stack.push((auth_id.clone(), depth.saturating_add(1)));
                }
            }
        }
    }
    (backwards, missing)
}

/// Forward-reachable descendants of `conflicted_set` under `reachability`,
/// restricted to events present in `events`.
fn collect_forwards_reachable<Id, C, S, K>(
    events: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    reachability: &RangePrefilterReachability<Id>,
    conflicted_set: &[Id],
) -> BTreeSet<Id>
where
    Id: crate::basespec::rezzy_types::EventId + Ord,
    S: core::hash::BuildHasher,
{
    reachability
        .forward_reachable_ids(conflicted_set.iter())
        .filter(|id| events.contains_key(*id))
        .cloned()
        .collect()
}

/// Intersection of two ID sets, iterating the smaller one.
fn intersect_sets<Id: Ord + Clone>(a: &BTreeSet<Id>, b: &BTreeSet<Id>) -> Vec<Id> {
    let (smaller, larger) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    smaller
        .iter()
        .filter(|id| larger.contains(*id))
        .cloned()
        .collect()
}
