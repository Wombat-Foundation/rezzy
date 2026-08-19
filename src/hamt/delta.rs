use std::{fmt, hash::Hash, sync::Arc, vec::Vec};

use crate::state::LtHash;

use super::{HamtNode, NodeRef, StructuralHash, HAMT_MAX_DEPTH};

pub type Delta<K, V> = Vec<(K, V)>;
pub type DeltaResult<K, V, E> = Result<(Delta<K, V>, Delta<K, V>), E>;

/// Isolates the delta (added/removed items) between two HAMT tries in O(|Delta|
/// * log32 N) time. Uses the `LtHash` lattice to quickly short-circuit if the
///   tries are convergently identical.
///
/// # Errors
/// Returns [`HamtTraversalError::Resolve`] if the `resolver` fails to resolve a
/// lazy node, or [`HamtTraversalError::MaxDepthExceeded`] if the diff recurses
/// past the deepest depth a legitimately-built HAMT can have.
pub fn isolate_delta<K, V, F, E>(
    root_a: &Arc<HamtNode<K, V>>,
    lattice_a: &LtHash,
    root_b: &Arc<HamtNode<K, V>>,
    lattice_b: &LtHash,
    resolver: &mut F,
) -> DeltaResult<K, V, HamtTraversalError<E>>
where
    K: Hash + Clone + Eq,
    V: Hash + Clone + Eq,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    // Short-circuit only when both the lattice and the root structural hashes
    // match. A lattice collision alone must not suppress a real structural
    // diff.
    if lattice_a == lattice_b && root_a.structural_hash == root_b.structural_hash {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut added = Vec::new();
    let mut removed = Vec::new();

    // Begin recursive diffing
    diff_nodes(root_a, root_b, &mut added, &mut removed, resolver, 0)?;

    Ok((added, removed))
}

/// Isolates the delta (added/removed items) between two HAMT root nodes directly,
/// short-circuiting on identical structural hashes without requiring `LtHash` references.
///
/// # Errors
/// Returns [`HamtTraversalError::Resolve`] if the `resolver` fails to resolve a
/// lazy node, or [`HamtTraversalError::MaxDepthExceeded`] if the diff recurses
/// past the deepest depth a legitimately-built HAMT can have.
pub fn diff_hamt_nodes<K, V, F, E>(
    root_a: &Arc<HamtNode<K, V>>,
    root_b: &Arc<HamtNode<K, V>>,
    resolver: &mut F,
) -> DeltaResult<K, V, HamtTraversalError<E>>
where
    K: Hash + Clone + Eq,
    V: Hash + Clone + Eq,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    if root_a.structural_hash == root_b.structural_hash {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut added = Vec::new();
    let mut removed = Vec::new();

    diff_nodes(root_a, root_b, &mut added, &mut removed, resolver, 0)?;

    Ok((added, removed))
}

fn diff_nodes<K, V, F, E>(
    node_a: &Arc<HamtNode<K, V>>,
    node_b: &Arc<HamtNode<K, V>>,
    added: &mut Vec<(K, V)>,
    removed: &mut Vec<(K, V)>,
    resolver: &mut F,
    depth: usize,
) -> Result<(), HamtTraversalError<E>>
where
    K: Hash + Clone + Eq,
    V: Hash + Clone + Eq,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    // Pointer equality check (fastest path for structurally shared nodes)
    if Arc::ptr_eq(node_a, node_b) {
        return Ok(());
    }

    // Structural hash check (fast path across process/storage boundaries)
    if node_a.structural_hash == node_b.structural_hash {
        return Ok(());
    }

    if depth >= HAMT_MAX_DEPTH {
        return Err(HamtTraversalError::MaxDepthExceeded { depth });
    }
    let next_depth = depth.saturating_add(1);

    // Traverse datamaps
    let d_a = node_a.datamap;
    let d_b = node_b.datamap;

    let mut idx_a = 0;
    let mut idx_b = 0;

    for i in 0..32 {
        let bit = 1 << i;
        let in_a = (d_a & bit) != 0;
        let in_b = (d_b & bit) != 0;

        match (in_a, in_b) {
            (true, true) => {
                let (k_a, v_a) = &node_a.leaves[idx_a];
                let (k_b, v_b) = &node_b.leaves[idx_b];
                if k_a != k_b || v_a != v_b {
                    removed.push((k_a.clone(), v_a.clone()));
                    added.push((k_b.clone(), v_b.clone()));
                }
                idx_a = idx_a.wrapping_add(1);
                idx_b = idx_b.wrapping_add(1);
            }
            (true, false) => {
                let (k_a, v_a) = &node_a.leaves[idx_a];
                removed.push((k_a.clone(), v_a.clone()));
                idx_a = idx_a.wrapping_add(1);
            }
            (false, true) => {
                let (k_b, v_b) = &node_b.leaves[idx_b];
                added.push((k_b.clone(), v_b.clone()));
                idx_b = idx_b.wrapping_add(1);
            }
            (false, false) => {}
        }
    }

    // Traverse nodemaps
    let n_a = node_a.nodemap;
    let n_b = node_b.nodemap;

    let mut cidx_a = 0;
    let mut cidx_b = 0;

    for i in 0..32 {
        let bit = 1 << i;
        let in_a = (n_a & bit) != 0;
        let in_b = (n_b & bit) != 0;

        match (in_a, in_b) {
            (true, true) => {
                let child_a = &node_a.children[cidx_a];
                let child_b = &node_b.children[cidx_b];

                if child_a.structural_hash() != child_b.structural_hash() {
                    let res_a =
                        resolve_node(child_a, resolver).map_err(HamtTraversalError::Resolve)?;
                    let res_b =
                        resolve_node(child_b, resolver).map_err(HamtTraversalError::Resolve)?;
                    diff_nodes(&res_a, &res_b, added, removed, resolver, next_depth)?;
                }

                cidx_a = cidx_a.wrapping_add(1);
                cidx_b = cidx_b.wrapping_add(1);
            }
            (true, false) => {
                let child_a = &node_a.children[cidx_a];
                let res_a = resolve_node(child_a, resolver).map_err(HamtTraversalError::Resolve)?;
                collect_all_leaves(&res_a, removed, resolver, next_depth)?;
                cidx_a = cidx_a.wrapping_add(1);
            }
            (false, true) => {
                let child_b = &node_b.children[cidx_b];
                let res_b = resolve_node(child_b, resolver).map_err(HamtTraversalError::Resolve)?;
                collect_all_leaves(&res_b, added, resolver, next_depth)?;
                cidx_b = cidx_b.wrapping_add(1);
            }
            (false, false) => {}
        }
    }

    Ok(())
}

fn resolve_node<K, V, F, E>(
    node_ref: &NodeRef<K, V>,
    resolver: &mut F,
) -> Result<Arc<HamtNode<K, V>>, E>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    match node_ref {
        NodeRef::Resolved(arc) => Ok(arc.clone()),
        NodeRef::Lazy(hash) => resolver(hash),
    }
}

/// Error returned by the node-hash traversal helpers
/// ([`diff_node_hashes`], [`reachable_node_hashes`],
/// [`walk_reachable_node_hashes`]): either the caller-supplied `resolver`
/// failed, or the walk exceeded the crate's internal max-depth bound — the
/// deepest a HAMT this crate builds can ever legitimately be.
///
/// A resolver reading from a store can be handed corrupted or adversarial
/// data — a node whose `nodemap` children chain far deeper than any tree
/// [`build_hamt`](super::build_hamt) could have produced (or, in the limit,
/// a cycle). Recursing on that without a bound risks exhausting the call
/// stack and aborting the whole process; `MaxDepthExceeded` turns that into
/// an ordinary `Result::Err` instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HamtTraversalError<E> {
    /// The resolver failed to load a lazy child the walk needed to descend
    /// into.
    Resolve(E),
    /// The walk recursed past the deepest depth a legitimately-built HAMT
    /// can have, which only happens against corrupted or adversarial node
    /// data.
    MaxDepthExceeded { depth: usize },
}

impl<E> fmt::Display for HamtTraversalError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve(err) => write!(f, "hamt traversal resolver failed: {err}"),
            Self::MaxDepthExceeded { depth } => {
                write!(f, "hamt traversal exceeded max depth at {depth}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for HamtTraversalError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resolve(err) => Some(err),
            Self::MaxDepthExceeded { .. } => None,
        }
    }
}

/// The result of [`diff_node_hashes`]: the node hashes a path-copying
/// mutation superseded vs. the ones it newly created.
///
/// A named struct instead of a `(Vec<_>, Vec<_>)` tuple deliberately, since
/// the two fields hold the same element type in opposite GC roles —
/// swapping them at a call site would type-check silently while inverting
/// refcount increments and decrements. See [`diff_node_hashes`] for the
/// full timing contract these two lists are meant to be used under.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeHashDelta {
    /// Node hashes present in `root_a` but not `root_b`. GC candidates once
    /// `root_a` is retired — never delete these while `root_a` is still
    /// live.
    pub superseded_node_hashes: Vec<StructuralHash>,
    /// Node hashes present in `root_b` but not `root_a`. Safe to increment
    /// refcounts for as soon as `root_b` is persisted.
    pub new_node_hashes: Vec<StructuralHash>,
}

/// Diffs the internal node hashes between two HAMT roots produced by a
/// *single* path-copying mutation (e.g. before/after an
/// [`insert`](super::insert) or [`remove`](super::remove) call), identifying
/// which persisted nodes the mutation superseded and which it newly created.
///
/// Because HAMT nodes are content-addressed by [`StructuralHash`], the two
/// lists are exactly what a storage backend needs to maintain per-hash
/// refcounts for garbage collection — but the two halves fire at *different
/// times*, not in the same transaction as the mutation:
///
/// - Increment every hash in `new_node_hashes` when the new root is
///   persisted. This is always safe to do immediately, since `root_a`'s
///   nodes are already counted from when *it* was persisted.
/// - Decrement every hash in `superseded_node_hashes` only when `root_a`
///   itself is retired (e.g. an old state generation aging out of history),
///   **not** when `root_b` is written — `root_a` is typically still a live,
///   independently-referenced root at that point (that's the entire reason
///   path copying returns a new root instead of mutating in place), and
///   decrementing its spine early will drive still-referenced nodes to a
///   refcount of zero while other roots still point at them.
///
/// A hash reaching a refcount of zero has no live root referencing it and is
/// safe to delete. If increments and decrements for the same transition
/// ever do land in one batch, apply the increments first, so a hash that
/// appears in both lists can't transiently hit zero.
///
/// Bootstrapping refcounts for nodes that already exist in a store (or
/// verifying they haven't drifted) needs a separate, one-time reachability
/// walk over every currently-live root — see
/// [`reachable_node_hashes`] — since this
/// function only reports the delta between two adjacent roots, not absolute
/// counts.
///
/// A `superseded` hash is only a GC *candidate* even after its root is
/// retired, not certain garbage — structural sharing means the same subtree
/// can still be reachable from another live root (a different room's
/// snapshot, a sibling branch, ...), which is exactly what the refcount is
/// for.
///
/// # Branching hazard — read before wiring this into retirement
///
/// This function is only safe as the *sole* source of what to decrement
/// when `root_a` is retired if `root_b` is `root_a`'s **one and only** live
/// successor. If `root_a` has more than one live descendant at retirement
/// time — a forked resolution branch, a forward-extremity that hasn't
/// converged yet, anything where two different roots both path-copied out
/// of `root_a` — diffing against just one of them will report a subtree as
/// `superseded` even though a *different* still-live descendant still needs
/// it, and decrementing on that basis can zero out and delete live data.
/// This isn't a bug fixable in this function: a two-root diff structurally
/// cannot see a third root. When retirement can't be modeled as a strict
/// linear chain, use [`walk_reachable_node_hashes`] to mark-sweep across
/// *every* currently-live root instead of decrementing from a pairwise
/// diff — it's the only way to know a hash is truly unreachable from
/// anywhere live.
///
/// Runs in `O(|spine|)` when `root_a` and `root_b` are adjacent (one
/// mutation apart), the same `O(log32 N)` path the mutation itself touched,
/// since unrelated subtrees short-circuit on the first matching
/// `structural_hash`. For roots that are unrelated or many mutations apart,
/// this degrades to `O(N)` and may resolve every lazy node in the entire
/// divergent region — it is not a general-purpose tree diff.
///
/// # Errors
/// Returns [`HamtTraversalError::Resolve`] if `resolver` fails, or
/// [`HamtTraversalError::MaxDepthExceeded`] if the walk recurses past the
/// deepest depth a legitimately-built HAMT can have.
pub fn diff_node_hashes<K, V, F, E>(
    root_a: &Arc<HamtNode<K, V>>,
    root_b: &Arc<HamtNode<K, V>>,
    resolver: &mut F,
) -> Result<NodeHashDelta, HamtTraversalError<E>>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    let mut superseded_node_hashes = Vec::new();
    let mut new_node_hashes = Vec::new();
    diff_node_hashes_rec(
        root_a,
        root_b,
        &mut superseded_node_hashes,
        &mut new_node_hashes,
        resolver,
        0,
    )?;
    Ok(NodeHashDelta {
        superseded_node_hashes,
        new_node_hashes,
    })
}

fn diff_node_hashes_rec<K, V, F, E>(
    node_a: &Arc<HamtNode<K, V>>,
    node_b: &Arc<HamtNode<K, V>>,
    superseded: &mut Vec<StructuralHash>,
    new: &mut Vec<StructuralHash>,
    resolver: &mut F,
    depth: usize,
) -> Result<(), HamtTraversalError<E>>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    // Pointer equality check (fastest path for structurally shared nodes)
    if Arc::ptr_eq(node_a, node_b) {
        return Ok(());
    }

    // Structural hash check (fast path across process/storage boundaries)
    if node_a.structural_hash == node_b.structural_hash {
        return Ok(());
    }

    if depth >= HAMT_MAX_DEPTH {
        return Err(HamtTraversalError::MaxDepthExceeded { depth });
    }

    superseded.push(node_a.structural_hash);
    new.push(node_b.structural_hash);

    let n_a = node_a.nodemap;
    let n_b = node_b.nodemap;

    let mut cidx_a = 0;
    let mut cidx_b = 0;
    let next_depth = depth.saturating_add(1);

    for i in 0..32 {
        let bit = 1 << i;
        let in_a = (n_a & bit) != 0;
        let in_b = (n_b & bit) != 0;

        match (in_a, in_b) {
            (true, true) => {
                let child_a = &node_a.children[cidx_a];
                let child_b = &node_b.children[cidx_b];

                if child_a.structural_hash() != child_b.structural_hash() {
                    let res_a =
                        resolve_node(child_a, resolver).map_err(HamtTraversalError::Resolve)?;
                    let res_b =
                        resolve_node(child_b, resolver).map_err(HamtTraversalError::Resolve)?;
                    diff_node_hashes_rec(&res_a, &res_b, superseded, new, resolver, next_depth)?;
                }

                cidx_a = cidx_a.wrapping_add(1);
                cidx_b = cidx_b.wrapping_add(1);
            }
            (true, false) => {
                let child_a = &node_a.children[cidx_a];
                let res_a = resolve_node(child_a, resolver).map_err(HamtTraversalError::Resolve)?;
                append_reachable_node_hashes(&res_a, superseded, resolver, next_depth)?;
                cidx_a = cidx_a.wrapping_add(1);
            }
            (false, true) => {
                let child_b = &node_b.children[cidx_b];
                let res_b = resolve_node(child_b, resolver).map_err(HamtTraversalError::Resolve)?;
                append_reachable_node_hashes(&res_b, new, resolver, next_depth)?;
                cidx_b = cidx_b.wrapping_add(1);
            }
            (false, false) => {}
        }
    }

    Ok(())
}

/// Collects the structural hash of `root` and every internal node reachable
/// from it via `nodemap` children.
///
/// This is the bootstrap/verification primitive for refcount-based garbage
/// collection: a storage backend can sum this over every currently-live root
/// to compute (or double-check) absolute per-hash reference counts, which
/// [`diff_node_hashes`] alone cannot provide since it only reports the delta
/// between two adjacent roots.
///
/// Runs in `O(N)` in the number of internal nodes reachable from `root` and
/// may resolve every lazy child along the way.
///
/// # Errors
/// Returns [`HamtTraversalError::Resolve`] if `resolver` fails, or
/// [`HamtTraversalError::MaxDepthExceeded`] if the walk recurses past the
/// deepest depth a legitimately-built HAMT can have.
pub fn reachable_node_hashes<K, V, F, E>(
    root: &Arc<HamtNode<K, V>>,
    resolver: &mut F,
) -> Result<Vec<StructuralHash>, HamtTraversalError<E>>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    let mut hashes = Vec::new();
    append_reachable_node_hashes(root, &mut hashes, resolver, 0)?;
    Ok(hashes)
}

/// Walks the internal-node reachability graph of `root`, calling `mark` on
/// every node hash encountered and skipping recursion into any subtree
/// whose hash `mark` reports as already seen.
///
/// Built for sweeping reachability across *many* roots that share most of
/// their structure (e.g. every historical root recorded for a room, or
/// every room's current root): call this once per root against the same
/// `mark` closure backed by one shared set, and every subtree already
/// accounted for by an earlier root is skipped in O(1) instead of
/// re-resolved and re-walked. This is the same content-addressing property
/// [`diff_node_hashes`] uses to short-circuit its two-root comparison,
/// generalized from 2 roots to N.
///
/// `mark(hash)` must record `hash` as seen in the caller's set and return
/// `true` if it was newly inserted (not previously present), `false` if it
/// was already there. Returning `false` stops this call from resolving or
/// descending into that node's children at all — the caller-owned set,
/// not this function, is the single source of truth for "already
/// accounted for," so callers are free to back it with a `BTreeSet`, a
/// `HashSet`, or anything else that fits their scale.
///
/// [`reachable_node_hashes`] covers the single-root case and does not
/// require a `mark` closure; reach for this one directly once you're
/// sweeping more than one root and want the shared subtrees between them
/// walked only once in total.
///
/// # Errors
/// Returns [`HamtTraversalError::Resolve`] if `resolver` fails, or
/// [`HamtTraversalError::MaxDepthExceeded`] if the walk recurses past the
/// deepest depth a legitimately-built HAMT can have.
///
/// On either error, `mark` may already have recorded the hash of the node
/// that failed to resolve (or of nodes deeper in an aborted branch) as
/// "seen," even though its subtree was never walked and its descendants
/// were never marked. Retrying the sweep against that same set would then
/// skip that subtree as already-accounted-for, silently omitting live
/// descendants from the result. Do not reuse a `mark` set after an error —
/// discard it and rebuild from scratch (or restart the whole sweep) instead
/// of retrying with it in place.
pub fn walk_reachable_node_hashes<K, V, F, E, M>(
    root: &Arc<HamtNode<K, V>>,
    resolver: &mut F,
    mark: &mut M,
) -> Result<(), HamtTraversalError<E>>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
    M: FnMut(StructuralHash) -> bool,
{
    if !mark(root.structural_hash) {
        return Ok(());
    }
    walk_reachable_children(root, resolver, mark, 0)
}

/// Walks `node`'s children, checking each child's hash against `mark`
/// *before* resolving it — a shared subtree already marked by an earlier
/// call in the same sweep is skipped without ever calling `resolver` for
/// it. This matters beyond avoiding wasted resolves: if the caller is
/// mid-GC-sweep and an already-accounted-for node has since been reaped by
/// a concurrent pass, resolving it again to reach a `mark` check we didn't
/// need would fail the whole walk for no reason — checking first makes
/// that impossible.
fn walk_reachable_children<K, V, F, E, M>(
    node: &Arc<HamtNode<K, V>>,
    resolver: &mut F,
    mark: &mut M,
    depth: usize,
) -> Result<(), HamtTraversalError<E>>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
    M: FnMut(StructuralHash) -> bool,
{
    if depth >= HAMT_MAX_DEPTH {
        return Err(HamtTraversalError::MaxDepthExceeded { depth });
    }
    let next_depth = depth.saturating_add(1);
    for child in &node.children {
        if !mark(child.structural_hash()) {
            continue;
        }
        let child_node = resolve_node(child, resolver).map_err(HamtTraversalError::Resolve)?;
        walk_reachable_children(&child_node, resolver, mark, next_depth)?;
    }
    Ok(())
}

/// Appends the structural hash of `node` and every internal node reachable
/// from it, in pre-order. Shared by [`reachable_node_hashes`] and
/// [`diff_node_hashes`] (to enumerate a whole subtree that only exists on
/// one side of a diff).
fn append_reachable_node_hashes<K, V, F, E>(
    node: &Arc<HamtNode<K, V>>,
    collection: &mut Vec<StructuralHash>,
    resolver: &mut F,
    depth: usize,
) -> Result<(), HamtTraversalError<E>>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    collection.push(node.structural_hash);
    if depth >= HAMT_MAX_DEPTH {
        return Err(HamtTraversalError::MaxDepthExceeded { depth });
    }
    let next_depth = depth.saturating_add(1);
    for child in &node.children {
        let child_node = resolve_node(child, resolver).map_err(HamtTraversalError::Resolve)?;
        append_reachable_node_hashes(&child_node, collection, resolver, next_depth)?;
    }
    Ok(())
}

fn collect_all_leaves<K, V, F, E>(
    node: &Arc<HamtNode<K, V>>,
    collection: &mut Vec<(K, V)>,
    resolver: &mut F,
    depth: usize,
) -> Result<(), HamtTraversalError<E>>
where
    K: Hash + Clone + Eq,
    V: Hash + Clone + Eq,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    if depth >= HAMT_MAX_DEPTH {
        return Err(HamtTraversalError::MaxDepthExceeded { depth });
    }
    let next_depth = depth.saturating_add(1);
    for (k, v) in &node.leaves {
        collection.push((k.clone(), v.clone()));
    }
    for child in &node.children {
        let child_node = resolve_node(child, resolver).map_err(HamtTraversalError::Resolve)?;
        collect_all_leaves(&child_node, collection, resolver, next_depth)?;
    }
    Ok(())
}
