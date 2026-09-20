//! Subtree differencing and mutation delta tracking for HAMT tries.

use alloc::{sync::Arc, vec::Vec};
use core::{fmt, hash::Hash};

use crate::state::LtHash;

use super::{map_index, HamtNode, NodeRef, StructuralHash, HAMT_MAX_DEPTH};

pub type Delta<K, V> = Vec<(K, V)>;
pub type DeltaResult<K, V, E> = Result<(Delta<K, V>, Delta<K, V>), E>;

/// Isolates the delta (added/removed items) between two HAMT tries in O(|Delta|
/// * log32 N) time. Uses the `LtHash` lattice to quickly short-circuit if the
///   tries are convergently identical.
///
/// # Errors
/// Returns [`HamtTraversalError::Resolve`] if the `resolver` fails to resolve a lazy node, or
/// [`HamtTraversalError::MaxDepthExceeded`] if the diff recurses past the deepest depth a
/// legitimately-built HAMT can have.
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
/// Returns [`HamtTraversalError::Resolve`] if the `resolver` fails to resolve a lazy node, or
/// [`HamtTraversalError::MaxDepthExceeded`] if the diff recurses past the deepest depth a
/// legitimately-built HAMT can have.
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

/// Helper to iterate over the indices of set bits in a 32-bit integer.
fn set_bits(mut bits: u32) -> impl Iterator<Item = usize> {
    core::iter::from_fn(move || {
        if bits == 0 {
            None
        } else {
            let bit = bits & bits.wrapping_neg();
            bits &= bits.wrapping_sub(1);
            Some(bit.trailing_zeros() as usize)
        }
    })
}

/// Recursively compute the structural diff between two HAMT nodes.
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

    // Traverse datamaps. Derive the three disjoint slot classes with bitwise
    // set ops, then walk only the occupied slots instead of all 32.
    let d_a = node_a.datamap;
    let d_b = node_b.datamap;

    let union = d_a | d_b;
    for slot in set_bits(union) {
        let bit = 1 << slot;
        let in_a = (d_a & bit) != 0;
        let in_b = (d_b & bit) != 0;

        if in_a && in_b {
            let idx_a = map_index(d_a, slot);
            let idx_b = map_index(d_b, slot);
            let (k_a, v_a) = &node_a.leaves[idx_a];
            let (k_b, v_b) = &node_b.leaves[idx_b];
            if k_a != k_b || v_a != v_b {
                removed.push((k_a.clone(), v_a.clone()));
                added.push((k_b.clone(), v_b.clone()));
            }
            continue;
        }
        if in_a {
            let idx_a = map_index(d_a, slot);
            let (k_a, v_a) = &node_a.leaves[idx_a];
            removed.push((k_a.clone(), v_a.clone()));
            continue;
        }
        // `bit` is in `union`, and reaching here means it was neither the
        // `in_a && in_b` nor the `in_a`-only case above, so `in_b` is
        // guaranteed true -- no need to re-test it.
        let idx_b = map_index(d_b, slot);
        let (k_b, v_b) = &node_b.leaves[idx_b];
        added.push((k_b.clone(), v_b.clone()));
    }

    // Traverse nodemaps
    let n_a = node_a.nodemap;
    let n_b = node_b.nodemap;

    let union = n_a | n_b;
    for slot in set_bits(union) {
        let bit = 1 << slot;
        let in_a = (n_a & bit) != 0;
        let in_b = (n_b & bit) != 0;

        if in_a && in_b {
            let cidx_a = map_index(n_a, slot);
            let cidx_b = map_index(n_b, slot);
            let child_a = &node_a.children[cidx_a];
            let child_b = &node_b.children[cidx_b];

            if child_a.structural_hash() != child_b.structural_hash() {
                let res_a = resolve_node(child_a, resolver).map_err(HamtTraversalError::Resolve)?;
                let res_b = resolve_node(child_b, resolver).map_err(HamtTraversalError::Resolve)?;
                diff_nodes(&res_a, &res_b, added, removed, resolver, next_depth)?;
            }
            continue;
        }
        if in_a {
            let cidx_a = map_index(n_a, slot);
            let child_a = &node_a.children[cidx_a];
            let res_a = resolve_node(child_a, resolver).map_err(HamtTraversalError::Resolve)?;
            collect_all_leaves(&res_a, removed, resolver, next_depth)?;
            continue;
        }
        // `bit` is in `union`, and reaching here means it was neither the
        // `in_a && in_b` nor the `in_a`-only case above, so `in_b` is
        // guaranteed true -- no need to re-test it.
        let cidx_b = map_index(n_b, slot);
        let child_b = &node_b.children[cidx_b];
        let res_b = resolve_node(child_b, resolver).map_err(HamtTraversalError::Resolve)?;
        collect_all_leaves(&res_b, added, resolver, next_depth)?;
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

impl<E> core::error::Error for HamtTraversalError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
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

/// Returns the internal-node hash delta for one path-copying mutation.
/// `new_node_hashes` are incremented when `root_b` is persisted;
/// `superseded_node_hashes` are decremented only when `root_a` is retired.
/// See the optional `unstable-refcount-gc` integration.
///
/// Pairwise retirement is safe only for a linear root history. If `root_a`
/// has multiple live descendants, use [`walk_reachable_node_hashes`] across
/// every live root: a two-root diff cannot see sharing through a third root.
/// Use [`reachable_node_hashes`] to bootstrap or verify absolute refcounts.
///
/// Adjacent roots take `O(|spine|)`; unrelated roots may take `O(N)`.
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

/// Recursively compute the hash differences between two HAMT nodes.
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

    let next_depth = depth.saturating_add(1);

    let union = n_a | n_b;
    for slot in set_bits(union) {
        let bit = 1 << slot;
        let in_a = (n_a & bit) != 0;
        let in_b = (n_b & bit) != 0;

        if in_a && in_b {
            let cidx_a = map_index(n_a, slot);
            let cidx_b = map_index(n_b, slot);
            let child_a = &node_a.children[cidx_a];
            let child_b = &node_b.children[cidx_b];

            if child_a.structural_hash() != child_b.structural_hash() {
                let res_a = resolve_node(child_a, resolver).map_err(HamtTraversalError::Resolve)?;
                let res_b = resolve_node(child_b, resolver).map_err(HamtTraversalError::Resolve)?;
                diff_node_hashes_rec(&res_a, &res_b, superseded, new, resolver, next_depth)?;
            }
            continue;
        }
        if in_a {
            let cidx_a = map_index(n_a, slot);
            let child_a = &node_a.children[cidx_a];
            let res_a = resolve_node(child_a, resolver).map_err(HamtTraversalError::Resolve)?;
            append_reachable_node_hashes(&res_a, superseded, resolver, next_depth)?;
            continue;
        }
        // `bit` is in `union`, and reaching here means it was neither the
        // `in_a && in_b` nor the `in_a`-only case above, so `in_b` is
        // guaranteed true -- no need to re-test it.
        let cidx_b = map_index(n_b, slot);
        let child_b = &node_b.children[cidx_b];
        let res_b = resolve_node(child_b, resolver).map_err(HamtTraversalError::Resolve)?;
        append_reachable_node_hashes(&res_b, new, resolver, next_depth)?;
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
/// Runs in `O(N)` time where `N` is the number of internal nodes reachable from `root` and
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

/// Walks `root`'s internal-node graph, calling `mark` for every hash.
/// Reuse one caller-owned mark set across roots: `false` skips an already
/// visited subtree, so shared structure is walked once. Use
/// [`reachable_node_hashes`] for a single root.
///
/// # Errors
/// Returns [`HamtTraversalError::Resolve`] if `resolver` fails, or
/// [`HamtTraversalError::MaxDepthExceeded`] if the walk recurses past the
/// deepest depth a legitimately-built HAMT can have.
///
/// Do not reuse the mark set after an error: it may contain an unresolved
/// node whose descendants were never visited.
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
