//! Reachability audit for content-addressed HAMT storage.
//!
//! This module answers exactly one question, in-memory and storage-agnostic:
//! given a set of live roots and the full universe of node hashes a storage
//! backend currently holds, which of those node hashes are *not* reachable
//! from any root?
//!
//! It deliberately does not decide what to do with the answer. Root-set
//! completeness (is the caller's root list actually every live root?),
//! scan/snapshot consistency (was `universe` collected consistently with the
//! roots?), and any notion of quarantine, age cutoffs, or hard deletion are
//! the storage backend's responsibility, not this module's. Treat the
//! `unreachable` side of a [`ReachabilityAudit`] as a candidate list for
//! further safety checks, never as a delete list on its own.

use std::collections::HashSet;
use std::{sync::Arc, vec::Vec};

use super::{
    delta::{walk_reachable_node_hashes, HamtTraversalError},
    HamtNode, StructuralHash,
};

/// The result of a multi-root reachability audit: `universe` partitioned
/// into hashes reachable from at least one of the audited roots and hashes
/// that are not.
///
/// `reachable` is exposed (not just `unreachable`) so a caller can reuse the
/// same mark set for a second-pass confirmation check right before acting
/// on `unreachable` (e.g. `audit.reachable.contains(&hash)`), instead of
/// re-deriving it downstream as `universe - unreachable` or re-walking the
/// roots a second time.
#[derive(Debug, Clone)]
pub struct ReachabilityAudit {
    /// Hashes in `universe` reachable from at least one audited root.
    pub reachable: HashSet<StructuralHash>,
    /// Hashes in `universe` reachable from none of the audited roots.
    pub unreachable: Vec<StructuralHash>,
}

/// Partitions `universe` into hashes reachable from `roots` and hashes that
/// are not.
///
/// Walks each root with [`walk_reachable_node_hashes`] against one shared
/// `HashSet`, so subtrees shared between roots are resolved and walked only
/// once in total. `resolver` is called once per distinct node hash
/// encountered across all roots combined (not once per root), same as the
/// underlying walk.
///
/// `reachable` is the full mark set intersected with `universe`; nodes the
/// walk reaches that are outside `universe` (e.g. a caller's scan missed
/// them) are not included in either field.
///
/// # Errors
/// Returns [`HamtTraversalError::Resolve`] if `resolver` fails, or
/// [`HamtTraversalError::MaxDepthExceeded`] if a walk recurses past the
/// deepest depth a legitimately-built HAMT can have.
///
/// On error, the in-progress mark set may be partially populated (see
/// [`walk_reachable_node_hashes`]'s error-recovery note); this function
/// discards it and returns the error rather than a partial answer, so a
/// caller never mistakes a partial reachable set for a complete one.
pub fn reachability_audit<K, V, F, E>(
    roots: impl IntoIterator<Item = Arc<HamtNode<K, V>>>,
    universe: impl IntoIterator<Item = StructuralHash>,
    resolver: &mut F,
) -> Result<ReachabilityAudit, HamtTraversalError<E>>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    let mut marked: HashSet<StructuralHash> = HashSet::new();
    for root in roots {
        walk_reachable_node_hashes(&root, resolver, &mut |hash| marked.insert(hash))?;
    }

    let mut reachable: HashSet<StructuralHash> = HashSet::new();
    let mut unreachable: Vec<StructuralHash> = Vec::new();
    for hash in universe {
        if marked.contains(&hash) {
            reachable.insert(hash);
        } else {
            unreachable.push(hash);
        }
    }

    Ok(ReachabilityAudit {
        reachable,
        unreachable,
    })
}

/// Computes the node hashes in `universe` that are not reachable from any of
/// `roots`.
///
/// Convenience wrapper over [`reachability_audit`] for callers that only
/// need the candidate list; see [`ReachabilityAudit`] if the reachable side
/// is also useful (e.g. for a second-pass confirmation check).
///
/// # Errors
/// See [`reachability_audit`].
pub fn unreachable_node_hashes<K, V, F, E>(
    roots: impl IntoIterator<Item = Arc<HamtNode<K, V>>>,
    universe: impl IntoIterator<Item = StructuralHash>,
    resolver: &mut F,
) -> Result<Vec<StructuralHash>, HamtTraversalError<E>>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    reachability_audit(roots, universe, resolver).map(|audit| audit.unreachable)
}
