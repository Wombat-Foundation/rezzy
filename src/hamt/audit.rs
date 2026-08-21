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
//! the storage backend's responsibility, not this module's. Treat the result
//! of [`unreachable_node_hashes`] as a candidate list for further safety
//! checks, never as a delete list on its own.

use std::collections::HashSet;
use std::{sync::Arc, vec::Vec};

use super::{
    delta::{walk_reachable_node_hashes, HamtTraversalError},
    HamtNode, StructuralHash,
};

/// Computes the node hashes in `universe` that are not reachable from any of
/// `roots`.
///
/// Walks each root with [`walk_reachable_node_hashes`] against one shared
/// `HashSet`, so subtrees shared between roots are resolved and walked only
/// once in total. The result is `universe` minus that shared reachable set.
///
/// `resolver` is called once per distinct node hash encountered across all
/// roots combined (not once per root), same as the underlying walk.
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
pub fn unreachable_node_hashes<K, V, F, E>(
    roots: impl IntoIterator<Item = Arc<HamtNode<K, V>>>,
    universe: impl IntoIterator<Item = StructuralHash>,
    resolver: &mut F,
) -> Result<Vec<StructuralHash>, HamtTraversalError<E>>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    let mut reachable: HashSet<StructuralHash> = HashSet::new();
    for root in roots {
        walk_reachable_node_hashes(&root, resolver, &mut |hash| reachable.insert(hash))?;
    }

    Ok(universe
        .into_iter()
        .filter(|hash| !reachable.contains(hash))
        .collect())
}
