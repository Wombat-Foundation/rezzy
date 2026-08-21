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

use std::collections::{HashMap, HashSet};
use std::{sync::Arc, vec::Vec};

use roaring::RoaringBitmap;

use super::{
    delta::{walk_reachable_node_hashes, HamtTraversalError},
    HamtNode, StructuralHash,
};

/// A `universe` of node hashes assigned dense `u32` indexes, in the order the
/// hashes were given.
///
/// This is the compaction step a `RoaringBitmap`-backed audit needs:
/// `StructuralHash` (16 bytes, high-entropy, not locally dense) cannot be
/// used as a roaring index directly, so every hash in `universe` is given a
/// stable position instead. Identity always resolves back through
/// [`Self::hash_at`]/`hashes` to the full hash — the dense index is a
/// local, single-call addressing scheme, not an identifier of its own.
#[derive(Debug, Clone)]
pub struct IndexedUniverse {
    /// `hashes[i]` is the `StructuralHash` assigned to dense index `i`.
    hashes: Vec<StructuralHash>,
    index_by_hash: HashMap<StructuralHash, u32>,
}

impl IndexedUniverse {
    /// Assigns each hash in `universe` a dense `u32` index, first-seen order.
    /// Duplicate hashes collapse onto the same index.
    ///
    /// # Panics
    /// Panics if `universe` contains more than `u32::MAX` distinct hashes —
    /// not a realistic size for a single audit's node universe.
    #[must_use]
    pub fn build(universe: impl IntoIterator<Item = StructuralHash>) -> Self {
        let mut hashes: Vec<StructuralHash> = Vec::new();
        let mut index_by_hash: HashMap<StructuralHash, u32> = HashMap::new();
        for hash in universe {
            index_by_hash.entry(hash).or_insert_with(|| {
                let idx = u32::try_from(hashes.len())
                    .expect("universe has far fewer than u32::MAX distinct hashes");
                hashes.push(hash);
                idx
            });
        }
        Self {
            hashes,
            index_by_hash,
        }
    }

    /// The number of distinct hashes indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// True if no hashes are indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// The dense index assigned to `hash`, if it was part of `universe`.
    #[must_use]
    pub fn index_of(&self, hash: &StructuralHash) -> Option<u32> {
        self.index_by_hash.get(hash).copied()
    }

    /// The full hash assigned to dense index `idx`, if in range.
    #[must_use]
    pub fn hash_at(&self, idx: u32) -> Option<StructuralHash> {
        self.hashes.get(idx as usize).copied()
    }

    /// All indexed hashes, in dense-index order.
    #[must_use]
    pub fn hashes(&self) -> &[StructuralHash] {
        &self.hashes
    }
}

/// The result of a multi-root reachability audit, expressed as
/// [`RoaringBitmap`]s over an [`IndexedUniverse`] rather than as
/// `StructuralHash` collections.
///
/// Use this instead of [`ReachabilityAudit`] when the caller needs to keep
/// many audits in memory, diff them, or intersect/union them repeatedly —
/// operations `RoaringBitmap` is built for and a `HashSet<StructuralHash>`
/// is not. `universe` is the only place `StructuralHash` identity lives;
/// `reachable`/`unreachable` are addressed purely through its dense indexes.
#[derive(Debug, Clone)]
pub struct BitmapReachabilityAudit {
    pub universe: IndexedUniverse,
    pub reachable: RoaringBitmap,
    pub unreachable: RoaringBitmap,
}

/// Partitions `universe` into reachable/unreachable [`RoaringBitmap`]s over a
/// freshly built [`IndexedUniverse`].
///
/// Same traversal and semantics as [`reachability_audit`]; this only differs
/// in how the result is represented.
///
/// # Errors
/// See [`reachability_audit`].
///
/// # Panics
/// See [`IndexedUniverse::build`].
pub fn bitmap_reachability_audit<K, V, F, E>(
    roots: impl IntoIterator<Item = Arc<HamtNode<K, V>>>,
    universe: impl IntoIterator<Item = StructuralHash>,
    resolver: &mut F,
) -> Result<BitmapReachabilityAudit, HamtTraversalError<E>>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    let universe = IndexedUniverse::build(universe);

    let mut marked: HashSet<StructuralHash> = HashSet::new();
    for root in roots {
        walk_reachable_node_hashes(&root, resolver, &mut |hash| marked.insert(hash))?;
    }

    let mut reachable = RoaringBitmap::new();
    let mut unreachable = RoaringBitmap::new();
    for (idx, hash) in universe.hashes.iter().enumerate() {
        let idx = u32::try_from(idx).expect("IndexedUniverse::build already bounds-checked this");
        if marked.contains(hash) {
            reachable.insert(idx);
        } else {
            unreachable.insert(idx);
        }
    }

    Ok(BitmapReachabilityAudit {
        universe,
        reachable,
        unreachable,
    })
}

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
