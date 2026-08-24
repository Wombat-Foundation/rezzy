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
//! `unreachable` side of a [`NodeReachabilityAudit`] as a candidate list for
//! further safety checks, never as a delete list on its own.

use crate::{HashMap, HashSet};
use alloc::{sync::Arc, vec::Vec};
use core::fmt;

#[cfg(feature = "std")]
use roaring::RoaringBitmap;

use super::{
    delta::{walk_reachable_node_hashes, HamtTraversalError},
    HamtNode, StructuralHash,
};

/// [`IndexedUniverse::try_build`] was given more than `u32::MAX` distinct
/// hashes, so no dense index could be assigned to all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniverseTooLarge {
    /// The true total number of distinct hashes in `universe` (which exceeds
    /// `u32::MAX`). Not a constant `u32::MAX + 1`: the builder keeps counting
    /// distinct hashes past the bound before failing.
    pub distinct_count: usize,
}

impl fmt::Display for UniverseTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "universe has {} distinct hashes, more than u32::MAX can index",
            self.distinct_count
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UniverseTooLarge {}

/// A `universe` of node hashes assigned dense `u32` indexes, in the order the
/// hashes were given.
///
/// This is the compaction step a `RoaringBitmap`-backed audit needs:
/// `StructuralHash` (16 bytes, high-entropy, not locally dense) cannot be
/// used as a roaring index directly, so every hash in `universe` is given a
/// stable position instead. Identity always resolves back through
/// [`Self::hash_at`]/`hashes` to the full hash — the dense index is a
/// local, single-call addressing scheme, not an identifier of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedUniverse {
    /// `hashes[i]` is the `StructuralHash` assigned to dense index `i`.
    hashes: Vec<StructuralHash>,
    index_by_hash: HashMap<StructuralHash, u32>,
}

impl IndexedUniverse {
    /// Assigns each hash in `universe` a dense `u32` index, first-seen order.
    /// Duplicate hashes collapse onto the same index.
    ///
    /// # Errors
    /// Returns [`UniverseTooLarge`] if `universe` contains more than
    /// `u32::MAX` distinct hashes.
    ///
    /// # Panics
    /// Never — the internal `u32::try_from` index assignment is guaranteed
    /// to fit by the same `UniverseTooLarge` guard above it.
    pub fn try_build(
        universe: impl IntoIterator<Item = StructuralHash>,
    ) -> Result<Self, UniverseTooLarge> {
        Self::try_build_bounded(universe, u32::MAX as usize)
    }

    /// [`Self::try_build`], but with the overflow bound as a parameter
    /// instead of the hard-coded `u32::MAX`.
    ///
    /// This is the actual overflow-handling logic; `try_build` is a thin
    /// wrapper fixing `bound` to `u32::MAX`. The indirection exists purely so
    /// tests can exercise the "past the bound" branch (the counting loop
    /// starting at what's now line ~152 below) at a tiny, deterministic
    /// universe size instead of needing ~4.3 billion actual `StructuralHash`
    /// entries in memory to reach it -- the two run the identical code, just
    /// parameterized on where the line is.
    pub(crate) fn try_build_bounded(
        universe: impl IntoIterator<Item = StructuralHash>,
        bound: usize,
    ) -> Result<Self, UniverseTooLarge> {
        let mut hashes: Vec<StructuralHash> = Vec::new();
        let mut index_by_hash: HashMap<StructuralHash, u32> = HashMap::default();
        let mut iter = universe.into_iter();
        for hash in iter.by_ref() {
            if index_by_hash.contains_key(&hash) {
                continue;
            }
            // A new distinct hash needs index `hashes.len()`. If we're
            // already at `bound` (`u32::MAX` in production), the
            // resulting length would be one past what still fits in a
            // `u32` (and would make the later
            // `u32::try_from(universe.len())` for bitmap construction
            // panic). Reject here so `len()` is always representable.
            if hashes.len() >= bound {
                // Keep counting distinct hashes past the bound so
                // `distinct_count` reports the *true* total — the previous
                // value was always `bound + 1` (no information).
                let mut seen: HashSet<StructuralHash> = index_by_hash.keys().copied().collect();
                seen.insert(hash);
                let mut distinct_count = seen.len();
                for h in iter {
                    if seen.insert(h) {
                        distinct_count = distinct_count.saturating_add(1);
                    }
                }
                return Err(UniverseTooLarge { distinct_count });
            }
            let idx = u32::try_from(hashes.len())
                .expect("hashes.len() < u32::MAX, guaranteed by the check above");
            index_by_hash.insert(hash, idx);
            hashes.push(hash);
        }
        Ok(Self {
            hashes,
            index_by_hash,
        })
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
/// Use this instead of [`NodeReachabilityAudit`] when the caller needs to keep
/// many audits in memory, diff them, or intersect/union them repeatedly —
/// operations `RoaringBitmap` is built for and a `HashSet<StructuralHash>`
/// is not. `universe` is the only place `StructuralHash` identity lives;
/// `reachable`/`unreachable` are addressed purely through its dense indexes.
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq)]
pub struct BitmapNodeReachabilityAudit {
    pub universe: IndexedUniverse,
    pub reachable: RoaringBitmap,
    pub unreachable: RoaringBitmap,
}

/// Errors from [`bitmap_node_reachability_audit`]: either the traversal itself
/// failed, or `universe` could not be given a dense index.
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq)]
pub enum BitmapAuditError<E> {
    /// `universe` had more than `u32::MAX` distinct hashes.
    Universe(UniverseTooLarge),
    /// The reachability walk itself failed.
    Traversal(HamtTraversalError<E>),
}

#[cfg(feature = "std")]
impl<E: fmt::Display> fmt::Display for BitmapAuditError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Universe(err) => write!(f, "{err}"),
            Self::Traversal(err) => write!(f, "{err}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for BitmapAuditError<E>
where
    E: std::error::Error + fmt::Debug + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Universe(err) => Some(err),
            Self::Traversal(err) => Some(err),
        }
    }
}

#[cfg(feature = "std")]
impl<E> From<UniverseTooLarge> for BitmapAuditError<E> {
    fn from(err: UniverseTooLarge) -> Self {
        Self::Universe(err)
    }
}

#[cfg(feature = "std")]
impl<E> From<HamtTraversalError<E>> for BitmapAuditError<E> {
    fn from(err: HamtTraversalError<E>) -> Self {
        Self::Traversal(err)
    }
}

/// Partitions `universe` into reachable/unreachable [`RoaringBitmap`]s over a
/// freshly built [`IndexedUniverse`].
///
/// Same traversal and semantics as [`node_reachability_audit`], but marks
/// directly into a `RoaringBitmap` via `universe`'s dense index instead of
/// accumulating a `HashSet<StructuralHash>` mark set first — this is the
/// version worth using when the caller actually wants the roaring
/// representation, not `node_reachability_audit`'s result reshaped afterward.
/// Hashes the walk reaches that are outside `universe` are marked but never
/// materialize a bitmap entry, matching `node_reachability_audit`'s handling of
/// the same case.
///
/// # Errors
/// Returns [`BitmapAuditError::Universe`] if `universe` has more than
/// `u32::MAX` distinct hashes, or [`BitmapAuditError::Traversal`] on the
/// same conditions as [`node_reachability_audit`].
///
/// # Panics
/// Does not panic on any caller-controlled input — an oversized `universe`
/// is reported as [`BitmapAuditError::Universe`], not a panic. The one
/// `.expect()` in this function's body re-derives `universe.len()` as a
/// `u32` for bitmap construction, which [`IndexedUniverse::try_build`]
/// (called just above it, and propagated with `?` on failure) already
/// guarantees fits.
#[cfg(feature = "std")]
pub fn bitmap_node_reachability_audit<K, V, F, E>(
    roots: impl IntoIterator<Item = Arc<HamtNode<K, V>>>,
    universe: impl IntoIterator<Item = StructuralHash>,
    resolver: &mut F,
) -> Result<BitmapNodeReachabilityAudit, BitmapAuditError<E>>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    let universe = IndexedUniverse::try_build(universe)?;

    let mut reachable = RoaringBitmap::new();
    // Hashes outside `universe` still need dedup so a subtree shared across
    // roots (or reachable from inside and outside `universe`) is walked
    // once, same as `node_reachability_audit`. `reachable`'s own membership
    // check covers dedup for anything actually in `universe`, so this set
    // only ever grows for hashes the caller's `universe` scan missed.
    let mut visited_outside_universe: HashSet<StructuralHash> = HashSet::default();
    for root in roots {
        walk_reachable_node_hashes(&root, resolver, &mut |hash| {
            if let Some(idx) = universe.index_of(&hash) {
                reachable.insert(idx)
            } else {
                visited_outside_universe.insert(hash)
            }
        })
        .map_err(BitmapAuditError::Traversal)?;
    }

    let universe_len = u32::try_from(universe.len())
        .expect("IndexedUniverse::try_build already bounds-checked this");
    // `unreachable` is the full index range minus `reachable`; build the full
    // range as a bitmap and subtract. `MultiOps::difference` reduces over many
    // bitmaps; for a pair, call `Sub::sub` by name to sidestep clippy's
    // `arithmetic_side_effects` (a false positive for set-difference).
    let full_range: RoaringBitmap = (0..universe_len).collect();
    let unreachable: RoaringBitmap = core::ops::Sub::sub(full_range, &reachable);

    Ok(BitmapNodeReachabilityAudit {
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
pub struct NodeReachabilityAudit {
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
pub fn node_reachability_audit<K, V, F, E>(
    roots: impl IntoIterator<Item = Arc<HamtNode<K, V>>>,
    universe: impl IntoIterator<Item = StructuralHash>,
    resolver: &mut F,
) -> Result<NodeReachabilityAudit, HamtTraversalError<E>>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    let mut marked: HashSet<StructuralHash> = HashSet::default();
    for root in roots {
        walk_reachable_node_hashes(&root, resolver, &mut |hash| marked.insert(hash))?;
    }

    let mut reachable: HashSet<StructuralHash> = HashSet::default();
    // `unreachable` is a partition of `universe`, so a hash that appears
    // multiple times in `universe` must be emitted only once -- matching the
    // dedup that `IndexedUniverse` (and thus the bitmap variant) provides.
    let mut seen_unreachable: HashSet<StructuralHash> = HashSet::default();
    let mut unreachable: Vec<StructuralHash> = Vec::new();
    for hash in universe {
        if marked.contains(&hash) {
            reachable.insert(hash);
        } else if seen_unreachable.insert(hash) {
            unreachable.push(hash);
        }
    }

    Ok(NodeReachabilityAudit {
        reachable,
        unreachable,
    })
}

/// Computes the node hashes in `universe` that are not reachable from any of
/// `roots`.
///
/// Convenience wrapper over [`node_reachability_audit`] for callers that only
/// need the candidate list; see [`NodeReachabilityAudit`] if the reachable side
/// is also useful (e.g. for a second-pass confirmation check).
///
/// # Errors
/// See [`node_reachability_audit`].
pub fn unreachable_node_hashes<K, V, F, E>(
    roots: impl IntoIterator<Item = Arc<HamtNode<K, V>>>,
    universe: impl IntoIterator<Item = StructuralHash>,
    resolver: &mut F,
) -> Result<Vec<StructuralHash>, HamtTraversalError<E>>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    node_reachability_audit(roots, universe, resolver).map(|audit| audit.unreachable)
}
