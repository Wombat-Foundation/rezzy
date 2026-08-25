//! A first-seen-order dense index over a set of items.
//!
//! The "assign a compact integer index to every distinct item in a set, both
//! directions, so a `RoaringBitmap` (or a plain array) can address it" pattern
//! was previously reimplemented independently across the crate (see
//! `docs/tech_debt.md`, "dense-index" section). [`DenseIndex`] is the shared
//! primitive that replaces those hand-rolled copies: one engine, parameterized
//! over the indexed type `T` and the index width `Idx`, with
//! [`Result`]-based overflow handling so a caller never gets a silent wrap or
//! an index-width panic.
//!
//! `T` is generic so the same primitive serves `StructuralHash`, `String`
//! event IDs, or any other `Hash + Eq` item. `Idx` defaults to `u32` (the
//! width the roaring-based call sites need) but can be widened to `usize` for
//! callers whose sets are too large to fit in 32 bits (or that want the
//! overflow-free `usize` indexing).

use crate::HashMap;
use alloc::vec::Vec;
use core::fmt;

/// The largest index value a [`DenseIndex`] index width can hold. Used to pick
/// the default overflow bound in [`DenseIndex::try_build`].
pub trait DenseIndexWidth: Copy {
    /// The largest index this width can represent, as a `usize`.
    const MAX: usize;
}

impl DenseIndexWidth for u32 {
    const MAX: usize = u32::MAX as usize;
}

impl DenseIndexWidth for usize {
    const MAX: usize = usize::MAX;
}

/// [`DenseIndex::try_build`]/[`DenseIndex::try_build_bounded`] was given more
/// distinct items than the index width can address, so no dense index could be
/// assigned to all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexTooLarge {
    /// The true total number of distinct items (which exceeds the bound). Not
    /// a constant `bound + 1`: the builder keeps counting distinct items past
    /// the bound before failing.
    pub distinct_count: usize,
}

impl fmt::Display for IndexTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "index has {} distinct items, more than the index width can address",
            self.distinct_count
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IndexTooLarge {}

/// A set of `T` assigned dense `Idx` indexes, in first-seen order.
///
/// Duplicate items collapse onto the same index. Identity always resolves back
/// through [`Self::item_at`]/[`Self::items`] to the full item — the dense
/// index is a local, single-call addressing scheme, not an identifier of its
/// own.
#[derive(Debug, Clone)]
pub struct DenseIndex<T, Idx = u32> {
    /// `items[i]` is the `T` assigned to dense index `i`.
    items: Vec<T>,
    /// Maps each distinct `T` to its dense index.
    index_by_item: HashMap<T, Idx>,
}

impl<T: Eq + core::hash::Hash, Idx: Eq> PartialEq for DenseIndex<T, Idx> {
    fn eq(&self, other: &Self) -> bool {
        self.items == other.items && self.index_by_item == other.index_by_item
    }
}

impl<T: Eq + core::hash::Hash, Idx: Eq> Eq for DenseIndex<T, Idx> {}

impl<T: Eq + Clone + core::hash::Hash, Idx: Copy + TryFrom<usize> + DenseIndexWidth>
    DenseIndex<T, Idx>
{
    /// Assigns each item in `universe` a dense index, first-seen order.
    /// Duplicate items collapse onto the same index.
    ///
    /// # Errors
    /// Returns [`IndexTooLarge`] if `universe` contains more distinct items
    /// than `Idx` can address (`Idx::MAX`).
    pub fn try_build(universe: impl IntoIterator<Item = T>) -> Result<Self, IndexTooLarge> {
        Self::try_build_bounded(universe, Idx::MAX)
    }

    /// [`Self::try_build`], but with the overflow bound as a parameter instead
    /// of the width's `Idx::MAX`.
    ///
    /// This is the actual overflow-handling logic; `try_build` is a thin
    /// wrapper fixing `bound` to the index width's maximum. The indirection
    /// exists purely so tests can exercise the "past the bound" branch at a
    /// tiny, deterministic universe size instead of needing billions of actual
    /// items in memory.
    ///
    /// # Errors
    /// Returns [`IndexTooLarge`] if `universe` contains `bound` or more
    /// distinct items.
    pub fn try_build_bounded(
        universe: impl IntoIterator<Item = T>,
        bound: usize,
    ) -> Result<Self, IndexTooLarge> {
        let mut items: Vec<T> = Vec::new();
        let mut index_by_item: HashMap<T, Idx> = HashMap::default();
        let mut iter = universe.into_iter();
        for item in iter.by_ref() {
            if index_by_item.contains_key(&item) {
                continue;
            }
            // A new distinct item needs index `items.len()`. If we're already
            // at `bound`, the resulting length would be one past what still
            // fits in `Idx` (and would make a later `TryFrom` for bitmap
            // construction fail). Reject here so `len()` is always
            // representable.
            if items.len() >= bound {
                // Keep counting distinct items past the bound so
                // `distinct_count` reports the *true* total — the previous
                // value was always `bound + 1` (no information). Every item
                // already in `index_by_item` is a distinct pre-bound item, so
                // it is counted without copying all of its keys into a second
                // set; only items discovered *after* the bound need their own
                // small set for dedup.
                let mut distinct_count = index_by_item.len();
                let mut post_bound: crate::HashSet<T> = crate::HashSet::default();
                post_bound.insert(item);
                distinct_count = distinct_count.saturating_add(1);
                for i in iter {
                    if index_by_item.contains_key(&i) {
                        continue;
                    }
                    if post_bound.insert(i) {
                        distinct_count = distinct_count.saturating_add(1);
                    }
                }
                return Err(IndexTooLarge { distinct_count });
            }
            let idx = Idx::try_from(items.len()).map_err(|_| IndexTooLarge {
                distinct_count: items.len(),
            })?;
            index_by_item.insert(item.clone(), idx);
            items.push(item);
        }
        Ok(Self {
            items,
            index_by_item,
        })
    }

    /// The number of distinct items indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True if no items are indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The dense index assigned to `item`, if it was part of `universe`.
    #[must_use]
    pub fn index_of(&self, item: &T) -> Option<Idx> {
        self.index_by_item.get(item).copied()
    }

    /// The full item assigned to dense index `idx`, if in range.
    #[must_use]
    pub fn item_at(&self, idx: usize) -> Option<&T> {
        self.items.get(idx)
    }

    /// All indexed items, in dense-index order.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn first_seen_order_and_dedup() {
        let idx: DenseIndex<u32> = DenseIndex::try_build([7, 3, 7, 9, 3]).unwrap();
        assert_eq!(idx.len(), 3);
        assert_eq!(idx.index_of(&7), Some(0));
        assert_eq!(idx.index_of(&3), Some(1));
        assert_eq!(idx.index_of(&9), Some(2));
        assert_eq!(idx.index_of(&5), None);
        assert_eq!(idx.item_at(0), Some(&7));
        assert_eq!(idx.item_at(1), Some(&3));
        assert_eq!(idx.item_at(2), Some(&9));
        assert_eq!(idx.item_at(3), None);
        assert_eq!(idx.items(), &[7, 3, 9]);
    }

    #[test]
    fn usize_width() {
        let idx: DenseIndex<&str, usize> = DenseIndex::try_build(["a", "b", "a", "c"]).unwrap();
        assert_eq!(idx.index_of(&"b"), Some(1));
        assert_eq!(idx.item_at(2), Some(&"c"));
    }

    #[test]
    fn bounded_reports_true_distinct_count() {
        // Bound of 2: indices 0 and 1 fill, the 3rd distinct item trips it.
        let err = DenseIndex::<u32>::try_build_bounded([1, 2, 3, 2, 4, 4], 2)
            .expect_err("more than 2 distinct items must fail");
        // Distinct items: 1, 2, 3, 4 -> 4 total.
        assert_eq!(err.distinct_count, 4);
    }

    #[test]
    fn bounded_allows_exactly_bound_minus_one() {
        let idx = DenseIndex::<u32>::try_build_bounded([1, 2, 3], 3).unwrap();
        assert_eq!(idx.len(), 3);
        let err = DenseIndex::<u32>::try_build_bounded([1, 2, 3, 4], 3)
            .expect_err("4 distinct items must fail a bound of 3");
        assert_eq!(err.distinct_count, 4);
    }

    #[test]
    fn borrowed_construction_dedups() {
        let data = [10u32, 20, 10, 30];
        let idx: DenseIndex<&u32> = DenseIndex::try_build(data.iter()).unwrap();
        assert_eq!(idx.len(), 3);
        assert_eq!(idx.index_of(&&10), Some(0));
        assert_eq!(idx.index_of(&&20), Some(1));
        assert_eq!(idx.index_of(&&30), Some(2));
        assert_eq!(idx.item_at(2), Some(&&30));
    }
}
