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

#[cfg(test)]
std::thread_local! {
    static FORCE_ALLOCATION_FAILURE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[inline]
fn allocation_should_fail() -> bool {
    #[cfg(test)]
    {
        FORCE_ALLOCATION_FAILURE.with(core::cell::Cell::get)
    }
    #[cfg(not(test))]
    false
}

#[cfg(test)]
pub(crate) fn set_force_allocation_failure(value: bool) {
    FORCE_ALLOCATION_FAILURE.with(|flag| flag.set(value));
}

/// The largest index value a [`DenseIndex`] index width can hold. Used to pick
/// the default overflow bound in [`DenseIndex::try_build`].
pub trait DenseIndexWidth: Copy {
    /// The largest index this width can represent, as a `usize`.
    const MAX: usize;
}

impl DenseIndexWidth for u32 {
    const MAX: usize = u32::MAX as usize;
}

impl DenseIndexWidth for u8 {
    const MAX: usize = u8::MAX as usize;
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
    /// True when construction stopped because memory allocation failed.
    pub allocation_failed: bool,
}

impl fmt::Display for IndexTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.allocation_failed {
            return f.write_str("failed to allocate memory while building index");
        }
        write!(
            f,
            "index has {} distinct items, more than the index width can address",
            self.distinct_count
        )
    }
}

impl core::error::Error for IndexTooLarge {}

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
    /// than `Idx` can address (`Idx::MAX + 1` addressable slots — exactly
    /// `Idx::MAX + 1` distinct items succeeds; only a larger universe fails).
    pub fn try_build(universe: impl IntoIterator<Item = T>) -> Result<Self, IndexTooLarge> {
        // `Idx::MAX` (e.g. `u8::MAX` = 255) is itself a representable index
        // value, so the number of addressable slots is `Idx::MAX + 1` (256),
        // not `Idx::MAX`. Passing `Idx::MAX` as `bound` would reject a
        // universe of exactly that many distinct items on its last one, even
        // though its highest assigned index (`Idx::MAX`) fits. `saturating_add`
        // only matters for `Idx = usize`, where `usize::MAX + 1` would
        // overflow; saturating keeps the bound at `usize::MAX`, which no real
        // universe reaches anyway.
        Self::try_build_bounded(universe, Idx::MAX.saturating_add(1))
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
    /// Returns [`IndexTooLarge`] if `universe` contains more than `bound`
    /// distinct items (exactly `bound` distinct items succeeds; the bound is
    /// the highest index the width can address plus one).
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
                if allocation_should_fail() || post_bound.try_reserve(1).is_err() {
                    return Err(IndexTooLarge {
                        distinct_count,
                        allocation_failed: true,
                    });
                }
                post_bound.insert(item);
                distinct_count = distinct_count.saturating_add(1);
                for i in iter {
                    if index_by_item.contains_key(&i) {
                        continue;
                    }
                    if allocation_should_fail() || post_bound.try_reserve(1).is_err() {
                        return Err(IndexTooLarge {
                            distinct_count,
                            allocation_failed: true,
                        });
                    }
                    if post_bound.insert(i) {
                        distinct_count = distinct_count.saturating_add(1);
                    }
                }
                return Err(IndexTooLarge {
                    distinct_count,
                    allocation_failed: false,
                });
            }
            if allocation_should_fail()
                || items.try_reserve(1).is_err()
                || index_by_item.try_reserve(1).is_err()
            {
                return Err(IndexTooLarge {
                    distinct_count: items.len(),
                    allocation_failed: true,
                });
            }
            let idx = Idx::try_from(items.len()).map_err(|_| IndexTooLarge {
                distinct_count: items.len(),
                allocation_failed: false,
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
    use alloc::string::ToString;

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
    fn bounded_allows_exactly_bound_distinct_items() {
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

    #[test]
    fn partial_eq_covers_same_and_different_indexes() {
        let a: DenseIndex<u32> = DenseIndex::try_build([1, 2, 3]).unwrap();
        let b: DenseIndex<u32> = DenseIndex::try_build([1, 2, 3]).unwrap();
        let c: DenseIndex<u32> = DenseIndex::try_build([1, 2]).unwrap();
        let d: DenseIndex<u32> = DenseIndex::try_build([3, 2, 1]).unwrap();
        assert_eq!(a, b, "same items in the same order are equal");
        assert_ne!(a, c, "a different item set is not equal");
        assert_ne!(
            a, d,
            "same items in a different first-seen order are not equal"
        );
    }

    #[test]
    fn index_too_large_displays_distinct_count() {
        let err = IndexTooLarge {
            distinct_count: 3,
            allocation_failed: false,
        };
        assert_eq!(
            err.to_string(),
            "index has 3 distinct items, more than the index width can address"
        );
    }

    #[test]
    fn try_build_accepts_exactly_idx_max_plus_one_items() {
        // Regression: `try_build` used to pass `Idx::MAX` (255 for u8)
        // straight through as `bound`, rejecting the 256th distinct item even
        // though its index (255) is representable in `u8`. A universe of
        // exactly `Idx::MAX + 1` (256) distinct items must succeed, with the
        // last item assigned index 255.
        let idx: DenseIndex<u32, u8> = DenseIndex::try_build(0u32..256).unwrap();
        assert_eq!(idx.len(), 256);
        assert_eq!(idx.index_of(&255), Some(255));
        assert_eq!(idx.item_at(255), Some(&255));

        // One more distinct item genuinely overflows `u8`.
        let err = DenseIndex::<u32, u8>::try_build(0u32..257)
            .expect_err("257 distinct items cannot fit in a u8 index");
        assert_eq!(err.distinct_count, 257);
    }

    #[test]
    fn width_smaller_than_bound_trips_tryfrom() {
        // Idx = u8 (MAX 255) with bound 300: the `items.len() >= bound` guard
        // never trips before the item count overflows u8, so the
        // `Idx::try_from` fallback error is the branch that fires.
        let err = DenseIndex::<u32, u8>::try_build_bounded(0..300u32, 300)
            .expect_err("256 distinct items cannot fit in a u8 index");
        assert_eq!(err.distinct_count, 256);
    }

    #[test]
    fn allocation_failure_is_reported_without_panicking() {
        FORCE_ALLOCATION_FAILURE.with(|flag| flag.set(true));
        let err = DenseIndex::<u32>::try_build_bounded([1], 10)
            .expect_err("injected allocation failure must be returned");
        FORCE_ALLOCATION_FAILURE.with(|flag| flag.set(false));
        assert!(err.allocation_failed);
        assert_eq!(err.distinct_count, 0);
    }
}

#[cfg(test)]
mod targeted_coverage_tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn displays_allocation_failure() {
        let error = IndexTooLarge {
            distinct_count: 0,
            allocation_failed: true,
        };
        assert_eq!(
            error.to_string(),
            "failed to allocate memory while building index"
        );
    }

    #[test]
    fn reports_failure_while_seeding_post_bound_set() {
        set_force_allocation_failure(true);
        let error = DenseIndex::<u32>::try_build_bounded([1], 0)
            .expect_err("injected post-bound allocation failure must be returned");
        set_force_allocation_failure(false);
        assert!(error.allocation_failed);
        assert_eq!(error.distinct_count, 0);
    }

    #[test]
    fn reports_failure_while_counting_post_bound_items() {
        struct FailAfterFirst {
            next: u32,
        }

        impl Iterator for FailAfterFirst {
            type Item = u32;

            fn next(&mut self) -> Option<Self::Item> {
                let item = self.next;
                self.next = self.next.saturating_add(1);
                if item == 2 {
                    set_force_allocation_failure(true);
                }
                (item <= 2).then_some(item)
            }
        }

        set_force_allocation_failure(false);
        let error = DenseIndex::<u32>::try_build_bounded(FailAfterFirst { next: 1 }, 0)
            .expect_err("injected post-bound counting failure must be returned");
        set_force_allocation_failure(false);
        assert!(error.allocation_failed);
        assert_eq!(error.distinct_count, 1);
    }
}
