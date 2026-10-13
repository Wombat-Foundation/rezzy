//! `u64` and `u128` sets built on [`Bitmap`].
//!
//! The high bits of each value key a `BTreeMap`; the low 32 bits live in a
//! [`Bitmap`], so all chunk-level behaviour (array/bitset containers,
//! copy-on-write sharing, canonical form) is inherited. Empty inner bitmaps are
//! never stored, so `==` is structural.

use super::Bitmap;
use alloc::collections::{btree_map, BTreeMap};
use core::fmt;
use core::iter::FromIterator;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Sub, SubAssign};

macro_rules! wide_bitmap {
    ($(#[$doc:meta])* $name:ident, $iter:ident, $value:ty, $key:ty, $len:ty) => {
        $(#[$doc])*
        #[derive(Clone, Default, PartialEq, Eq)]
        pub struct $name {
            /// Non-empty inner bitmaps keyed by the value's high bits.
            map: BTreeMap<$key, Bitmap>,
        }

        impl $name {
            fn split(value: $value) -> ($key, u32) {
                let key = <$key>::try_from(value >> 32).expect("wide bitmap key fits");
                let low = u32::try_from(value & <$value>::from(u32::MAX))
                    .expect("wide bitmap low half fits");
                (key, low)
            }

            /// Creates an empty set.
            #[must_use]
            pub const fn new() -> Self {
                Self { map: BTreeMap::new() }
            }

            /// Returns `true` if the set holds no values.
            #[must_use]
            pub fn is_empty(&self) -> bool {
                self.map.is_empty()
            }

            /// Returns the number of values in the set.
            #[must_use]
            pub fn len(&self) -> $len {
                self.map.values().map(|b| <$len>::from(b.len())).sum()
            }

            /// Returns `true` if `value` is in the set.
            #[must_use]
            pub fn contains(&self, value: $value) -> bool {
                let (key, low) = Self::split(value);
                self.map
                    .get(&key)
                    .is_some_and(|b| b.contains(low))
            }

            /// Adds `value`, returning `true` if it was not already present.
            pub fn insert(&mut self, value: $value) -> bool {
                let (key, low) = Self::split(value);
                self.map
                    .entry(key)
                    .or_default()
                    .insert(low)
            }

            /// Removes `value`, returning `true` if it was present.
            pub fn remove(&mut self, value: $value) -> bool {
                let (key, low) = Self::split(value);
                let Some(bitmap) = self.map.get_mut(&key) else {
                    return false;
                };
                let removed = bitmap.remove(low);
                if bitmap.is_empty() {
                    self.map.remove(&key);
                }
                removed
            }

            /// Returns whether every value in `self` is also in `other`.
            #[must_use]
            pub fn is_subset(&self, other: &Self) -> bool {
                self.map.iter().all(|(key, bitmap)| {
                    other.map.get(key).is_some_and(|candidate| bitmap.is_subset(candidate))
                })
            }

            /// Returns whether `self` and `other` have no values in common.
            #[must_use]
            pub fn is_disjoint(&self, other: &Self) -> bool {
                self.map.iter().all(|(key, bitmap)| {
                    other.map.get(key).is_none_or(|candidate| bitmap.is_disjoint(candidate))
                })
            }

            /// Merges `bitmap` into the entry for `key`.
            fn absorb(&mut self, key: $key, bitmap: Bitmap) {
                match self.map.entry(key) {
                    btree_map::Entry::Vacant(slot) => {
                        slot.insert(bitmap);
                    }
                    btree_map::Entry::Occupied(mut slot) => *slot.get_mut() |= &bitmap,
                }
            }

            fn subtract_assign(&mut self, rhs: &Self) {
                self.map.retain(|k, b| {
                    if let Some(o) = rhs.map.get(k) {
                        b.subtract_assign(o);
                    }
                    !b.is_empty()
                });
            }

            /// Iterates the values in ascending order.
            #[must_use]
            pub fn iter(&self) -> $iter<'_> {
                $iter { outer: self.map.iter(), inner: None }
            }
        }

        /// Borrowing iterator, ascending.
        pub struct $iter<'a> {
            outer: btree_map::Iter<'a, $key, Bitmap>,
            inner: Option<($value, super::Iter<'a>)>,
        }

        impl Iterator for $iter<'_> {
            type Item = $value;

            fn next(&mut self) -> Option<$value> {
                loop {
                    if let Some((hi, it)) = &mut self.inner {
                        if let Some(lo) = it.next() {
                            return Some(*hi | <$value>::from(lo));
                        }
                    }
                    let (k, b) = self.outer.next()?;
                    self.inner = Some((<$value>::from(*k) << 32, b.iter()));
                }
            }
        }

        impl<'a> IntoIterator for &'a $name {
            type Item = $value;
            type IntoIter = $iter<'a>;

            fn into_iter(self) -> $iter<'a> {
                self.iter()
            }
        }

        impl Extend<$value> for $name {
            fn extend<I: IntoIterator<Item = $value>>(&mut self, iter: I) {
                // Values usually arrive grouped by high bits (sorted input), so
                // fill one inner bitmap at a time and touch the map only when the
                // key changes.
                let mut current: Option<($key, Bitmap)> = None;
                for v in iter {
                    let (key, low) = Self::split(v);
                    match &mut current {
                        Some((k, bitmap)) if *k == key => {
                            bitmap.insert(low);
                        }
                        _ => {
                            if let Some((k, bitmap)) = current.take() {
                                self.absorb(k, bitmap);
                            }
                            let mut bitmap = Bitmap::new();
                            bitmap.insert(low);
                            current = Some((key, bitmap));
                        }
                    }
                }
                if let Some((k, bitmap)) = current {
                    self.absorb(k, bitmap);
                }
            }
        }

        impl FromIterator<$value> for $name {
            fn from_iter<I: IntoIterator<Item = $value>>(iter: I) -> Self {
                let mut set = Self::new();
                set.extend(iter);
                set
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_set().entries(self.iter()).finish()
            }
        }

        impl BitOrAssign<&Self> for $name {
            fn bitor_assign(&mut self, rhs: &Self) {
                for (k, b) in &rhs.map {
                    *self.map.entry(*k).or_default() |= b;
                }
            }
        }

        impl BitAndAssign<&Self> for $name {
            fn bitand_assign(&mut self, rhs: &Self) {
                self.map.retain(|k, b| match rhs.map.get(k) {
                    Some(o) => {
                        *b &= o;
                        !b.is_empty()
                    }
                    None => false,
                });
            }
        }

        impl SubAssign<&Self> for $name {
            fn sub_assign(&mut self, rhs: &Self) {
                self.subtract_assign(rhs);
            }
        }

        impl BitOr<&$name> for &$name {
            type Output = $name;

            fn bitor(self, rhs: &$name) -> $name {
                let mut out = self.clone();
                out |= rhs;
                out
            }
        }

        impl BitAnd<&$name> for &$name {
            type Output = $name;

            fn bitand(self, rhs: &$name) -> $name {
                let mut out = Self::Output::new();
                for (k, b) in &self.map {
                    if let Some(o) = rhs.map.get(k) {
                        let r = b & o;
                        if !r.is_empty() {
                            out.map.insert(*k, r);
                        }
                    }
                }
                out
            }
        }

        impl Sub<&Self> for $name {
            type Output = Self;

            fn sub(mut self, rhs: &Self) -> Self {
                self.subtract_assign(rhs);
                self
            }
        }

        impl Sub for $name {
            type Output = Self;

            fn sub(self, rhs: Self) -> Self {
                let mut out = self;
                out.subtract_assign(&rhs);
                out
            }
        }
    };
}

wide_bitmap!(
    /// A compressed set of `u64` values.
    Bitmap64,
    Iter64,
    u64,
    u32,
    u64
);
wide_bitmap!(
    /// A compressed set of `u128` values.
    Bitmap128,
    Iter128,
    u128,
    u128,
    u128
);

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// `groups` high-bit groups of 40k low values at ~`pm`/1000 density.
    fn gen(rng: &mut Rng, groups: u64, pm: u64, stride: u64) -> BTreeSet<u128> {
        let mut out = BTreeSet::new();
        for g in 0..groups {
            let base = (u128::from(g.checked_mul(stride).expect("test value fits u64")) << 32)
                | (u128::from(g) << 100);
            for v in 0..40_000u32 {
                if rng.next() % 1000 < pm {
                    out.insert(base | u128::from(v));
                }
            }
        }
        out
    }

    #[test]
    fn bitmap128_matches_btreeset() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for &pm in &[0u64, 5, 60, 500, 1000] {
            let sa = gen(&mut rng, 4, pm, 3);
            let sb = gen(&mut rng, 4, pm, 2);
            let a: Bitmap128 = sa.iter().copied().collect();
            let b: Bitmap128 = sb.iter().copied().collect();
            assert_eq!(a.len(), sa.len() as u128);
            assert_eq!(a.is_empty(), sa.is_empty());
            assert!(a.iter().eq(sa.iter().copied()));
            assert!((&a | &b).iter().eq(sa.union(&sb).copied()));
            assert!((&a & &b).iter().eq(sa.intersection(&sb).copied()));
            assert!((a.clone() - &b).iter().eq(sa.difference(&sb).copied()));
            assert!((a.clone() - b.clone())
                .iter()
                .eq(sa.difference(&sb).copied()));
            // Canonical: results equal a fresh build of the same values.
            let and: Bitmap128 = sa.intersection(&sb).copied().collect();
            assert_eq!(&a & &b, and);
            let mut c = a.clone();
            c &= &b;
            assert_eq!(c, and);
            for v in sb.iter().take(200) {
                assert_eq!(a.contains(*v), sa.contains(v));
            }
        }
    }

    #[test]
    fn bitmap64_extremes_and_dedup() {
        let mut s = Bitmap64::new();
        for v in [
            0u64,
            1,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            u64::MAX,
        ] {
            assert!(s.insert(v));
            assert!(!s.insert(v));
            assert!(s.contains(v));
        }
        assert!(!s.contains(2));
        assert_eq!(s.len(), 5);
        assert!(s.iter().eq([0, 1, 4_294_967_295, 4_294_967_296, u64::MAX]));
        assert_eq!(
            alloc::format!("{:?}", Bitmap64::from_iter([2, 1])),
            "{1, 2}"
        );
        assert!((s.clone() - &s).is_empty());
        let mut e = s.clone();
        e &= &Bitmap64::new();
        assert_eq!(e, Bitmap64::default());
    }

    #[test]
    fn bitmap128_extremes() {
        let vals = [
            0u128,
            u128::MAX,
            1 << 64,
            (1 << 64) - 1,
            1 << 32,
            u128::from(u32::MAX),
        ];
        let s: Bitmap128 = vals.into_iter().collect();
        assert_eq!(s.len(), 6);
        let expected: BTreeSet<u128> = vals.into_iter().collect();
        assert!(s.iter().eq(expected.iter().copied()));
        for v in vals {
            assert!(s.contains(v));
        }
        assert!(!s.contains(u128::MAX - 1));
    }

    #[test]
    fn wide_relationships_and_remove() {
        let mut a: Bitmap64 = [1, 1u64 << 32, u64::MAX].into_iter().collect();
        let b: Bitmap64 = [1, u64::MAX].into_iter().collect();
        assert!(!a.is_subset(&b));
        assert!(!a.is_disjoint(&b));
        assert!(a.remove(1));
        assert!(!a.remove(1));
        assert!(a.remove(u64::MAX));
        assert!(a.is_disjoint(&b));

        let mut wide: Bitmap128 = [0, 1 << 100].into_iter().collect();
        assert!(wide.remove(1 << 100));
        assert!(wide.is_subset(&Bitmap128::from_iter([0])));
    }
}
