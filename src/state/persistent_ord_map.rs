//! Backend-neutral persistent ordered map used by room-state resolution.
//!
//! This is intentionally a small compatibility layer. The current backend is
//! an `Arc<BTreeMap>` baseline; it can be replaced by a path-copying tree after
//! real workloads establish that copy-on-write is insufficient.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::borrow::Borrow;
use core::cmp::Ordering;
use core::fmt;
use core::iter::Peekable;
use core::ops::{Index, RangeBounds};
/// An ordered, cloneable map with shared persistent snapshots.
#[derive(Clone, Default)]
pub struct PersistentOrdMap<K, V>(Arc<BTreeMap<K, V>>);

impl<K: Ord + fmt::Debug, V: fmt::Debug> fmt::Debug for PersistentOrdMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<K: Ord, V: PartialEq> PartialEq for PersistentOrdMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<K: Ord, V: Eq> Eq for PersistentOrdMap<K, V> {}

impl<K, V> PersistentOrdMap<K, V> {
    /// Creates an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(BTreeMap::new()))
    }

    /// Returns whether two maps share the same persistent root.
    #[must_use]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Returns the value associated with `key`.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Ord,
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.0.get(key)
    }

    /// Returns whether `key` is present.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Ord,
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.0.contains_key(key)
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the map has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates over entries in key order.
    #[must_use]
    pub fn iter(&self) -> Iter<'_, K, V>
    where
        K: Ord,
    {
        Iter(self.0.iter())
    }

    /// Iterates over keys in key order.
    pub fn keys(&self) -> impl Iterator<Item = &K>
    where
        K: Ord,
    {
        self.iter().map(|(key, _)| key)
    }

    /// Iterates over values in key order.
    pub fn values(&self) -> impl Iterator<Item = &V>
    where
        K: Ord,
    {
        self.iter().map(|(_, value)| value)
    }

    /// Iterates over a key range in key order.
    pub fn range<R>(&self, range: R) -> impl Iterator<Item = (&K, &V)>
    where
        K: Ord,
        R: RangeBounds<K>,
    {
        self.0.range(range)
    }

    /// Returns the differences needed to transform this map into `other`.
    #[must_use]
    pub fn diff<'a, 'b>(&'a self, other: &'b Self) -> Diff<'a, 'b, K, V>
    where
        K: Ord,
        V: PartialEq,
    {
        Diff {
            left: self.0.iter().peekable(),
            right: other.0.iter().peekable(),
        }
    }
}

impl<K, V, Q: ?Sized> Index<&Q> for PersistentOrdMap<K, V>
where
    K: Ord + Borrow<Q>,
    Q: Ord,
{
    type Output = V;

    fn index(&self, key: &Q) -> &Self::Output {
        self.get(key)
            .expect("persistent ordered map index out of bounds")
    }
}

impl<K, V> FromIterator<(K, V)> for PersistentOrdMap<K, V>
where
    K: Ord + Clone,
    V: Clone,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        Self(Arc::new(iter.into_iter().collect()))
    }
}

impl<'a, K: Ord, V> IntoIterator for &'a PersistentOrdMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<K: Ord + Clone, V: Clone> IntoIterator for PersistentOrdMap<K, V> {
    type Item = (K, V);
    type IntoIter = alloc::vec::IntoIter<(K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }
}

impl<K, V> AsRef<Self> for PersistentOrdMap<K, V> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<K, V> PersistentOrdMap<K, V>
where
    K: Ord,
    K: Clone,
    V: Clone,
{
    /// Inserts a key/value pair, returning the previous value if present.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        Arc::make_mut(&mut self.0).insert(key, value)
    }

    /// Removes a key, returning its value if present.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        Arc::make_mut(&mut self.0).remove(key)
    }
}

/// Ordered map iterator.
pub struct Iter<'a, K, V>(alloc::collections::btree_map::Iter<'a, K, V>);

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// One ordered-map difference.
#[derive(Debug, Eq, PartialEq)]
pub enum DiffItem<'a, 'b, K, V> {
    /// An entry added to the new map.
    Add(&'b K, &'b V),
    /// An entry changed between maps.
    Update {
        /// The old entry.
        old: (&'a K, &'a V),
        /// The new entry.
        new: (&'b K, &'b V),
    },
    /// An entry removed from the new map.
    Remove(&'a K, &'a V),
}

/// Iterator over ordered-map differences.
pub struct Diff<'a, 'b, K, V> {
    left: Peekable<alloc::collections::btree_map::Iter<'a, K, V>>,
    right: Peekable<alloc::collections::btree_map::Iter<'b, K, V>>,
}

impl<'a, 'b, K, V> Iterator for Diff<'a, 'b, K, V>
where
    K: Ord,
    V: PartialEq,
{
    type Item = DiffItem<'a, 'b, K, V>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match (self.left.peek(), self.right.peek()) {
                (Some((left_key, left_value)), Some((right_key, right_value))) => {
                    match left_key.cmp(right_key) {
                        Ordering::Less => {
                            let (key, value) = self.left.next().expect("peeked entry disappeared");
                            return Some(DiffItem::Remove(key, value));
                        }
                        Ordering::Greater => {
                            let (key, value) = self.right.next().expect("peeked entry disappeared");
                            return Some(DiffItem::Add(key, value));
                        }
                        Ordering::Equal => {
                            let changed = left_value != right_value;
                            let old = self.left.next().expect("peeked entry disappeared");
                            let new = self.right.next().expect("peeked entry disappeared");
                            if changed {
                                return Some(DiffItem::Update { old, new });
                            }
                        }
                    }
                }
                (Some(_), None) => {
                    let (key, value) = self.left.next().expect("peeked entry disappeared");
                    return Some(DiffItem::Remove(key, value));
                }
                (None, Some(_)) => {
                    let (key, value) = self.right.next().expect("peeked entry disappeared");
                    return Some(DiffItem::Add(key, value));
                }
                (None, None) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::PersistentOrdMap;

    #[test]
    fn snapshots_are_independent() {
        let mut original = PersistentOrdMap::new();
        original.insert(1, "one");

        let snapshot = original.clone();
        original.insert(2, "two");

        assert_eq!(snapshot.get(&1), Some(&"one"));
        assert_eq!(snapshot.get(&2), None);
        assert_eq!(original.get(&2), Some(&"two"));
        assert!(!original.ptr_eq(&snapshot));
    }

    #[test]
    fn ordered_iteration_matches_map_contract() {
        let map: PersistentOrdMap<_, _> = [(3, "c"), (1, "a"), (2, "b")].into_iter().collect();
        let keys: Vec<_> = map.keys().copied().collect();
        assert_eq!(keys, [1, 2, 3]);
    }

    #[test]
    fn mutation_and_diff_match_map_contract() {
        let old: PersistentOrdMap<_, _> = [(1, "a"), (2, "b"), (4, "d")].into_iter().collect();
        let mut new = old.clone();
        assert!(old.ptr_eq(&new));

        new.insert(2, "changed");
        new.remove(&4);
        new.insert(3, "c");

        let mut changes = Vec::new();
        for change in old.diff(&new) {
            match change {
                super::DiffItem::Add(key, value) => changes.push(("add", *key, *value)),
                super::DiffItem::Remove(key, value) => changes.push(("remove", *key, *value)),
                super::DiffItem::Update {
                    old: (key, value), ..
                } => changes.push(("update", *key, *value)),
            }
        }

        assert_eq!(
            changes,
            [("update", 2, "b"), ("add", 3, "c"), ("remove", 4, "d")]
        );
        assert!(!old.ptr_eq(&new));
        assert_eq!(old.get(&2), Some(&"b"));
        assert_eq!(new.get(&2), Some(&"changed"));
    }
}
