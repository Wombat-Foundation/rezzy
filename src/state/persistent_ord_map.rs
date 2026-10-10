//! Backend-neutral persistent ordered map used by room-state resolution.
//!
//! The backend is a path-copying B+tree. Cloning a map is O(1) (one `Arc`
//! bump); the first write after a fork copies only the root-to-leaf path it
//! touches (`Arc::make_mut` at each level), leaving every other subtree
//! shared with the original. `diff` walks two trees by key range and skips
//! any pair of subtrees that are the same `Arc`, so its cost scales with the
//! size of the change rather than the size of the map.
//!
//! Invariants:
//! - every leaf sits at the same depth (`height` levels above it);
//! - an internal node has `keys.len() + 1 == children.len()`, with
//!   `keys[i]` a lower bound on every key in `children[i + 1]` and an upper
//!   bound (exclusive) on every key in `children[i]`;
//! - removal never rebalances: an emptied child is dropped and a root with a
//!   single child is collapsed, so non-root nodes may be under-full.
use core::borrow::Borrow;
use core::cmp::Ordering;
use core::fmt;
use core::mem;
use core::ops::{Bound, Index, RangeBounds};
use std::{sync::Arc, vec, vec::Vec};

/// Maximum entries in a leaf and children in an internal node.
const MAX_FANOUT: usize = 24;
/// Target node fill for sorted bulk builds, leaving slack for later inserts.
const BULK_FILL: usize = MAX_FANOUT - MAX_FANOUT / 4;

enum Node<K, V> {
    Leaf(Vec<(K, V)>),
    Internal(Internal<K, V>),
}

struct Internal<K, V> {
    keys: Vec<K>,
    children: Vec<Arc<Node<K, V>>>,
}

impl<K: Clone, V: Clone> Clone for Node<K, V> {
    fn clone(&self) -> Self {
        match self {
            Self::Leaf(entries) => Self::Leaf(entries.clone()),
            Self::Internal(internal) => Self::Internal(Internal {
                keys: internal.keys.clone(),
                children: internal.children.clone(),
            }),
        }
    }
}

impl<K, V> Internal<K, V> {
    /// Unlinks child `idx` (and its separator) once it has become empty.
    fn drop_if_empty(&mut self, idx: usize) {
        if self.children[idx].is_empty() {
            self.children.remove(idx);
            if !self.keys.is_empty() {
                self.keys.remove(idx.saturating_sub(1));
            }
        }
    }

    /// Index of the child whose key range contains `key`.
    fn child_index<Q>(&self, key: &Q) -> usize
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.keys
            .partition_point(|k| Borrow::<Q>::borrow(k).cmp(key) != Ordering::Greater)
    }
}

impl<K, V> Node<K, V> {
    fn is_empty(&self) -> bool {
        match self {
            Self::Leaf(entries) => entries.is_empty(),
            Self::Internal(internal) => internal.children.is_empty(),
        }
    }

    /// Smallest key in the subtree, if any.
    fn first_key(&self) -> Option<&K> {
        let mut node = self;
        loop {
            match node {
                Self::Leaf(entries) => return entries.first().map(|(key, _)| key),
                Self::Internal(internal) => node = internal.children.first()?,
            }
        }
    }
}

/// An ordered, cloneable map with shared persistent snapshots.
pub struct PersistentOrdMap<K, V> {
    root: Arc<Node<K, V>>,
    height: u8,
    len: usize,
}

impl<K, V> Clone for PersistentOrdMap<K, V> {
    fn clone(&self) -> Self {
        Self {
            root: Arc::clone(&self.root),
            height: self.height,
            len: self.len,
        }
    }
}

impl<K, V> Default for PersistentOrdMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Ord + fmt::Debug, V: fmt::Debug> fmt::Debug for PersistentOrdMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<K: Ord, V: PartialEq> PartialEq for PersistentOrdMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.ptr_eq(other) || (self.len == other.len && self.diff(other).next().is_none())
    }
}

impl<K: Ord, V: Eq> Eq for PersistentOrdMap<K, V> {}

impl<K, V> PersistentOrdMap<K, V> {
    /// Creates an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: Arc::new(Node::Leaf(Vec::new())),
            height: 0,
            len: 0,
        }
    }

    /// Returns whether two maps share the same persistent root.
    #[must_use]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.root, &other.root)
    }

    /// Returns the number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the map has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the value associated with `key`.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Ord + Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let mut node: &Node<K, V> = &self.root;
        loop {
            match node {
                Node::Leaf(entries) => {
                    return entries
                        .binary_search_by(|(k, _)| Borrow::<Q>::borrow(k).cmp(key))
                        .ok()
                        .map(|i| &entries[i].1);
                }
                Node::Internal(internal) => {
                    node = internal.children.get(internal.child_index(key))?;
                }
            }
        }
    }

    /// Returns whether `key` is present.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Ord + Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.get(key).is_some()
    }

    /// Iterates over entries in key order.
    #[must_use]
    pub fn iter(&self) -> Iter<'_, K, V>
    where
        K: Ord,
    {
        let mut iter = Iter::empty();
        iter.descend_leftmost(&self.root);
        iter
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
    pub fn range<R>(&self, range: R) -> Range<'_, K, V, R>
    where
        K: Ord,
        R: RangeBounds<K>,
    {
        let iter = match range.start_bound() {
            Bound::Unbounded => self.iter(),
            Bound::Included(key) => Iter::seek(&self.root, key, true),
            Bound::Excluded(key) => Iter::seek(&self.root, key, false),
        };
        Range {
            iter,
            bounds: range,
        }
    }

    /// Returns the differences needed to transform this map into `other`.
    ///
    /// Subtrees shared by both maps (the same `Arc`) are skipped without being
    /// read, so the cost tracks the size of the change.
    #[must_use]
    pub fn diff<'a, 'b>(&'a self, other: &'b Self) -> Diff<'a, 'b, K, V>
    where
        K: Ord,
        V: PartialEq,
    {
        Diff {
            walker: DiffWalker::new(self, other),
        }
    }

    /// Number of nodes `diff` had to open; tests use it to prove subtree skipping.
    #[cfg(test)]
    fn diff_expansions(&self, other: &Self) -> usize
    where
        K: Ord,
        V: PartialEq,
    {
        let mut walker = DiffWalker::new(self, other);
        while walker.next_item().is_some() {}
        walker.expansions
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
        let mut entries: Vec<(K, V)> = iter.into_iter().collect();
        // Stable sort, then keep the last value per key (map-collect semantics).
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut deduped: Vec<(K, V)> = Vec::with_capacity(entries.len());
        for entry in entries {
            match deduped.last_mut() {
                Some(last) if last.0 == entry.0 => *last = entry,
                _ => deduped.push(entry),
            }
        }
        Self::from_sorted(deduped)
    }
}

impl<K: Clone, V> PersistentOrdMap<K, V> {
    /// Builds a balanced tree bottom-up from strictly ascending entries.
    fn from_sorted(entries: Vec<(K, V)>) -> Self {
        let len = entries.len();
        if len == 0 {
            return Self::new();
        }

        let mut level: Vec<(K, Arc<Node<K, V>>)> = Vec::new();
        let mut source = entries.into_iter();
        for size in even_chunks(len) {
            let chunk: Vec<(K, V)> = source.by_ref().take(size).collect();
            let min = chunk[0].0.clone();
            level.push((min, Arc::new(Node::Leaf(chunk))));
        }

        let mut height = 0u8;
        while level.len() > 1 {
            let mut next = Vec::new();
            let mut source = level.into_iter();
            let sizes: Vec<usize> = even_chunks(source.len()).collect();
            for size in sizes {
                let group: Vec<(K, Arc<Node<K, V>>)> = source.by_ref().take(size).collect();
                let min = group[0].0.clone();
                let mut keys = Vec::with_capacity(
                    size.checked_sub(1)
                        .expect("internal group must be non-empty"),
                );
                let mut children = Vec::with_capacity(size);
                for (i, (child_min, child)) in group.into_iter().enumerate() {
                    if i > 0 {
                        keys.push(child_min);
                    }
                    children.push(child);
                }
                next.push((min, Arc::new(Node::Internal(Internal { keys, children }))));
            }
            level = next;
            height = height.checked_add(1).expect("tree height overflow");
        }

        let (_, root) = level.pop().expect("non-empty level");
        Self { root, height, len }
    }
}

/// Splits `n` items into near-equal groups no larger than `BULK_FILL`.
fn even_chunks(n: usize) -> impl Iterator<Item = usize> {
    let groups = n.div_ceil(BULK_FILL).max(1);
    let base = n
        .checked_div(groups)
        .expect("chunk group count is non-zero");
    let extra = n
        .checked_rem(groups)
        .expect("chunk group count is non-zero");
    (0..groups).map(move |i| {
        base.checked_add(usize::from(i < extra))
            .expect("chunk size overflow")
    })
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
    type IntoIter = std::vec::IntoIter<(K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
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

/// Right half produced when a node overflows: `(separator, new right sibling)`.
type Split<K, V> = Option<(K, Arc<Node<K, V>>)>;

impl<K, V> PersistentOrdMap<K, V>
where
    K: Ord + Clone,
    V: Clone,
{
    /// Inserts a key/value pair, returning the previous value if present.
    ///
    /// # Panics
    ///
    /// Panics only if the map length or tree height exceeds its representable
    /// integer range, which is prevented by the allocation and node invariants.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let (old, split) = insert_rec(&mut self.root, key, value);
        if let Some((separator, right)) = split {
            let left = Arc::clone(&self.root);
            self.root = Arc::new(Node::Internal(Internal {
                keys: vec![separator],
                children: vec![left, right],
            }));
            self.height = self.height.checked_add(1).expect("tree height overflow");
        }
        if old.is_none() {
            self.len = self.len.checked_add(1).expect("map length overflow");
        }
        old
    }

    /// Removes a key, returning its value if present.
    ///
    /// # Panics
    ///
    /// Panics only if an internal length or height invariant is violated.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let removed = remove_rec(&mut self.root, key)?;
        self.len = self.len.checked_sub(1).expect("map length underflow");

        loop {
            let only_child = match &*self.root {
                Node::Internal(internal) if internal.children.len() == 1 => {
                    Arc::clone(&internal.children[0])
                }
                _ => break,
            };
            self.root = only_child;
            self.height = self.height.checked_sub(1).expect("tree height underflow");
        }
        if self.len == 0 {
            *self = Self::new();
        }
        Some(removed)
    }
}

fn insert_rec<K, V>(node: &mut Arc<Node<K, V>>, key: K, value: V) -> (Option<V>, Split<K, V>)
where
    K: Ord + Clone,
    V: Clone,
{
    match Arc::make_mut(node) {
        Node::Leaf(entries) => match entries.binary_search_by(|(k, _)| k.cmp(&key)) {
            Ok(i) => (Some(mem::replace(&mut entries[i].1, value)), None),
            Err(i) => {
                entries.insert(i, (key, value));
                if entries.len() > MAX_FANOUT {
                    let split_at = entries
                        .len()
                        .checked_div(2)
                        .expect("split divisor is non-zero");
                    let right = entries.split_off(split_at);
                    let separator = right[0].0.clone();
                    (None, Some((separator, Arc::new(Node::Leaf(right)))))
                } else {
                    (None, None)
                }
            }
        },
        Node::Internal(internal) => {
            let idx = internal.child_index(&key);
            let (old, split) = insert_rec(&mut internal.children[idx], key, value);
            let Some((separator, right)) = split else {
                return (old, None);
            };
            internal.keys.insert(idx, separator);
            internal
                .children
                .insert(idx.checked_add(1).expect("child index overflow"), right);
            if internal.children.len() <= MAX_FANOUT {
                return (old, None);
            }
            let mid = internal
                .children
                .len()
                .checked_div(2)
                .expect("split divisor is non-zero");
            let right_children = internal.children.split_off(mid);
            let mut right_keys = internal
                .keys
                .split_off(mid.checked_sub(1).expect("split midpoint must be non-zero"));
            let promoted = right_keys.remove(0);
            let sibling = Arc::new(Node::Internal(Internal {
                keys: right_keys,
                children: right_children,
            }));
            (old, Some((promoted, sibling)))
        }
    }
}

/// Removes `key` in a single descent, copying the path only if the key exists.
///
/// An unshared node is edited in place (nothing is modified until the leaf
/// confirms the key is present); a shared node is rebuilt by `remove_copied`,
/// which allocates only on a hit.
fn remove_rec<K, V, Q>(node: &mut Arc<Node<K, V>>, key: &Q) -> Option<V>
where
    K: Ord + Clone + Borrow<Q>,
    V: Clone,
    Q: Ord + ?Sized,
{
    let Some(unique) = Arc::get_mut(node) else {
        let (rebuilt, removed) = remove_copied(node, key)?;
        *node = Arc::new(rebuilt);
        return Some(removed);
    };
    match unique {
        Node::Leaf(entries) => {
            let i = entries
                .binary_search_by(|(k, _)| Borrow::<Q>::borrow(k).cmp(key))
                .ok()?;
            Some(entries.remove(i).1)
        }
        Node::Internal(internal) => {
            let idx = internal.child_index(key);
            let removed = remove_rec(&mut internal.children[idx], key)?;
            internal.drop_if_empty(idx);
            Some(removed)
        }
    }
}

/// Returns a copy of shared `node` without `key`, or `None` if it is absent.
fn remove_copied<K, V, Q>(node: &Node<K, V>, key: &Q) -> Option<(Node<K, V>, V)>
where
    K: Ord + Clone + Borrow<Q>,
    V: Clone,
    Q: Ord + ?Sized,
{
    match node {
        Node::Leaf(entries) => {
            let i = entries
                .binary_search_by(|(k, _)| Borrow::<Q>::borrow(k).cmp(key))
                .ok()?;
            let mut rest = Vec::with_capacity(entries.len().saturating_sub(1));
            rest.extend_from_slice(&entries[..i]);
            rest.extend_from_slice(&entries[i.saturating_add(1)..]);
            Some((Node::Leaf(rest), entries[i].1.clone()))
        }
        Node::Internal(internal) => {
            let idx = internal.child_index(key);
            let (child, removed) = remove_copied(&internal.children[idx], key)?;
            let mut copy = Internal {
                keys: internal.keys.clone(),
                children: internal.children.clone(),
            };
            copy.children[idx] = Arc::new(child);
            copy.drop_if_empty(idx);
            Some((Node::Internal(copy), removed))
        }
    }
}

/// An ancestor's children and the index of the next child to visit.
type Ancestor<'a, K, V> = (&'a [Arc<Node<K, V>>], usize);

/// Ordered map iterator.
pub struct Iter<'a, K, V> {
    stack: Vec<Ancestor<'a, K, V>>,
    leaf: &'a [(K, V)],
    pos: usize,
}

impl<'a, K, V> Iter<'a, K, V> {
    const fn empty() -> Self {
        Self {
            stack: Vec::new(),
            leaf: &[],
            pos: 0,
        }
    }

    /// Positions the iterator at the first entry of `node`'s subtree.
    fn descend_leftmost(&mut self, mut node: &'a Node<K, V>) {
        loop {
            match node {
                Node::Leaf(entries) => {
                    self.leaf = entries;
                    self.pos = 0;
                    return;
                }
                Node::Internal(internal) => {
                    let Some(first) = internal.children.first() else {
                        self.leaf = &[];
                        self.pos = 0;
                        return;
                    };
                    self.stack.push((internal.children.as_slice(), 1));
                    node = first;
                }
            }
        }
    }

    /// Positions the iterator at the first entry `>= key` (or `> key`).
    fn seek(root: &'a Node<K, V>, key: &K, inclusive: bool) -> Self
    where
        K: Ord,
    {
        let mut iter = Self::empty();
        let mut node = root;
        loop {
            match node {
                Node::Leaf(entries) => {
                    iter.leaf = entries;
                    iter.pos = entries.partition_point(
                        |(k, _)| {
                            if inclusive {
                                k < key
                            } else {
                                k <= key
                            }
                        },
                    );
                    return iter;
                }
                Node::Internal(internal) => {
                    if internal.children.is_empty() {
                        return iter;
                    }
                    let idx = internal.child_index(key);
                    iter.stack.push((
                        internal.children.as_slice(),
                        idx.checked_add(1).expect("iterator index overflow"),
                    ));
                    node = &internal.children[idx];
                }
            }
        }
    }
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((key, value)) = self.leaf.get(self.pos).map(|e| (&e.0, &e.1)) {
                self.pos = self.pos.checked_add(1).expect("iterator position overflow");
                return Some((key, value));
            }
            // Current leaf exhausted: move to the next unvisited child.
            loop {
                let frame = self.stack.last_mut()?;
                let children: &'a [Arc<Node<K, V>>] = frame.0;
                if let Some(child) = children.get(frame.1) {
                    frame.1 = frame.1.checked_add(1).expect("iterator index overflow");
                    self.descend_leftmost(child);
                    break;
                }
                self.stack.pop();
            }
        }
    }
}

/// Iterator over a key range of a [`PersistentOrdMap`].
pub struct Range<'a, K, V, R> {
    iter: Iter<'a, K, V>,
    bounds: R,
}

impl<'a, K: Ord, V, R: RangeBounds<K>> Iterator for Range<'a, K, V, R> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let (key, value) = self.iter.next()?;
        let within = match self.bounds.end_bound() {
            Bound::Included(end) => key <= end,
            Bound::Excluded(end) => key < end,
            Bound::Unbounded => true,
        };
        if within {
            Some((key, value))
        } else {
            self.iter = Iter::empty();
            None
        }
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
///
/// Lazy: items are produced as the dual cursors advance, so nothing is
/// buffered and an early exit (`next().is_none()`, `take(n)`) only pays for the
/// part of the trees it actually visited.
pub struct Diff<'a, 'b, K, V> {
    walker: DiffWalker<'a, 'b, K, V>,
}

impl<'a, 'b, K: Ord, V: PartialEq> Iterator for Diff<'a, 'b, K, V> {
    type Item = DiffItem<'a, 'b, K, V>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walker.next_item()
    }
}

/// The next unconsumed item of a diff cursor.
enum Head<'a, K, V> {
    Node(&'a Arc<Node<K, V>>),
    Entry(&'a K, &'a V),
}

/// One level of a diff cursor's stack of pending items.
enum Frame<'a, K, V> {
    Nodes {
        items: &'a [Arc<Node<K, V>>],
        idx: usize,
        height: u8,
    },
    Entries {
        items: &'a [(K, V)],
        idx: usize,
    },
}

/// Walks a tree in key order, exposing subtrees as units until they are opened.
struct Cursor<'a, K, V> {
    stack: Vec<Frame<'a, K, V>>,
}

impl<'a, K, V> Cursor<'a, K, V> {
    fn new(root: &'a Arc<Node<K, V>>, height: u8) -> Self {
        Self {
            stack: vec![Frame::Nodes {
                items: core::slice::from_ref(root),
                idx: 0,
                height,
            }],
        }
    }

    /// Returns the next item without consuming it, dropping exhausted frames.
    fn head(&mut self) -> Option<Head<'a, K, V>> {
        loop {
            match self.stack.last()? {
                Frame::Nodes { items, idx, .. } => {
                    let items: &'a [Arc<Node<K, V>>] = items;
                    if let Some(node) = items.get(*idx) {
                        return Some(Head::Node(node));
                    }
                }
                Frame::Entries { items, idx } => {
                    let items: &'a [(K, V)] = items;
                    if let Some(entry) = items.get(*idx) {
                        return Some(Head::Entry(&entry.0, &entry.1));
                    }
                }
            }
            self.stack.pop();
        }
    }

    /// Consumes the head item (a whole subtree, or one entry) unread.
    fn skip(&mut self) {
        match self.stack.last_mut() {
            Some(Frame::Nodes { idx, .. } | Frame::Entries { idx, .. }) => {
                *idx = idx.checked_add(1).expect("cursor index overflow");
            }
            None => {}
        }
    }

    /// Replaces a head subtree with its children (or its entries, for a leaf).
    fn expand(&mut self) {
        let (node, height) = match self.stack.last_mut() {
            Some(Frame::Nodes { items, idx, height }) => {
                let items: &'a [Arc<Node<K, V>>] = items;
                let Some(node) = items.get(*idx) else { return };
                *idx = idx.checked_add(1).expect("cursor index overflow");
                (node, *height)
            }
            _ => return,
        };
        match &**node {
            Node::Leaf(entries) => self.stack.push(Frame::Entries {
                items: entries,
                idx: 0,
            }),
            Node::Internal(internal) => self.stack.push(Frame::Nodes {
                items: &internal.children,
                idx: 0,
                height: height.saturating_sub(1),
            }),
        }
    }
}

/// Merges two trees in key order, skipping subtrees both sides share.
struct DiffWalker<'a, 'b, K, V> {
    left: Cursor<'a, K, V>,
    right: Cursor<'b, K, V>,
    /// Nodes opened so far; tests use it to prove subtree skipping.
    expansions: usize,
}

impl<'a, 'b, K: Ord, V: PartialEq> DiffWalker<'a, 'b, K, V> {
    fn new(old: &'a PersistentOrdMap<K, V>, new: &'b PersistentOrdMap<K, V>) -> Self {
        Self {
            left: Cursor::new(&old.root, old.height),
            right: Cursor::new(&new.root, new.height),
            expansions: 0,
        }
    }

    fn opened(&mut self, count: usize) {
        self.expansions = self
            .expansions
            .checked_add(count)
            .expect("diff expansion count overflow");
    }

    /// Advances the cursors until the next difference, or the end.
    fn next_item(&mut self) -> Option<DiffItem<'a, 'b, K, V>> {
        loop {
            match (self.left.head(), self.right.head()) {
                (None, None) => return None,
                (Some(Head::Entry(key, value)), None) => {
                    self.left.skip();
                    return Some(DiffItem::Remove(key, value));
                }
                (None, Some(Head::Entry(key, value))) => {
                    self.right.skip();
                    return Some(DiffItem::Add(key, value));
                }
                (Some(Head::Node(_)), None) => {
                    self.left.expand();
                    self.opened(1);
                }
                (None, Some(Head::Node(_))) => {
                    self.right.expand();
                    self.opened(1);
                }
                (Some(Head::Entry(lk, lv)), Some(Head::Entry(rk, rv))) => match lk.cmp(rk) {
                    Ordering::Less => {
                        self.left.skip();
                        return Some(DiffItem::Remove(lk, lv));
                    }
                    Ordering::Greater => {
                        self.right.skip();
                        return Some(DiffItem::Add(rk, rv));
                    }
                    Ordering::Equal => {
                        self.left.skip();
                        self.right.skip();
                        if lv != rv {
                            return Some(DiffItem::Update {
                                old: (lk, lv),
                                new: (rk, rv),
                            });
                        }
                    }
                },
                (Some(Head::Node(ln)), Some(Head::Node(rn))) => {
                    let opened = advance_nodes(&mut self.left, &mut self.right, ln, rn);
                    self.opened(opened);
                }
                (Some(Head::Node(ln)), Some(Head::Entry(rk, rv))) => match ln.first_key() {
                    None => self.left.skip(),
                    Some(lk) if lk > rk => {
                        self.right.skip();
                        return Some(DiffItem::Add(rk, rv));
                    }
                    Some(_) => {
                        self.left.expand();
                        self.opened(1);
                    }
                },
                (Some(Head::Entry(lk, lv)), Some(Head::Node(rn))) => match rn.first_key() {
                    None => self.right.skip(),
                    Some(rk) if rk > lk => {
                        self.left.skip();
                        return Some(DiffItem::Remove(lk, lv));
                    }
                    Some(_) => {
                        self.right.expand();
                        self.opened(1);
                    }
                },
            }
        }
    }
}

/// Handles two subtrees at the heads of both cursors; returns nodes opened.
fn advance_nodes<K: Ord, V>(
    left: &mut Cursor<'_, K, V>,
    right: &mut Cursor<'_, K, V>,
    ln: &Arc<Node<K, V>>,
    rn: &Arc<Node<K, V>>,
) -> usize {
    if Arc::ptr_eq(ln, rn) {
        left.skip();
        right.skip();
        return 0;
    }
    let (Some(lk), Some(rk)) = (ln.first_key(), rn.first_key()) else {
        // An empty subtree holds nothing to compare; drop it.
        if ln.first_key().is_none() {
            left.skip();
        } else {
            right.skip();
        }
        return 0;
    };
    match lk.cmp(rk) {
        Ordering::Less => {
            left.expand();
            1
        }
        Ordering::Greater => {
            right.expand();
            1
        }
        Ordering::Equal => {
            // Open the taller side first so subtrees can realign across a
            // height difference; open both when level.
            let (left_height, right_height) = (frame_height(left), frame_height(right));
            let mut opened: usize = 0;
            if left_height >= right_height {
                left.expand();
                opened = opened
                    .checked_add(1)
                    .expect("diff expansion count overflow");
            }
            if right_height >= left_height {
                right.expand();
                opened = opened
                    .checked_add(1)
                    .expect("diff expansion count overflow");
            }
            opened
        }
    }
}

/// Height of the subtree at the cursor's head (0 for a leaf).
fn frame_height<K, V>(cursor: &Cursor<'_, K, V>) -> u8 {
    match cursor.stack.last() {
        Some(Frame::Nodes { height, .. }) => *height,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::vec::Vec;

    use super::{DiffItem, Node, PersistentOrdMap, MAX_FANOUT};

    /// Deterministic xorshift generator so failures reproduce.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next()
                .checked_rem(bound)
                .expect("random bound must be non-zero")
        }
    }

    /// Checks every structural invariant and returns the entry count.
    fn check_node<K: Ord + Clone + core::fmt::Debug, V>(
        node: &Node<K, V>,
        depth: u8,
        height: u8,
        lower: Option<&K>,
        upper: Option<&K>,
        is_root: bool,
    ) -> usize {
        match node {
            Node::Leaf(entries) => {
                assert_eq!(depth, height, "leaf at wrong depth");
                assert!(entries.len() <= MAX_FANOUT, "leaf overflow");
                assert!(is_root || !entries.is_empty(), "empty non-root leaf");
                assert!(entries.windows(2).all(|w| w[0].0 < w[1].0), "leaf unsorted");
                if let (Some(lo), Some(first)) = (lower, entries.first()) {
                    assert!(&first.0 >= lo, "leaf below lower bound");
                }
                if let (Some(hi), Some(last)) = (upper, entries.last()) {
                    assert!(&last.0 < hi, "leaf at or above upper bound");
                }
                entries.len()
            }
            Node::Internal(internal) => {
                assert!(depth < height, "internal node at leaf depth");
                assert!(internal.children.len() <= MAX_FANOUT, "internal overflow");
                assert!(!internal.children.is_empty(), "empty internal node");
                assert_eq!(
                    internal
                        .keys
                        .len()
                        .checked_add(1)
                        .expect("child count overflow"),
                    internal.children.len()
                );
                assert!(internal.keys.windows(2).all(|w| w[0] < w[1]));
                let mut total: usize = 0;
                for (i, child) in internal.children.iter().enumerate() {
                    let lo = if i == 0 {
                        lower
                    } else {
                        Some(&internal.keys[i.checked_sub(1).expect("non-zero child index")])
                    };
                    let hi = internal.keys.get(i).or(upper);
                    total = total
                        .checked_add(check_node(
                            child,
                            depth.checked_add(1).expect("tree depth overflow"),
                            height,
                            lo,
                            hi,
                            false,
                        ))
                        .expect("entry count overflow");
                }
                total
            }
        }
    }

    fn check<K: Ord + Clone + core::fmt::Debug, V>(map: &PersistentOrdMap<K, V>) {
        let counted = check_node(&map.root, 0, map.height, None, None, true);
        assert_eq!(counted, map.len, "len out of sync");
    }

    fn assert_matches(map: &PersistentOrdMap<u64, u64>, model: &BTreeMap<u64, u64>) {
        check(map);
        assert_eq!(map.len(), model.len());
        assert!(map
            .iter()
            .map(|(k, v)| (*k, *v))
            .eq(model.iter().map(|(k, v)| (*k, *v))));
    }

    /// Naive reference: what a plain merge of the two maps would report.
    fn naive_diff(old: &BTreeMap<u64, u64>, new: &BTreeMap<u64, u64>) -> Vec<(&'static str, u64)> {
        let mut out = Vec::new();
        let mut keys: Vec<u64> = old.keys().chain(new.keys()).copied().collect();
        keys.sort_unstable();
        keys.dedup();
        for key in keys {
            match (old.get(&key), new.get(&key)) {
                (Some(_), None) => out.push(("remove", key)),
                (None, Some(_)) => out.push(("add", key)),
                (Some(a), Some(b)) if a != b => out.push(("update", key)),
                _ => {}
            }
        }
        out
    }

    fn tree_diff(
        old: &PersistentOrdMap<u64, u64>,
        new: &PersistentOrdMap<u64, u64>,
    ) -> Vec<(&'static str, u64)> {
        old.diff(new)
            .map(|item| match item {
                DiffItem::Add(k, _) => ("add", *k),
                DiffItem::Remove(k, _) => ("remove", *k),
                DiffItem::Update { old: (k, _), .. } => ("update", *k),
            })
            .collect()
    }

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
                DiffItem::Add(key, value) => changes.push(("add", *key, *value)),
                DiffItem::Remove(key, value) => changes.push(("remove", *key, *value)),
                DiffItem::Update {
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

    #[test]
    fn sequential_inserts_and_removes_keep_invariants() {
        for descending in [false, true] {
            let mut map = PersistentOrdMap::new();
            let mut model = BTreeMap::new();
            let keys: Vec<u64> = if descending {
                (0..4000).rev().collect()
            } else {
                (0..4000).collect()
            };
            for key in &keys {
                assert_eq!(map.insert(*key, key * 2), model.insert(*key, key * 2));
            }
            assert_matches(&map, &model);
            assert!(map.height >= 2, "test must exercise a multi-level tree");

            for key in keys.iter().step_by(3) {
                assert_eq!(map.remove(key), model.remove(key));
            }
            assert_matches(&map, &model);
            assert_eq!(map.remove(&999_999), None);

            for key in keys {
                assert_eq!(map.remove(&key), model.remove(&key));
            }
            assert!(map.is_empty());
            assert_matches(&map, &model);
        }
    }

    #[test]
    fn random_operations_match_btreemap_and_snapshots_stay_immutable() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut map = PersistentOrdMap::new();
        let mut model = BTreeMap::new();
        let mut snapshots: Vec<(PersistentOrdMap<u64, u64>, BTreeMap<u64, u64>)> = Vec::new();

        for step in 0..30_000u64 {
            let key = rng.below(3000);
            match rng.below(10) {
                0..=5 => assert_eq!(map.insert(key, step), model.insert(key, step)),
                6..=8 => assert_eq!(map.remove(&key), model.remove(&key)),
                _ => assert_eq!(map.get(&key), model.get(&key)),
            }
            if step.checked_rem(2500).expect("test divisor is non-zero") == 0 {
                check(&map);
                snapshots.push((map.clone(), model.clone()));
            }
        }
        assert_matches(&map, &model);
        for (snapshot, snapshot_model) in &snapshots {
            assert_matches(snapshot, snapshot_model);
        }
    }

    #[test]
    fn range_matches_btreemap() {
        use core::ops::Bound::{Excluded, Included, Unbounded};

        let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
        let model: BTreeMap<u64, u64> =
            (0..3000).map(|_| (rng.below(10_000), rng.next())).collect();
        let map: PersistentOrdMap<u64, u64> = model.iter().map(|(k, v)| (*k, *v)).collect();
        check(&map);

        for _ in 0..500 {
            let a = rng.below(10_500);
            let b = rng.below(10_500);
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            for bounds in [
                (Included(lo), Included(hi)),
                (Included(lo), Excluded(hi)),
                (Excluded(lo), Included(hi)),
                (Unbounded, Excluded(hi)),
                (Included(lo), Unbounded),
            ] {
                let got: Vec<_> = map.range(bounds).map(|(k, v)| (*k, *v)).collect();
                let want: Vec<_> = model.range(bounds).map(|(k, v)| (*k, *v)).collect();
                assert_eq!(got, want, "range {bounds:?}");
            }
        }
    }

    #[test]
    fn bulk_build_matches_incremental_and_last_duplicate_wins() {
        let entries: Vec<(u64, u64)> = (0u64..5000)
            .map(|i| {
                (
                    i.checked_mul(7919)
                        .expect("test key multiplication overflow")
                        .checked_rem(6007)
                        .expect("test divisor is non-zero"),
                    i,
                )
            })
            .collect();
        let bulk: PersistentOrdMap<u64, u64> = entries.iter().copied().collect();
        let mut incremental = PersistentOrdMap::new();
        let mut model = BTreeMap::new();
        for (k, v) in &entries {
            incremental.insert(*k, *v);
            model.insert(*k, *v);
        }
        assert_matches(&bulk, &model);
        assert_matches(&incremental, &model);
        assert!(bulk == incremental);
    }

    #[test]
    fn diff_matches_naive_merge_on_random_edits() {
        let mut rng = Rng(0x1234_5678_9ABC_DEF1);
        for round in 0usize..40 {
            let base_size =
                [0, 5, 40, 500, 4000][round.checked_rem(5).expect("test divisor is non-zero")];
            let base: PersistentOrdMap<u64, u64> = (0..base_size).map(|i| (i * 3, i)).collect();
            let mut base_model: BTreeMap<u64, u64> = (0..base_size).map(|i| (i * 3, i)).collect();
            let mut other = base.clone();
            for _ in 0..rng.below(60) {
                let key = rng.below(
                    base_size
                        .checked_mul(3)
                        .and_then(|n| n.checked_add(10))
                        .expect("test key bound overflow"),
                );
                if rng.below(3) == 0 {
                    other.remove(&key);
                } else {
                    other.insert(key, rng.next());
                }
            }
            let other_model: BTreeMap<u64, u64> = other.iter().map(|(k, v)| (*k, *v)).collect();
            check(&other);
            assert_eq!(
                tree_diff(&base, &other),
                naive_diff(&base_model, &other_model)
            );
            // Reverse direction too.
            assert_eq!(
                tree_diff(&other, &base),
                naive_diff(&other_model, &base_model)
            );
            base_model.clear();
        }
    }

    #[test]
    fn diff_skips_shared_subtrees() {
        let base: PersistentOrdMap<u64, u64> = (0..50_000).map(|i| (i, i)).collect();
        assert!(base.height >= 2);

        // Nothing changed: the roots are the same Arc, so nothing is opened.
        assert_eq!(base.diff_expansions(&base.clone()), 0);

        // One edit opens only the changed path, not the 50k-entry map.
        let mut edited = base.clone();
        edited.insert(25_000, 0);
        let opened = base.diff_expansions(&edited);
        assert!(opened <= 16, "opened {opened} nodes for a one-key change");
        assert_eq!(tree_diff(&base, &edited), [("update", 25_000)]);

        // A handful of scattered edits scale with the edits, not the map.
        let mut many = base.clone();
        for key in [10, 9_000, 20_000, 31_000, 45_000, 49_999] {
            many.remove(&key);
        }
        let opened = base.diff_expansions(&many);
        assert!(opened <= 6 * 16, "opened {opened} nodes for six removals");
    }

    #[test]
    fn diff_realigns_across_a_height_change() {
        // Grow a tree one level taller than its ancestor snapshot.
        let mut map: PersistentOrdMap<u64, u64> =
            (0..(MAX_FANOUT as u64 * 24)).map(|i| (i * 2, i)).collect();
        let before = map.clone();
        let mut model: BTreeMap<u64, u64> = map.iter().map(|(k, v)| (*k, *v)).collect();
        let mut key = 1;
        while map.height == before.height {
            map.insert(key, key);
            model.insert(key, key);
            key = key.checked_add(2).expect("test key overflow");
        }
        check(&map);
        let before_model: BTreeMap<u64, u64> = before.iter().map(|(k, v)| (*k, *v)).collect();
        assert_eq!(tree_diff(&before, &map), naive_diff(&before_model, &model));
        assert_eq!(tree_diff(&map, &before), naive_diff(&model, &before_model));
    }

    #[test]
    fn equality_uses_structure_not_identity() {
        let a: PersistentOrdMap<u64, u64> = (0..1000).map(|i| (i, i)).collect();
        let mut b = a.clone();
        assert!(a == b);
        b.insert(500, 0);
        assert!(a != b);
        b.insert(500, 500);
        assert!(a == b);
        assert!(!a.ptr_eq(&b));
    }
}
