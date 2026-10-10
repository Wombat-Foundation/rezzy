//! Generic HAMT primitives used by higher-level state handling.
//!
//! Layout:
//! - `hash`: keyed structural hashing for subtree identity
//! - `codec`: dense on-disk encoding for persisted internal nodes
//! - `delta`: subtree differencing for set isolation
//! - `audit`: multi-root reachability audit for storage GC
//! - `gc`: experimental incremental refcount bookkeeping for integrations
//!   with a strictly linear root history (behind `unstable-refcount-gc`)
//! - `tests`: regression coverage for the generic HAMT core
//!
//! # Release notes
//!
//! - **0.6.0**: the HAMT storage-GC reachability-audit API was renamed to
//!   disambiguate it from `resolve::reachability`'s unrelated event-DAG
//!   concept. `ReachabilityAudit` → [`NodeReachabilityAudit`],
//!   `reachability_audit` → [`node_reachability_audit`],
//!   `BitmapReachabilityAudit` → [`BitmapNodeReachabilityAudit`], and
//!   `bitmap_reachability_audit` → [`bitmap_node_reachability_audit`]. The old
//!   names were removed (no aliases remain), so downstream code must use the
//!   new names; at the time of the rename neither had any caller.

use core::{
    borrow::Borrow,
    fmt,
    hash::{Hash, Hasher},
};
use std::{sync::Arc, vec, vec::Vec};

pub mod audit;
pub mod codec;
pub mod delta;
#[cfg(any(test, feature = "unstable-refcount-gc"))]
pub mod gc;
pub mod hash;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

pub use audit::{bitmap_node_reachability_audit, BitmapAuditError, BitmapNodeReachabilityAudit};
pub use audit::{
    node_reachability_audit, unreachable_node_hashes, IndexedUniverse, NodeReachabilityAudit,
    UniverseTooLarge,
};
pub use codec::{
    HamtCodec, PersistedInternalNode, HAMT_NODE_MAGIC, HAMT_ROOT_MAGIC, HAMT_WIRE_VERSION,
};
pub use delta::{
    diff_hamt_nodes, diff_node_hashes, isolate_delta, reachable_node_hashes,
    walk_reachable_node_hashes, Delta, DeltaResult, HamtTraversalError, NodeHashDelta,
};
#[cfg(feature = "unstable-refcount-gc")]
pub use gc::{LinearRootChain, RefcountTable, RefcountUnderflow};
pub use hash::{
    state_group_id_from_lthash, RootHandle, StateGroupId, StructuralHash, HAMT_CODEC_VERSION,
    HAMT_ROUTING_VERSION,
};

/// 256-bit routing path hash for a key in the HAMT.
pub type KeyPathHash = StructuralHash;

/// Shared pointer to a (possibly interned) HAMT node.
pub(crate) type NodePtr<K, V> = Arc<HamtNode<K, V>>;

/// Resolves a child node's [`StructuralHash`] to that node, or returns `E` if
/// it cannot be fetched.
///
/// This is the callback every HAMT descent, diff, and mutation entry point
/// takes, named so callers can spell the bound once instead of repeating the
/// full `FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>` signature
/// (e.g. to store a `Box<dyn NodeResolver<..>>` or write a generic wrapper).
///
/// It is blanket-implemented for every matching `FnMut` closure and carries no
/// methods, so callers pass ordinary closures and never implement it
/// themselves.
pub trait NodeResolver<K, V, E>: FnMut(&StructuralHash) -> Result<NodePtr<K, V>, E> {}

impl<K, V, E, F> NodeResolver<K, V, E> for F where
    F: FnMut(&StructuralHash) -> Result<NodePtr<K, V>, E>
{
}

/// A key storable in a HAMT: hashable, comparable, cloneable, and codec-able.
///
/// Blanket-implemented; callers never implement it themselves. Names the bound
/// shared by the HAMT descent, mutation, and persistence entry points.
pub trait HamtKey: Hash + Eq + Clone + HamtCodec {}

impl<K: Hash + Eq + Clone + HamtCodec> HamtKey for K {}

/// A value storable in a HAMT: cloneable and codec-able.
///
/// Blanket-implemented; callers never implement it themselves.
pub trait HamtValue: Clone + HamtCodec {}

impl<V: Clone + HamtCodec> HamtValue for V {}

/// The outcome of descending one level of a HAMT with a batch of requested keys.
#[derive(Debug, PartialEq, Eq)]
pub struct DescendResult<V> {
    /// Keys found at this level with their associated value.
    pub found: Vec<(KeyPathHash, V)>,
    /// Keys proven to be absent at this level (the corresponding slot bit was clear).
    pub absent: Vec<KeyPathHash>,
    /// Keys that need to descend further (to `depth + 1`), grouped by the child node's `StructuralHash`.
    pub pending: Vec<(StructuralHash, Vec<KeyPathHash>)>,
}

/// Errors that can occur during level-synchronous descent over persisted node bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum DescendError {
    /// Node decoding failed (invalid version or truncated buffer).
    Decode(&'static str),
    /// Invariant violation: bitmap indicated a leaf or child slot, but the array index was missing.
    CorruptNode(&'static str),
}

impl fmt::Display for DescendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(msg) => write!(f, "hamt descend decode error: {msg}"),
            Self::CorruptNode(msg) => write!(f, "hamt descend corrupt node: {msg}"),
        }
    }
}

impl core::error::Error for DescendError {}

/// A single step in a published state-group chain.
pub struct ChainStep<K, V> {
    /// The resolved root at this step.
    pub root: NodePtr<K, V>,
    /// The structural hash of `root`.
    pub root_hash: StructuralHash,
    /// The value displaced by this mutation, if any (needed for lattice subtraction).
    pub displaced: Option<V>,
    /// Nodes created by this step relative to the IMMEDIATELY PRECEDING root.
    ///
    /// These nodes must be written to storage before this step's `state_group` is published.
    pub created: Vec<(StructuralHash, Vec<u8>)>,
}

use hash::StructuralHashBuilder;

const STRUCTURAL_HASH_DOMAIN_V1: &[u8] = b"rezzy:hamt:structural-hash:v1\0";

const HAMT_BRANCH_BITS: usize = 5;
const HAMT_BRANCH_FACTOR: usize = 1 << HAMT_BRANCH_BITS;
const HAMT_BRANCH_MASK: u16 = 0b1_1111;
const HAMT_MAX_DEPTH: usize =
    (core::mem::size_of::<StructuralHash>() * 8).div_ceil(HAMT_BRANCH_BITS);

/// A reference to a child node in the HAMT.
#[derive(Clone, Debug)]
pub enum NodeRef<K, V> {
    /// A fully loaded child node.
    Resolved(NodePtr<K, V>),
    /// A lazy-loaded child node that hasn't been fetched from storage yet.
    Lazy(StructuralHash),
}

impl<K, V> NodeRef<K, V> {
    /// Gets the structural hash of the child node without loading it.
    #[must_use]
    pub fn structural_hash(&self) -> StructuralHash {
        match self {
            Self::Resolved(node) => node.structural_hash,
            Self::Lazy(hash) => *hash,
        }
    }
}

/// A node in the 32-way CHAMP (Compressed Hash Array Mapped Prefix) trie.
#[derive(Debug)]
pub struct HamtNode<K, V> {
    /// Bitmap marking which of the 32 slots contain leaf data.
    pub datamap: u32,
    /// Bitmap marking which of the 32 slots contain child internal nodes.
    pub nodemap: u32,
    /// The inline array of leaf key-value pairs. Length matches `datamap.count_ones()`.
    pub leaves: Vec<(K, V)>,
    /// The array of child nodes. Length matches `nodemap.count_ones()`.
    pub children: Vec<NodeRef<K, V>>,
    /// Structural hash for O(1) subtree equivalence checks.
    pub structural_hash: StructuralHash,
}

impl<K, V> HamtNode<K, V> {
    /// Computes the structural hash of this node from its contents.
    ///
    pub fn compute_structural_hash(
        key: &[u8],
        datamap: u32,
        nodemap: u32,
        leaves: &[(K, V)],
        children: &[NodeRef<K, V>],
    ) -> StructuralHash
    where
        K: HamtCodec,
        V: HamtCodec,
    {
        let child_hashes = children
            .iter()
            .map(NodeRef::structural_hash)
            .collect::<Vec<_>>();
        let canonical_bytes =
            PersistedInternalNode::encode_v1_parts(datamap, nodemap, leaves, &child_hashes);
        let mut mac = StructuralHashBuilder::new(key);
        mac.write(STRUCTURAL_HASH_DOMAIN_V1);
        mac.write(&canonical_bytes);
        mac.finalize()
    }

    /// Looks up a key in a fully materialized HAMT.
    ///
    /// This is the cheapest read path and should be used when the tree is
    /// already fully resolved in memory.
    ///
    /// This variant hashes the key with the same keyed structural hash used
    /// for trees built by [`build_hamt`]. If the tree was built with
    /// [`build_hamt_with_key_hash`], use [`Self::get_with_key_hash`] or
    /// [`Self::get_by_path_hash`] with the exact routing hash used when the
    /// tree was constructed.
    #[must_use]
    pub fn get<Q>(&self, structural_key: &[u8], key: &Q) -> Option<&V>
    where
        K: Hash + Eq + Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let path_hash = key_path_hash(structural_key, key);
        self.get_by_path_hash(key, &path_hash)
    }

    /// Looks up a key using a caller-provided path-hash function.
    ///
    /// This matches [`build_hamt_with_key_hash`] and is required when the tree
    /// was built with a custom routing function instead of the default keyed
    /// structural hash.
    #[must_use]
    pub fn get_with_key_hash<Q, F>(&self, key: &Q, mut key_hash: F) -> Option<&V>
    where
        K: Eq + Borrow<Q>,
        Q: Eq + ?Sized,
        F: FnMut(&Q) -> StructuralHash,
    {
        let path_hash = key_hash(key);
        self.get_by_path_hash(key, &path_hash)
    }

    /// Looks up a key using a caller-provided routing hash.
    ///
    /// This is the most general lookup entry point. Use it when the caller
    /// already knows the exact path hash that was used to build or mutate the
    /// tree.
    #[must_use]
    pub fn get_by_path_hash<Q>(&self, key: &Q, path_hash: &StructuralHash) -> Option<&V>
    where
        K: Eq + Borrow<Q>,
        Q: Eq + ?Sized,
    {
        self.get_by_path_hash_inner(key, path_hash, 0)
    }

    /// Looks up a key in a HAMT that may contain lazy children.
    ///
    /// Lazy children are resolved through `resolver` as needed. The returned
    /// value is cloned so the lookup does not need to hold references into
    /// transient resolved child allocations.
    ///
    /// # Errors
    /// Returns the error from `resolver` if a lazy child cannot be loaded.
    ///
    /// This variant hashes the key with the same keyed structural hash used
    /// for trees built by [`build_hamt`]. If the tree was built with
    /// [`build_hamt_with_key_hash`], use [`Self::search_with_key_hash`] or
    /// [`Self::search_by_path_hash`] with the exact routing hash used when the
    /// tree was constructed.
    pub fn search<Q, F, E>(
        &self,
        structural_key: &[u8],
        key: &Q,
        resolver: &mut F,
    ) -> Result<Option<V>, E>
    where
        K: Hash + Eq + Borrow<Q>,
        V: Clone,
        Q: Hash + Eq + ?Sized,
        F: NodeResolver<K, V, E>,
    {
        let path_hash = key_path_hash(structural_key, key);
        self.search_by_path_hash(key, &path_hash, resolver)
    }

    /// Looks up a key using a caller-provided path-hash function.
    ///
    /// This is the search equivalent of [`Self::get_with_key_hash`] for HAMTs built
    /// with [`build_hamt_with_key_hash`].
    ///
    /// # Errors
    /// Returns the error from `resolver` if a lazy child cannot be loaded.
    pub fn search_with_key_hash<Q, KeyHash, F, E>(
        &self,
        key: &Q,
        mut key_hash: KeyHash,
        resolver: &mut F,
    ) -> Result<Option<V>, E>
    where
        K: Eq + Borrow<Q>,
        V: Clone,
        Q: Eq + ?Sized,
        KeyHash: FnMut(&Q) -> StructuralHash,
        F: NodeResolver<K, V, E>,
    {
        let path_hash = key_hash(key);
        self.search_by_path_hash(key, &path_hash, resolver)
    }

    /// Looks up a key using a caller-provided routing hash.
    ///
    /// This is the most general lookup entry point. Use it when the caller
    /// already knows the exact path hash that was used to build or mutate the
    /// tree.
    ///
    /// # Errors
    /// Returns the error from `resolver` if a lazy child cannot be loaded.
    pub fn search_by_path_hash<Q, F, E>(
        &self,
        key: &Q,
        path_hash: &StructuralHash,
        resolver: &mut F,
    ) -> Result<Option<V>, E>
    where
        K: Eq + Borrow<Q>,
        V: Clone,
        Q: Eq + ?Sized,
        F: NodeResolver<K, V, E>,
    {
        // Iterative descent with a single owned cursor for resolved children:
        // each child is an `Arc`, so replacing the cursor drops the previous
        // node without retaining the ancestor chain.
        let mut cursor: Option<NodePtr<K, V>> = None;
        for depth in 0..HAMT_MAX_DEPTH {
            let node: &HamtNode<K, V> = match &cursor {
                Some(child) => child,
                None => self,
            };
            match node.slot_at(path_hash, depth) {
                Slot::Leaf((stored_key, value)) => {
                    return Ok((stored_key.borrow() == key).then(|| value.clone()));
                }
                Slot::Child(NodeRef::Resolved(child)) => cursor = Some(child.clone()),
                Slot::Child(NodeRef::Lazy(hash)) => cursor = Some(resolver(hash)?),
                Slot::Empty => return Ok(None),
            }
        }
        Ok(None)
    }

    /// Visits every key/value pair in the HAMT, resolving lazy children as
    /// needed.
    ///
    /// This is the reusable traversal primitive for callers that need to
    /// stream or collect the full contents of a subtree.
    ///
    /// # Errors
    /// Returns the error from either `resolver` or `visitor`.
    pub fn visit_entries<F, E>(
        &self,
        resolver: &mut F,
        visitor: &mut impl FnMut(&K, &V) -> Result<(), E>,
    ) -> Result<(), E>
    where
        F: NodeResolver<K, V, E>,
    {
        for (key, value) in &self.leaves {
            visitor(key, value)?;
        }

        for child in &self.children {
            let child_node = delta::resolve_node(child, resolver)?;
            child_node.visit_entries(resolver, visitor)?;
        }

        Ok(())
    }

    /// Returns `true` if this node contains no leaf entries and no child nodes.
    ///
    /// This is an O(1) structural check on the node's bitmaps.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.datamap == 0 && self.nodemap == 0
    }

    /// Checks if any key-value entry in the HAMT satisfies a predicate.
    ///
    /// Traversal proceeds lazily across child nodes, returning `Ok(true)` and
    /// stopping immediately on the first entry for which `predicate(&key, &value)`
    /// returns `Ok(true)`. Returns `Ok(false)` if no matching entry is found.
    ///
    /// # Errors
    /// Returns [`HamtTraversalError::Resolve`] with the error emitted by
    /// `resolver` or `predicate`, or [`HamtTraversalError::MaxDepthExceeded`]
    /// if the walk recurses past the deepest depth a legitimately-built HAMT
    /// can have.
    pub fn any_entry<F, E>(
        &self,
        resolver: &mut F,
        predicate: &mut impl FnMut(&K, &V) -> Result<bool, E>,
    ) -> Result<bool, HamtTraversalError<E>>
    where
        F: NodeResolver<K, V, E>,
    {
        self.any_entry_inner(resolver, predicate, 0)
    }

    fn any_entry_inner<F, E>(
        &self,
        resolver: &mut F,
        predicate: &mut impl FnMut(&K, &V) -> Result<bool, E>,
        depth: usize,
    ) -> Result<bool, HamtTraversalError<E>>
    where
        F: NodeResolver<K, V, E>,
    {
        crate::hamt::delta::check_depth(depth)?;
        let next_depth = depth.saturating_add(1);

        if self.first_matching_leaf(predicate)?.is_some() {
            return Ok(true);
        }

        for child in &self.children {
            let child_node = delta::resolve_node_checked(child, resolver)?;
            if child_node.any_entry_inner(resolver, predicate, next_depth)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Returns the first leaf (in slot order) for which `predicate` yields
    /// `Ok(true)`, resolving the predicate's error into
    /// [`HamtTraversalError`] the same way the recursive walkers do.
    fn first_matching_leaf<E>(
        &self,
        predicate: &mut impl FnMut(&K, &V) -> Result<bool, E>,
    ) -> Result<Option<&(K, V)>, HamtTraversalError<E>> {
        for entry in &self.leaves {
            if predicate(&entry.0, &entry.1).map_err(HamtTraversalError::Resolve)? {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    /// Finds the first key-value entry in the HAMT that satisfies a predicate.
    ///
    /// Traversal proceeds lazily across child nodes, returning `Ok(Some((key, value)))`
    /// and stopping immediately on the first entry for which `predicate(&key, &value)`
    /// returns `Ok(true)`. Returns `Ok(None)` if no matching entry is found.
    ///
    /// # Errors
    /// Returns [`HamtTraversalError::Resolve`] with the error emitted by
    /// `resolver` or `predicate`, or [`HamtTraversalError::MaxDepthExceeded`]
    /// if the walk recurses past the deepest depth a legitimately-built HAMT
    /// can have.
    pub fn find_entry<F, E>(
        &self,
        resolver: &mut F,
        predicate: &mut impl FnMut(&K, &V) -> Result<bool, E>,
    ) -> Result<Option<(K, V)>, HamtTraversalError<E>>
    where
        K: Clone,
        V: Clone,
        F: NodeResolver<K, V, E>,
    {
        self.find_entry_inner(resolver, predicate, 0)
    }

    fn find_entry_inner<F, E>(
        &self,
        resolver: &mut F,
        predicate: &mut impl FnMut(&K, &V) -> Result<bool, E>,
        depth: usize,
    ) -> Result<Option<(K, V)>, HamtTraversalError<E>>
    where
        K: Clone,
        V: Clone,
        F: NodeResolver<K, V, E>,
    {
        crate::hamt::delta::check_depth(depth)?;
        let next_depth = depth.saturating_add(1);

        if let Some((key, value)) = self.first_matching_leaf(predicate)? {
            return Ok(Some((key.clone(), value.clone())));
        }

        for child in &self.children {
            let child_node = delta::resolve_node_checked(child, resolver)?;
            if let Some(entry) = child_node.find_entry_inner(resolver, predicate, next_depth)? {
                return Ok(Some(entry));
            }
        }

        Ok(None)
    }

    /// Resolves which slot `path_hash` routes to at `depth` and returns what
    /// occupies it, if anything.
    ///
    /// This is the single shared CHAMP descent step: it computes the slot,
    /// tests it against `datamap`/`nodemap`, and resolves the compressed
    /// index. Both [`get_by_path_hash`](Self::get_by_path_hash) and
    /// [`search_by_path_hash`](Self::search_by_path_hash) build on it and
    /// only differ in how they terminate at a leaf or follow a child.
    fn slot_at(&self, path_hash: &StructuralHash, depth: usize) -> Slot<'_, K, V> {
        let slot = bucket_index(path_hash, depth);
        let bit = 1_u32 << slot;

        if (self.datamap & bit) != 0 {
            Slot::Leaf(&self.leaves[map_index(self.datamap, slot)])
        } else if (self.nodemap & bit) != 0 {
            Slot::Child(&self.children[map_index(self.nodemap, slot)])
        } else {
            Slot::Empty
        }
    }

    fn get_by_path_hash_inner<Q>(
        &self,
        key: &Q,
        path_hash: &StructuralHash,
        depth: usize,
    ) -> Option<&V>
    where
        K: Eq + Borrow<Q>,
        Q: Eq + ?Sized,
    {
        if depth >= HAMT_MAX_DEPTH {
            return None;
        }
        let next_depth = depth.saturating_add(1);

        match self.slot_at(path_hash, depth) {
            Slot::Leaf((stored_key, value)) => (stored_key.borrow() == key).then_some(value),
            Slot::Child(NodeRef::Resolved(child)) => {
                child.get_by_path_hash_inner(key, path_hash, next_depth)
            }
            Slot::Child(NodeRef::Lazy(_)) | Slot::Empty => None,
        }
    }
}

/// What occupies a single CHAMP slot: a leaf entry, a child node, or nothing.
enum Slot<'a, K, V> {
    Leaf(&'a (K, V)),
    Child(&'a NodeRef<K, V>),
    Empty,
}

/// Errors that can occur while building a HAMT from an entry iterator.
#[derive(Debug, PartialEq, Eq)]
pub enum HamtBuildError {
    /// Too many entries collided into the same slot after exhausting the
    /// available hash depth.
    HashCollision { depth: usize, bucket_size: usize },
}

impl fmt::Display for HamtBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HashCollision { depth, bucket_size } => write!(
                f,
                "hamt build hash collision at depth {depth} with bucket size {bucket_size}"
            ),
        }
    }
}

impl core::error::Error for HamtBuildError {}

fn key_path_hash<K: Hash + ?Sized>(structural_key: &[u8], key: &K) -> StructuralHash {
    let mut hasher = StructuralHashBuilder::new(structural_key);
    key.hash(&mut hasher);
    hasher.finalize()
}

fn map_index(bitmap: u32, slot: usize) -> usize {
    let mask = lower_slot_mask(slot);
    (bitmap & mask).count_ones() as usize
}

const LOWER_SLOT_MASKS: [u32; 32] = [
    0x0000_0000,
    0x0000_0001,
    0x0000_0003,
    0x0000_0007,
    0x0000_000f,
    0x0000_001f,
    0x0000_003f,
    0x0000_007f,
    0x0000_00ff,
    0x0000_01ff,
    0x0000_03ff,
    0x0000_07ff,
    0x0000_0fff,
    0x0000_1fff,
    0x0000_3fff,
    0x0000_7fff,
    0x0000_ffff,
    0x0001_ffff,
    0x0003_ffff,
    0x0007_ffff,
    0x000f_ffff,
    0x001f_ffff,
    0x003f_ffff,
    0x007f_ffff,
    0x00ff_ffff,
    0x01ff_ffff,
    0x03ff_ffff,
    0x07ff_ffff,
    0x0fff_ffff,
    0x1fff_ffff,
    0x3fff_ffff,
    0x7fff_ffff,
];

fn lower_slot_mask(slot: usize) -> u32 {
    LOWER_SLOT_MASKS.get(slot).copied().unwrap_or(u32::MAX)
}

fn bucket_index(hash: &StructuralHash, depth: usize) -> usize {
    debug_assert!(
        depth < HAMT_MAX_DEPTH,
        "bucket_index called at or beyond HAMT_MAX_DEPTH ({depth} >= {HAMT_MAX_DEPTH})"
    );
    let bit_offset = depth.saturating_mul(HAMT_BRANCH_BITS);
    let byte_index = bit_offset / 8;
    let bit_shift = bit_offset % 8;
    let hash_len = hash.len();
    debug_assert!(
        byte_index < hash_len,
        "byte_index out of bounds for StructuralHash ({byte_index} >= {hash_len})",
    );

    let mut word = u16::from(hash[byte_index]);
    // No checked_add: byte_index < hash_len (32, asserted above) always, so
    // byte_index + 1 <= 32 never overflows usize. A checked_add here can
    // never observe None -- it's not a real safety margin, just an untestable
    // dead branch (a coverage tool will flag its closing brace as unreached,
    // correctly: reaching it would require byte_index near usize::MAX, which
    // contradicts the precondition this function already asserts).
    if let Some(next) = hash.get(byte_index.saturating_add(1)) {
        word |= u16::from(*next) << 8;
    }
    usize::from((word >> bit_shift) & HAMT_BRANCH_MASK)
}

struct BuildEntry<K, V> {
    key: K,
    value: V,
    path_hash: StructuralHash,
}

fn build_node<K, V>(
    structural_key: &[u8],
    entries: Vec<BuildEntry<K, V>>,
    depth: usize,
) -> Result<NodePtr<K, V>, HamtBuildError>
where
    K: Hash + HamtCodec,
    V: HamtCodec,
{
    if depth >= HAMT_MAX_DEPTH {
        return Err(HamtBuildError::HashCollision {
            depth,
            bucket_size: entries.len(),
        });
    }

    let mut buckets: Vec<Vec<BuildEntry<K, V>>> =
        (0..HAMT_BRANCH_FACTOR).map(|_| Vec::new()).collect();
    for entry in entries {
        let slot = bucket_index(&entry.path_hash, depth);
        buckets[slot].push(entry);
    }

    let mut datamap = 0_u32;
    let mut nodemap = 0_u32;
    let mut leaves = Vec::new();
    let mut children = Vec::new();

    for (slot, mut bucket) in buckets.into_iter().enumerate() {
        if bucket.is_empty() {
            continue;
        }

        let bit = 1_u32 << slot;
        if bucket.len() == 1 {
            datamap |= bit;
            let entry = bucket
                .pop()
                .expect("singleton bucket must contain one entry");
            leaves.push((entry.key, entry.value));
            continue;
        }

        let next_depth = depth.saturating_add(1);
        if next_depth >= HAMT_MAX_DEPTH {
            return Err(HamtBuildError::HashCollision {
                depth,
                bucket_size: bucket.len(),
            });
        }

        nodemap |= bit;
        let child = build_node(structural_key, bucket, next_depth)?;
        children.push(NodeRef::Resolved(child));
    }

    let structural_hash =
        HamtNode::compute_structural_hash(structural_key, datamap, nodemap, &leaves, &children);

    Ok(Arc::new(HamtNode {
        datamap,
        nodemap,
        leaves,
        children,
        structural_hash,
    }))
}

/// Builds a full HAMT from an iterator of key/value entries.
///
/// The caller supplies the `structural_key` (typically the room's `room_id.as_bytes()`)
/// used for subtree hashing and deterministic routing within this namespace.
///
/// # Errors
/// Returns [`HamtBuildError::HashCollision`] if the input exhausts the
/// available trie depth before entries can be separated into distinct slots.
pub fn build_hamt<K, V, I>(
    structural_key: &[u8],
    entries: I,
) -> Result<NodePtr<K, V>, HamtBuildError>
where
    K: Hash + HamtCodec,
    V: HamtCodec,
    I: IntoIterator<Item = (K, V)>,
{
    build_hamt_with_key_hash(structural_key, entries, |key| {
        key_path_hash(structural_key, key)
    })
}

/// Builds a full HAMT from an iterator of key/value entries using a custom
/// per-key path hash function.
///
/// Callers that build a tree with this function must use the matching custom
/// lookup and mutation APIs:
/// - [`HamtNode::get_with_key_hash`]
/// - [`HamtNode::search_with_key_hash`]
/// - [`HamtMutator::insert`]
/// - [`HamtMutator::remove`]
/// - [`HamtNode::get_by_path_hash`]
/// - [`HamtNode::search_by_path_hash`]
///
/// The default [`HamtNode::get`], [`HamtNode::search`], [`insert`], and
/// [`remove`] helpers derive their own routing hash using the same keyed
/// structural hash used by [`build_hamt`], and are only correct for trees
/// built by [`build_hamt`].
///
/// This is the most general builder entry point and is useful when a caller
/// already has a pre-hashed key stream.
///
/// # Errors
/// Returns [`HamtBuildError::HashCollision`] if the input exhausts the
/// available trie depth before entries can be separated into distinct slots.
pub fn build_hamt_with_key_hash<K, V, I, F>(
    structural_key: &[u8],
    entries: I,
    mut key_hash: F,
) -> Result<NodePtr<K, V>, HamtBuildError>
where
    K: Hash + HamtCodec,
    V: HamtCodec,
    I: IntoIterator<Item = (K, V)>,
    F: FnMut(&K) -> StructuralHash,
{
    let entries = entries
        .into_iter()
        .map(|(key, value)| {
            let path_hash = key_hash(&key);
            BuildEntry {
                key,
                value,
                path_hash,
            }
        })
        .collect::<Vec<_>>();
    build_node(structural_key, entries, 0)
}

/// Builds a root handle for a freshly constructed HAMT.
///
/// This is a convenience helper for downstream code that already knows the
/// resolved lattice and wants both the tree and the root identity in one call.
/// # Errors
/// Returns the same build errors as [`build_hamt`].
pub fn build_hamt_root_handle<K, V, I>(
    structural_key: &[u8],
    lattice: &crate::incremental::LtHash,
    entries: I,
) -> Result<(RootHandle, NodePtr<K, V>), HamtBuildError>
where
    K: Hash + HamtCodec,
    V: HamtCodec,
    I: IntoIterator<Item = (K, V)>,
{
    let root = build_hamt(structural_key, entries)?;
    let handle = RootHandle::from_lthash(root.structural_hash, lattice);
    Ok((handle, root))
}

/// Errors that can occur while incrementally mutating a HAMT via
/// [`insert`] or [`remove`].
#[derive(Debug, PartialEq, Eq)]
pub enum HamtMutateError<E> {
    /// Too many entries collided into the same slot after exhausting the
    /// available hash depth.
    HashCollision { depth: usize, bucket_size: usize },
    /// Traversal exceeded maximum allowable HAMT depth.
    MaxDepthExceeded { depth: usize },
    /// The resolver failed to load a lazy child that the mutation needed to
    /// descend into.
    Resolve(E),
}

impl<E> fmt::Display for HamtMutateError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HashCollision { depth, bucket_size } => write!(
                f,
                "hamt mutation hash collision at depth {depth} with bucket size {bucket_size}"
            ),
            Self::MaxDepthExceeded { depth } => {
                write!(f, "hamt mutation max depth exceeded at depth {depth}")
            }
            Self::Resolve(err) => write!(f, "hamt mutation resolver failed: {err}"),
        }
    }
}

impl<E> core::error::Error for HamtMutateError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::HashCollision { .. } | Self::MaxDepthExceeded { .. } => None,
            Self::Resolve(err) => Some(err),
        }
    }
}

impl<E> From<HamtBuildError> for HamtMutateError<E> {
    fn from(err: HamtBuildError) -> Self {
        match err {
            HamtBuildError::HashCollision { depth, bucket_size } => {
                Self::HashCollision { depth, bucket_size }
            }
        }
    }
}

impl<E> From<HamtTraversalError<E>> for HamtMutateError<E> {
    fn from(err: HamtTraversalError<E>) -> Self {
        match err {
            HamtTraversalError::Resolve(e) => Self::Resolve(e),
            HamtTraversalError::MaxDepthExceeded { depth } => Self::MaxDepthExceeded { depth },
        }
    }
}

/// Result of an [`insert`]/`insert_node` mutation: the new root and the
/// value that previously occupied the key, if any.
type MutateResult<K, V, E> = Result<(NodePtr<K, V>, Option<V>), HamtMutateError<E>>;

/// Result of a `remove_node` step: what remains of the subtree, and the
/// value that was removed, if the key was present.
type RemoveStepResult<K, V, E> = Result<(RemoveOutcome<K, V>, Option<V>), HamtMutateError<E>>;

fn rebuild_node<K, V>(
    structural_key: &[u8],
    datamap: u32,
    nodemap: u32,
    leaves: Vec<(K, V)>,
    children: Vec<NodeRef<K, V>>,
) -> NodePtr<K, V>
where
    K: Hash + HamtCodec,
    V: HamtCodec,
{
    let structural_hash =
        HamtNode::compute_structural_hash(structural_key, datamap, nodemap, &leaves, &children);
    Arc::new(HamtNode {
        datamap,
        nodemap,
        leaves,
        children,
        structural_hash,
    })
}

type MutationSink<'a, K, V> = dyn FnMut(&NodePtr<K, V>) + 'a;

fn emit_node_to_sink<K, V>(node: &NodePtr<K, V>, sink: &mut MutationSink<'_, K, V>) {
    sink(node);
}

fn emit_split_nodes_to_sink<K, V>(node: &NodePtr<K, V>, sink: &mut MutationSink<'_, K, V>) {
    sink(node);
    for child in &node.children {
        if let NodeRef::Resolved(child_node) = child {
            emit_split_nodes_to_sink(child_node, sink);
        }
    }
}

fn resolve_child_ref<K, V, F, E>(
    child: &NodeRef<K, V>,
    resolver: &mut F,
) -> Result<NodePtr<K, V>, HamtMutateError<E>>
where
    F: NodeResolver<K, V, E>,
{
    match child {
        NodeRef::Resolved(child) => Ok(child.clone()),
        NodeRef::Lazy(hash) => resolver(hash).map_err(HamtMutateError::Resolve),
    }
}

fn rebuild_with_child<K, V>(
    node: &NodePtr<K, V>,
    structural_key: &[u8],
    idx: usize,
    new_child: NodePtr<K, V>,
    sink: &mut MutationSink<'_, K, V>,
) -> NodePtr<K, V>
where
    K: Hash + Clone + HamtCodec,
    V: HamtValue,
{
    let mut children = node.children.clone();
    children[idx] = NodeRef::Resolved(new_child);
    let new_node = rebuild_node(
        structural_key,
        node.datamap,
        node.nodemap,
        node.leaves.clone(),
        children,
    );
    emit_node_to_sink(&new_node, sink);
    new_node
}

// This adapter keeps the mutation call sites explicit, then immediately packs
// the context arguments into `InsertCtx` for the recursive worker.
#[allow(clippy::too_many_arguments)]
fn insert_via_ctx<K, V, KeyHash, F, E>(
    node: &NodePtr<K, V>,
    structural_key: &[u8],
    key: K,
    value: V,
    path_hash: StructuralHash,
    depth: usize,
    key_hash: &mut KeyHash,
    resolver: &mut F,
    sink: &mut MutationSink<'_, K, V>,
) -> MutateResult<K, V, E>
where
    K: HamtKey,
    V: HamtValue,
    KeyHash: FnMut(&K) -> StructuralHash,
    F: NodeResolver<K, V, E>,
{
    let mut ctx = InsertCtx {
        structural_key,
        key_hash,
        resolver,
        sink,
    };
    ctx.insert_node(node, key, value, path_hash, depth)
}

#[cfg(test)]
fn insert_node<K, V, F, E>(
    node: &NodePtr<K, V>,
    structural_key: &[u8],
    key: K,
    value: V,
    path_hash: &StructuralHash,
    depth: usize,
    resolver: &mut F,
) -> MutateResult<K, V, E>
where
    K: HamtKey,
    V: HamtValue,
    F: NodeResolver<K, V, E>,
{
    let mut key_hash = |k: &K| key_path_hash(structural_key, k);
    let mut sink = |_: &NodePtr<K, V>| {};
    insert_via_ctx(
        node,
        structural_key,
        key,
        value,
        *path_hash,
        depth,
        &mut key_hash,
        resolver,
        &mut sink,
    )
}

struct InsertCtx<'a, K, V, KeyHash, F> {
    structural_key: &'a [u8],
    key_hash: &'a mut KeyHash,
    resolver: &'a mut F,
    sink: &'a mut MutationSink<'a, K, V>,
}

struct InsertStep<K, V> {
    key: K,
    value: V,
    path_hash: StructuralHash,
    slot: usize,
    bit: u32,
}

impl<K, V, KeyHash, F> InsertCtx<'_, K, V, KeyHash, F>
where
    K: HamtKey,
    V: HamtValue,
    KeyHash: FnMut(&K) -> StructuralHash,
{
    fn insert_node<E>(
        &mut self,
        node: &NodePtr<K, V>,
        key: K,
        value: V,
        path_hash: StructuralHash,
        depth: usize,
    ) -> MutateResult<K, V, E>
    where
        F: NodeResolver<K, V, E>,
    {
        if depth >= HAMT_MAX_DEPTH {
            return Err(HamtMutateError::HashCollision {
                depth,
                bucket_size: node.leaves.len().saturating_add(1),
            });
        }

        let structural_key = self.structural_key;
        let slot = bucket_index(&path_hash, depth);
        let bit = 1_u32 << slot;
        let step = InsertStep {
            key,
            value,
            path_hash,
            slot,
            bit,
        };

        if (node.datamap & bit) != 0 {
            let idx = map_index(node.datamap, slot);
            if node.leaves[idx].0 == step.key {
                let mut leaves = node.leaves.clone();
                let old_value = core::mem::replace(&mut leaves[idx].1, step.value);
                let new_node = rebuild_node(
                    structural_key,
                    node.datamap,
                    node.nodemap,
                    leaves,
                    node.children.clone(),
                );
                emit_node_to_sink(&new_node, self.sink);
                return Ok((new_node, Some(old_value)));
            }

            return self.insert_into_occupied_slot(node, step, depth.saturating_add(1));
        }

        if (node.nodemap & bit) != 0 {
            return self.insert_into_occupied_slot(node, step, depth.saturating_add(1));
        }

        // Empty slot: insert directly as a new leaf.
        let mut leaves = node.leaves.clone();
        let idx = map_index(node.datamap, step.slot);
        leaves.insert(idx, (step.key, step.value));
        let new_datamap = node.datamap | step.bit;
        let new_node = rebuild_node(
            structural_key,
            new_datamap,
            node.nodemap,
            leaves,
            node.children.clone(),
        );
        emit_node_to_sink(&new_node, self.sink);
        Ok((new_node, None))
    }

    fn insert_into_occupied_slot<E>(
        &mut self,
        node: &NodePtr<K, V>,
        step: InsertStep<K, V>,
        next_depth: usize,
    ) -> MutateResult<K, V, E>
    where
        F: NodeResolver<K, V, E>,
    {
        if (node.datamap & step.bit) != 0 {
            // Leaf slot: split the displaced leaf and this one into a new child.
            let InsertStep {
                key,
                value,
                path_hash,
                slot,
                bit,
            } = step;
            let idx = map_index(node.datamap, slot);

            let (existing_key, existing_value) = node.leaves[idx].clone();
            let existing_path_hash = (self.key_hash)(&existing_key);
            let split_entries = vec![
                BuildEntry {
                    key: existing_key,
                    value: existing_value,
                    path_hash: existing_path_hash,
                },
                BuildEntry {
                    key,
                    value,
                    path_hash,
                },
            ];
            let child = build_node(self.structural_key, split_entries, next_depth)?;
            emit_split_nodes_to_sink(&child, self.sink);

            let mut leaves = node.leaves.clone();
            leaves.remove(idx);
            let new_datamap = node.datamap & !bit;
            let new_nodemap = node.nodemap | bit;
            let child_idx = map_index(new_nodemap, slot);
            let mut children = node.children.clone();
            children.insert(child_idx, NodeRef::Resolved(child));
            let new_node = rebuild_node(
                self.structural_key,
                new_datamap,
                new_nodemap,
                leaves,
                children,
            );
            emit_node_to_sink(&new_node, self.sink);
            Ok((new_node, None))
        } else {
            // Child slot: recurse into the existing child.
            let InsertStep {
                key,
                value,
                path_hash,
                slot,
                ..
            } = step;
            let idx = map_index(node.nodemap, slot);
            let child = resolve_child_ref(&node.children[idx], self.resolver)?;
            let (new_child, old_value) =
                self.insert_node(&child, key, value, path_hash, next_depth)?;
            let new_node = rebuild_with_child(node, self.structural_key, idx, new_child, self.sink);
            Ok((new_node, old_value))
        }
    }
}

/// Inserts or replaces a key/value pair in a HAMT via `O(log S)`
/// path-copying, without rebuilding the whole tree.
///
/// Returns the new root and the value that previously occupied `key`, if
/// any — callers that maintain a homomorphic lattice alongside the tree
/// (e.g. `LtHash`) need the displaced value to subtract it before adding
/// the new one.
///
/// This helper is only correct for trees built with [`build_hamt`]. If the
/// tree was built with [`build_hamt_with_key_hash`], use
/// [`HamtMutator::insert`] with the same routing function instead.
///
/// # Errors
/// Returns [`HamtMutateError::HashCollision`] if the input exhausts the
/// available trie depth, or [`HamtMutateError::Resolve`] if `resolver`
/// fails to load a lazy child on the path to `key`.
pub fn insert<K, V, F, E>(
    node: &NodePtr<K, V>,
    structural_key: &[u8],
    key: K,
    value: V,
    resolver: &mut F,
) -> MutateResult<K, V, E>
where
    K: HamtKey,
    V: HamtValue,
    F: NodeResolver<K, V, E>,
{
    HamtMutator::new(|k: &K| key_path_hash(structural_key, k), resolver).insert(
        node,
        structural_key,
        key,
        value,
    )
}

/// Carries the routing hash and lazy resolver shared by the HAMT mutation
/// operations, so each entry point names the key/value/key-hash bounds once
/// instead of repeating them.
///
/// The default-hash free functions ([`insert`], [`remove`],
/// [`persist_mutations`], [`persist_chain`]) construct one internally; callers
/// using a custom routing hash build one with [`HamtMutator::new`].
pub struct HamtMutator<K, V, KeyHash, F> {
    key_hash: KeyHash,
    resolver: F,
    _marker: core::marker::PhantomData<fn() -> (K, V)>,
}

impl<K, V, KeyHash, F> HamtMutator<K, V, KeyHash, F>
where
    K: HamtKey,
    V: HamtValue,
    KeyHash: FnMut(&K) -> StructuralHash,
{
    /// Creates a mutator from a routing hash and a lazy resolver.
    pub fn new(key_hash: KeyHash, resolver: F) -> Self {
        Self {
            key_hash,
            resolver,
            _marker: core::marker::PhantomData,
        }
    }

    /// Inserts or replaces a key/value pair using the caller-provided routing
    /// hash. See [`insert`] for the default-hash variant.
    ///
    /// # Errors
    /// Returns [`HamtMutateError::HashCollision`] if the input exhausts the
    /// available trie depth, or [`HamtMutateError::Resolve`] if the resolver
    /// fails to load a lazy child on the path to `key`.
    pub fn insert<E>(
        &mut self,
        node: &NodePtr<K, V>,
        structural_key: &[u8],
        key: K,
        value: V,
    ) -> MutateResult<K, V, E>
    where
        F: NodeResolver<K, V, E>,
    {
        let Self {
            key_hash, resolver, ..
        } = self;
        let path_hash = key_hash(&key);
        let mut sink = |_: &NodePtr<K, V>| {};
        insert_via_ctx(
            node,
            structural_key,
            key,
            value,
            path_hash,
            0,
            key_hash,
            resolver,
            &mut sink,
        )
    }

    /// Removes `key` using the caller-provided routing hash. See [`remove`] for
    /// the default-hash variant.
    ///
    /// # Errors
    /// Returns [`HamtMutateError::Resolve`] if the resolver fails to load a
    /// lazy child on the path to `key`.
    pub fn remove<E>(
        &mut self,
        node: &NodePtr<K, V>,
        structural_key: &[u8],
        key: &K,
    ) -> MutateResult<K, V, E>
    where
        F: NodeResolver<K, V, E>,
    {
        let Self {
            key_hash, resolver, ..
        } = self;
        let path_hash = key_hash(key);
        let mut sink = |_: &NodePtr<K, V>| {};
        remove_spine(
            node,
            structural_key,
            key,
            &path_hash,
            |leaf_key| bucket_index(&key_hash(leaf_key), 0),
            resolver,
            &mut sink,
        )
    }

    /// Persists a batch of mutations producing a single published final root.
    /// See [`persist_mutations`] for the publication contract.
    ///
    /// # Errors
    /// Returns [`HamtMutateError`] if the resolver fails to load a lazy child
    /// or depth is exhausted.
    pub fn persist_mutations<E, I>(
        &mut self,
        prev_root: &NodePtr<K, V>,
        structural_key: &[u8],
        mutations: I,
    ) -> PersistMutationsResult<K, V, E>
    where
        V: Hash,
        I: IntoIterator<Item = (K, Option<V>)>,
        F: NodeResolver<K, V, E>,
    {
        let mut current_root = prev_root.clone();
        let mut displaced_vec = Vec::new();

        for (key, opt_val) in mutations {
            let (next_root, displaced) = if let Some(val) = opt_val {
                self.insert(&current_root, structural_key, key, val)?
            } else {
                self.remove(&current_root, structural_key, &key)?
            };
            displaced_vec.push(displaced);
            current_root = next_root;
        }

        finalize_persisted_mutations(prev_root, current_root, displaced_vec, &mut self.resolver)
    }

    /// Persists a sequence of mutations where every intermediate step publishes
    /// a distinct root. See [`persist_chain`] for the publication contract.
    ///
    /// # Errors
    /// Returns [`HamtMutateError`] if the resolver fails to load a lazy child
    /// or depth is exhausted.
    pub fn persist_chain<E, I>(
        &mut self,
        prev_root: &NodePtr<K, V>,
        structural_key: &[u8],
        mutations: I,
    ) -> Result<Vec<ChainStep<K, V>>, HamtMutateError<E>>
    where
        V: Hash,
        I: IntoIterator<Item = (K, Option<V>)>,
        F: NodeResolver<K, V, E>,
    {
        let mut steps = Vec::new();
        let mut current_root = prev_root.clone();

        for (key, opt_val) in mutations {
            let (next_root, displaced, created) = persist_mutation_with_key_hash(
                &current_root,
                structural_key,
                key,
                opt_val,
                &mut self.key_hash,
                &mut self.resolver,
            )?;
            steps.push(ChainStep {
                root_hash: next_root.structural_hash,
                root: next_root.clone(),
                displaced,
                created,
            });
            current_root = next_root;
        }

        Ok(steps)
    }
}

/// Builds a mutator that routes keys with the default keyed structural hash.
fn default_mutator<'a, K, V, F>(
    structural_key: &'a [u8],
    resolver: &'a mut F,
) -> HamtMutator<K, V, impl FnMut(&K) -> StructuralHash + 'a, &'a mut F>
where
    K: HamtKey,
    V: HamtValue,
{
    HamtMutator::new(move |k: &K| key_path_hash(structural_key, k), resolver)
}

/// What remains of a subtree after a leaf was removed from it.
#[derive(Debug)]
enum RemoveOutcome<K, V> {
    /// The subtree has no entries left.
    Empty,
    /// The subtree collapsed to a single leaf, which must be inlined into
    /// the parent's `datamap` rather than kept as a child node — the same
    /// invariant `build_node` enforces when building from scratch.
    Leaf(K, V),
    /// The subtree still has two or more entries and remains a node.
    Node(NodePtr<K, V>),
}

/// Builds the outcome for a node whose contents just changed, collapsing it
/// to `Leaf`/`Empty` if it no longer has enough entries to justify being a
/// node, so the structural hash always matches what `build_node` would have
/// produced for the same final key set.
fn finalize_after_removal<K, V>(
    structural_key: &[u8],
    datamap: u32,
    nodemap: u32,
    leaves: Vec<(K, V)>,
    children: Vec<NodeRef<K, V>>,
) -> RemoveOutcome<K, V>
where
    K: Hash + HamtCodec,
    V: HamtCodec,
{
    if nodemap == 0 {
        if leaves.is_empty() {
            return RemoveOutcome::Empty;
        }
        if leaves.len() == 1 {
            let (key, value) = leaves
                .into_iter()
                .next()
                .expect("checked leaves.len() == 1 above");
            return RemoveOutcome::Leaf(key, value);
        }
    }
    RemoveOutcome::Node(rebuild_node(
        structural_key,
        datamap,
        nodemap,
        leaves,
        children,
    ))
}

struct RemoveCtx<'a, K, V, F> {
    structural_key: &'a [u8],
    resolver: &'a mut F,
    sink: &'a mut MutationSink<'a, K, V>,
}

fn remove_spine<K, V, Q, F, Slot, E>(
    node: &NodePtr<K, V>,
    structural_key: &[u8],
    key: &Q,
    path_hash: &StructuralHash,
    root_slot_for_leaf: Slot,
    resolver: &mut F,
    sink: &mut MutationSink<'_, K, V>,
) -> MutateResult<K, V, E>
where
    K: Hash + Eq + Borrow<Q> + Clone + HamtCodec,
    V: HamtValue,
    Q: Eq + ?Sized,
    F: NodeResolver<K, V, E>,
    Slot: FnMut(&K) -> usize,
{
    let (outcome, old_value) = {
        let mut ctx = RemoveCtx {
            structural_key,
            resolver,
            sink,
        };
        remove_node_with_ctx(node, key, path_hash, 0, &mut ctx)?
    };
    let new_root = finalize_remove_root(structural_key, outcome, root_slot_for_leaf, sink);
    Ok((new_root, old_value))
}

/// Removes a key from a HAMT via `O(log S)` path-copying, without
/// rebuilding the whole tree.
///
/// Collapses any subtree that drops to a single leaf back into its
/// parent's `datamap`, cascading as needed, so the resulting tree's
/// `structural_hash` always matches what [`build_hamt`] would have
/// produced from the same final key set.
///
/// Returns the new root and the removed value, if `key` was present.
///
/// This helper is only correct for trees built with [`build_hamt`]. If the
/// tree was built with [`build_hamt_with_key_hash`], use
/// [`HamtMutator::remove`] with the same routing function instead.
///
/// # Errors
/// Returns [`HamtMutateError::Resolve`] if `resolver` fails to load a lazy
/// child on the path to `key`.
pub fn remove<K, V, Q, F, E>(
    node: &NodePtr<K, V>,
    structural_key: &[u8],
    key: &Q,
    resolver: &mut F,
) -> MutateResult<K, V, E>
where
    K: Hash + Eq + Borrow<Q> + Clone + HamtCodec,
    V: HamtValue,
    Q: Hash + Eq + ?Sized,
    F: NodeResolver<K, V, E>,
{
    let path_hash = key_path_hash(structural_key, key);
    let mut sink = |_: &NodePtr<K, V>| {};
    remove_spine(
        node,
        structural_key,
        key,
        &path_hash,
        |leaf_key| bucket_index(&key_path_hash(structural_key, leaf_key), 0),
        resolver,
        &mut sink,
    )
}

fn remove_node_with_ctx<K, V, Q, F, E>(
    node: &NodePtr<K, V>,
    key: &Q,
    path_hash: &StructuralHash,
    depth: usize,
    ctx: &mut RemoveCtx<'_, K, V, F>,
) -> RemoveStepResult<K, V, E>
where
    K: Hash + Eq + Borrow<Q> + Clone + HamtCodec,
    V: HamtValue,
    Q: Eq + ?Sized,
    F: NodeResolver<K, V, E>,
{
    if depth >= HAMT_MAX_DEPTH {
        return Err(HamtMutateError::MaxDepthExceeded { depth });
    }

    let slot = bucket_index(path_hash, depth);
    let bit = 1_u32 << slot;
    let structural_key = ctx.structural_key;

    if (node.datamap & bit) != 0 {
        let idx = map_index(node.datamap, slot);
        if node.leaves[idx].0.borrow() != key {
            return Ok((RemoveOutcome::Node(node.clone()), None));
        }

        let old_value = node.leaves[idx].1.clone();
        let mut leaves = node.leaves.clone();
        leaves.remove(idx);
        let new_datamap = node.datamap & !bit;
        let outcome = finalize_after_removal(
            structural_key,
            new_datamap,
            node.nodemap,
            leaves,
            node.children.clone(),
        );
        if let RemoveOutcome::Node(ref new_node) = outcome {
            emit_node_to_sink(new_node, ctx.sink);
        }
        return Ok((outcome, Some(old_value)));
    }

    if (node.nodemap & bit) == 0 {
        return Ok((RemoveOutcome::Node(node.clone()), None));
    }

    let idx = map_index(node.nodemap, slot);
    let child = resolve_child_ref(&node.children[idx], ctx.resolver)?;

    let next_depth = depth.saturating_add(1);
    if next_depth >= HAMT_MAX_DEPTH {
        return Err(HamtMutateError::MaxDepthExceeded { depth: next_depth });
    }
    let (child_outcome, old_value) = remove_node_with_ctx(&child, key, path_hash, next_depth, ctx)?;
    if old_value.is_none() {
        return Ok((RemoveOutcome::Node(node.clone()), None));
    }

    match child_outcome {
        RemoveOutcome::Empty => {
            let mut children = node.children.clone();
            children.remove(idx);
            let new_nodemap = node.nodemap & !bit;
            let outcome = finalize_after_removal(
                structural_key,
                node.datamap,
                new_nodemap,
                node.leaves.clone(),
                children,
            );
            if let RemoveOutcome::Node(ref new_node) = outcome {
                emit_node_to_sink(new_node, ctx.sink);
            }
            Ok((outcome, old_value))
        }
        RemoveOutcome::Leaf(leaf_key, leaf_value) => {
            let mut children = node.children.clone();
            children.remove(idx);
            let new_nodemap = node.nodemap & !bit;
            let new_datamap = node.datamap | bit;
            let leaf_idx = map_index(node.datamap, slot);
            let mut leaves = node.leaves.clone();
            leaves.insert(leaf_idx, (leaf_key, leaf_value));
            let outcome =
                finalize_after_removal(structural_key, new_datamap, new_nodemap, leaves, children);
            if let RemoveOutcome::Node(ref new_node) = outcome {
                emit_node_to_sink(new_node, ctx.sink);
            }
            Ok((outcome, old_value))
        }
        RemoveOutcome::Node(new_child) => {
            let new_node = rebuild_with_child(node, structural_key, idx, new_child, ctx.sink);
            Ok((RemoveOutcome::Node(new_node), old_value))
        }
    }
}

fn finalize_remove_root<K, V, F>(
    structural_key: &[u8],
    outcome: RemoveOutcome<K, V>,
    mut root_slot_for_leaf: F,
    sink: &mut MutationSink<'_, K, V>,
) -> NodePtr<K, V>
where
    K: Hash + Clone + HamtCodec,
    V: HamtValue,
    F: FnMut(&K) -> usize,
{
    match outcome {
        RemoveOutcome::Empty => {
            let root = rebuild_node(structural_key, 0, 0, Vec::new(), Vec::new());
            emit_node_to_sink(&root, sink);
            root
        }
        RemoveOutcome::Leaf(leaf_key, leaf_value) => {
            let root_slot = root_slot_for_leaf(&leaf_key);
            let leaves = vec![(leaf_key, leaf_value)];
            let root = rebuild_node(structural_key, 1_u32 << root_slot, 0, leaves, Vec::new());
            emit_node_to_sink(&root, sink);
            root
        }
        RemoveOutcome::Node(new_root) => new_root,
    }
}

/// Result of a [`persist_mutation`] operation: the new root, displaced value, and encoded new nodes.
pub type PersistMutationResult<K, V, E> =
    Result<(NodePtr<K, V>, Option<V>, Vec<(StructuralHash, Vec<u8>)>), HamtMutateError<E>>;

/// Result of a [`persist_mutations`] batch operation: the new root, displaced values, and encoded new nodes.
pub type PersistMutationsResult<K, V, E> = Result<
    (
        NodePtr<K, V>,
        Vec<Option<V>>,
        Vec<(StructuralHash, Vec<u8>)>,
    ),
    HamtMutateError<E>,
>;

/// Persists a single mutation (insert if `Some`, remove if `None`) on top of `prev_root`.
///
/// Emits all created spine nodes inline during the mutation descent without a second
/// post-hoc tree traversal or redundant lazy-child resolutions.
///
/// Returns:
/// - The new root `NodePtr<K, V>`
/// - The displaced / removed value, if any (needed for lattice subtraction)
/// - The encoded binary bytes of the newly created spine nodes (`Vec<(StructuralHash, Vec<u8>)>`)
///
/// # Publication Contract
/// This is for a single published state group. The returned `created` nodes must be written to
/// storage before publishing the state group root pointer.
///
/// # Custom-hash roots
/// This always routes with the default keyed structural hash, the same one
/// [`build_hamt`] uses. It is only correct for trees built by [`build_hamt`]
/// (or `prev_root`s produced by a prior call to this function). Do not call
/// this on a `prev_root` built by [`build_hamt_with_key_hash`] — it will
/// route with the wrong hash, silently missing existing entries and leaving
/// the tree inconsistent. Use [`persist_mutation_with_key_hash`] or the
/// [`HamtMutator`] methods for those trees instead.
///
/// # Errors
/// Returns [`HamtMutateError`] if `resolver` fails to load a lazy child or depth is exhausted.
pub fn persist_mutation<K, V, F, E>(
    prev_root: &NodePtr<K, V>,
    structural_key: &[u8],
    key: K,
    value: Option<V>,
    resolver: &mut F,
) -> PersistMutationResult<K, V, E>
where
    K: HamtKey,
    V: HamtValue + Hash,
    F: NodeResolver<K, V, E>,
{
    persist_mutation_with_key_hash(
        prev_root,
        structural_key,
        key,
        value,
        |k: &K| key_path_hash(structural_key, k),
        resolver,
    )
}

/// [`persist_mutation`] equivalent for trees built with
/// [`build_hamt_with_key_hash`]: routes with the caller-supplied `key_hash`
/// instead of the default keyed structural hash, so it is correct for trees
/// whose routing hash differs from [`build_hamt`]'s.
///
/// See [`persist_mutation`] for the return value and publication contract.
///
/// # Errors
/// Returns [`HamtMutateError`] if `resolver` fails to load a lazy child or depth is exhausted.
pub fn persist_mutation_with_key_hash<K, V, KeyHash, F, E>(
    prev_root: &NodePtr<K, V>,
    structural_key: &[u8],
    key: K,
    value: Option<V>,
    mut key_hash: KeyHash,
    resolver: &mut F,
) -> PersistMutationResult<K, V, E>
where
    K: HamtKey,
    V: HamtValue + Hash,
    KeyHash: FnMut(&K) -> StructuralHash,
    F: NodeResolver<K, V, E>,
{
    let mut created = Vec::new();
    let (new_root, displaced) = {
        let mut sink = |node: &NodePtr<K, V>| {
            created.push((
                node.structural_hash,
                PersistedInternalNode::from(node.as_ref()).encode_v1(),
            ));
        };
        if let Some(val) = value {
            let path_hash = key_hash(&key);
            insert_via_ctx(
                prev_root,
                structural_key,
                key,
                val,
                path_hash,
                0,
                &mut key_hash,
                resolver,
                &mut sink,
            )?
        } else {
            let path_hash = key_hash(&key);
            remove_spine(
                prev_root,
                structural_key,
                &key,
                &path_hash,
                |leaf_key: &K| bucket_index(&key_hash(leaf_key), 0),
                resolver,
                &mut sink,
            )?
        }
    };

    if new_root.structural_hash == prev_root.structural_hash {
        created.clear();
    }

    Ok((new_root, displaced, created))
}

fn finalize_persisted_mutations<K, V, F, E>(
    prev_root: &NodePtr<K, V>,
    current_root: NodePtr<K, V>,
    displaced_vec: Vec<Option<V>>,
    resolver: &mut F,
) -> PersistMutationsResult<K, V, E>
where
    K: HamtKey,
    V: HamtValue + Hash,
    F: NodeResolver<K, V, E>,
{
    if current_root.structural_hash == prev_root.structural_hash {
        return Ok((current_root, displaced_vec, Vec::new()));
    }

    let delta = diff_node_hashes(prev_root, &current_root, resolver)?;
    let new_set: crate::HashSet<StructuralHash> = delta.new_node_hashes.into_iter().collect();

    let mut created = Vec::with_capacity(new_set.len());
    let mut stack = vec![current_root.clone()];
    while let Some(node) = stack.pop() {
        if new_set.contains(&node.structural_hash) {
            let bytes = PersistedInternalNode::from(node.as_ref()).encode_v1();
            created.push((node.structural_hash, bytes));
            for child in &node.children {
                if let NodeRef::Resolved(child_node) = child {
                    if new_set.contains(&child_node.structural_hash) {
                        stack.push(child_node.clone());
                    }
                }
            }
        }
    }

    Ok((current_root, displaced_vec, created))
}

/// Persists a batch of mutations producing a SINGLE published final root.
///
/// # Publication Contract — READ BEFORE USE
/// This function is ONLY correct when **no intermediate roots are published** (e.g.
/// bulk initial state build or a single coalesced update). If any intermediate state group
/// is published or referenced elsewhere, you MUST use [`persist_chain`] instead; otherwise,
/// intermediate state groups will point to nodes that were never persisted.
///
/// Returns the final root, all displaced values per mutation (for lattice arithmetic),
/// and the encoded new nodes.
///
/// # Performance Note
/// Callers using lazy resolvers should pass a memoizing resolver (or use [`persist_chain`])
/// to avoid repeated backend fetches during the end-of-batch diff pass.
///
/// # Custom-hash roots
/// Same default-hash-only routing as [`persist_mutation`]; see its
/// "Custom-hash roots" section — do not call this on a
/// [`build_hamt_with_key_hash`] tree. Use
/// [`HamtMutator::persist_mutations`] instead.
///
/// # Errors
/// Returns [`HamtMutateError`] if `resolver` fails to load a lazy child or depth is exhausted.
pub fn persist_mutations<K, V, I, F, E>(
    prev_root: &NodePtr<K, V>,
    structural_key: &[u8],
    mutations: I,
    resolver: &mut F,
) -> PersistMutationsResult<K, V, E>
where
    K: HamtKey,
    V: HamtValue + Hash,
    I: IntoIterator<Item = (K, Option<V>)>,
    F: NodeResolver<K, V, E>,
{
    default_mutator(structural_key, resolver).persist_mutations(
        prev_root,
        structural_key,
        mutations,
    )
}

/// Persists a sequence of mutations where EVERY intermediate step publishes a distinct root.
///
/// This is the entry point used by homeserver batch-persistence paths (e.g. Synapse's
/// `store_state_deltas_for_batched`). It emits [`ChainStep`]s containing the exact set of
/// new nodes created at each step relative to its immediate predecessor.
///
/// # Publication Contract
/// For each step $i$, the `step.created` nodes must be written to storage before publishing
/// the corresponding state group root.
///
/// # Custom-hash roots
/// Same default-hash-only routing as [`persist_mutation`]; see its
/// "Custom-hash roots" section — do not call this on a
/// [`build_hamt_with_key_hash`] tree. Use [`HamtMutator::persist_chain`]
/// instead.
///
/// # Errors
/// Returns [`HamtMutateError`] if `resolver` fails to load a lazy child or depth is exhausted.
pub fn persist_chain<K, V, I, F, E>(
    prev_root: &NodePtr<K, V>,
    structural_key: &[u8],
    mutations: I,
    resolver: &mut F,
) -> Result<Vec<ChainStep<K, V>>, HamtMutateError<E>>
where
    K: HamtKey,
    V: HamtValue + Hash,
    I: IntoIterator<Item = (K, Option<V>)>,
    F: NodeResolver<K, V, E>,
{
    default_mutator(structural_key, resolver).persist_chain(prev_root, structural_key, mutations)
}

/// Descends into a batch of persisted node byte slices for their targeted keys.
///
/// `nodes_and_keys` contains the expected node hash, encoded bytes, depth, and
/// target key hashes for each fetched node. All entries in a single `nodes_and_keys`
/// call must share the same `depth` (the current level of breadth-first descent).
/// Each node is evaluated only against the keys that routed to it at that depth.
/// `key_hash_fn` computes the `KeyPathHash` of a decoded leaf key to verify exact matches.
///
/// # Depth Contract
/// All tuples in `nodes_and_keys` must specify the same `depth` level. Successful
/// descent produces [`DescendResult::pending`] entries representing child nodes at `depth + 1`.
///
/// # Absence Invariant
/// A key is reported in `absent` ONLY when:
/// 1. Its routed slot bit is clear in both `datamap` and `nodemap`.
/// 2. Its routed slot bit is set in `datamap`, but the decoded leaf key at that slot has a
///    different path hash. (Note: this is sound because this HAMT rejects multi-leaf bucket
///    overflow with [`HamtMutateError::HashCollision`] rather than storing collision lists).
///
/// # Errors
/// Returns [`DescendError::Decode`] if any node byte slice fails v1 parsing, or
/// [`DescendError::CorruptNode`] if internal bitmap invariants are violated.
pub fn descend_level<K, V, KeyHash>(
    structural_key: &[u8],
    nodes_and_keys: &[(StructuralHash, &[u8], usize, &[KeyPathHash])],
    mut key_hash_fn: KeyHash,
) -> Result<DescendResult<V>, DescendError>
where
    K: HamtKey,
    V: HamtValue + Hash,
    KeyHash: FnMut(&K) -> KeyPathHash,
{
    if let Some(&(_, _, first_depth, _)) = nodes_and_keys.first() {
        // Runtime check: mixed-depth entries would merge requests from different
        // levels into one frontier, misrouting subsequent lookups. The
        // debug_assert! was previously only checked in debug builds.
        if !nodes_and_keys.iter().all(|&(_, _, d, _)| d == first_depth) {
            return Err(DescendError::CorruptNode(
                "mixed-depth entries in a single descend_level call",
            ));
        }
    }

    let mut found = Vec::new();
    let mut absent = Vec::new();
    let mut pending_map: crate::HashMap<StructuralHash, Vec<KeyPathHash>> =
        crate::HashMap::default();

    for &(expected_hash, node_bytes, depth, target_keys) in nodes_and_keys {
        let node = PersistedInternalNode::<K, V>::decode_v1_unverified(node_bytes)
            .map_err(DescendError::Decode)?
            .into_hamt_node_verified(structural_key, expected_hash)
            .map_err(|_| {
                DescendError::CorruptNode("decoded node contents do not match requested node hash")
            })?;

        for &req_hash in target_keys {
            if depth >= HAMT_MAX_DEPTH {
                return Err(DescendError::CorruptNode(
                    "HAMT depth exceeds routing limit",
                ));
            }
            let slot = bucket_index(&req_hash, depth);
            let bit = 1_u32 << slot;

            if (node.datamap & bit) != 0 {
                let leaf_idx = map_index(node.datamap, slot);
                let (leaf_key, val) = node
                    .leaves
                    .get(leaf_idx)
                    .ok_or(DescendError::CorruptNode("leaf index out of bounds"))?;
                // Lazy slot validation: only check the leaf being read, not
                // the entire datamap. In a correct CHAMP HAMT, a leaf at
                // slot `s` must satisfy bucket_index(key_hash(leaf_key), depth) == s.
                if depth < HAMT_MAX_DEPTH {
                    let expected_slot = bucket_index(&key_hash_fn(leaf_key), depth);
                    if expected_slot != slot {
                        return Err(DescendError::CorruptNode("leaf routed to wrong slot"));
                    }
                }
                if key_hash_fn(leaf_key) == req_hash {
                    found.push((req_hash, val.clone()));
                } else {
                    // Different leaf occupies this exact slot: key is proven absent
                    // (Sound because this HAMT rejects bucket overflow with HashCollision)
                    absent.push(req_hash);
                }
            } else if (node.nodemap & bit) != 0 {
                let child_idx = map_index(node.nodemap, slot);
                let child_hash = node
                    .children
                    .get(child_idx)
                    .ok_or(DescendError::CorruptNode("child index out of bounds"))?
                    .structural_hash();
                pending_map.entry(child_hash).or_default().push(req_hash);
            } else {
                // Bitmap slot is clear: proven, terminal absence
                absent.push(req_hash);
            }
        }
    }

    let pending = pending_map.into_iter().collect();

    Ok(DescendResult {
        found,
        absent,
        pending,
    })
}
