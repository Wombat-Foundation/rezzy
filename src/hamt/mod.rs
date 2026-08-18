//! Generic HAMT primitives used by higher-level state handling.
//!
//! Layout:
//! - `hash`: keyed structural hashing for subtree identity
//! - `codec`: dense on-disk encoding for persisted internal nodes
//! - `delta`: subtree differencing for set isolation
//! - `tests`: regression coverage for the generic HAMT core

use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    borrow::Borrow,
    fmt,
    hash::{Hash, Hasher},
};

pub mod codec;
pub mod delta;
pub mod hash;

#[cfg(test)]
mod tests;

pub use codec::PersistedInternalNode;
pub use hash::{state_group_id_from_lthash, RootHandle, StateGroupId, StructuralHash};

use hash::StructuralHashBuilder;

const HAMT_BRANCH_BITS: usize = 5;
const HAMT_BRANCH_FACTOR: usize = 1 << HAMT_BRANCH_BITS;
const HAMT_BRANCH_MASK: u16 = 0b1_1111;
const HAMT_MAX_DEPTH: usize =
    (core::mem::size_of::<StructuralHash>() * 8).div_ceil(HAMT_BRANCH_BITS);

/// A reference to a child node in the HAMT.
#[derive(Clone, Debug)]
pub enum NodeRef<K, V> {
    /// A fully loaded child node.
    Resolved(Arc<HamtNode<K, V>>),
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
#[derive(Clone, Debug)]
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
        K: Hash,
        V: Hash,
    {
        let mut mac = StructuralHashBuilder::new(key);
        mac.write(&datamap.to_le_bytes());
        mac.write(&nodemap.to_le_bytes());
        for (k, v) in leaves {
            let mut leaf_mac = StructuralHashBuilder::new(key);
            k.hash(&mut leaf_mac);
            mac.write(&leaf_mac.finish());

            let mut leaf_mac = StructuralHashBuilder::new(key);
            v.hash(&mut leaf_mac);
            mac.write(&leaf_mac.finish());
        }
        for child in children {
            mac.write(&child.structural_hash());
        }
        mac.finish()
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
        F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
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
        F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
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
        F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
    {
        self.search_by_path_hash_inner(key, path_hash, 0, resolver)
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
        F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
    {
        for (key, value) in &self.leaves {
            visitor(key, value)?;
        }

        for child in &self.children {
            let child_node = match child {
                NodeRef::Resolved(node) => node.clone(),
                NodeRef::Lazy(hash) => resolver(hash)?,
            };
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

    /// Checks if any key-value entry in the HAMT satisfies `predicate`.
    ///
    /// Traversal proceeds lazily across child nodes, returning `Ok(true)` and
    /// stopping immediately on the first entry for which `predicate(&key, &value)`
    /// returns `true`. Returns `Ok(false)` if no matching entry is found.
    ///
    /// # Errors
    /// Returns any error emitted by `resolver`.
    pub fn any_entry<F, E>(
        &self,
        resolver: &mut F,
        predicate: &mut impl FnMut(&K, &V) -> bool,
    ) -> Result<bool, E>
    where
        F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
    {
        for (key, value) in &self.leaves {
            if predicate(key, value) {
                return Ok(true);
            }
        }

        for child in &self.children {
            let child_node = match child {
                NodeRef::Resolved(node) => node.clone(),
                NodeRef::Lazy(hash) => resolver(hash)?,
            };
            if child_node.any_entry(resolver, predicate)? {
                return Ok(true);
            }
        }

        Ok(false)
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
        let next_depth = depth.wrapping_add(1);

        match self.slot_at(path_hash, depth) {
            Slot::Leaf((stored_key, value)) => (stored_key.borrow() == key).then_some(value),
            Slot::Child(NodeRef::Resolved(child)) => {
                child.get_by_path_hash_inner(key, path_hash, next_depth)
            }
            Slot::Child(NodeRef::Lazy(_)) | Slot::Empty => None,
        }
    }

    fn search_by_path_hash_inner<Q, F, E>(
        &self,
        key: &Q,
        path_hash: &StructuralHash,
        depth: usize,
        resolver: &mut F,
    ) -> Result<Option<V>, E>
    where
        K: Eq + Borrow<Q>,
        V: Clone,
        Q: Eq + ?Sized,
        F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
    {
        if depth >= HAMT_MAX_DEPTH {
            return Ok(None);
        }
        let next_depth = depth.wrapping_add(1);

        match self.slot_at(path_hash, depth) {
            Slot::Leaf((stored_key, value)) => {
                Ok((stored_key.borrow() == key).then(|| value.clone()))
            }
            Slot::Child(NodeRef::Resolved(child)) => {
                child.search_by_path_hash_inner(key, path_hash, next_depth, resolver)
            }
            Slot::Child(NodeRef::Lazy(hash)) => {
                let child = resolver(hash)?;
                child.search_by_path_hash_inner(key, path_hash, next_depth, resolver)
            }
            Slot::Empty => Ok(None),
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
#[derive(Clone, Debug, PartialEq, Eq)]
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

#[cfg(feature = "std")]
impl std::error::Error for HamtBuildError {}

fn key_path_hash<K: Hash + ?Sized>(structural_key: &[u8], key: &K) -> StructuralHash {
    let mut hasher = StructuralHashBuilder::new(structural_key);
    key.hash(&mut hasher);
    hasher.finish()
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
    debug_assert!(
        byte_index < hash.len(),
        "byte_index out of bounds for StructuralHash ({byte_index} >= {})",
        hash.len()
    );

    let mut word = u16::from(hash[byte_index]);
    if let Some(next_index) = byte_index.checked_add(1) {
        if let Some(next) = hash.get(next_index) {
            word |= u16::from(*next) << 8;
        }
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
) -> Result<Arc<HamtNode<K, V>>, HamtBuildError>
where
    K: Hash,
    V: Hash,
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
/// The caller supplies the structural key used for subtree hashing. Keys are
/// placed into the trie using a deterministic keyed hash derived from that
/// same secret.
///
/// # Errors
/// Returns [`HamtBuildError::HashCollision`] if the input exhausts the
/// available trie depth before entries can be separated into distinct slots.
pub fn build_hamt<K, V, I>(
    structural_key: &[u8],
    entries: I,
) -> Result<Arc<HamtNode<K, V>>, HamtBuildError>
where
    K: Hash,
    V: Hash,
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
/// - [`insert_with_key_hash`]
/// - [`remove_with_key_hash`]
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
) -> Result<Arc<HamtNode<K, V>>, HamtBuildError>
where
    K: Hash,
    V: Hash,
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
    lattice: &crate::state::LtHash,
    entries: I,
) -> Result<(RootHandle, Arc<HamtNode<K, V>>), HamtBuildError>
where
    K: Hash,
    V: Hash,
    I: IntoIterator<Item = (K, V)>,
{
    let root = build_hamt(structural_key, entries)?;
    let handle = RootHandle::from_lthash(root.structural_hash, lattice);
    Ok((handle, root))
}

/// Errors that can occur while incrementally mutating a HAMT via
/// [`insert`] or [`remove`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HamtMutateError<E> {
    /// Too many entries collided into the same slot after exhausting the
    /// available hash depth.
    HashCollision { depth: usize, bucket_size: usize },
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
            Self::Resolve(err) => write!(f, "hamt mutation resolver failed: {err}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for HamtMutateError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HashCollision { .. } => None,
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

/// Result of an [`insert`]/`insert_node` mutation: the new root and the
/// value that previously occupied the key, if any.
type MutateResult<K, V, E> = Result<(Arc<HamtNode<K, V>>, Option<V>), HamtMutateError<E>>;

/// Result of a `remove_node` step: what remains of the subtree, and the
/// value that was removed, if the key was present.
type RemoveStepResult<K, V, E> = Result<(RemoveOutcome<K, V>, Option<V>), HamtMutateError<E>>;

fn rebuild_node<K, V>(
    structural_key: &[u8],
    datamap: u32,
    nodemap: u32,
    leaves: Vec<(K, V)>,
    children: Vec<NodeRef<K, V>>,
) -> Arc<HamtNode<K, V>>
where
    K: Hash,
    V: Hash,
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

fn insert_node<K, V, F, E>(
    node: &Arc<HamtNode<K, V>>,
    structural_key: &[u8],
    key: K,
    value: V,
    path_hash: &StructuralHash,
    depth: usize,
    resolver: &mut F,
) -> MutateResult<K, V, E>
where
    K: Hash + Eq + Clone,
    V: Hash + Clone,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    let mut key_hash = |key: &K| key_path_hash(structural_key, key);
    let mut ctx = InsertCtx {
        structural_key,
        key_hash: &mut key_hash,
        resolver,
    };
    insert_node_with_ctx(node, key, value, *path_hash, depth, &mut ctx)
}

struct InsertCtx<'a, KeyHash, F> {
    structural_key: &'a [u8],
    key_hash: &'a mut KeyHash,
    resolver: &'a mut F,
}

struct InsertStep<K, V> {
    key: K,
    value: V,
    path_hash: StructuralHash,
    slot: usize,
    bit: u32,
}

fn insert_node_with_ctx<K, V, KeyHash, F, E>(
    node: &Arc<HamtNode<K, V>>,
    key: K,
    value: V,
    path_hash: StructuralHash,
    depth: usize,
    ctx: &mut InsertCtx<'_, KeyHash, F>,
) -> MutateResult<K, V, E>
where
    K: Hash + Eq + Clone,
    V: Hash + Clone,
    KeyHash: FnMut(&K) -> StructuralHash,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    if depth >= HAMT_MAX_DEPTH {
        return Err(HamtMutateError::HashCollision {
            depth,
            bucket_size: node.leaves.len().saturating_add(1),
        });
    }

    let structural_key = ctx.structural_key;
    let key_hash = &mut *ctx.key_hash;
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
            return Ok((new_node, Some(old_value)));
        }

        return insert_into_leaf_slot(
            node,
            structural_key,
            step,
            depth.saturating_add(1),
            key_hash,
        );
    }

    if (node.nodemap & bit) != 0 {
        return insert_into_child_slot(node, structural_key, step, depth.saturating_add(1), ctx);
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
    Ok((new_node, None))
}

fn insert_into_leaf_slot<K, V, KeyHash, E>(
    node: &Arc<HamtNode<K, V>>,
    structural_key: &[u8],
    step: InsertStep<K, V>,
    next_depth: usize,
    key_hash: &mut KeyHash,
) -> MutateResult<K, V, E>
where
    K: Hash + Eq + Clone,
    V: Hash + Clone,
    KeyHash: FnMut(&K) -> StructuralHash,
{
    let InsertStep {
        key,
        value,
        path_hash,
        slot,
        bit,
    } = step;
    let idx = map_index(node.datamap, slot);

    let (existing_key, existing_value) = node.leaves[idx].clone();
    let existing_path_hash = key_hash(&existing_key);
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
    let child = build_node(structural_key, split_entries, next_depth)?;

    let mut leaves = node.leaves.clone();
    leaves.remove(idx);
    let new_datamap = node.datamap & !bit;
    let new_nodemap = node.nodemap | bit;
    let child_idx = map_index(new_nodemap, slot);
    let mut children = node.children.clone();
    children.insert(child_idx, NodeRef::Resolved(child));
    let new_node = rebuild_node(structural_key, new_datamap, new_nodemap, leaves, children);
    Ok((new_node, None))
}

fn insert_into_child_slot<K, V, KeyHash, F, E>(
    node: &Arc<HamtNode<K, V>>,
    structural_key: &[u8],
    step: InsertStep<K, V>,
    next_depth: usize,
    ctx: &mut InsertCtx<'_, KeyHash, F>,
) -> MutateResult<K, V, E>
where
    K: Hash + Eq + Clone,
    V: Hash + Clone,
    KeyHash: FnMut(&K) -> StructuralHash,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    let InsertStep {
        key,
        value,
        path_hash,
        slot,
        ..
    } = step;
    let idx = map_index(node.nodemap, slot);
    let child = match &node.children[idx] {
        NodeRef::Resolved(child) => child.clone(),
        NodeRef::Lazy(hash) => (ctx.resolver)(hash).map_err(HamtMutateError::Resolve)?,
    };
    let (new_child, old_value) =
        insert_node_with_ctx(&child, key, value, path_hash, next_depth, ctx)?;
    let mut children = node.children.clone();
    children[idx] = NodeRef::Resolved(new_child);
    let new_node = rebuild_node(
        structural_key,
        node.datamap,
        node.nodemap,
        node.leaves.clone(),
        children,
    );
    Ok((new_node, old_value))
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
/// [`insert_with_key_hash`] with the same routing function instead.
///
/// # Errors
/// Returns [`HamtMutateError::HashCollision`] if the input exhausts the
/// available trie depth, or [`HamtMutateError::Resolve`] if `resolver`
/// fails to load a lazy child on the path to `key`.
pub fn insert<K, V, F, E>(
    node: &Arc<HamtNode<K, V>>,
    structural_key: &[u8],
    key: K,
    value: V,
    resolver: &mut F,
) -> MutateResult<K, V, E>
where
    K: Hash + Eq + Clone,
    V: Hash + Clone,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    let path_hash = key_path_hash(structural_key, &key);
    insert_node(node, structural_key, key, value, &path_hash, 0, resolver)
}

/// Inserts or replaces a key/value pair in a HAMT using a caller-provided
/// routing hash for every key involved in the mutation.
///
/// This is the mutation equivalent of [`HamtNode::get_with_key_hash`] and is
/// required for trees built with [`build_hamt_with_key_hash`].
///
/// Returns the new root and the value that previously occupied `key`, if
/// any — callers that maintain a homomorphic lattice alongside the tree
/// (e.g. `LtHash`) need the displaced value to subtract it before adding
/// the new one.
///
/// # Errors
/// Returns [`HamtMutateError::HashCollision`] if the input exhausts the
/// available trie depth, or [`HamtMutateError::Resolve`] if `resolver`
/// fails to load a lazy child on the path to `key`.
pub fn insert_with_key_hash<K, V, KeyHash, F, E>(
    node: &Arc<HamtNode<K, V>>,
    structural_key: &[u8],
    key: K,
    value: V,
    mut key_hash: KeyHash,
    resolver: &mut F,
) -> MutateResult<K, V, E>
where
    K: Hash + Eq + Clone,
    V: Hash + Clone,
    KeyHash: FnMut(&K) -> StructuralHash,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    let path_hash = key_hash(&key);
    let mut ctx = InsertCtx {
        structural_key,
        key_hash: &mut key_hash,
        resolver,
    };
    insert_node_with_ctx(node, key, value, path_hash, 0, &mut ctx)
}

/// What remains of a subtree after a leaf was removed from it.
enum RemoveOutcome<K, V> {
    /// The subtree has no entries left.
    Empty,
    /// The subtree collapsed to a single leaf, which must be inlined into
    /// the parent's `datamap` rather than kept as a child node — the same
    /// invariant `build_node` enforces when building from scratch.
    Leaf(K, V),
    /// The subtree still has two or more entries and remains a node.
    Node(Arc<HamtNode<K, V>>),
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
    K: Hash,
    V: Hash,
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
/// [`remove_with_key_hash`] with the same routing function instead.
///
/// # Errors
/// Returns [`HamtMutateError::Resolve`] if `resolver` fails to load a lazy
/// child on the path to `key`.
pub fn remove<K, V, Q, F, E>(
    node: &Arc<HamtNode<K, V>>,
    structural_key: &[u8],
    key: &Q,
    resolver: &mut F,
) -> MutateResult<K, V, E>
where
    K: Hash + Eq + Borrow<Q> + Clone,
    V: Hash + Clone,
    Q: Hash + Eq + ?Sized,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    let path_hash = key_path_hash(structural_key, key);
    let (outcome, old_value) =
        remove_node_with_ctx(node, structural_key, key, &path_hash, 0, resolver)?;
    let new_root = finalize_remove_root(structural_key, outcome, |leaf_key| {
        bucket_index(&key_path_hash(structural_key, leaf_key), 0)
    });
    Ok((new_root, old_value))
}

fn remove_node_with_ctx<K, V, Q, F, E>(
    node: &Arc<HamtNode<K, V>>,
    structural_key: &[u8],
    key: &Q,
    path_hash: &StructuralHash,
    depth: usize,
    resolver: &mut F,
) -> RemoveStepResult<K, V, E>
where
    K: Hash + Eq + Borrow<Q> + Clone,
    V: Hash + Clone,
    Q: Eq + ?Sized,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    if depth >= HAMT_MAX_DEPTH {
        return Ok((RemoveOutcome::Node(node.clone()), None));
    }

    let slot = bucket_index(path_hash, depth);
    let bit = 1_u32 << slot;

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
        return Ok((outcome, Some(old_value)));
    }

    if (node.nodemap & bit) == 0 {
        return Ok((RemoveOutcome::Node(node.clone()), None));
    }

    let idx = map_index(node.nodemap, slot);
    let child = match &node.children[idx] {
        NodeRef::Resolved(child) => child.clone(),
        NodeRef::Lazy(hash) => resolver(hash).map_err(HamtMutateError::Resolve)?,
    };
    let Some(next_depth) = depth.checked_add(1) else {
        return Ok((RemoveOutcome::Node(node.clone()), None));
    };
    if next_depth >= HAMT_MAX_DEPTH {
        return Ok((RemoveOutcome::Node(node.clone()), None));
    }
    let (child_outcome, old_value) =
        remove_node_with_ctx(&child, structural_key, key, path_hash, next_depth, resolver)?;
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
            Ok((outcome, old_value))
        }
        RemoveOutcome::Node(new_child) => {
            let mut children = node.children.clone();
            children[idx] = NodeRef::Resolved(new_child);
            let new_node = rebuild_node(
                structural_key,
                node.datamap,
                node.nodemap,
                node.leaves.clone(),
                children,
            );
            Ok((RemoveOutcome::Node(new_node), old_value))
        }
    }
}

fn finalize_remove_root<K, V, F>(
    structural_key: &[u8],
    outcome: RemoveOutcome<K, V>,
    mut root_slot_for_leaf: F,
) -> Arc<HamtNode<K, V>>
where
    K: Hash + Clone,
    V: Hash + Clone,
    F: FnMut(&K) -> usize,
{
    match outcome {
        RemoveOutcome::Empty => rebuild_node(structural_key, 0, 0, Vec::new(), Vec::new()),
        RemoveOutcome::Leaf(leaf_key, leaf_value) => {
            let root_slot = root_slot_for_leaf(&leaf_key);
            let leaves = vec![(leaf_key, leaf_value)];
            rebuild_node(structural_key, 1_u32 << root_slot, 0, leaves, Vec::new())
        }
        RemoveOutcome::Node(new_root) => new_root,
    }
}

/// Removes a key from a HAMT using a caller-provided routing hash for every
/// key involved in the mutation.
///
/// This is the mutation equivalent of [`HamtNode::get_with_key_hash`] and is
/// required for trees built with [`build_hamt_with_key_hash`].
///
/// Collapses any subtree that drops to a single leaf back into its
/// parent's `datamap`, cascading as needed, so the resulting tree's
/// `structural_hash` always matches what [`build_hamt_with_key_hash`]
/// would have produced from the same final key set when using the same
/// routing function.
///
/// Returns the new root and the removed value, if `key` was present.
///
/// # Errors
/// Returns [`HamtMutateError::Resolve`] if `resolver` fails to load a lazy
/// child on the path to `key`.
pub fn remove_with_key_hash<K, V, KeyHash, F, E>(
    node: &Arc<HamtNode<K, V>>,
    structural_key: &[u8],
    key: &K,
    mut key_hash: KeyHash,
    resolver: &mut F,
) -> MutateResult<K, V, E>
where
    K: Hash + Eq + Clone,
    V: Hash + Clone,
    KeyHash: FnMut(&K) -> StructuralHash,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    let path_hash = key_hash(key);
    let (outcome, old_value) =
        remove_node_with_ctx(node, structural_key, key, &path_hash, 0, resolver)?;
    let new_root = finalize_remove_root(structural_key, outcome, |leaf_key| {
        bucket_index(&key_hash(leaf_key), 0)
    });
    Ok((new_root, old_value))
}
