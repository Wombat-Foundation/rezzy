//! Generic HAMT primitives used by higher-level state handling.
//!
//! Layout:
//! - `hash`: keyed structural hashing for subtree identity
//! - `codec`: dense on-disk encoding for persisted internal nodes
//! - `delta`: subtree differencing for set isolation
//! - `tests`: regression coverage for the generic HAMT core

use alloc::{sync::Arc, vec::Vec};
use core::{
    borrow::Borrow,
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
    #[must_use]
    pub fn get<Q>(&self, structural_key: &[u8], key: &Q) -> Option<&V>
    where
        K: Hash + Eq + Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let path_hash = key_path_hash(structural_key, key);
        self.get_by_path_hash(key, &path_hash, 0)
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
        self.get_by_path_hash(key, &path_hash, 0)
    }

    /// Looks up a key in a HAMT that may contain lazy children.
    ///
    /// Lazy children are resolved through `resolver` as needed. The returned
    /// value is cloned so the lookup does not need to hold references into
    /// transient resolved child allocations.
    ///
    /// # Errors
    /// Returns the error from `resolver` if a lazy child cannot be loaded.
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
        self.search_by_path_hash(key, &path_hash, 0, resolver)
    }

    /// Looks up a key using a caller-provided path-hash function.
    ///
    /// This is the search equivalent of [`get_with_key_hash`] for HAMTs built
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
        self.search_by_path_hash(key, &path_hash, 0, resolver)
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

    fn get_by_path_hash<Q>(&self, key: &Q, path_hash: &StructuralHash, depth: usize) -> Option<&V>
    where
        K: Eq + Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let slot = bucket_index(path_hash, depth);
        let bit = 1_u32 << slot;

        if (self.datamap & bit) != 0 {
            let idx = map_index(self.datamap, slot);
            let (stored_key, value) = &self.leaves[idx];
            if stored_key.borrow() == key {
                return Some(value);
            }
            return None;
        }

        if (self.nodemap & bit) != 0 {
            let idx = map_index(self.nodemap, slot);
            match &self.children[idx] {
                NodeRef::Resolved(child) => {
                    return child.get_by_path_hash(key, path_hash, depth.saturating_add(1));
                }
                NodeRef::Lazy(_) => return None,
            }
        }

        None
    }

    fn search_by_path_hash<Q, F, E>(
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
        let slot = bucket_index(path_hash, depth);
        let bit = 1_u32 << slot;

        if (self.datamap & bit) != 0 {
            let idx = map_index(self.datamap, slot);
            let (stored_key, value) = &self.leaves[idx];
            if stored_key.borrow() == key {
                return Ok(Some(value.clone()));
            }
            return Ok(None);
        }

        if (self.nodemap & bit) != 0 {
            let idx = map_index(self.nodemap, slot);
            let child = match &self.children[idx] {
                NodeRef::Resolved(child) => child.clone(),
                NodeRef::Lazy(hash) => resolver(hash)?,
            };
            return child.search_by_path_hash(key, path_hash, depth.saturating_add(1), resolver);
        }

        Ok(None)
    }
}

/// Errors that can occur while building a HAMT from an entry iterator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HamtBuildError {
    /// Too many entries collided into the same slot after exhausting the
    /// available hash depth.
    HashCollision { depth: usize, bucket_size: usize },
}

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
    let bit_offset = depth.saturating_mul(HAMT_BRANCH_BITS);
    let byte_index = bit_offset / 8;
    let bit_shift = bit_offset % 8;

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

        let Some(next_depth) = depth.checked_add(1) else {
            return Err(HamtBuildError::HashCollision {
                depth,
                bucket_size: bucket.len(),
            });
        };
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
