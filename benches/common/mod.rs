//! Shared helpers for the HAMT benchmark suite.
//!
//! The HAMT benches (`persistence`, `state_groups`, `cumulative_rebuild`) all
//! need the same node-walk / encoding utilities. Keeping them here — generic
//! over `K, V` and referenced from a single `mod common;` in each bench —
//! means a change to the HAMT child layout or to `PersistedInternalNode` is
//! fixed once instead of silently drifting across three copies.

use std::sync::Arc;

use rezzy::hamt::{self, HamtNode, PersistedInternalNode};

/// Deterministic PRNG (`xorshift128+`) so bench inputs are reproducible
/// without adding a `rand` dependency.
pub struct Xorshift128 {
    state: [u64; 2],
}

impl Xorshift128 {
    pub fn new(seed: u64) -> Self {
        Self {
            state: [seed ^ 0x9E37_79B9_7F4A_7C15, seed.wrapping_add(1) | 1],
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state[0];
        let y = self.state[1];
        self.state[0] = y;
        x ^= x << 23;
        x ^= x >> 17;
        x ^= y ^ (y >> 26);
        self.state[1] = x;
        x.wrapping_add(y)
    }
}

/// Walks `old` and `new` in lockstep (same alignment logic
/// `diff_node_hashes` uses internally) and collects every node in `new`
/// that wasn't already present in `old` — i.e. exactly the nodes a
/// path-copying mutation newly allocated and that a storage backend must
/// persist to make `new` durable.
///
/// Trees here are always fully resolved (no `NodeRef::Lazy`), so this never
/// needs a resolver.
pub fn collect_new_nodes<K, V>(
    old: &Arc<HamtNode<K, V>>,
    new: &Arc<HamtNode<K, V>>,
    out: &mut Vec<Arc<HamtNode<K, V>>>,
) {
    if Arc::ptr_eq(old, new) || old.structural_hash == new.structural_hash {
        return;
    }
    out.push(Arc::clone(new));

    let (n_a, n_b) = (old.nodemap, new.nodemap);
    let (mut cidx_a, mut cidx_b) = (0usize, 0usize);
    for i in 0..32 {
        let bit = 1u32 << i;
        let (in_a, in_b) = (n_a & bit != 0, n_b & bit != 0);
        match (in_a, in_b) {
            (true, true) => {
                if let (hamt::NodeRef::Resolved(a), hamt::NodeRef::Resolved(b)) =
                    (&old.children[cidx_a], &new.children[cidx_b])
                {
                    collect_new_nodes(a, b, out);
                }
                cidx_a += 1;
                cidx_b += 1;
            }
            (true, false) => cidx_a += 1,
            (false, true) => {
                if let hamt::NodeRef::Resolved(b) = &new.children[cidx_b] {
                    // Entire subtree is new (a fresh branch point), not just
                    // its root — every node under it must be persisted too.
                    collect_all_nodes(b, out);
                }
                cidx_b += 1;
            }
            (false, false) => {}
        }
    }
}

/// Collects `node` and every internal node reachable from it via `nodemap`
/// children, in pre-order.
pub fn collect_all_nodes<K, V>(node: &Arc<HamtNode<K, V>>, out: &mut Vec<Arc<HamtNode<K, V>>>) {
    out.push(Arc::clone(node));
    for child in &node.children {
        if let hamt::NodeRef::Resolved(c) = child {
            collect_all_nodes(c, out);
        }
    }
}

/// Re-encodes a `HamtNode` as the on-disk [`PersistedInternalNode`] shape,
/// so its `encode_v1()` length measures the exact persisted byte cost.
pub fn to_persisted<K: Clone, V: Clone>(node: &HamtNode<K, V>) -> PersistedInternalNode<K, V> {
    PersistedInternalNode {
        datamap: node.datamap,
        nodemap: node.nodemap,
        structural_hash: node.structural_hash,
        leaves: node.leaves.clone(),
        child_hashes: node
            .children
            .iter()
            .map(hamt::NodeRef::structural_hash)
            .collect(),
    }
}
