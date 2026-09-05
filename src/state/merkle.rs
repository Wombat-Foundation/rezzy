//! Sparse-Merkle commitments and selective proofs for resolved room state.
//!
//! This is deliberately complementary to [`super::LtHash`]: it proves a
//! particular `(event_type, state_key) -> event_id` binding or its absence,
//! whereas `LtHash` is the efficient homomorphic accumulator for a whole map.

use alloc::{collections::BTreeMap, string::ToString, vec::Vec};
use sha3::{Digest, Sha3_256};

use crate::state::at::SharedState;

/// A SHA3-256 digest used for state-map keys, leaves, and internal nodes.
pub type Hash = [u8; 32];

/// The fixed bit depth of the resolved-state sparse Merkle map.
pub const STATE_DEPTH: usize = 256;

const KEY_DST: &[u8] = b"msc4511:state-key:v1";
const LEAF_DST: &[u8] = b"msc4511:state-leaf:v1";
const NODE_DST: &[u8] = b"msc4511:state-node:v1";
const EMPTY_DST: &[u8] = b"msc4511:state-empty:v1";

fn hash_parts(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha3_256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn bit(key: &Hash, depth: usize) -> u8 {
    (key[depth / 8] >> 7_usize.saturating_sub(depth % 8)) & 1
}

fn encode_pair(event_type: &str, state_key: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &u64::try_from(event_type.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(event_type.as_bytes());
    bytes.extend_from_slice(
        &u64::try_from(state_key.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(state_key.as_bytes());
    bytes
}

/// Derives the sparse-tree position for a resolved-state key.
#[must_use]
pub fn state_key_hash(event_type: &str, state_key: &str) -> Hash {
    let encoded = encode_pair(event_type, state_key);
    hash_parts(&[KEY_DST, &encoded])
}

/// Derives the committed leaf for a resolved-state key and its winning event.
#[must_use]
pub fn state_leaf_hash(event_type: &str, state_key: &str, event_id: &str) -> Hash {
    let encoded = encode_pair(event_type, state_key);
    hash_parts(&[
        LEAF_DST,
        &encoded,
        &u64::try_from(event_id.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
        event_id.as_bytes(),
    ])
}

fn node(depth: usize, left: Hash, right: Hash) -> Hash {
    hash_parts(&[
        NODE_DST,
        &u16::try_from(depth).unwrap_or(u16::MAX).to_be_bytes(),
        &left,
        &right,
    ])
}

fn empty_table() -> [Hash; STATE_DEPTH + 1] {
    let mut empty = [[0; 32]; STATE_DEPTH + 1];
    empty[STATE_DEPTH] = hash_parts(&[EMPTY_DST]);
    for depth in (0..STATE_DEPTH).rev() {
        let child_depth = depth.saturating_add(1);
        empty[depth] = node(depth, empty[child_depth], empty[child_depth]);
    }
    empty
}

/// One sibling in a state-map proof, ordered leaf-to-root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateProofStep {
    pub hash: Hash,
}

/// A sparse-Merkle commitment to a resolved state map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateMap {
    leaves: BTreeMap<Hash, Hash>,
}

impl StateMap {
    /// Builds a state-map commitment from an already-resolved state map.
    #[must_use]
    pub fn from_state<Id, K>(state: &SharedState<Id, K>) -> Self
    where
        Id: core::fmt::Display,
        K: Ord + AsRef<str>,
    {
        let mut leaves = BTreeMap::new();
        for ((event_type, state_key), event_id) in state {
            let event_id = event_id.to_string();
            leaves.insert(
                state_key_hash(event_type.as_str(), state_key.as_ref()),
                state_leaf_hash(event_type.as_str(), state_key.as_ref(), &event_id),
            );
        }
        Self { leaves }
    }

    /// Returns the canonical root, including the canonical empty root.
    #[must_use]
    pub fn root(&self) -> Hash {
        let empty = empty_table();
        let entries: Vec<(Hash, Hash)> = self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        subtree(&entries, 0, &empty)
    }

    /// Like [`Self::root`], wrapped as an [`crate::merkle::UnsignedRoot`] --
    /// see that type's docs for what a caller needs to do before presenting
    /// this value as a proof of anything to someone else (this crate's own
    /// "State DAG interaction" text already treats a resolved-state root as
    /// local/unauthoritative for the identical reason: nothing signs
    /// `state_root` on any event today). Prefer this over `root()` at any
    /// call site that hands the root outside the local process.
    #[must_use]
    pub fn unsigned_root(&self) -> crate::merkle::UnsignedRoot {
        crate::merkle::UnsignedRoot(self.root())
    }

    /// Returns an inclusion proof for a resolved-state binding.
    #[must_use]
    pub fn inclusion_proof(
        &self,
        event_type: &str,
        state_key: &str,
        event_id: &str,
    ) -> Option<(Vec<StateProofStep>, Hash)> {
        let key = state_key_hash(event_type, state_key);
        if self.leaves.get(&key) != Some(&state_leaf_hash(event_type, state_key, event_id)) {
            return None;
        }
        let empty = empty_table();
        let entries: Vec<(Hash, Hash)> = self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        let (_, path) = descend(&entries, &key, 0, &empty);
        Some((path, self.root()))
    }

    /// Returns a non-inclusion proof for an absent state key.
    #[must_use]
    pub fn non_inclusion_proof(
        &self,
        event_type: &str,
        state_key: &str,
    ) -> Option<(Vec<StateProofStep>, usize, Hash)> {
        let key = state_key_hash(event_type, state_key);
        if self.leaves.contains_key(&key) {
            return None;
        }
        let empty = empty_table();
        let entries: Vec<(Hash, Hash)> = self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        let (depth, path) = descend(&entries, &key, 0, &empty);
        Some((path, depth, self.root()))
    }
}

fn subtree(entries: &[(Hash, Hash)], depth: usize, empty: &[Hash; STATE_DEPTH + 1]) -> Hash {
    if entries.is_empty() {
        return empty[depth];
    }
    if depth == STATE_DEPTH {
        return entries[0].1;
    }
    let mut left = Vec::new();
    let mut right = Vec::new();
    for entry in entries {
        if bit(&entry.0, depth) == 0 {
            left.push(*entry);
        } else {
            right.push(*entry);
        }
    }
    node(
        depth,
        subtree(&left, depth.saturating_add(1), empty),
        subtree(&right, depth.saturating_add(1), empty),
    )
}

fn descend(
    entries: &[(Hash, Hash)],
    key: &Hash,
    depth: usize,
    empty: &[Hash; STATE_DEPTH + 1],
) -> (usize, Vec<StateProofStep>) {
    if entries.is_empty() || depth == STATE_DEPTH {
        return (depth, Vec::new());
    }
    let mut left = Vec::new();
    let mut right = Vec::new();
    for entry in entries {
        if bit(&entry.0, depth) == 0 {
            left.push(*entry);
        } else {
            right.push(*entry);
        }
    }
    let (term, mut path) = if bit(key, depth) == 0 {
        descend(&left, key, depth.saturating_add(1), empty)
    } else {
        descend(&right, key, depth.saturating_add(1), empty)
    };
    let sibling = if bit(key, depth) == 0 {
        subtree(&right, depth.saturating_add(1), empty)
    } else {
        subtree(&left, depth.saturating_add(1), empty)
    };
    path.push(StateProofStep { hash: sibling });
    (term, path)
}

/// Verifies that a state key is bound to an event ID by `root`.
#[must_use]
pub fn verify_inclusion(
    event_type: &str,
    state_key: &str,
    event_id: &str,
    path: &[StateProofStep],
    root: Hash,
) -> bool {
    verify(
        state_key_hash(event_type, state_key),
        state_leaf_hash(event_type, state_key, event_id),
        STATE_DEPTH,
        path,
        root,
    )
}

/// Verifies that a state key is absent from `root`.
#[must_use]
pub fn verify_non_inclusion(
    event_type: &str,
    state_key: &str,
    terminal_depth: usize,
    path: &[StateProofStep],
    root: Hash,
) -> bool {
    if terminal_depth > STATE_DEPTH {
        return false;
    }
    verify(
        state_key_hash(event_type, state_key),
        empty_table()[terminal_depth],
        terminal_depth,
        path,
        root,
    )
}

fn verify(
    key: Hash,
    mut value: Hash,
    terminal_depth: usize,
    path: &[StateProofStep],
    root: Hash,
) -> bool {
    if path.len() != terminal_depth {
        return false;
    }
    for (i, step) in path.iter().enumerate() {
        let depth = terminal_depth.saturating_sub(1).saturating_sub(i);
        value = if bit(&key, depth) == 0 {
            node(depth, value, step.hash)
        } else {
            node(depth, step.hash, value)
        };
    }
    value == root
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use alloc::string::String;

    use super::*;

    fn state() -> SharedState<String, String> {
        let mut state = SharedState::new();
        state.insert(
            ("m.room.create".into(), String::new()),
            "$create:example.org".into(),
        );
        state.insert(
            ("m.room.member".into(), "@alice:example.org".into()),
            "$alice:example.org".into(),
        );
        state
    }

    #[test]
    fn inclusion_proves_resolved_state_binding() {
        let map = StateMap::from_state(&state());
        let (path, root) = map
            .inclusion_proof("m.room.member", "@alice:example.org", "$alice:example.org")
            .unwrap();
        assert_eq!(path.len(), STATE_DEPTH);
        assert!(verify_inclusion(
            "m.room.member",
            "@alice:example.org",
            "$alice:example.org",
            &path,
            root,
        ));
        assert!(!verify_inclusion(
            "m.room.member",
            "@alice:example.org",
            "$wrong:example.org",
            &path,
            root,
        ));
    }

    #[test]
    fn non_inclusion_proves_absent_state_key() {
        let map = StateMap::from_state(&state());
        let (path, terminal_depth, root) = map.non_inclusion_proof("m.room.topic", "").unwrap();
        assert!(verify_non_inclusion(
            "m.room.topic",
            "",
            terminal_depth,
            &path,
            root,
        ));
        assert!(!verify_non_inclusion(
            "m.room.name",
            "",
            terminal_depth,
            &path,
            root,
        ));
    }

    #[test]
    fn roots_change_when_a_winner_changes() {
        let before = StateMap::from_state(&state()).root();
        let mut changed = state();
        changed.insert(
            ("m.room.member".into(), "@alice:example.org".into()),
            "$alice-new:example.org".into(),
        );
        assert_ne!(before, StateMap::from_state(&changed).root());
    }
}
