// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! State delta compression — efficient incremental state storage/checkpoint chains.
//!
//! Instead of storing the full `state_map` at *every* event, homeservers can
//! store a base snapshot and a chain of deltas.
//! This module provides the primitives for computing and applying those deltas.

use alloc::string::String;
use alloc::vec::Vec;

/// Which phase of state resolution produced a delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ResolvePhase {
    /// Power events: `m.room.create`, `m.room.power_levels`, `m.room.join_rules`,
    /// bans, and kicks. Sorted by reverse topological order (Kahn's algorithm).
    Power,
    /// Non-power events: everything else. Sorted by mainline proximity.
    NonPower,
}

/// A per-event record of what changed in the resolved state during resolution.
///
/// [`resolve_iterative_sort_with_deltas`](crate::resolve_iterative_sort_with_deltas) emits one of
/// these for every conflicted event that is auth-checked, regardless of whether
/// it was accepted or rejected.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolutionDelta<Id: crate::basespec::rezzy_types::EventId = String> {
    /// The event that was auth-checked.
    pub event_id: Id,
    /// Whether the event passed the iterative auth check.
    pub accepted: bool,
    /// The `(event_type, state_key)` slot this event targets.
    pub key: (String, String),
    /// The event ID that was previously in this slot (if any).
    /// `None` if the slot was empty before this event.
    pub replaced: Option<Id>,
    /// Whether this was processed in the power phase or non-power phase.
    pub phase: ResolvePhase,
}

/// A single state delta entry — an addition, modification, or deletion.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StateDelta<Id: crate::basespec::rezzy_types::EventId = String> {
    /// The event type (e.g. `"m.room.member"`).
    pub event_type: String,
    /// The state key (e.g. `"@alice:example.com"` or `""`).
    pub state_key: String,
    /// The new event ID, or `None` if this key was deleted.
    pub event_id: Option<Id>,
}

/// Computes the delta between a parent state and the current state.
///
/// Returns a list of [`StateDelta`] entries representing:
/// - **Additions**: keys present in `current` but not in `parent`.
/// - **Modifications**: keys present in both but with different event IDs.
/// - **Deletions**: keys present in `parent` but not in `current`.
///
/// If the two states are identical, returns an empty `Vec`.
#[must_use]
pub fn compute_state_delta<Id: crate::basespec::rezzy_types::EventId>(
    parent: &crate::state::at::SharedState<Id>,
    current: &crate::state::at::SharedState<Id>,
) -> Vec<StateDelta<Id>> {
    let mut deltas = Vec::new();

    // Additions and modifications
    for ((event_type, state_key), event_id) in current {
        match parent.get(&(event_type.clone(), state_key.clone())) {
            Some(parent_event_id) if parent_event_id == event_id => {}
            _ => {
                deltas.push(StateDelta {
                    event_type: event_type.clone(),
                    state_key: state_key.clone(),
                    event_id: Some(event_id.clone()),
                });
            }
        }
    }

    // Deletions
    for key in parent.keys() {
        if !current.contains_key(key) {
            deltas.push(StateDelta {
                event_type: key.0.clone(),
                state_key: key.1.clone(),
                event_id: None,
            });
        }
    }

    deltas
}

/// Applies a list of deltas to a base state, producing the reconstructed state.
///
/// - Entries with `event_id = Some(id)` are inserted/overwritten.
/// - Entries with `event_id = None` are removed from the base.
#[must_use]
pub fn apply_state_delta<Id: crate::basespec::rezzy_types::EventId>(
    base: &crate::state::at::SharedState<Id>,
    deltas: &[StateDelta<Id>],
) -> crate::state::at::SharedState<Id> {
    let mut result = base.clone();
    for delta in deltas {
        let key = (delta.event_type.clone(), delta.state_key.clone());
        if let Some(ref event_id) = delta.event_id {
            result.insert(key, event_id.clone());
        } else {
            result.remove(&key);
        }
    }
    result
}

pub mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    /// # Errors
    /// Returns an error if the hex string fails to serialize.
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        let mut hex = alloc::string::String::with_capacity(64);
        for b in bytes {
            use core::fmt::Write;
            write!(hex, "{b:02x}").expect("String formatting is infallible");
        }
        serializer.serialize_str(&hex)
    }

    /// # Errors
    /// Returns an error if the string is not exactly 64 characters long or contains invalid hex characters.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let s = alloc::string::String::deserialize(deserializer)?;
        if s.len() != 64 {
            return Err(serde::de::Error::custom("expected 64-character hex string"));
        }
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let start = i.saturating_mul(2);
            let end = start.saturating_add(2);
            let byte_str = &s[start..end];
            *byte = u8::from_str_radix(byte_str, 16)
                .map_err(|_| serde::de::Error::custom("invalid hex character"))?;
        }
        Ok(bytes)
    }
}

pub mod hex_serde_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    /// # Errors
    /// Returns an error if the underlying hex string fails to serialize.
    pub fn serialize<S: Serializer>(
        bytes: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => super::hex_serde::serialize(b, serializer),
            None => serializer.serialize_none(),
        }
    }

    /// # Errors
    /// Returns an error if the string is present but is not exactly 64 characters long or contains invalid hex characters.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        let opt = Option::<alloc::string::String>::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                if s.len() != 64 {
                    return Err(serde::de::Error::custom("expected 64-character hex string"));
                }
                let mut bytes = [0u8; 32];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    let start = i.saturating_mul(2);
                    let end = start.saturating_add(2);
                    let byte_str = &s[start..end];
                    *byte = u8::from_str_radix(byte_str, 16)
                        .map_err(|_| serde::de::Error::custom("invalid hex character"))?;
                }
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }
}

/// A 2048-byte homomorphic state hash using `LtHash`.
///
/// `LtHash` (Lattice Hash) is based on the homomorphic hashing paradigm first introduced
/// by Bellare and Micciancio in their 1997 paper *"A New Paradigm for Collision-Free
/// Hashing: Incrementality at Reduced Cost"*. This specific 2048-byte instantiation
/// (using 1024 16-bit integers and wrapping addition) is modeled after the industry-standard
/// implementation in Meta's Folly library (`folly::crypto::LtHash`).
///
/// Each `(event_type, state_key, event_id)` entry is expanded to 1024 16-bit
/// integers via SHA-256 (acting as an XOF). The state hash is the wrapping
/// addition of all these vectors. This provides:
///
/// - **O(1) incremental updates**: insert = `hash + expanded`,
///   remove = `hash - expanded`.
/// - **Order independence**: addition is commutative + associative.
/// - **Cryptographic security**: hard to find multiset collisions (SVP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LtHash(pub [u16; 1024]);

impl Default for LtHash {
    fn default() -> Self {
        Self::ZERO
    }
}

struct HasherWrite<'a>(&'a mut sha2::Sha256);
impl core::fmt::Write for HasherWrite<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        use sha2::Digest;
        self.0.update(s.as_bytes());
        Ok(())
    }
}

impl LtHash {
    /// The identity element (empty state).
    pub const ZERO: Self = Self([0u16; 1024]);

    /// Compute the 2048-byte expanded seed for a single state entry.
    #[must_use]
    fn seed(event_type: &str, state_key: &str, event_id: &dyn core::fmt::Display) -> Self {
        use core::fmt::Write;
        use sha2::{Digest, Sha256};

        let mut out = [0u16; 1024];

        let mut base_hasher = Sha256::new();
        base_hasher.update((event_type.len() as u64).to_le_bytes());
        base_hasher.update(event_type.as_bytes());
        base_hasher.update((state_key.len() as u64).to_le_bytes());
        base_hasher.update(state_key.as_bytes());

        let mut writer = HasherWrite(&mut base_hasher);
        write!(writer, "{event_id}").expect("HasherWrite formatting is infallible");

        for i in 0..64u16 {
            let mut hasher = base_hasher.clone();
            hasher.update(i.to_le_bytes());
            let digest = hasher.finalize();

            for j in 0..16usize {
                let idx1 = j.saturating_mul(2);
                let idx2 = idx1.saturating_add(1);
                let bytes = [digest[idx1], digest[idx2]];
                let out_idx = usize::from(i).saturating_mul(16).saturating_add(j);
                out[out_idx] = u16::from_le_bytes(bytes);
            }
        }

        Self(out)
    }

    /// Add a seed into the hash (insert).
    fn add_seed(&mut self, seed: &Self) {
        for (a, b) in self.0.iter_mut().zip(seed.0.iter()) {
            *a = a.wrapping_add(*b);
        }
    }

    /// Subtract a seed from the hash (remove).
    fn sub_seed(&mut self, seed: &Self) {
        for (a, b) in self.0.iter_mut().zip(seed.0.iter()) {
            *a = a.wrapping_sub(*b);
        }
    }

    /// Record a state entry being inserted.
    pub fn insert(&mut self, event_type: &str, state_key: &str, event_id: &str) {
        let s = Self::seed(event_type, state_key, &event_id);
        self.add_seed(&s);
    }

    /// Record a state entry being removed.
    pub fn remove(&mut self, event_type: &str, state_key: &str, event_id: &str) {
        let s = Self::seed(event_type, state_key, &event_id);
        self.sub_seed(&s);
    }

    /// Record a state entry being replaced (old → new).
    pub fn replace(
        &mut self,
        event_type: &str,
        state_key: &str,
        old_event_id: &str,
        new_event_id: &str,
    ) {
        let old = Self::seed(event_type, state_key, &old_event_id);
        let new = Self::seed(event_type, state_key, &new_event_id);
        self.sub_seed(&old);
        self.add_seed(&new);
    }

    /// Compute the full hash from a state map (non-incremental).
    #[must_use]
    pub fn from_state<Id>(state: &crate::state::at::SharedState<Id>) -> Self
    where
        Id: crate::basespec::rezzy_types::EventId,
    {
        let mut hash = Self::ZERO;
        for ((event_type, state_key), event_id) in state {
            let s = Self::seed(event_type, state_key, event_id);
            hash.add_seed(&s);
        }
        hash
    }

    /// Finalize the 2048-byte lattice into a compact 32-byte cryptographic checksum.
    #[must_use]
    pub fn checksum(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for val in &self.0 {
            hasher.update(val.to_le_bytes());
        }
        hasher.finalize().into()
    }
}

/// Computes a deterministic 256-bit `LtHash` fingerprint of a
/// state map, returned as a 32-byte array.
///
/// This is a convenience wrapper around
/// [`LtHash::from_state`]. Each
/// `(event_type, state_key, event_id)` entry is hashed via
/// SHA-256 to produce a 2048-byte seed, and the state hash is the
/// wrapping addition of all seeds — making it order-independent and
/// incrementally updatable.
#[must_use]
pub fn compute_state_hash<Id: crate::basespec::rezzy_types::EventId>(
    state: &crate::state::at::SharedState<Id>,
) -> [u8; 32] {
    LtHash::from_state(state).checksum()
}

/// Maximum number of delta hops before a full snapshot is inserted (default: 100,
/// configurable: true).
///
/// Matches Synapse's `MAX_STATE_DELTA_HOPS`. When a delta chain would exceed
/// this length, [`compute_compacted_delta_chain_from_resolved`] inserts a full
/// base snapshot instead of another delta, bounding reconstruction cost to at
/// most this many hops.
pub const MAX_DELTA_CHAIN_HOPS: usize = 100;

/// A checkpoint that may be either a delta from a parent or a full snapshot.
///
/// When chain compaction triggers (every [`MAX_DELTA_CHAIN_HOPS`] events),
/// the checkpoint stores the full state map as `snapshot` instead of a delta.
/// Readers walk backwards from any checkpoint, applying deltas, until they
/// hit a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CompactedCheckpoint<Id: crate::basespec::rezzy_types::EventId = String> {
    /// 256-bit hash of the state map at this point.
    #[serde(with = "hex_serde")]
    pub state_hash: [u8; 32],
    /// Hash of the parent checkpoint (if any).
    #[serde(with = "hex_serde_opt")]
    pub parent_hash: Option<[u8; 32]>,
    /// The event ID that produced this checkpoint.
    pub event_id: Id,
    /// Deltas from the parent state. Empty when `snapshot` is `Some`.
    pub deltas: Vec<StateDelta<Id>>,
    /// Full state snapshot, present every [`MAX_DELTA_CHAIN_HOPS`] checkpoints.
    /// When this is `Some`, `deltas` is empty and reconstruction starts here.
    pub snapshot: Option<crate::state::at::SharedState<Id>>,
}

/// Builds a compacted delta chain from pre-resolved `(event_id, state_map)` pairs,
/// inserting full snapshots every `max_hops` events to bound reconstruction cost.
///
/// This is the recommended API for homeserver state storage. The caller supplies
/// pre-resolved states (from [`compute_state_at_batch`](crate::compute_state_at_batch)
/// / [`resolve_iterative_sort`](crate::resolve_iterative_sort)), and this function handles only the
/// storage compression concern.
///
/// A custom `max_hops` can be provided; pass `None` to use the default
/// [`MAX_DELTA_CHAIN_HOPS`] (100).
#[must_use]
pub fn compute_compacted_delta_chain_from_resolved<Id: crate::basespec::rezzy_types::EventId>(
    resolved_states: impl IntoIterator<Item = (Id, crate::state::at::SharedState<Id>)>,
    max_hops: Option<usize>,
) -> Vec<CompactedCheckpoint<Id>> {
    let max_hops = max_hops.unwrap_or(MAX_DELTA_CHAIN_HOPS);
    let mut checkpoints = Vec::new();
    let mut prev_state: Option<crate::state::at::SharedState<Id>> = None;
    let mut prev_hash: Option<[u8; 32]> = None;
    let mut hops_since_snapshot: usize = 0;

    for (event_id, state) in resolved_states {
        let state_hash = compute_state_hash(&state);
        let current_hops = hops_since_snapshot.saturating_add(1);

        let (deltas, snapshot, recorded_hops) = match prev_state {
            Some(ref base) if current_hops < max_hops => {
                let deltas = compute_state_delta(base, &state);
                (deltas, None, current_hops)
            }
            _ => {
                // First event or chain exceeded max_hops — insert a
                // full snapshot to reset the chain.
                (Vec::new(), Some(state.clone()), 0)
            }
        };

        checkpoints.push(CompactedCheckpoint {
            state_hash,
            parent_hash: prev_hash,
            event_id,
            deltas,
            snapshot,
        });

        prev_hash = Some(state_hash);
        prev_state = Some(state);
        hops_since_snapshot = recorded_hops;
    }

    checkpoints
}

/// Reconstruct the full state map by looking up a checkpoint by event ID.
///
/// This is a convenience wrapper around [`reconstruct_state_at`] that finds
/// the checkpoint index for the given `event_id` and reconstructs the state.
///
/// Returns `None` if the event ID is not found in the checkpoint chain or
/// the chain is broken.
#[must_use]
pub fn reconstruct_state_at_by_event_id<Id: crate::basespec::rezzy_types::EventId>(
    checkpoints: &[CompactedCheckpoint<Id>],
    event_id: &Id,
) -> Option<crate::state::at::SharedState<Id>> {
    let idx = checkpoints.iter().position(|cp| &cp.event_id == event_id)?;
    reconstruct_state_at(checkpoints, idx)
}

/// Reconstructs the full state map from a stored delta chain.
///
/// Walks `checkpoints` **backwards** from `target_index`, applying deltas
/// until a snapshot is found. Returns the reconstructed state at that index.
///
/// # Arguments
///
/// * `checkpoints` — a slice of [`CompactedCheckpoint`]s in chronological order.
/// * `target_index` — the index of the checkpoint to reconstruct.
///
/// # Returns
///
/// `Some(state_map)` if a snapshot base was found, `None` if the chain is
/// broken (no snapshot ancestor exists).
#[must_use]
pub fn reconstruct_state_at<Id: crate::basespec::rezzy_types::EventId>(
    checkpoints: &[CompactedCheckpoint<Id>],
    target_index: usize,
) -> Option<crate::state::at::SharedState<Id>> {
    if target_index >= checkpoints.len() {
        return None;
    }

    // Collect deltas by walking backwards until we hit a snapshot
    let mut delta_stack: Vec<&[StateDelta<Id>]> = Vec::new();
    let mut current_idx = target_index;

    loop {
        let cp = &checkpoints[current_idx];

        if let Some(ref snapshot) = cp.snapshot {
            // Found a base snapshot — apply accumulated deltas forward
            let mut state = snapshot.clone();
            while let Some(deltas) = delta_stack.pop() {
                for delta in deltas {
                    let key = (delta.event_type.clone(), delta.state_key.clone());
                    if let Some(ref event_id) = delta.event_id {
                        state.insert(key, event_id.clone());
                    } else {
                        state.remove(&key);
                    }
                }
            }
            return Some(state);
        }

        // No snapshot — push deltas and walk to parent
        delta_stack.push(&cp.deltas);

        let parent_hash = cp.parent_hash.as_ref()?;
        // Prefer immediate predecessor; fall back to scanning earlier checkpoints.
        if let Some(prev) = current_idx
            .checked_sub(1)
            .filter(|&pi| checkpoints[pi].state_hash == *parent_hash)
        {
            current_idx = prev;
        } else {
            current_idx = checkpoints[..current_idx]
                .iter()
                .rposition(|cp| cp.state_hash == *parent_hash)?;
        }
    }
}

/// Reconstructs the full state map at multiple checkpoint indices in one pass.
///
/// Instead of calling [`reconstruct_state_at`] N times (which re-walks shared
/// ancestors), this function finds the nearest snapshot before the earliest
/// target and walks forward once, capturing state at each requested index.
///
/// **Complexity**: `O(span)` where `span = max(targets) - snapshot_base`,
/// versus `O(N * span)` for N individual calls.
///
/// # Arguments
///
/// * `checkpoints` — a slice of [`CompactedCheckpoint`]s in chronological order.
/// * `target_indices` — the indices to reconstruct (duplicates and out-of-bounds
///   are silently ignored).
///
/// # Returns
///
/// A `imbl::OrdMap<usize, state_map>` keyed by the requested indices. Missing
/// entries indicate broken chains or out-of-bounds indices.
///
/// # Panics
///
/// Panics if an internal index increment overflows `usize` (should never
/// happen with valid checkpoint data).
#[must_use]
pub fn reconstruct_state_batch<Id: crate::basespec::rezzy_types::EventId>(
    checkpoints: &[CompactedCheckpoint<Id>],
    target_indices: &[usize],
) -> imbl::OrdMap<usize, crate::state::at::SharedState<Id>> {
    use crate::HashMap;

    let mut sorted_targets: Vec<usize> = target_indices
        .iter()
        .copied()
        .filter(|&i| i < checkpoints.len())
        .collect();
    sorted_targets.sort_unstable();
    sorted_targets.dedup();

    if sorted_targets.is_empty() {
        return imbl::OrdMap::new();
    }

    // Backward-only parent lookup: prefer immediate predecessor, fall back to
    // scanning earlier checkpoints. This avoids the HashMap shadowing bug where
    // duplicate hashes overwrite earlier entries.
    let find_parent_idx = |idx: usize, parent_hash: &[u8; 32]| -> Option<usize> {
        idx.checked_sub(1)
            .filter(|&pi| checkpoints[pi].state_hash == *parent_hash)
            .or_else(|| {
                checkpoints[..idx]
                    .iter()
                    .rposition(|cp| cp.state_hash == *parent_hash)
            })
    };

    // Walk backwards from all targets to find all required ancestors
    let mut required_indices = alloc::collections::BTreeSet::new();
    let mut queue: Vec<usize> = sorted_targets.clone();
    while let Some(idx) = queue.pop() {
        if required_indices.insert(idx) && checkpoints[idx].snapshot.is_none() {
            if let Some(parent_hash) = &checkpoints[idx].parent_hash {
                if let Some(p_idx) = find_parent_idx(idx, parent_hash) {
                    queue.push(p_idx);
                }
            }
        }
    }

    let mut known_states = HashMap::new();
    let mut results = imbl::OrdMap::new();

    // Iterate forward only through the required indices
    for idx in required_indices {
        let cp = &checkpoints[idx];
        let state = if let Some(ref snapshot) = cp.snapshot {
            snapshot.clone()
        } else if let Some(parent_hash) = &cp.parent_hash {
            if let Some(p_idx) = find_parent_idx(idx, parent_hash) {
                if let Some(parent_state) = known_states.get(&p_idx) {
                    apply_state_delta(parent_state, &cp.deltas)
                } else {
                    #[cfg(feature = "std")]
                    std::eprintln!(
                        "state_delta: checkpoint {idx} parent {p_idx} not reconstructed"
                    );
                    continue; // BROKEN CHAIN: Parent was required but not reconstructed (gap in chain)
                }
            } else {
                #[cfg(feature = "std")]
                std::eprintln!(
                    "state_delta: checkpoint {idx} has no earlier match for parent_hash {parent_hash:?}"
                );
                continue; // BROKEN CHAIN: No earlier checkpoint matches parent_hash
            }
        } else {
            #[cfg(feature = "std")]
            std::eprintln!(
                "state_delta: checkpoint {idx} is an orphan (no snapshot, no parent_hash)"
            );
            continue; // BROKEN CHAIN: No snapshot and no parent_hash — orphan checkpoint
        };

        if sorted_targets.binary_search(&idx).is_ok() {
            results.insert(idx, state.clone());
        }
        known_states.insert(idx, state);
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    type StateMap = crate::state::at::SharedState<String>;
    type ResolvedStates = Vec<(String, StateMap)>;

    #[test]
    fn test_roundtrip_identity() {
        let mut state = StateMap::new();
        state.insert(("m.room.create".into(), String::new()), "$1".into());
        state.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            "$2".into(),
        );

        let delta = compute_state_delta(&state, &state);
        assert!(
            delta.is_empty(),
            "identical states should produce no deltas"
        );
    }

    #[test]
    fn test_roundtrip_add_modify_delete() {
        let mut parent = StateMap::new();
        parent.insert(("m.room.create".into(), String::new()), "$1".into());
        parent.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            "$2".into(),
        );

        let mut current = StateMap::new();
        current.insert(
            ("m.room.create".into(), String::new()),
            "$1".into(), // unchanged
        );
        current.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            "$4".into(), // modified
        );
        current.insert(
            ("m.room.member".into(), "@bob:example.com".into()),
            "$3".into(), // added
        );
        // m.room.create is unchanged, alice is modified, bob is added
        // no deletions in this case

        let delta = compute_state_delta(&parent, &current);
        let reconstructed = apply_state_delta(&parent, &delta);
        assert_eq!(current, reconstructed);
    }

    #[test]
    fn test_deletion_roundtrip() {
        let mut parent = StateMap::new();
        parent.insert(("m.room.create".into(), String::new()), "$1".into());
        parent.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            "$2".into(),
        );

        // Current state has alice removed
        let mut current = StateMap::new();
        current.insert(("m.room.create".into(), String::new()), "$1".into());

        let delta = compute_state_delta(&parent, &current);
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].event_id, None); // deletion marker

        let reconstructed = apply_state_delta(&parent, &delta);
        assert_eq!(current, reconstructed);
    }

    #[test]
    fn test_state_hash_determinism() {
        let mut state = StateMap::new();
        state.insert(("m.room.create".into(), String::new()), "$1".into());
        state.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            "$2".into(),
        );

        let h1 = compute_state_hash(&state);
        let h2 = compute_state_hash(&state);
        assert_eq!(h1, h2, "same state must produce same hash");
        assert_eq!(h1.len(), 32, "LtHash final checksum should be 32 bytes");
    }

    #[test]
    fn test_state_hash_sensitivity() {
        let mut state_a = StateMap::new();
        state_a.insert(("m.room.create".into(), String::new()), "$1".into());

        let mut state_b = StateMap::new();
        state_b.insert(("m.room.create".into(), String::new()), "$2".into());

        assert_ne!(
            compute_state_hash(&state_a),
            compute_state_hash(&state_b),
            "different states must produce different hashes"
        );
    }

    #[test]
    fn test_lthash_determinism() {
        let mut state = StateMap::new();
        state.insert(("m.room.create".into(), String::new()), "$1".into());
        state.insert(("m.room.member".into(), "@a:x".into()), "$2".into());
        let h1 = LtHash::from_state(&state);
        let h2 = LtHash::from_state(&state);
        assert_eq!(h1, h2);
        assert_ne!(h1, LtHash::ZERO);
        assert_eq!(h1.checksum().len(), 32);
    }

    #[test]
    fn test_lthash_sensitivity() {
        let mut a = StateMap::new();
        a.insert(("m.room.create".into(), String::new()), "$1".into());
        let mut b = StateMap::new();
        b.insert(("m.room.create".into(), String::new()), "$2".into());
        assert_ne!(LtHash::from_state(&a), LtHash::from_state(&b),);
    }

    #[test]
    fn test_lthash_order_independence() {
        // Insert in different orders, same result
        let mut h1 = LtHash::ZERO;
        h1.insert("m.room.create", "", "$c");
        h1.insert("m.room.member", "@a:x", "$m");

        let mut h2 = LtHash::ZERO;
        h2.insert("m.room.member", "@a:x", "$m");
        h2.insert("m.room.create", "", "$c");

        assert_eq!(h1, h2);
    }

    #[test]
    fn test_lthash_incremental_matches_full() {
        let mut state = StateMap::new();
        state.insert(("m.room.create".into(), String::new()), "$c".into());
        state.insert(("m.room.topic".into(), String::new()), "$t".into());

        let full = LtHash::from_state(&state);

        let mut inc = LtHash::ZERO;
        inc.insert("m.room.create", "", "$c");
        inc.insert("m.room.topic", "", "$t");

        assert_eq!(full, inc);
    }

    #[test]
    fn test_lthash_insert_remove_roundtrip() {
        let mut h = LtHash::ZERO;
        h.insert("m.room.topic", "", "$t");
        assert_ne!(h, LtHash::ZERO);
        h.remove("m.room.topic", "", "$t");
        assert_eq!(h, LtHash::ZERO);
    }

    #[test]
    fn test_lthash_replace() {
        // Build state with $t1, then replace → $t2
        let mut h = LtHash::ZERO;
        h.insert("m.room.create", "", "$c");
        h.insert("m.room.topic", "", "$t1");
        h.replace("m.room.topic", "", "$t1", "$t2");

        // Build state with $t2 from scratch
        let mut expected = LtHash::ZERO;
        expected.insert("m.room.create", "", "$c");
        expected.insert("m.room.topic", "", "$t2");

        assert_eq!(h, expected);
    }

    #[test]
    fn test_compaction_inserts_snapshots() {
        // NOTE: This test creates `O(N^2)` state items as it builds the DAG.
        // `LtHash` computes 64 SHA-256 iterations per item, making large `N` values
        // extremely slow in debug builds. We keep `N=35` to ensure fast tests.
        // Build 35 pre-resolved states — should trigger snapshots at 0, 10, 20, 30
        let states: ResolvedStates = (1..=35)
            .map(|i| {
                let mut state = StateMap::new();
                for j in 1..=i {
                    state.insert(
                        (
                            "m.room.member".into(),
                            alloc::format!("@user_{j}:example.com"),
                        ),
                        alloc::format!("${j}"),
                    );
                }
                (alloc::format!("${i}"), state)
            })
            .collect();

        let checkpoints = compute_compacted_delta_chain_from_resolved(states, Some(10));
        assert_eq!(checkpoints.len(), 35);

        // First event always gets a snapshot (no parent)
        assert!(
            checkpoints[0].snapshot.is_some(),
            "first event must have snapshot"
        );

        // Count snapshots
        let snapshot_count = checkpoints
            .iter()
            .filter(|cp| cp.snapshot.is_some())
            .count();
        assert!(
            snapshot_count >= 3,
            "35 events with max_hops=10 should produce at least 3 snapshots, got {snapshot_count}"
        );

        // No delta chain should exceed max_hops
        for (i, cp) in checkpoints.iter().enumerate() {
            if cp.snapshot.is_some() {
                continue;
            }
            // Walk back to find the nearest snapshot
            let mut hops = 0;
            let mut idx = i;
            while checkpoints[idx].snapshot.is_none() {
                hops += 1;
                // Find parent by hash
                let parent_hash = checkpoints[idx].parent_hash.as_ref().unwrap();
                idx = checkpoints
                    .iter()
                    .position(|c| c.state_hash == *parent_hash)
                    .unwrap();
            }
            assert!(
                hops < 10,
                "delta chain at index {i} has {hops} hops, exceeds max 10"
            );
        }
    }

    #[test]
    fn test_reconstruct_state_at() {
        // NOTE: This test creates `O(N^2)` state items as it builds the DAG.
        // `LtHash` computes 64 SHA-256 iterations per item, making large `N` values
        // extremely slow in debug builds. We keep `N=45` to ensure fast tests.
        // Build 45 pre-resolved states — will have snapshots at 0, 10, 20, 30, 40
        let states: ResolvedStates = (1..=45)
            .map(|i| {
                let mut state = StateMap::new();
                for j in 1..=i {
                    state.insert(
                        (
                            "m.room.member".into(),
                            alloc::format!("@user_{j}:example.com"),
                        ),
                        alloc::format!("${j}"),
                    );
                }
                (alloc::format!("${i}"), state)
            })
            .collect();

        let checkpoints = compute_compacted_delta_chain_from_resolved(states, Some(10));

        // Reconstruct state at the last event
        let state =
            reconstruct_state_at(&checkpoints, 44).expect("should reconstruct state at tip");

        // Should have 45 member entries
        assert_eq!(state.len(), 45, "state at tip should have 45 entries");

        // Verify a specific entry
        let key = ("m.room.member".into(), "@user_12:example.com".into());
        assert_eq!(state.get(&key), Some(&"$12".into()));

        // Reconstruct at the first event
        let state_first =
            reconstruct_state_at(&checkpoints, 0).expect("should reconstruct state at first");
        assert_eq!(state_first.len(), 1);

        // Reconstruct at mid-point
        let state_mid =
            reconstruct_state_at(&checkpoints, 22).expect("should reconstruct at index 22");
        assert_eq!(state_mid.len(), 23); // events 1..=23
    }

    #[test]
    fn test_reconstruct_out_of_bounds() {
        let result = reconstruct_state_at::<String>(&[], 0);
        assert!(result.is_none());

        let result = reconstruct_state_at::<String>(&[], 42);
        assert!(result.is_none());
    }

    #[test]
    fn test_compacted_delta_chain_from_resolved_snapshots() {
        // NOTE: This test creates `O(N^2)` state items as it builds the DAG.
        // `LtHash` computes 64 SHA-256 iterations per item, making large `N` values
        // extremely slow in debug builds. We keep `N=35` to ensure fast tests.
        // Create 35 sequential resolved states
        let states: ResolvedStates = (1..=35)
            .map(|i| {
                let mut state = StateMap::new();
                state.insert(
                    (
                        "m.room.member".into(),
                        alloc::format!("@user_{i}:example.com"),
                    ),
                    alloc::format!("${i}"),
                );
                // Keep previous entries too
                for j in 1..i {
                    state.insert(
                        (
                            "m.room.member".into(),
                            alloc::format!("@user_{j}:example.com"),
                        ),
                        alloc::format!("${j}"),
                    );
                }
                (alloc::format!("${i}"), state)
            })
            .collect();

        let checkpoints = compute_compacted_delta_chain_from_resolved(states.clone(), Some(10));

        assert_eq!(checkpoints.len(), 35);

        // First event always gets a snapshot
        assert!(checkpoints[0].snapshot.is_some());

        // Count snapshots
        let snapshot_count = checkpoints
            .iter()
            .filter(|cp| cp.snapshot.is_some())
            .count();
        assert!(
            snapshot_count >= 3,
            "35 events with max_hops=10 should produce at least 3 snapshots, got {snapshot_count}"
        );

        // Verify all states are reconstructable
        let last_state = reconstruct_state_at(&checkpoints, 34).expect("should reconstruct last");
        assert_eq!(last_state.len(), 35);

        // Verify no checkpoint is more than max_hops deltas away from a snapshot
        let mut hops = 0_usize;
        for cp in &checkpoints {
            if cp.snapshot.is_some() {
                hops = 0;
            } else {
                hops += 1;
                assert!(
                    hops < 10,
                    "checkpoint {} is {hops} hops from nearest snapshot, exceeds max_hops=10",
                    cp.event_id
                );
            }
        }
    }

    #[test]
    fn test_reconstruct_state_at_by_event_id_lookup() {
        let states: ResolvedStates = (1..=10)
            .map(|i| {
                let mut state = StateMap::new();
                for j in 1..=i {
                    state.insert(
                        (
                            "m.room.member".into(),
                            alloc::format!("@user_{j}:example.com"),
                        ),
                        alloc::format!("${j}"),
                    );
                }
                (alloc::format!("${i}"), state)
            })
            .collect();

        let checkpoints = compute_compacted_delta_chain_from_resolved(states, Some(100));

        // Lookup by event ID
        let state_5 = reconstruct_state_at_by_event_id(&checkpoints, &String::from("$5"))
            .expect("should find $5");
        assert_eq!(state_5.len(), 5);

        let state_10 = reconstruct_state_at_by_event_id(&checkpoints, &String::from("$10"))
            .expect("should find $10");
        assert_eq!(state_10.len(), 10);

        // Missing event ID
        assert!(reconstruct_state_at_by_event_id(&checkpoints, &String::from("$999")).is_none());
    }

    #[test]
    fn test_consecutive_identical_states_reconstruction() {
        // Consecutive states with identical content produce identical hashes.
        // This must not break backward reconstruction.
        let state = {
            let mut s = StateMap::new();
            s.insert(("m.room.create".into(), String::new()), "$create".into());
            s
        };

        // 5 events, all producing the same state (non-state events)
        let states: ResolvedStates = (1..=5)
            .map(|i| (alloc::format!("${i}"), state.clone()))
            .collect();

        let checkpoints = compute_compacted_delta_chain_from_resolved(states, Some(100));
        assert_eq!(checkpoints.len(), 5);

        // All hashes should be identical
        let first_hash = &checkpoints[0].state_hash;
        for cp in &checkpoints[1..] {
            assert_eq!(&cp.state_hash, first_hash);
        }

        // Every checkpoint must still reconstruct correctly
        for i in 0..5 {
            let reconstructed = reconstruct_state_at(&checkpoints, i)
                .unwrap_or_else(|| panic!("failed to reconstruct checkpoint {i}"));
            assert_eq!(reconstructed, state, "mismatch at checkpoint {i}");
        }

        // Event ID lookup must also work
        for i in 1..=5 {
            let result = reconstruct_state_at_by_event_id(&checkpoints, &alloc::format!("${i}"));
            assert!(result.is_some(), "event ID lookup failed for ${i}");
            assert_eq!(result.unwrap(), state);
        }
    }

    /// Builds the shared forward-jump regression fixture: 3 checkpoints where
    /// indices 0 and 2 share the same state hash, with index 1 having a
    /// different hash. Returns `(checkpoints, state_a, state_b)`.
    fn forward_jump_fixture() -> (alloc::vec::Vec<CompactedCheckpoint>, StateMap, StateMap) {
        let shared_hash = [0xAA; 32];
        let different_hash = [0xBB; 32];

        let state_a = {
            let mut s = StateMap::new();
            s.insert(("m.room.create".into(), String::new()), "$c".into());
            s
        };
        let state_b = {
            let mut s = state_a.clone();
            s.insert(("m.room.topic".into(), String::new()), "$t".into());
            s
        };

        let checkpoints = alloc::vec![
            CompactedCheckpoint::<String> {
                state_hash: shared_hash,
                parent_hash: None,
                event_id: "$0".into(),
                deltas: alloc::vec![],
                snapshot: Some(state_a.clone()),
            },
            CompactedCheckpoint::<String> {
                state_hash: different_hash,
                parent_hash: Some(shared_hash),
                event_id: "$1".into(),
                deltas: alloc::vec![StateDelta {
                    event_type: "m.room.topic".into(),
                    state_key: String::new(),
                    event_id: Some("$t".into()),
                }],
                snapshot: None,
            },
            CompactedCheckpoint::<String> {
                state_hash: shared_hash, // same as checkpoint 0!
                parent_hash: Some(different_hash),
                event_id: "$2".into(),
                deltas: alloc::vec![StateDelta {
                    event_type: "m.room.topic".into(),
                    state_key: String::new(),
                    event_id: None, // deletion — reverts to state_a
                }],
                snapshot: None,
            },
        ];

        (checkpoints, state_a, state_b)
    }

    /// Regression: `hash_to_idx` used to map duplicate hashes to the *last*
    /// occurrence, which could cause `reconstruct_state_at` to jump *forward*
    /// instead of backward, corrupting or hanging reconstruction.
    #[test]
    fn test_no_forward_jump_on_duplicate_hashes() {
        let (checkpoints, state_a, state_b) = forward_jump_fixture();

        // Without the forward-jump guard, hash_to_idx["HASH_A"] = 2 (last),
        // and checkpoint 1's parent lookup would jump to 2 (forward!) instead of 0.
        let result_0 = reconstruct_state_at(&checkpoints, 0).expect("cp 0");
        assert_eq!(result_0, state_a);

        let result_1 = reconstruct_state_at(&checkpoints, 1).expect("cp 1");
        assert_eq!(result_1, state_b);

        let result_2 = reconstruct_state_at(&checkpoints, 2).expect("cp 2");
        assert_eq!(result_2, state_a);
    }

    /// Same forward-jump regression but for the batch reconstruction path.
    #[test]
    fn test_no_forward_jump_batch_reconstruction() {
        let (checkpoints, state_a, state_b) = forward_jump_fixture();

        let results = reconstruct_state_batch(&checkpoints, &[0, 1, 2]);
        assert_eq!(results.len(), 3);
        assert_eq!(results[&0], state_a);
        assert_eq!(results[&1], state_b);
        assert_eq!(results[&2], state_a);
    }

    #[test]
    fn test_checkpoint_serde_coverage() {
        // Covers `hex_serde`, `hex_serde_opt`, and `LtHash::default()`
        let _def = LtHash::default();

        let cp: CompactedCheckpoint<String> = CompactedCheckpoint {
            state_hash: [0xab; 32],
            parent_hash: Some([0xcd; 32]),
            event_id: "$1".into(),
            deltas: alloc::vec![],
            snapshot: None,
        };

        let serialized = serde_json::to_string(&cp).unwrap();
        let deserialized: CompactedCheckpoint<String> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(cp, deserialized);

        let cp_none: CompactedCheckpoint<String> = CompactedCheckpoint {
            state_hash: [0xab; 32],
            parent_hash: None,
            event_id: "$2".into(),
            deltas: alloc::vec![],
            snapshot: None,
        };
        let serialized_none = serde_json::to_string(&cp_none).unwrap();
        let deserialized_none: CompactedCheckpoint<String> =
            serde_json::from_str(&serialized_none).unwrap();
        assert_eq!(cp_none, deserialized_none);

        // Test error conditions
        assert!(serde_json::from_str::<CompactedCheckpoint<String>>(
            r#"{"state_hash":"deadbeef","parent_hash":null,"event_id":"$1","deltas":[],"snapshot":null}"#
        ).is_err());

        assert!(serde_json::from_str::<CompactedCheckpoint<String>>(
            r#"{"state_hash":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz","parent_hash":null,"event_id":"$1","deltas":[],"snapshot":null}"#
        ).is_err());

        assert!(serde_json::from_str::<CompactedCheckpoint<String>>(
            r#"{"state_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","parent_hash":"deadbeef","event_id":"$1","deltas":[],"snapshot":null}"#
        ).is_err());

        assert!(serde_json::from_str::<CompactedCheckpoint<String>>(
            r#"{"state_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","parent_hash":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz","event_id":"$1","deltas":[],"snapshot":null}"#
        ).is_err());
    }

    #[test]
    fn test_batch_empty_and_oob_targets() {
        let (checkpoints, _, _) = forward_jump_fixture();

        // Empty targets
        let results = reconstruct_state_batch(&checkpoints, &[]);
        assert!(results.is_empty());

        // All out-of-bounds
        let results = reconstruct_state_batch(&checkpoints, &[999, 1000]);
        assert!(results.is_empty());
    }

    /// Regression: `hash_to_idx` `HashMap` shadowing — when duplicate hashes exist,
    /// `.collect()` only stores the LAST index, erasing the valid earlier parent.
    /// This test constructs a chain where `HASH_A` appears at indices 0 and 4, and
    /// verifies that index 3 (whose parent is `HASH_A`) correctly resolves to
    /// index 0, not silently fails because index 4 shadowed the lookup.
    #[test]
    fn test_batch_hash_shadowing_regression() {
        let hash_a = [0xAA; 32];
        let hash_b = [0xBB; 32];
        let hash_c = [0xCC; 32];
        let hash_d = [0xDD; 32];

        let state_a = {
            let mut s = StateMap::new();
            s.insert(("m.room.create".into(), String::new()), "$c".into());
            s
        };

        // Chain: [0:A] -> [1:B] -> [2:C] -> [3:D] -> [4:A]
        // Index 3's parent_hash is HASH_C (index 2) — normal.
        // Index 1's parent_hash is HASH_A — should resolve to index 0.
        // Index 4's parent_hash is HASH_D (index 3) — normal.
        // The trap: hash_to_idx["HASH_A"] would be 4 (last), not 0.
        // Reconstructing index 1 needs HASH_A → index 0, but HashMap returns 4.
        let checkpoints = alloc::vec![
            CompactedCheckpoint::<String> {
                state_hash: hash_a,
                parent_hash: None,
                event_id: "$0".into(),
                deltas: alloc::vec![],
                snapshot: Some(state_a.clone()),
            },
            CompactedCheckpoint::<String> {
                state_hash: hash_b,
                parent_hash: Some(hash_a),
                event_id: "$1".into(),
                deltas: alloc::vec![StateDelta {
                    event_type: "m.room.topic".into(),
                    state_key: String::new(),
                    event_id: Some("$t1".into()),
                }],
                snapshot: None,
            },
            CompactedCheckpoint::<String> {
                state_hash: hash_c,
                parent_hash: Some(hash_b),
                event_id: "$2".into(),
                deltas: alloc::vec![StateDelta {
                    event_type: "m.room.topic".into(),
                    state_key: String::new(),
                    event_id: Some("$t2".into()),
                }],
                snapshot: None,
            },
            CompactedCheckpoint::<String> {
                state_hash: hash_d,
                parent_hash: Some(hash_c),
                event_id: "$3".into(),
                deltas: alloc::vec![StateDelta {
                    event_type: "m.room.topic".into(),
                    state_key: String::new(),
                    event_id: Some("$t3".into()),
                }],
                snapshot: None,
            },
            CompactedCheckpoint::<String> {
                state_hash: hash_a, // Duplicate of index 0!
                parent_hash: Some(hash_d),
                event_id: "$4".into(),
                deltas: alloc::vec![StateDelta {
                    event_type: "m.room.topic".into(),
                    state_key: String::new(),
                    event_id: None, // deletion — reverts to state_a
                }],
                snapshot: None,
            },
        ];

        // Batch reconstruct all — with HashMap shadowing, indices 1-3 would
        // silently fail because HASH_A maps to index 4 (future), not index 0.
        let results = reconstruct_state_batch(&checkpoints, &[0, 1, 2, 3, 4]);
        assert_eq!(results.len(), 5, "all 5 checkpoints should reconstruct");
        assert_eq!(results[&0], state_a, "index 0 (snapshot)");
        assert_eq!(results[&4], state_a, "index 4 (reverted to state_a)");

        // Also verify single-target reconstruction matches batch
        for i in 0..5 {
            let single = reconstruct_state_at(&checkpoints, i)
                .unwrap_or_else(|| panic!("single reconstruct failed at {i}"));
            assert_eq!(single, results[&i], "single vs batch mismatch at index {i}");
        }
    }

    /// Coverage: exercises the `rposition` fallback in `reconstruct_state_at`
    /// (lines 325-327) when the parent hash doesn't match the immediate
    /// predecessor — e.g. after a fork/merge or gap in the chain.
    #[test]
    fn test_reconstruct_rposition_fallback() {
        let mut state_a = StateMap::new();
        state_a.insert(("m.room.create".into(), String::new()), "$c".into());
        let hash_a = compute_state_hash(&state_a);

        let mut state_b = StateMap::new();
        state_b.insert(("m.room.create".into(), String::new()), "$c".into());
        state_b.insert(("m.room.member".into(), "@alice:x".into()), "$j".into());
        let hash_b = compute_state_hash(&state_b);

        let mut state_c = StateMap::new();
        state_c.insert(("m.room.create".into(), String::new()), "$c".into());
        state_c.insert(("m.room.member".into(), "@bob:x".into()), "$k".into());
        let hash_c = compute_state_hash(&state_c);

        // Chain: [0]=snapshot(A), [1]=delta->A(B), [2]=delta->A(C)
        // Index 2's parent_hash points to A (index 0), but index 1 has hash_b ≠ hash_a,
        // so the immediate-predecessor check fails and rposition scans backwards.
        let delta_c_from_a = compute_state_delta(&state_a, &state_c);
        let checkpoints = alloc::vec![
            CompactedCheckpoint::<String> {
                state_hash: hash_a,
                parent_hash: None,
                event_id: "$e0".into(),
                deltas: alloc::vec![],
                snapshot: Some(state_a.clone()),
            },
            CompactedCheckpoint::<String> {
                state_hash: hash_b,
                parent_hash: Some(hash_a),
                event_id: "$e1".into(),
                deltas: compute_state_delta(&state_a, &state_b),
                snapshot: None,
            },
            CompactedCheckpoint::<String> {
                state_hash: hash_c,
                parent_hash: Some(hash_a), // points to index 0, NOT index 1
                event_id: "$e2".into(),
                deltas: delta_c_from_a,
                snapshot: None,
            },
        ];

        // Reconstruct index 2 — must use rposition to find parent at index 0
        let reconstructed = reconstruct_state_at(&checkpoints, 2)
            .expect("should reconstruct via rposition fallback");
        assert_eq!(reconstructed, state_c);

        // Verify single-event lookup also works
        let by_id = reconstruct_state_at_by_event_id(&checkpoints, &String::from("$e2"))
            .expect("event ID lookup should work");
        assert_eq!(by_id, state_c);
    }
}
