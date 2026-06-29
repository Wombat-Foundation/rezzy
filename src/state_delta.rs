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

//! State delta compression — efficient incremental state storage.
//!
//! Instead of storing the full `BTreeMap<(type, state_key), event_id>` at every
//! event, homeservers can store a base snapshot and a chain of deltas.
//! This module provides the primitives for computing and applying those deltas.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use rezzy::state_delta::{compute_state_delta, apply_state_delta, compute_state_hash};
//! use std::collections::BTreeMap;
//!
//! let parent: BTreeMap<(String, Option<String>), String> = BTreeMap::new();
//! let current: BTreeMap<(String, Option<String>), String> = BTreeMap::new();
//!
//! let delta = compute_state_delta(&parent, &current);
//! let reconstructed = apply_state_delta(&parent, &delta);
//! assert_eq!(current, reconstructed);
//! ```
//!
//! ## Hashing
//!
//! [`compute_state_hash`] produces a deterministic FNV-1a fingerprint of a
//! state map, suitable for fast equality checks and delta chain bookkeeping.
//! It is **not** cryptographic — use the `hashing` feature for SHA-256.

use alloc::collections::BTreeMap;
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
/// [`resolve_lean_with_deltas`](crate::resolve_lean_with_deltas) emits one of
/// these for every conflicted event that is auth-checked, regardless of whether
/// it was accepted or rejected.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolutionDelta<Id = String> {
    /// The event that was auth-checked.
    pub event_id: Id,
    /// Whether the event passed the iterative auth check.
    pub accepted: bool,
    /// The `(event_type, state_key)` slot this event targets.
    pub key: (String, Option<String>),
    /// The event ID that was previously in this slot (if any).
    /// `None` if the slot was empty before this event.
    pub replaced: Option<Id>,
    /// Whether this was processed in the power phase or non-power phase.
    pub phase: ResolvePhase,
}

/// A single state delta entry — an addition, modification, or deletion.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StateDelta {
    /// The event type (e.g. `"m.room.member"`).
    pub event_type: String,
    /// The state key (e.g. `Some("@alice:example.com")`).
    pub state_key: Option<String>,
    /// The new event ID, or `None` if this key was deleted.
    pub event_id: Option<String>,
}

/// A state checkpoint — a snapshot's hash, its parent, and the delta from parent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StateCheckpoint {
    /// FNV-1a hash of the state map at this point.
    pub state_hash: String,
    /// Hash of the parent checkpoint (if any).
    pub parent_hash: Option<String>,
    /// The event ID that produced this checkpoint.
    pub event_id: String,
    /// Deltas from the parent state to this state.
    pub deltas: Vec<StateDelta>,
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
pub fn compute_state_delta(
    parent: &BTreeMap<(String, Option<String>), String>,
    current: &BTreeMap<(String, Option<String>), String>,
) -> Vec<StateDelta> {
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
pub fn apply_state_delta(
    base: &BTreeMap<(String, Option<String>), String>,
    deltas: &[StateDelta],
) -> BTreeMap<(String, Option<String>), String> {
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

/// Computes a deterministic FNV-1a fingerprint of a state map.
///
/// The hash is computed over `(event_type, state_key, event_id)` tuples in
/// `BTreeMap` iteration order (lexicographic). This produces a stable,
/// reproducible 64-bit hex string suitable for delta chain bookkeeping.
///
/// **Not cryptographic** — use SHA-256 (via the `hashing` feature) for
/// content-addressable storage.
#[must_use]
pub fn compute_state_hash(state: &BTreeMap<(String, Option<String>), String>) -> String {
    let mut hash: u64 = 14_695_981_039_346_656_037; // FNV offset basis
    for ((event_type, state_key), event_id) in state {
        for &byte in event_type.as_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(1_099_511_628_211); // FNV prime
        }
        hash ^= 0x00;
        hash = hash.wrapping_mul(1_099_511_628_211);
        if let Some(key) = state_key {
            for &byte in key.as_bytes() {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(1_099_511_628_211);
            }
        }
        hash ^= 0x00;
        hash = hash.wrapping_mul(1_099_511_628_211);
        for &byte in event_id.as_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(1_099_511_628_211);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(1_099_511_628_211);
    }
    alloc::format!("{hash:016x}")
}

/// Walks a topologically-ordered slice of events and produces a
/// [`StateCheckpoint`] for each one, chaining parent hashes and deltas.
///
/// Events **must** be in topological order (parents before children).
/// Non-state events (where `state_key` is `None`) still produce a checkpoint
/// but with an empty delta and the same state hash as their parent.
///
/// This is the high-level API that replaces manual delta-chain loops.
///
/// # Arguments
///
/// * `events` — a topologically-ordered slice of [`LeanEvent`](crate::LeanEvent)s.
///
/// # Returns
///
/// A `Vec<StateCheckpoint>` with one entry per input event.
#[must_use]
pub fn compute_delta_chain(events: &[crate::types::LeanEvent]) -> Vec<StateCheckpoint> {
    use crate::HashMap;

    let mut state_after_map: HashMap<String, BTreeMap<(String, Option<String>), String>> =
        HashMap::new();
    let mut state_hash_map: HashMap<String, String> = HashMap::new();
    let mut checkpoints = Vec::with_capacity(events.len());

    for ev in events {
        let mut state_before = BTreeMap::new();
        let mut parent_hash = None;

        if let Some(prev_id) = ev.prev_events.first() {
            if let Some(prev_state) = state_after_map.get(prev_id) {
                state_before = prev_state.clone();
                parent_hash = state_hash_map.get(prev_id).cloned();
            }
        }

        let mut state_after = state_before.clone();
        if ev.state_key.is_some() {
            state_after.insert(
                (ev.event_type.clone(), ev.state_key.clone()),
                ev.event_id.clone(),
            );
        }

        let state_hash = compute_state_hash(&state_after);
        let deltas = compute_state_delta(&state_before, &state_after);

        state_after_map.insert(ev.event_id.clone(), state_after);
        state_hash_map.insert(ev.event_id.clone(), state_hash.clone());

        checkpoints.push(StateCheckpoint {
            state_hash,
            parent_hash,
            event_id: ev.event_id.clone(),
            deltas,
        });
    }

    checkpoints
}

/// Maximum number of delta hops before a full snapshot is inserted.
///
/// Matches Synapse's `MAX_STATE_DELTA_HOPS`. When a delta chain would exceed
/// this length, [`compute_compacted_delta_chain`] inserts a full base snapshot
/// instead of another delta, bounding reconstruction cost to at most this many
/// hops.
pub const MAX_DELTA_CHAIN_HOPS: usize = 100;

/// A checkpoint that may be either a delta from a parent or a full snapshot.
///
/// When chain compaction triggers (every [`MAX_DELTA_CHAIN_HOPS`] events),
/// the checkpoint stores the full state map as `snapshot` instead of a delta.
/// Readers walk backwards from any checkpoint, applying deltas, until they
/// hit a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CompactedCheckpoint {
    /// FNV-1a hash of the state map at this point.
    pub state_hash: String,
    /// Hash of the parent checkpoint (if any).
    pub parent_hash: Option<String>,
    /// The event ID that produced this checkpoint.
    pub event_id: String,
    /// Deltas from the parent state. Empty when `snapshot` is `Some`.
    pub deltas: Vec<StateDelta>,
    /// Full state snapshot, present every [`MAX_DELTA_CHAIN_HOPS`] checkpoints.
    /// When this is `Some`, `deltas` is empty and reconstruction starts here.
    pub snapshot: Option<BTreeMap<(String, Option<String>), String>>,
}

/// Like [`compute_delta_chain`], but inserts full snapshots every
/// [`MAX_DELTA_CHAIN_HOPS`] events to bound reconstruction cost.
///
/// Events **must** be in topological order (parents before children).
///
/// A custom `max_hops` can be provided; pass `None` to use the default
/// [`MAX_DELTA_CHAIN_HOPS`] (100).
#[must_use]
pub fn compute_compacted_delta_chain(
    events: &[crate::types::LeanEvent],
    max_hops: Option<usize>,
) -> Vec<CompactedCheckpoint> {
    use crate::HashMap;

    let max_hops = max_hops.unwrap_or(MAX_DELTA_CHAIN_HOPS);

    let mut state_after_map: HashMap<String, BTreeMap<(String, Option<String>), String>> =
        HashMap::new();
    let mut state_hash_map: HashMap<String, String> = HashMap::new();
    let mut hops_since_snapshot: HashMap<String, usize> = HashMap::new();
    let mut checkpoints = Vec::with_capacity(events.len());

    for ev in events {
        let mut state_before = BTreeMap::new();
        let mut parent_hash = None;
        let mut parent_hops: usize = 0;

        if let Some(prev_id) = ev.prev_events.first() {
            if let Some(prev_state) = state_after_map.get(prev_id) {
                state_before = prev_state.clone();
                parent_hash = state_hash_map.get(prev_id).cloned();
                parent_hops = hops_since_snapshot.get(prev_id).copied().unwrap_or(0);
            }
        }

        let mut state_after = state_before.clone();
        if ev.state_key.is_some() {
            state_after.insert(
                (ev.event_type.clone(), ev.state_key.clone()),
                ev.event_id.clone(),
            );
        }

        let state_hash = compute_state_hash(&state_after);
        let current_hops = parent_hops.saturating_add(1);

        let (deltas, snapshot, recorded_hops) = if current_hops >= max_hops || parent_hash.is_none()
        {
            // Insert a full snapshot — resets the chain
            (Vec::new(), Some(state_after.clone()), 0)
        } else {
            let deltas = compute_state_delta(&state_before, &state_after);
            (deltas, None, current_hops)
        };

        state_after_map.insert(ev.event_id.clone(), state_after);
        state_hash_map.insert(ev.event_id.clone(), state_hash.clone());
        hops_since_snapshot.insert(ev.event_id.clone(), recorded_hops);

        checkpoints.push(CompactedCheckpoint {
            state_hash,
            parent_hash,
            event_id: ev.event_id.clone(),
            deltas,
            snapshot,
        });
    }

    checkpoints
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
pub fn reconstruct_state_at(
    checkpoints: &[CompactedCheckpoint],
    target_index: usize,
) -> Option<BTreeMap<(String, Option<String>), String>> {
    use crate::HashMap;

    if target_index >= checkpoints.len() {
        return None;
    }

    // Build an index from state_hash -> checkpoint index for parent lookups
    let hash_to_idx: HashMap<&str, usize> = checkpoints
        .iter()
        .enumerate()
        .map(|(i, cp)| (cp.state_hash.as_str(), i))
        .collect();

    // Collect deltas by walking backwards until we hit a snapshot
    let mut delta_stack: Vec<&[StateDelta]> = Vec::new();
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
        current_idx = *hash_to_idx.get(parent_hash.as_str())?;
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
/// A `BTreeMap<usize, state_map>` keyed by the requested indices. Missing
/// entries indicate broken chains or out-of-bounds indices.
///
/// # Panics
///
/// Panics if an internal index increment overflows `usize` (should never
/// happen with valid checkpoint data).
#[must_use]
pub fn reconstruct_state_batch(
    checkpoints: &[CompactedCheckpoint],
    target_indices: &[usize],
) -> BTreeMap<usize, BTreeMap<(String, Option<String>), String>> {
    use crate::HashMap;

    let mut sorted_targets: Vec<usize> = target_indices
        .iter()
        .copied()
        .filter(|&i| i < checkpoints.len())
        .collect();
    sorted_targets.sort_unstable();
    sorted_targets.dedup();

    if sorted_targets.is_empty() {
        return BTreeMap::new();
    }

    let earliest = sorted_targets[0];
    let latest = *sorted_targets.last().unwrap();

    // Build hash -> index map for parent lookups
    let hash_to_idx: HashMap<&str, usize> = checkpoints
        .iter()
        .enumerate()
        .map(|(i, cp)| (cp.state_hash.as_str(), i))
        .collect();

    // Walk backwards from the earliest target to find the nearest snapshot
    let mut snapshot_idx = earliest;
    loop {
        if checkpoints[snapshot_idx].snapshot.is_some() {
            break;
        }
        let Some(parent_hash) = checkpoints[snapshot_idx].parent_hash.as_ref() else {
            return BTreeMap::new(); // broken chain
        };
        match hash_to_idx.get(parent_hash.as_str()) {
            Some(&idx) => snapshot_idx = idx,
            None => return BTreeMap::new(), // broken chain
        }
    }

    // Start from the snapshot base
    let mut state = checkpoints[snapshot_idx].snapshot.as_ref().unwrap().clone();
    let mut results = BTreeMap::new();
    let mut target_ptr = 0;

    // Check if the snapshot itself is a target
    while target_ptr < sorted_targets.len() && sorted_targets[target_ptr] == snapshot_idx {
        results.insert(snapshot_idx, state.clone());
        target_ptr = target_ptr.checked_add(1).expect("target_ptr overflow");
    }

    // Walk forward, applying deltas and capturing at each target
    for i in (snapshot_idx.checked_add(1).expect("snapshot_idx overflow"))..=latest {
        if i >= checkpoints.len() {
            break;
        }

        let cp = &checkpoints[i];

        // If this checkpoint has a snapshot, use it (resets accumulated state)
        if let Some(ref snapshot) = cp.snapshot {
            state = snapshot.clone();
        } else {
            // Apply deltas
            for delta in &cp.deltas {
                let key = (delta.event_type.clone(), delta.state_key.clone());
                if let Some(ref event_id) = delta.event_id {
                    state.insert(key, event_id.clone());
                } else {
                    state.remove(&key);
                }
            }
        }

        // Capture if this is a target
        while target_ptr < sorted_targets.len() && sorted_targets[target_ptr] == i {
            results.insert(i, state.clone());
            target_ptr = target_ptr.checked_add(1).expect("target_ptr overflow");
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_identity() {
        let mut state = BTreeMap::new();
        state.insert(("m.room.create".into(), Some(String::new())), "$1".into());
        state.insert(
            ("m.room.member".into(), Some("@alice:example.com".into())),
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
        let mut parent = BTreeMap::new();
        parent.insert(("m.room.create".into(), Some(String::new())), "$1".into());
        parent.insert(
            ("m.room.member".into(), Some("@alice:example.com".into())),
            "$2".into(),
        );

        let mut current = BTreeMap::new();
        current.insert(
            ("m.room.create".into(), Some(String::new())),
            "$1".into(), // unchanged
        );
        current.insert(
            ("m.room.member".into(), Some("@alice:example.com".into())),
            "$4".into(), // modified
        );
        current.insert(
            ("m.room.member".into(), Some("@bob:example.com".into())),
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
        let mut parent = BTreeMap::new();
        parent.insert(("m.room.create".into(), Some(String::new())), "$1".into());
        parent.insert(
            ("m.room.member".into(), Some("@alice:example.com".into())),
            "$2".into(),
        );

        // Current state has alice removed
        let mut current = BTreeMap::new();
        current.insert(("m.room.create".into(), Some(String::new())), "$1".into());

        let delta = compute_state_delta(&parent, &current);
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].event_id, None); // deletion marker

        let reconstructed = apply_state_delta(&parent, &delta);
        assert_eq!(current, reconstructed);
    }

    #[test]
    fn test_state_hash_determinism() {
        let mut state = BTreeMap::new();
        state.insert(("m.room.create".into(), Some(String::new())), "$1".into());
        state.insert(
            ("m.room.member".into(), Some("@alice:example.com".into())),
            "$2".into(),
        );

        let h1 = compute_state_hash(&state);
        let h2 = compute_state_hash(&state);
        assert_eq!(h1, h2, "same state must produce same hash");
        assert_eq!(h1.len(), 16, "FNV-1a hash should be 16 hex chars");
    }

    #[test]
    fn test_state_hash_sensitivity() {
        let mut state_a = BTreeMap::new();
        state_a.insert(("m.room.create".into(), Some(String::new())), "$1".into());

        let mut state_b = BTreeMap::new();
        state_b.insert(("m.room.create".into(), Some(String::new())), "$2".into());

        assert_ne!(
            compute_state_hash(&state_a),
            compute_state_hash(&state_b),
            "different states must produce different hashes"
        );
    }

    #[test]
    fn test_compaction_inserts_snapshots() {
        use crate::types::LeanEvent;

        // Create a chain of 250 events — should trigger snapshots at 0, 100, 200
        let events: Vec<LeanEvent> = (1..=250)
            .map(|i| LeanEvent {
                event_id: alloc::format!("${i}"),
                event_type: "m.room.member".into(),
                state_key: Some(alloc::format!("@user_{i}:example.com")),
                prev_events: if i > 1 {
                    alloc::vec![alloc::format!("${}", i - 1)]
                } else {
                    alloc::vec![]
                },
                depth: u64::try_from(i).unwrap(),
                ..Default::default()
            })
            .collect();

        let checkpoints = compute_compacted_delta_chain(&events, Some(100));
        assert_eq!(checkpoints.len(), 250);

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
            "250 events with max_hops=100 should produce at least 3 snapshots, got {snapshot_count}"
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
                hops < 100,
                "delta chain at index {i} has {hops} hops, exceeds max 100"
            );
        }
    }

    #[test]
    fn test_reconstruct_state_at() {
        use crate::types::LeanEvent;

        // Create 150 events — will have snapshots at 0 and ~100
        let events: Vec<LeanEvent> = (1..=150)
            .map(|i| LeanEvent {
                event_id: alloc::format!("${i}"),
                event_type: "m.room.member".into(),
                state_key: Some(alloc::format!("@user_{i}:example.com")),
                prev_events: if i > 1 {
                    alloc::vec![alloc::format!("${}", i - 1)]
                } else {
                    alloc::vec![]
                },
                depth: u64::try_from(i).unwrap(),
                ..Default::default()
            })
            .collect();

        let checkpoints = compute_compacted_delta_chain(&events, Some(100));

        // Reconstruct state at the last event
        let state =
            reconstruct_state_at(&checkpoints, 149).expect("should reconstruct state at tip");

        // Should have 150 member entries
        assert_eq!(state.len(), 150, "state at tip should have 150 entries");

        // Verify a specific entry
        let key = ("m.room.member".into(), Some("@user_42:example.com".into()));
        assert_eq!(state.get(&key), Some(&"$42".into()));

        // Reconstruct at the first event
        let state_first =
            reconstruct_state_at(&checkpoints, 0).expect("should reconstruct state at first");
        assert_eq!(state_first.len(), 1);

        // Reconstruct at mid-point
        let state_mid =
            reconstruct_state_at(&checkpoints, 74).expect("should reconstruct at index 74");
        assert_eq!(state_mid.len(), 75); // events 1..=75
    }

    #[test]
    fn test_reconstruct_out_of_bounds() {
        let result = reconstruct_state_at(&[], 0);
        assert!(result.is_none());

        let result = reconstruct_state_at(&[], 42);
        assert!(result.is_none());
    }
}
