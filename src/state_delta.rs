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

/// A single state delta entry — an addition, modification, or deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDelta {
    /// The event type (e.g. `"m.room.member"`).
    pub event_type: String,
    /// The state key (e.g. `Some("@alice:example.com")`).
    pub state_key: Option<String>,
    /// The new event ID, or `None` if this key was deleted.
    pub event_id: Option<String>,
}

/// A state checkpoint — a snapshot's hash, its parent, and the delta from parent.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
