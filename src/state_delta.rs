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
    /// 128-bit FNV-1a hash of the state map at this point.
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

/// Computes a deterministic 128-bit FNV-1a fingerprint of a state map.
///
/// The hash is computed over `(event_type, state_key, event_id)` tuples in
/// `BTreeMap` iteration order (lexicographic). This produces a stable,
/// reproducible 128-bit hex string suitable for delta chain bookkeeping.
///
/// 128-bit FNV-1a gives a collision probability of ~2^-128 per pair,
/// effectively zero for any realistic state map count.
///
/// **Not cryptographic** — use SHA-256 (via the `hashing` feature) for
/// content-addressable storage.
#[must_use]
pub fn compute_state_hash(state: &BTreeMap<(String, Option<String>), String>) -> String {
    // FNV-1a 128-bit offset basis and prime
    // See: <https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function>
    const FNV128_PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
    let mut hash: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;

    for ((event_type, state_key), event_id) in state {
        for &byte in event_type.as_bytes() {
            hash ^= u128::from(byte);
            hash = hash.wrapping_mul(FNV128_PRIME);
        }
        hash ^= 0x00;
        hash = hash.wrapping_mul(FNV128_PRIME);
        if let Some(key) = state_key {
            hash ^= 0x02; // discriminant: Some
            hash = hash.wrapping_mul(FNV128_PRIME);
            for &byte in key.as_bytes() {
                hash ^= u128::from(byte);
                hash = hash.wrapping_mul(FNV128_PRIME);
            }
        } else {
            hash ^= 0x01; // discriminant: None
            hash = hash.wrapping_mul(FNV128_PRIME);
        }
        hash ^= 0x00;
        hash = hash.wrapping_mul(FNV128_PRIME);
        for &byte in event_id.as_bytes() {
            hash ^= u128::from(byte);
            hash = hash.wrapping_mul(FNV128_PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(FNV128_PRIME);
    }
    alloc::format!("{hash:032x}")
}

/// Walks a topologically-ordered slice of events and produces a
/// [`StateCheckpoint`] for each one, chaining parent hashes and deltas.
///
/// Events **must** be in topological order (parents before children).
/// Non-state events (where `state_key` is `None`) still produce a checkpoint
/// but with an empty delta and the same state hash as their parent.
///
/// # Multi-parent merge strategy
///
/// When an event has multiple `prev_events`, this function merges their
/// states by keeping the lexicographically greatest event ID per key.
/// This is **not** state resolution — it is a deterministic tie-break
/// for delta chain storage only. The resulting `state_hash` is internally
/// consistent and reproducible via [`reconstruct_state_at`], but may
/// differ from what [`resolve_lean`](crate::resolve::resolve_lean) would
/// produce. Actual state resolution is performed separately.
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
        // A DAG merge event can have multiple parents. To compute an accurate delta chain,
        // we must accumulate the state from all parents deterministically before applying
        // the current event's state.
        let mut merged_state = BTreeMap::new();
        let mut parent_hash = None;
        let mut base_state = BTreeMap::new(); // The state corresponding to parent_hash

        for prev_id in &ev.prev_events {
            if let Some(prev_state) = state_after_map.get(prev_id) {
                if parent_hash.is_none() {
                    parent_hash = state_hash_map.get(prev_id).cloned();
                    base_state = prev_state.clone();
                }
                // NOTE: Deterministic merge: when parents disagree on a key, pick the
                // lexicographically greater event ID. This is NOT state resolution —
                // just a reproducible tie-break for delta chain storage.
                for (k, v) in prev_state {
                    match merged_state.get(k) {
                        Some(existing) if existing >= v => {}
                        _ => {
                            merged_state.insert(k.clone(), v.clone());
                        }
                    }
                }
            }
        }

        let mut state_after = merged_state;
        if ev.state_key.is_some() {
            state_after.insert(
                (ev.event_type.clone(), ev.state_key.clone()),
                ev.event_id.clone(),
            );
        }

        let state_hash = compute_state_hash(&state_after);
        let deltas = compute_state_delta(&base_state, &state_after);

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
    /// 128-bit FNV-1a hash of the state map at this point.
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
/// Multi-parent merging uses the same deterministic lexicographic
/// tie-break as [`compute_delta_chain`] (not state resolution).
///
/// A custom `max_hops` can be provided; pass `None` to use the default
/// [`MAX_DELTA_CHAIN_HOPS`] (100).
///
/// # Panics
///
/// Panics if an event's `prev_events` reference IDs not present in the
/// topologically-preceding output (i.e. events are not in valid topo order).
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
        let mut first_parent_id: Option<&str> = None;
        let mut parent_hash = None;
        let mut parent_hops: usize = 0;

        for prev_id in &ev.prev_events {
            if let Some(prev_state) = state_after_map.get(prev_id) {
                if parent_hash.is_none() {
                    parent_hash = state_hash_map.get(prev_id).cloned();
                    parent_hops = hops_since_snapshot.get(prev_id).copied().unwrap_or(0);
                    first_parent_id = Some(prev_id);
                }
                // NOTE: Deterministic merge (not state resolution). See compute_delta_chain.
                for (k, v) in prev_state {
                    match state_before.get(k) {
                        Some(existing) if existing >= v => {}
                        _ => {
                            state_before.insert(k.clone(), v.clone());
                        }
                    }
                }
            }
        }

        let mut state_after = state_before;
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
            // Deferred clone: only look up the first parent's state when we
            // actually need it for delta computation, not on snapshot boundaries.
            let base_state = &state_after_map[first_parent_id.unwrap()];
            let deltas = compute_state_delta(base_state, &state_after);
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

/// Produces a [`StateCheckpoint`] chain from a sequence of **pre-resolved**
/// `(event_id, state_map)` pairs.
///
/// Unlike [`compute_delta_chain`], this function performs **no graph traversal**
/// and **no fork merging**. The caller is responsible for providing the correct
/// resolved state at each position (e.g. via
/// [`compute_state_at_batch`](crate::compute_state_at_batch) or
/// [`resolve_lean`](crate::resolve_lean)).
///
/// This is the architecturally correct way to build delta chains: resolution
/// is a separate concern from storage compression.
///
/// # Arguments
///
/// * `resolved_states` — an iterator of `(event_id, resolved_state_map)` pairs,
///   in chronological / topological order.
#[must_use]
pub fn compute_delta_chain_from_resolved(
    resolved_states: impl IntoIterator<Item = (String, BTreeMap<(String, Option<String>), String>)>,
) -> Vec<StateCheckpoint> {
    let mut checkpoints = Vec::new();
    let mut prev_state: Option<BTreeMap<(String, Option<String>), String>> = None;
    let mut prev_hash: Option<String> = None;

    for (event_id, state) in resolved_states {
        let state_hash = compute_state_hash(&state);

        let deltas = if let Some(ref base) = prev_state {
            compute_state_delta(base, &state)
        } else {
            // First entry: delta from empty
            compute_state_delta(&BTreeMap::new(), &state)
        };

        checkpoints.push(StateCheckpoint {
            state_hash: state_hash.clone(),
            parent_hash: prev_hash,
            event_id,
            deltas,
        });

        prev_hash = Some(state_hash);
        prev_state = Some(state);
    }

    checkpoints
}

/// Like [`compute_delta_chain_from_resolved`], but inserts full snapshots every
/// `max_hops` events to bound reconstruction cost.
///
/// This is the recommended API for homeserver state storage. The caller supplies
/// pre-resolved states (from [`compute_state_at_batch`](crate::compute_state_at_batch)
/// / [`resolve_lean`](crate::resolve_lean)), and this function handles only the
/// storage compression concern.
///
/// A custom `max_hops` can be provided; pass `None` to use the default
/// [`MAX_DELTA_CHAIN_HOPS`] (100).
#[must_use]
pub fn compute_compacted_delta_chain_from_resolved(
    resolved_states: impl IntoIterator<Item = (String, BTreeMap<(String, Option<String>), String>)>,
    max_hops: Option<usize>,
) -> Vec<CompactedCheckpoint> {
    let max_hops = max_hops.unwrap_or(MAX_DELTA_CHAIN_HOPS);
    let mut checkpoints = Vec::new();
    let mut prev_state: Option<BTreeMap<(String, Option<String>), String>> = None;
    let mut prev_hash: Option<String> = None;
    let mut hops_since_snapshot: usize = 0;

    for (event_id, state) in resolved_states {
        let state_hash = compute_state_hash(&state);
        let current_hops = hops_since_snapshot.saturating_add(1);

        let (deltas, snapshot, recorded_hops) = if current_hops >= max_hops || prev_state.is_none()
        {
            // Insert a full snapshot — resets the chain
            (Vec::new(), Some(state.clone()), 0)
        } else if let Some(ref base) = prev_state {
            let deltas = compute_state_delta(base, &state);
            (deltas, None, current_hops)
        } else {
            unreachable!()
        };

        checkpoints.push(CompactedCheckpoint {
            state_hash: state_hash.clone(),
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
pub fn reconstruct_state_at_by_event_id(
    checkpoints: &[CompactedCheckpoint],
    event_id: &str,
) -> Option<BTreeMap<(String, Option<String>), String>> {
    let idx = checkpoints.iter().position(|cp| cp.event_id == event_id)?;
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
pub fn reconstruct_state_at(
    checkpoints: &[CompactedCheckpoint],
    target_index: usize,
) -> Option<BTreeMap<(String, Option<String>), String>> {
    if target_index >= checkpoints.len() {
        return None;
    }

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
        // Prefer immediate predecessor; fall back to scanning earlier checkpoints.
        if let Some(prev) = current_idx
            .checked_sub(1)
            .filter(|&pi| checkpoints[pi].state_hash == *parent_hash)
        {
            current_idx = prev;
        } else {
            current_idx = checkpoints[..current_idx]
                .iter()
                .rposition(|cp| cp.state_hash.as_str() == parent_hash.as_str())?;
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

    // Build hash -> index map for parent lookups
    let hash_to_idx: HashMap<&str, usize> = checkpoints
        .iter()
        .enumerate()
        .map(|(i, cp)| (cp.state_hash.as_str(), i))
        .collect();

    // Walk backwards from all targets to find all required ancestors
    let mut required_indices = alloc::collections::BTreeSet::new();
    let mut queue: Vec<usize> = sorted_targets.clone();
    while let Some(idx) = queue.pop() {
        if required_indices.insert(idx) && checkpoints[idx].snapshot.is_none() {
            if let Some(parent_hash) = &checkpoints[idx].parent_hash {
                // Prefer sequential index to avoid hash collisions
                if let Some(prev) = idx
                    .checked_sub(1)
                    .filter(|&pi| checkpoints[pi].state_hash == *parent_hash)
                {
                    queue.push(prev);
                } else if let Some(&p_idx) = hash_to_idx
                    .get(parent_hash.as_str())
                    .filter(|&&pi| pi < idx)
                {
                    queue.push(p_idx);
                }
            }
        }
    }

    let mut known_states = HashMap::new();
    let mut results = BTreeMap::new();

    // Iterate forward only through the required indices
    for idx in required_indices {
        let cp = &checkpoints[idx];
        let state = if let Some(ref snapshot) = cp.snapshot {
            snapshot.clone()
        } else if let Some(parent_hash) = &cp.parent_hash {
            // Prefer sequential index to avoid hash collisions
            let p_idx = if let Some(prev) = idx
                .checked_sub(1)
                .filter(|&pi| checkpoints[pi].state_hash == *parent_hash)
            {
                prev
            } else if let Some(&pi) = hash_to_idx
                .get(parent_hash.as_str())
                .filter(|&&pi| pi < idx)
            {
                pi
            } else {
                continue; // Broken chain
            };
            if let Some(parent_state) = known_states.get(&p_idx) {
                apply_state_delta(parent_state, &cp.deltas)
            } else {
                continue; // Broken chain
            }
        } else {
            continue; // Broken chain
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
    type ResolvedStates = Vec<(String, BTreeMap<(String, Option<String>), String>)>;

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
        assert_eq!(h1.len(), 32, "FNV-1a 128-bit hash should be 32 hex chars");
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

    #[test]
    fn test_delta_chain_from_resolved_roundtrip() {
        // Simulate 5 sequential state snapshots
        let mut states: ResolvedStates = Vec::new();

        for i in 1..=5 {
            let mut state = BTreeMap::new();
            for j in 1..=i {
                state.insert(
                    (
                        "m.room.member".into(),
                        Some(alloc::format!("@user_{j}:example.com")),
                    ),
                    alloc::format!("${j}"),
                );
            }
            states.push((alloc::format!("${i}"), state));
        }

        let checkpoints = compute_delta_chain_from_resolved(states.clone());

        assert_eq!(checkpoints.len(), 5);

        // First checkpoint: delta from empty has all entries
        assert_eq!(checkpoints[0].event_id, "$1");
        assert!(checkpoints[0].parent_hash.is_none());
        assert_eq!(checkpoints[0].deltas.len(), 1);

        // Second checkpoint: adds one member
        assert_eq!(checkpoints[1].event_id, "$2");
        assert_eq!(
            checkpoints[1].parent_hash,
            Some(checkpoints[0].state_hash.clone())
        );
        assert_eq!(checkpoints[1].deltas.len(), 1);
        assert_eq!(
            checkpoints[1].deltas[0].state_key,
            Some("@user_2:example.com".into())
        );

        // Verify hashes are chained
        for i in 1..5 {
            assert_eq!(
                checkpoints[i].parent_hash,
                Some(checkpoints[i - 1].state_hash.clone())
            );
        }

        // Verify deltas reconstruct the original resolved states
        let mut reconstructed = BTreeMap::new();
        for (i, cp) in checkpoints.iter().enumerate() {
            reconstructed = apply_state_delta(&reconstructed, &cp.deltas);
            assert_eq!(&reconstructed, &states[i].1);
        }
    }

    #[test]
    fn test_compacted_delta_chain_from_resolved_snapshots() {
        // Create 250 sequential resolved states
        let states: ResolvedStates = (1..=250)
            .map(|i| {
                let mut state = BTreeMap::new();
                state.insert(
                    (
                        "m.room.member".into(),
                        Some(alloc::format!("@user_{i}:example.com")),
                    ),
                    alloc::format!("${i}"),
                );
                // Keep previous entries too
                for j in 1..i {
                    state.insert(
                        (
                            "m.room.member".into(),
                            Some(alloc::format!("@user_{j}:example.com")),
                        ),
                        alloc::format!("${j}"),
                    );
                }
                (alloc::format!("${i}"), state)
            })
            .collect();

        let checkpoints = compute_compacted_delta_chain_from_resolved(states.clone(), Some(100));

        assert_eq!(checkpoints.len(), 250);

        // First event always gets a snapshot
        assert!(checkpoints[0].snapshot.is_some());

        // Count snapshots
        let snapshot_count = checkpoints
            .iter()
            .filter(|cp| cp.snapshot.is_some())
            .count();
        assert!(
            snapshot_count >= 3,
            "250 events with max_hops=100 should produce at least 3 snapshots, got {snapshot_count}"
        );

        // Verify all states are reconstructable
        let last_state = reconstruct_state_at(&checkpoints, 249).expect("should reconstruct last");
        assert_eq!(last_state.len(), 250);

        // Verify no checkpoint is more than max_hops deltas away from a snapshot
        let mut hops = 0_usize;
        for cp in &checkpoints {
            if cp.snapshot.is_some() {
                hops = 0;
            } else {
                hops += 1;
                assert!(
                    hops < 100,
                    "checkpoint {} is {hops} hops from nearest snapshot, exceeds max_hops=100",
                    cp.event_id
                );
            }
        }
    }

    #[test]
    fn test_reconstruct_state_at_by_event_id_lookup() {
        let states: ResolvedStates = (1..=10)
            .map(|i| {
                let mut state = BTreeMap::new();
                for j in 1..=i {
                    state.insert(
                        (
                            "m.room.member".into(),
                            Some(alloc::format!("@user_{j}:example.com")),
                        ),
                        alloc::format!("${j}"),
                    );
                }
                (alloc::format!("${i}"), state)
            })
            .collect();

        let checkpoints = compute_compacted_delta_chain_from_resolved(states, Some(100));

        // Lookup by event ID
        let state_5 = reconstruct_state_at_by_event_id(&checkpoints, "$5").expect("should find $5");
        assert_eq!(state_5.len(), 5);

        let state_10 =
            reconstruct_state_at_by_event_id(&checkpoints, "$10").expect("should find $10");
        assert_eq!(state_10.len(), 10);

        // Missing event ID
        assert!(reconstruct_state_at_by_event_id(&checkpoints, "$999").is_none());
    }

    #[test]
    fn test_consecutive_identical_states_reconstruction() {
        // Consecutive states with identical content produce identical hashes.
        // This must not break backward reconstruction.
        let state = {
            let mut s = BTreeMap::new();
            s.insert(
                ("m.room.create".into(), Some(String::new())),
                "$create".into(),
            );
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

    /// Regression: `hash_to_idx` used to map duplicate hashes to the *last*
    /// occurrence, which could cause `reconstruct_state_at` to jump *forward*
    /// instead of backward, corrupting or hanging reconstruction.
    #[test]
    fn test_no_forward_jump_on_duplicate_hashes() {
        // Craft a chain where checkpoints 0 and 2 share the same state hash
        // but checkpoint 1 has a different hash. Without the guard,
        // reconstructing checkpoint 2 would jump to checkpoint 2 (self-loop)
        // or a later index instead of walking backward.
        let shared_hash: String = "HASH_A".into();
        let different_hash: String = "HASH_B".into();

        let state_a = {
            let mut s = BTreeMap::new();
            s.insert(("m.room.create".into(), Some(String::new())), "$c".into());
            s
        };
        let state_b = {
            let mut s = state_a.clone();
            s.insert(("m.room.topic".into(), Some(String::new())), "$t".into());
            s
        };

        let checkpoints = alloc::vec![
            CompactedCheckpoint {
                state_hash: shared_hash.clone(),
                parent_hash: None,
                event_id: "$0".into(),
                deltas: alloc::vec![],
                snapshot: Some(state_a.clone()),
            },
            CompactedCheckpoint {
                state_hash: different_hash.clone(),
                parent_hash: Some(shared_hash.clone()),
                event_id: "$1".into(),
                deltas: alloc::vec![StateDelta {
                    event_type: "m.room.topic".into(),
                    state_key: Some(String::new()),
                    event_id: Some("$t".into()),
                }],
                snapshot: None,
            },
            CompactedCheckpoint {
                state_hash: shared_hash.clone(), // same as checkpoint 0!
                parent_hash: Some(different_hash),
                event_id: "$2".into(),
                deltas: alloc::vec![StateDelta {
                    event_type: "m.room.topic".into(),
                    state_key: Some(String::new()),
                    event_id: None, // deletion — reverts to state_a
                }],
                snapshot: None,
            },
        ];

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
        let shared_hash: String = "HASH_A".into();
        let different_hash: String = "HASH_B".into();

        let state_a = {
            let mut s = BTreeMap::new();
            s.insert(("m.room.create".into(), Some(String::new())), "$c".into());
            s
        };
        let state_b = {
            let mut s = state_a.clone();
            s.insert(("m.room.topic".into(), Some(String::new())), "$t".into());
            s
        };

        let checkpoints = alloc::vec![
            CompactedCheckpoint {
                state_hash: shared_hash.clone(),
                parent_hash: None,
                event_id: "$0".into(),
                deltas: alloc::vec![],
                snapshot: Some(state_a.clone()),
            },
            CompactedCheckpoint {
                state_hash: different_hash.clone(),
                parent_hash: Some(shared_hash.clone()),
                event_id: "$1".into(),
                deltas: alloc::vec![StateDelta {
                    event_type: "m.room.topic".into(),
                    state_key: Some(String::new()),
                    event_id: Some("$t".into()),
                }],
                snapshot: None,
            },
            CompactedCheckpoint {
                state_hash: shared_hash.clone(),
                parent_hash: Some(different_hash),
                event_id: "$2".into(),
                deltas: alloc::vec![StateDelta {
                    event_type: "m.room.topic".into(),
                    state_key: Some(String::new()),
                    event_id: None,
                }],
                snapshot: None,
            },
        ];

        let results = reconstruct_state_batch(&checkpoints, &[0, 1, 2]);
        assert_eq!(results.len(), 3);
        assert_eq!(results[&0], state_a);
        assert_eq!(results[&1], state_b);
        assert_eq!(results[&2], state_a);
    }
}
