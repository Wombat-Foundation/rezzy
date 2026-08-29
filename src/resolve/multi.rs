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

//! Multi-state resolution — resolve N parent state maps into one.
//!
//! This module provides the high-level entry point for resolving state across
//! multiple DAG forks (e.g., multiple forward extremities). Given N state maps,
//! it partitions entries into unconflicted (agreed by all forks) and conflicted
//! (differing across forks), then delegates to [`resolve_iterative_sort`](crate::resolve::iterative::resolve_iterative_sort)
//! for the conflicted subset.
//!
//! # Example
//!
//! ```rust,no_run
//! use rezzy::{LeanEvent, SharedState, StateResVersion, HashMap};
//! use rezzy::resolve::multi::resolve_state_maps;
//!
//! // Two forks with different member events
//! let mut fork_a = SharedState::new();
//! fork_a.insert(("m.room.create".into(), "".into()), "$create".into());
//! fork_a.insert(("m.room.member".into(), "@alice:x".into()), "$join_a".into());
//!
//! let mut fork_b = SharedState::new();
//! fork_b.insert(("m.room.create".into(), "".into()), "$create".into());
//! fork_b.insert(("m.room.member".into(), "@alice:x".into()), "$join_b".into());
//!
//! // Build event context (auth chain + conflicted events)
//! let mut ctx: HashMap<String, LeanEvent> = HashMap::new();
//! // ... populate with conflicted events and their auth chains ...
//!
//! let resolved = resolve_state_maps(
//!     &[fork_a, fork_b],
//!     &ctx,
//!     StateResVersion::V2,
//! );
//! ```

use crate::basespec::event_types::EventType;
use crate::basespec::rezzy_types::{
    EventContent, EventId, EventProvider, LeanEvent, StateKey, StateResVersion,
};
use crate::state::at::SharedState;
use crate::state::diff::{StateDiff, StateDiffEntry};
use crate::{FastMap, FastSet, HashMap};
use alloc::vec::Vec;

/// Partitions N state maps into unconflicted state (agreed by all) and a set
/// of conflicted event IDs (present in some forks with different values).
///
/// An entry is **unconflicted** if all N maps contain the same event ID for
/// that `(event_type, state_key)` slot. Otherwise, all event IDs for that
/// slot are added to the conflicted set.
///
/// # Parameters
///
/// - `state_maps`: Iterator of N state maps, each yielding
///   `(&(event_type, state_key), &event_id)` pairs.
/// - `num_maps`: The number of state maps (needed to determine unanimity).
///
/// # Returns
///
/// A tuple of:
/// - `SharedState<Id>`: the unconflicted entries (agreed by all N maps).
/// - `Vec<Id>`: the conflicted event IDs (present in at least one map
///   but not unanimously agreed upon).
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn partition_state_maps<'a, Id, K, I, Iter>(
    state_maps: I,
    num_maps: usize,
) -> (SharedState<Id, K>, Vec<Id>)
where
    Id: EventId,
    I: IntoIterator<Item = Iter>,
    K: StateKey + 'a,
    Iter: IntoIterator<Item = (&'a (EventType, K), &'a Id)>,
    Id: 'a,
{
    // Flattened borrowed-key scan: a single `FastMap` allocation instead of a
    // nested `HashMap` per `(event_type, state_key)` slot, zero `String`/`Id`
    // clones during the pass, and one hash lookup per `(key, id)` pair (no
    // double hashing). Conflict vectors are allocated only on actual
    // disagreement. `foldhash` (hashbrown's default hasher) hashes the
    // attacker-chosen state keys faster than SipHash while staying randomized
    // enough for these internal-only maps.
    let mut occurrences: FastMap<&'a (EventType, K), Occurrence<'a, Id>> = FastMap::default();

    for map in state_maps {
        for (key, id) in map {
            match occurrences.entry(key) {
                hashbrown::hash_map::Entry::Vacant(e) => {
                    e.insert(Occurrence {
                        first_id: id,
                        count: 1,
                        conflicts: None,
                    });
                }
                hashbrown::hash_map::Entry::Occupied(mut e) => {
                    let occ = e.get_mut();
                    occ.count = occ.count.saturating_add(1);
                    if occ.first_id != id {
                        // Seed the conflict vector with the first id so the
                        // tail pass emits every distinct id as conflicted. The
                        // membership set keeps dedup amortized O(1).
                        match &mut occ.conflicts {
                            None => {
                                let mut set = FastSet::default();
                                set.insert(occ.first_id);
                                set.insert(id);
                                occ.conflicts = Some((alloc::vec![occ.first_id, id], set));
                            }
                            Some((ids, seen)) => {
                                if seen.insert(id) {
                                    ids.push(id);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut unconflicted_state = SharedState::new();
    let mut conflicted_ids = Vec::new();

    for (key, occ) in occurrences {
        if occ.count == num_maps && occ.conflicts.is_none() {
            // Unanimous: seen in every map with a single, consistent id.
            unconflicted_state.insert(key.clone(), occ.first_id.clone());
        } else if let Some((conflicts, _)) = occ.conflicts {
            // Disagreement: emit every distinct id as conflicted.
            for id in conflicts {
                conflicted_ids.push(id.clone());
            }
        } else {
            // Seen in fewer than `num_maps` maps (absent from some forks) with
            // no disagreement among the maps that do contain it.
            conflicted_ids.push(occ.first_id.clone());
        }
    }

    (unconflicted_state, conflicted_ids)
}

/// Per-`(event_type, state_key)` occurrence tally accumulated during the
/// partition scan. Borrows from the input state maps so the scan performs zero
/// clones; owned values are produced only when a `(key, id)` is written to the
/// output `SharedState`/`Vec`.
struct Occurrence<'a, Id> {
    first_id: &'a Id,
    count: usize,
    /// Distinct conflicting ids in first-seen order, plus an O(1) membership
    /// set so dedup stays amortized O(1) instead of a linear scan per id
    /// (which would be quadratic for a slot with many distinct ids).
    conflicts: Option<(Vec<&'a Id>, FastSet<&'a Id>)>,
}

/// Resolves N parent state maps into a single deterministic state map.
///
/// This is the high-level entry point for multi-fork state resolution.
/// It handles the full pipeline:
///
/// 1. **Short-circuit**: if all maps are identical, returns the first one.
/// 2. **Partition**: splits entries into unconflicted (unanimous) and
///    conflicted (differing across forks).
/// 3. **Subgraph** (V2.1+ only): computes the MSC4297 conflicted subgraph
///    from the auth DAG and adds subgraph events to the conflicted set.
/// 4. **Resolve**: delegates to [`resolve_iterative_sort`] with the
///    partitioned state and conflicted events.
///
/// # Parameters
///
/// - `state_maps`: Slice of N state maps (one per fork/extremity).
/// - `event_context`: The events needed for resolution. At minimum this
///   must contain every conflicted state event (referenced by the state
///   maps) **and** the transitive closure of their auth chains. Passing
///   a full event map also works — extra events are harmless but waste
///   memory. Homeservers with compressed auth-chain bitmaps can pass
///   just the auth chain for optimal performance.
/// - `version`: Which resolution algorithm to use.
///
/// # Returns
///
/// The resolved `SharedState<Id>` — the single deterministic state.
///
/// # Panics
///
/// Panics if `state_maps` is empty, or if a conflicted event ID from
/// the state maps is not found in `event_context`.
///
/// [`resolve_iterative_sort`]: crate::resolve::iterative::resolve_iterative_sort
#[must_use]
pub fn resolve_state_maps<Id, C, S>(
    state_maps: &[SharedState<Id>],
    event_context: &HashMap<Id, LeanEvent<Id, C>, S>,
    version: StateResVersion,
) -> SharedState<Id>
where
    Id: EventId,
    C: EventContent + Clone,
    S: core::hash::BuildHasher,
{
    resolve_state_maps_generic(
        state_maps,
        event_context,
        version,
        &alloc::string::String::new(),
    )
    .0
}

fn resolve_state_maps_generic<Id, C, S, K>(
    state_maps: &[SharedState<Id, K>],
    event_context: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    version: StateResVersion,
    empty_key: &K,
) -> (SharedState<Id, K>, crate::FastSet<(EventType, K)>)
where
    Id: EventId,
    C: EventContent + Clone,
    S: core::hash::BuildHasher,
    K: StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    assert!(
        !state_maps.is_empty(),
        "resolve_state_maps requires at least one state map"
    );

    // Fast path: all maps identical. Check pointer identity first (O(1)):
    // sibling forks derived from a common ancestor often share the same
    // `imbl::OrdMap` root, so a full structural `==` comparison is wasted.
    let first = &state_maps[0];
    if state_maps.len() == 2 && first.ptr_eq(&state_maps[1]) {
        return (first.clone(), crate::FastSet::default());
    }
    let all_identical = state_maps[1..].iter().all(|m| m == first);
    if all_identical {
        return (first.clone(), crate::FastSet::default());
    }

    // Partition into unconflicted / conflicted
    let (unconflicted_state, conflicted_ids) =
        partition_state_maps(state_maps.iter().map(AsRef::as_ref), state_maps.len());

    // Build the conflicted events map from the event context.
    // Panic if a conflicted event is missing — event_context must contain all
    // events referenced by the state maps.
    let mut conflicted_events: HashMap<Id, LeanEvent<Id, C, K>> = HashMap::new();
    for id in &conflicted_ids {
        let ev = event_context
            .get(id)
            .unwrap_or_else(|| panic!("event_context missing conflicted event {id}"));
        conflicted_events.insert(id.clone(), ev.clone());
    }

    // Genuinely conflicted keys: captured *before* the MSC4297 subgraph
    // supplement below adds more events to `conflicted_events` purely as
    // auth-chain context. Threading this narrower set into resolution
    // prevents a subgraph-context event from clobbering a key every input
    // state map actually agreed on (see resolve_iterative_sort_with_all_caches).
    // TODO(perf): duplicates an EventType::from() conversion the power/
    // non-power phases redo per event — see the identical TODO on
    // resolve::iterative::derive_all_conflicted_keys.
    let conflicted_keys =
        crate::resolve::iterative::derive_all_conflicted_keys(&conflicted_events, empty_key);

    // For V2.1+ rooms, compute the conflicted subgraph (MSC4297).
    if matches!(version, StateResVersion::V2_1 | StateResVersion::V2_1_1) {
        let subgraph = compute_v2_1_subgraph(event_context.iter(), &conflicted_ids);
        for (id, _) in subgraph {
            conflicted_events.entry(id.clone()).or_insert_with(|| {
                event_context
                    .get(&id)
                    .expect("subgraph event must be in event_context")
                    .clone()
            });
        }
    }

    let mut pl_cache: HashMap<Id, i64, hashbrown::DefaultHashBuilder> = HashMap::default();
    let resolved = crate::resolve::iterative::resolve_iterative_sort_with_all_caches(
        &unconflicted_state,
        &conflicted_events,
        event_context,
        None,
        version,
        &mut pl_cache,
        &mut crate::FastMap::default(),
        &conflicted_keys,
        empty_key,
    );
    (resolved, conflicted_keys)
}

/// Computes the exact state mutations needed to update the selected input
/// state map to the result of resolving `state_maps`.
///
/// This is the incremental handoff API for callers that already persist the
/// predecessor state elsewhere (for example, in a HAMT). The baseline is
/// explicit by index and is never inferred from map allocation identity or
/// iteration order.
///
/// The returned [`StateDiff`] contains final state changes only:
/// additions, removals, and replacements. It does not contain the
/// per-event auth-processing trace exposed by
/// [`crate::resolve_iterative_sort_with_deltas`].
///
/// This function does not change the existing [`resolve_state_maps`] return
/// type. Rezzy still materializes the resolved `SharedState` internally in
/// order to perform resolution; this API avoids making callers retain or
/// rebuild that full map at the persistence boundary. Because the baseline is
/// an input fork, the final diff only examines the genuinely conflicted
/// state-key slots.
///
/// `empty_key` is passed explicitly because [`StateKey`] does not require a
/// default value. It is used for state events whose `state_key` is absent.
///
/// # Panics
///
/// Panics if `base_state_index` is outside `state_maps` or if a conflicted
/// event is missing from `event_context`.
///
#[must_use]
pub fn resolve_state_maps_diff<Id, C, S, K>(
    base_state_index: usize,
    state_maps: &[SharedState<Id, K>],
    event_context: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    version: StateResVersion,
    empty_key: &K,
) -> StateDiff<Id, K>
where
    Id: EventId,
    C: EventContent + Clone,
    S: core::hash::BuildHasher,
    K: StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    let base_state = state_maps
        .get(base_state_index)
        .unwrap_or_else(|| panic!("base_state_index out of range: {base_state_index}"));
    let (resolved, conflicted_keys) =
        resolve_state_maps_generic(state_maps, event_context, version, empty_key);

    let mut entries = Vec::new();
    // Sort keys to emit entries in a stable, deterministic order (matching
    // compute_state_diff's sorted key order). Without this, the diff order
    // depends on the hash-bucket iteration order of the HashSet, which is
    // fragile and non-reproducible.
    let mut sorted_keys: Vec<_> = conflicted_keys.into_iter().collect();
    sorted_keys.sort();
    for key in sorted_keys {
        match (base_state.get(&key), resolved.get(&key)) {
            (None, Some(new_id)) => entries.push(StateDiffEntry::Added {
                key,
                event_id: new_id.clone(),
            }),
            (Some(old_id), None) => entries.push(StateDiffEntry::Removed {
                key,
                event_id: old_id.clone(),
            }),
            (Some(old_id), Some(new_id)) if old_id != new_id => {
                entries.push(StateDiffEntry::Changed {
                    key,
                    old_event_id: old_id.clone(),
                    new_event_id: new_id.clone(),
                });
            }
            _ => {}
        }
    }
    StateDiff { entries }
}

/// Builds a stripped auth-only event map and computes the V2.1+ conflicted
/// subgraph (MSC4297).
///
/// Events in the auth DAG that lie at the intersection of backwards-reachable
/// (ancestors) and forwards-reachable (descendants) from the conflicted set
/// must be added to the conflicted set so the mainline sort considers them.
///
/// The `events` iterator provides all events to consider (e.g., `event_context`
/// for the eager path, or `auth_context.chain(conflicted_events)` for the lazy
/// path). The returned subgraph events must be merged into `conflicted_events`
/// by the caller.
#[inline(never)]
fn compute_v2_1_subgraph<'a, Id, C, I, K>(
    events: I,
    conflicted_ids: &[Id],
) -> HashMap<Id, LeanEvent<Id>>
where
    Id: EventId + 'a,
    C: 'a,
    K: StateKey + 'a,
    I: IntoIterator<Item = (&'a Id, &'a LeanEvent<Id, C, K>)>,
{
    let auth_only: HashMap<Id, LeanEvent<Id>> = events
        .into_iter()
        .map(|(id, ev)| {
            (
                id.clone(),
                LeanEvent {
                    rejected: false,
                    soft_fail: false,
                    event_id: ev.event_id.clone(),
                    event_type: ev.event_type.clone(),
                    state_key: ev
                        .state_key
                        .as_ref()
                        .map(|key| alloc::string::String::from(key.as_ref())),
                    sender: ev.sender.clone(),
                    auth_events: ev.auth_events.clone(),
                    prev_events: Vec::new(),
                    content: serde_json::Value::Null,
                    power_level: 0,
                    origin_server_ts: 0,
                    depth: 0,
                    room_id: ev.room_id.clone(),
                },
            )
        })
        .collect();
    crate::resolve::subgraph::compute_v2_1_conflicted_subgraph(&auth_only, conflicted_ids)
}

/// Populate `auth_context` from a precomputed auth diff, skipping events
/// already in `conflicted_events`.
///
/// Extracted as a separate `#[inline(never)]` function to ensure LLVM
/// coverage instruments it independently of the generic caller.
#[inline(never)]
fn populate_auth_from_diff<Id, C>(
    auth_diff: impl IntoIterator<Item = Id>,
    conflicted_events: &HashMap<Id, LeanEvent<Id, C>>,
    provider: &impl EventProvider<Id, C>,
    auth_context: &mut HashMap<Id, LeanEvent<Id, C>>,
) where
    Id: EventId,
    C: Clone,
{
    for aid in auth_diff {
        if conflicted_events.contains_key(&aid) {
            continue;
        }
        if let Some(ev) = provider.get_event(&aid) {
            auth_context.insert(aid, ev.clone());
        }
    }
}

/// Insert subgraph events into `conflicted_events`, sourcing them from
/// `auth_context`.
///
/// # Invariant
///
/// `subgraph ⊆ auth_context ∪ conflicted_events`. If `or_insert_with`
/// fires (event not in `conflicted_events`), it **must** be in
/// `auth_context`.
///
/// # Panics
///
/// Panics if a subgraph event is found in neither `conflicted_events`
/// nor `auth_context` (invariant violation).
#[inline(never)]
fn insert_subgraph_events<Id: EventId, C: Clone>(
    subgraph: HashMap<Id, LeanEvent<Id>>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>>,
    conflicted_events: &mut HashMap<Id, LeanEvent<Id, C>>,
) {
    for (id, _) in subgraph {
        conflicted_events.entry(id.clone()).or_insert_with(|| {
            auth_context
                .get(&id)
                .unwrap_or_else(|| panic!("subgraph event {id} must be in auth_context"))
                .clone()
        });
    }
}

/// Like [`resolve_state_maps`], but accepts an [`EventProvider`] instead of a
/// concrete `HashMap`, enabling lazy/on-demand event loading from a database or
/// LRU cache.
///
/// Instead of requiring the caller to pre-materialize the entire auth context
/// into a `HashMap`, this function:
///
/// 1. Partitions state maps into unconflicted/conflicted (no events needed).
/// 2. Fetches **only** the conflicted events via `provider.get_event(id)`.
/// 3. BFS-walks auth chains from conflicted events to build the minimal auth
///    context (lazy — only touches events reachable from the conflicted set).
/// 4. For V2.1+, computes the conflicted subgraph from the lazily-built context.
/// 5. Delegates to [`resolve_iterative_sort`](crate::resolve::iterative::resolve_iterative_sort).
///
/// # Performance
///
/// For rooms with large auth chains, this can be significantly faster than
/// [`resolve_state_maps`] because it never loads events outside the
/// backwards-reachable set of the conflicted events.
///
/// # Panics
///
/// Panics if `state_maps` is empty, or if a conflicted event ID from
/// the state maps is not found via the provider.
///
/// [`EventProvider`]: crate::basespec::rezzy_types::EventProvider
#[must_use]
pub fn resolve_state_maps_lazy_with_diff<Id, C>(
    state_maps: &[SharedState<Id>],
    provider: &impl crate::basespec::rezzy_types::EventProvider<Id, C>,
    precomputed_auth_diff: Option<impl IntoIterator<Item = Id>>,
    version: StateResVersion,
) -> SharedState<Id>
where
    Id: EventId,
    C: EventContent + Clone,
{
    assert!(
        !state_maps.is_empty(),
        "resolve_state_maps_lazy requires at least one state map"
    );

    // Fast path: all maps identical
    let first = &state_maps[0];
    if state_maps[1..].iter().all(|m| m == first) {
        return first.clone();
    }

    // Partition into unconflicted / conflicted (no events needed)
    let (unconflicted_state, conflicted_ids) =
        partition_state_maps(state_maps.iter().map(AsRef::as_ref), state_maps.len());

    // Lazily fetch conflicted events
    let mut conflicted_events: HashMap<Id, LeanEvent<Id, C>> = HashMap::new();
    for id in &conflicted_ids {
        let ev = provider
            .get_event(id)
            .unwrap_or_else(|| panic!("provider missing conflicted event {id}"));
        conflicted_events.insert(id.clone(), ev.clone());
    }

    // Genuinely conflicted keys, captured before the MSC4297 subgraph
    // supplement below adds more (auth-chain-context-only) events — see
    // resolve_state_maps's identical comment for why this matters.
    let empty_key = alloc::string::String::new();
    let conflicted_keys =
        crate::resolve::iterative::derive_all_conflicted_keys(&conflicted_events, &empty_key);

    // Lazily BFS auth chains from conflicted events to build minimal auth context
    let mut auth_context: HashMap<Id, LeanEvent<Id, C>> = HashMap::new();

    if let Some(auth_diff) = precomputed_auth_diff {
        // Fast path: we already know exactly which events are in the auth diff.
        populate_auth_from_diff(auth_diff, &conflicted_events, provider, &mut auth_context);
    } else {
        // Slow path: dynamically discover the auth diff via BFS
        let mut auth_queue: alloc::collections::VecDeque<Id> = alloc::collections::VecDeque::new();
        for ev in conflicted_events.values() {
            for aid in &ev.auth_events {
                if !conflicted_events.contains_key(aid) {
                    auth_queue.push_back(aid.clone());
                }
            }
        }
        while let Some(aid) = auth_queue.pop_front() {
            if auth_context.contains_key(&aid) || conflicted_events.contains_key(&aid) {
                continue;
            }
            if let Some(ev) = provider.get_event(&aid) {
                auth_context.insert(aid, ev.clone());
                for parent_id in &ev.auth_events {
                    if !auth_context.contains_key(parent_id)
                        && !conflicted_events.contains_key(parent_id)
                    {
                        auth_queue.push_back(parent_id.clone());
                    }
                }
            }
        }
    }

    // V2.1+ subgraph computation from the lazily-built context
    if matches!(version, StateResVersion::V2_1 | StateResVersion::V2_1_1) {
        let subgraph = compute_v2_1_subgraph(
            auth_context.iter().chain(conflicted_events.iter()),
            &conflicted_ids,
        );
        insert_subgraph_events(subgraph, &auth_context, &mut conflicted_events);
    }

    // Merge conflicted events into auth_context so that
    // `route_msc4297_ancestral_power_events` (and `compute_local_auth`) can
    // BFS through them — matching the non-lazy `resolve_state_maps` where
    // `event_context` includes all events.
    for (id, ev) in &conflicted_events {
        auth_context.entry(id.clone()).or_insert_with(|| ev.clone());
    }

    let mut pl_cache: HashMap<Id, i64, hashbrown::DefaultHashBuilder> = HashMap::default();
    crate::resolve::iterative::resolve_iterative_sort_with_all_caches(
        &unconflicted_state,
        &conflicted_events,
        &auth_context,
        None,
        version,
        &mut pl_cache,
        &mut crate::FastMap::default(),
        &conflicted_keys,
        &empty_key,
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #![allow(
        clippy::manual_string_new,
        clippy::arithmetic_side_effects,
        clippy::useless_conversion
    )]
    use super::*;
    use crate::basespec::rezzy_types::LeanEvent;

    type StateMap = SharedState<alloc::string::String>;

    fn make_event(
        id: &str,
        event_type: &str,
        state_key: &str,
        sender: &str,
        auth_events: Vec<alloc::string::String>,
        depth: u64,
    ) -> LeanEvent {
        LeanEvent {
            rejected: false,
            soft_fail: false,
            event_id: id.into(),
            event_type: event_type.into(),
            state_key: Some(state_key.into()),
            sender: sender.into(),
            content: serde_json::Value::Object(serde_json::Map::new()),
            auth_events,
            prev_events: alloc::vec![],
            depth,
            power_level: 0,
            origin_server_ts: depth * 1000,
            room_id: None,
        }
    }

    /// Parse a JSONL string into a `HashMap<String, LeanEvent>` keyed by `event_id`.
    fn parse_jsonl_map(input: &str) -> HashMap<alloc::string::String, LeanEvent> {
        let mut map = HashMap::new();
        for line in input.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            let ev: LeanEvent = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("bad JSONL: {e}\n  line: {line}"));
            map.insert(ev.event_id.clone(), ev);
        }
        map
    }

    #[test]
    fn test_partition_identical_maps() {
        let mut map = StateMap::new();
        map.insert(("m.room.create".into(), "".into()), "$create".into());
        map.insert(("m.room.member".into(), "@alice:x".into()), "$join".into());

        let (unconflicted, conflicted) =
            partition_state_maps([map.iter(), map.iter()].into_iter(), 2);

        assert_eq!(unconflicted.len(), 2);
        assert_eq!(conflicted, [] as [std::string::String; 0]);
    }

    #[test]
    fn test_partition_conflicting_maps() {
        let mut map_a = StateMap::new();
        map_a.insert(("m.room.create".into(), "".into()), "$create".into());
        map_a.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$join_a".into(),
        );

        let mut map_b = StateMap::new();
        map_b.insert(("m.room.create".into(), "".into()), "$create".into());
        map_b.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$join_b".into(),
        );

        let (unconflicted, conflicted) =
            partition_state_maps([map_a.iter(), map_b.iter()].into_iter(), 2);

        // m.room.create is unconflicted, member is conflicted
        assert_eq!(unconflicted.len(), 1);
        assert!(unconflicted.contains_key(&("m.room.create".into(), "".into())));
        assert_eq!(conflicted.len(), 2); // $join_a and $join_b
    }

    #[test]
    fn test_partition_absent_from_some_forks() {
        // Two forks share no keys: every slot appears in only one of the two
        // maps, so nothing is unanimous. Each single-id slot must still be
        // reported as conflicted (it is absent from the other fork) — this is
        // the `count < num_maps` tail of the flattened Occurrence scan.
        let mut map_a = StateMap::new();
        map_a.insert(("m.room.member".into(), "@alice:x".into()), "$join".into());
        let mut map_b = StateMap::new();
        map_b.insert(("m.room.create".into(), "".into()), "$create".into());

        let (unconflicted, conflicted) =
            partition_state_maps([map_a.iter(), map_b.iter()].into_iter(), 2);

        assert_eq!(unconflicted.len(), 0);
        assert_eq!(conflicted.len(), 2);
        assert!(conflicted.contains(&"$join".into()));
        assert!(conflicted.contains(&"$create".into()));
    }

    #[test]
    fn test_resolve_identical_maps_ptr_eq_fast_path() {
        let mut map = StateMap::new();
        map.insert(("m.room.create".into(), "".into()), "$create".into());

        // A clone of an imbl::OrdMap shares its root, so `ptr_eq` is true and
        // resolve_state_maps takes the O(1) identity fast path rather than a
        // full structural `==` comparison.
        let fork_a = map.clone();
        let fork_b = map.clone();
        assert!(fork_a.ptr_eq(&fork_b));

        let events: HashMap<alloc::string::String, LeanEvent> = HashMap::new();
        let result = resolve_state_maps(&[fork_a, fork_b], &events, StateResVersion::V2);
        assert_eq!(result, map);
    }

    #[test]
    fn test_resolve_identical_maps() {
        let mut map = StateMap::new();
        map.insert(("m.room.create".into(), "".into()), "$create".into());

        let events: HashMap<alloc::string::String, LeanEvent> = HashMap::new();
        let result = resolve_state_maps(&[map.clone(), map.clone()], &events, StateResVersion::V2);
        assert_eq!(result, map);
    }

    #[test]
    fn test_resolve_state_maps_diff_supports_interned_state_keys() {
        let base: SharedState<alloc::string::String, crate::InternedKey> = SharedState::new();
        let states = [base.clone()];
        let diff = resolve_state_maps_diff(
            0,
            &states,
            &HashMap::<
                alloc::string::String,
                LeanEvent<alloc::string::String, serde_json::Value, crate::InternedKey>,
            >::new(),
            StateResVersion::V2,
            &crate::InternedKey::new(""),
        );

        assert!(diff.is_empty());
    }

    #[test]
    #[should_panic(expected = "base_state_index out of range: 1")]
    fn test_resolve_state_maps_diff_rejects_invalid_baseline_index() {
        let states: [StateMap; 1] = [StateMap::new()];
        let events: HashMap<alloc::string::String, LeanEvent> = HashMap::new();

        let _ = resolve_state_maps_diff(
            1,
            &states,
            &events,
            StateResVersion::V2,
            &alloc::string::String::new(),
        );
    }

    fn assert_two_fork_diff(diff: &StateDiff<alloc::string::String>) {
        use crate::state::diff::StateDiffEntry;

        assert_eq!(diff.len(), 3);
        assert!(diff.entries.iter().any(|entry| matches!(
            entry,
            StateDiffEntry::Added { event_id, .. } if event_id == "$alice_join"
        )));
        assert!(diff.entries.iter().any(|entry| matches!(
            entry,
            StateDiffEntry::Removed { event_id, .. } if event_id == "$bob_join"
        )));
        assert!(diff.entries.iter().any(|entry| matches!(
            entry,
            StateDiffEntry::Changed {
                old_event_id,
                new_event_id,
                ..
            } if old_event_id == "$pl_b" && new_event_id == "$pl_a"
        )));
    }

    fn assert_unchanged_baseline_diff(
        fork_a: StateMap,
        fork_b: StateMap,
        events: &HashMap<alloc::string::String, LeanEvent>,
    ) {
        let diff = resolve_state_maps_diff(
            0,
            &[fork_a, fork_b],
            events,
            StateResVersion::V2,
            &alloc::string::String::new(),
        );
        assert!(diff.is_empty());
    }

    #[test]
    fn test_resolve_two_forks() {
        // Scenario: two forks disagree on who sent the latest PL event.
        // Fork A has PL from alice (creator), fork B has PL from bob (non-creator).
        // State res should pick alice's PL (creator wins in V2).
        let mut events: HashMap<alloc::string::String, LeanEvent> = HashMap::new();

        let create = make_event("$create", "m.room.create", "", "@alice:x", alloc::vec![], 0);
        events.insert("$create".into(), create);

        let alice_join = make_event(
            "$alice_join",
            "m.room.member",
            "@alice:x",
            "@alice:x",
            alloc::vec!["$create".into()],
            1,
        );
        events.insert("$alice_join".into(), {
            let mut ev = alice_join;
            ev.content = serde_json::json!({"membership": "join"});
            ev
        });

        let bob_join = make_event(
            "$bob_join",
            "m.room.member",
            "@bob:x",
            "@bob:x",
            alloc::vec!["$create".into()],
            1,
        );
        events.insert("$bob_join".into(), {
            let mut ev = bob_join;
            ev.content = serde_json::json!({"membership": "join"});
            ev
        });

        // Fork A: alice sets PL
        let pl_a = make_event(
            "$pl_a",
            "m.room.power_levels",
            "",
            "@alice:x",
            alloc::vec!["$create".into(), "$alice_join".into()],
            2,
        );
        events.insert("$pl_a".into(), {
            let mut ev = pl_a;
            ev.content = serde_json::json!({"users": {"@alice:x": 100}});
            ev.power_level = 100;
            ev
        });

        // Fork B: bob sets PL (unauthorized in practice, but let's see who wins)
        let pl_b = make_event(
            "$pl_b",
            "m.room.power_levels",
            "",
            "@bob:x",
            alloc::vec!["$create".into(), "$bob_join".into()],
            2,
        );
        events.insert("$pl_b".into(), {
            let mut ev = pl_b;
            ev.content = serde_json::json!({"users": {"@bob:x": 100}});
            ev.power_level = 0;
            ev
        });

        let mut fork_a = StateMap::new();
        fork_a.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_a.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$alice_join".into(),
        );
        fork_a.insert(("m.room.power_levels".into(), "".into()), "$pl_a".into());

        let mut fork_b = StateMap::new();
        fork_b.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_b.insert(
            ("m.room.member".into(), "@bob:x".into()),
            "$bob_join".into(),
        );
        fork_b.insert(("m.room.power_levels".into(), "".into()), "$pl_b".into());

        let resolved = resolve_state_maps(
            &[fork_a.clone(), fork_b.clone()],
            &events,
            StateResVersion::V2,
        );

        let diff = resolve_state_maps_diff(
            1,
            &[fork_a.clone(), fork_b.clone()],
            &events,
            StateResVersion::V2,
            &alloc::string::String::new(),
        );

        // The designated predecessor is fork B, not state_maps[0]. The
        // shared create slot is unchanged; member and PL conflicts mutate.
        assert_two_fork_diff(&diff);

        // With fork A as the baseline, the winning PL event is unchanged.
        // This exercises the no-op branch for an actual resolved conflict.
        assert_unchanged_baseline_diff(fork_a, fork_b, &events);

        // The create event should be unconflicted
        assert_eq!(
            resolved.get(&("m.room.create".into(), "".into())),
            Some(&"$create".into())
        );

        // The PL slot should have a winner (alice's, since she's the creator)
        let pl_winner = resolved
            .get(&("m.room.power_levels".into(), "".into()))
            .expect("PL slot should be resolved");
        assert_eq!(
            pl_winner, "$pl_a",
            "alice's PL should win (creator has implicit PL 100)"
        );
    }

    #[test]
    #[should_panic(expected = "requires at least one state map")]
    fn test_resolve_empty_panics() {
        let events: HashMap<alloc::string::String, LeanEvent> = HashMap::new();
        let _ = resolve_state_maps::<alloc::string::String, serde_json::Value, _>(
            &[],
            &events,
            StateResVersion::V2,
        );
    }

    #[test]
    #[should_panic(expected = "event_context missing conflicted event")]
    fn test_resolve_missing_conflicted_event_panics() {
        // Two forks disagree on a member slot. The conflicted event ID
        // is NOT in events_map, so the defensive panic should fire.
        let mut fork_a = StateMap::new();
        fork_a.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_a.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$join_a".into(),
        );

        let mut fork_b = StateMap::new();
        fork_b.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_b.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$join_b".into(), // differs from fork_a → conflicted
        );

        // events_map only has create — missing both join events
        let mut events: HashMap<alloc::string::String, LeanEvent> = HashMap::new();
        events.insert(
            "$create".into(),
            make_event("$create", "m.room.create", "", "@alice:x", alloc::vec![], 0),
        );

        let _ = resolve_state_maps(&[fork_a, fork_b], &events, StateResVersion::V2);
    }

    #[test]
    fn test_resolve_single_map() {
        let mut map = StateMap::new();
        map.insert(("m.room.create".into(), "".into()), "$create".into());
        map.insert(("m.room.member".into(), "@alice:x".into()), "$join".into());

        let events: HashMap<alloc::string::String, LeanEvent> = HashMap::new();
        let result = resolve_state_maps(&[map.clone()], &events, StateResVersion::V2);
        assert_eq!(result, map);
    }

    #[test]
    fn test_resolve_three_forks() {
        // Three forks: two agree on alice's join, one differs.
        // Partitioning requires unanimity, so this slot is conflicted and must be resolved.
        let mut events: HashMap<alloc::string::String, LeanEvent> = HashMap::new();

        events.insert(
            "$create".into(),
            make_event("$create", "m.room.create", "", "@alice:x", alloc::vec![], 0),
        );
        events.insert("$alice_join".into(), {
            let mut ev = make_event(
                "$alice_join",
                "m.room.member",
                "@alice:x",
                "@alice:x",
                alloc::vec!["$create".into()],
                1,
            );
            ev.content = serde_json::json!({"membership": "join"});
            ev
        });
        events.insert("$bob_join".into(), {
            let mut ev = make_event(
                "$bob_join",
                "m.room.member",
                "@alice:x",
                "@alice:x",
                alloc::vec!["$create".into()],
                1,
            );
            ev.content = serde_json::json!({"membership": "join"});
            ev
        });

        let mut fork_a = StateMap::new();
        fork_a.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_a.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$alice_join".into(),
        );

        let fork_b = fork_a.clone();

        let mut fork_c = StateMap::new();
        fork_c.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_c.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$bob_join".into(),
        );

        let resolved = resolve_state_maps(&[fork_a, fork_b, fork_c], &events, StateResVersion::V2);

        // Create is unconflicted (all three agree)
        assert_eq!(
            resolved.get(&("m.room.create".into(), "".into())),
            Some(&"$create".into())
        );

        // Member slot should be resolved (alice_join or bob_join — both are valid joins)
        assert!(resolved.contains_key(&("m.room.member".into(), "@alice:x".into())));
    }

    #[test]
    fn test_resolve_lazy_identical_maps() {
        let mut map = StateMap::new();
        map.insert(("m.room.create".into(), "".into()), "$create".into());

        let events: HashMap<alloc::string::String, LeanEvent> = HashMap::new();
        let result = resolve_state_maps_lazy_with_diff(
            &[map.clone(), map.clone()],
            &events,
            None::<alloc::vec::Vec<alloc::string::String>>,
            StateResVersion::V2,
        );
        assert_eq!(result, map);
    }

    #[test]
    fn test_resolve_lazy_matches_concrete() {
        // Same two-fork scenario as test_resolve_two_forks —
        // verify the lazy variant produces identical results.
        let mut events: HashMap<alloc::string::String, LeanEvent> = HashMap::new();

        events.insert(
            "$create".into(),
            make_event("$create", "m.room.create", "", "@alice:x", alloc::vec![], 0),
        );
        events.insert("$alice_join".into(), {
            let mut ev = make_event(
                "$alice_join",
                "m.room.member",
                "@alice:x",
                "@alice:x",
                alloc::vec!["$create".into()],
                1,
            );
            ev.content = serde_json::json!({"membership": "join"});
            ev
        });
        events.insert("$bob_join".into(), {
            let mut ev = make_event(
                "$bob_join",
                "m.room.member",
                "@bob:x",
                "@bob:x",
                alloc::vec!["$create".into()],
                1,
            );
            ev.content = serde_json::json!({"membership": "join"});
            ev
        });
        events.insert("$pl_a".into(), {
            let mut ev = make_event(
                "$pl_a",
                "m.room.power_levels",
                "",
                "@alice:x",
                alloc::vec!["$create".into(), "$alice_join".into()],
                2,
            );
            ev.content = serde_json::json!({"users": {"@alice:x": 100}});
            ev.power_level = 100;
            ev
        });
        events.insert("$pl_b".into(), {
            let mut ev = make_event(
                "$pl_b",
                "m.room.power_levels",
                "",
                "@bob:x",
                alloc::vec!["$create".into(), "$bob_join".into()],
                2,
            );
            ev.content = serde_json::json!({"users": {"@bob:x": 100}});
            ev.power_level = 0;
            ev
        });

        let mut fork_a = StateMap::new();
        fork_a.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_a.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$alice_join".into(),
        );
        fork_a.insert(("m.room.power_levels".into(), "".into()), "$pl_a".into());

        let mut fork_b = StateMap::new();
        fork_b.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_b.insert(
            ("m.room.member".into(), "@bob:x".into()),
            "$bob_join".into(),
        );
        fork_b.insert(("m.room.power_levels".into(), "".into()), "$pl_b".into());

        let concrete = resolve_state_maps(
            &[fork_a.clone(), fork_b.clone()],
            &events,
            StateResVersion::V2,
        );
        let lazy = resolve_state_maps_lazy_with_diff(
            &[fork_a, fork_b],
            &events,
            None::<alloc::vec::Vec<alloc::string::String>>,
            StateResVersion::V2,
        );

        assert_eq!(
            concrete, lazy,
            "lazy resolver must produce identical results to concrete"
        );
    }

    #[test]
    fn test_resolve_lazy_matches_concrete_v2_1() {
        // Deep auth chain to exercise:
        //   1. Transitive BFS walk (lines 333-340): $create and $alice_join are
        //      ONLY reachable via $pl's auth chain, not directly from the
        //      conflicted events.
        //   2. V2_1 subgraph insertion (lines 370-378): $pl sits in the auth
        //      intersection of both conflicted events, so the subgraph
        //      computation adds it to conflicted_events.
        //
        // Auth DAG (transitive-only links for $create, $alice_join):
        //   $create ← $alice_join ← $pl ← $topic_a (fork A)
        //                                ← $topic_b (fork B)
        //
        // NOTE: $topic_a/$topic_b only auth [$pl], NOT [$create, $alice_join].
        // NOTE: $topic_a/$topic_b only auth [$pl] — $create and $alice_join
        // must be discovered transitively by the BFS walk.
        let events = parse_jsonl_map(
            r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@alice:x", "content": {}}
{"event_id": "$alice_join", "type": "m.room.member", "state_key": "@alice:x", "sender": "@alice:x", "auth_events": ["$create"], "depth": 1, "content": {"membership": "join"}}
{"event_id": "$pl", "type": "m.room.power_levels", "state_key": "", "sender": "@alice:x", "auth_events": ["$create", "$alice_join"], "depth": 2, "power_level": 100, "content": {"users": {"@alice:x": 100}}}
{"event_id": "$topic_a", "type": "m.room.topic", "state_key": "", "sender": "@alice:x", "auth_events": ["$pl"], "depth": 3, "content": {}}
{"event_id": "$topic_b", "type": "m.room.topic", "state_key": "", "sender": "@alice:x", "auth_events": ["$pl"], "depth": 3, "content": {}}
"#,
        );

        let mut fork_a = StateMap::new();
        fork_a.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_a.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$alice_join".into(),
        );
        fork_a.insert(("m.room.power_levels".into(), "".into()), "$pl".into());
        fork_a.insert(("m.room.topic".into(), "".into()), "$topic_a".into());

        let mut fork_b = StateMap::new();
        fork_b.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_b.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$alice_join".into(),
        );
        fork_b.insert(("m.room.power_levels".into(), "".into()), "$pl".into());
        fork_b.insert(("m.room.topic".into(), "".into()), "$topic_b".into());

        let concrete = resolve_state_maps(
            &[fork_a.clone(), fork_b.clone()],
            &events,
            StateResVersion::V2_1,
        );
        // None auth diff → exercises BFS slow path with transitive auth walk
        let lazy = resolve_state_maps_lazy_with_diff(
            &[fork_a, fork_b],
            &events,
            None::<alloc::vec::Vec<alloc::string::String>>,
            StateResVersion::V2_1,
        );

        assert_eq!(
            concrete, lazy,
            "lazy resolver must produce identical results to concrete for V2_1"
        );
    }

    #[test]
    fn test_resolve_lazy_v2_1_subgraph_insertion() {
        // Exercise the `or_insert_with` at L372-377: a non-conflicted event
        // ($mid) sits between two conflicted state keys in the auth chain.
        //
        // Conflicted slots:
        //   (m.room.power_levels, "") → $pl_a vs $pl_b
        //   (m.room.topic, "")       → $topic_a vs $topic_b
        //
        // Auth DAG:
        //   $create ← $pl_a ← $mid ← $topic_a
        //           ← $pl_b         ← $topic_b
        //
        // $mid is AGREED (same in both forks) so it's NOT in conflicted_events.
        // But the subgraph backward/forward intersection includes $mid because:
        //   backwards: $topic_a → $mid → $pl_a → $create (ancestor path)
        //   forwards:  $pl_a → children[$pl_a]=[$mid] → children[$mid]=[$topic_a]
        // so $mid ∈ backwards ∩ forwards → triggers or_insert_with.
        let events = parse_jsonl_map(
            r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@alice:x", "content": {}}
{"event_id": "$alice_join", "type": "m.room.member", "state_key": "@alice:x", "sender": "@alice:x", "auth_events": ["$create"], "depth": 1, "content": {"membership": "join"}}
{"event_id": "$pl_a", "type": "m.room.power_levels", "state_key": "", "sender": "@alice:x", "auth_events": ["$create"], "depth": 2, "power_level": 100, "content": {"users": {"@alice:x": 100}}}
{"event_id": "$pl_b", "type": "m.room.power_levels", "state_key": "", "sender": "@alice:x", "auth_events": ["$create"], "depth": 2, "power_level": 100, "content": {"users": {"@alice:x": 100}}}
{"event_id": "$mid", "type": "m.room.name", "state_key": "", "sender": "@alice:x", "auth_events": ["$pl_a"], "depth": 3, "content": {"name": "test"}}
{"event_id": "$topic_a", "type": "m.room.topic", "state_key": "", "sender": "@alice:x", "auth_events": ["$mid"], "depth": 4, "content": {}}
{"event_id": "$topic_b", "type": "m.room.topic", "state_key": "", "sender": "@alice:x", "auth_events": ["$pl_b"], "depth": 4, "content": {}}
"#,
        );

        let mut fork_a = StateMap::new();
        fork_a.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_a.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$alice_join".into(),
        );
        fork_a.insert(("m.room.power_levels".into(), "".into()), "$pl_a".into());
        fork_a.insert(("m.room.name".into(), "".into()), "$mid".into());
        fork_a.insert(("m.room.topic".into(), "".into()), "$topic_a".into());

        let mut fork_b = StateMap::new();
        fork_b.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_b.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$alice_join".into(),
        );
        fork_b.insert(("m.room.power_levels".into(), "".into()), "$pl_b".into());
        fork_b.insert(("m.room.name".into(), "".into()), "$mid".into());
        fork_b.insert(("m.room.topic".into(), "".into()), "$topic_b".into());

        let concrete = resolve_state_maps(
            &[fork_a.clone(), fork_b.clone()],
            &events,
            StateResVersion::V2_1,
        );
        let lazy = resolve_state_maps_lazy_with_diff(
            &[fork_a, fork_b],
            &events,
            None::<alloc::vec::Vec<alloc::string::String>>,
            StateResVersion::V2_1,
        );

        assert_eq!(
            concrete, lazy,
            "lazy resolver with subgraph insertion must match concrete"
        );
    }

    #[test]
    #[should_panic(expected = "requires at least one state map")]
    fn test_resolve_lazy_empty_panics() {
        let events: HashMap<alloc::string::String, LeanEvent> = HashMap::new();
        let _ = resolve_state_maps_lazy_with_diff(
            &[],
            &events,
            None::<alloc::vec::Vec<alloc::string::String>>,
            StateResVersion::V2,
        );
    }

    #[test]
    #[should_panic(expected = "subgraph event $orphan must be in auth_context")]
    fn test_insert_subgraph_events_missing_auth_panics() {
        // Directly test the defensive panic in insert_subgraph_events by
        // violating its invariant: pass a subgraph containing an event
        // that exists in neither conflicted_events nor auth_context.
        let mut subgraph: HashMap<alloc::string::String, LeanEvent> = HashMap::new();
        subgraph.insert(
            "$orphan".into(),
            make_event("$orphan", "m.room.topic", "", "@alice:x", alloc::vec![], 0),
        );

        let auth_context: HashMap<alloc::string::String, LeanEvent> = HashMap::new();
        let mut conflicted_events: HashMap<alloc::string::String, LeanEvent> = HashMap::new();

        insert_subgraph_events(subgraph, &auth_context, &mut conflicted_events);
    }

    #[test]
    #[should_panic(expected = "provider missing conflicted event")]
    fn test_resolve_lazy_missing_conflicted_event_panics() {
        let mut fork_a = StateMap::new();
        fork_a.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_a.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$join_a".into(),
        );

        let mut fork_b = StateMap::new();
        fork_b.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_b.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$join_b".into(),
        );

        // Provider has $create but NOT the conflicted join events
        let events = parse_jsonl_map(
            r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@alice:x", "content": {}}
"#,
        );

        let _ = resolve_state_maps_lazy_with_diff(
            &[fork_a, fork_b],
            &events,
            None::<alloc::vec::Vec<alloc::string::String>>,
            StateResVersion::V2,
        );
    }

    #[test]
    fn test_resolve_lazy_with_precomputed_auth_diff() {
        // Exercise the `Some(auth_diff)` fast path in resolve_state_maps_lazy_with_diff
        let events = parse_jsonl_map(
            r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@alice:x", "content": {}}
{"event_id": "$alice_join", "type": "m.room.member", "state_key": "@alice:x", "sender": "@alice:x", "auth_events": ["$create"], "depth": 1, "content": {"membership": "join"}}
{"event_id": "$bob_join", "type": "m.room.member", "state_key": "@bob:x", "sender": "@bob:x", "auth_events": ["$create"], "depth": 1, "content": {"membership": "join"}}
"#,
        );

        let mut fork_a = StateMap::new();
        fork_a.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_a.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "$alice_join".into(),
        );

        let mut fork_b = StateMap::new();
        fork_b.insert(("m.room.create".into(), "".into()), "$create".into());
        fork_b.insert(
            ("m.room.member".into(), "@bob:x".into()),
            "$bob_join".into(),
        );

        let concrete = resolve_state_maps(
            &[fork_a.clone(), fork_b.clone()],
            &events,
            StateResVersion::V2,
        );

        // Include an auth event already present in conflicted_events. It must
        // be skipped by populate_auth_from_diff rather than reinserted.
        let auth_diff: alloc::vec::Vec<alloc::string::String> =
            alloc::vec!["$create".into(), "$alice_join".into()];
        let lazy = resolve_state_maps_lazy_with_diff(
            &[fork_a, fork_b],
            &events,
            Some(auth_diff),
            StateResVersion::V2,
        );

        assert_eq!(
            concrete, lazy,
            "lazy resolver with precomputed auth diff must match concrete"
        );
    }
}
