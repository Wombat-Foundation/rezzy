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

use crate::basespec::rezzy_types::{EventContent, EventId, LeanEvent, StateResVersion};
use crate::state::at::SharedState;
use crate::HashMap;
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
/// This function will not panic under normal use. Internal `unwrap()` calls
/// are guarded by a `len() == 1` check on the occurrence map.
#[must_use]
pub fn partition_state_maps<'a, Id, I, Iter>(
    state_maps: I,
    num_maps: usize,
) -> (SharedState<Id>, Vec<Id>)
where
    Id: EventId,
    I: IntoIterator<Item = Iter>,
    Iter: IntoIterator<Item = (&'a (alloc::string::String, alloc::string::String), &'a Id)>,
    Id: 'a,
{
    let mut occurrences: HashMap<
        (alloc::string::String, alloc::string::String),
        HashMap<Id, usize>,
    > = HashMap::new();
    for map in state_maps {
        for (key, id) in map {
            let val = occurrences
                .entry(key.clone())
                .or_default()
                .entry(id.clone())
                .or_insert(0);
            *val = val.saturating_add(1);
        }
    }

    let mut unconflicted_state = SharedState::new();
    let mut conflicted_ids = Vec::new();

    for (key, ids) in occurrences {
        if ids.len() == 1 && ids.values().next().unwrap() == &num_maps {
            let id = ids.into_keys().next().unwrap();
            unconflicted_state.insert(key, id);
        } else {
            for id in ids.into_keys() {
                conflicted_ids.push(id);
            }
        }
    }

    (unconflicted_state, conflicted_ids)
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
    assert!(
        !state_maps.is_empty(),
        "resolve_state_maps requires at least one state map"
    );

    // Fast path: all maps identical
    let first = &state_maps[0];
    let all_identical = state_maps[1..].iter().all(|m| m == first);
    if all_identical {
        return first.clone();
    }

    // Partition into unconflicted / conflicted
    let (unconflicted_state, conflicted_ids) =
        partition_state_maps(state_maps.iter().map(AsRef::as_ref), state_maps.len());

    // Build the conflicted events map from the event context.
    // Panic if a conflicted event is missing — event_context must contain all
    // events referenced by the state maps.
    let mut conflicted_events: HashMap<Id, LeanEvent<Id, C>> = HashMap::new();
    for id in &conflicted_ids {
        let ev = event_context
            .get(id)
            .unwrap_or_else(|| panic!("event_context missing conflicted event {id}"));
        conflicted_events.insert(id.clone(), ev.clone());
    }

    // For V2.1+ rooms, compute the conflicted subgraph (MSC4297): events in
    // the auth DAG that lie at the intersection of backwards-reachable
    // (ancestors) and forwards-reachable (descendants) from the conflicted
    // set.  These events must be added to the conflicted set so the mainline
    // sort considers them — without this, intermediate PL events in the auth
    // chain are missed and resolution picks wrong winners.
    //
    // We build a stripped event map (auth_events only, no content) to satisfy
    // the `LeanEvent<Id>` signature of `compute_v2_1_conflicted_subgraph`.
    if matches!(version, StateResVersion::V2_1 | StateResVersion::V2_1_1) {
        let auth_only: HashMap<Id, LeanEvent<Id>> = event_context
            .iter()
            .map(|(id, ev)| {
                (
                    id.clone(),
                    LeanEvent {
                        event_id: ev.event_id.clone(),
                        event_type: ev.event_type.clone(),
                        state_key: ev.state_key.clone(),
                        sender: ev.sender.clone(),
                        auth_events: ev.auth_events.clone(),
                        prev_events: Vec::new(),
                        content: serde_json::Value::Null,
                        power_level: 0,
                        origin_server_ts: 0,
                        depth: 0,
                    },
                )
            })
            .collect();
        let subgraph =
            crate::resolve::subgraph::compute_v2_1_conflicted_subgraph(&auth_only, &conflicted_ids);
        for (id, _) in subgraph {
            conflicted_events.entry(id.clone()).or_insert_with(|| {
                event_context
                    .get(&id)
                    .expect("subgraph event must be in event_context")
                    .clone()
            });
        }
    }

    crate::resolve::iterative::resolve_iterative_sort(
        unconflicted_state,
        conflicted_events,
        event_context,
        version,
    )
}

#[cfg(test)]
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
        }
    }

    #[test]
    fn test_partition_identical_maps() {
        let mut map = StateMap::new();
        map.insert(("m.room.create".into(), "".into()), "$create".into());
        map.insert(("m.room.member".into(), "@alice:x".into()), "$join".into());

        let (unconflicted, conflicted) =
            partition_state_maps([map.iter(), map.iter()].into_iter(), 2);

        assert_eq!(unconflicted.len(), 2);
        assert!(conflicted.is_empty());
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
    fn test_resolve_identical_maps() {
        let mut map = StateMap::new();
        map.insert(("m.room.create".into(), "".into()), "$create".into());

        let events: HashMap<alloc::string::String, LeanEvent> = HashMap::new();
        let result = resolve_state_maps(&[map.clone(), map.clone()], &events, StateResVersion::V2);
        assert_eq!(result, map);
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

        let resolved = resolve_state_maps(&[fork_a, fork_b], &events, StateResVersion::V2);

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
}
