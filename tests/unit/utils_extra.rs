//! Unit-binary-only test helpers, split out of `tests/utils/mod.rs`.
//!
//! These are referenced only by the merged `unit` test binary. The stress,
//! snapshot, and oracle binaries compile `tests/utils/mod.rs` too, so keeping
//! them there caused per-target `dead_code` warnings once each binary only
//! included a subset of the helpers. They are deliberately NOT feature-gated:
//! the `--all-features` CI job builds the `unit` binary with `stress` and
//! `regen` enabled, so a `not(feature = ...)` gate would strip them from the
//! very target that uses them. Scoping them to this module confines them to
//! the `unit` compilation unit instead.

use rezzy::auth::RoomState;
use rezzy::basespec::rezzy_types::LeanEvent;
use std::collections::HashMap;

use crate::utils::parse_jsonl_events;

/// Builds an initial unconflicted state map from the selected event IDs in
/// `auth_context`.
///
/// This is for tests that want the authoritative base state to include more
/// than just `m.room.create` while still deriving the `(event_type, state_key)`
/// tuple from the event itself instead of hand-writing the key at each call
/// site.
pub fn build_unconflicted_state_from_ids(
    auth_context: &HashMap<String, LeanEvent>,
    event_ids: &[&str],
) -> imbl::OrdMap<(rezzy::basespec::event_types::EventType, String), String> {
    let mut unconflicted = imbl::OrdMap::new();

    for event_id in event_ids {
        let ev = auth_context
            .get(*event_id)
            .unwrap_or_else(|| panic!("fixture auth_context missing event {event_id:?}"));
        let state_key = ev
            .state_key
            .clone()
            .unwrap_or_else(|| panic!("fixture event {event_id:?} must have state_key"));
        unconflicted.insert(
            (
                rezzy::basespec::event_types::EventType::from(ev.event_type.as_str()),
                state_key,
            ),
            ev.event_id.clone(),
        );
    }

    unconflicted
}

/// Parses a multiline JSONL string directly into a `RoomState`.
pub fn parse_jsonl_state(input: &str) -> RoomState {
    let mut state = RoomState::new();
    let events = parse_jsonl_events(input);
    for event in events {
        if let Some(sk) = &event.state_key {
            state.insert((event.event_type.clone(), sk.clone()), event);
        }
    }
    state
}

/// Field-by-field equality for [`LeanEvent`], for test assertions.
///
/// `LeanEvent`'s own `PartialEq` deliberately compares only `event_id` (it's
/// used for `Ord`/set membership elsewhere in the crate), so it's blind to
/// two same-id events differing in sender, content, type, etc. The JSONL
/// asserters below need the stronger check: a fixture/actual pair should
/// match on every field, not just carry the same id.
fn lean_events_fully_eq(a: &LeanEvent, b: &LeanEvent) -> bool {
    a.event_id == b.event_id
        && a.event_type == b.event_type
        && a.state_key == b.state_key
        && a.power_level == b.power_level
        && a.origin_server_ts == b.origin_server_ts
        && a.sender == b.sender
        && a.content == b.content
        && a.prev_events == b.prev_events
        && a.auth_events == b.auth_events
        && a.depth == b.depth
        && a.rejected == b.rejected
        && a.soft_fail == b.soft_fail
        && a.room_id == b.room_id
}

/// Asserts that a given `RoomState` exactly matches the state defined in a JSONL string.
pub fn assert_jsonl_state_eq(actual: &RoomState, expected_jsonl: &str) {
    let expected = parse_jsonl_state(expected_jsonl);

    // First, assert the lengths are the same
    assert_eq!(
        actual.len(),
        expected.len(),
        "State lengths differ. Expected {}, got {}",
        expected.len(),
        actual.len()
    );

    // Then, assert each element matches precisely (all fields, not just event_id)
    for (key, expected_event) in &expected {
        let actual_event = actual.get(key).unwrap_or_else(|| {
            panic!("Actual state missing expected event at key {key:?}");
        });

        assert!(
            lean_events_fully_eq(actual_event, expected_event),
            "Event mismatch at key {key:?}\n  actual:   {actual_event:?}\n  expected: {expected_event:?}"
        );
    }
}

/// Asserts that a given slice of [`LeanEvent`]s exactly matches the events defined in a JSONL string.
pub fn assert_jsonl_events_eq(actual: &[LeanEvent], expected_jsonl: &str) {
    let expected = parse_jsonl_events(expected_jsonl);

    // First, assert the lengths are the same
    assert_eq!(
        actual.len(),
        expected.len(),
        "Events lengths differ. Expected {}, got {}",
        expected.len(),
        actual.len()
    );

    // Then, assert each element matches precisely (all fields, not just event_id)
    for (i, (actual_event, expected_event)) in actual.iter().zip(expected.iter()).enumerate() {
        assert!(
            lean_events_fully_eq(actual_event, expected_event),
            "Event mismatch at index {i}\n  actual:   {actual_event:?}\n  expected: {expected_event:?}"
        );
    }
}

/// Computes and assigns the topological depth for a set of events based on their `prev_events`.
/// The depth of an event is 1 if it has no `prev_events`, or 1 greater than the maximum depth
/// of its `prev_events` otherwise.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn compute_local_naive_topological_depth(events: &mut [LeanEvent]) {
    fn get_depth(
        event_id: &str,
        event_map: &std::collections::HashMap<String, usize>,
        events: &[LeanEvent],
        depths: &mut std::collections::HashMap<String, u64>,
        in_progress: &mut std::collections::HashSet<String>,
    ) -> u64 {
        if let Some(&d) = depths.get(event_id) {
            return d;
        }

        assert!(
            in_progress.insert(event_id.to_string()),
            "cycle detected in prev_events at {event_id}"
        );

        let Some(&idx) = event_map.get(event_id) else {
            in_progress.remove(event_id);
            return 1;
        };

        let ev = &events[idx];
        if ev.prev_events.is_empty() {
            depths.insert(event_id.to_string(), 1);
            in_progress.remove(event_id);
            return 1;
        }

        let mut max_prev_depth = 0;
        for prev_id in &ev.prev_events {
            max_prev_depth =
                max_prev_depth.max(get_depth(prev_id, event_map, events, depths, in_progress));
        }

        let d = max_prev_depth.saturating_add(1);
        depths.insert(event_id.to_string(), d);
        in_progress.remove(event_id);
        d
    }

    let mut event_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (i, ev) in events.iter().enumerate() {
        event_map.insert(ev.event_id.clone(), i);
    }

    let mut depths: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut in_progress: std::collections::HashSet<String> = std::collections::HashSet::new();

    for i in 0..events.len() {
        let ev_id = events[i].event_id.clone();
        events[i].depth = get_depth(&ev_id, &event_map, events, &mut depths, &mut in_progress);
    }
}
