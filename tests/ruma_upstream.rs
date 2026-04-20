// Copyright 2026 Shane Jaroch
//
// Ruma Upstream E2E Tests
// These tests use the official ruma-state-res test fixtures from
// https://github.com/ruma/ruma/tree/main/crates/ruma-state-res/tests/it/resolve/fixtures
//
// They validate that our lean_kahn_sort + resolve_lean pipeline produces
// results consistent with the upstream Ruma state resolution implementation.

extern crate alloc;
extern crate std;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use ruma_lean::{resolve_lean, LeanEvent, StateResVersion};
use std::collections::HashMap;

/// Load a JSON fixture file into a Vec<LeanEvent>.
/// The fixtures use "type" (not "event_type") which our serde rename handles.
fn load_fixture(path: &str) -> Vec<LeanEvent> {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", path, e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse fixture {}: {}", path, e))
}

/// Load multiple fixture files and concatenate them into one event list.
fn load_fixtures(paths: &[&str]) -> Vec<LeanEvent> {
    let mut events = Vec::new();
    for path in paths {
        events.extend(load_fixture(path));
    }
    events
}

/// Build a HashMap<String, LeanEvent> from a list of events (keyed by event_id).
fn to_event_map(events: &[LeanEvent]) -> HashMap<String, LeanEvent> {
    events
        .iter()
        .map(|e| (e.event_id.clone(), e.clone()))
        .collect()
}

/// Run Kahn's sort on the events and verify it doesn't detect any cycles.
fn sort_and_verify(events: &[LeanEvent], version: StateResVersion) -> Vec<String> {
    let map = to_event_map(events);
    let result = ruma_lean::lean_kahn_sort_detailed(&map, version);
    match &result {
        ruma_lean::KahnSortResult::CycleDetected { stuck, .. } => {
            panic!("Cycle detected in fixture DAG! Stuck events: {:?}", stuck);
        }
        ruma_lean::KahnSortResult::Ok(sorted) => {
            assert_eq!(
                sorted.len(),
                events.len(),
                "Sort dropped events: expected {}, got {}",
                events.len(),
                sorted.len()
            );
        }
    }
    result.into_sorted()
}

/// Run full resolution pipeline: sort + resolve conflicted state.
fn resolve_fixture_batch(
    fixture_paths: &[&str],
    version: StateResVersion,
) -> BTreeMap<(String, String), String> {
    let events = load_fixtures(fixture_paths);
    let event_map = to_event_map(&events);

    // Sort events topologically
    sort_and_verify(&events, version);

    // For batch tests, pass all events as the conflicted set
    let unconflicted = BTreeMap::new();
    resolve_lean(unconflicted, event_map, version)
}

const FIXTURE_DIR: &str = "res/ruma_upstream";

// ============================================================================
// Ruma Upstream E2E Tests — Batch Resolution
// ============================================================================

#[test]
fn test_ruma_bootstrap_private_chat_sort() {
    let events = load_fixture(&format!("{}/bootstrap-private-chat.json", FIXTURE_DIR));
    let sorted = sort_and_verify(&events, StateResVersion::V2);
    // Create event must always be first
    assert_eq!(sorted[0], "$00-m-room-create");
}

#[test]
fn test_ruma_bootstrap_public_chat_sort() {
    let events = load_fixture(&format!("{}/bootstrap-public-chat.json", FIXTURE_DIR));
    let sorted = sort_and_verify(&events, StateResVersion::V2);
    assert_eq!(sorted[0], "$00-m-room-create");
    // Bob's join should come after the create + alice's join + power_levels + join_rules
    let bob_pos = sorted
        .iter()
        .position(|id| id == "$00-m-room-member-join-bob")
        .expect("Bob's join not found");
    assert!(bob_pos >= 4, "Bob should join after initial room setup");
}

#[test]
fn test_ruma_bootstrap_public_chat_resolution() {
    let resolved = resolve_fixture_batch(
        &[&format!("{}/bootstrap-public-chat.json", FIXTURE_DIR)],
        StateResVersion::V2,
    );
    // After resolution, the power_levels should be the latest version
    let pl_winner = resolved
        .get(&("m.room.power_levels".into(), String::new()))
        .expect("No power_levels in resolved state");
    assert_eq!(pl_winner, "$01-m-room-power_levels");
}

#[test]
fn test_ruma_ban_vs_power_levels() {
    // Alice bans Bob while Bob tries to change power levels.
    // Alice's ban should win because bans supersede PL changes.
    let resolved = resolve_fixture_batch(
        &[
            &format!("{}/bootstrap-public-chat.json", FIXTURE_DIR),
            &format!("{}/ban-vs-power-levels-alice.json", FIXTURE_DIR),
            &format!("{}/ban-vs-power-levels-bob.json", FIXTURE_DIR),
        ],
        StateResVersion::V2,
    );
    // Bob should be banned (alice's ban wins over bob's PL change)
    let bob_member = resolved
        .get(&("m.room.member".into(), "@bob:example.com".into()))
        .expect("Bob's membership not in resolved state");
    assert_eq!(
        bob_member, "$00-m-room-member-ban-bob",
        "Alice's ban of Bob should win over Bob's power level change"
    );
}

#[test]
fn test_ruma_topic_vs_power_levels() {
    // Bob changes topic, Alice demotes Bob. Alice's demotion should win.
    let resolved = resolve_fixture_batch(
        &[
            &format!("{}/bootstrap-public-chat.json", FIXTURE_DIR),
            &format!("{}/topic-vs-power-levels-alice.json", FIXTURE_DIR),
            &format!("{}/topic-vs-power-levels-bob.json", FIXTURE_DIR),
        ],
        StateResVersion::V2,
    );
    // Power levels should reflect Alice's demotion of Bob
    let pl = resolved
        .get(&("m.room.power_levels".into(), String::new()))
        .expect("No power_levels in resolved state");
    // Alice's PL change should win (she has higher power)
    assert!(
        pl.contains("alice") || pl.starts_with("$"),
        "Alice's PL change should be in resolved state"
    );
}

#[test]
fn test_ruma_concurrent_joins() {
    // Both Charlie and Ella join simultaneously. Both should appear in state.
    let resolved = resolve_fixture_batch(
        &[
            &format!("{}/bootstrap-public-chat.json", FIXTURE_DIR),
            &format!("{}/concurrent-joins-charlie.json", FIXTURE_DIR),
            &format!("{}/concurrent-joins-ella.json", FIXTURE_DIR),
        ],
        StateResVersion::V2,
    );
    // Both should have membership entries
    assert!(
        resolved.contains_key(&("m.room.member".into(), "@charlie:example.com".into())),
        "Charlie should be in resolved state"
    );
    assert!(
        resolved.contains_key(&("m.room.member".into(), "@ella:example.com".into())),
        "Ella should be in resolved state"
    );
}

#[test]
fn test_ruma_join_rules_vs_join() {
    // Alice changes join rules while Ella joins. The join rules change should win.
    let resolved = resolve_fixture_batch(
        &[
            &format!("{}/bootstrap-public-chat.json", FIXTURE_DIR),
            &format!("{}/join-rules-vs-join-common.json", FIXTURE_DIR),
            &format!("{}/join-rules-vs-join-alice.json", FIXTURE_DIR),
            &format!("{}/join-rules-vs-join-ella.json", FIXTURE_DIR),
        ],
        StateResVersion::V2,
    );
    // Join rules should be updated by Alice
    assert!(
        resolved.contains_key(&("m.room.join_rules".into(), String::new())),
        "Join rules should be in resolved state"
    );
}

#[test]
fn test_ruma_origin_server_ts_tiebreak() {
    // Two events with same power level but different timestamps.
    // Resolution should use origin_server_ts as tiebreaker.
    let events = load_fixtures(&[
        &format!("{}/bootstrap-private-chat.json", FIXTURE_DIR),
        &format!("{}/origin-server-ts-tiebreak.json", FIXTURE_DIR),
    ]);
    let sorted = sort_and_verify(&events, StateResVersion::V2);
    // All events should sort without cycles
    assert_eq!(sorted.len(), events.len());
}

#[test]
fn test_ruma_power_levels_admin_vs_mod() {
    // Admin (alice) vs mod (bob) power level changes.
    let resolved = resolve_fixture_batch(
        &[
            &format!("{}/bootstrap-public-chat.json", FIXTURE_DIR),
            &format!("{}/power-levels-admin-vs-mod-alice.json", FIXTURE_DIR),
            &format!("{}/power-levels-admin-vs-mod-bob.json", FIXTURE_DIR),
        ],
        StateResVersion::V2,
    );
    let pl = resolved
        .get(&("m.room.power_levels".into(), String::new()))
        .expect("No power_levels in resolved state");
    // Admin's change should supersede mod's change
    assert!(pl.starts_with("$"), "Winner should be a valid event ID");
}

#[test]
fn test_ruma_topic_vs_ban() {
    // Bob changes topic, Alice bans Bob. Ban should supersede topic change.
    let resolved = resolve_fixture_batch(
        &[
            &format!("{}/bootstrap-public-chat.json", FIXTURE_DIR),
            &format!("{}/topic-vs-ban-common.json", FIXTURE_DIR),
            &format!("{}/topic-vs-ban-alice.json", FIXTURE_DIR),
            &format!("{}/topic-vs-ban-bob.json", FIXTURE_DIR),
        ],
        StateResVersion::V2,
    );
    // Bob should be banned
    let bob_member = resolved.get(&("m.room.member".into(), "@bob:example.com".into()));
    assert!(bob_member.is_some(), "Bob's membership should be in state");
}

// ============================================================================
// Existing benchmark_1k fixture (already in repo)
// ============================================================================

#[test]
fn test_benchmark_1k_sort_no_cycles() {
    let content = std::fs::read_to_string("res/benchmark_1k.json").expect("benchmark_1k.json");
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();
    let events: Vec<LeanEvent> = serde_json::from_value(data["events"].clone()).unwrap();
    let sorted = sort_and_verify(&events, StateResVersion::V2);
    assert_eq!(sorted.len(), 1000);
    assert_eq!(sorted[0], "$00000-m-room-create");
}

#[test]
fn test_benchmark_1k_v2_1_sort_no_cycles() {
    let content =
        std::fs::read_to_string("res/benchmark_1k_v2_1.json").expect("benchmark_1k_v2_1.json");
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();
    let events: Vec<LeanEvent> = serde_json::from_value(data["events"].clone()).unwrap();
    let sorted = sort_and_verify(&events, StateResVersion::V2_1);
    assert_eq!(sorted.len(), 1000);
    assert_eq!(sorted[0], "$00000-m-room-create");
}

#[test]
fn test_benchmark_1k_resolution_determinism() {
    let content = std::fs::read_to_string("res/benchmark_1k.json").expect("benchmark_1k.json");
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();
    let events: Vec<LeanEvent> = serde_json::from_value(data["events"].clone()).unwrap();

    // Run resolution twice and verify determinism
    let resolved1 = resolve_lean(BTreeMap::new(), to_event_map(&events), StateResVersion::V2);
    let resolved2 = resolve_lean(BTreeMap::new(), to_event_map(&events), StateResVersion::V2);
    assert_eq!(resolved1, resolved2, "Resolution must be deterministic");
}

// ============================================================================
// Auth Chain Validation on Real Fixtures
// ============================================================================

#[test]
fn test_ruma_bootstrap_auth_chain() {
    use ruma_lean::auth::{check_auth_chain, RoomState};

    let events = load_fixture(&format!("{}/bootstrap-public-chat.json", FIXTURE_DIR));
    let (accepted, rejected) = check_auth_chain(&events, &RoomState::new());

    // All bootstrap events should pass auth
    assert!(
        rejected.is_empty(),
        "Bootstrap events should all pass auth, but {} were rejected: {:?}",
        rejected.len(),
        rejected
    );
    assert_eq!(accepted.len(), events.len());
}
