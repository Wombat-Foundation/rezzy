//! Lattice-coordinatized state resolution tests.
//!
//! Tests the LUB comparator, `route_power_events`, and `resolve_lattice_fold`.

mod utils;

use rezzy::resolve::lattice::{is_lattice_winner_better, resolve_lattice_fold, route_power_events};
use rezzy::{LeanEvent, StateResVersion};
use std::collections::HashMap;

const FIXTURE: &str = r#"
{"event_id":"$create","type":"m.room.create","state_key":"","sender":"@alice:a.com","depth":0,"origin_server_ts":1000,"content":{"creator":"@alice:a.com","room_version":"11"},"prev_events":[],"auth_events":[]}
{"event_id":"$alice_join","type":"m.room.member","state_key":"@alice:a.com","sender":"@alice:a.com","depth":1,"origin_server_ts":1001,"content":{"membership":"join"},"prev_events":["$create"],"auth_events":["$create"]}
{"event_id":"$pl","type":"m.room.power_levels","state_key":"","sender":"@alice:a.com","depth":2,"origin_server_ts":1002,"content":{"users":{"@alice:a.com":100},"events_default":0,"state_default":50,"ban":50,"kick":50,"invite":0},"prev_events":["$alice_join"],"auth_events":["$create","$alice_join"]}
{"event_id":"$jr","type":"m.room.join_rules","state_key":"","sender":"@alice:a.com","depth":3,"origin_server_ts":1003,"content":{"join_rule":"public"},"prev_events":["$pl"],"auth_events":["$create","$alice_join","$pl"]}
{"event_id":"$topic_a","type":"m.room.topic","state_key":"","sender":"@alice:a.com","depth":4,"origin_server_ts":2000,"content":{"topic":"Alice topic"},"prev_events":["$jr"],"auth_events":["$create","$alice_join","$pl"]}
{"event_id":"$topic_b","type":"m.room.topic","state_key":"","sender":"@alice:a.com","depth":4,"origin_server_ts":3000,"content":{"topic":"Later topic"},"prev_events":["$jr"],"auth_events":["$create","$alice_join","$pl"]}
"#;

fn to_event_map(events: &[LeanEvent]) -> HashMap<String, LeanEvent> {
    events
        .iter()
        .map(|e| (e.event_id.clone(), e.clone()))
        .collect()
}

// ============================================================================
// LUB comparator unit tests
// ============================================================================

fn ev(id: &str, ts: u64) -> LeanEvent {
    LeanEvent {
        event_id: id.to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@user:x".to_string()),
        origin_server_ts: ts,
        sender: "@s:x".to_string(),
        depth: 1,
        ..Default::default()
    }
}

#[test]
fn test_lub_mainline_closer_wins() {
    let a = ev("$a", 100);
    let b = ev("$b", 200);
    let mut dists = HashMap::new();
    dists.insert("$a".to_string(), 1usize);
    dists.insert("$b".to_string(), 5usize);
    assert!(is_lattice_winner_better(&a, &b, &dists, 10));
    assert!(!is_lattice_winner_better(&b, &a, &dists, 10));
}

#[test]
fn test_lub_mainline_tie_ts_wins() {
    let a = ev("$a", 300);
    let b = ev("$b", 100);
    let mut dists = HashMap::new();
    dists.insert("$a".to_string(), 3usize);
    dists.insert("$b".to_string(), 3usize);
    assert!(is_lattice_winner_better(&a, &b, &dists, 10));
    assert!(!is_lattice_winner_better(&b, &a, &dists, 10));
}

#[test]
fn test_lub_full_tie_event_id_tiebreak() {
    let a = ev("$z_big", 100);
    let b = ev("$a_small", 100);
    let dists: HashMap<String, usize> = HashMap::new();
    assert!(is_lattice_winner_better(&a, &b, &dists, 10));
    assert!(!is_lattice_winner_better(&b, &a, &dists, 10));
}

#[test]
fn test_lub_missing_mainline_defaults_to_len() {
    let a = ev("$a", 100);
    let b = ev("$b", 100);
    let mut dists = HashMap::new();
    dists.insert("$a".to_string(), 2usize);
    // $b missing → defaults to mainline_len (10)
    assert!(is_lattice_winner_better(&a, &b, &dists, 10));
}

// ============================================================================
// route_power_events
// ============================================================================

#[test]
fn test_route_power_events_classification() {
    let events = utils::parse_jsonl_events(FIXTURE);
    let map = to_event_map(&events);

    let mut power = HashMap::new();
    let mut non_power = HashMap::new();
    route_power_events(&map, &mut power, &mut non_power, StateResVersion::V2);

    // create, PL, join_rules, and member events are power events
    assert!(power.contains_key("$create"));
    assert!(power.contains_key("$pl"));
    assert!(power.contains_key("$jr"));
    assert!(power.contains_key("$alice_join"));
    // topics are non-power
    assert!(non_power.contains_key("$topic_a"));
    assert!(non_power.contains_key("$topic_b"));
}

// ============================================================================
// resolve_lattice_fold (end-to-end)
// ============================================================================

#[test]
fn test_lattice_fold_resolves_conflicting_topics() {
    let events = utils::parse_jsonl_events(FIXTURE);
    let map = to_event_map(&events);

    // Build unconflicted state (everything except the conflicting topics)
    let unconflicted = utils::build_unconflicted_state_test_helper(&map);

    // Conflicted events: the two topics
    let mut conflicted = HashMap::new();
    conflicted.insert("$topic_a".to_string(), map["$topic_a"].clone());
    conflicted.insert("$topic_b".to_string(), map["$topic_b"].clone());

    let resolved = resolve_lattice_fold(unconflicted, conflicted, &map, StateResVersion::V2);

    // The topic with later timestamp ($topic_b, ts=3000) should win
    let topic_key = ("m.room.topic".to_string(), String::new());
    assert_eq!(
        resolved.get(&topic_key),
        Some(&"$topic_b".to_string()),
        "Lattice fold should pick topic_b (later ts)"
    );
}

#[test]
fn test_lattice_fold_parity_with_iterative() {
    let events = utils::parse_jsonl_events(FIXTURE);
    let map = to_event_map(&events);

    let unconflicted = utils::build_unconflicted_state_test_helper(&map);

    let mut conflicted = HashMap::new();
    conflicted.insert("$topic_a".to_string(), map["$topic_a"].clone());
    conflicted.insert("$topic_b".to_string(), map["$topic_b"].clone());

    let lattice = resolve_lattice_fold(
        unconflicted.clone(),
        conflicted.clone(),
        &map,
        StateResVersion::V2,
    );
    let iterative = rezzy::resolve_iterative_sort(
        unconflicted,
        conflicted,
        &map,
        StateResVersion::V2,
        &mut std::collections::HashMap::new(),
    );

    // Lattice and iterative should agree on the topic winner
    let topic_key = ("m.room.topic".to_string(), String::new());
    assert_eq!(
        lattice.get(&topic_key),
        iterative.get(&topic_key),
        "Lattice fold must agree with iterative sort"
    );
}

#[test]
fn test_lattice_fold_deterministic() {
    let events = utils::parse_jsonl_events(FIXTURE);
    let map = to_event_map(&events);
    let unconflicted = utils::build_unconflicted_state_test_helper(&map);

    let mut conflicted = HashMap::new();
    conflicted.insert("$topic_a".to_string(), map["$topic_a"].clone());
    conflicted.insert("$topic_b".to_string(), map["$topic_b"].clone());

    let r1 = resolve_lattice_fold(
        unconflicted.clone(),
        conflicted.clone(),
        &map,
        StateResVersion::V2,
    );
    let r2 = resolve_lattice_fold(unconflicted, conflicted, &map, StateResVersion::V2);
    assert_eq!(r1, r2, "Lattice fold must be deterministic");
}

/// Coverage: `fold_lattice_chunk` skips events with `state_key: None`
/// (lattice.rs:160-162). Non-state events (e.g. messages) that end up
/// in the conflicted set should be silently ignored during the fold.
#[test]
fn test_lattice_fold_skips_non_state_events() {
    // Base fixture plus a non-state event (message with no state_key)
    let fixture = r#"
{"event_id":"$create","type":"m.room.create","state_key":"","sender":"@alice:a.com","depth":0,"origin_server_ts":1000,"content":{"creator":"@alice:a.com","room_version":"11"},"prev_events":[],"auth_events":[]}
{"event_id":"$alice_join","type":"m.room.member","state_key":"@alice:a.com","sender":"@alice:a.com","depth":1,"origin_server_ts":1001,"content":{"membership":"join"},"prev_events":["$create"],"auth_events":["$create"]}
{"event_id":"$pl","type":"m.room.power_levels","state_key":"","sender":"@alice:a.com","depth":2,"origin_server_ts":1002,"content":{"users":{"@alice:a.com":100},"events_default":0,"state_default":50,"ban":50,"kick":50,"invite":0},"prev_events":["$alice_join"],"auth_events":["$create","$alice_join"]}
{"event_id":"$jr","type":"m.room.join_rules","state_key":"","sender":"@alice:a.com","depth":3,"origin_server_ts":1003,"content":{"join_rule":"public"},"prev_events":["$pl"],"auth_events":["$create","$alice_join","$pl"]}
{"event_id":"$topic_a","type":"m.room.topic","state_key":"","sender":"@alice:a.com","depth":4,"origin_server_ts":2000,"content":{"topic":"Alice topic"},"prev_events":["$jr"],"auth_events":["$create","$alice_join","$pl"]}
{"event_id":"$topic_b","type":"m.room.topic","state_key":"","sender":"@alice:a.com","depth":4,"origin_server_ts":3000,"content":{"topic":"Later topic"},"prev_events":["$jr"],"auth_events":["$create","$alice_join","$pl"]}
{"event_id":"$msg","type":"m.room.message","sender":"@alice:a.com","depth":4,"origin_server_ts":2500,"content":{"body":"hello"},"prev_events":["$jr"],"auth_events":["$create","$alice_join","$pl"]}
"#;
    let events = utils::parse_jsonl_events(fixture);
    let map = to_event_map(&events);

    let unconflicted = utils::build_unconflicted_state_test_helper(&map);

    // Include the message (state_key: None) in the conflicted set
    let mut conflicted = HashMap::new();
    conflicted.insert("$topic_a".to_string(), map["$topic_a"].clone());
    conflicted.insert("$topic_b".to_string(), map["$topic_b"].clone());
    conflicted.insert("$msg".to_string(), map["$msg"].clone());

    let resolved = resolve_lattice_fold(unconflicted, conflicted, &map, StateResVersion::V2);

    // topic_b wins (later ts), message is silently skipped
    let topic_key = ("m.room.topic".to_string(), String::new());
    assert_eq!(
        resolved.get(&topic_key),
        Some(&"$topic_b".to_string()),
        "topic_b should win"
    );
    // No (m.room.message, _) key should appear — it has no state_key
    assert!(
        !resolved.iter().any(|((t, _), _)| t == "m.room.message"),
        "message event must not appear in resolved state"
    );
}

#[test]
fn test_lattice_fold_unconflicted_power_bootstrap_v2_1() {
    let events = utils::parse_jsonl_events(FIXTURE);
    let map = to_event_map(&events);

    // Build unconflicted state (starts with m.room.create)
    let mut unconflicted = utils::build_unconflicted_state_test_helper(&map);
    // Manually add unconflicted power levels and join rules to unconflicted input state
    unconflicted.insert(
        ("m.room.power_levels".to_string(), String::new()),
        "$pl".to_string(),
    );
    unconflicted.insert(
        ("m.room.join_rules".to_string(), String::new()),
        "$jr".to_string(),
    );

    // Conflicted events: the two topics
    let mut conflicted = HashMap::new();
    conflicted.insert("$topic_a".to_string(), map["$topic_a"].clone());
    conflicted.insert("$topic_b".to_string(), map["$topic_b"].clone());

    // Resolve with V2_1: resolve_lattice_fold delegates to resolve_iterative_sort for V2.1+.
    // This exercises the iterative fallback path, not the lattice fold's merge logic.
    let resolved = resolve_lattice_fold(unconflicted, conflicted, &map, StateResVersion::V2_1);

    let topic_key = ("m.room.topic".to_string(), String::new());
    assert_eq!(
        resolved.get(&topic_key),
        Some(&"$topic_b".to_string()),
        "Lattice fold V2.1 should pick topic_b (later ts)"
    );

    // Verify unconflicted power levels, join rules, and create events are successfully resolved and present
    assert_eq!(
        resolved.get(&("m.room.power_levels".to_string(), String::new())),
        Some(&"$pl".to_string())
    );
    assert_eq!(
        resolved.get(&("m.room.join_rules".to_string(), String::new())),
        Some(&"$jr".to_string())
    );
    assert_eq!(
        resolved.get(&("m.room.create".to_string(), String::new())),
        Some(&"$create".to_string())
    );
}

#[test]
fn test_msc4297_lattice_fold_dependency_v2_1_fallback() {
    let events = utils::parse_jsonl_events(
        r#"
{"event_id":"$create","type":"m.room.create","state_key":"","sender":"@admin:x","depth":0,"origin_server_ts":1000,"content":{"creator":"@admin:x","room_version":"11"},"prev_events":[],"auth_events":[]}
{"event_id":"$pl","type":"m.room.power_levels","state_key":"","sender":"@admin:x","depth":1,"origin_server_ts":1001,"content":{"users":{"@admin:x":100},"events_default":0,"state_default":0,"ban":50,"kick":50,"invite":0},"prev_events":["$create"],"auth_events":["$create"]}
{"event_id":"$jr","type":"m.room.join_rules","state_key":"","sender":"@admin:x","depth":2,"origin_server_ts":1002,"content":{"join_rule":"public"},"prev_events":["$pl"],"auth_events":["$create","$pl"]}
{"event_id":"$alice_join","type":"m.room.member","state_key":"@alice:x","sender":"@alice:x","depth":3,"origin_server_ts":1003,"content":{"membership":"join"},"prev_events":["$jr"],"auth_events":["$create","$pl","$jr"]}
{"event_id":"$alice_topic","type":"m.room.topic","state_key":"","sender":"@alice:x","depth":4,"origin_server_ts":1004,"content":{"topic":"Alice Topic"},"prev_events":["$alice_join"],"auth_events":["$create","$pl","$alice_join"]}
"#,
    );

    let map = to_event_map(&events);

    // Build unconflicted state: has $create, $pl, $jr
    let mut unconflicted = utils::build_unconflicted_state_test_helper(&map);
    unconflicted.insert(
        ("m.room.power_levels".to_string(), String::new()),
        "$pl".to_string(),
    );
    unconflicted.insert(
        ("m.room.join_rules".to_string(), String::new()),
        "$jr".to_string(),
    );

    // Conflicted events: $alice_join and $alice_topic are on one fork
    let mut conflicted = HashMap::new();
    conflicted.insert("$alice_join".to_string(), map["$alice_join"].clone());
    conflicted.insert("$alice_topic".to_string(), map["$alice_topic"].clone());

    // Resolve under V2.1. The fallback automatically redirects to resolve_iterative_sort,
    // which correctly respects the topological non-power dependency!
    let resolved = resolve_lattice_fold(unconflicted, conflicted, &map, StateResVersion::V2_1);

    // Verify that the topic is successfully authorized and present!
    let topic_key = ("m.room.topic".to_string(), String::new());
    assert_eq!(
        resolved.get(&topic_key),
        Some(&"$alice_topic".to_string()),
        "V2.1 fallback must authorize and resolve Alice's topic change successfully"
    );
}
