#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// Quick scratch test - run from ruma-lean root
use rezzy::auth::{check_auth, RoomState};
use rezzy::{LeanEvent, StateResVersion};
use serde_json::json;

#[test]
fn test_tombstone_auth() {
    let create = LeanEvent::<String> {
        event_id: "$create".into(),
        event_type: "m.room.create".into(),
        state_key: Some(String::new()),
        sender: "@alice:hs1".into(),
        content: json!({"room_version": "11", "creator": "@alice:hs1"}),
        ..Default::default()
    };

    let join = LeanEvent::<String> {
        event_id: "$join".into(),
        event_type: "m.room.member".into(),
        state_key: Some("@alice:hs1".into()),
        sender: "@alice:hs1".into(),
        content: json!({"membership": "join"}),
        auth_events: vec!["$create".into()],
        ..Default::default()
    };

    let pl = LeanEvent::<String> {
        event_id: "$pl".into(),
        event_type: "m.room.power_levels".into(),
        state_key: Some(String::new()),
        sender: "@alice:hs1".into(),
        content: json!({
            "users": {"@alice:hs1": 100},
            "users_default": 0,
            "events_default": 0,
            "state_default": 50,
            "ban": 50, "kick": 50, "invite": 0, "redact": 50
        }),
        auth_events: vec!["$create".into(), "$join".into()],
        ..Default::default()
    };

    let tombstone = LeanEvent::<String> {
        event_id: "$tombstone".into(),
        event_type: "m.room.tombstone".into(),
        state_key: Some(String::new()),
        sender: "@alice:hs1".into(),
        content: json!({"body": "replaced", "replacement_room": "!new:hs1"}),
        prev_events: vec!["$pl".into()],
        auth_events: vec!["$create".into(), "$join".into(), "$pl".into()],
        ..Default::default()
    };

    let mut state = RoomState::new();
    state.insert(("m.room.create".into(), String::new()), create);
    state.insert(("m.room.member".into(), "@alice:hs1".into()), join);
    state.insert(("m.room.power_levels".into(), String::new()), pl);

    let r1 = check_auth(&tombstone, &state, StateResVersion::V2, None);
    println!("V2:     {r1:?}");

    let r2 = check_auth(&tombstone, &state, StateResVersion::V2_1, None);
    println!("V2_1:   {r2:?}");

    let r3 = check_auth(&tombstone, &state, StateResVersion::V2_1_1, None);
    println!("V2_1_1: {r3:?}");
}
