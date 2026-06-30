mod utils;

#[test]
fn test_jsonl_parser_utility() {
    let state = utils::parse_jsonl_state(
        r#"
        // This is a comment
        {"event_id": "$c", "type": "m.room.create", "state_key": "", "sender": "@alice:matrix.org", "content": {"creator": "@alice:matrix.org"}}
        {"event_id": "$pl", "type": "m.room.power_levels", "state_key": "", "sender": "@alice:matrix.org", "content": {"users": {"@alice:matrix.org": 100}, "invite": 50}}
        {"event_id": "$b", "type": "m.room.member", "state_key": "@bob:matrix.org", "sender": "@bob:matrix.org", "content": {"membership": "join"}}
    "#,
    );

    assert_eq!(state.len(), 3);
    let pl_event = &state[&("m.room.power_levels".to_string(), String::new())];
    assert_eq!(pl_event.event_id, "$pl");
    assert_eq!(pl_event.sender, "@alice:matrix.org");

    let events = utils::parse_jsonl_events(
        r#"
        {"event_id": "$msg", "type": "m.room.message", "sender": "@bob:matrix.org", "content": {"body": "hello"}}
    "#,
    );
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "m.room.message");
    assert_eq!(events[0].state_key, None);
}

#[test]
fn test_jsonl_asserters() {
    let state = utils::parse_jsonl_state(
        r#"
        {"event_id": "$c", "type": "m.room.create", "state_key": "", "sender": "@alice:matrix.org"}
        {"event_id": "$pl", "type": "m.room.power_levels", "state_key": "", "sender": "@alice:matrix.org"}
    "#,
    );

    // This should pass
    utils::assert_jsonl_state_eq(
        &state,
        r#"
        {"event_id": "$c", "type": "m.room.create", "state_key": "", "sender": "@alice:matrix.org"}
        {"event_id": "$pl", "type": "m.room.power_levels", "state_key": "", "sender": "@alice:matrix.org"}
    "#,
    );

    let events = utils::parse_jsonl_events(
        r#"
        {"event_id": "$msg1", "type": "m.room.message", "sender": "@alice:matrix.org"}
        {"event_id": "$msg2", "type": "m.room.message", "sender": "@bob:matrix.org"}
    "#,
    );

    // This should pass
    utils::assert_jsonl_events_eq(
        &events,
        r#"
        {"event_id": "$msg1", "type": "m.room.message", "sender": "@alice:matrix.org"}
        {"event_id": "$msg2", "type": "m.room.message", "sender": "@bob:matrix.org"}
    "#,
    );
}

#[test]
fn test_compute_local_naive_topological_depth() {
    let mut events = utils::parse_jsonl_events(
        r#"
        {"event_id": "$1", "type": "m.room.create", "sender": "@a:x", "prev_events": []}
        {"event_id": "$2", "type": "m.room.message", "sender": "@a:x", "prev_events": ["$1"]}
        {"event_id": "$3", "type": "m.room.message", "sender": "@a:x", "prev_events": ["$2"]}
        {"event_id": "$4", "type": "m.room.message", "sender": "@a:x", "prev_events": ["$1"]}
        {"event_id": "$5", "type": "m.room.message", "sender": "@a:x", "prev_events": ["$3", "$4"]}
        "#,
    );

    utils::compute_local_naive_topological_depth(&mut events);

    assert_eq!(events[0].depth, 1);
    assert_eq!(events[1].depth, 2);
    assert_eq!(events[2].depth, 3);
    assert_eq!(events[3].depth, 2);
    assert_eq!(events[4].depth, 4); // max(3, 2) + 1 = 4
}
