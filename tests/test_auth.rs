mod utils;
use rezzy::auth::*;
use rezzy::basespec::event_types::M_ROOM_CREATE;
use rezzy::*;
use serde_json::json;

fn make_event(
    id: &str,
    event_type: &str,
    state_key: Option<&str>,
    sender: &str,
    content: serde_json::Value,
) -> LeanEvent {
    LeanEvent {
        event_id: id.into(),
        event_type: event_type.into(),
        state_key: state_key.map(std::convert::Into::into),
        sender: sender.into(),
        content,
        ..Default::default()
    }
}

#[test]
fn test_self_ban_rejected() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$create",
            M_ROOM_CREATE,
            Some(""),
            "@alice:example.com",
            json!({}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@alice:example.com".into()),
        make_event(
            "$join",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
        ),
    );
    let self_ban = make_event(
        "$selfban",
        "m.room.member",
        Some("@alice:example.com"),
        "@alice:example.com",
        json!({"membership": "ban"}),
    );
    assert!(
        check_auth(
            &self_ban,
            &state,
            rezzy::basespec::rezzy_types::StateResVersion::V2_1,
            None
        )
        .is_err(),
        "Self-bans must be rejected"
    );
}

#[test]
fn test_flagged_events_are_not_auth_checked() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$create",
            M_ROOM_CREATE,
            Some(""),
            "@alice:example.com",
            json!({}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@alice:example.com".into()),
        make_event(
            "$join",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
        ),
    );

    let mut rejected = make_event(
        "$rejected",
        "m.room.message",
        None,
        "@alice:example.com",
        json!({"body": "hello"}),
    );
    rejected.rejected = true;

    let mut soft_fail = make_event(
        "$soft_fail",
        "m.room.message",
        None,
        "@alice:example.com",
        json!({"body": "hello"}),
    );
    soft_fail.soft_fail = true;

    for event in [&rejected, &soft_fail] {
        assert!(
            matches!(
                check_auth(event, &state, StateResVersion::V2_1, None),
                Err(AuthError::InvalidSyntax(reason)) if reason.contains("rejected or soft-failed")
            ),
            "flagged events must not be auth-checked"
        );
    }
}

#[test]
fn test_flagged_auth_state_is_not_used() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$create",
            M_ROOM_CREATE,
            Some(""),
            "@alice:example.com",
            json!({}),
        ),
    );

    let mut flagged_join = make_event(
        "$join",
        "m.room.member",
        Some("@alice:example.com"),
        "@alice:example.com",
        json!({"membership": "join"}),
    );
    flagged_join.rejected = true;
    state.insert(
        ("m.room.member".into(), "@alice:example.com".into()),
        flagged_join,
    );

    let event = make_event(
        "$msg",
        "m.room.message",
        None,
        "@alice:example.com",
        json!({"body": "hello"}),
    );

    assert!(
        matches!(
            check_auth(&event, &state, StateResVersion::V2_1, None),
            Err(AuthError::InvalidSyntax(reason)) if reason.contains("auth state event")
        ),
        "flagged auth state must not authorize later events"
    );
}

#[test]
fn test_flagged_join_rules_do_not_block_unrelated_events() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$create",
            M_ROOM_CREATE,
            Some(""),
            "@alice:example.com",
            json!({}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@alice:example.com".into()),
        make_event(
            "$join",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
        ),
    );

    let mut flagged_join_rules = make_event(
        "$join_rules",
        "m.room.join_rules",
        Some(""),
        "@alice:example.com",
        json!({"join_rule": "invite"}),
    );
    flagged_join_rules.rejected = true;
    state.insert(
        ("m.room.join_rules".into(), String::new()),
        flagged_join_rules,
    );

    let event = make_event(
        "$msg",
        "m.room.message",
        None,
        "@alice:example.com",
        json!({"body": "hello"}),
    );

    assert!(
        check_auth(&event, &state, StateResVersion::V2_1, None).is_ok(),
        "unrelated events must not fail just because unused join_rules state is flagged"
    );
}

#[test]
fn test_invite_banned_user_rejected() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@alice:example.com",
            json!({}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@alice:example.com".into()),
        make_event(
            "$j",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@bob:example.com".into()),
        make_event(
            "$ban",
            "m.room.member",
            Some("@bob:example.com"),
            "@alice:example.com",
            json!({"membership": "ban"}),
        ),
    );
    let invite_banned = make_event(
        "$invite_banned",
        "m.room.member",
        Some("@bob:example.com"),
        "@alice:example.com",
        json!({"membership": "invite"}),
    );
    assert!(
        matches!(
            check_auth(&invite_banned, &state, rezzy::StateResVersion::V2_1, None),
            Err(AuthError::BannedUser { .. })
        ),
        "Inviting a banned user must fail with BannedUser error"
    );
}

#[test]
fn test_invite_insufficient_power_level() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@admin:x.com",
            json!({"invite": 75, "users": {"@low:x.com": 10}}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@low:x.com".into()),
        make_event(
            "$j",
            "m.room.member",
            Some("@low:x.com"),
            "@low:x.com",
            json!({"membership": "join"}),
        ),
    );
    let invite = make_event(
        "$invite",
        "m.room.member",
        Some("@target:x.com"),
        "@low:x.com",
        json!({"membership": "invite"}),
    );
    assert!(
        matches!(
            check_auth(&invite, &state, rezzy::StateResVersion::V2_1, None),
            Err(AuthError::InsufficientPowerLevel { .. })
        ),
        "Invite with PL 10 < invite PL 75 must fail"
    );
}

#[test]
fn test_self_invite_rejected() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@alice:x.com", json!({})),
    );
    state.insert(
        ("m.room.member".into(), "@alice:x.com".into()),
        make_event(
            "$j",
            "m.room.member",
            Some("@alice:x.com"),
            "@alice:x.com",
            json!({"membership": "join"}),
        ),
    );
    let self_invite = make_event(
        "$self_invite",
        "m.room.member",
        Some("@alice:x.com"),
        "@alice:x.com",
        json!({"membership": "invite"}),
    );
    assert!(
        matches!(
            check_auth(&self_invite, &state, rezzy::StateResVersion::V2_1, None),
            Err(AuthError::InvalidStateKey { .. })
        ),
        "Self-invites must be rejected with InvalidStateKey error"
    );
}

#[test]
fn test_join_banned_user_rejected() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.join_rules".into(), String::new()),
        make_event(
            "$jr",
            "m.room.join_rules",
            Some(""),
            "@admin:x.com",
            json!({"join_rule": "public"}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@banned:x.com".into()),
        make_event(
            "$ban",
            "m.room.member",
            Some("@banned:x.com"),
            "@admin:x.com",
            json!({"membership": "ban"}),
        ),
    );
    let join_attempt = make_event(
        "$join",
        "m.room.member",
        Some("@banned:x.com"),
        "@banned:x.com",
        json!({"membership": "join"}),
    );
    assert!(
        matches!(
            check_auth(&join_attempt, &state, rezzy::StateResVersion::V2_1, None),
            Err(AuthError::BannedUser { .. })
        ),
        "Banned user joining must fail"
    );
}

#[test]
fn test_public_room_join_allowed() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.join_rules".into(), String::new()),
        make_event(
            "$jr",
            "m.room.join_rules",
            Some(""),
            "@admin:x.com",
            json!({"join_rule": "public"}),
        ),
    );
    let join = make_event(
        "$join",
        "m.room.member",
        Some("@newcomer:x.com"),
        "@newcomer:x.com",
        json!({"membership": "join"}),
    );
    assert!(
        check_auth(
            &join,
            &state,
            rezzy::basespec::rezzy_types::StateResVersion::V2_1,
            None
        )
        .is_ok(),
        "Public room join must succeed"
    );
}

#[test]
fn test_member_pl_hierarchy_enforcement() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@admin:x.com",
            json!({"kick": 50, "users": {"@mod:x.com": 50, "@target:x.com": 50}}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@mod:x.com".into()),
        make_event(
            "$j1",
            "m.room.member",
            Some("@mod:x.com"),
            "@mod:x.com",
            json!({"membership": "join"}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@target:x.com".into()),
        make_event(
            "$j2",
            "m.room.member",
            Some("@target:x.com"),
            "@target:x.com",
            json!({"membership": "join"}),
        ),
    );

    // PL 50 trying to kick PL 50 target → must fail (needs PL > target)
    let kick = make_event(
        "$kick",
        "m.room.member",
        Some("@target:x.com"),
        "@mod:x.com",
        json!({"membership": "leave"}),
    );
    assert!(
        check_auth(
            &kick,
            &state,
            rezzy::basespec::rezzy_types::StateResVersion::V2_1,
            None
        )
        .is_err(),
        "Equal PL kick must fail"
    );
}

#[test]
fn test_auth_error_display_variants() {
    let err: AuthError<String> = AuthError::InsufficientPowerLevel {
        required: 50,
        actual: 10,
        event_type: "m.room.topic".into(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("10"));
    assert!(msg.contains("50"));
    assert!(msg.contains("m.room.topic"));

    let err2: AuthError<String> = AuthError::InvalidStateKey {
        expected: "@alice:x.com".into(),
        actual: "@bob:x.com".into(),
    };
    let msg2 = format!("{err2}");
    assert!(msg2.contains("@alice"));
    assert!(msg2.contains("@bob"));

    let err3: AuthError<String> = AuthError::NotMember {
        sender: "@charlie:x.com".into(),
        event_id: "$event123".into(),
    };
    let msg3 = format!("{err3}");
    assert!(msg3.contains("@charlie"));

    let err4: AuthError<String> = AuthError::BannedUser {
        sender: "@dave:x.com".into(),
        event_id: "$event456".into(),
    };
    let msg4 = format!("{err4}");
    assert!(msg4.contains("@dave"));

    let err5: AuthError<String> = AuthError::MissingAuthEvent("$event123".into());
    let msg5 = format!("{err5}");
    assert!(msg5.contains("$event123"));

    let err6: AuthError<String> = AuthError::CreateWithPrevEvents;
    let msg6 = format!("{err6}");
    assert!(msg6.contains("m.room.create"));

    let err7: AuthError<String> = AuthError::InvalidSyntax("bad json".into());
    let msg7 = format!("{err7}");
    assert!(msg7.contains("bad json"));

    let err8: AuthError<String> = AuthError::MissingCreate;
    let msg8 = format!("{err8}");
    assert!(msg8.contains("m.room.create"));
}

#[test]
fn test_create_event_no_prev_events() {
    let create = make_event(
        "$create",
        "m.room.create",
        Some(""),
        "@alice:example.com",
        json!({}),
    );
    let state: RoomState = RoomState::new();
    assert!(check_auth(
        &create,
        &state,
        rezzy::basespec::rezzy_types::StateResVersion::V2_1,
        None
    )
    .is_ok());
}

#[test]
fn test_create_event_with_prev_events() {
    let mut create = make_event(
        "$create",
        "m.room.create",
        Some(""),
        "@alice:example.com",
        json!({}),
    );
    create.prev_events = vec!["$other".into()];
    let state: RoomState = RoomState::new();
    assert_eq!(
        check_auth(
            &create,
            &state,
            rezzy::basespec::rezzy_types::StateResVersion::V2_1,
            None
        ),
        Err(AuthError::CreateWithPrevEvents)
    );
}

#[test]
fn test_non_member_rejection() {
    let msg = make_event(
        "$msg",
        "m.room.message",
        None,
        "@bob:example.com",
        json!({}),
    );
    let state: RoomState = RoomState::new();
    assert!(matches!(
        check_auth(&msg, &state, rezzy::StateResVersion::V2_1, None),
        Err(AuthError::NotMember { .. })
    ));
}

#[test]
fn test_joined_member_can_send() {
    let msg = make_event(
        "$msg",
        "m.room.message",
        None,
        "@alice:example.com",
        json!({}),
    );
    let mut state = RoomState::new();
    state.insert(
        ("m.room.member".into(), "@alice:example.com".into()),
        make_event(
            "$join",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
        ),
    );
    assert!(check_auth(
        &msg,
        &state,
        rezzy::basespec::rezzy_types::StateResVersion::V2_1,
        None
    )
    .is_ok());
}

#[test]
fn test_banned_user_rejected() {
    let msg = make_event(
        "$msg",
        "m.room.message",
        None,
        "@alice:example.com",
        json!({}),
    );
    let mut state = RoomState::new();
    state.insert(
        ("m.room.member".into(), "@alice:example.com".into()),
        make_event(
            "$ban",
            "m.room.member",
            Some("@alice:example.com"),
            "@admin:example.com",
            json!({"membership": "ban"}),
        ),
    );
    assert!(matches!(
        check_auth(&msg, &state, rezzy::StateResVersion::V2_1, None),
        Err(AuthError::BannedUser { .. })
    ));
}

#[test]
fn test_insufficient_power_level() {
    let msg = make_event(
        "$msg",
        "m.room.power_levels",
        Some(""),
        "@alice:example.com",
        json!({}),
    );
    let mut state = RoomState::new();
    state.insert(
        ("m.room.member".into(), "@alice:example.com".into()),
        make_event(
            "$join",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
        ),
    );
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@admin:example.com",
            json!({"state_default": 50, "users": {"@admin:example.com": 100}}),
        ),
    );
    assert!(matches!(
        check_auth(&msg, &state, rezzy::StateResVersion::V2_1, None),
        Err(AuthError::InsufficientPowerLevel { .. })
    ));
}

#[test]
fn test_join_self_only() {
    let join = make_event(
        "$join",
        "m.room.member",
        Some("@bob:example.com"),
        "@alice:example.com",
        json!({"membership": "join"}),
    );
    let state: RoomState = RoomState::new();
    assert!(matches!(
        check_auth(&join, &state, rezzy::StateResVersion::V2_1, None),
        Err(AuthError::NotMember { .. })
    ));
}

#[test]
fn test_iterative_auth_chain() {
    let create = make_event(
        "$create",
        "m.room.create",
        Some(""),
        "@alice:example.com",
        json!({}),
    );
    let join = make_event(
        "$join",
        "m.room.member",
        Some("@alice:example.com"),
        "@alice:example.com",
        json!({"membership": "join"}),
    );
    let msg = make_event(
        "$msg",
        "m.room.message",
        None,
        "@alice:example.com",
        json!({"body": "hello"}),
    );
    let (accepted, rejected) = check_auth_chain(
        &[create, join, msg],
        &RoomState::new(),
        rezzy::basespec::rezzy_types::StateResVersion::V2_1,
    );
    assert_eq!(accepted, vec!["$create", "$join", "$msg"]);
    assert!(rejected.is_empty());
}

#[test]
fn test_auth_chain_rejects_unauthorized() {
    let events = utils::parse_jsonl_events(
        r#"
{"event_id":"$create","type":"m.room.create","state_key":"","sender":"@alice:x.com","depth":0,"origin_server_ts":1000,"content":{"room_version":"12"},"prev_events":[],"auth_events":[]}
{"event_id":"$alice_join","type":"m.room.member","state_key":"@alice:x.com","sender":"@alice:x.com","depth":1,"origin_server_ts":1001,"content":{"membership":"join"},"prev_events":["$create"],"auth_events":[]}
{"event_id":"$pl","type":"m.room.power_levels","state_key":"","sender":"@alice:x.com","depth":2,"origin_server_ts":1002,"content":{"ban":50,"users":{"@alice:x.com":100}},"prev_events":["$alice_join"],"auth_events":["$alice_join"]}
{"event_id":"$ban_bob","type":"m.room.member","state_key":"@bob:x.com","sender":"@alice:x.com","depth":3,"origin_server_ts":1003,"content":{"membership":"ban"},"prev_events":["$pl"],"auth_events":["$alice_join","$pl"]}
{"event_id":"$bob_msg","type":"m.room.message","sender":"@bob:x.com","depth":4,"origin_server_ts":1004,"content":{"body":"I am banned"},"prev_events":["$ban_bob"],"auth_events":[]}
    "#,
    );

    let (accepted, rejected) =
        check_auth_chain(&events, &RoomState::new(), rezzy::StateResVersion::V2_1);

    assert_eq!(
        accepted,
        vec!["$create", "$alice_join", "$pl", "$ban_bob"],
        "First four events should pass auth"
    );
    assert_eq!(rejected.len(), 1, "Bob's message should be rejected");
    assert_eq!(rejected[0].0, "$bob_msg");
    assert!(
        matches!(rejected[0].1, AuthError::BannedUser { .. }),
        "Expected BannedUser error, got: {:?}",
        rejected[0].1
    );
}

#[test]
fn test_auth_chain_propagates_rejection_via_auth_events() {
    // $bad_ban is rejected: with no PL event, only the room creator (alice)
    // falls back to implicit PL 100 (V1-V11 fallback) — bob falls back to
    // the plain default PL 0, below the default ban level of 50.
    // $downstream references $bad_ban in its auth_events, so it must be
    // short-circuited via Rule 2.3 (`has_rejected_auth_event` in
    // check_auth_chain) without rerunning full auth checks against it.
    let events = utils::parse_jsonl_events(
        r#"
{"event_id":"$create","type":"m.room.create","state_key":"","sender":"@alice:x.com","depth":0,"origin_server_ts":1000,"content":{},"prev_events":[],"auth_events":[]}
{"event_id":"$alice_join","type":"m.room.member","state_key":"@alice:x.com","sender":"@alice:x.com","depth":1,"origin_server_ts":1001,"content":{"membership":"join"},"prev_events":["$create"],"auth_events":["$create"]}
{"event_id":"$join_rules","type":"m.room.join_rules","state_key":"","sender":"@alice:x.com","depth":2,"origin_server_ts":1002,"content":{"join_rule":"public"},"prev_events":["$alice_join"],"auth_events":["$create","$alice_join"]}
{"event_id":"$bob_join","type":"m.room.member","state_key":"@bob:x.com","sender":"@bob:x.com","depth":3,"origin_server_ts":1003,"content":{"membership":"join"},"prev_events":["$join_rules"],"auth_events":["$create","$join_rules"]}
{"event_id":"$bad_ban","type":"m.room.member","state_key":"@carol:x.com","sender":"@bob:x.com","depth":4,"origin_server_ts":1004,"content":{"membership":"ban"},"prev_events":["$bob_join"],"auth_events":["$create","$bob_join"]}
{"event_id":"$downstream","type":"m.room.message","sender":"@alice:x.com","depth":5,"origin_server_ts":1005,"content":{"body":"hi"},"prev_events":["$bad_ban"],"auth_events":["$create","$alice_join","$bad_ban"]}
    "#,
    );

    let (accepted, rejected) =
        check_auth_chain(&events, &RoomState::new(), rezzy::StateResVersion::V2);

    assert_eq!(
        accepted,
        vec!["$create", "$alice_join", "$join_rules", "$bob_join"],
        "Create, alice's join, join_rules, and bob's join should pass auth"
    );
    assert_eq!(rejected.len(), 2);
    assert_eq!(rejected[0].0, "$bad_ban");
    assert!(
        matches!(rejected[0].1, AuthError::InsufficientPowerLevel { .. }),
        "Expected InsufficientPowerLevel for the ban itself, got: {:?}",
        rejected[0].1
    );
    assert_eq!(rejected[1].0, "$downstream");
    assert!(
        matches!(rejected[1].1, AuthError::InvalidSyntax(ref msg) if msg.contains("auth_event was previously rejected")),
        "Expected propagated rejection for $downstream, got: {:?}",
        rejected[1].1
    );
}

#[test]
fn test_auth_error_display() {
    let err: AuthError = AuthError::NotMember {
        sender: "@bob:example.com".into(),
        event_id: "$unused".into(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("bob"));
}

/// Cover `get_required_power_level` → `get_event_power_level` return path:
/// when the PL event has an `events` map with an override for the event type.
#[test]
fn test_event_type_power_level_override() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$c", "type": "m.room.create", "state_key": "", "sender": "@admin:x.com", "content": {"creator": "@admin:x.com"}}
{"event_id": "$j1", "type": "m.room.member", "state_key": "@alice:x.com", "sender": "@alice:x.com", "content": {"membership": "join"}}
{"event_id": "$j2", "type": "m.room.member", "state_key": "@admin:x.com", "sender": "@admin:x.com", "content": {"membership": "join"}}
{"event_id": "$pl", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:x.com", "content": {"users": {"@admin:x.com": 100, "@alice:x.com": 50}, "events": {"m.room.topic": 80}}}
"#,
    );
    // Alice (PL 50) tries to send m.room.topic (requires 80 via events override) → rejected
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$topic", "type": "m.room.topic", "state_key": "", "sender": "@alice:x.com", "content": {"topic": "hello"}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_err(),
        "Sender PL 50 should be rejected for event type requiring 80: {res:?}"
    );

    // Admin (PL 100) sends m.room.topic (requires 80 via events override) → allowed
    let events2 = utils::parse_jsonl_events(
        r#"
{"event_id": "$topic2", "type": "m.room.topic", "state_key": "", "sender": "@admin:x.com", "content": {"topic": "hello"}}
"#,
    );
    let res2 = check_auth(&events2[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res2.is_ok(),
        "Admin PL 100 should pass event type PL 80: {res2:?}"
    );
}

/// Cover invite-join-rule branch: invited user self-joining under invite rules.
#[test]
fn test_invited_user_self_join_allowed() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$c", "type": "m.room.create", "state_key": "", "sender": "@admin:x.com", "content": {"creator": "@admin:x.com"}}
{"event_id": "$jr", "type": "m.room.join_rules", "state_key": "", "sender": "@admin:x.com", "content": {"join_rule": "invite"}}
{"event_id": "$inv", "type": "m.room.member", "state_key": "@alice:x.com", "sender": "@admin:x.com", "content": {"membership": "invite"}}
"#,
    );
    // Alice self-joins — should be allowed because she's invited
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$join", "type": "m.room.member", "state_key": "@alice:x.com", "sender": "@alice:x.com", "content": {"membership": "join"}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_ok(),
        "Invited user should be allowed to self-join under invite rules: {res:?}"
    );
}

#[test]
fn test_moderator_can_override_admin_ban() {
    let mut state = RoomState::new();

    // Create event
    state.insert(
        ("m.room.create".into(), String::new()),
        make_event(
            "$create",
            "m.room.create",
            Some(""),
            "@creator:example.com",
            json!({}),
        ),
    );

    // Power levels event (admin = 100, mod = 50)
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@admin:example.com",
            json!({
                "users": {
                    "@admin:example.com": 100,
                    "@mod:example.com": 50
                }
            }),
        ),
    );

    // Admin join
    state.insert(
        ("m.room.member".into(), "@admin:example.com".into()),
        make_event(
            "$join_admin",
            "m.room.member",
            Some("@admin:example.com"),
            "@admin:example.com",
            json!({"membership": "join"}),
        ),
    );

    // Mod join
    state.insert(
        ("m.room.member".into(), "@mod:example.com".into()),
        make_event(
            "$join_mod",
            "m.room.member",
            Some("@mod:example.com"),
            "@mod:example.com",
            json!({"membership": "join"}),
        ),
    );

    // Target is banned by @admin (PL 100)
    state.insert(
        ("m.room.member".into(), "@target:example.com".into()),
        make_event(
            "$ban_target",
            "m.room.member",
            Some("@target:example.com"),
            "@admin:example.com",
            json!({"membership": "ban"}),
        ),
    );

    // Moderator (PL 50) attempts to kick/unban the target
    let mod_kick = make_event(
        "$mod_kick",
        "m.room.member",
        Some("@target:example.com"),
        "@mod:example.com",
        json!({"membership": "leave"}),
    );

    // NOTE: the spec does not mandate a "previous sender" check.
    // Per spec §5.5: sender PL (50) >= ban level (50) and target PL (0) < sender PL (50) -> allow.
    let result = check_auth(
        &mod_kick,
        &state,
        rezzy::basespec::rezzy_types::StateResVersion::V2_1,
        None,
    );
    assert!(
        result.is_ok(),
        "Per spec, mod (PL 50) can unban target (PL 0) even if banned by admin (PL 100). Got {result:?}"
    );
}

#[test]
fn test_moderator_can_unban_self_ban() {
    let mut state = RoomState::new();

    // Create event
    state.insert(
        ("m.room.create".into(), String::new()),
        make_event(
            "$create",
            "m.room.create",
            Some(""),
            "@creator:example.com",
            json!({}),
        ),
    );

    // Power levels event (admin = 100, mod = 50)
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@admin:example.com",
            json!({
                "users": {
                    "@admin:example.com": 100,
                    "@mod:example.com": 50
                }
            }),
        ),
    );

    // Mod join
    state.insert(
        ("m.room.member".into(), "@mod:example.com".into()),
        make_event(
            "$join_mod",
            "m.room.member",
            Some("@mod:example.com"),
            "@mod:example.com",
            json!({"membership": "join"}),
        ),
    );

    // Target is banned by @mod (PL 50)
    state.insert(
        ("m.room.member".into(), "@target:example.com".into()),
        make_event(
            "$ban_target",
            "m.room.member",
            Some("@target:example.com"),
            "@mod:example.com",
            json!({"membership": "ban"}),
        ),
    );

    // Moderator (PL 50) attempts to unban/leave their own ban
    let mod_unban = make_event(
        "$mod_unban",
        "m.room.member",
        Some("@target:example.com"),
        "@mod:example.com",
        json!({"membership": "leave"}),
    );

    // Should succeed because current sender matches previous sender (the mod themselves)
    let result = check_auth(
        &mod_unban,
        &state,
        rezzy::basespec::rezzy_types::StateResVersion::V2_1,
        None,
    );
    assert!(result.is_ok(), "Expected Ok(()), got {result:?}");
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_equal_power_invite_override_allowed() {
    let mut state = RoomState::new();

    // Create event
    state.insert(
        ("m.room.create".into(), String::new()),
        make_event(
            "$create",
            "m.room.create",
            Some(""),
            "@creator:example.com",
            json!({}),
        ),
    );

    // Power levels event (admin = 100, mod1 = 50, mod2 = 50)
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@admin:example.com",
            json!({
                "users": {
                    "@admin:example.com": 100,
                    "@mod1:example.com": 50,
                    "@mod2:example.com": 50
                }
            }),
        ),
    );

    // Mod1 join
    state.insert(
        ("m.room.member".into(), "@mod1:example.com".into()),
        make_event(
            "$join_mod1",
            "m.room.member",
            Some("@mod1:example.com"),
            "@mod1:example.com",
            json!({"membership": "join"}),
        ),
    );

    // Mod2 join
    state.insert(
        ("m.room.member".into(), "@mod2:example.com".into()),
        make_event(
            "$join_mod2",
            "m.room.member",
            Some("@mod2:example.com"),
            "@mod2:example.com",
            json!({"membership": "join"}),
        ),
    );

    // Target is invited by @mod1 (PL 50)
    state.insert(
        ("m.room.member".into(), "@target:example.com".into()),
        make_event(
            "$invite_target",
            "m.room.member",
            Some("@target:example.com"),
            "@mod1:example.com",
            json!({"membership": "invite"}),
        ),
    );

    // Moderator 2 (PL 50) attempts to invite the target again (equal power override)
    let mod2_invite = make_event(
        "$mod2_invite",
        "m.room.member",
        Some("@target:example.com"),
        "@mod2:example.com",
        json!({"membership": "invite"}),
    );

    // Should succeed because previous membership is invite (not ban or join), and Mod2 has invite power
    let result = check_auth(
        &mod2_invite,
        &state,
        rezzy::basespec::rezzy_types::StateResVersion::V2_1,
        None,
    );
    assert!(result.is_ok(), "Expected Ok(()), got {result:?}");

    // Target is now banned by @mod1 (PL 50)
    state.insert(
        ("m.room.member".into(), "@target:example.com".into()),
        make_event(
            "$ban_target",
            "m.room.member",
            Some("@target:example.com"),
            "@mod1:example.com",
            json!({"membership": "ban"}),
        ),
    );

    // Moderator 2 (PL 50) attempts to invite the banned target
    let mod2_invite_banned = make_event(
        "$mod2_invite_banned",
        "m.room.member",
        Some("@target:example.com"),
        "@mod2:example.com",
        json!({"membership": "invite"}),
    );

    // Should fail because you can't invite a banned user (rule 4.4.3)
    let result = check_auth(
        &mod2_invite_banned,
        &state,
        rezzy::basespec::rezzy_types::StateResVersion::V2_1,
        None,
    );
    assert!(
        matches!(
            result,
            Err(AuthError::BannedUser {
                ref sender,
                ..
            }) if sender == "@target:example.com"
        ),
        "Expected BannedUser error, got {result:?}"
    );
}

/// Regression test: when `kick_pl` > `ban_pl`, unbanning a user should succeed
/// if the sender meets `ban_pl`. Previously the kick check ran unconditionally
/// after the unban check, incorrectly requiring `kick_pl` for unbans.
#[test]
#[allow(clippy::too_many_lines)]
fn test_unban_succeeds_when_kick_pl_exceeds_ban_pl() {
    let mut state = RoomState::new();

    state.insert(
        ("m.room.create".into(), String::new()),
        make_event(
            "$create",
            "m.room.create",
            Some(""),
            "@admin:example.com",
            json!({}),
        ),
    );

    // Power levels: ban=30, kick=60, mod has PL 50
    // mod can ban (50 >= 30) but cannot kick (50 < 60)
    // mod should still be able to unban (50 >= ban_pl=30)
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@admin:example.com",
            json!({
                "ban": 30,
                "kick": 60,
                "users": {
                    "@admin:example.com": 100,
                    "@mod:example.com": 50
                }
            }),
        ),
    );

    // Mod join
    state.insert(
        ("m.room.member".into(), "@mod:example.com".into()),
        make_event(
            "$join_mod",
            "m.room.member",
            Some("@mod:example.com"),
            "@mod:example.com",
            json!({"membership": "join"}),
        ),
    );

    // Target is currently banned
    state.insert(
        ("m.room.member".into(), "@target:example.com".into()),
        make_event(
            "$ban_target",
            "m.room.member",
            Some("@target:example.com"),
            "@admin:example.com",
            json!({"membership": "ban"}),
        ),
    );

    // Mod (PL 50) attempts to unban target (ban_pl=30, kick_pl=60)
    let unban = make_event(
        "$unban",
        "m.room.member",
        Some("@target:example.com"),
        "@mod:example.com",
        json!({"membership": "leave"}),
    );

    // Should succeed: unban only requires ban_pl (30), not kick_pl (60)
    let result = check_auth(
        &unban,
        &state,
        rezzy::basespec::rezzy_types::StateResVersion::V2_1,
        None,
    );
    assert!(
        result.is_ok(),
        "Unban should succeed when sender PL (50) >= ban_pl (30), \
         even though sender PL < kick_pl (60). Got {result:?}"
    );

    // Verify that kick still requires kick_pl: change target to "join" (not banned)
    state.insert(
        ("m.room.member".into(), "@target:example.com".into()),
        make_event(
            "$join_target",
            "m.room.member",
            Some("@target:example.com"),
            "@target:example.com",
            json!({"membership": "join"}),
        ),
    );

    // Mod (PL 50) attempts to kick target (kick_pl=60)
    let kick = make_event(
        "$kick",
        "m.room.member",
        Some("@target:example.com"),
        "@mod:example.com",
        json!({"membership": "leave"}),
    );

    // Should fail: kick requires kick_pl (60), mod only has 50
    let result = check_auth(
        &kick,
        &state,
        rezzy::basespec::rezzy_types::StateResVersion::V2_1,
        None,
    );
    assert!(
        matches!(
            result,
            Err(AuthError::InsufficientPowerLevel {
                required: 60,
                actual: 50,
                ..
            })
        ),
        "Kick should fail with InsufficientPowerLevel(required=60, actual=50). Got {result:?}"
    );
}

/// **KNOWN VULNERABILITY (V1-V11, all implementations):**
/// PL wipeout — if a PL event with `users: {}` enters the room state (via state
/// resolution, rogue federation peer, etc.), the creator drops to `users_default`
/// (0). Nobody has sufficient PL to send state events or fix the PL event.
/// The room is permanently bricked. No recovery possible.
///
/// This is spec-correct behavior — V1-V11 auth rules have no implicit creator
/// power level. The creator gets PL 100 only because the server puts them in
/// the PL event's `users` map at room creation. Synapse's `get_user_power_level`
/// behaves identically: PL event present + `users: {}` → creator gets 0.
///
/// V12 (MSC4289) fixes this by granting creators immutable infinite PL.
/// See `test_msc4289_v2_1_creator_immune_to_pl_wipeout` for passing test.
///
/// **xfail**: Asserts the vulnerable behavior. If a V2.0.1 state res patch is
/// introduced to mitigate this, this test should be updated to assert recovery.
#[test]
fn test_v2_pl_wipeout_vulnerability() {
    let mut state = RoomState::new();

    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$create",
            "m.room.create",
            Some(""),
            "@creator:x.com",
            json!({}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@creator:x.com".into()),
        make_event(
            "$join",
            "m.room.member",
            Some("@creator:x.com"),
            "@creator:x.com",
            json!({"membership": "join"}),
        ),
    );
    // Attacker-crafted PL event with empty users map.
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@creator:x.com",
            json!({"users": {}}),
        ),
    );

    // Creator tries to send a state event → rejected (PL 0 < required 50).
    let state_event = make_event(
        "$topic",
        "m.room.topic",
        Some(""),
        "@creator:x.com",
        json!({"topic": "hello"}),
    );
    let result = check_auth(&state_event, &state, rezzy::StateResVersion::V2, None);
    assert!(
        result.is_err(),
        "xfail: SRV2 room is bricked; creator has PL 0, cannot send state events: {result:?}"
    );

    // Creator tries to fix the PL event → also rejected (same PL 0).
    let fix_pl = make_event(
        "$fix_pl",
        "m.room.power_levels",
        Some(""),
        "@creator:x.com",
        json!({"users": {"@creator:x.com": 100}}),
    );
    let result = check_auth(&fix_pl, &state, rezzy::StateResVersion::V2, None);
    assert!(
        result.is_err(),
        "xfail: SRV2 room is unrecoverable; creator cannot fix the PL event: {result:?}"
    );
}

/// V2.1 (room V12, MSC4289) is immune to the PL wipeout vulnerability above.
/// Even with `users: {}`, the creator has immutable infinite PL and can still
/// send state events. This is the key security improvement over V1-V11.
#[test]
fn test_msc4289_v2_1_creator_immune_to_pl_wipeout() {
    let mut state = RoomState::new();

    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$create",
            "m.room.create",
            Some(""),
            "@creator:x.com",
            json!({"room_version": "12", "creator": "@creator:x.com"}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@creator:x.com".into()),
        make_event(
            "$join",
            "m.room.member",
            Some("@creator:x.com"),
            "@creator:x.com",
            json!({"membership": "join"}),
        ),
    );
    // PL event with empty users map — same scenario that bricks V2 rooms.
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@creator:x.com",
            json!({"users": {}}),
        ),
    );

    // Creator sends a state event. In V2 this is rejected (PL 0 < required 50).
    // In V2.1, MSC4289 grants immutable i64::MAX PL → allowed.
    let state_event = make_event(
        "$topic",
        "m.room.topic",
        Some(""),
        "@creator:x.com",
        json!({"topic": "hello"}),
    );

    let result = check_auth(&state_event, &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        result.is_ok(),
        "V2.1 creator must retain infinite PL even with users:{{}} — immune to PL wipeout: {result:?}"
    );
}
/// MSC4289 (V12+): creators have spec-mandated infinite power level, immutable
/// and not representable in the PL event. This test verifies the implicit PL
/// for the primary creator and `additional_creators` in V2.1 (room version 12).
#[test]
#[allow(clippy::too_many_lines)]
fn test_msc4289_creator_implicit_power_level() {
    let mut state = RoomState::new();

    // Create event with V2.1 extensions (additional creators)
    state.insert(
        ("m.room.create".into(), String::new()),
        make_event(
            "$create",
            "m.room.create",
            Some(""),
            "@creator:example.com",
            json!({
                "room_version": "12",
                "creator": "@creator:example.com",
                "additional_creators": ["@additional:example.com"]
            }),
        ),
    );

    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@creator:example.com", // Sent by creator, authorized by implicit MAX_POWER_LEVEL
            json!({
                "kick": 50,
                "users_default": 0
            }),
        ),
    );

    // Target user
    state.insert(
        ("m.room.member".into(), "@target:example.com".into()),
        make_event(
            "$join_target",
            "m.room.member",
            Some("@target:example.com"),
            "@target:example.com",
            json!({"membership": "join"}),
        ),
    );

    // Additional creator must be joined (only primary creator has implicit join in v11)
    state.insert(
        ("m.room.member".into(), "@additional:example.com".into()),
        make_event(
            "$join_additional",
            "m.room.member",
            Some("@additional:example.com"),
            "@additional:example.com",
            json!({"membership": "join"}),
        ),
    );

    // Normal user must be joined
    state.insert(
        ("m.room.member".into(), "@normal:example.com".into()),
        make_event(
            "$join_normal",
            "m.room.member",
            Some("@normal:example.com"),
            "@normal:example.com",
            json!({"membership": "join"}),
        ),
    );

    // Primary creator attempts to kick
    let creator_kick = make_event(
        "$kick1",
        "m.room.member",
        Some("@target:example.com"),
        "@creator:example.com",
        json!({"membership": "leave"}),
    );

    // Additional creator attempts to kick
    let additional_kick = make_event(
        "$kick2",
        "m.room.member",
        Some("@target:example.com"),
        "@additional:example.com",
        json!({"membership": "leave"}),
    );

    // Normal user attempts to kick
    let normal_kick = make_event(
        "$kick3",
        "m.room.member",
        Some("@target:example.com"),
        "@normal:example.com",
        json!({"membership": "leave"}),
    );

    // Asserts
    assert!(
        check_auth(
            &creator_kick,
            &state,
            rezzy::basespec::rezzy_types::StateResVersion::V2_1,
            None
        )
        .is_ok(),
        "Primary creator should have implicit MAX_POWER_LEVEL and succeed."
    );

    assert!(
        check_auth(
            &additional_kick,
            &state,
            rezzy::basespec::rezzy_types::StateResVersion::V2_1,
            None
        )
        .is_ok(),
        "Additional creator should have implicit MAX_POWER_LEVEL and succeed."
    );

    assert!(
        matches!(
            check_auth(&normal_kick, &state, rezzy::StateResVersion::V2_1, None),
            Err(AuthError::InsufficientPowerLevel {
                required: 50,
                actual: 0,
                ..
            })
        ),
        "Normal user should fail with InsufficientPowerLevel."
    );
}

/// Verify that in V1-V11, if `m.room.power_levels` is entirely missing,
/// the room creator gets PL 100 and other users get PL 0.
#[test]
fn test_v1_v11_missing_pl_event_creator_fallback() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@creator:example.com", "content": {"creator": "@creator:example.com", "room_version": "10"}}
{"event_id": "$join1", "type": "m.room.member", "state_key": "@creator:example.com", "sender": "@creator:example.com", "content": {"membership": "join"}}
{"event_id": "$join2", "type": "m.room.member", "state_key": "@normal:example.com", "sender": "@normal:example.com", "content": {"membership": "join"}}
"#,
    );

    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$topic1", "type": "m.room.topic", "state_key": "", "sender": "@creator:example.com", "content": {"topic": "allowed"}}
{"event_id": "$topic2", "type": "m.room.topic", "state_key": "", "sender": "@normal:example.com", "content": {"topic": "rejected"}}
"#,
    );
    let creator_event = &events[0];
    let normal_event = &events[1];

    // Creator tries to send a state event (m.room.topic requires PL 50 by default when no PL event exists).
    // Creator should have PL 100 due to the fallback.
    let res = check_auth(creator_event, &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_ok(),
        "Creator should get PL 100 and be allowed to send state events: {res:?}"
    );

    // Normal user tries to send a state event.
    // Normal user gets PL 0, so 0 < 50, should be rejected.
    let res = check_auth(normal_event, &state, rezzy::StateResVersion::V2, None);
    assert!(
        matches!(
            res,
            Err(crate::auth::AuthError::InsufficientPowerLevel {
                required: 50,
                actual: 0,
                ..
            })
        ),
        "Normal user should have PL 0 and be rejected: {res:?}"
    );
}

/// Verify that in V2 (pre-MSC4289), creators get PL 100, not `MAX_POWER_LEVEL`.
#[test]
fn test_msc4289_v2_creator_gets_pl_100_not_max() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$create",
            M_ROOM_CREATE,
            Some(""),
            "@creator:example.com",
            json!({"creator": "@creator:example.com", "room_version": "10"}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@creator:example.com".into()),
        make_event(
            "$join",
            "m.room.member",
            Some("@creator:example.com"),
            "@creator:example.com",
            json!({"membership": "join"}),
        ),
    );
    // Add a power level event that sets ban to 150
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@creator:example.com",
            json!({"ban": 150}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@target:example.com".into()),
        make_event(
            "$target_join",
            "m.room.member",
            Some("@target:example.com"),
            "@target:example.com",
            json!({"membership": "join"}),
        ),
    );

    let ban_event = make_event(
        "$ban",
        "m.room.member",
        Some("@target:example.com"),
        "@creator:example.com",
        json!({"membership": "ban"}),
    );
    assert!(
        check_auth(
            &ban_event,
            &state,
            rezzy::basespec::rezzy_types::StateResVersion::V2,
            None
        )
        .is_err(),
        "V2 creator (PL 100) should NOT be able to ban (requires PL 150)"
    );
    assert!(
        check_auth(
            &ban_event,
            &state,
            rezzy::basespec::rezzy_types::StateResVersion::V2_1,
            None
        )
        .is_ok(),
        "V2.1 creator (MAX_POWER_LEVEL) should be able to ban (requires PL 150)"
    );
}

/// Verify that `additional_creators` are ignored in V2 (pre-MSC4289).
#[test]
fn test_msc4289_v2_additional_creators_ignored() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$create",
            M_ROOM_CREATE,
            Some(""),
            "@creator:example.com",
            json!({
                "creator": "@creator:example.com",
                "room_version": "10",
                "additional_creators": ["@additional:example.com"]
            }),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@additional:example.com".into()),
        make_event(
            "$join",
            "m.room.member",
            Some("@additional:example.com"),
            "@additional:example.com",
            json!({"membership": "join"}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@target:example.com".into()),
        make_event(
            "$target_join",
            "m.room.member",
            Some("@target:example.com"),
            "@target:example.com",
            json!({"membership": "join"}),
        ),
    );

    // additional_creator tries to kick — should FAIL in V2 (they have PL 0, not creator privilege)
    let kick_event = make_event(
        "$kick",
        "m.room.member",
        Some("@target:example.com"),
        "@additional:example.com",
        json!({"membership": "leave"}),
    );
    assert!(
        check_auth(
            &kick_event,
            &state,
            rezzy::basespec::rezzy_types::StateResVersion::V2,
            None
        )
        .is_err(),
        "V2 should ignore additional_creators — user should have PL 0 and fail kick"
    );

    // Same kick should SUCCEED in V2.1
    assert!(
        check_auth(
            &kick_event,
            &state,
            rezzy::basespec::rezzy_types::StateResVersion::V2_1,
            None
        )
        .is_ok(),
        "V2.1 should honor additional_creators — user should have MAX_POWER_LEVEL"
    );
}

#[test]
fn test_ban_insufficient_power_level() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.member".into(), "@low:x.com".into()),
        make_event(
            "$j",
            "m.room.member",
            Some("@low:x.com"),
            "@low:x.com",
            json!({"membership": "join"}),
        ),
    );
    let ban = make_event(
        "$ban",
        "m.room.member",
        Some("@target:x.com"),
        "@low:x.com",
        json!({"membership": "ban"}),
    );
    let result = check_auth(&ban, &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        matches!(
            result,
            Err(AuthError::InsufficientPowerLevel {
                required: 50,
                actual: 0,
                ref event_type
            }) if event_type == "ban"
        ),
        "Expected InsufficientPowerLevel for ban, got {result:?}"
    );
}

#[test]
fn test_kick_insufficient_power_level() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.member".into(), "@low:x.com".into()),
        make_event(
            "$j1",
            "m.room.member",
            Some("@low:x.com"),
            "@low:x.com",
            json!({"membership": "join"}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@target:x.com".into()),
        make_event(
            "$j2",
            "m.room.member",
            Some("@target:x.com"),
            "@target:x.com",
            json!({"membership": "join"}),
        ),
    );
    let kick = make_event(
        "$kick",
        "m.room.member",
        Some("@target:x.com"),
        "@low:x.com",
        json!({"membership": "leave"}),
    );
    let result = check_auth(&kick, &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        matches!(
            result,
            Err(AuthError::InsufficientPowerLevel {
                required: 50,
                actual: 0,
                ref event_type
            }) if event_type == "kick"
        ),
        "Expected InsufficientPowerLevel for kick, got {result:?}"
    );
}

#[test]
fn test_state_key_dyn_trait_coverage() {
    use std::borrow::Borrow;

    let key1 = ("m.room.message".to_string(), "state_key1".to_string());
    let key2 = ("m.room.message".to_string(), "state_key1".to_string());
    let key3 = ("m.room.member".to_string(), "state_key2".to_string());

    let b1: &dyn StateKeyDyn = key1.borrow();
    let b2: &dyn StateKeyDyn = key2.borrow();
    let b3: &dyn StateKeyDyn = key3.borrow();

    assert!(b1 == b2);
    assert!(b1 != b3);

    assert_eq!(b1.partial_cmp(b2), Some(std::cmp::Ordering::Equal));
    assert_eq!(b3.partial_cmp(b1), Some(std::cmp::Ordering::Less));
    assert_eq!(b1.partial_cmp(b3), Some(std::cmp::Ordering::Greater));

    let s1 = ("m.room.message", "state_key1");
    let s2 = ("m.room.member", "state_key2");
    let dyn_s1: &dyn StateKeyDyn = &s1;
    let dyn_s2: &dyn StateKeyDyn = &s2;

    assert_eq!(dyn_s1.ev_type(), "m.room.message");
    assert_eq!(dyn_s1.state_key(), "state_key1");
    assert_eq!(dyn_s2.ev_type(), "m.room.member");
    assert_eq!(dyn_s2.state_key(), "state_key2");
}

#[test]
fn test_auth_types_for_event() {
    let types = auth_types_for_event(
        "m.room.create",
        "@alice:x.com",
        Some(""),
        &json!({}),
        StateResVersion::V2_1,
    );
    assert!(types.is_empty());

    let types = auth_types_for_event(
        "m.room.message",
        "@alice:x.com",
        None,
        &json!({}),
        StateResVersion::V2,
    );
    assert!(types.contains(&("m.room.create".to_string(), String::new())));
    assert!(types.contains(&("m.room.member".to_string(), "@alice:x.com".to_string())));
    assert!(types.contains(&("m.room.power_levels".to_string(), String::new())));

    let types = auth_types_for_event(
        "m.room.message",
        "@alice:x.com",
        None,
        &json!({}),
        StateResVersion::V2_1,
    );
    assert!(!types.contains(&("m.room.create".to_string(), String::new())));

    let content = json!({
        "membership": "join",
        "third_party_invite": {
            "signed": {
                "token": "token123"
            }
        }
    });
    let types = auth_types_for_event(
        "m.room.member",
        "@alice:x.com",
        Some("@bob:x.com"),
        &content,
        StateResVersion::V2_1,
    );
    assert!(types.contains(&("m.room.member".to_string(), "@bob:x.com".to_string())));
    assert!(types.contains(&("m.room.join_rules".to_string(), String::new())));
    assert!(types.contains(&(
        "m.room.third_party_invite".to_string(),
        "token123".to_string()
    )));

    // Knock events must include join_rules in auth state
    let types = auth_types_for_event(
        "m.room.member",
        "@alice:x.com",
        Some("@alice:x.com"),
        &json!({"membership": "knock"}),
        StateResVersion::V2,
    );
    assert!(
        types.contains(&("m.room.join_rules".to_string(), String::new())),
        "knock membership must require m.room.join_rules in auth types"
    );
}

#[test]
fn test_join_rules_not_member_invite_only() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.join_rules".into(), String::new()),
        make_event(
            "$jr",
            "m.room.join_rules",
            Some(""),
            "@admin:x.com",
            json!({"join_rule": "invite"}),
        ),
    );
    let join_attempt = make_event(
        "$join",
        "m.room.member",
        Some("@newcomer:x.com"),
        "@newcomer:x.com",
        json!({"membership": "join"}),
    );
    let result = check_auth(&join_attempt, &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        matches!(
            result,
            Err(AuthError::NotMember {
                ref sender,
                ..
            }) if sender == "@newcomer:x.com"
        ),
        "Expected NotMember error when joining invite-only room without invite, got {result:?}"
    );
}

#[test]
fn test_join_rules_not_member_knock() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.join_rules".into(), String::new()),
        make_event(
            "$jr",
            "m.room.join_rules",
            Some(""),
            "@admin:x.com",
            json!({"join_rule": "knock"}),
        ),
    );
    let join_attempt = make_event(
        "$join",
        "m.room.member",
        Some("@newcomer:x.com"),
        "@newcomer:x.com",
        json!({"membership": "join"}),
    );
    let result = check_auth(&join_attempt, &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        matches!(
            result,
            Err(AuthError::NotMember {
                ref sender,
                ..
            }) if sender == "@newcomer:x.com"
        ),
        "Expected NotMember error when joining knock room without knock/invite, got {result:?}"
    );
}

#[test]
fn test_join_rules_not_member_custom_rule() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.join_rules".into(), String::new()),
        make_event(
            "$jr",
            "m.room.join_rules",
            Some(""),
            "@admin:x.com",
            json!({"join_rule": "private"}),
        ),
    );
    let join_attempt = make_event(
        "$join",
        "m.room.member",
        Some("@newcomer:x.com"),
        "@newcomer:x.com",
        json!({"membership": "join"}),
    );
    let result = check_auth(&join_attempt, &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        matches!(
            result,
            Err(AuthError::NotMember {
                ref sender,
                ..
            }) if sender == "@newcomer:x.com"
        ),
        "Expected NotMember error when joining custom-rule room, got {result:?}"
    );
}

#[test]
fn test_membership_rules_fallback() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.member".into(), "@alice:x.com".into()),
        make_event(
            "$j",
            "m.room.member",
            Some("@alice:x.com"),
            "@alice:x.com",
            json!({"membership": "join"}),
        ),
    );
    // Truly unknown membership transition: spec rule 5.8 says reject.
    // Note: "knock" is no longer unknown — it has proper validation (MSC2403).
    let unknown = make_event(
        "$unknown",
        "m.room.member",
        Some("@alice:x.com"),
        "@alice:x.com",
        json!({"membership": "custom_xyz"}),
    );
    let result = check_auth(&unknown, &state, rezzy::StateResVersion::V2_1, None);
    // Spec rule 5.8: unknown membership must be rejected.
    assert!(
        result.is_err(),
        "Unknown membership must be rejected, got {result:?}"
    );
}

#[test]
fn test_invite_already_joined_user_rejected() {
    // Per spec: inviting a user who is already joined must be rejected.
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@admin:x.com",
            json!({"users": {"@admin:x.com": 100}}),
        ),
    );
    // Admin is joined
    state.insert(
        ("m.room.member".into(), "@admin:x.com".into()),
        make_event(
            "$admin_join",
            "m.room.member",
            Some("@admin:x.com"),
            "@admin:x.com",
            json!({"membership": "join"}),
        ),
    );
    // Bob is already joined
    state.insert(
        ("m.room.member".into(), "@bob:x.com".into()),
        make_event(
            "$bob_join",
            "m.room.member",
            Some("@bob:x.com"),
            "@bob:x.com",
            json!({"membership": "join"}),
        ),
    );

    // Admin tries to re-invite Bob who is already joined
    let invite = make_event(
        "$reinvite",
        "m.room.member",
        Some("@bob:x.com"),
        "@admin:x.com",
        json!({"membership": "invite"}),
    );
    let result = check_auth(&invite, &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        result.is_err(),
        "inviting an already-joined user must be rejected, got {result:?}"
    );
}

#[test]
fn test_unstable_msc3757_owned_state_key_rejected_when_sender_mismatch() {
    // Spec auth rule 9 (all versions): For non-member state events with @-prefixed state_key,
    // the sender must match the state_key.
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@admin:x.com",
            json!({"users": {"@admin:x.com": 100}}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@admin:x.com".into()),
        make_event(
            "$admin_join",
            "m.room.member",
            Some("@admin:x.com"),
            "@admin:x.com",
            json!({"membership": "join"}),
        ),
    );

    // Admin tries to set a state event with state_key=@bob (not themselves)
    let owned_event = make_event(
        "$owned",
        "org.example.custom",
        Some("@bob:x.com"),
        "@admin:x.com",
        json!({"data": "hijack"}),
    );
    let result = check_auth(&owned_event, &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        result.is_err(),
        "non-member state event with @-prefixed state_key must reject sender mismatch, got {result:?}"
    );
}

#[test]
fn test_unstable_msc3757_owned_state_key_allowed_when_sender_matches() {
    // Spec auth rule 9: sender == state_key should be allowed.
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@alice:x.com", json!({})),
    );
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@alice:x.com",
            json!({"users": {"@alice:x.com": 100}}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@alice:x.com".into()),
        make_event(
            "$alice_join",
            "m.room.member",
            Some("@alice:x.com"),
            "@alice:x.com",
            json!({"membership": "join"}),
        ),
    );

    // Alice sets her own state_key — should succeed
    let owned_event = make_event(
        "$owned",
        "org.example.custom",
        Some("@alice:x.com"),
        "@alice:x.com",
        json!({"data": "mine"}),
    );
    let result = check_auth(&owned_event, &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        result.is_ok(),
        "sender matching @-prefixed state_key should be allowed, got {result:?}"
    );
}

#[test]
fn test_self_leave_rejected_when_already_left() {
    // Spec rule 5.5.1: self-leave is only allowed if current membership is
    // invite, join, or knock. A user who has already left cannot leave again.
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    // Alice has already left (or was never in the room — default is "leave")
    state.insert(
        ("m.room.member".into(), "@alice:x.com".into()),
        make_event(
            "$alice_leave",
            "m.room.member",
            Some("@alice:x.com"),
            "@alice:x.com",
            json!({"membership": "leave"}),
        ),
    );

    // Alice tries to self-leave again
    let leave = make_event(
        "$leave_again",
        "m.room.member",
        Some("@alice:x.com"),
        "@alice:x.com",
        json!({"membership": "leave"}),
    );
    let result = check_auth(&leave, &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        result.is_err(),
        "self-leave when already left must be rejected, got {result:?}"
    );
}

#[test]
fn test_self_leave_allowed_from_knock() {
    // Spec rule 5.5.1 (V8+): self-leave is allowed from knock membership.
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.member".into(), "@alice:x.com".into()),
        make_event(
            "$alice_knock",
            "m.room.member",
            Some("@alice:x.com"),
            "@alice:x.com",
            json!({"membership": "knock"}),
        ),
    );

    // Alice retracts her knock by leaving
    let leave = make_event(
        "$retract_knock",
        "m.room.member",
        Some("@alice:x.com"),
        "@alice:x.com",
        json!({"membership": "leave"}),
    );
    let result = check_auth(&leave, &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        result.is_ok(),
        "self-leave from knock should be allowed, got {result:?}"
    );
}

#[test]
fn test_third_party_invite_rejected_when_target_banned() {
    use rezzy::basespec::event_types::{
        M_ROOM_MEMBER, M_ROOM_POWER_LEVELS, M_ROOM_THIRD_PARTY_INVITE,
    };
    // Rule 5.4.1.1: If target user is banned, reject — even if 3PI is valid.
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@alice:matrix.org",
            json!({"creator": "@alice:matrix.org"}),
        ),
    );
    state.insert(
        (M_ROOM_POWER_LEVELS.into(), String::new()),
        make_event(
            "$pl",
            M_ROOM_POWER_LEVELS,
            Some(""),
            "@alice:matrix.org",
            json!({ "users": { "@alice:matrix.org": 100 }, "invite": 50 }),
        ),
    );
    state.insert(
        (M_ROOM_MEMBER.into(), "@alice:matrix.org".into()),
        make_event(
            "$a",
            M_ROOM_MEMBER,
            Some("@alice:matrix.org"),
            "@alice:matrix.org",
            json!({"membership": "join"}),
        ),
    );
    // Charlie is BANNED
    state.insert(
        (M_ROOM_MEMBER.into(), "@charlie:matrix.org".into()),
        make_event(
            "$ban_charlie",
            M_ROOM_MEMBER,
            Some("@charlie:matrix.org"),
            "@alice:matrix.org",
            json!({"membership": "ban"}),
        ),
    );
    // Alice created a valid 3PI token
    state.insert(
        (M_ROOM_THIRD_PARTY_INVITE.into(), "abc_token".into()),
        make_event(
            "$tpi",
            M_ROOM_THIRD_PARTY_INVITE,
            Some("abc_token"),
            "@alice:matrix.org",
            json!({"display_name": "charlie"}),
        ),
    );

    // Alice tries to invite the banned user via 3PI
    let invite = make_event(
        "$inv",
        M_ROOM_MEMBER,
        Some("@charlie:matrix.org"),
        "@alice:matrix.org",
        json!({
            "membership": "invite",
            "third_party_invite": {
                "display_name": "charlie",
                "signed": {
                    "token": "abc_token",
                    "mxid": "@charlie:matrix.org",
                    "signatures": {
                        "example.com": { "ed25519:1": "dummy" }
                    }
                }
            }
        }),
    );

    let result = check_auth(&invite, &state, StateResVersion::V2, None);
    assert!(
        matches!(result, Err(AuthError::BannedUser { .. })),
        "3PI invite targeting a banned user must be rejected as BannedUser (Rule 5.4.1.1), got: {result:?}"
    );
}

#[test]
fn test_third_party_invite_allowed_when_issuer_has_power() {
    use rezzy::basespec::event_types::{
        M_ROOM_MEMBER, M_ROOM_POWER_LEVELS, M_ROOM_THIRD_PARTY_INVITE,
    };

    // Alice has PL to invite.
    // Alice creates m.room.third_party_invite with state_key "abc_token".
    // Alice issues m.room.member (invite) for Charlie, referencing "abc_token" and her own mxid.
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@alice:matrix.org",
            json!({"creator": "@alice:matrix.org"}),
        ),
    );
    state.insert(
        (M_ROOM_POWER_LEVELS.into(), String::new()),
        make_event(
            "$pl",
            M_ROOM_POWER_LEVELS,
            Some(""),
            "@alice:matrix.org",
            json!({
                "users": { "@alice:matrix.org": 100, "@bob:matrix.org": 0 },
                "invite": 50
            }),
        ),
    );
    state.insert(
        (M_ROOM_MEMBER.into(), "@alice:matrix.org".into()),
        make_event(
            "$a",
            M_ROOM_MEMBER,
            Some("@alice:matrix.org"),
            "@alice:matrix.org",
            json!({"membership": "join"}),
        ),
    );
    state.insert(
        (M_ROOM_MEMBER.into(), "@bob:matrix.org".into()),
        make_event(
            "$b",
            M_ROOM_MEMBER,
            Some("@bob:matrix.org"),
            "@bob:matrix.org",
            json!({"membership": "join"}),
        ),
    );

    // Alice creates the third party invite
    state.insert(
        (M_ROOM_THIRD_PARTY_INVITE.into(), "abc_token".into()),
        make_event(
            "$tpi",
            M_ROOM_THIRD_PARTY_INVITE,
            Some("abc_token"),
            "@alice:matrix.org",
            json!({"display_name": "charlie"}),
        ),
    );

    // Alice sends the actual invite, leveraging her own 3PI token
    let alice_invite = make_event(
        "$inv",
        M_ROOM_MEMBER,
        Some("@charlie:matrix.org"),
        "@alice:matrix.org",
        json!({
            "membership": "invite",
            "third_party_invite": {
                "display_name": "charlie",
                "signed": {
                    "token": "abc_token",
                    "mxid": "@charlie:matrix.org",
                    "signatures": {
                        "example.com": {
                            "ed25519:1": "dummy_signature"
                        }
                    }
                }
            }
        }),
    );

    let result = check_auth(&alice_invite, &state, StateResVersion::V2, None);
    assert!(
        result.is_ok(),
        "3PI invite should be allowed when issuer correctly sends the invite: {result:?}"
    );
}

#[test]
fn test_third_party_invite_rejected_when_sender_mismatch() {
    use rezzy::basespec::event_types::{
        M_ROOM_MEMBER, M_ROOM_POWER_LEVELS, M_ROOM_THIRD_PARTY_INVITE,
    };
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_POWER_LEVELS.into(), String::new()),
        make_event(
            "$pl",
            M_ROOM_POWER_LEVELS,
            Some(""),
            "@alice:matrix.org",
            json!({
                "users": { "@alice:matrix.org": 100, "@bob:matrix.org": 100 },
                "invite": 50
            }),
        ),
    );
    state.insert(
        (M_ROOM_MEMBER.into(), "@bob:matrix.org".into()),
        make_event(
            "$b",
            M_ROOM_MEMBER,
            Some("@bob:matrix.org"),
            "@bob:matrix.org",
            json!({"membership": "join"}),
        ),
    );

    // ALICE creates the third party invite
    state.insert(
        (M_ROOM_THIRD_PARTY_INVITE.into(), "abc_token".into()),
        make_event(
            "$tpi",
            M_ROOM_THIRD_PARTY_INVITE,
            Some("abc_token"),
            "@alice:matrix.org",
            json!({"display_name": "charlie"}),
        ),
    );

    // BOB (who also has PL) tries to send the invite using ALICE's token
    let bob_invite = make_event(
        "$inv",
        M_ROOM_MEMBER,
        Some("@charlie:matrix.org"),
        "@bob:matrix.org",
        json!({
            "membership": "invite",
            "third_party_invite": {
                "signed": {
                    "token": "abc_token",
                    "mxid": "@charlie:matrix.org",
                    "signatures": { "example.com": { "ed25519:1": "dummy" } }
                }
            }
        }),
    );

    let result = check_auth(&bob_invite, &state, StateResVersion::V2, None);
    assert!(
        matches!(result, Err(AuthError::InvalidStateKey { .. })),
        "3PI invite must fail as InvalidStateKey if sender mismatches, got: {result:?}"
    );
}

#[test]
fn test_third_party_invite_rejected_when_mxid_mismatch() {
    use rezzy::basespec::event_types::{
        M_ROOM_MEMBER, M_ROOM_POWER_LEVELS, M_ROOM_THIRD_PARTY_INVITE,
    };
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_POWER_LEVELS.into(), String::new()),
        make_event(
            "$pl",
            M_ROOM_POWER_LEVELS,
            Some(""),
            "@alice:matrix.org",
            json!({ "users": { "@alice:matrix.org": 100 }, "invite": 50 }),
        ),
    );
    state.insert(
        (M_ROOM_MEMBER.into(), "@alice:matrix.org".into()),
        make_event(
            "$a",
            M_ROOM_MEMBER,
            Some("@alice:matrix.org"),
            "@alice:matrix.org",
            json!({"membership": "join"}),
        ),
    );

    state.insert(
        (M_ROOM_THIRD_PARTY_INVITE.into(), "abc_token".into()),
        make_event(
            "$tpi",
            M_ROOM_THIRD_PARTY_INVITE,
            Some("abc_token"),
            "@alice:matrix.org",
            json!({"display_name": "charlie"}),
        ),
    );

    // Alice sends the invite, but the mxid in the token does NOT match the state_key
    let alice_invite = make_event(
        "$inv",
        M_ROOM_MEMBER,
        Some("@charlie:matrix.org"),
        "@alice:matrix.org",
        json!({
            "membership": "invite",
            "third_party_invite": {
                "signed": {
                    "token": "abc_token",
                    "mxid": "@wrong_user:matrix.org",
                    "signatures": { "example.com": { "ed25519:1": "dummy" } }
                }
            }
        }),
    );

    let result = check_auth(&alice_invite, &state, StateResVersion::V2, None);
    assert!(
        matches!(result, Err(AuthError::InvalidStateKey { .. })),
        "3PI invite must fail if mxid does not match target user, got: {result:?}"
    );
}

#[test]
fn test_third_party_invite_rejected_when_signatures_missing() {
    use rezzy::basespec::event_types::{
        M_ROOM_MEMBER, M_ROOM_POWER_LEVELS, M_ROOM_THIRD_PARTY_INVITE,
    };
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_POWER_LEVELS.into(), String::new()),
        make_event(
            "$pl",
            M_ROOM_POWER_LEVELS,
            Some(""),
            "@alice:matrix.org",
            json!({ "users": { "@alice:matrix.org": 100 }, "invite": 50 }),
        ),
    );
    state.insert(
        (M_ROOM_MEMBER.into(), "@alice:matrix.org".into()),
        make_event(
            "$a",
            M_ROOM_MEMBER,
            Some("@alice:matrix.org"),
            "@alice:matrix.org",
            json!({"membership": "join"}),
        ),
    );

    state.insert(
        (M_ROOM_THIRD_PARTY_INVITE.into(), "abc_token".into()),
        make_event(
            "$tpi",
            M_ROOM_THIRD_PARTY_INVITE,
            Some("abc_token"),
            "@alice:matrix.org",
            json!({"display_name": "charlie"}),
        ),
    );

    let alice_invite = make_event(
        "$inv",
        M_ROOM_MEMBER,
        Some("@charlie:matrix.org"),
        "@alice:matrix.org",
        json!({
            "membership": "invite",
            "third_party_invite": {
                "signed": {
                    "token": "abc_token",
                    "mxid": "@charlie:matrix.org"
                    // missing signatures
                }
            }
        }),
    );

    let result = check_auth(&alice_invite, &state, StateResVersion::V2, None);
    assert!(
        matches!(result, Err(AuthError::InvalidSyntax(_))),
        "3PI invite must fail as InvalidSyntax if signatures block is missing, got: {result:?}"
    );
}

#[test]
fn test_third_party_invite_rejected_when_token_missing() {
    use rezzy::basespec::event_types::{M_ROOM_MEMBER, M_ROOM_POWER_LEVELS};
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_POWER_LEVELS.into(), String::new()),
        make_event(
            "$pl",
            M_ROOM_POWER_LEVELS,
            Some(""),
            "@alice:matrix.org",
            json!({ "users": { "@alice:matrix.org": 100 }, "invite": 50 }),
        ),
    );
    state.insert(
        (M_ROOM_MEMBER.into(), "@alice:matrix.org".into()),
        make_event(
            "$a",
            M_ROOM_MEMBER,
            Some("@alice:matrix.org"),
            "@alice:matrix.org",
            json!({"membership": "join"}),
        ),
    );

    // NO m.room.third_party_invite event is in the state!

    // Alice sends the invite, referencing a token that doesn't exist
    let alice_invite = make_event(
        "$inv",
        M_ROOM_MEMBER,
        Some("@charlie:matrix.org"),
        "@alice:matrix.org",
        json!({
            "membership": "invite",
            "third_party_invite": {
                "signed": {
                    "token": "missing_token",
                    "mxid": "@charlie:matrix.org",
                    "signatures": { "example.com": { "ed25519:1": "dummy" } }
                }
            }
        }),
    );

    let result = check_auth(&alice_invite, &state, StateResVersion::V2, None);
    assert!(
        matches!(result, Err(AuthError::InvalidStateKey { .. })),
        "3PI invite must fail as InvalidStateKey if token does not exist in state, got: {result:?}"
    );
}

#[test]
fn test_third_party_invite_rejected_when_issuer_lacks_power() {
    use rezzy::basespec::event_types::{
        M_ROOM_MEMBER, M_ROOM_POWER_LEVELS, M_ROOM_THIRD_PARTY_INVITE,
    };
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@alice:matrix.org",
            json!({"creator": "@alice:matrix.org"}),
        ),
    );
    state.insert(
        (M_ROOM_POWER_LEVELS.into(), String::new()),
        make_event(
            "$pl",
            M_ROOM_POWER_LEVELS,
            Some(""),
            "@alice:matrix.org",
            json!({
                "users": { "@alice:matrix.org": 100, "@bob:matrix.org": 10 },
                "invite": 50
            }),
        ),
    );
    state.insert(
        (M_ROOM_MEMBER.into(), "@bob:matrix.org".into()),
        make_event(
            "$b",
            M_ROOM_MEMBER,
            Some("@bob:matrix.org"),
            "@bob:matrix.org",
            json!({"membership": "join"}),
        ),
    );
    // Bob created the 3PI token but only has PL 10, invite requires 50
    state.insert(
        (M_ROOM_THIRD_PARTY_INVITE.into(), "abc_token".into()),
        make_event(
            "$tpi",
            M_ROOM_THIRD_PARTY_INVITE,
            Some("abc_token"),
            "@bob:matrix.org",
            json!({"display_name": "charlie"}),
        ),
    );

    let invite = make_event(
        "$inv",
        M_ROOM_MEMBER,
        Some("@charlie:matrix.org"),
        "@bob:matrix.org",
        json!({
            "membership": "invite",
            "third_party_invite": {
                "signed": {
                    "token": "abc_token",
                    "mxid": "@charlie:matrix.org",
                    "signatures": { "example.com": { "ed25519:1": "dummy" } }
                }
            }
        }),
    );

    let result = check_auth(&invite, &state, StateResVersion::V2, None);
    assert!(
        matches!(result, Err(AuthError::InsufficientPowerLevel { .. })),
        "3PI invite must fail as InsufficientPowerLevel when issuer PL < invite PL, got: {result:?}"
    );
}

#[test]
fn test_third_party_invite_rejected_when_mxid_missing() {
    use rezzy::basespec::event_types::{M_ROOM_MEMBER, M_ROOM_POWER_LEVELS};
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_POWER_LEVELS.into(), String::new()),
        make_event(
            "$pl",
            M_ROOM_POWER_LEVELS,
            Some(""),
            "@alice:matrix.org",
            json!({ "users": { "@alice:matrix.org": 100 }, "invite": 50 }),
        ),
    );
    state.insert(
        (M_ROOM_MEMBER.into(), "@alice:matrix.org".into()),
        make_event(
            "$a",
            M_ROOM_MEMBER,
            Some("@alice:matrix.org"),
            "@alice:matrix.org",
            json!({"membership": "join"}),
        ),
    );

    // third_party_invite.signed has token and signatures but NO mxid
    let invite = make_event(
        "$inv",
        M_ROOM_MEMBER,
        Some("@charlie:matrix.org"),
        "@alice:matrix.org",
        json!({
            "membership": "invite",
            "third_party_invite": {
                "signed": {
                    "token": "abc_token",
                    "signatures": { "example.com": { "ed25519:1": "dummy" } }
                }
            }
        }),
    );

    let result = check_auth(&invite, &state, StateResVersion::V2, None);
    assert!(
        matches!(result, Err(AuthError::InvalidSyntax(_))),
        "3PI invite must fail as InvalidSyntax when mxid is missing from signed block, got: {result:?}"
    );
}

#[test]
fn test_third_party_invite_override_is_ignored() {
    use rezzy::basespec::event_types::{
        M_ROOM_CREATE, M_ROOM_MEMBER, M_ROOM_POWER_LEVELS, M_ROOM_THIRD_PARTY_INVITE,
    };
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@creator:example.com",
            json!({ "creator": "@creator:example.com" }),
        ),
    );

    // invite requires PL 50, but third_party_invite event-specific override (0) must be ignored
    let pl_content = json!({
        "invite": 50,
        "events": {
            "m.room.third_party_invite": 0
        },
        "users": {
            "@creator:example.com": 100
        }
    });

    state.insert(
        (M_ROOM_POWER_LEVELS.into(), String::new()),
        make_event(
            "$pl",
            M_ROOM_POWER_LEVELS,
            Some(""),
            "@creator:example.com",
            pl_content,
        ),
    );

    state.insert(
        (M_ROOM_MEMBER.into(), "@user:example.com".into()),
        make_event(
            "$join",
            M_ROOM_MEMBER,
            Some("@user:example.com"),
            "@user:example.com",
            json!({"membership": "join"}),
        ),
    );

    let tpi_event = make_event(
        "$tpi",
        M_ROOM_THIRD_PARTY_INVITE,
        Some("token"),
        "@user:example.com", // user has default PL 0
        json!({
            "display_name": "bob",
            "public_key": "abc"
        }),
    );

    let result = rezzy::auth::check_auth(&tpi_event, &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        matches!(
            result,
            Err(rezzy::auth::AuthError::InsufficientPowerLevel { .. })
        ),
        "m.room.third_party_invite must require the invite level (50) and ignore the event-specific override (0), got: {result:?}"
    );
}

#[test]
fn test_malformed_third_party_invite_presence() {
    use rezzy::basespec::event_types::{M_ROOM_CREATE, M_ROOM_MEMBER, M_ROOM_POWER_LEVELS};
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@creator:example.com",
            json!({ "creator": "@creator:example.com" }),
        ),
    );

    state.insert(
        (M_ROOM_POWER_LEVELS.into(), String::new()),
        make_event(
            "$pl",
            M_ROOM_POWER_LEVELS,
            Some(""),
            "@creator:example.com",
            json!({
                "invite": 50,
                "users": {
                    "@admin:example.com": 100
                }
            }),
        ),
    );

    state.insert(
        (M_ROOM_MEMBER.into(), "@admin:example.com".into()),
        make_event(
            "$join",
            M_ROOM_MEMBER,
            Some("@admin:example.com"),
            "@admin:example.com",
            json!({"membership": "join"}),
        ),
    );

    // Admin sends an invite to @target:example.com
    // BUT the payload has a malformed third_party_invite object (missing signed)
    let invite_event = make_event(
        "$inv",
        M_ROOM_MEMBER,
        Some("@target:example.com"),
        "@admin:example.com", // Admin has PL 100, which is enough to invite
        json!({
            "membership": "invite",
            "third_party_invite": {
                "display_name": "bob"
            }
        }),
    );

    let result = rezzy::auth::check_auth(&invite_event, &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        matches!(result, Err(rezzy::auth::AuthError::InvalidSyntax(_))),
        "Invite with malformed third_party_invite property must be rejected as InvalidSyntax, got: {result:?}"
    );
}

// ─── EventVerifier trait coverage ───────────────────────────────────────────

/// A pass-through verifier that uses all default `Ok(())` impls.
struct PassThroughVerifier;
impl rezzy::EventVerifier<String> for PassThroughVerifier {}

/// A verifier that rejects on `verify_event_id_hash`.
struct RejectEventIdHash;
impl rezzy::EventVerifier<String> for RejectEventIdHash {
    fn verify_event_id_hash(&self, _event_id: &String) -> Result<(), String> {
        Err("bad event id hash".into())
    }
}

/// A verifier that rejects on `verify_signatures`.
struct RejectSignatures;
impl rezzy::EventVerifier<String> for RejectSignatures {
    fn verify_signatures(&self, _event_id: &String) -> Result<(), String> {
        Err("bad signature".into())
    }
}

/// A verifier that rejects on `verify_content_hash`.
struct RejectContentHash;
impl rezzy::EventVerifier<String> for RejectContentHash {
    fn verify_content_hash(&self, _event_id: &String) -> Result<(), String> {
        Err("bad content hash".into())
    }
}

/// A verifier that rejects on `verify_third_party_invite`.
struct RejectThirdPartyInvite;
impl rezzy::EventVerifier<String> for RejectThirdPartyInvite {
    fn verify_third_party_invite(
        &self,
        _event_id: &String,
        _tpi_token: &str,
    ) -> Result<(), String> {
        Err("bad 3pi signature".into())
    }
}

/// Helper: build minimal valid state + member event for verifier tests.
fn make_verifier_test_state() -> (RoomState, LeanEvent) {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:x.com",
            json!({}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@alice:x.com".into()),
        make_event(
            "$join",
            "m.room.member",
            Some("@alice:x.com"),
            "@alice:x.com",
            json!({"membership": "join"}),
        ),
    );
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@alice:x.com",
            json!({"users": {"@alice:x.com": 100}}),
        ),
    );
    let msg = make_event(
        "$msg",
        "m.room.message",
        None,
        "@alice:x.com",
        json!({"body": "hi"}),
    );
    (state, msg)
}

#[test]
fn test_event_verifier_passthrough_allows() {
    let (state, msg) = make_verifier_test_state();
    let result = check_auth(
        &msg,
        &state,
        rezzy::StateResVersion::V2_1,
        Some(&PassThroughVerifier),
    );
    assert!(
        result.is_ok(),
        "PassThroughVerifier should allow: {result:?}"
    );
}

#[test]
fn test_event_verifier_reject_event_id_hash() {
    let (state, msg) = make_verifier_test_state();
    let result = check_auth(
        &msg,
        &state,
        rezzy::StateResVersion::V2_1,
        Some(&RejectEventIdHash),
    );
    assert!(
        matches!(&result, Err(AuthError::InvalidSyntax(s)) if s.contains("bad event id hash")),
        "Should reject with bad event id hash: {result:?}"
    );
}

#[test]
fn test_event_verifier_reject_signatures() {
    let (state, msg) = make_verifier_test_state();
    let result = check_auth(
        &msg,
        &state,
        rezzy::StateResVersion::V2_1,
        Some(&RejectSignatures),
    );
    assert!(
        matches!(&result, Err(AuthError::InvalidSyntax(s)) if s.contains("bad signature")),
        "Should reject with bad signature: {result:?}"
    );
}

#[test]
fn test_event_verifier_reject_content_hash() {
    let (state, msg) = make_verifier_test_state();
    let result = check_auth(
        &msg,
        &state,
        rezzy::StateResVersion::V2_1,
        Some(&RejectContentHash),
    );
    assert!(
        matches!(&result, Err(AuthError::InvalidSyntax(s)) if s.contains("bad content hash")),
        "Should reject with bad content hash: {result:?}"
    );
}

#[test]
fn test_event_verifier_reject_third_party_invite() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:x.com",
            json!({}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@alice:x.com".into()),
        make_event(
            "$join",
            "m.room.member",
            Some("@alice:x.com"),
            "@alice:x.com",
            json!({"membership": "join"}),
        ),
    );
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@alice:x.com",
            json!({"users": {"@alice:x.com": 100}}),
        ),
    );
    state.insert(
        ("m.room.third_party_invite".into(), "tok123".into()),
        make_event(
            "$tpi",
            "m.room.third_party_invite",
            Some("tok123"),
            "@alice:x.com",
            json!({"public_key": "abc"}),
        ),
    );

    let invite = make_event(
        "$inv",
        "m.room.member",
        Some("@bob:x.com"),
        "@alice:x.com",
        json!({
            "membership": "invite",
            "third_party_invite": {
                "signed": {
                    "mxid": "@bob:x.com",
                    "token": "tok123",
                    "signatures": {"x.com": {"ed25519:auto": "sig"}}
                }
            }
        }),
    );

    let result = check_auth(
        &invite,
        &state,
        rezzy::StateResVersion::V2_1,
        Some(&RejectThirdPartyInvite),
    );
    assert!(
        matches!(&result, Err(AuthError::InvalidSyntax(s)) if s.contains("bad 3pi signature")),
        "Should reject with bad 3pi signature: {result:?}"
    );
}

/// Coverage: `get_required_power_level` line 377 — `m.room.third_party_invite`
/// defaults to PL 0 when no `m.room.power_levels` event exists.
#[test]
fn test_third_party_invite_default_pl_without_power_levels() {
    use rezzy::basespec::event_types::{M_ROOM_MEMBER, M_ROOM_THIRD_PARTY_INVITE};

    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@alice:x",
            json!({"creator": "@alice:x"}),
        ),
    );
    state.insert(
        (M_ROOM_MEMBER.into(), "@alice:x".into()),
        make_event(
            "$j",
            M_ROOM_MEMBER,
            Some("@alice:x"),
            "@alice:x",
            json!({"membership": "join"}),
        ),
    );
    // NO m.room.power_levels in state — triggers the fallback at line 376-377

    let tpi = make_event(
        "$tpi",
        M_ROOM_THIRD_PARTY_INVITE,
        Some("token123"),
        "@alice:x",
        json!({"display_name": "charlie"}),
    );

    let result = rezzy::auth::check_auth(&tpi, &state, rezzy::StateResVersion::V2, None);
    assert!(
        result.is_ok(),
        "TPI with no PL event should succeed (default PL=0): {result:?}"
    );
}

// ── Regression tests: malformed m.room.member events ────────────────

/// Regression: m.room.member event with no `state_key` must be rejected
/// with `InvalidSyntax`, not silently authorized with `target_user`="".
#[test]
fn test_member_event_missing_state_key_rejected() {
    let mut state: RoomState = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@alice:x",
            json!({"creator": "@alice:x"}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@alice:x".into()),
        make_event(
            "$j",
            "m.room.member",
            Some("@alice:x"),
            "@alice:x",
            json!({"membership": "join"}),
        ),
    );

    // Member event with NO state_key
    let malformed = LeanEvent {
        event_id: "$bad".into(),
        event_type: "m.room.member".into(),
        state_key: None,
        sender: "@alice:x".into(),
        content: json!({"membership": "join"}),
        ..Default::default()
    };

    let result = rezzy::auth::check_auth(&malformed, &state, rezzy::StateResVersion::V2, None);
    assert!(
        result.is_err(),
        "Member event without state_key must be rejected: {result:?}"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("missing state_key"),
        "Error should mention missing state_key: {err_msg}"
    );
}

/// Regression: m.room.member event with no membership field must be
/// rejected with `InvalidSyntax`, not silently authorized with membership="".
#[test]
fn test_member_event_missing_membership_rejected() {
    let mut state: RoomState = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@alice:x",
            json!({"creator": "@alice:x"}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@alice:x".into()),
        make_event(
            "$j",
            "m.room.member",
            Some("@alice:x"),
            "@alice:x",
            json!({"membership": "join"}),
        ),
    );

    // Member event with state_key but NO membership in content
    let malformed = make_event(
        "$bad",
        "m.room.member",
        Some("@alice:x"),
        "@alice:x",
        json!({}), // empty content — no "membership" field
    );

    let result = rezzy::auth::check_auth(&malformed, &state, rezzy::StateResVersion::V2, None);
    assert!(
        result.is_err(),
        "Member event without membership field must be rejected: {result:?}"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("missing membership"),
        "Error should mention missing membership: {err_msg}"
    );
}

// ── Coverage: syntactic validation limits ────────────────────────────

/// Events with >20 `prev_events` must be rejected.
#[test]
fn test_prev_events_exceeds_max_rejected() {
    let mut state: RoomState = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@a:x",
            json!({"creator": "@a:x"}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@a:x".into()),
        make_event(
            "$j",
            "m.room.member",
            Some("@a:x"),
            "@a:x",
            json!({"membership": "join"}),
        ),
    );

    let too_many: Vec<String> = (0..21).map(|i| format!("$prev{i}")).collect();
    let event = LeanEvent {
        event_id: "$bad".into(),
        event_type: "m.room.message".into(),
        state_key: None,
        sender: "@a:x".into(),
        content: json!({"body": "hi"}),
        prev_events: too_many,
        ..Default::default()
    };

    let result = rezzy::auth::check_auth(&event, &state, rezzy::StateResVersion::V2, None);
    assert!(result.is_err(), "Should reject >20 prev_events: {result:?}");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("prev_events"),
        "Error should mention prev_events: {msg}"
    );
}

/// Events with >10 `auth_events` must be rejected.
#[test]
fn test_auth_events_exceeds_max_rejected() {
    let mut state: RoomState = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@a:x",
            json!({"creator": "@a:x"}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@a:x".into()),
        make_event(
            "$j",
            "m.room.member",
            Some("@a:x"),
            "@a:x",
            json!({"membership": "join"}),
        ),
    );

    let too_many: Vec<String> = (0..11).map(|i| format!("$auth{i}")).collect();
    let event = LeanEvent {
        event_id: "$bad".into(),
        event_type: "m.room.message".into(),
        state_key: None,
        sender: "@a:x".into(),
        content: json!({"body": "hi"}),
        auth_events: too_many,
        ..Default::default()
    };

    let result = rezzy::auth::check_auth(&event, &state, rezzy::StateResVersion::V2, None);
    assert!(result.is_err(), "Should reject >10 auth_events: {result:?}");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("auth_events"),
        "Error should mention auth_events: {msg}"
    );
}

/// Events with empty `event_type` must be rejected.
#[test]
fn test_empty_event_type_rejected() {
    let mut state: RoomState = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@a:x",
            json!({"creator": "@a:x"}),
        ),
    );
    state.insert(
        ("m.room.member".into(), "@a:x".into()),
        make_event(
            "$j",
            "m.room.member",
            Some("@a:x"),
            "@a:x",
            json!({"membership": "join"}),
        ),
    );

    let event = LeanEvent {
        event_id: "$bad".into(),
        event_type: String::new(), // empty!
        state_key: None,
        sender: "@a:x".into(),
        content: json!({"body": "hi"}),
        ..Default::default()
    };

    // check_auth path
    let result = rezzy::auth::check_auth(&event, &state, rezzy::StateResVersion::V2, None);
    assert!(
        result.is_err(),
        "Should reject empty event_type: {result:?}"
    );
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("event_type"),
        "Error should mention event_type: {msg}"
    );

    // validate_syntactic path
    let syntactic = event.validate_syntactic("11");
    assert!(syntactic.is_err());
    assert_eq!(syntactic.unwrap_err(), "event_type cannot be empty");
}

// ═══════════════════════════════════════════════════════════════════════════
// Rule 10: m.room.power_levels validation
// ═══════════════════════════════════════════════════════════════════════════

/// Rule 10.3: `users` map with a non-user-ID key should be rejected.
#[test]
fn test_pl_validation_users_invalid_key_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "10"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@admin:example.com", "sender": "@admin:example.com", "content": {"membership": "join"}}
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100}}}
"#,
    );
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl1", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100, "not_a_user_id": 50}}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_err(),
        "Invalid user ID key should be rejected: {res:?}"
    );
    let err = res.unwrap_err();
    assert!(
        matches!(err, crate::auth::AuthError::InvalidSyntax(ref s) if s.contains("not_a_user_id")),
        "Error should mention the bad key: {err:?}"
    );
}

/// Rule 10.6: sender tries to set `ban` higher than their own PL → reject.
#[test]
fn test_pl_validation_scalar_escalation_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "10"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@mod:example.com", "sender": "@mod:example.com", "content": {"membership": "join"}}
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}, "ban": 50}}
"#,
    );
    // Mod (PL 50) tries to raise `ban` to 60
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl1", "type": "m.room.power_levels", "state_key": "", "sender": "@mod:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}, "ban": 60}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_err(),
        "Mod raising ban above own PL should be rejected: {res:?}"
    );
}

/// Rule 10.6: sender sets `ban` to a value ≤ their PL → allow.
#[test]
fn test_pl_validation_scalar_change_allowed() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "10"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@mod:example.com", "sender": "@mod:example.com", "content": {"membership": "join"}}
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}, "ban": 40}}
"#,
    );
    // Mod (PL 50) changes `ban` from 40 to 50 — both ≤ 50, so allowed
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl1", "type": "m.room.power_levels", "state_key": "", "sender": "@mod:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}, "ban": 50}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_ok(),
        "Mod changing ban within own PL should be allowed: {res:?}"
    );
}

/// Rules 10.7–10.8: sender adds an `events` entry > their PL → reject.
#[test]
fn test_pl_validation_events_escalation_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "10"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@mod:example.com", "sender": "@mod:example.com", "content": {"membership": "join"}}
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}}}
"#,
    );
    // Mod (PL 50) adds events["m.room.topic"] = 60
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl1", "type": "m.room.power_levels", "state_key": "", "sender": "@mod:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}, "events": {"m.room.topic": 60}}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_err(),
        "Mod adding events entry above own PL should be rejected: {res:?}"
    );
}

/// Rule 10.10: sender promotes another user above their own PL → reject.
#[test]
fn test_pl_validation_users_promote_above_self_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "10"}}
{"event_id": "$join1", "type": "m.room.member", "state_key": "@mod:example.com", "sender": "@mod:example.com", "content": {"membership": "join"}}
{"event_id": "$join2", "type": "m.room.member", "state_key": "@user:example.com", "sender": "@user:example.com", "content": {"membership": "join"}}
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50, "@user:example.com": 0}}}
"#,
    );
    // Mod (PL 50) promotes user to 60
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl1", "type": "m.room.power_levels", "state_key": "", "sender": "@mod:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50, "@user:example.com": 60}}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_err(),
        "Mod promoting user above own PL should be rejected: {res:?}"
    );
}

/// Rule 10.9: sender tries to demote a user at equal PL → reject (uses >=).
#[test]
fn test_pl_validation_users_demote_equal_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "10"}}
{"event_id": "$join1", "type": "m.room.member", "state_key": "@mod1:example.com", "sender": "@mod1:example.com", "content": {"membership": "join"}}
{"event_id": "$join2", "type": "m.room.member", "state_key": "@mod2:example.com", "sender": "@mod2:example.com", "content": {"membership": "join"}}
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100, "@mod1:example.com": 50, "@mod2:example.com": 50}}}
"#,
    );
    // Mod1 (PL 50) tries to demote Mod2 (also PL 50) to 0
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl1", "type": "m.room.power_levels", "state_key": "", "sender": "@mod1:example.com", "content": {"users": {"@admin:example.com": 100, "@mod1:example.com": 50, "@mod2:example.com": 0}}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_err(),
        "Mod demoting equal-PL user should be rejected (>= check): {res:?}"
    );
}

/// Rule 10.9: sender demotes a user below their own PL → allow.
#[test]
fn test_pl_validation_users_demote_lower_allowed() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "10"}}
{"event_id": "$join1", "type": "m.room.member", "state_key": "@admin:example.com", "sender": "@admin:example.com", "content": {"membership": "join"}}
{"event_id": "$join2", "type": "m.room.member", "state_key": "@mod:example.com", "sender": "@mod:example.com", "content": {"membership": "join"}}
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}}}
"#,
    );
    // Admin (PL 100) demotes mod (PL 50) to 10 — 50 < 100, so allowed
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl1", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 10}}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_ok(),
        "Admin demoting lower-PL user should be allowed: {res:?}"
    );
}

/// Rule 10.9 exemption: sender lowers their own PL → allow (self-entry exempt).
#[test]
fn test_pl_validation_users_self_demote_allowed() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "10"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@admin:example.com", "sender": "@admin:example.com", "content": {"membership": "join"}}
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100}}}
"#,
    );
    // Admin demotes themselves from 100 to 50
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl1", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 50}}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(res.is_ok(), "Self-demotion should be allowed: {res:?}");
}

/// Rule 10.7: mod tries to change an `events` entry whose current value > mod's PL -> reject.
#[test]
fn test_pl_validation_events_old_value_too_high_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "10"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@mod:example.com", "sender": "@mod:example.com", "content": {"membership": "join"}}
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}, "events": {"m.room.topic": 80}}}
"#,
    );
    // Mod (PL 50) tries to lower events["m.room.topic"] from 80 to 30 — old value 80 > 50
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl1", "type": "m.room.power_levels", "state_key": "", "sender": "@mod:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}, "events": {"m.room.topic": 30}}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_err(),
        "Mod changing events entry with old value > own PL should be rejected: {res:?}"
    );
}

/// Rule 10.6: mod tries to change a scalar property whose current value > mod's PL → reject.
#[test]
fn test_pl_validation_scalar_old_value_too_high_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "10"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@mod:example.com", "sender": "@mod:example.com", "content": {"membership": "join"}}
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}, "kick": 80}}
"#,
    );
    // Mod (PL 50) tries to lower `kick` from 80 to 30 — old value 80 > 50
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl1", "type": "m.room.power_levels", "state_key": "", "sender": "@mod:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}, "kick": 30}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_err(),
        "Mod changing scalar with old value > own PL should be rejected: {res:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Rule 10 V12-only: 10.1, 10.2, 10.4
// ═══════════════════════════════════════════════════════════════════════════

/// Rule 10.1 (V12): scalar PL property that is not an integer → reject.
#[test]
fn test_pl_v12_scalar_not_integer_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "12"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@admin:example.com", "sender": "@admin:example.com", "content": {"membership": "join"}}
"#,
    );
    // First PL event with ban as a boolean instead of integer
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"ban": true}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        res.is_err(),
        "Non-integer scalar PL should be rejected in V12: {res:?}"
    );
}

/// Rule 10.1: non-integer scalar PL passes in room version 9 (pre-V10).
/// V10+ enforces integer types; V9 and earlier do not.
#[test]
fn test_pl_v2_scalar_not_integer_allowed() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "9"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@admin:example.com", "sender": "@admin:example.com", "content": {"membership": "join"}}
"#,
    );
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"ban": true}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_ok(),
        "Non-integer scalar PL should be allowed in room V9: {res:?}"
    );
}

/// Rule 2.4 / 10.1: `get_room_version_num` returns `Err(MissingCreate)` if
/// `m.room.create` is absent. This previously panicked but now gracefully
/// rejects the event — essential for state resolution over DAG forks where
/// the create event may not yet be in accumulated state.
#[test]
fn test_pl_missing_create_event_returns_error() {
    let state = utils::parse_jsonl_state(
        r#"{"event_id": "$join", "type": "m.room.member", "state_key": "@admin:example.com", "sender": "@admin:example.com", "content": {"membership": "join"}}"#,
    );
    let events = utils::parse_jsonl_events(
        r#"{"event_id": "$pl", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {}}"#,
    );
    let result = check_auth(&events[0], &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        matches!(result, Err(crate::auth::AuthError::MissingCreate)),
        "Missing create should return MissingCreate error, got: {result:?}"
    );
    // Exercise Display impl for coverage
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("m.room.create"));
}

#[test]
fn test_auth_missing_create_event_in_v2_room_state_with_context() {
    let state = RoomState::new();
    let provider: rezzy::HashMap<String, LeanEvent> = rezzy::HashMap::new();
    let event = make_event(
        "$pl",
        "m.room.power_levels",
        Some(""),
        "@admin:example.com",
        json!({}),
    );

    let result =
        check_auth_with_context(&event, &state, StateResVersion::V2, None, Some(&provider));
    assert!(
        matches!(result, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("missing m.room.create in room state"))
    );
}

/// Rule 10.2 (V12): `events` map with non-integer value → reject.
#[test]
fn test_pl_v12_events_map_non_integer_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "12"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@admin:example.com", "sender": "@admin:example.com", "content": {"membership": "join"}}
"#,
    );
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"events": {"m.room.topic": "not_a_number"}}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        res.is_err(),
        "Non-integer events map value should be rejected in V12: {res:?}"
    );
}

/// Rule 10.2 (V12): `events` is not an object → reject.
#[test]
fn test_pl_v12_events_not_object_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "12"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@admin:example.com", "sender": "@admin:example.com", "content": {"membership": "join"}}
"#,
    );
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"events": 42}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        res.is_err(),
        "events as non-object should be rejected in V12: {res:?}"
    );
}

/// Rule 10.4 (V12): `users` map contains the room creator → reject.
#[test]
fn test_pl_v12_users_contains_creator_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "12"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@admin:example.com", "sender": "@admin:example.com", "content": {"membership": "join"}}
"#,
    );
    // First PL event listing the creator in `users` — forbidden in V12
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100}}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        res.is_err(),
        "users containing creator should be rejected in V12: {res:?}"
    );
}

/// Rule 10.4 (V12): `users` map contains an `additional_creator` → reject.
#[test]
fn test_pl_v12_users_contains_additional_creator_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "12", "additional_creators": ["@extra:example.com"]}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@other:example.com", "sender": "@other:example.com", "content": {"membership": "join"}}
"#,
    );
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@other:example.com", "content": {"users": {"@other:example.com": 50, "@extra:example.com": 80}}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        res.is_err(),
        "users containing additional_creator should be rejected in V12: {res:?}"
    );
}

/// Rule 10.2 (V12): `notifications` map with non-integer value → reject.
#[test]
fn test_pl_v12_notifications_non_integer_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "12"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@admin:example.com", "sender": "@admin:example.com", "content": {"membership": "join"}}
"#,
    );
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"notifications": {"room": "not_a_number"}}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2_1, None);
    assert!(
        res.is_err(),
        "Non-integer notifications value should be rejected in V12: {res:?}"
    );
}

/// Rule 10.8: mod tries to set `notifications[room]` above own PL -> reject.
#[test]
fn test_pl_validation_notifications_escalation_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "10"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@mod:example.com", "sender": "@mod:example.com", "content": {"membership": "join"}}
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}}}
"#,
    );
    // Mod (PL 50) tries to set notifications["room"] to 80
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl1", "type": "m.room.power_levels", "state_key": "", "sender": "@mod:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}, "notifications": {"room": 80}}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_err(),
        "Setting notifications above own PL should be rejected: {res:?}"
    );
}

/// Rule 10.7: mod tries to lower `notifications[room]` whose old value > own PL -> reject.
#[test]
fn test_pl_validation_notifications_old_value_too_high_rejected() {
    let state = utils::parse_jsonl_state(
        r#"
{"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@admin:example.com", "content": {"creator": "@admin:example.com", "room_version": "10"}}
{"event_id": "$join", "type": "m.room.member", "state_key": "@mod:example.com", "sender": "@mod:example.com", "content": {"membership": "join"}}
{"event_id": "$pl0", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}, "notifications": {"room": 80}}}
"#,
    );
    // Mod (PL 50) tries to lower notifications["room"] from 80 to 30
    let events = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl1", "type": "m.room.power_levels", "state_key": "", "sender": "@mod:example.com", "content": {"users": {"@admin:example.com": 100, "@mod:example.com": 50}, "notifications": {"room": 30}}}
"#,
    );
    let res = check_auth(&events[0], &state, rezzy::StateResVersion::V2, None);
    assert!(
        res.is_err(),
        "Lowering notifications with old value > own PL should be rejected: {res:?}"
    );
}

#[test]
fn test_forward_extremity_validation_valid() {
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    state.insert(
        ("m.room.member".into(), "@alice:x.com".into()),
        make_event(
            "$j",
            "m.room.member",
            Some("@alice:x.com"),
            "@alice:x.com",
            json!({"membership": "join"}),
        ),
    );

    let event = make_event(
        "$msg",
        "m.room.message",
        None,
        "@alice:x.com",
        json!({"body": "hello"}),
    );

    // Pass same state for both to ensure it's valid
    let result =
        validate_forward_extremity(&event, &state, &state, rezzy::StateResVersion::V2_1, None);
    assert_eq!(result, ForwardExtremityResult::Valid);
}

#[test]
fn test_forward_extremity_validation_rejected() {
    let mut auth_state = RoomState::new();
    // No join event for alice in auth_state!
    auth_state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );

    let mut room_state = RoomState::new();
    room_state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );

    let event = make_event(
        "$msg",
        "m.room.message",
        None,
        "@alice:x.com",
        json!({"body": "hello"}),
    );

    // Fails the auth_events check -> Rejected
    let result = validate_forward_extremity(
        &event,
        &auth_state,
        &room_state,
        rezzy::StateResVersion::V2_1,
        None,
    );
    assert!(matches!(result, ForwardExtremityResult::Rejected(_)));
}

#[test]
fn test_forward_extremity_validation_soft_failed() {
    let mut auth_state = RoomState::new();
    // Alice is joined in auth_state
    auth_state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    auth_state.insert(
        ("m.room.member".into(), "@alice:x.com".into()),
        make_event(
            "$j",
            "m.room.member",
            Some("@alice:x.com"),
            "@alice:x.com",
            json!({"membership": "join"}),
        ),
    );

    let mut room_state = RoomState::new();
    // Alice is BANNED in room_state
    room_state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@admin:x.com", json!({})),
    );
    room_state.insert(
        ("m.room.member".into(), "@alice:x.com".into()),
        make_event(
            "$ban",
            "m.room.member",
            Some("@alice:x.com"),
            "@admin:x.com",
            json!({"membership": "ban"}),
        ),
    );

    let event = make_event(
        "$msg",
        "m.room.message",
        None,
        "@alice:x.com",
        json!({"body": "hello"}),
    );

    // Passes auth_state, fails room_state -> SoftFailed
    let result = validate_forward_extremity(
        &event,
        &auth_state,
        &room_state,
        rezzy::StateResVersion::V2_1,
        None,
    );
    assert!(matches!(result, ForwardExtremityResult::SoftFailed(_)));
}

#[test]
fn test_warn_unexpected_auth_events_v12_create() {
    let mut auth_context = std::collections::HashMap::new();
    let create_event = make_event(
        "$c",
        rezzy::basespec::event_types::M_ROOM_CREATE,
        Some(""),
        "@alice:x.com",
        json!({}),
    );
    auth_context.insert("$c".to_string(), create_event);

    let mut event = make_event(
        "$msg",
        "m.room.message",
        None,
        "@alice:x.com",
        json!({"body": "hello"}),
    );
    event.auth_events = vec!["$c".to_string()];

    // Should hit the v12+ m.room.create branch
    warn_unexpected_auth_events(&event, &auth_context, rezzy::StateResVersion::V2_1);
}

#[test]
fn test_warn_unexpected_auth_events_unexpected_type() {
    let mut auth_context = std::collections::HashMap::new();
    let unexpected_event = make_event(
        "$u",
        "m.room.message",
        None,
        "@alice:x.com",
        json!({"body": "hello"}),
    );
    auth_context.insert("$u".to_string(), unexpected_event);

    let mut event = make_event(
        "$msg2",
        "m.room.message",
        None,
        "@alice:x.com",
        json!({"body": "world"}),
    );
    event.auth_events = vec!["$u".to_string()];

    // Should hit the unexpected auth type branch
    warn_unexpected_auth_events(&event, &auth_context, rezzy::StateResVersion::V1);
}

#[test]
fn test_warn_unexpected_auth_events_valid() {
    let mut auth_context = std::collections::HashMap::new();
    let member_event = make_event(
        "$j",
        rezzy::basespec::event_types::M_ROOM_MEMBER,
        Some("@alice:x.com"),
        "@alice:x.com",
        json!({"membership": "join"}),
    );
    auth_context.insert("$j".to_string(), member_event);

    let mut event = make_event(
        "$msg3",
        "m.room.message",
        None,
        "@alice:x.com",
        json!({"body": "ok"}),
    );
    event.auth_events = vec!["$j".to_string()];

    // Should not hit any warnings
    warn_unexpected_auth_events(&event, &auth_context, rezzy::StateResVersion::V1);
}

#[test]
fn test_pl_v10_plus_users_contains_non_integer_rejected() {
    let cases = vec![
        ("10", rezzy::StateResVersion::V2),
        ("12", rezzy::StateResVersion::V2_1),
    ];
    for (version_str, state_res) in cases {
        let mut state = RoomState::new();
        state.insert(
            (M_ROOM_CREATE.into(), String::new()),
            make_event(
                "$c",
                rezzy::basespec::event_types::M_ROOM_CREATE,
                Some(""),
                "@admin:x.com",
                json!({"room_version": version_str}),
            ),
        );
        let pl = make_event(
            "$pl",
            rezzy::basespec::event_types::M_ROOM_POWER_LEVELS,
            Some(""),
            "@admin:x.com",
            json!({
                "users": {
                    "@alice:x.com": "50" // string instead of integer
                }
            }),
        );
        assert!(
            matches!(
                check_auth(&pl, &state, state_res, None),
                Err(AuthError::InvalidSyntax(_))
            ),
            "V10+ (version {version_str}) power levels with non-integer users value must be rejected"
        );
    }
}

/// Parameterized across room versions.
/// A coercible string `"50"` is accepted by V1-V9 (non-strict) but rejected by V10+ (strict).
/// A non-coercible string `"banana"` is rejected by ALL versions.
#[test]
fn test_pl_users_non_integer_across_versions() {
    use rezzy::StateResVersion;

    // (room_version, StateResVersion, coercible "50" allowed?)
    let versions = [
        ("1", StateResVersion::V1, true),
        ("6", StateResVersion::V2, true),
        ("9", StateResVersion::V2, true),
        ("10", StateResVersion::V2, false),
        ("11", StateResVersion::V2, false),
        ("12", StateResVersion::V2_1, false),
    ];

    for (room_ver, state_res, coercible_allowed) in versions {
        // Test coercible "50"
        let coercible = utils::parse_jsonl_events(&format!(
            r#"
{{"event_id":"$c","type":"m.room.create","state_key":"","sender":"@admin:x.com","depth":0,"origin_server_ts":1000,"content":{{"room_version":"{room_ver}"}},"prev_events":[],"auth_events":[]}}
{{"event_id":"$pl","type":"m.room.power_levels","state_key":"","sender":"@admin:x.com","depth":1,"origin_server_ts":1001,"content":{{"users":{{"@alice:x.com":"50"}}}},"prev_events":["$c"],"auth_events":["$c"]}}
            "#
        ));

        let mut state = RoomState::new();
        state.insert((M_ROOM_CREATE.into(), String::new()), coercible[0].clone());

        let result = check_auth(&coercible[1], &state, state_res, None);
        if coercible_allowed {
            assert!(
                result.is_ok(),
                "room v{room_ver}: coercible '50' should be accepted, got {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(AuthError::InvalidSyntax(_))),
                "room v{room_ver}: coercible '50' should be rejected (strict), got {result:?}"
            );
        }

        // Test non-coercible "banana" — must be rejected by ALL versions
        let non_coercible = utils::parse_jsonl_events(&format!(
            r#"
{{"event_id":"$c","type":"m.room.create","state_key":"","sender":"@admin:x.com","depth":0,"origin_server_ts":1000,"content":{{"room_version":"{room_ver}"}},"prev_events":[],"auth_events":[]}}
{{"event_id":"$pl","type":"m.room.power_levels","state_key":"","sender":"@admin:x.com","depth":1,"origin_server_ts":1001,"content":{{"users":{{"@alice:x.com":"banana"}}}},"prev_events":["$c"],"auth_events":["$c"]}}
            "#
        ));

        let mut state2 = RoomState::new();
        state2.insert(
            (M_ROOM_CREATE.into(), String::new()),
            non_coercible[0].clone(),
        );

        let result2 = check_auth(&non_coercible[1], &state2, state_res, None);
        assert!(
            matches!(result2, Err(AuthError::InvalidSyntax(_))),
            "room v{room_ver}: non-coercible 'banana' must always be rejected, got {result2:?}"
        );
    }
}

#[test]
fn test_pl_v10_plus_users_not_an_object_rejected() {
    let cases = vec![
        ("10", rezzy::StateResVersion::V2),
        ("12", rezzy::StateResVersion::V2_1),
    ];
    for (version_str, state_res) in cases {
        let mut state = RoomState::new();
        state.insert(
            (M_ROOM_CREATE.into(), String::new()),
            make_event(
                "$c",
                rezzy::basespec::event_types::M_ROOM_CREATE,
                Some(""),
                "@admin:x.com",
                json!({"room_version": version_str}),
            ),
        );
        let pl = make_event(
            "$pl",
            rezzy::basespec::event_types::M_ROOM_POWER_LEVELS,
            Some(""),
            "@admin:x.com",
            json!({
                "users": ["@alice:x.com"] // array instead of object
            }),
        );
        assert!(
            matches!(
                check_auth(&pl, &state, state_res, None),
                Err(AuthError::InvalidSyntax(_))
            ),
            "V10+ (version {version_str}) power levels with non-object users must be rejected"
        );
    }
}

#[test]
fn test_auth_types_for_event_join_authorised_via_users_server() {
    let content = json!({
        "membership": "join",
        "join_authorised_via_users_server": "@admin:x.com"
    });
    let types = auth_types_for_event(
        "m.room.member",
        "@alice:x.com",
        Some("@alice:x.com"),
        &content,
        StateResVersion::V2_1,
    );
    assert!(types.contains(&("m.room.member".to_string(), "@admin:x.com".to_string())));
}

#[test]
fn test_domain_parsing_helpers() {
    use rezzy::basespec::rezzy_types::{domain_matches, extract_domain};
    assert_eq!(extract_domain("@alice:example.com"), Some("example.com"));
    assert_eq!(
        extract_domain("!room:matrix.org:8448"),
        Some("matrix.org:8448")
    );
    assert_eq!(extract_domain("$ev:foo.bar"), Some("foo.bar"));
    assert_eq!(extract_domain("example.com"), None);

    assert!(domain_matches("@alice:example.com", "@bob:EXAMPLE.COM"));
    assert!(domain_matches("example.com", "@bob:example.com"));
    assert!(!domain_matches("@alice:foo.com", "@bob:bar.com"));
}

#[test]
fn test_rule_1_2_create_invalid_sender_mxid() {
    let state = RoomState::new();
    let create_ev = make_event(
        "$c",
        M_ROOM_CREATE,
        Some(""),
        "invalid_no_domain",
        json!({"room_version": "10"}),
    );
    let res = check_auth(&create_ev, &state, StateResVersion::V2, None);
    assert!(matches!(res, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("valid MXID")));
}

#[test]
fn test_rule_3_m_federate_false_cross_domain_rejected() {
    use rezzy::basespec::event_types::M_ROOM_MEMBER;
    let mut state = RoomState::new();
    let create_ev = make_event(
        "$c",
        M_ROOM_CREATE,
        Some(""),
        "@admin:example.com",
        json!({"m.federate": false}),
    );
    state.insert((M_ROOM_CREATE.into(), String::new()), create_ev);

    let cross_domain_msg = make_event(
        "$msg",
        "m.room.message",
        None,
        "@evil:otherdomain.com",
        json!({"body": "hi"}),
    );
    let res = check_auth(&cross_domain_msg, &state, StateResVersion::V2, None);
    assert!(
        matches!(res, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("m.federate=false")),
        "Cross-domain event must be rejected when m.federate is false, got {res:?}"
    );

    let same_domain_join = make_event(
        "$join",
        M_ROOM_MEMBER,
        Some("@bob:example.com"),
        "@bob:example.com",
        json!({"membership": "join"}),
    );
    // Same domain should pass m.federate check (fails next on PL/state if unjoined, but passes m.federate)
    let res2 = check_auth(&same_domain_join, &state, StateResVersion::V2, None);
    assert!(
        !matches!(res2, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("m.federate=false"))
    );
}

#[test]
fn test_rule_4_aliases_domain_mismatch_v1_rejected() {
    use rezzy::basespec::event_types::M_ROOM_MEMBER;
    let mut state = RoomState::new();
    let create_ev = make_event(
        "$c",
        M_ROOM_CREATE,
        Some(""),
        "@admin:example.com",
        json!({"room_version": "1"}),
    );
    state.insert((M_ROOM_CREATE.into(), String::new()), create_ev);

    let member_ev = make_event(
        "$m",
        M_ROOM_MEMBER,
        Some("@admin:example.com"),
        "@admin:example.com",
        json!({"membership": "join"}),
    );
    state.insert(
        (M_ROOM_MEMBER.into(), "@admin:example.com".into()),
        member_ev,
    );

    let bad_alias = make_event(
        "$alias",
        "m.room.aliases",
        Some("otherdomain.com"),
        "@admin:example.com",
        json!({"aliases": ["#test:otherdomain.com"]}),
    );
    let res = check_auth(&bad_alias, &state, StateResVersion::V1, None);
    assert!(
        matches!(res, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("m.room.aliases state_key domain must match")),
        "Alias event with domain mismatch in V1 must be rejected, got {res:?}"
    );

    let good_alias = make_event(
        "$alias2",
        "m.room.aliases",
        Some("example.com"),
        "@admin:example.com",
        json!({"aliases": ["#test:example.com"]}),
    );
    let res_good = check_auth(&good_alias, &state, StateResVersion::V1, None);
    assert!(
        res_good.is_ok(),
        "Matching domain alias event in V1 should be accepted"
    );
}

#[test]
fn test_rule_4_aliases_enforced_v2_through_v5_not_v6_plus() {
    use rezzy::basespec::event_types::M_ROOM_MEMBER;

    // Room versions 2-5 all resolve to StateResVersion::V2, but Rule 4 must
    // still be enforced for each of them individually (it's only removed
    // starting real room version 6, per v6.txt).
    for room_version in ["2", "3", "4", "5"] {
        let mut state = RoomState::new();
        let create_ev = make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@admin:example.com",
            json!({"room_version": room_version}),
        );
        state.insert((M_ROOM_CREATE.into(), String::new()), create_ev);
        state.insert(
            (M_ROOM_MEMBER.into(), "@admin:example.com".into()),
            make_event(
                "$m",
                M_ROOM_MEMBER,
                Some("@admin:example.com"),
                "@admin:example.com",
                json!({"membership": "join"}),
            ),
        );

        let bad_alias = make_event(
            "$alias",
            "m.room.aliases",
            Some("otherdomain.com"),
            "@admin:example.com",
            json!({"aliases": ["#test:otherdomain.com"]}),
        );
        let res = check_auth(&bad_alias, &state, StateResVersion::V2, None);
        assert!(
            matches!(res, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("m.room.aliases state_key domain must match")),
            "room_version {room_version}: alias domain mismatch must be rejected, got {res:?}"
        );
    }

    // Room version 6+ removes Rule 4 entirely; a domain mismatch must no
    // longer be rejected by this check.
    for room_version in ["6", "7", "10"] {
        let mut state = RoomState::new();
        let create_ev = make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@admin:example.com",
            json!({"room_version": room_version}),
        );
        state.insert((M_ROOM_CREATE.into(), String::new()), create_ev);
        state.insert(
            (M_ROOM_MEMBER.into(), "@admin:example.com".into()),
            make_event(
                "$m",
                M_ROOM_MEMBER,
                Some("@admin:example.com"),
                "@admin:example.com",
                json!({"membership": "join"}),
            ),
        );

        let mismatched_alias = make_event(
            "$alias",
            "m.room.aliases",
            Some("otherdomain.com"),
            "@admin:example.com",
            json!({"aliases": ["#test:otherdomain.com"]}),
        );
        let res = check_auth(&mismatched_alias, &state, StateResVersion::V2, None);
        assert!(
            res.is_ok(),
            "room_version {room_version}: Rule 4 is removed, domain mismatch should be allowed, got {res:?}"
        );
    }
}

#[test]
fn test_rule_4_aliases_missing_state_key_rejected() {
    use rezzy::basespec::event_types::M_ROOM_MEMBER;
    let mut state = RoomState::new();
    let create_ev = make_event(
        "$c",
        M_ROOM_CREATE,
        Some(""),
        "@admin:example.com",
        json!({"room_version": "1"}),
    );
    state.insert((M_ROOM_CREATE.into(), String::new()), create_ev);
    state.insert(
        (M_ROOM_MEMBER.into(), "@admin:example.com".into()),
        make_event(
            "$m",
            M_ROOM_MEMBER,
            Some("@admin:example.com"),
            "@admin:example.com",
            json!({"membership": "join"}),
        ),
    );

    let no_state_key_alias = make_event(
        "$alias",
        "m.room.aliases",
        None,
        "@admin:example.com",
        json!({"aliases": ["#test:example.com"]}),
    );
    let res = check_auth(&no_state_key_alias, &state, StateResVersion::V1, None);
    assert!(
        matches!(res, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("m.room.aliases event must have a state_key")),
        "m.room.aliases without a state_key must be rejected, got {res:?}"
    );
}

/// Builds room state (v1 by default) with a creator and a joined `@bob:domain1.com`.
fn rule_11_base_state(room_version: &str) -> RoomState {
    use rezzy::basespec::event_types::M_ROOM_MEMBER;
    let mut state = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event(
            "$c",
            M_ROOM_CREATE,
            Some(""),
            "@admin:domain1.com",
            json!({"room_version": room_version}),
        ),
    );
    state.insert(
        (M_ROOM_MEMBER.into(), "@bob:domain1.com".into()),
        make_event(
            "$bob_join",
            M_ROOM_MEMBER,
            Some("@bob:domain1.com"),
            "@bob:domain1.com",
            json!({"membership": "join"}),
        ),
    );
    state
}

#[test]
fn test_rule_11_redaction_insufficient_pl_different_domain_rejected() {
    let state = rule_11_base_state("1");
    // Bob has no explicit PL (default 0, below the default redact level of
    // 50), and the redacted event is on a different domain.
    let redaction = make_event(
        "$redact:domain1.com",
        "m.room.redaction",
        None,
        "@bob:domain1.com",
        json!({"redacts": "$target:domain2.com"}),
    );
    let res = check_auth(&redaction, &state, StateResVersion::V1, None);
    assert!(
        matches!(res, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("m.room.redaction requires sender PL")),
        "Redaction with insufficient PL and a different domain must be rejected, got {res:?}"
    );
}

#[test]
fn test_rule_11_redaction_insufficient_pl_same_domain_allowed() {
    let state = rule_11_base_state("1");
    // Same domain as the redacted event allows it despite insufficient PL.
    let redaction = make_event(
        "$redact:domain1.com",
        "m.room.redaction",
        None,
        "@bob:domain1.com",
        json!({"redacts": "$target:domain1.com"}),
    );
    let res = check_auth(&redaction, &state, StateResVersion::V1, None);
    assert!(
        res.is_ok(),
        "Redaction of an event on the same domain must be allowed, got {res:?}"
    );
}

#[test]
fn test_rule_11_redaction_sufficient_pl_different_domain_allowed() {
    use rezzy::basespec::event_types::M_ROOM_POWER_LEVELS;
    let mut state = rule_11_base_state("1");
    state.insert(
        (M_ROOM_POWER_LEVELS.into(), String::new()),
        make_event(
            "$pl",
            M_ROOM_POWER_LEVELS,
            Some(""),
            "@admin:domain1.com",
            json!({"redact": 50, "users": {"@bob:domain1.com": 50}}),
        ),
    );
    let redaction = make_event(
        "$redact:domain1.com",
        "m.room.redaction",
        None,
        "@bob:domain1.com",
        json!({"redacts": "$target:domain2.com"}),
    );
    let res = check_auth(&redaction, &state, StateResVersion::V1, None);
    assert!(
        res.is_ok(),
        "Redaction with sender PL >= redact level must be allowed regardless of domain, got {res:?}"
    );
}

#[test]
fn test_rule_11_redaction_not_enforced_v3_plus() {
    let state = rule_11_base_state("3");
    // Same conditions that would be rejected under v1-v2 (insufficient PL,
    // different domain) must not be rejected by Rule 11 in v3+, since the
    // rule was removed starting v3.
    let redaction = make_event(
        "$redact:domain1.com",
        "m.room.redaction",
        None,
        "@bob:domain1.com",
        json!({"redacts": "$target:domain2.com"}),
    );
    let res = check_auth(&redaction, &state, StateResVersion::V2, None);
    assert!(
        !matches!(res, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("m.room.redaction requires sender PL")),
        "Rule 11 must not apply in v3+, got {res:?}"
    );
}

#[test]
fn test_rule_2_1_duplicate_auth_event_pair_rejected() {
    use rezzy::basespec::event_types::M_ROOM_MEMBER;
    let mut state = RoomState::new();
    let create_ev = make_event(
        "$c",
        M_ROOM_CREATE,
        Some(""),
        "@admin:example.com",
        json!({}),
    );
    state.insert((M_ROOM_CREATE.into(), String::new()), create_ev.clone());

    let member1 = make_event(
        "$m1",
        M_ROOM_MEMBER,
        Some("@admin:example.com"),
        "@admin:example.com",
        json!({"membership": "join"}),
    );
    let member2 = make_event(
        "$m2",
        M_ROOM_MEMBER,
        Some("@admin:example.com"),
        "@admin:example.com",
        json!({"membership": "join"}),
    );

    let mut provider = rezzy::HashMap::new();
    provider.insert("$c".to_string(), create_ev);
    provider.insert("$m1".to_string(), member1);
    provider.insert("$m2".to_string(), member2);

    let mut msg = make_event(
        "$msg",
        "m.room.message",
        None,
        "@admin:example.com",
        json!({"body": "dup"}),
    );
    msg.auth_events = vec!["$c".into(), "$m1".into(), "$m2".into()];

    let res = check_auth_with_context(&msg, &state, StateResVersion::V2, None, Some(&provider));
    assert!(
        matches!(res, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("duplicate (type, state_key)")),
        "Duplicate auth events of same type and state_key must be rejected, got {res:?}"
    );
}

#[test]
fn test_rule_2_2_invalid_auth_event_type_and_v12_create() {
    let mut state = RoomState::new();
    let create_ev = make_event(
        "$c",
        M_ROOM_CREATE,
        Some(""),
        "@admin:example.com",
        json!({}),
    );
    state.insert((M_ROOM_CREATE.into(), String::new()), create_ev.clone());

    let msg_as_auth = make_event(
        "$invalid_auth",
        "m.room.message",
        None,
        "@admin:example.com",
        json!({"body": "invalid"}),
    );

    let mut provider = rezzy::HashMap::new();
    provider.insert("$c".to_string(), create_ev);
    provider.insert("$invalid_auth".to_string(), msg_as_auth);

    let mut msg = make_event(
        "$msg",
        "m.room.name",
        Some(""),
        "@admin:example.com",
        json!({"name": "test"}),
    );
    msg.auth_events = vec!["$c".into(), "$invalid_auth".into()];

    let res = check_auth_with_context(&msg, &state, StateResVersion::V2, None, Some(&provider));
    assert!(
        matches!(res, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("unexpected event type in auth_events")),
        "Unexpected event type in auth_events must be rejected, got {res:?}"
    );

    // In V12+ (V2_1), referencing m.room.create in auth_events is forbidden
    let mut msg_v12 = make_event(
        "$msg2",
        "m.room.name",
        Some(""),
        "@admin:example.com",
        json!({"name": "test"}),
    );
    msg_v12.auth_events = vec!["$c".into()];
    let res_v12 = check_auth_with_context(
        &msg_v12,
        &state,
        StateResVersion::V2_1,
        None,
        Some(&provider),
    );
    assert!(
        matches!(res_v12, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("forbidden in room v12+")),
        "Referencing m.room.create in v12+ auth_events must be rejected, got {res_v12:?}"
    );
}

#[test]
fn test_rule_2_3_rejected_auth_event() {
    use rezzy::basespec::event_types::M_ROOM_MEMBER;
    let mut state = RoomState::new();
    let create_ev = make_event(
        "$c",
        M_ROOM_CREATE,
        Some(""),
        "@admin:example.com",
        json!({}),
    );
    state.insert((M_ROOM_CREATE.into(), String::new()), create_ev.clone());

    let mut rejected_member = make_event(
        "$rej_m",
        M_ROOM_MEMBER,
        Some("@bob:example.com"),
        "@bob:example.com",
        json!({"membership": "join"}),
    );
    rejected_member.rejected = true;

    let mut provider = rezzy::HashMap::new();
    provider.insert("$c".to_string(), create_ev);
    provider.insert("$rej_m".to_string(), rejected_member);

    let mut msg = make_event(
        "$msg",
        "m.room.message",
        None,
        "@bob:example.com",
        json!({"body": "test"}),
    );
    msg.auth_events = vec!["$c".into(), "$rej_m".into()];

    let res = check_auth_with_context(&msg, &state, StateResVersion::V2, None, Some(&provider));
    assert!(
        matches!(res, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("was previously rejected")),
        "Auth check must reject when an auth_event was previously rejected, got {res:?}"
    );
}

#[test]
fn test_rule_2_4_missing_create_in_v1_v11_auth_events() {
    use rezzy::basespec::event_types::M_ROOM_MEMBER;
    let mut state = RoomState::new();
    let create_ev = make_event(
        "$c",
        M_ROOM_CREATE,
        Some(""),
        "@admin:example.com",
        json!({}),
    );
    state.insert((M_ROOM_CREATE.into(), String::new()), create_ev.clone());

    let member_ev = make_event(
        "$m",
        M_ROOM_MEMBER,
        Some("@admin:example.com"),
        "@admin:example.com",
        json!({"membership": "join"}),
    );
    state.insert(
        (M_ROOM_MEMBER.into(), "@admin:example.com".into()),
        member_ev,
    );

    let mut provider = rezzy::HashMap::new();
    provider.insert("$c".to_string(), create_ev);

    let msg_missing_create = make_event(
        "$msg",
        "m.room.message",
        None,
        "@admin:example.com",
        json!({"body": "test"}),
    );
    let res = check_auth_with_context(
        &msg_missing_create,
        &state,
        StateResVersion::V2,
        None,
        Some(&provider),
    );
    assert!(
        matches!(res, Err(AuthError::InvalidSyntax(ref msg)) if msg.contains("must contain m.room.create")),
        "Pre-v12 events missing m.room.create in auth_events must be rejected when auth_context is supplied, got {res:?}"
    );
}

#[test]
fn test_auth_events_unresolved_by_provider_returns_missing_auth_event() {
    let mut state = RoomState::new();
    let create_ev = make_event(
        "$c",
        M_ROOM_CREATE,
        Some(""),
        "@admin:example.com",
        json!({}),
    );
    state.insert((M_ROOM_CREATE.into(), String::new()), create_ev.clone());

    // Provider only knows about $c; $ghost is referenced in auth_events but
    // cannot be resolved, so it must hard-fail with MissingAuthEvent instead
    // of being silently skipped.
    let mut provider = rezzy::HashMap::new();
    provider.insert("$c".to_string(), create_ev);

    let mut msg = make_event(
        "$msg",
        "m.room.message",
        None,
        "@admin:example.com",
        json!({"body": "hi"}),
    );
    msg.auth_events = vec!["$c".into(), "$ghost".into()];

    let res = check_auth_with_context(&msg, &state, StateResVersion::V2, None, Some(&provider));
    assert_eq!(
        res,
        Err(AuthError::MissingAuthEvent("$ghost".to_string())),
        "Unresolvable auth_id must return MissingAuthEvent, got {res:?}"
    );
}

#[test]
fn test_event_content_default_get_m_federate() {
    use rezzy::basespec::rezzy_types::EventContent;

    #[derive(Clone, Debug, Default)]
    struct DummyContent;

    impl EventContent for DummyContent {
        fn get_membership(&self) -> Option<&str> {
            None
        }
        fn get_third_party_invite_token(&self) -> Option<&str> {
            None
        }
        fn get_join_rule(&self) -> Option<&str> {
            None
        }
        fn get_user_power_level(&self, _user: &str) -> Option<i64> {
            None
        }
        fn get_event_power_level(&self, _event_type: &str) -> Option<i64> {
            None
        }
        fn get_users_default(&self) -> Option<i64> {
            None
        }
        fn get_events_default(&self) -> Option<i64> {
            None
        }
        fn get_state_default(&self) -> Option<i64> {
            None
        }
        fn get_ban(&self) -> Option<i64> {
            None
        }
        fn get_kick(&self) -> Option<i64> {
            None
        }
        fn get_invite(&self) -> Option<i64> {
            None
        }
        fn get_redact(&self) -> Option<i64> {
            None
        }
        fn get_creator(&self) -> Option<&str> {
            None
        }
        fn has_additional_creator(&self, _sender: &str) -> bool {
            false
        }
        fn get_join_authorised_via_users_server(&self) -> Option<&str> {
            None
        }
        fn visit_event_power_levels<'a>(&'a self, _: &mut dyn FnMut(&'a str, i64)) {}
        fn visit_user_power_levels<'a>(&'a self, _: &mut dyn FnMut(&'a str, i64)) {}
        fn visit_notification_power_levels<'a>(&'a self, _: &mut dyn FnMut(&'a str, i64)) {}
        fn visit_user_keys<'a>(&'a self, _: &mut dyn FnMut(&'a str)) {}
    }

    let dummy = DummyContent;
    assert_eq!(dummy.get_m_federate(), None);
}
