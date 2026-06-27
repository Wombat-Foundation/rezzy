use ruma_lean::auth::*;
use ruma_lean::*;
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
fn test_create_event_no_prev_events() {
    let create = make_event(
        "$create",
        "m.room.create",
        Some(""),
        "@alice:example.com",
        json!({}),
    );
    let state = RoomState::new();
    assert!(check_auth(&create, &state).is_ok());
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
    let state = RoomState::new();
    assert_eq!(
        check_auth(&create, &state),
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
    let state = RoomState::new();
    assert!(matches!(
        check_auth(&msg, &state),
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
        ("m.room.member".into(), Some("@alice:example.com".into())),
        make_event(
            "$join",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
        ),
    );
    assert!(check_auth(&msg, &state).is_ok());
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
        ("m.room.member".into(), Some("@alice:example.com".into())),
        make_event(
            "$ban",
            "m.room.member",
            Some("@alice:example.com"),
            "@admin:example.com",
            json!({"membership": "ban"}),
        ),
    );
    assert!(matches!(
        check_auth(&msg, &state),
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
        ("m.room.member".into(), Some("@alice:example.com".into())),
        make_event(
            "$join",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
        ),
    );
    state.insert(
        ("m.room.power_levels".into(), Some(String::new())),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@admin:example.com",
            json!({"state_default": 50, "users": {"@admin:example.com": 100}}),
        ),
    );
    assert!(matches!(
        check_auth(&msg, &state),
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
    let state = RoomState::new();
    assert!(matches!(
        check_auth(&join, &state),
        Err(AuthError::InvalidStateKey { .. })
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
    let (accepted, rejected) = check_auth_chain(&[create, join, msg], &RoomState::new());
    assert_eq!(accepted, vec!["$create", "$join", "$msg"]);
    assert!(rejected.is_empty());
}

#[test]
fn test_auth_error_display() {
    let err = AuthError::NotMember {
        sender: "@bob:example.com".into(),
        event_id: "$unused".into(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("bob"));
}
