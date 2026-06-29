use rezzy::auth::*;
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
    let (accepted, rejected) = check_auth_chain(&[create, join, msg], &RoomState::new());
    assert_eq!(accepted, vec!["$create", "$join", "$msg"]);
    assert!(rejected.is_empty());
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

#[test]
fn test_moderator_can_override_admin_ban() {
    let mut state = RoomState::new();

    // Create event
    state.insert(
        ("m.room.create".into(), Some(String::new())),
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
        ("m.room.power_levels".into(), Some(String::new())),
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
        ("m.room.member".into(), Some("@admin:example.com".into())),
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
        ("m.room.member".into(), Some("@mod:example.com".into())),
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
        ("m.room.member".into(), Some("@target:example.com".into())),
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
    let result = check_auth(&mod_kick, &state);
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
        ("m.room.create".into(), Some(String::new())),
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
        ("m.room.power_levels".into(), Some(String::new())),
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
        ("m.room.member".into(), Some("@mod:example.com".into())),
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
        ("m.room.member".into(), Some("@target:example.com".into())),
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
    let result = check_auth(&mod_unban, &state);
    assert!(result.is_ok(), "Expected Ok(()), got {result:?}");
}

#[test]
fn test_equal_power_invite_override_allowed() {
    let mut state = RoomState::new();

    // Create event
    state.insert(
        ("m.room.create".into(), Some(String::new())),
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
        ("m.room.power_levels".into(), Some(String::new())),
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
        ("m.room.member".into(), Some("@mod1:example.com".into())),
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
        ("m.room.member".into(), Some("@mod2:example.com".into())),
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
        ("m.room.member".into(), Some("@target:example.com".into())),
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
    let result = check_auth(&mod2_invite, &state);
    assert!(result.is_ok(), "Expected Ok(()), got {result:?}");

    // Target is now banned by @mod1 (PL 50)
    state.insert(
        ("m.room.member".into(), Some("@target:example.com".into())),
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
    let result = check_auth(&mod2_invite_banned, &state);
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
fn test_unban_succeeds_when_kick_pl_exceeds_ban_pl() {
    let mut state = RoomState::new();

    state.insert(
        ("m.room.create".into(), Some(String::new())),
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
        ("m.room.power_levels".into(), Some(String::new())),
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
        ("m.room.member".into(), Some("@mod:example.com".into())),
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
        ("m.room.member".into(), Some("@target:example.com".into())),
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
    let result = check_auth(&unban, &state);
    assert!(
        result.is_ok(),
        "Unban should succeed when sender PL (50) >= ban_pl (30), \
         even though sender PL < kick_pl (60). Got {result:?}"
    );

    // Verify that kick still requires kick_pl: change target to "join" (not banned)
    state.insert(
        ("m.room.member".into(), Some("@target:example.com".into())),
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
    let result = check_auth(&kick, &state);
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
