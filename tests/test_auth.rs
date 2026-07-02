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
        matches!(result, Err(rezzy::auth::AuthError::InsufficientPowerLevel { .. })),
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
        make_event("$c", M_ROOM_CREATE, Some(""), "@a:x", json!({"creator": "@a:x"})),
    );
    state.insert(
        ("m.room.member".into(), "@a:x".into()),
        make_event("$j", "m.room.member", Some("@a:x"), "@a:x", json!({"membership": "join"})),
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
    assert!(msg.contains("prev_events"), "Error should mention prev_events: {msg}");
}

/// Events with >10 `auth_events` must be rejected.
#[test]
fn test_auth_events_exceeds_max_rejected() {
    let mut state: RoomState = RoomState::new();
    state.insert(
        (M_ROOM_CREATE.into(), String::new()),
        make_event("$c", M_ROOM_CREATE, Some(""), "@a:x", json!({"creator": "@a:x"})),
    );
    state.insert(
        ("m.room.member".into(), "@a:x".into()),
        make_event("$j", "m.room.member", Some("@a:x"), "@a:x", json!({"membership": "join"})),
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
    assert!(msg.contains("auth_events"), "Error should mention auth_events: {msg}");
}
