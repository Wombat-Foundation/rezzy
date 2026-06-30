//! Tests for restricted and `knock_restricted` join rule support.
//!
//! Previously, rezzy's `check_auth` only handled `public`, `invite`, and `knock`
//! join rules. `restricted` (V8+) and `knock_restricted` (V10+) join rules were
//! rejected with `NotMember` errors. These tests verify the fix.

use rezzy::auth::{check_auth, RoomState};
use rezzy::{LeanEvent, StateResVersion};
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
        state_key: state_key.map(Into::into),
        sender: sender.into(),
        content,
        ..Default::default()
    }
}

/// Set up a standard room state with a create event, power levels, and
/// join rules set to the given rule.
fn room_with_join_rule(join_rule: &str) -> RoomState {
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

    state.insert(
        ("m.room.member".into(), "@admin:example.com".into()),
        make_event(
            "$admin_join",
            "m.room.member",
            Some("@admin:example.com"),
            "@admin:example.com",
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
            json!({
                "users": {"@admin:example.com": 100},
                "users_default": 0,
                "events_default": 0,
                "state_default": 50,
            }),
        ),
    );

    state.insert(
        ("m.room.join_rules".into(), String::new()),
        make_event(
            "$jr",
            "m.room.join_rules",
            Some(""),
            "@admin:example.com",
            json!({
                "join_rule": join_rule,
                "allow": [
                    {"type": "m.room_membership", "room_id": "!other:example.com"}
                ]
            }),
        ),
    );

    state
}

// ─── Restricted join rules (room version 8+) ────────────────────────────

#[test]
fn test_restricted_join_with_invite_allowed() {
    // A user who is already invited should be allowed to join a restricted room.
    let mut state = room_with_join_rule("restricted");

    // User has an outstanding invite
    state.insert(
        ("m.room.member".into(), "@bob:example.com".into()),
        make_event(
            "$invite_bob",
            "m.room.member",
            Some("@bob:example.com"),
            "@admin:example.com",
            json!({"membership": "invite"}),
        ),
    );

    let join_event = make_event(
        "$bob_join",
        "m.room.member",
        Some("@bob:example.com"),
        "@bob:example.com",
        json!({"membership": "join"}),
    );

    let result = check_auth(&join_event, &state, StateResVersion::V2);
    assert!(
        result.is_ok(),
        "invited user should be able to join a restricted room, got: {result:?}"
    );
}

#[test]
fn test_restricted_join_with_authorized_via_allowed() {
    // A user joining via `join_authorised_via_users_server` should be allowed.
    let state = room_with_join_rule("restricted");

    // No invite, but has join_authorised_via_users_server
    let join_event = make_event(
        "$bob_join",
        "m.room.member",
        Some("@bob:example.com"),
        "@bob:example.com",
        json!({
            "membership": "join",
            "join_authorised_via_users_server": "@admin:example.com"
        }),
    );

    let result = check_auth(&join_event, &state, StateResVersion::V2);
    assert!(
        result.is_ok(),
        "user with join_authorised_via_users_server should be able to join restricted room, got: {result:?}"
    );
}

#[test]
fn test_restricted_join_without_invite_or_authorized_rejected() {
    // A user with no invite and no join_authorised_via_users_server should be rejected.
    let state = room_with_join_rule("restricted");

    let join_event = make_event(
        "$bob_join",
        "m.room.member",
        Some("@bob:example.com"),
        "@bob:example.com",
        json!({"membership": "join"}),
    );

    let result = check_auth(&join_event, &state, StateResVersion::V2);
    assert!(
        result.is_err(),
        "user without invite or authorized_via must be rejected from restricted room"
    );
}

// ─── Knock-restricted join rules (room version 10+) ─────────────────────

#[test]
fn test_knock_restricted_join_with_invite_allowed() {
    let mut state = room_with_join_rule("knock_restricted");

    state.insert(
        ("m.room.member".into(), "@carol:example.com".into()),
        make_event(
            "$invite_carol",
            "m.room.member",
            Some("@carol:example.com"),
            "@admin:example.com",
            json!({"membership": "invite"}),
        ),
    );

    let join_event = make_event(
        "$carol_join",
        "m.room.member",
        Some("@carol:example.com"),
        "@carol:example.com",
        json!({"membership": "join"}),
    );

    let result = check_auth(&join_event, &state, StateResVersion::V2);
    assert!(
        result.is_ok(),
        "invited user should be able to join knock_restricted room, got: {result:?}"
    );
}

#[test]
fn test_knock_restricted_join_with_authorized_via_allowed() {
    let state = room_with_join_rule("knock_restricted");

    let join_event = make_event(
        "$carol_join",
        "m.room.member",
        Some("@carol:example.com"),
        "@carol:example.com",
        json!({
            "membership": "join",
            "join_authorised_via_users_server": "@admin:example.com"
        }),
    );

    let result = check_auth(&join_event, &state, StateResVersion::V2);
    assert!(
        result.is_ok(),
        "user with join_authorised_via_users_server should join knock_restricted room, got: {result:?}"
    );
}

#[test]
fn test_knock_restricted_knock_allowed() {
    // In knock_restricted, knocking should be allowed (same as knock).
    let state = room_with_join_rule("knock_restricted");

    let knock_event = make_event(
        "$dave_knock",
        "m.room.member",
        Some("@dave:example.com"),
        "@dave:example.com",
        json!({"membership": "knock"}),
    );

    let result = check_auth(&knock_event, &state, StateResVersion::V2);
    assert!(
        result.is_ok(),
        "knocking should be allowed in knock_restricted room, got: {result:?}"
    );
}

#[test]
fn test_restricted_knock_rejected() {
    // In `restricted` (not knock_restricted), knocking should NOT be allowed.
    let state = room_with_join_rule("restricted");

    let knock_event = make_event(
        "$dave_knock",
        "m.room.member",
        Some("@dave:example.com"),
        "@dave:example.com",
        json!({"membership": "knock"}),
    );

    let result = check_auth(&knock_event, &state, StateResVersion::V2);
    assert!(
        result.is_err(),
        "knocking must NOT be allowed in plain restricted room (only knock_restricted)"
    );
}

#[test]
fn test_invite_only_knock_rejected() {
    // Knocking should NOT be allowed in an invite-only room.
    let state = room_with_join_rule("invite");

    let knock_event = make_event(
        "$dave_knock",
        "m.room.member",
        Some("@dave:example.com"),
        "@dave:example.com",
        json!({"membership": "knock"}),
    );

    let result = check_auth(&knock_event, &state, StateResVersion::V2);
    assert!(
        result.is_err(),
        "knocking must NOT be allowed in invite-only room"
    );
}

#[test]
fn test_public_knock_rejected() {
    // Knocking should NOT be allowed in a public room (just join directly).
    let state = room_with_join_rule("public");

    let knock_event = make_event(
        "$dave_knock",
        "m.room.member",
        Some("@dave:example.com"),
        "@dave:example.com",
        json!({"membership": "knock"}),
    );

    let result = check_auth(&knock_event, &state, StateResVersion::V2);
    assert!(
        result.is_err(),
        "knocking must NOT be allowed in public room"
    );
}

#[test]
fn test_knock_room_knock_allowed() {
    // Knocking SHOULD be allowed when join_rule is "knock".
    let state = room_with_join_rule("knock");

    let knock_event = make_event(
        "$dave_knock",
        "m.room.member",
        Some("@dave:example.com"),
        "@dave:example.com",
        json!({"membership": "knock"}),
    );

    let result = check_auth(&knock_event, &state, StateResVersion::V2);
    assert!(
        result.is_ok(),
        "knocking should be allowed in knock room, got: {result:?}"
    );
}

#[test]
fn test_banned_user_cannot_knock() {
    // A banned user must not be able to knock.
    let mut state = room_with_join_rule("knock");

    state.insert(
        ("m.room.member".into(), "@evil:example.com".into()),
        make_event(
            "$ban_evil",
            "m.room.member",
            Some("@evil:example.com"),
            "@admin:example.com",
            json!({"membership": "ban"}),
        ),
    );

    let knock_event = make_event(
        "$evil_knock",
        "m.room.member",
        Some("@evil:example.com"),
        "@evil:example.com",
        json!({"membership": "knock"}),
    );

    let result = check_auth(&knock_event, &state, StateResVersion::V2);
    assert!(result.is_err(), "banned user must NOT be able to knock");
}

#[test]
fn test_restricted_banned_user_cannot_join_even_with_authorized_via() {
    // A banned user must not be able to join even with join_authorised_via_users_server.
    let mut state = room_with_join_rule("restricted");

    state.insert(
        ("m.room.member".into(), "@evil:example.com".into()),
        make_event(
            "$ban_evil",
            "m.room.member",
            Some("@evil:example.com"),
            "@admin:example.com",
            json!({"membership": "ban"}),
        ),
    );

    let join_event = make_event(
        "$evil_join",
        "m.room.member",
        Some("@evil:example.com"),
        "@evil:example.com",
        json!({
            "membership": "join",
            "join_authorised_via_users_server": "@admin:example.com"
        }),
    );

    let result = check_auth(&join_event, &state, StateResVersion::V2);
    assert!(
        result.is_err(),
        "banned user must NOT be able to join even with authorized_via"
    );
}

// ─── Authorising user validation (MSC3083) ──────────────────────────────

#[test]
fn test_restricted_join_rejected_when_authorising_user_not_joined() {
    // The authorising user must be joined to the room.
    let state = room_with_join_rule("restricted");

    // @bob tries to join with authorisation from @ghost who is NOT in the room.
    let join_event = make_event(
        "$bob_join",
        "m.room.member",
        Some("@bob:example.com"),
        "@bob:example.com",
        json!({
            "membership": "join",
            "join_authorised_via_users_server": "@ghost:example.com"
        }),
    );

    let result = check_auth(&join_event, &state, StateResVersion::V2);
    assert!(
        result.is_err(),
        "restricted join must be rejected when authorising user is not joined"
    );
}

#[test]
fn test_restricted_join_rejected_when_authorising_user_lacks_invite_pl() {
    // The authorising user must have sufficient power level to invite.
    let mut state = room_with_join_rule("restricted");

    // @lowpl is joined but has PL 0 (invite requires PL 0 by default,
    // so we set invite PL to 50 to make them insufficient).
    state.insert(
        ("m.room.member".into(), "@lowpl:example.com".into()),
        make_event(
            "$lowpl_join",
            "m.room.member",
            Some("@lowpl:example.com"),
            "@lowpl:example.com",
            json!({"membership": "join"}),
        ),
    );
    // Override power levels: set invite PL to 50 so @lowpl (PL 0) can't invite.
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl2",
            "m.room.power_levels",
            Some(""),
            "@admin:example.com",
            json!({
                "users": {"@admin:example.com": 100},
                "users_default": 0,
                "invite": 50,
            }),
        ),
    );

    let join_event = make_event(
        "$bob_join",
        "m.room.member",
        Some("@bob:example.com"),
        "@bob:example.com",
        json!({
            "membership": "join",
            "join_authorised_via_users_server": "@lowpl:example.com"
        }),
    );

    let result = check_auth(&join_event, &state, StateResVersion::V2);
    assert!(
        result.is_err(),
        "restricted join must be rejected when authorising user lacks invite PL"
    );
}

#[test]
fn test_msc4289_restricted_join_v12_creator_authorising() {
    // V12: check_authorising_user manually queried the PL map instead of
    // using get_sender_power_level, so the creator (not in `users` map) got PL 0.
    // In V2_1 (room v12), the creator should get i64::MAX implicitly.
    let mut state = RoomState::new();

    // Creator creates the room — NOT listed in the PL users map
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
    state.insert(
        ("m.room.member".into(), "@creator:example.com".into()),
        make_event(
            "$creator_join",
            "m.room.member",
            Some("@creator:example.com"),
            "@creator:example.com",
            json!({"membership": "join"}),
        ),
    );
    // PL event does NOT include creator in users map — V12 relies on implicit creator PL
    state.insert(
        ("m.room.power_levels".into(), String::new()),
        make_event(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@creator:example.com",
            json!({
                "users_default": 0,
                "invite": 50,
            }),
        ),
    );
    state.insert(
        ("m.room.join_rules".into(), String::new()),
        make_event(
            "$jr",
            "m.room.join_rules",
            Some(""),
            "@creator:example.com",
            json!({
                "join_rule": "restricted",
                "allow": [
                    {"type": "m.room_membership", "room_id": "!other:example.com"}
                ]
            }),
        ),
    );

    // Bob joins via the creator as the authorising user
    let join_event = make_event(
        "$bob_join",
        "m.room.member",
        Some("@bob:example.com"),
        "@bob:example.com",
        json!({
            "membership": "join",
            "join_authorised_via_users_server": "@creator:example.com"
        }),
    );

    // V2_1 = room v12: creator should have implicit max power
    let result = check_auth(&join_event, &state, StateResVersion::V2_1);
    assert!(
        result.is_ok(),
        "V12 creator should be able to authorise a restricted join even without being in PL users map, got: {result:?}"
    );
}
