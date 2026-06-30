//! Tests for restricted and knock_restricted join rule support.
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
