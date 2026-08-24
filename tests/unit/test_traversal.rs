#![allow(clippy::too_many_lines, clippy::type_complexity, clippy::similar_names)]
use crate::utils;
use rezzy::{resolve_iterative_sort, LeanEvent, StateResVersion};
use serde_json::json;
use std::collections::HashMap;

fn run_auth_lookup_scenario(join_auth_includes_pl: bool, exp_v21: bool, exp_v211: bool) {
    let create_ev = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@creator:example.com".to_string(),
        origin_server_ts: 100,
        ..Default::default()
    };

    let pl_ev = LeanEvent {
        event_id: "$pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@creator:example.com".to_string(),
        origin_server_ts: 200,
        content: json!({
            "users": { "@alice:example.com": 100 },
            "state_default": 50
        }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    let mut join_auth = vec!["$create".to_string()];
    if join_auth_includes_pl {
        join_auth.push("$pl".to_string());
    }

    let alice_join = LeanEvent {
        event_id: "$join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@alice:example.com".to_string()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 300,
        content: json!({ "membership": "join" }),
        auth_events: join_auth,
        ..Default::default()
    };

    // The name event. It requires PL 50.
    // It lists the join in auth_events, but OMITS the PL event.
    let alice_name = LeanEvent {
        event_id: "$name".to_string(),
        event_type: "m.room.name".to_string(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 400,
        content: json!({ "name": "Alice's Room" }),
        // OMIT the PL event directly. It's only 1-hop if we put it here, which we don't.
        auth_events: vec!["$create".to_string(), "$join".to_string()],
        ..Default::default()
    };

    let mut auth_context = HashMap::new();
    auth_context.insert(create_ev.event_id.clone(), create_ev);
    auth_context.insert(pl_ev.event_id.clone(), pl_ev);
    auth_context.insert(alice_join.event_id.clone(), alice_join);

    let mut conflicted_events = HashMap::new();
    conflicted_events.insert(alice_name.event_id.clone(), alice_name);

    // V2.1: Should FAIL to resolve the name change.
    // It doesn't see the PL event, so it uses default PL 0 for Alice.
    let resolved_v21 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events.clone(),
        &auth_context,
        StateResVersion::V2_1,
        &mut std::collections::HashMap::new(),
    );
    let ok_v21 = resolved_v21.contains_key(&(
        rezzy::basespec::event_types::EventType::from("m.room.name"),
        String::new(),
    ));
    assert_eq!(
        ok_v21, exp_v21,
        "V2.1 success expectation mismatched: got {ok_v21}, expected {exp_v21}"
    );

    let resolved_v211 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events,
        &auth_context,
        StateResVersion::V2_1_1,
        &mut std::collections::HashMap::new(),
    );
    let ok_v211 = resolved_v211.contains_key(&(
        rezzy::basespec::event_types::EventType::from("m.room.name"),
        String::new(),
    ));
    assert_eq!(
        ok_v211, exp_v211,
        "V2.1.1 success expectation mismatched: got {ok_v211}, expected {exp_v211}"
    );
}

#[test]
fn test_v2_1_vs_v2_1_1_recursive_auth_lookup() {
    // Join event includes PL. PL is in the auth ancestry (depth 2).
    // V2.1 fails because it only checks 1-hop (depth 1).
    // V2.1.1 PASSES because it introduces BFS transitive context gathering.
    run_auth_lookup_scenario(true, false, true);
}

/// A banned user's message must be **hard-rejected** (never soft-failed) when
/// the ban is present in the resolved state before the message. This is *not*
/// the soft-failure mechanism (which is about an event passing auth against
/// its own local state-at-event but failing against the later resolved
/// state). Here the ban is genuinely in the state-before, so rejecting the
/// message is unconditional -- the sender's membership resolves to the ban.
///
/// Both V2.1 and V2.1.1 hard-reject here: the ban is a power event that
/// resolves before the non-power message in either version. The V2.1 vs
/// V2.1.1 distinction (transitive auth-context gathering for `power_levels` / `join_rules`)
/// is a separate mechanism, exercised by `run_auth_lookup_scenario`, not this
/// one.
#[test]
fn test_banned_sender_message_is_hard_rejected() {
    let create_ev = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 100,
        content: json!({ "room_version": "12.1", "creator": "@admin:example.com" }),
        ..Default::default()
    };
    let admin_join = LeanEvent {
        event_id: "$admin_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@admin:example.com".to_string()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 200,
        content: json!({ "membership": "join" }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };
    let pl_ev = LeanEvent {
        event_id: "$pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 300,
        content: json!({ "users": { "@admin:example.com": 100, "@bob:example.com": 50 }, "ban": 50, "state_default": 50 }),
        auth_events: vec!["$create".to_string(), "$admin_join".to_string()],
        ..Default::default()
    };
    // A public join rule, so bob's self-join is authorized. Without it the
    // default is `invite`, and bob (never invited) cannot validly join -- which
    // would make the hard-reject below trivially true for the wrong reason
    // (bob never a valid member), not because of the ban.
    let join_rules = LeanEvent {
        event_id: "$join_rules".to_string(),
        event_type: "m.room.join_rules".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 350,
        content: json!({ "join_rule": "public" }),
        auth_events: vec![
            "$create".to_string(),
            "$admin_join".to_string(),
            "$pl".to_string(),
        ],
        ..Default::default()
    };
    let bob_join = LeanEvent {
        event_id: "$bob_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@bob:example.com".to_string()),
        sender: "@bob:example.com".to_string(),
        origin_server_ts: 400,
        content: json!({ "membership": "join" }),
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$join_rules".to_string(),
        ],
        ..Default::default()
    };
    // The ban of bob. Bob's message does not cite this ban directly: the ban
    // is not reachable transitively from the message's own auth_events
    // ($create, $bob_join -> $create, $pl). It surfaces because the required
    // sender-membership key for the message's auth is supplemented from the
    // resolved state (MSC4297 in V2.1), where the ban wins over bob's join.
    let ban_bob = LeanEvent {
        event_id: "$ban_bob".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@bob:example.com".to_string()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 500,
        content: json!({ "membership": "ban" }),
        auth_events: vec![
            "$create".to_string(),
            "$admin_join".to_string(),
            "$bob_join".to_string(),
            "$pl".to_string(),
        ],
        ..Default::default()
    };
    // Bob's message. It omits the ban from its own auth_events, so whether the
    // auth check sees bob as banned depends on the resolved state supplying the
    // required sender-membership key (which resolves to the ban).
    let bob_msg = LeanEvent {
        event_id: "$bob_msg".to_string(),
        event_type: "m.room.message".to_string(),
        state_key: Some(String::new()),
        sender: "@bob:example.com".to_string(),
        origin_server_ts: 600,
        content: json!({ "body": "hello" }),
        auth_events: vec![
            "$create".to_string(),
            "$bob_join".to_string(),
            "$pl".to_string(),
        ],
        ..Default::default()
    };

    let mut auth_context = HashMap::new();
    for ev in [
        &create_ev,
        &admin_join,
        &pl_ev,
        &join_rules,
        &bob_join,
        &ban_bob,
        &bob_msg,
    ] {
        auth_context.insert(ev.event_id.clone(), ev.clone());
    }

    // Control: with no ban, bob is a valid public-rule member and his message
    // must resolve. This proves the hard-reject below is caused by the ban,
    // not by an otherwise-invalid fixture.
    for version in [StateResVersion::V2_1, StateResVersion::V2_1_1] {
        let mut control_conflicted = HashMap::new();
        control_conflicted.insert("$bob_join".to_string(), bob_join.clone());
        control_conflicted.insert("$bob_msg".to_string(), bob_msg.clone());
        let resolved = resolve_iterative_sort(
            utils::build_unconflicted_state_test_helper(&auth_context),
            control_conflicted.clone(),
            &auth_context,
            version,
            &mut std::collections::HashMap::new(),
        );
        assert!(
            resolved.contains_key(&(
                rezzy::basespec::event_types::EventType::from("m.room.message"),
                String::new()
            )),
            "{version:?} control must accept bob's message when he is joined and not banned"
        );
    }

    let mut conflicted = HashMap::new();
    conflicted.insert("$ban_bob".to_string(), ban_bob);
    conflicted.insert("$bob_msg".to_string(), bob_msg.clone());

    for version in [StateResVersion::V2_1, StateResVersion::V2_1_1] {
        let resolved = resolve_iterative_sort(
            utils::build_unconflicted_state_test_helper(&auth_context),
            conflicted.clone(),
            &auth_context,
            version,
            &mut std::collections::HashMap::new(),
        );
        // The ban must win the member key...
        assert_eq!(
            resolved.get(&(
                rezzy::basespec::event_types::EventType::from("m.room.member"),
                "@bob:example.com".to_string()
            )),
            Some(&"$ban_bob".to_string()),
            "ban must be the resolved membership for {version:?}"
        );
        // ...and bob's message must be hard-rejected (absent from resolved).
        assert!(
            !resolved.contains_key(&(
                rezzy::basespec::event_types::EventType::from("m.room.message"),
                String::new()
            )),
            "{version:?} must hard-reject the banned sender's message (no soft-fail)"
        );
    }
}

#[test]
fn test_v2_1_1_xfail_disconnected_auth() {
    // Join event DOES NOT include PL. PL is disconnected from auth graph.
    // V2.1 fails.
    // V2.1.1 also fails, correctly expected.
    run_auth_lookup_scenario(false, false, false);
}

#[test]
fn test_v2_1_1_ancient_prev_event_allowed() {
    // SCENARIO: Alice sends a state event (m.room.name) where her client
    // sets `prev_events` to the VERY FIRST event in the room ($create),
    // effectively skipping the entire timeline graph.
    // This proves that State Resolution doesn't care about `prev_events`.

    let create_ev = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@creator:example.com".to_string(),
        origin_server_ts: 100,
        ..Default::default()
    };

    let pl_ev = LeanEvent {
        event_id: "$pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@creator:example.com".to_string(),
        origin_server_ts: 200,
        content: serde_json::json!({
            "users": { "@alice:example.com": 100 },
            "state_default": 50
        }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    let alice_join = LeanEvent {
        event_id: "$join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@alice:example.com".to_string()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 300,
        content: serde_json::json!({ "membership": "join" }),
        auth_events: vec!["$create".to_string(), "$pl".to_string()],
        ..Default::default()
    };

    let mut auth_context = HashMap::new();
    auth_context.insert(create_ev.event_id.clone(), create_ev.clone());
    auth_context.insert(pl_ev.event_id.clone(), pl_ev.clone());
    auth_context.insert(alice_join.event_id.clone(), alice_join.clone());

    // Alice changes the room name, but references the ancient $create event in prev_events.
    let alice_name = LeanEvent {
        event_id: "$name".to_string(),
        event_type: "m.room.name".to_string(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 1000,
        content: serde_json::json!({ "name": "Alice's Room" }),
        auth_events: vec![
            "$create".to_string(),
            "$join".to_string(),
            "$pl".to_string(),
        ],
        prev_events: vec!["$create".to_string()], // <-- Ancient prev_event!
        ..Default::default()
    };

    let mut conflicted_events = HashMap::new();
    conflicted_events.insert(alice_name.event_id.clone(), alice_name);

    let resolved_v211 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events,
        &auth_context,
        StateResVersion::V2_1_1,
        &mut std::collections::HashMap::new(),
    );

    // State resolution still passes because the auth_events are valid.
    assert!(
        resolved_v211.contains_key(&(
            rezzy::basespec::event_types::EventType::from("m.room.name"),
            String::new()
        )),
        "V2.1.1 should allow the event even with an ancient prev_event"
    );
}

#[test]
fn test_kahn_tiebreak_power_level_overwrites_via_auth() {
    // This test explicitly proves how the tie-breaker works for Power Events.
    // High Power Levels pop FIRST in Kahn's sort. Wait, if they pop first, don't they lose to Last-Write-Wins?
    // No! Power Events are special. They set the authorization rules for the rest of the loop!
    // If Alice (PL 100) bans Bob, her event pops first and sets the ban in the state map.
    // When Bob's conflicting PL 0 join pops later, the state already contains the ban.
    // `iterative_auth_ok` evaluates Bob's join, sees he is banned, and completely rejects his event.
    // So Alice's ban stays.

    let create_ev = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 100,
        ..Default::default()
    };

    let pl_ev = LeanEvent {
        event_id: "$pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 200,
        content: json!({
            "users": { "@alice:example.com": 100 },
            "events_default": 0,
            "state_default": 50
        }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    // Alice (PL 100) bans Bob.
    let alice_ban = LeanEvent {
        event_id: "$alice_ban".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@bob:example.com".to_string()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 300,
        content: json!({ "membership": "ban" }),
        auth_events: vec!["$create".to_string(), "$pl".to_string()],
        ..Default::default()
    };

    // Bob (PL 0) attempts to join.
    // Exact same origin_server_ts as the ban to force a pure Power Level tie-break.
    let bob_join = LeanEvent {
        event_id: "$bob_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@bob:example.com".to_string()),
        sender: "@bob:example.com".to_string(),
        origin_server_ts: 300,
        content: json!({ "membership": "join" }),
        auth_events: vec!["$create".to_string(), "$pl".to_string()],
        ..Default::default()
    };

    let mut auth_context = HashMap::new();
    auth_context.insert(create_ev.event_id.clone(), create_ev);
    auth_context.insert(pl_ev.event_id.clone(), pl_ev);

    let mut conflicted_events = HashMap::new();
    conflicted_events.insert(alice_ban.event_id.clone(), alice_ban);
    conflicted_events.insert(bob_join.event_id.clone(), bob_join);

    let resolved = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events,
        &auth_context,
        StateResVersion::V2_1_1,
        &mut std::collections::HashMap::new(),
    );

    // The resolved state should contain the ban, not the join
    let member_key = (
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        "@bob:example.com".to_string(),
    );
    assert_eq!(
        &resolved[&member_key], "$alice_ban",
        "Alice's ban should win against Bob's concurrent join because her higher PL forces it to pop first, setting the auth rules."
    );
}

#[test]
fn test_kahn_tiebreak_mods_banning_each_other_v2_1_1() {
    // Exact same test, but running under V2.1.1 to confirm the outcome is unchanged.
    let create_ev = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 100,
        ..Default::default()
    };

    let join_rules = LeanEvent {
        event_id: "$jr".to_string(),
        event_type: "m.room.join_rules".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 150,
        content: serde_json::json!({ "join_rule": "public" }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    let pl_alice = LeanEvent {
        event_id: "$pl_alice".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 200,
        content: serde_json::json!({
            "users": { "@alice:example.com": 60, "@bob:example.com": 50 },
            "events_default": 0,
            "state_default": 50
        }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    let pl_bob = LeanEvent {
        event_id: "$pl_bob".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 200,
        content: serde_json::json!({
            "users": { "@alice:example.com": 50, "@bob:example.com": 60 },
            "events_default": 0,
            "state_default": 50
        }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    let alice_join = LeanEvent {
        event_id: "$alice_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@alice:example.com".to_string()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 250,
        content: serde_json::json!({ "membership": "join" }),
        auth_events: vec!["$create".to_string(), "$jr".to_string()],
        ..Default::default()
    };

    let bob_join = LeanEvent {
        event_id: "$bob_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@bob:example.com".to_string()),
        sender: "@bob:example.com".to_string(),
        origin_server_ts: 250,
        content: serde_json::json!({ "membership": "join" }),
        auth_events: vec!["$create".to_string(), "$jr".to_string()],
        ..Default::default()
    };

    let alice_ban = LeanEvent {
        event_id: "$A_alice_ban".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@bob:example.com".to_string()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 300,
        content: serde_json::json!({ "membership": "ban" }),
        auth_events: vec![
            "$create".to_string(),
            "$pl_alice".to_string(),
            "$alice_join".to_string(),
            "$bob_join".to_string(),
        ],
        ..Default::default()
    };

    let bob_ban = LeanEvent {
        event_id: "$Z_bob_ban".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@alice:example.com".to_string()),
        sender: "@bob:example.com".to_string(),
        origin_server_ts: 300,
        content: serde_json::json!({ "membership": "ban" }),
        auth_events: vec![
            "$create".to_string(),
            "$pl_bob".to_string(),
            "$alice_join".to_string(),
            "$bob_join".to_string(),
        ],
        ..Default::default()
    };

    let mut auth_context = std::collections::HashMap::new();
    auth_context.insert(create_ev.event_id.clone(), create_ev.clone());
    auth_context.insert(join_rules.event_id.clone(), join_rules.clone());
    auth_context.insert(pl_alice.event_id.clone(), pl_alice);
    auth_context.insert(pl_bob.event_id.clone(), pl_bob);
    auth_context.insert(alice_join.event_id.clone(), alice_join.clone());
    auth_context.insert(bob_join.event_id.clone(), bob_join.clone());

    let mut conflicted_events = std::collections::HashMap::new();
    conflicted_events.insert(alice_ban.event_id.clone(), alice_ban);
    conflicted_events.insert(bob_ban.event_id.clone(), bob_ban);

    let mut unconflicted = imbl::OrdMap::new();
    unconflicted.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        create_ev.event_id.clone(),
    );
    unconflicted.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.join_rules"),
            String::new(),
        ),
        join_rules.event_id.clone(),
    );
    unconflicted.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@alice:example.com".to_string(),
        ),
        alice_join.event_id.clone(),
    );
    unconflicted.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@bob:example.com".to_string(),
        ),
        bob_join.event_id.clone(),
    );

    let resolved = rezzy::resolve_iterative_sort(
        unconflicted,
        conflicted_events,
        &auth_context,
        rezzy::StateResVersion::V2_1_1,
        &mut std::collections::HashMap::new(),
    );

    let bob_member_key = (
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        "@bob:example.com".to_string(),
    );
    let alice_member_key = (
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        "@alice:example.com".to_string(),
    );

    // Under STOCK V2.1, this resulted in Mutual Destruction.
    // BUT under V2.1 Fixed (V3), Alice's ban pops first and is supplemented!
    // So Bob's ban of Alice is evaluated while Bob is ALREADY banned, and is thus REJECTED.
    // "Who shoots first wins" mathematically holds.
    assert_eq!(&resolved[&bob_member_key], "$A_alice_ban");
    assert_eq!(
        &resolved[&alice_member_key], "$alice_join",
        "Bob's ban of Alice should be rightfully rejected because Alice shot first!"
    );
}

#[test]
fn test_v2_1_1_cve_demotion_evasion() {
    let create_ev = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 100,
        ..Default::default()
    };

    // Alice makes Eve an Admin (PL 100)
    let pl_promo = LeanEvent {
        event_id: "$pl_promo".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 200,
        content: serde_json::json!({
            "users": { "@eve:evil.com": 100 },
            "state_default": 50
        }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    // Eve joins (auths against the PL where she is Admin)
    let eve_join = LeanEvent {
        event_id: "$eve_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@eve:evil.com".to_string()),
        sender: "@eve:evil.com".to_string(),
        origin_server_ts: 300,
        content: serde_json::json!({ "membership": "join" }),
        auth_events: vec!["$create".to_string(), "$pl_promo".to_string()],
        ..Default::default()
    };

    // Alice realizes Eve is evil, DEMOTES her to PL 0
    let pl_demote = LeanEvent {
        event_id: "$pl_demote".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 400,
        content: serde_json::json!({
            "users": { "@eve:evil.com": 0 },
            "state_default": 50
        }),
        auth_events: vec!["$create".to_string(), "$pl_promo".to_string()],
        ..Default::default()
    };

    // THE ATTACK: Eve maliciously changes the room name.
    // She intentionally OMITS the demotion from her 1-hop auth_events,
    // trying to hide it.
    let eve_attack = LeanEvent {
        event_id: "$eve_attack".to_string(),
        event_type: "m.room.name".to_string(),
        state_key: Some(String::new()),
        sender: "@eve:evil.com".to_string(),
        origin_server_ts: 500,
        content: serde_json::json!({ "name": "Hacked by Eve" }),
        // OMITTED: "$pl_demote"
        auth_events: vec!["$create".to_string(), "$eve_join".to_string()],
        ..Default::default()
    };

    let mut auth_context = std::collections::HashMap::new();
    auth_context.insert("$create".to_string(), create_ev);
    auth_context.insert("$pl_promo".to_string(), pl_promo.clone());
    auth_context.insert("$eve_join".to_string(), eve_join);
    auth_context.insert("$pl_demote".to_string(), pl_demote.clone());

    let mut conflicted_events = std::collections::HashMap::new();
    conflicted_events.insert("$pl_promo".to_string(), pl_promo);
    conflicted_events.insert("$pl_demote".to_string(), pl_demote);
    conflicted_events.insert("$eve_attack".to_string(), eve_attack);

    // --- V2.1 SECURELY BLOCKS THE ATTACK ---
    // V2.1 resolves PLs first (picking the demotion). When validating Eve's attack,
    // V2.1 overlays the consensus PL (demotion). Eve is PL 0. Name change requires 50. REJECTED.
    let resolved_v21 = rezzy::resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events.clone(),
        &auth_context,
        rezzy::StateResVersion::V2_1,
        &mut std::collections::HashMap::new(),
    );
    let name_key = (
        rezzy::basespec::event_types::EventType::from("m.room.name"),
        String::new(),
    );
    assert!(
        !resolved_v21.contains_key(&name_key),
        "V2.1 Rightly Rejected the attack because Eve was demoted."
    );

    // --- V2.1.1 DEFEATS THE ATTACK ---
    // V2.1.1 strictly enforces 1-hop security and supplements the demotion.
    // Therefore, Eve is caught and her attack is rightfully rejected!
    let resolved_v211 = rezzy::resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events,
        &auth_context,
        rezzy::StateResVersion::V2_1_1,
        &mut std::collections::HashMap::new(),
    );
    assert!(
        !resolved_v211.contains_key(&name_key),
        "SUCCESS: V2.1.1 successfully protected against Demotion Evasion!"
    );
}

#[test]
fn test_v2_1_flaw_concurrent_ban_evasion() {
    // SCENARIO: The "Phantom State" Flaw in V2.1
    // If Alice bans Bob on Fork A, and Bob concurrently changes the room name on Fork B,
    // Bob's name change will NOT see the ban during resolution, because V2.1 isolated
    // memberships to the local auth chain. Bob's state event will be accepted
    // into the final resolved state despite him being banned!

    let create_ev = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 100,
        ..Default::default()
    };

    let pl_ev = LeanEvent {
        event_id: "$pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 200,
        content: serde_json::json!({
            "users": { "@bob:example.com": 50 },
            "state_default": 50
        }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    let bob_join = LeanEvent {
        event_id: "$bob_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@bob:example.com".to_string()),
        sender: "@bob:example.com".to_string(),
        origin_server_ts: 300,
        content: serde_json::json!({ "membership": "join" }),
        auth_events: vec!["$create".to_string(), "$pl".to_string()],
        ..Default::default()
    };

    // FORK A: Alice bans Bob
    let alice_bans_bob = LeanEvent {
        event_id: "$alice_bans_bob".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@bob:example.com".to_string()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 400,
        content: serde_json::json!({ "membership": "ban" }),
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$bob_join".to_string(),
        ],
        ..Default::default()
    };

    // FORK B: Bob changes the room name (happens concurrently)
    let bob_name_change = LeanEvent {
        event_id: "$bob_name_change".to_string(),
        event_type: "m.room.name".to_string(),
        state_key: Some(String::new()),
        sender: "@bob:example.com".to_string(),
        origin_server_ts: 405,
        content: serde_json::json!({ "name": "Bob Rules" }),
        // Bob's local auth chain knows nothing of the ban on Fork A
        auth_events: vec![
            "$create".to_string(),
            "$bob_join".to_string(),
            "$pl".to_string(),
        ],
        ..Default::default()
    };

    let mut auth_context = std::collections::HashMap::new();
    auth_context.insert("$create".to_string(), create_ev);
    auth_context.insert("$pl".to_string(), pl_ev);
    auth_context.insert("$bob_join".to_string(), bob_join);

    let mut conflicted_events = std::collections::HashMap::new();
    conflicted_events.insert("$alice_bans_bob".to_string(), alice_bans_bob);
    conflicted_events.insert("$bob_name_change".to_string(), bob_name_change);

    // Run V2.1 Resolution (Stock)
    let resolved_v21 = rezzy::resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events.clone(),
        &auth_context,
        rezzy::StateResVersion::V2_1,
        &mut std::collections::HashMap::new(),
    );

    // Alice's ban has PL 100, so Kahn sort evaluates it FIRST. It is added to the resolved state.
    assert_eq!(
        &resolved_v21[&(
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@bob:example.com".to_string()
        )],
        "$alice_bans_bob",
        "Bob should be banned in the final state"
    );

    // V2.1 now correctly REJECTS Bob's concurrent name change!
    assert!(
        !resolved_v21.contains_key(&(
            rezzy::basespec::event_types::EventType::from("m.room.name"),
            String::new()
        )),
        "V2.1 now correctly rejects Bob's name change because it evaluates his concurrent ban!"
    );

    // Run V2.1.1 Resolution (The V3 Fix)
    let resolved_v211 = rezzy::resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events,
        &auth_context,
        rezzy::StateResVersion::V2_1_1,
        &mut std::collections::HashMap::new(),
    );

    // V2.1.1 REJECTS Bob's concurrent name change!
    assert!(
        !resolved_v211.contains_key(&(rezzy::basespec::event_types::EventType::from("m.room.name"), String::new())),
        "V2.1.1 Fixed: Rightfully rejected Bob's name change because it supplemented the concurrent ban!"
    );
}

#[test]
fn test_v2_1_strictness_future_v3_should_pass() {
    let create_ev = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 100,
        ..Default::default()
    };

    // Join Rules: Public
    let join_rules = LeanEvent {
        event_id: "$jr".to_string(),
        event_type: "m.room.join_rules".to_string(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 200,
        content: serde_json::json!({ "join_rule": "public" }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    // Bob joins. He is allowed because the room is public.
    // BUT a client bug caused him to omit `$jr` from his auth_events!
    let bob_join = LeanEvent {
        event_id: "$bob_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@bob:example.com".to_string()),
        sender: "@bob:example.com".to_string(),
        origin_server_ts: 300,
        content: serde_json::json!({ "membership": "join" }),
        // BUG: Missing "$jr"
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    let mut auth_context = std::collections::HashMap::new();
    auth_context.insert("$create".to_string(), create_ev);
    auth_context.insert("$jr".to_string(), join_rules);

    let mut conflicted_events = std::collections::HashMap::new();
    conflicted_events.insert("$bob_join".to_string(), bob_join);

    let resolved_v21 = rezzy::resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events.clone(),
        &auth_context,
        rezzy::StateResVersion::V2_1,
        &mut std::collections::HashMap::new(),
    );

    // V2.1 Rightfully Fails: It enforces the 1-hop strictness. Without "$jr" in the auth chain,
    // it defaults to Invite-Only and rejects the join.
    assert!(
        !resolved_v21.contains_key(&(
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@bob:example.com".to_string()
        )),
        "V2.1 rightfully rejected the event because the 1-hop auth list was incomplete."
    );

    // A future State DAG (MSC4242) algorithm could theoretically pass this by validating
    // the room state via `prev_state_events` instead of relying on the fragile string array.
}

fn make_ghost_moderator_events() -> (
    HashMap<String, LeanEvent>,
    HashMap<String, LeanEvent>,
    imbl::OrdMap<(rezzy::basespec::event_types::EventType, String), String>,
) {
    let create_ev = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 100,
        ..Default::default()
    };

    let pl_ev = LeanEvent {
        event_id: "$pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 200,
        content: serde_json::json!({
            "users": { "@admin:example.com": 100 },
        }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    let jr_pub = LeanEvent {
        event_id: "$jr_pub".to_string(),
        event_type: "m.room.join_rules".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 300,
        content: serde_json::json!({ "join_rule": "public" }),
        auth_events: vec!["$create".to_string(), "$pl".to_string()],
        ..Default::default()
    };

    let charlie_join = LeanEvent {
        event_id: "$charlie_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@charlie:example.com".to_string()),
        sender: "@charlie:example.com".to_string(),
        origin_server_ts: 400,
        content: serde_json::json!({ "membership": "join" }),
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$jr_pub".to_string(),
        ],
        ..Default::default()
    };

    // FORK A: Admin locks the room
    let admin_lock = LeanEvent {
        event_id: "$admin_lock".to_string(),
        event_type: "m.room.join_rules".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 500,
        content: serde_json::json!({ "join_rule": "invite" }),
        auth_events: vec!["$create".to_string(), "$pl".to_string()],
        ..Default::default()
    };

    // FORK B: Nexy joins on public rules, is promoted to Moderator, and bans spammer
    let nexy_join = LeanEvent {
        event_id: "$nexy_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@nexy:example.com".to_string()),
        sender: "@nexy:example.com".to_string(),
        origin_server_ts: 450,
        content: serde_json::json!({ "membership": "join" }),
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$jr_pub".to_string(),
        ],
        ..Default::default()
    };

    let nexy_promo = LeanEvent {
        event_id: "$nexy_promo".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 460,
        content: serde_json::json!({
            "users": {
                "@admin:example.com": 100,
                "@nexy:example.com": 50,
            }
        }),
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$nexy_join".to_string(),
        ],
        ..Default::default()
    };

    let nexy_bans_spammer = LeanEvent {
        event_id: "$nexy_bans_spammer".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@spammer:example.com".to_string()),
        sender: "@nexy:example.com".to_string(),
        origin_server_ts: 470,
        content: serde_json::json!({ "membership": "ban" }),
        auth_events: vec![
            "$create".to_string(),
            "$nexy_promo".to_string(),
            "$nexy_join".to_string(),
        ],
        ..Default::default()
    };

    let mut auth_context = std::collections::HashMap::new();
    auth_context.insert("$create".to_string(), create_ev);
    auth_context.insert("$pl".to_string(), pl_ev);
    auth_context.insert("$jr_pub".to_string(), jr_pub);
    auth_context.insert("$charlie_join".to_string(), charlie_join);

    let mut conflicted_events = std::collections::HashMap::new();
    conflicted_events.insert("$admin_lock".to_string(), admin_lock);
    conflicted_events.insert("$nexy_join".to_string(), nexy_join);
    conflicted_events.insert("$nexy_promo".to_string(), nexy_promo);
    conflicted_events.insert("$nexy_bans_spammer".to_string(), nexy_bans_spammer);

    let mut unconflicted_state = imbl::OrdMap::new();
    unconflicted_state.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "$create".to_string(),
    );
    unconflicted_state.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
            String::new(),
        ),
        "$pl".to_string(),
    );
    unconflicted_state.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.join_rules"),
            String::new(),
        ),
        "$jr_pub".to_string(),
    );

    (auth_context, conflicted_events, unconflicted_state)
}

/// Covers the anomaly where ghost-moderator propagation changes membership resolution.
#[test]
fn test_v2_1_1_anomaly_06b_ghost_moderator() {
    // Anomaly 06b: Moderator Membership Evaporation / Ghost Moderator
    // A moderator (Nexy) joins and gets promoted on a public fork, then bans a spammer.
    // Concurrently, an Admin locks the room to "invite".
    // Phase 1 evaluates the lockdown and Nexy\'s promotion and ban first (because they are Power Events).
    // Phase 2 evaluates Nexy\'s join. Nexy\'s join is rejected due to the lockdown.
    // In unpatched v2.1, her promotion and ban survive, leaving a "Ghost Moderator".
    // Under V2.1.1 resolution the outcome is the same: Nexy's join is rejected
    // against the resolved (invite) join rules and her member key is absent,
    // while her ban of the spammer and her promotion still resolve. Only the
    // join evaporates; her promotion and ban are not transitively dropped.

    let (auth_context, conflicted_events, unconflicted_state) = make_ghost_moderator_events();

    // Run V2.2 (CDO Enabled / State Res v2.2)
    let resolved_v211 = rezzy::resolve_iterative_sort(
        unconflicted_state,
        conflicted_events,
        &auth_context,
        rezzy::StateResVersion::V2_1_1,
        &mut std::collections::HashMap::new(),
    );

    let nexy_member_key = (
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        "@nexy:example.com".to_string(),
    );
    let spammer_member_key = (
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        "@spammer:example.com".to_string(),
    );
    let pl_key = (
        rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
        String::new(),
    );

    // Per the spec, nexy's join is auth-checked against the resolved join_rules
    // (which resolves to invite); nexy is not invited, so her join is rejected
    // and her member key is absent. Her ban on the spammer and her promotion
    // (admin's power_levels) are separate power events that still resolve.
    assert_eq!(
        resolved_v211.get(&nexy_member_key).map(String::as_str),
        None
    );
    assert_eq!(
        resolved_v211.get(&spammer_member_key).map(String::as_str),
        Some("$nexy_bans_spammer")
    );
    assert_eq!(resolved_v211.get(&pl_key), Some(&"$nexy_promo".to_string()));
}

/// Covers the admin lockout anomaly fixture under V2.1.1 traversal.
#[test]
fn test_v2_1_1_anomaly_02_admin_lockout() {
    // Anomaly 02: Admin Lockout / Lockdown Evasion
    // Alice (Admin) locks the room to "invite-only".
    // Concurrently, Bob (Spammer) joins the room under the old "public" join rules.
    // Under stock v2.1, Bob's join is evaluated against Fork B's local public rules and accepted,
    // evading the lock.
    // Under CDO (v2.1.1), the concurrent lockdown dominates and drops Bob's join.

    let create_ev = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 100,
        ..Default::default()
    };

    let pl_ev = LeanEvent {
        event_id: "$pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 200,
        content: serde_json::json!({
            "users": { "@admin:example.com": 100 },
        }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    let jr_pub = LeanEvent {
        event_id: "$jr_pub".to_string(),
        event_type: "m.room.join_rules".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 300,
        content: serde_json::json!({ "join_rule": "public" }),
        auth_events: vec!["$create".to_string(), "$pl".to_string()],
        ..Default::default()
    };

    // FORK A: Admin locks the room to "invite"
    let admin_lock = LeanEvent {
        event_id: "$admin_lock".to_string(),
        event_type: "m.room.join_rules".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 400,
        content: serde_json::json!({ "join_rule": "invite" }),
        auth_events: vec!["$create".to_string(), "$pl".to_string()],
        ..Default::default()
    };

    // FORK B: Spammer concurrently joins under public rules
    let spammer_join = LeanEvent {
        event_id: "$spammer_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@spammer:example.com".to_string()),
        sender: "@spammer:example.com".to_string(),
        origin_server_ts: 450,
        content: serde_json::json!({ "membership": "join" }),
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$jr_pub".to_string(),
        ],
        ..Default::default()
    };

    let mut auth_context = std::collections::HashMap::new();
    auth_context.insert("$create".to_string(), create_ev);
    auth_context.insert("$pl".to_string(), pl_ev);
    auth_context.insert("$jr_pub".to_string(), jr_pub);

    let mut conflicted_events = std::collections::HashMap::new();
    conflicted_events.insert("$admin_lock".to_string(), admin_lock);
    conflicted_events.insert("$spammer_join".to_string(), spammer_join);

    let mut unconflicted_state = imbl::OrdMap::new();
    unconflicted_state.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "$create".to_string(),
    );
    unconflicted_state.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
            String::new(),
        ),
        "$pl".to_string(),
    );
    unconflicted_state.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.join_rules"),
            String::new(),
        ),
        "$jr_pub".to_string(),
    );

    // Run V2.1.1 Resolution (CDO Enabled)
    let resolved_v211 = rezzy::resolve_iterative_sort(
        unconflicted_state,
        conflicted_events,
        &auth_context,
        rezzy::StateResVersion::V2_1_1,
        &mut std::collections::HashMap::new(),
    );

    let spammer_key = (
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        "@spammer:example.com".to_string(),
    );

    // Per the spec, spammer's join is auth-checked against the resolved
    // join_rules (which resolves to invite); spammer is not invited, so the
    // join is rejected and spammer's member key is absent from the result.
    assert_eq!(resolved_v211.get(&spammer_key).map(String::as_str), None);
    assert_eq!(
        resolved_v211.get(&(
            rezzy::basespec::event_types::EventType::from("m.room.join_rules"),
            String::new()
        )),
        Some(&"$admin_lock".to_string())
    );
}

#[test]
fn test_v2_1_spec_compliant_step_4_supplementation() {
    // This test explicitly verifies that in the spec-compliant V2.1 implementation,
    // lookups in Step 4 of non-power events (like m.room.topic) successfully supplement
    // from the partially resolved state (S), which correctly blocks banned users from
    // sending state changes concurrently.

    let create_ev = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 100,
        ..Default::default()
    };

    let pl_ev = LeanEvent {
        event_id: "$pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 200,
        content: serde_json::json!({
            "users": { "@bob:example.com": 50 },
            "state_default": 50
        }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    let bob_join = LeanEvent {
        event_id: "$bob_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@bob:example.com".to_string()),
        sender: "@bob:example.com".to_string(),
        origin_server_ts: 300,
        content: serde_json::json!({ "membership": "join" }),
        auth_events: vec!["$create".to_string(), "$pl".to_string()],
        ..Default::default()
    };

    // FORK A: Alice bans Bob
    let alice_bans_bob = LeanEvent {
        event_id: "$alice_bans_bob".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@bob:example.com".to_string()),
        sender: "@alice:example.com".to_string(),
        origin_server_ts: 400,
        content: serde_json::json!({ "membership": "ban" }),
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$bob_join".to_string(),
        ],
        ..Default::default()
    };

    // FORK B: Bob changes the room topic (concurrently)
    let bob_topic_change = LeanEvent {
        event_id: "$bob_topic_change".to_string(),
        event_type: "m.room.topic".to_string(),
        state_key: Some(String::new()),
        sender: "@bob:example.com".to_string(),
        origin_server_ts: 405,
        content: serde_json::json!({ "topic": "Bob's Space" }),
        auth_events: vec![
            "$create".to_string(),
            "$bob_join".to_string(),
            "$pl".to_string(),
        ],
        ..Default::default()
    };

    let mut auth_context = std::collections::HashMap::new();
    auth_context.insert("$create".to_string(), create_ev);
    auth_context.insert("$pl".to_string(), pl_ev);
    auth_context.insert("$bob_join".to_string(), bob_join);

    let mut conflicted_events = std::collections::HashMap::new();
    conflicted_events.insert("$alice_bans_bob".to_string(), alice_bans_bob);
    conflicted_events.insert("$bob_topic_change".to_string(), bob_topic_change);

    // Run V2.1 Resolution (Fixed & Spec-Compliant)
    let resolved_v21 = rezzy::resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events,
        &auth_context,
        rezzy::StateResVersion::V2_1,
        &mut std::collections::HashMap::new(),
    );

    // Bob's ban must be resolved first in Step 2.
    assert_eq!(
        &resolved_v21[&(
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@bob:example.com".to_string()
        )],
        "$alice_bans_bob",
        "Bob should be banned in the final resolved state"
    );

    // Bob's topic change must be REJECTED in Step 4 because Step 4 correctly
    // supplements Bob's membership status (which is 'ban' in the partially resolved state S).
    assert!(
        !resolved_v21.contains_key(&(
            rezzy::basespec::event_types::EventType::from("m.room.topic"),
            String::new()
        )),
        "V2.1 must reject Bob's topic change because he is banned in the partially resolved state"
    );
}
#[test]
fn test_missing_auth_diff_mainline_distortion() {
    let mut events_map: HashMap<&'static str, LeanEvent<&'static str, serde_json::Value>> =
        HashMap::new();

    let create_ev = LeanEvent {
        rejected: false,
        soft_fail: false,
        event_id: "CREATE",
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "alice".to_string(),
        depth: 0,
        origin_server_ts: 0,
        power_level: 100,
        prev_events: vec![],
        auth_events: vec![],
        content: serde_json::Value::Null,
        room_id: None,
    };
    events_map.insert("CREATE", create_ev);

    let pl0 = LeanEvent {
        rejected: false,
        soft_fail: false,
        event_id: "PL0",
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "alice".to_string(),
        depth: 1,
        origin_server_ts: 1,
        power_level: 100,
        prev_events: vec!["CREATE"],
        auth_events: vec!["CREATE"],
        content: serde_json::json!({ "users": { "alice": 100, "bob": 100 } }),
        room_id: None,
    };
    events_map.insert("PL0", pl0);

    let pl1 = LeanEvent {
        rejected: false,
        soft_fail: false,
        event_id: "PL1",
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "alice".to_string(),
        depth: 2,
        origin_server_ts: 2,
        power_level: 100,
        prev_events: vec!["PL0"],
        auth_events: vec!["PL0"],
        content: serde_json::json!({ "users": { "alice": 100, "bob": 100 } }),
        room_id: None,
    };
    events_map.insert("PL1", pl1);

    let sa1 = LeanEvent {
        rejected: false,
        soft_fail: false,
        event_id: "S_A1",
        event_type: "m.room.topic".to_string(),
        state_key: Some(String::new()),
        sender: "alice".to_string(),
        depth: 3,
        origin_server_ts: 3,
        power_level: 0,
        prev_events: vec!["PL1"],
        auth_events: vec!["PL1"],
        content: serde_json::Value::Null,
        room_id: None,
    };
    events_map.insert("S_A1", sa1);

    let pl2 = LeanEvent {
        rejected: false,
        soft_fail: false,
        event_id: "PL2",
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "alice".to_string(),
        depth: 4,
        origin_server_ts: 4,
        power_level: 100,
        prev_events: vec!["S_A1"],
        auth_events: vec!["PL1"],
        content: serde_json::json!({ "users": { "alice": 100, "bob": 100 } }),
        room_id: None,
    };
    events_map.insert("PL2", pl2);

    let sb1 = LeanEvent {
        rejected: false,
        soft_fail: false,
        event_id: "S_B1",
        event_type: "m.room.topic".to_string(),
        state_key: Some(String::new()),
        sender: "alice".to_string(), // alice is creator, bypasses some auth checks
        depth: 2,
        origin_server_ts: 2,
        power_level: 0,
        prev_events: vec!["PL0"],
        auth_events: vec!["PL0"],
        content: serde_json::Value::Null,
        room_id: None,
    };
    events_map.insert("S_B1", sb1);

    let pl_b = LeanEvent {
        rejected: false,
        soft_fail: false,
        event_id: "PL_B",
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "bob".to_string(),
        depth: 3,
        origin_server_ts: 3,
        power_level: 100,
        prev_events: vec!["S_B1"],
        auth_events: vec!["PL0"],
        content: serde_json::json!({ "users": { "alice": 100, "bob": 100 } }),
        room_id: None,
    };
    events_map.insert("PL_B", pl_b);

    // Call resolve_iterative_sort directly
    let mut unconflicted_state = imbl::OrdMap::new();
    unconflicted_state.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
            String::new(),
        ),
        "PL0",
    );

    unconflicted_state.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "CREATE",
    );
    let mut conflicted_buggy = HashMap::new();
    conflicted_buggy.insert("PL2", events_map["PL2"].clone());
    conflicted_buggy.insert("S_A1", events_map["S_A1"].clone());
    conflicted_buggy.insert("PL_B", events_map["PL_B"].clone());
    conflicted_buggy.insert("S_B1", events_map["S_B1"].clone());

    let (resolved_buggy, _) = rezzy::resolve::resolve_iterative_sort_with_cache_and_deltas(
        unconflicted_state.clone(),
        conflicted_buggy,
        &events_map,
        None,
        StateResVersion::V2,
        &mut std::collections::HashMap::new(),
    );

    // Test the "correct auth diff" scenario (FIXED)
    let mut conflicted_fixed = HashMap::new();
    conflicted_fixed.insert("PL1", events_map["PL1"].clone()); // Added auth_difference!
    conflicted_fixed.insert("PL2", events_map["PL2"].clone());
    conflicted_fixed.insert("S_A1", events_map["S_A1"].clone());
    conflicted_fixed.insert("PL_B", events_map["PL_B"].clone());
    conflicted_fixed.insert("S_B1", events_map["S_B1"].clone());

    let (resolved_fixed, _) = rezzy::resolve::resolve_iterative_sort_with_cache_and_deltas(
        unconflicted_state.clone(),
        conflicted_fixed,
        &events_map,
        None,
        StateResVersion::V2,
        &mut std::collections::HashMap::new(),
    );

    // Both scenarios resolve to the same winner because the mainline ordering is
    // dominated by PL0 (the unconflicted power-levels event).
    // Adding PL1 to the conflicted set doesn't change the mainline walk result.
    let topic_key = (
        rezzy::basespec::event_types::EventType::from("m.room.topic"),
        String::new(),
    );

    // Pin the concrete winner: S_A1 wins via mainline sort (higher depth/ts)
    assert_eq!(
        resolved_buggy.get(&topic_key),
        Some(&"S_A1"),
        "Resolved topic should be S_A1"
    );
    assert_eq!(
        resolved_buggy.get(&topic_key),
        resolved_fixed.get(&topic_key),
        "Buggy and fixed paths should agree when auth_diff doesn't alter mainline"
    );
}

/// Coverage: V2.1.1 power-phase ban supplementation (at.rs:130).
///
/// During V2.1.1 power phase, `OverlayState::get_event` filters member events
/// from resolved state — only returning bans and kicks (not joins/invites).
/// This test constructs a scenario where a conflicted PL event's sender has
/// `membership: "ban"` in the unconflicted resolved state. The auth check
/// for that PL event calls `state.get_event("m.room.member", sender)`,
/// triggering the ban supplementation return at line 130.
#[test]
fn test_v2_1_1_power_phase_ban_supplementation() {
    // Room creator sets up the room
    let create = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:x".to_string(),
        origin_server_ts: 100,
        content: json!({"room_version": "10", "creator": "@admin:x"}),
        ..Default::default()
    };
    let admin_join = LeanEvent {
        event_id: "$admin_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@admin:x".to_string()),
        sender: "@admin:x".to_string(),
        origin_server_ts: 200,
        content: json!({"membership": "join"}),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };
    let pl = LeanEvent {
        event_id: "$pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:x".to_string(),
        origin_server_ts: 300,
        content: json!({
            "users": { "@mallory:x": 50 },
            "state_default": 50
        }),
        auth_events: vec!["$create".to_string(), "$admin_join".to_string()],
        ..Default::default()
    };
    let mallory_join = LeanEvent {
        event_id: "$mallory_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@mallory:x".to_string()),
        sender: "@mallory:x".to_string(),
        origin_server_ts: 400,
        content: json!({"membership": "join"}),
        auth_events: vec!["$create".to_string(), "$pl".to_string()],
        ..Default::default()
    };

    // Admin bans Mallory — this is unconflicted state
    let mallory_ban = LeanEvent {
        event_id: "$mallory_ban".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@mallory:x".to_string()),
        sender: "@admin:x".to_string(),
        origin_server_ts: 500,
        content: json!({"membership": "ban"}),
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$admin_join".to_string(),
            "$mallory_join".to_string(),
        ],
        ..Default::default()
    };

    // Conflicted: Mallory somehow sends a PL event (will fail auth because banned,
    // but the OverlayState still returns the ban via line 130).
    let mallory_pl = LeanEvent {
        event_id: "$mallory_pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@mallory:x".to_string(),
        origin_server_ts: 600,
        content: json!({
            "users": { "@mallory:x": 100 }
        }),
        auth_events: vec![
            "$create".to_string(),
            "$mallory_join".to_string(),
            "$pl".to_string(),
        ],
        ..Default::default()
    };

    // Admin's competing PL event (should win)
    let admin_pl = LeanEvent {
        event_id: "$admin_pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:x".to_string(),
        origin_server_ts: 700,
        content: json!({
            "state_default": 50
        }),
        auth_events: vec![
            "$create".to_string(),
            "$admin_join".to_string(),
            "$pl".to_string(),
        ],
        ..Default::default()
    };

    // Auth context: unconflicted events
    let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();
    auth_context.insert("$create".to_string(), create);
    auth_context.insert("$admin_join".to_string(), admin_join);
    auth_context.insert("$pl".to_string(), pl);
    auth_context.insert("$mallory_join".to_string(), mallory_join);
    auth_context.insert("$mallory_ban".to_string(), mallory_ban);

    // Conflicted: two competing PL events
    let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
    conflicted.insert("$mallory_pl".to_string(), mallory_pl);
    conflicted.insert("$admin_pl".to_string(), admin_pl);

    // Unconflicted state includes the ban
    let unconflicted = utils::build_unconflicted_state_test_helper(&auth_context);

    let resolved = resolve_iterative_sort(
        unconflicted,
        conflicted,
        &auth_context,
        StateResVersion::V2_1_1,
        &mut std::collections::HashMap::new(),
    );

    // Mallory's PL event must be rejected (banned sender)
    // Admin's PL event must win
    let pl_key = (
        rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
        String::new(),
    );
    assert_eq!(
        resolved.get(&pl_key),
        Some(&"$admin_pl".to_string()),
        "Admin's PL must win; Mallory's rejected because she's banned"
    );
}

/// V2.2 power-event ordering uses power level, then `origin_server_ts`, then
/// `event_id` (the redundant `auth_chain_distance` tie-break was removed). This
/// constructs two competing topic events with equal power level (0) and equal
/// `origin_server_ts`, forcing the final `event_id` lexicographic tie-break:
/// `$topic_a` sorts first and `$topic_b` (larger id) wins via last-write-wins.
#[test]
fn test_v2_2_event_id_tiebreak() {
    let auth_evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$create",     "type": "m.room.create",       "state_key": "", "sender": "@admin:x", "origin_server_ts": 100, "content": {"room_version": "13", "creator": "@admin:x"}}
        {"event_id": "$admin_join", "type": "m.room.member",       "state_key": "@admin:x", "sender": "@admin:x", "origin_server_ts": 200, "content": {"membership": "join"}, "auth_events": ["$create"]}
        {"event_id": "$pl",         "type": "m.room.power_levels", "state_key": "", "sender": "@admin:x", "origin_server_ts": 300, "content": {"users": {"@admin:x": 100, "@bob:x": 50}, "state_default": 50}, "auth_events": ["$create", "$admin_join"]}
        {"event_id": "$bob_join",   "type": "m.room.member",       "state_key": "@bob:x", "sender": "@bob:x", "origin_server_ts": 400, "content": {"membership": "join"}, "auth_events": ["$create", "$pl"]}
        {"event_id": "$jr",         "type": "m.room.join_rules",   "state_key": "", "sender": "@admin:x", "origin_server_ts": 450, "content": {"join_rule": "public"}, "auth_events": ["$create", "$pl", "$admin_join"]}
    "#,
    );

    let conflicted_evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$topic_a", "type": "m.room.topic", "state_key": "", "sender": "@admin:x", "origin_server_ts": 500, "content": {"topic": "Admin's topic"}, "auth_events": ["$create", "$pl", "$admin_join", "$jr"]}
        {"event_id": "$topic_b", "type": "m.room.topic", "state_key": "", "sender": "@bob:x",   "origin_server_ts": 500, "content": {"topic": "Bob's topic"},   "auth_events": ["$create", "$pl", "$bob_join"]}
    "#,
    );

    let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();
    for ev in auth_evs {
        auth_context.insert(ev.event_id.clone(), ev);
    }

    let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
    for ev in conflicted_evs {
        conflicted.insert(ev.event_id.clone(), ev);
    }

    let unconflicted = utils::build_unconflicted_state_test_helper(&auth_context);

    // Resolve with V2.2
    let resolved = resolve_iterative_sort(
        unconflicted,
        conflicted,
        &auth_context,
        StateResVersion::V2_2,
        &mut std::collections::HashMap::new(),
    );

    // $topic_b wins: both events have equal PL (0), empty mainline (position 0),
    // equal origin_server_ts (500). Tiebreak: $topic_a < $topic_b lexicographically,
    // so $topic_a sorts first -> $topic_b is applied last -> last-write-wins.
    let topic_key = (
        rezzy::basespec::event_types::EventType::from("m.room.topic"),
        String::new(),
    );
    assert_eq!(
        resolved.get(&topic_key),
        Some(&"$topic_b".to_string()),
        "V2.2: $topic_b must win via lexicographic event_id tiebreak (last-write-wins)"
    );
}

/// Rule 10.4 (V12): PL event with creator in `users` map is rejected during
/// state resolution. A competing PL without the creator wins.
#[test]
fn test_v2_1_1_creator_in_users_map_rejected() {
    let auth_evs = utils::parse_jsonl_events(
        r#"
{"event_id": "$create",     "type": "m.room.create",       "state_key": "", "sender": "@admin:x", "origin_server_ts": 100, "content": {"room_version": "12", "creator": "@admin:x"}}
{"event_id": "$admin_join", "type": "m.room.member",       "state_key": "@admin:x", "sender": "@admin:x", "origin_server_ts": 200, "content": {"membership": "join"}, "auth_events": ["$create"]}
{"event_id": "$pl",         "type": "m.room.power_levels", "state_key": "", "sender": "@admin:x", "origin_server_ts": 300, "content": {"state_default": 50}, "auth_events": ["$create", "$admin_join"]}
"#,
    );
    // Fork A: creator in users (forbidden in V12) vs Fork B: valid
    let conflicted_evs = utils::parse_jsonl_events(
        r#"
{"event_id": "$pl_bad",  "type": "m.room.power_levels", "state_key": "", "sender": "@admin:x", "origin_server_ts": 400, "content": {"users": {"@admin:x": 100}, "state_default": 50}, "auth_events": ["$create", "$admin_join", "$pl"]}
{"event_id": "$pl_good", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:x", "origin_server_ts": 500, "content": {"state_default": 50}, "auth_events": ["$create", "$admin_join", "$pl"]}
"#,
    );

    let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();
    for ev in auth_evs {
        auth_context.insert(ev.event_id.clone(), ev);
    }
    let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
    for ev in conflicted_evs {
        conflicted.insert(ev.event_id.clone(), ev);
    }

    let unconflicted = utils::build_unconflicted_state_test_helper(&auth_context);
    let resolved = resolve_iterative_sort(
        unconflicted,
        conflicted,
        &auth_context,
        StateResVersion::V2_1_1,
        &mut std::collections::HashMap::new(),
    );

    let pl_key = (
        rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
        String::new(),
    );
    assert_eq!(
        resolved.get(&pl_key),
        Some(&"$pl_good".to_string()),
        "V12 Rule 10.4: PL with creator in users must be rejected; valid PL wins"
    );
}

/// Coverage: V2.1.1 power-phase ban supplementation return (at.rs:134-135).
///
/// During V2.1.1's power phase, `OverlayState::get_event` only supplements
/// bans and kicks from the resolved state (not joins/invites). This test
/// creates a scenario where:
/// - The **unconflicted** resolved state contains a ban for `@mallory:x`
/// - A conflicted PL event from `@mallory:x` is auth-checked during power phase
/// - The auth checker queries `("m.room.member", "@mallory:x")` → the ban is
///   returned via the `is_ban_or_kick` branch → auth rejects the PL event
///
/// The PL from `@admin:x` must win because `@mallory:x` is banned.
#[test]
fn test_v2_1_1_ban_supplementation_return_path() {
    // Unconflicted auth context: room setup + mallory join + mallory ban
    let auth_evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$create",     "type": "m.room.create",       "state_key": "", "sender": "@admin:x", "origin_server_ts": 100, "content": {"room_version": "10"}}
        {"event_id": "$admin_join", "type": "m.room.member",       "state_key": "@admin:x", "sender": "@admin:x", "origin_server_ts": 200, "content": {"membership": "join"}, "auth_events": ["$create"]}
        {"event_id": "$pl",         "type": "m.room.power_levels", "state_key": "", "sender": "@admin:x", "origin_server_ts": 300, "content": {"users": {"@admin:x": 100, "@mallory:x": 50}, "state_default": 50}, "auth_events": ["$create", "$admin_join"]}
        {"event_id": "$jr",         "type": "m.room.join_rules",   "state_key": "", "sender": "@admin:x", "origin_server_ts": 350, "content": {"join_rule": "public"}, "auth_events": ["$create", "$pl", "$admin_join"]}
        {"event_id": "$mal_join",   "type": "m.room.member",       "state_key": "@mallory:x", "sender": "@mallory:x", "origin_server_ts": 400, "content": {"membership": "join"}, "auth_events": ["$create", "$pl", "$jr"]}
        {"event_id": "$mal_ban",    "type": "m.room.member",       "state_key": "@mallory:x", "sender": "@admin:x",   "origin_server_ts": 500, "content": {"membership": "ban"}, "auth_events": ["$create", "$pl", "$admin_join", "$mal_join"]}
    "#,
    );

    // Two conflicted PL events: one from banned @mallory:x, one from @admin:x
    // These are both PL events → power phase. When auth-checking $mal_pl,
    // the auth checker queries ("m.room.member", "@mallory:x") which should
    // return the ban via the V2.1.1 supplementation path.
    let conflicted_evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$mal_pl",   "type": "m.room.power_levels", "state_key": "", "sender": "@mallory:x", "origin_server_ts": 600, "content": {"users": {"@mallory:x": 100}}, "auth_events": ["$create", "$mal_join", "$pl"]}
        {"event_id": "$admin_pl", "type": "m.room.power_levels", "state_key": "", "sender": "@admin:x",   "origin_server_ts": 700, "content": {"users": {"@admin:x": 100}, "state_default": 50}, "auth_events": ["$create", "$admin_join", "$pl"]}
    "#,
    );

    let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();
    for ev in auth_evs {
        auth_context.insert(ev.event_id.clone(), ev);
    }

    let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
    for ev in conflicted_evs {
        conflicted.insert(ev.event_id.clone(), ev);
    }

    // Build unconflicted state manually — must include the ban so that
    // the power-phase auth checker finds it via OverlayState::get_event.
    // Sort by origin_server_ts so the latest event per state key wins
    // (HashMap iteration order is non-deterministic).
    let mut unconflicted = imbl::OrdMap::new();
    let mut sorted_auth: Vec<_> = auth_context.values().collect();
    sorted_auth.sort_by_key(|ev| ev.origin_server_ts);
    for ev in sorted_auth {
        if let Some(sk) = &ev.state_key {
            unconflicted.insert(
                (
                    rezzy::basespec::event_types::EventType::from(ev.event_type.as_str()),
                    sk.clone(),
                ),
                ev.event_id.clone(),
            );
        }
    }

    // Verify the ban is in the unconflicted state
    let mal_key = (
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        "@mallory:x".to_string(),
    );
    assert_eq!(
        unconflicted.get(&mal_key),
        Some(&"$mal_ban".to_string()),
        "Precondition: ban must be in unconflicted state"
    );

    let resolved = resolve_iterative_sort(
        unconflicted,
        conflicted,
        &auth_context,
        StateResVersion::V2_1_1,
        &mut std::collections::HashMap::new(),
    );

    // Mallory's PL must be rejected (she's banned)
    // Admin's PL must win
    let pl_key = (
        rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
        String::new(),
    );
    assert_eq!(
        resolved.get(&pl_key),
        Some(&"$admin_pl".to_string()),
        "V2.1.1: Admin PL must win; Mallory's PL rejected because she's banned \
         (ban supplementation at at.rs:134-135)"
    );
}

/// Verification: a banned sender's power-level event is rejected against the
/// resolved ban during power-phase authorization.
///
/// Required membership lookups consult the resolved state first, so if a user
/// is banned during Step 2, subsequent power-level events from that user are
/// rejected against the progressive consensus state (where they are banned)
/// rather than their local `auth_events` (where they are still joined).
#[test]
fn test_v2_1_1_power_phase_membership_bypass_prevention() {
    let auth_evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$create",     "type": "m.room.create",       "state_key": "", "sender": "@admin:x", "origin_server_ts": 100, "content": {"room_version": "12"}}
        {"event_id": "$admin_join", "type": "m.room.member",       "state_key": "@admin:x", "sender": "@admin:x", "origin_server_ts": 200, "content": {"membership": "join"}, "auth_events": ["$create"]}
        {"event_id": "$pl_init",    "type": "m.room.power_levels", "state_key": "", "sender": "@admin:x", "origin_server_ts": 300, "content": {"users": {"@admin:x": 100, "@mallory:x": 100}, "state_default": 50}, "auth_events": ["$create", "$admin_join"]}
        {"event_id": "$jr",         "type": "m.room.join_rules",   "state_key": "", "sender": "@admin:x", "origin_server_ts": 350, "content": {"join_rule": "public"}, "auth_events": ["$create", "$pl_init", "$admin_join"]}
        {"event_id": "$mal_join",   "type": "m.room.member",       "state_key": "@mallory:x", "sender": "@mallory:x", "origin_server_ts": 400, "content": {"membership": "join"}, "auth_events": ["$create", "$pl_init", "$jr"]}
    "#,
    );

    let conflicted_evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$mal_ban",    "type": "m.room.member",       "state_key": "@mallory:x", "sender": "@admin:x",   "origin_server_ts": 500, "content": {"membership": "ban"}, "auth_events": ["$create", "$pl_init", "$admin_join", "$mal_join"]}
        {"event_id": "$admin_pl",   "type": "m.room.power_levels", "state_key": "", "sender": "@admin:x",   "origin_server_ts": 600, "content": {"users": {"@admin:x": 100, "@mallory:x": 100}, "state_default": 10}, "auth_events": ["$create", "$admin_join", "$pl_init"]}
        {"event_id": "$mal_pl",     "type": "m.room.power_levels", "state_key": "", "sender": "@mallory:x", "origin_server_ts": 700, "content": {"users": {"@admin:x": 100, "@mallory:x": 100}, "state_default": 20}, "auth_events": ["$create", "$mal_join", "$pl_init"]}
    "#,
    );

    let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();
    for ev in auth_evs {
        auth_context.insert(ev.event_id.clone(), ev);
    }

    let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
    for ev in conflicted_evs {
        conflicted.insert(ev.event_id.clone(), ev);
    }

    let mut unconflicted = imbl::OrdMap::new();
    let mut sorted_auth: Vec<_> = auth_context.values().collect();
    sorted_auth.sort_by_key(|ev| ev.origin_server_ts);
    for ev in sorted_auth {
        if let Some(sk) = &ev.state_key {
            unconflicted.insert(
                (
                    rezzy::basespec::event_types::EventType::from(ev.event_type.as_str()),
                    sk.clone(),
                ),
                ev.event_id.clone(),
            );
        }
    }

    let resolved = resolve_iterative_sort(
        unconflicted,
        conflicted,
        &auth_context,
        StateResVersion::V2_1_1,
        &mut std::collections::HashMap::new(),
    );

    let pl_key = (
        rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
        String::new(),
    );

    // Mallory's PL event must be rejected because she is progressively banned:
    // the resolved ban is what her membership resolves to, so she fails the
    // "sender must not be banned" rule. Admin's PL event must win.
    assert_eq!(
        resolved.get(&pl_key),
        Some(&"$admin_pl".to_string()),
        "V2.1.1: Mallory's PL event must be rejected against the resolved ban (since she is banned)."
    );
}

/// Pin stock V2.1 (MSC4297) behavior: reject a power-level event when the sender
/// is progressively banned.
///
/// This is the *intentional* spec-mandated behavior. The resolved progressive ban causes
/// `$mal_pl` to fail authorization during the power phase, so it must not win its key.
#[test]
fn test_v2_1_rejects_pl_from_progressively_banned_sender() {
    let auth_evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$create",     "type": "m.room.create",       "state_key": "", "sender": "@admin:x", "origin_server_ts": 100, "content": {"room_version": "12"}}
        {"event_id": "$admin_join", "type": "m.room.member",       "state_key": "@admin:x", "sender": "@admin:x", "origin_server_ts": 200, "content": {"membership": "join"}, "auth_events": ["$create"]}
        {"event_id": "$pl_init",    "type": "m.room.power_levels", "state_key": "", "sender": "@admin:x", "origin_server_ts": 300, "content": {"users": {"@admin:x": 100, "@mallory:x": 100}, "state_default": 50}, "auth_events": ["$create", "$admin_join"]}
        {"event_id": "$jr",         "type": "m.room.join_rules",   "state_key": "", "sender": "@admin:x", "origin_server_ts": 350, "content": {"join_rule": "public"}, "auth_events": ["$create", "$pl_init", "$admin_join"]}
        {"event_id": "$mal_join",   "type": "m.room.member",       "state_key": "@mallory:x", "sender": "@mallory:x", "origin_server_ts": 400, "content": {"membership": "join"}, "auth_events": ["$create", "$pl_init", "$jr"]}
    "#,
    );
    let conflicted_evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$mal_ban",    "type": "m.room.member",       "state_key": "@mallory:x", "sender": "@admin:x",   "origin_server_ts": 500, "content": {"membership": "ban"}, "auth_events": ["$create", "$pl_init", "$admin_join", "$mal_join"]}
        {"event_id": "$admin_pl",   "type": "m.room.power_levels", "state_key": "", "sender": "@admin:x",   "origin_server_ts": 600, "content": {"users": {"@admin:x": 100, "@mallory:x": 100}, "state_default": 10}, "auth_events": ["$create", "$admin_join", "$pl_init"]}
        {"event_id": "$mal_pl",     "type": "m.room.power_levels", "state_key": "", "sender": "@mallory:x", "origin_server_ts": 700, "content": {"users": {"@admin:x": 100, "@mallory:x": 100}, "state_default": 20}, "auth_events": ["$create", "$mal_join", "$pl_init"]}
    "#,
    );

    let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();
    for ev in auth_evs {
        auth_context.insert(ev.event_id.clone(), ev);
    }

    let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
    for ev in conflicted_evs {
        conflicted.insert(ev.event_id.clone(), ev);
    }

    let mut unconflicted = imbl::OrdMap::new();
    let mut sorted_auth: Vec<_> = auth_context.values().collect();
    sorted_auth.sort_by_key(|ev| ev.origin_server_ts);
    for ev in sorted_auth {
        if let Some(sk) = &ev.state_key {
            unconflicted.insert(
                (
                    rezzy::basespec::event_types::EventType::from(ev.event_type.as_str()),
                    sk.clone(),
                ),
                ev.event_id.clone(),
            );
        }
    }

    let resolved = resolve_iterative_sort(
        unconflicted,
        conflicted,
        &auth_context,
        StateResVersion::V2_1,
        &mut std::collections::HashMap::new(),
    );

    let pl_key = (
        rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
        String::new(),
    );

    // Under V2.1 (MSC4297), required auth keys (incl. the sender's member event)
    // come from the resolved state. $mal_ban (ts 500) sorts before $mal_pl (ts
    // 700), so by the time $mal_pl is auth-checked Mallory is resolved as banned
    // and $mal_pl is rejected — $admin_pl wins. (The prior "stock V2.1 does not
    // supplement membership" behavior was a non-spec deviation, now removed.)
    assert_eq!(
        resolved.get(&pl_key),
        Some(&"$admin_pl".to_string()),
        "Stock V2.1 must reject Mallory's PL since she is progressively banned."
    );
}

#[test]
fn test_process_pulled_event_with_rejected_missing_state() {
    let auth_events = utils::parse_jsonl_events(
        r#"
        {"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@creator:example.com", "origin_server_ts": 100}
        {"event_id": "$pl", "type": "m.room.power_levels", "state_key": "", "sender": "@creator:example.com", "origin_server_ts": 200, "content": {"users": {"@bob:example.com": 100, "@charlie:example.com": 0}}, "auth_events": ["$create"]}
        {"event_id": "$jr", "type": "m.room.join_rules", "state_key": "", "sender": "@creator:example.com", "origin_server_ts": 250, "content": {"join_rule": "public"}, "auth_events": ["$create", "$pl"]}
        {"event_id": "$join", "type": "m.room.member", "state_key": "@charlie:example.com", "sender": "@charlie:example.com", "origin_server_ts": 300, "content": {"membership": "join"}, "auth_events": ["$create", "$pl", "$jr"]}
        {"event_id": "$kick", "type": "m.room.member", "state_key": "@charlie:example.com", "sender": "@bob:example.com", "origin_server_ts": 400, "content": {"membership": "leave"}, "auth_events": ["$create", "$pl", "$join"], "__rejected": true}
        "#,
    );

    let mut auth_context = std::collections::HashMap::new();
    for ev in auth_events {
        auth_context.insert(ev.event_id.clone(), ev);
    }

    let state_maps = vec![
        imbl::OrdMap::from(vec![
            (
                (
                    rezzy::basespec::event_types::EventType::from("m.room.create"),
                    String::new(),
                ),
                "$create".to_string(),
            ),
            (
                (
                    rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
                    String::new(),
                ),
                "$pl".to_string(),
            ),
            (
                (
                    rezzy::basespec::event_types::EventType::from("m.room.join_rules"),
                    String::new(),
                ),
                "$jr".to_string(),
            ),
            (
                (
                    rezzy::basespec::event_types::EventType::from("m.room.member"),
                    "@charlie:example.com".to_string(),
                ),
                "$join".to_string(),
            ),
        ]),
        imbl::OrdMap::from(vec![
            (
                (
                    rezzy::basespec::event_types::EventType::from("m.room.create"),
                    String::new(),
                ),
                "$create".to_string(),
            ),
            (
                (
                    rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
                    String::new(),
                ),
                "$pl".to_string(),
            ),
            (
                (
                    rezzy::basespec::event_types::EventType::from("m.room.join_rules"),
                    String::new(),
                ),
                "$jr".to_string(),
            ),
            (
                (
                    rezzy::basespec::event_types::EventType::from("m.room.member"),
                    "@charlie:example.com".to_string(),
                ),
                "$kick".to_string(),
            ),
        ]),
    ];

    let result = rezzy::resolve_state_maps(&state_maps, &auth_context, StateResVersion::V2_1_1);

    let member_key = (
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        "@charlie:example.com".to_string(),
    );
    assert_eq!(
        result.get(&member_key),
        Some(&"$join".to_string()),
        "Rejected event must not be admitted to state!"
    );
}

/// Regression test for the auth-diff clobbering bug: an auth-diff-supplied
/// power event (pulled into `conflicted_events` purely to validate an
/// unrelated *genuine* conflict) must never overwrite a state key that both
/// merge parents actually agree on.
///
/// DAG shape (all V2, room v11-style):
///
/// ```text
/// $create -> $admin_join -> $pl -> $jr_old("knock") -> $jr_new("public")
///                                        \                    |
///                                         \-------(auth)-------+--> $branch1 (member join)
///                                                              +--> $branch2 (power_levels change,
///                                                                    auth_events includes $jr_old)
///                                        $branch1, $branch2 --> $merge (member join)
/// ```
///
/// `$branch2`'s `power_levels` event references the *superseded* `$jr_old` in
/// its `auth_events` (a realistic shape: an event's auth chain can freeze an
/// older ancestor snapshot even after a causally-later event supersedes it).
/// That makes `$jr_old` part of `auth(conflicted) \ auth(unconflicted)` at
/// the `$merge` fork — real conflict is only on `m.room.power_levels`
/// (`$pl` vs `$branch2`'s change); `m.room.join_rules` is agreed by both
/// parents as `$jr_new`. `$jr_old` must never win.
fn auth_diff_context_event_scenario(version: StateResVersion) -> Option<String> {
    use rezzy::StateUpdate;

    let create = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        depth: 0,
        content: json!({"room_version": "11"}),
        ..Default::default()
    };
    let admin_join = LeanEvent {
        event_id: "$admin_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@admin:example.com".to_string()),
        sender: "@admin:example.com".to_string(),
        depth: 1,
        content: json!({"membership": "join"}),
        prev_events: vec!["$create".to_string()],
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };
    let pl = LeanEvent {
        event_id: "$pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        depth: 2,
        content: json!({"users": {"@admin:example.com": 100}}),
        prev_events: vec!["$admin_join".to_string()],
        auth_events: vec!["$create".to_string(), "$admin_join".to_string()],
        ..Default::default()
    };
    let jr_old = LeanEvent {
        event_id: "$jr_old".to_string(),
        event_type: "m.room.join_rules".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        depth: 3,
        content: json!({"join_rule": "knock"}),
        prev_events: vec!["$pl".to_string()],
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$admin_join".to_string(),
        ],
        ..Default::default()
    };
    let jr_new = LeanEvent {
        event_id: "$jr_new".to_string(),
        event_type: "m.room.join_rules".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        depth: 4,
        content: json!({"join_rule": "public"}),
        prev_events: vec!["$jr_old".to_string()],
        // Deliberately does NOT auth against $jr_old — a plain JR change
        // authed purely by create+pl+membership, same as real DAGs.
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$admin_join".to_string(),
        ],
        ..Default::default()
    };
    let branch1 = LeanEvent {
        event_id: "$branch1".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@bob:example.com".to_string()),
        sender: "@bob:example.com".to_string(),
        depth: 5,
        content: json!({"membership": "join"}),
        prev_events: vec!["$jr_new".to_string()],
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$jr_new".to_string(),
        ],
        ..Default::default()
    };
    let branch2 = LeanEvent {
        event_id: "$branch2".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        depth: 5,
        content: json!({"users": {"@admin:example.com": 100, "@someone:example.com": 50}}),
        prev_events: vec!["$jr_new".to_string()],
        // References the superseded $jr_old, pulling it into the auth diff
        // for this genuine power_levels conflict.
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$admin_join".to_string(),
            "$jr_old".to_string(),
        ],
        ..Default::default()
    };
    let merge = LeanEvent {
        event_id: "$merge".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@carol:example.com".to_string()),
        sender: "@carol:example.com".to_string(),
        depth: 6,
        content: json!({"membership": "join"}),
        prev_events: vec!["$branch1".to_string(), "$branch2".to_string()],
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$jr_new".to_string(),
        ],
        ..Default::default()
    };

    let mut events: HashMap<String, LeanEvent> = HashMap::new();
    for ev in [
        create, admin_join, pl, jr_old, jr_new, branch1, branch2, merge,
    ] {
        events.insert(ev.event_id.clone(), ev);
    }

    let mut final_state: Option<HashMap<(String, String), String>> = None;
    let completed =
        rezzy::compute_state_at_streaming_optimized(&["$merge"], &events, version, |id, update| {
            if id != "$merge" {
                return;
            }
            if let StateUpdate::New { state, .. } = update {
                final_state = Some(
                    state
                        .iter()
                        .map(|(k, v)| ((k.0.as_str().to_string(), k.1.clone()), v.clone()))
                        .collect(),
                );
            }
        });
    assert!(
        completed,
        "compute_state_at_streaming_optimized detected a cycle"
    );

    let final_state = final_state.expect("$merge must resolve to a New state update");
    let jr_key = ("m.room.join_rules".to_string(), String::new());
    final_state.get(&jr_key).cloned()
}

/// Runs the auth-diff clobbering scenario across every resolution version.
/// All five must resolve `m.room.join_rules` to `$jr_new` (agreed by both
/// merge parents) rather than the auth-diff-context-only `$jr_old`:
///
/// - V1/V2: fixed by making the power/non-power phases only allowed to
///   write `resolved` for keys in the genuinely-conflicted-key set (computed
///   from the real per-key state-map diff, *before* the `auth(C) \ auth(U)`
///   supplement pulls in extra auth-chain-context events).
/// - V2.1+: same fix. These versions start `resolved` empty and deliberately
///   let the conflicted-phase win over unconflicted state for *genuinely*
///   conflicted keys (that's what makes MSC4297 ban/kick supplementation
///   work — see the `test_v2_1_1_*_supplementation` tests and
///   `test_v2_1_rejects_pl_from_progressively_banned_sender` above), but the new
///   genuinely-conflicted-key gate means an auth-diff-context event's own
///   key is never inserted into `resolved` at all when nothing actually
///   conflicts on it — so it's left for `merge_unconflicted_power_events`/
///   the final merge to supply from `unconflicted_state` instead.
#[test]
fn test_auth_diff_context_event_does_not_clobber_agreed_key() {
    for version in [
        StateResVersion::V1,
        StateResVersion::V2,
        StateResVersion::V2_1,
        StateResVersion::V2_1_1,
        StateResVersion::V2_2,
    ] {
        assert_eq!(
            auth_diff_context_event_scenario(version),
            Some("$jr_new".to_string()),
            "{version:?}: m.room.join_rules must stay '$jr_new' (agreed by both \
             merge parents); it must not be clobbered by '$jr_old', which only \
             appears in conflicted_events as auth context for the genuine \
             power_levels conflict."
        );
    }
}
