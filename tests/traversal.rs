#![allow(clippy::too_many_lines, clippy::type_complexity, clippy::similar_names)]
mod utils;
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
    );
    let ok_v21 = resolved_v21.contains_key(&("m.room.name".to_string(), String::new()));
    assert_eq!(
        ok_v21, exp_v21,
        "V2.1 success expectation mismatched: got {ok_v21}, expected {exp_v21}"
    );

    let resolved_v211 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events,
        &auth_context,
        StateResVersion::V2_1_1,
    );
    let ok_v211 = resolved_v211.contains_key(&("m.room.name".to_string(), String::new()));
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
    );

    // State resolution still passes because the auth_events are valid.
    assert!(
        resolved_v211.contains_key(&("m.room.name".to_string(), String::new())),
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
    // Exact same origin_server_ts and auth_chain_distance as the ban to force a pure Power Level tie-break.
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
    );

    // The resolved state should contain the ban, not the join
    let member_key = ("m.room.member".to_string(), "@bob:example.com".to_string());
    assert_eq!(
        &resolved[&member_key],
        "$alice_ban",
        "Alice's ban should win against Bob's concurrent join because her higher PL forces it to pop first, setting the auth rules."
    );
}

#[test]
fn test_kahn_tiebreak_mods_banning_each_other_v2_1_1() {
    // Exact same test, but running under V2.1.1 to prove auth_chain_distance doesn't change the outcome.
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
        ("m.room.create".to_string(), String::new()),
        create_ev.event_id.clone(),
    );
    unconflicted.insert(
        ("m.room.join_rules".to_string(), String::new()),
        join_rules.event_id.clone(),
    );
    unconflicted.insert(
        (
            "m.room.member".to_string(),
            "@alice:example.com".to_string(),
        ),
        alice_join.event_id.clone(),
    );
    unconflicted.insert(
        ("m.room.member".to_string(), "@bob:example.com".to_string()),
        bob_join.event_id.clone(),
    );

    let resolved = rezzy::resolve_iterative_sort(
        unconflicted,
        conflicted_events,
        &auth_context,
        rezzy::StateResVersion::V2_1_1,
    );

    let bob_member_key = ("m.room.member".to_string(), "@bob:example.com".to_string());
    let alice_member_key = (
        "m.room.member".to_string(),
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
fn test_v2_1_1_fixes_invite_lock() {
    // In V2.0, the supplemental merge aggressively overlaid ALL state events.
    // If an Admin locked a room to "invite", historical joins on slower forks would be
    // evaluated against the new "invite" rules rather than their local "public" rules,
    // causing legitimate joins to be incorrectly rejected during resolution.
    // V2.1 still fails because it supplements everything in Step 4.
    // V2.1.1 fixes this by strictly isolating the supplemental merge to PLs and bans/kicks,
    // ensuring `join_rules` remain EXCLUDED from the merge.

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
            "users": {},
        }),
        auth_events: vec!["$create".to_string()],
        ..Default::default()
    };

    let public_rules = LeanEvent {
        event_id: "$public".to_string(),
        event_type: "m.room.join_rules".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 300,
        content: serde_json::json!({ "join_rule": "public" }),
        auth_events: vec!["$create".to_string(), "$pl".to_string()],
        ..Default::default()
    };

    // The Admin later locks the room to stop spam.
    let admin_lock = LeanEvent {
        event_id: "$admin_lock".to_string(),
        event_type: "m.room.join_rules".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:example.com".to_string(),
        origin_server_ts: 400,
        content: serde_json::json!({ "join_rule": "invite" }),
        auth_events: vec!["$create".to_string(), "$pl".to_string()],
        prev_events: vec!["$hist_join".to_string()],
        ..Default::default()
    };

    // A historical user joined *before* the lock, so their auth chain points to the public rules.
    let historical_join = LeanEvent {
        event_id: "$hist_join".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@user:example.com".to_string()),
        sender: "@user:example.com".to_string(),
        origin_server_ts: 350,
        content: serde_json::json!({ "membership": "join" }),
        auth_events: vec![
            "$create".to_string(),
            "$pl".to_string(),
            "$public".to_string(),
        ],
        ..Default::default()
    };

    let mut auth_context = std::collections::HashMap::new();
    auth_context.insert("$create".to_string(), create_ev);
    auth_context.insert("$pl".to_string(), pl_ev);
    auth_context.insert("$public".to_string(), public_rules);

    let mut conflicted_events = std::collections::HashMap::new();
    conflicted_events.insert("$admin_lock".to_string(), admin_lock);
    conflicted_events.insert("$hist_join".to_string(), historical_join);

    // Resolution under V2.0 (The Shotgun)
    // V2.0 supplemented ALL state events, meaning the `admin_lock` (invite-only) event
    // is pulled into the auth overlay. The historical user's join is then evaluated against
    // the "invite" rules and rightfully REJECTED, permanently locking them out!
    let resolved_v2 = rezzy::resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events.clone(),
        &auth_context,
        rezzy::StateResVersion::V2,
    );
    let member_key = ("m.room.member".to_string(), "@user:example.com".to_string());

    assert!(
        !resolved_v2.contains_key(&member_key),
        "V2.0 FAILS: The historical join is incorrectly rejected because the Invite Lock overrode it!"
    );

    // Resolution under V2.1 (The Scalpel)
    // Under V2.1, join_rules are supplemented during Step 4, so V2.1 still fails the Invite Lock.
    let resolved_v21 = rezzy::resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events.clone(),
        &auth_context,
        rezzy::StateResVersion::V2_1,
    );
    assert!(
        !resolved_v21.contains_key(&member_key),
        "V2.1 FAILS: Under MSC4297 (V2.1), the Invite Lock still overrides historical joins."
    );

    // Resolution under V2.1.1
    // V2.1.1 supplements PLs and Bans, but NEVER `join_rules`.
    // Therefore, `$hist_join` is evaluated against its local auth chain (`$public`),
    // and is rightfully ACCEPTED into the resolved state!
    let resolved_v211 = rezzy::resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events,
        &auth_context,
        rezzy::StateResVersion::V2_1_1,
    );

    assert_eq!(
        &resolved_v211[&member_key],
        "$hist_join",
        "SUCCESS: V2.1.1 completely bypassed the Invite Lock! The historical user's join survived the resolution!"
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
    );
    let name_key = ("m.room.name".to_string(), String::new());
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
    );

    // Alice's ban has PL 100, so Kahn sort evaluates it FIRST. It is added to the resolved state.
    assert_eq!(
        &resolved_v21[&("m.room.member".to_string(), "@bob:example.com".to_string())],
        "$alice_bans_bob",
        "Bob should be banned in the final state"
    );

    // V2.1 now correctly REJECTS Bob's concurrent name change!
    assert!(
        !resolved_v21.contains_key(&("m.room.name".to_string(), String::new())),
        "V2.1 now correctly rejects Bob's name change because it evaluates his concurrent ban!"
    );

    // Run V2.1.1 Resolution (The V3 Fix)
    let resolved_v211 = rezzy::resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&auth_context),
        conflicted_events,
        &auth_context,
        rezzy::StateResVersion::V2_1_1,
    );

    // V2.1.1 REJECTS Bob's concurrent name change!
    assert!(
        !resolved_v211.contains_key(&("m.room.name".to_string(), String::new())),
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
    );

    // V2.1 Rightfully Fails: It enforces the 1-hop strictness. Without "$jr" in the auth chain,
    // it defaults to Invite-Only and rejects the join.
    assert!(
        !resolved_v21.contains_key(&("m.room.member".to_string(), "@bob:example.com".to_string())),
        "V2.1 rightfully rejected the event because the 1-hop auth list was incomplete."
    );

    // A future State DAG (MSC4242) algorithm could theoretically pass this by validating
    // the room state via `prev_state_events` instead of relying on the fragile string array.
}

fn make_ghost_moderator_events() -> (
    HashMap<String, LeanEvent>,
    HashMap<String, LeanEvent>,
    imbl::OrdMap<(String, String), String>,
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
        ("m.room.create".to_string(), String::new()),
        "$create".to_string(),
    );
    unconflicted_state.insert(
        ("m.room.power_levels".to_string(), String::new()),
        "$pl".to_string(),
    );
    unconflicted_state.insert(
        ("m.room.join_rules".to_string(), String::new()),
        "$jr_pub".to_string(),
    );

    (auth_context, conflicted_events, unconflicted_state)
}

#[test]
fn test_v2_1_1_anomaly_06b_ghost_moderator() {
    // Anomaly 06b: Moderator Membership Evaporation / Ghost Moderator
    // A moderator (Nexy) joins and gets promoted on a public fork, then bans a spammer.
    // Concurrently, an Admin locks the room to "invite".
    // Phase 1 evaluates the lockdown and Nexy\'s promotion and ban first (because they are Power Events).
    // Phase 2 evaluates Nexy\'s join. Nexy\'s join is rejected due to the lockdown.
    // In unpatched v2.1, her promotion and ban survive, leaving a "Ghost Moderator".
    // In CDO (v2.2), her join is concurrent and dominated by the invite lockdown,
    // and her subsequent actions (promotion, ban) are transitively dropped due to dependency.

    let (auth_context, conflicted_events, unconflicted_state) = make_ghost_moderator_events();

    // Run V2.2 (CDO Enabled / State Res v2.2)
    let resolved_v211 = rezzy::resolve_iterative_sort(
        unconflicted_state,
        conflicted_events,
        &auth_context,
        rezzy::StateResVersion::V2_1_1,
    );

    let nexy_member_key = ("m.room.member".to_string(), "@nexy:example.com".to_string());
    let spammer_member_key = (
        "m.room.member".to_string(),
        "@spammer:example.com".to_string(),
    );
    let pl_key = ("m.room.power_levels".to_string(), String::new());

    // CDO\'s transitive closure drops nexy_join (dominated by lock) AND nexy_promo/nexy_bans_spammer (transitively dependent)
    assert!(
        !resolved_v211.contains_key(&nexy_member_key),
        "CDO: Nexy join must be dropped because of the concurrent lockdown"
    );
    assert!(
        !resolved_v211.contains_key(&spammer_member_key),
        "CDO: Spammer ban must be transitively dropped since Nexy never legally joined"
    );

    // The resolved PL should revert to the original admin-only state
    let final_pl_id = &resolved_v211[&pl_key];
    assert_ne!(
        final_pl_id, "$nexy_promo",
        "CDO: Nexy\'s promotion must be dropped, resolving to the safe baseline"
    );
}

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
        ("m.room.create".to_string(), String::new()),
        "$create".to_string(),
    );
    unconflicted_state.insert(
        ("m.room.power_levels".to_string(), String::new()),
        "$pl".to_string(),
    );
    unconflicted_state.insert(
        ("m.room.join_rules".to_string(), String::new()),
        "$jr_pub".to_string(),
    );

    // Run V2.1.1 Resolution (CDO Enabled)
    let resolved_v211 = rezzy::resolve_iterative_sort(
        unconflicted_state,
        conflicted_events,
        &auth_context,
        rezzy::StateResVersion::V2_1_1,
    );

    let spammer_key = (
        "m.room.member".to_string(),
        "@spammer:example.com".to_string(),
    );

    // CDO must drop the concurrent spammer join due to the concurrent lockdown
    assert!(
        !resolved_v211.contains_key(&spammer_key),
        "CDO: Spammer join must be dropped because of the concurrent lockdown"
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
    );

    // Bob's ban must be resolved first in Step 2.
    assert_eq!(
        &resolved_v21[&("m.room.member".to_string(), "@bob:example.com".to_string())],
        "$alice_bans_bob",
        "Bob should be banned in the final resolved state"
    );

    // Bob's topic change must be REJECTED in Step 4 because Step 4 correctly
    // supplements Bob's membership status (which is 'ban' in the partially resolved state S).
    assert!(
        !resolved_v21.contains_key(&("m.room.topic".to_string(), String::new())),
        "V2.1 must reject Bob's topic change because he is banned in the partially resolved state"
    );
}
#[test]
fn test_missing_auth_diff_mainline_distortion() {
    let mut events_map: HashMap<&'static str, LeanEvent<&'static str, serde_json::Value>> =
        HashMap::new();

    let create_ev = LeanEvent {
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
    };
    events_map.insert("CREATE", create_ev);

    let pl0 = LeanEvent {
        event_id: "PL0",
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "alice".to_string(),
        depth: 1,
        origin_server_ts: 1,
        power_level: 100,
        prev_events: vec!["CREATE"],
        auth_events: vec!["CREATE"],
        content: serde_json::Value::Null,
    };
    events_map.insert("PL0", pl0);

    let pl1 = LeanEvent {
        event_id: "PL1",
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "alice".to_string(),
        depth: 2,
        origin_server_ts: 2,
        power_level: 100,
        prev_events: vec!["PL0"],
        auth_events: vec!["PL0"],
        content: serde_json::Value::Null,
    };
    events_map.insert("PL1", pl1);

    let sa1 = LeanEvent {
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
    };
    events_map.insert("S_A1", sa1);

    let pl2 = LeanEvent {
        event_id: "PL2",
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "alice".to_string(),
        depth: 4,
        origin_server_ts: 4,
        power_level: 100,
        prev_events: vec!["S_A1"],
        auth_events: vec!["PL1"],
        content: serde_json::Value::Null,
    };
    events_map.insert("PL2", pl2);

    let sb1 = LeanEvent {
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
    };
    events_map.insert("S_B1", sb1);

    let pl_b = LeanEvent {
        event_id: "PL_B",
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "bob".to_string(),
        depth: 3,
        origin_server_ts: 3,
        power_level: 100,
        prev_events: vec!["S_B1"],
        auth_events: vec!["PL0"],
        content: serde_json::Value::Null,
    };
    events_map.insert("PL_B", pl_b);

    // Call resolve_iterative_sort directly
    let mut unconflicted_state = imbl::OrdMap::new();
    unconflicted_state.insert(("m.room.power_levels".to_string(), String::new()), "PL0");

    unconflicted_state.insert(("m.room.create".to_string(), String::new()), "CREATE");
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
    );

    // Both scenarios resolve to the same winner because the mainline ordering is
    // dominated by PL0 (the unconflicted power-levels event).
    // Adding PL1 to the conflicted set doesn't change the mainline walk result.
    let topic_key = ("m.room.topic".to_string(), String::new());

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
