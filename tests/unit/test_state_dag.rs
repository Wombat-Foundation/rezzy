// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Unit tests for MSC4242 (State Res V2.2) State DAG library primitives.

use rezzy::auth::{check_auth_with_context, RoomState};
use rezzy::basespec::event_types::{
    EventType, M_ROOM_CREATE, M_ROOM_JOIN_RULES, M_ROOM_MEMBER, M_ROOM_POWER_LEVELS,
};
use rezzy::basespec::rezzy_types::{LeanEvent, RoomId, StateResVersion};
use rezzy::state::dag::{
    compute_state_after_from_dag, compute_state_before_from_dag, derive_auth_events_from_state_dag,
    order_missing_state_events_deterministic, validate_msc4242_prev_state_events, walk_state_dag,
    StateDagCompleteness, StateDagValidationError, StateDagWalkOptions,
};
use rezzy::HashMap;
use serde_json::json;

fn make_state_event(
    id: &str,
    event_type: &str,
    state_key: &str,
    sender: &str,
    prev_state_events: Vec<&str>,
    content: serde_json::Value,
    room_id: Option<&str>,
) -> LeanEvent {
    LeanEvent {
        event_id: id.to_string(),
        event_type: event_type.to_string(),
        state_key: Some(state_key.to_string()),
        sender: sender.to_string(),
        auth_events: prev_state_events
            .into_iter()
            .map(ToString::to_string)
            .collect(),
        content,
        room_id: room_id.map(RoomId::from),
        origin_server_ts: 1000,
        depth: 1,
        ..Default::default()
    }
}

fn make_timeline_event(
    id: &str,
    event_type: &str,
    sender: &str,
    prev_state_events: Vec<&str>,
    content: serde_json::Value,
    room_id: Option<&str>,
) -> LeanEvent {
    LeanEvent {
        event_id: id.to_string(),
        event_type: event_type.to_string(),
        state_key: None,
        sender: sender.to_string(),
        auth_events: prev_state_events
            .into_iter()
            .map(ToString::to_string)
            .collect(),
        content,
        room_id: room_id.map(RoomId::from),
        origin_server_ts: 1000,
        depth: 1,
        ..Default::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Validation Tests (validate_msc4242_prev_state_events)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_validation_create_event_cannot_have_prev_state_events() {
    let mut events = HashMap::new();
    let create_ev = make_state_event(
        "$create",
        M_ROOM_CREATE,
        "",
        "@alice:example.com",
        vec!["$invalid_parent"],
        json!({ "creator": "@alice:example.com" }),
        Some("!room:example.com"),
    );
    events.insert("$create".to_string(), create_ev.clone());

    let err = validate_msc4242_prev_state_events(&create_ev, &events).unwrap_err();
    assert_eq!(err, StateDagValidationError::CreateWithPrevStateEvents);
}

#[test]
fn test_validation_fanout_limit_exceeded() {
    let mut events = HashMap::new();
    let create_ev = make_state_event(
        "$create",
        M_ROOM_CREATE,
        "",
        "@alice:example.com",
        vec![],
        json!({ "creator": "@alice:example.com" }),
        Some("!room:example.com"),
    );
    events.insert("$create".to_string(), create_ev);

    let mut parent_ids = Vec::new();
    for i in 0..21 {
        let pid = format!("$p_{i}");
        let parent_ev = make_state_event(
            &pid,
            M_ROOM_MEMBER,
            &format!("@user_{i}:example.com"),
            "@alice:example.com",
            vec!["$create"],
            json!({ "membership": "join" }),
            Some("!room:example.com"),
        );
        events.insert(pid.clone(), parent_ev);
        parent_ids.push(pid);
    }

    let excessive_ev = make_state_event(
        "$excessive",
        M_ROOM_MEMBER,
        "@target:example.com",
        "@alice:example.com",
        parent_ids.iter().map(String::as_str).collect(),
        json!({ "membership": "join" }),
        Some("!room:example.com"),
    );

    let err = validate_msc4242_prev_state_events(&excessive_ev, &events).unwrap_err();
    assert_eq!(
        err,
        StateDagValidationError::FanoutExceeded {
            count: 21,
            limit: 20
        }
    );
}

#[test]
fn test_prev_state_events_fanout_limit_only_applies_to_v22() {
    // The 20-event `prev_state_events` cap is an MSC4242 rule that only
    // applies to V2.2 rooms; non-V2.2 events are not subject to it.
    let prev_state_events = (0..21).map(|i| format!("$p{i}")).collect::<Vec<_>>();
    let raw = json!({
        "event_id": "$e",
        "type": M_ROOM_MEMBER,
        "state_key": "@a:example.com",
        "sender": "@a:example.com",
        "prev_state_events": prev_state_events,
        "content": { "membership": "join" }
    });

    // Non-V2.2 room (v11): limit not enforced.
    // v11 reads `auth_events`, not `prev_state_events`, so set it explicitly;
    // 21 entries must still trip the v11 10-entry `auth_events` cap.
    let mut v11_raw = raw.clone();
    v11_raw["auth_events"] = json!(prev_state_events);
    let ev = LeanEvent::from_value(&v11_raw, Some("11")).unwrap();
    assert!(ev.validate_syntactic("11").is_err());
    // And an empty citation list is accepted under v11.
    let ev = LeanEvent::from_value(&raw, Some("11")).unwrap();
    assert!(ev.validate_syntactic("11").is_ok());
    // V2.2 (MSC4242): limit enforced.
    let ev = LeanEvent::from_value(&raw, Some("org.matrix.msc4242.12")).unwrap();
    assert!(ev.validate_syntactic("org.matrix.msc4242.12").is_err());
}

/// MSC4242 removes sender-specified `auth_events`; its state-DAG citations
/// are carried exclusively by `prev_state_events`.
#[test]
fn test_msc4242_rejects_legacy_auth_events_field() {
    let raw = json!({
        "type": M_ROOM_MEMBER,
        "state_key": "@a:example.com",
        "sender": "@a:example.com",
        "auth_events": ["$forged"],
        "prev_state_events": ["$state"],
        "content": {"membership": "join"}
    });
    let err = LeanEvent::from_value(&raw, Some("org.matrix.msc4242.12")).unwrap_err();
    assert!(err.to_string().contains("auth_events is not permitted"));
}

#[test]
fn test_validation_rejects_non_state_event_in_prev_state_events() {
    let mut events = HashMap::new();
    let msg_ev = make_timeline_event(
        "$msg",
        "m.room.message",
        "@alice:example.com",
        vec![],
        json!({ "body": "hello" }),
        Some("!room:example.com"),
    );
    events.insert("$msg".to_string(), msg_ev);

    let member_ev = make_state_event(
        "$member",
        M_ROOM_MEMBER,
        "@bob:example.com",
        "@bob:example.com",
        vec!["$msg"],
        json!({ "membership": "join" }),
        Some("!room:example.com"),
    );

    let err = validate_msc4242_prev_state_events(&member_ev, &events).unwrap_err();
    assert_eq!(
        err,
        StateDagValidationError::ReferencedNonStateEvent {
            citing_event: "$member".to_string(),
            referenced_event: "$msg".to_string(),
        }
    );
}

#[test]
fn test_validation_non_create_without_prev_state_events_rejected() {
    let events = HashMap::new();
    let orphan_pl = make_state_event(
        "$orphan_pl",
        M_ROOM_POWER_LEVELS,
        "",
        "@alice:example.com",
        vec![],
        json!({}),
        Some("!room:example.com"),
    );

    let err = validate_msc4242_prev_state_events(&orphan_pl, &events).unwrap_err();
    assert_eq!(
        err,
        StateDagValidationError::NonCreateWithoutPrevStateEvents {
            event_id: "$orphan_pl".to_string(),
        }
    );
}

#[test]
fn test_validation_rejects_rejected_event_in_prev_state_events() {
    let mut events = HashMap::new();
    let mut rejected_pl = make_state_event(
        "$rejected_pl",
        M_ROOM_POWER_LEVELS,
        "",
        "@eve:example.com",
        vec!["$create"],
        json!({ "users": { "@eve:example.com": 100 } }),
        Some("!room:example.com"),
    );
    rejected_pl.rejected = true;
    events.insert("$rejected_pl".to_string(), rejected_pl);

    let next_ev = make_state_event(
        "$next",
        M_ROOM_JOIN_RULES,
        "",
        "@eve:example.com",
        vec!["$rejected_pl"],
        json!({ "join_rule": "public" }),
        Some("!room:example.com"),
    );

    let err = validate_msc4242_prev_state_events(&next_ev, &events).unwrap_err();
    assert_eq!(
        err,
        StateDagValidationError::ReferencedRejectedEvent {
            citing_event: "$next".to_string(),
            referenced_event: "$rejected_pl".to_string(),
        }
    );
}

#[test]
fn test_validation_rejects_foreign_room_in_prev_state_events() {
    let mut events = HashMap::new();
    let foreign_ev = make_state_event(
        "$foreign",
        M_ROOM_CREATE,
        "",
        "@eve:example.com",
        vec![],
        json!({ "creator": "@eve:example.com" }),
        Some("!foreign_room:example.com"),
    );
    events.insert("$foreign".to_string(), foreign_ev);

    let citing_ev = make_state_event(
        "$citing",
        M_ROOM_MEMBER,
        "@eve:example.com",
        "@eve:example.com",
        vec!["$foreign"],
        json!({ "membership": "join" }),
        Some("!local_room:example.com"),
    );

    let err = validate_msc4242_prev_state_events(&citing_ev, &events).unwrap_err();
    assert_eq!(
        err,
        StateDagValidationError::ReferencedForeignRoom {
            citing_event: "$citing".to_string(),
            referenced_event: "$foreign".to_string(),
            expected_room: "!local_room:example.com".to_string(),
            actual_room: Some("!foreign_room:example.com".to_string()),
        }
    );
}

#[test]
fn test_validation_reports_missing_event_in_prev_state_events() {
    let events = HashMap::new();
    let citing_ev = make_state_event(
        "$citing",
        M_ROOM_MEMBER,
        "@alice:example.com",
        "@alice:example.com",
        vec!["$missing_create"],
        json!({ "membership": "join" }),
        Some("!room:example.com"),
    );

    let err = validate_msc4242_prev_state_events(&citing_ev, &events).unwrap_err();
    assert_eq!(
        err,
        StateDagValidationError::MissingReferencedEvent {
            citing_event: "$citing".to_string(),
            missing_id: "$missing_create".to_string(),
        }
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Traversal & Completeness Tests (walk_state_dag)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_walk_state_dag_complete_linear_path() {
    let mut events = HashMap::new();
    let create = make_state_event(
        "$create",
        M_ROOM_CREATE,
        "",
        "@alice:example.com",
        vec![],
        json!({}),
        None,
    );
    let pl = make_state_event(
        "$pl",
        M_ROOM_POWER_LEVELS,
        "",
        "@alice:example.com",
        vec!["$create"],
        json!({}),
        None,
    );
    let join = make_state_event(
        "$join",
        M_ROOM_MEMBER,
        "@alice:example.com",
        "@alice:example.com",
        vec!["$pl"],
        json!({ "membership": "join" }),
        None,
    );

    events.insert("$create".to_string(), create);
    events.insert("$pl".to_string(), pl);
    events.insert("$join".to_string(), join);

    let target_id = "$join".to_string();
    let result = walk_state_dag(&[&target_id], &events, StateDagWalkOptions::default());

    match result {
        StateDagCompleteness::Complete {
            create_event_id,
            state_event_count,
        } => {
            assert_eq!(create_event_id, "$create");
            assert_eq!(state_event_count, 3);
        }
        StateDagCompleteness::Incomplete { .. } => panic!("expected complete state DAG"),
    }
}

#[test]
fn test_walk_state_dag_incomplete_missing_gap() {
    let mut events = HashMap::new();
    let pl = make_state_event(
        "$pl",
        M_ROOM_POWER_LEVELS,
        "",
        "@alice:example.com",
        vec!["$create_missing"],
        json!({}),
        None,
    );
    let join = make_state_event(
        "$join",
        M_ROOM_MEMBER,
        "@alice:example.com",
        "@alice:example.com",
        vec!["$pl"],
        json!({ "membership": "join" }),
        None,
    );

    events.insert("$pl".to_string(), pl);
    events.insert("$join".to_string(), join);

    let target_id = "$join".to_string();
    let result = walk_state_dag(&[&target_id], &events, StateDagWalkOptions::default());

    match result {
        StateDagCompleteness::Incomplete {
            missing_event_ids,
            disconnected_event_ids,
            reachable_event_ids,
        } => {
            assert_eq!(missing_event_ids, vec!["$create_missing"]);
            assert_eq!(disconnected_event_ids, [] as [std::string::String; 0]);
            assert!(reachable_event_ids.contains(&"$join".to_string()));
            assert!(reachable_event_ids.contains(&"$pl".to_string()));
        }
        StateDagCompleteness::Complete { .. } => panic!("expected incomplete state DAG"),
    }
}

#[test]
fn test_walk_state_dag_incomplete_disconnected_leaf() {
    let mut events = HashMap::new();
    let disconnected_pl = make_state_event(
        "$disconnected_pl",
        M_ROOM_POWER_LEVELS,
        "",
        "@alice:example.com",
        vec![],
        json!({}),
        None,
    );
    let join = make_state_event(
        "$join",
        M_ROOM_MEMBER,
        "@alice:example.com",
        "@alice:example.com",
        vec!["$disconnected_pl"],
        json!({ "membership": "join" }),
        None,
    );

    events.insert("$disconnected_pl".to_string(), disconnected_pl);
    events.insert("$join".to_string(), join);

    let target_id = "$join".to_string();
    let result = walk_state_dag(&[&target_id], &events, StateDagWalkOptions::default());

    match result {
        StateDagCompleteness::Incomplete {
            missing_event_ids,
            disconnected_event_ids,
            reachable_event_ids,
        } => {
            assert_eq!(missing_event_ids, [] as [std::string::String; 0]);
            assert_eq!(disconnected_event_ids, vec!["$disconnected_pl"]);
            assert!(reachable_event_ids.contains(&"$join".to_string()));
            assert!(reachable_event_ids.contains(&"$disconnected_pl".to_string()));
        }
        StateDagCompleteness::Complete { .. } => panic!("expected incomplete state DAG"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Deterministic Missing Events Ordering (order_missing_state_events_deterministic)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_order_missing_state_events_deterministic_hops_and_ascii_tiebreak() {
    let mut events = HashMap::new();

    // Latest event citing 3 parents: $Z_hop1, $A_hop1, $M_hop1
    let latest = make_timeline_event(
        "$tip",
        "m.room.message",
        "@alice:example.com",
        vec!["$Z_hop1", "$A_hop1", "$M_hop1"],
        json!({}),
        None,
    );
    events.insert("$tip".to_string(), latest);

    // Hop 1 parents cite hop 2 parents:
    // $A_hop1 cites $B_hop2
    // $Z_hop1 cites $a_hop2 (ASCII 97 > uppercase 65-90)
    let a1 = make_state_event(
        "$A_hop1",
        M_ROOM_MEMBER,
        "@a:x",
        "@a:x",
        vec!["$B_hop2"],
        json!({}),
        None,
    );
    let z1 = make_state_event(
        "$Z_hop1",
        M_ROOM_MEMBER,
        "@z:x",
        "@z:x",
        vec!["$a_hop2"],
        json!({}),
        None,
    );
    let m1 = make_state_event(
        "$M_hop1",
        M_ROOM_MEMBER,
        "@m:x",
        "@m:x",
        vec![],
        json!({}),
        None,
    );

    let b2 = make_state_event(
        "$B_hop2",
        M_ROOM_CREATE,
        "",
        "@root:x",
        vec![],
        json!({}),
        None,
    );
    let a2 = make_state_event(
        "$a_hop2",
        M_ROOM_CREATE,
        "",
        "@root:x",
        vec![],
        json!({}),
        None,
    );

    events.insert("$A_hop1".to_string(), a1);
    events.insert("$Z_hop1".to_string(), z1);
    events.insert("$M_hop1".to_string(), m1);
    events.insert("$B_hop2".to_string(), b2);
    events.insert("$a_hop2".to_string(), a2);

    let tip_id = "$tip".to_string();
    let ordered = order_missing_state_events_deterministic(&[&tip_id], &events, 10);

    // Expected order:
    // Hops 1: $A_hop1, $M_hop1, $Z_hop1 (ASCII lexicographic order among hop 1)
    // Hops 2: $B_hop2 (uppercase B: ASCII 66) before $a_hop2 (lowercase a: ASCII 97)
    assert_eq!(
        ordered,
        vec!["$A_hop1", "$M_hop1", "$Z_hop1", "$B_hop2", "$a_hop2"]
    );
}

#[test]
fn test_order_missing_state_events_respects_limit() {
    let mut events = HashMap::new();
    let latest = make_timeline_event(
        "$tip",
        "m.room.message",
        "@alice:example.com",
        vec!["$1", "$2", "$3", "$4", "$5"],
        json!({}),
        None,
    );
    events.insert("$tip".to_string(), latest);

    for i in 1..=5 {
        let id = format!("${i}");
        events.insert(
            id.clone(),
            make_state_event(&id, M_ROOM_MEMBER, &id, "@u:x", vec![], json!({}), None),
        );
    }

    let tip_id = "$tip".to_string();
    let ordered = order_missing_state_events_deterministic(&[&tip_id], &events, 2);
    assert_eq!(ordered.len(), 2);
    assert_eq!(ordered, vec!["$1", "$2"]);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. State Computation & Resolution (compute_state_before/after_from_dag)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_compute_state_from_dag_linear_chain() {
    let mut events = HashMap::new();
    let empty_key = String::new();

    let create = make_state_event(
        "$create",
        M_ROOM_CREATE,
        "",
        "@alice:example.com",
        vec![],
        json!({ "creator": "@alice:example.com" }),
        None,
    );
    let pl = make_state_event(
        "$pl",
        M_ROOM_POWER_LEVELS,
        "",
        "@alice:example.com",
        vec!["$create"],
        json!({ "users": { "@alice:example.com": 100 } }),
        None,
    );
    let join_alice = make_state_event(
        "$join_alice",
        M_ROOM_MEMBER,
        "@alice:example.com",
        "@alice:example.com",
        vec!["$pl"],
        json!({ "membership": "join" }),
        None,
    );

    events.insert("$create".to_string(), create.clone());
    events.insert("$pl".to_string(), pl.clone());
    events.insert("$join_alice".to_string(), join_alice.clone());

    let state_before =
        compute_state_before_from_dag(&join_alice, &events, StateResVersion::V2_2, &empty_key)
            .expect("compute state before");

    assert_eq!(
        state_before.get(&(EventType::from(M_ROOM_CREATE), empty_key.clone())),
        Some(&"$create".to_string())
    );
    assert_eq!(
        state_before.get(&(EventType::from(M_ROOM_POWER_LEVELS), empty_key.clone())),
        Some(&"$pl".to_string())
    );
    assert_eq!(
        state_before.get(&(
            EventType::from(M_ROOM_MEMBER),
            "@alice:example.com".to_string()
        )),
        None
    );

    let state_after =
        compute_state_after_from_dag(&join_alice, &events, StateResVersion::V2_2, &empty_key)
            .expect("compute state after");

    assert_eq!(
        state_after.get(&(
            EventType::from(M_ROOM_MEMBER),
            "@alice:example.com".to_string()
        )),
        Some(&"$join_alice".to_string())
    );
}

#[test]
fn test_compute_state_from_dag_fork_resolution() {
    let mut events = HashMap::new();
    let empty_key = String::new();

    let create = make_state_event(
        "$create",
        M_ROOM_CREATE,
        "",
        "@creator:example.com",
        vec![],
        json!({ "creator": "@creator:example.com" }),
        None,
    );

    let mut pl_root = make_state_event(
        "$pl_root",
        M_ROOM_POWER_LEVELS,
        "",
        "@creator:example.com",
        vec!["$create"],
        json!({ "users": { "@creator:example.com": 100 } }),
        None,
    );
    pl_root.origin_server_ts = 100;
    pl_root.depth = 1;

    let mut join_rules = make_state_event(
        "$jr",
        M_ROOM_JOIN_RULES,
        "",
        "@creator:example.com",
        vec!["$pl_root"],
        json!({ "join_rule": "public" }),
        None,
    );
    join_rules.origin_server_ts = 150;
    join_rules.depth = 2;

    // Fork A: Topic changed by @creator:example.com
    let mut topic_a = make_state_event(
        "$topic_a",
        "m.room.topic",
        "",
        "@creator:example.com",
        vec!["$jr"],
        json!({ "topic": "Topic A" }),
        None,
    );
    topic_a.origin_server_ts = 200;
    topic_a.depth = 3;

    // Fork B: Member Bob joins on Fork B
    let mut member_bob = make_state_event(
        "$member_bob",
        M_ROOM_MEMBER,
        "@bob:example.com",
        "@bob:example.com",
        vec!["$jr"],
        json!({ "membership": "join" }),
        None,
    );
    member_bob.origin_server_ts = 300;
    member_bob.depth = 3;

    // Merge event citing both forks in prev_state_events
    let mut merge = make_timeline_event(
        "$merge",
        "m.room.message",
        "@creator:example.com",
        vec!["$topic_a", "$member_bob"],
        json!({ "body": "merge" }),
        None,
    );
    merge.depth = 4;

    events.insert("$create".to_string(), create);
    events.insert("$pl_root".to_string(), pl_root);
    events.insert("$jr".to_string(), join_rules);
    events.insert("$topic_a".to_string(), topic_a);
    events.insert("$member_bob".to_string(), member_bob);
    events.insert("$merge".to_string(), merge.clone());

    let state_before_merge =
        compute_state_before_from_dag(&merge, &events, StateResVersion::V2_2, &empty_key)
            .expect("state before merge");

    // Both topic A and Bob's membership should be present in the resolved state!
    assert_eq!(
        state_before_merge.get(&(EventType::from("m.room.topic"), empty_key.clone())),
        Some(&"$topic_a".to_string())
    );
    assert_eq!(
        state_before_merge.get(&(
            EventType::from(M_ROOM_MEMBER),
            "@bob:example.com".to_string()
        )),
        Some(&"$member_bob".to_string())
    );
}

/// A complete State DAG has one deterministic state-before result. Storage-map
/// insertion order must not affect which state tuple wins at a merge.
#[test]
fn test_compute_state_from_dag_is_deterministic_across_storage_order() {
    let empty_key = String::new();
    let create = make_state_event(
        "$create",
        M_ROOM_CREATE,
        "",
        "@creator:example.com",
        vec![],
        json!({ "creator": "@creator:example.com" }),
        None,
    );
    let mut name_a = make_state_event(
        "$name_a",
        "m.room.name",
        "",
        "@creator:example.com",
        vec!["$create"],
        json!({ "name": "A" }),
        None,
    );
    let mut name_b = make_state_event(
        "$name_b",
        "m.room.name",
        "",
        "@creator:example.com",
        vec!["$create"],
        json!({ "name": "B" }),
        None,
    );
    // Force the resolver's final event-ID tie-break rather than relying on a
    // storage iteration order or differing timestamps.
    name_a.origin_server_ts = 500;
    name_b.origin_server_ts = 500;
    name_a.depth = 2;
    name_b.depth = 2;
    let merge = make_timeline_event(
        "$merge",
        "m.room.message",
        "@creator:example.com",
        vec!["$name_a", "$name_b"],
        json!({ "body": "merge" }),
        None,
    );

    let all_events = [create, name_a, name_b, merge.clone()];
    let mut forward = HashMap::new();
    let mut reverse = HashMap::new();
    for event in &all_events {
        forward.insert(event.event_id.clone(), event.clone());
    }
    for event in all_events.iter().rev() {
        reverse.insert(event.event_id.clone(), event.clone());
    }

    let state_forward =
        compute_state_before_from_dag(&merge, &forward, StateResVersion::V2_2, &empty_key)
            .expect("complete State DAG must resolve");
    let state_reverse =
        compute_state_before_from_dag(&merge, &reverse, StateResVersion::V2_2, &empty_key)
            .expect("complete State DAG must resolve regardless of storage order");

    assert_eq!(state_forward, state_reverse);
    assert_eq!(
        state_forward.get(&(EventType::from("m.room.name"), empty_key)),
        Some(&"$name_b".to_string()),
        "equal timestamp candidates use the deterministic event-ID tie-break"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Auth Events Derivation (derive_auth_events_from_state_dag)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_derive_auth_events_for_membership() {
    let mut events = HashMap::new();
    let empty_key = String::new();

    let create = make_state_event(
        "$create",
        M_ROOM_CREATE,
        "",
        "@creator:example.com",
        vec![],
        json!({ "creator": "@creator:example.com" }),
        None,
    );
    let pl = make_state_event(
        "$pl",
        M_ROOM_POWER_LEVELS,
        "",
        "@creator:example.com",
        vec!["$create"],
        json!({ "users": { "@creator:example.com": 100 } }),
        None,
    );
    let join_rules = make_state_event(
        "$jr",
        M_ROOM_JOIN_RULES,
        "",
        "@creator:example.com",
        vec!["$pl"],
        json!({ "join_rule": "public" }),
        None,
    );
    let creator_join = make_state_event(
        "$creator_join",
        M_ROOM_MEMBER,
        "@creator:example.com",
        "@creator:example.com",
        vec!["$jr"],
        json!({ "membership": "join" }),
        None,
    );

    events.insert("$create".to_string(), create);
    events.insert("$pl".to_string(), pl);
    events.insert("$jr".to_string(), join_rules);
    events.insert("$creator_join".to_string(), creator_join.clone());

    let state_at_tip =
        compute_state_after_from_dag(&creator_join, &events, StateResVersion::V2_2, &empty_key)
            .expect("state after creator join");

    // A new user (@bob) joins the room
    let bob_join = make_state_event(
        "$bob_join",
        M_ROOM_MEMBER,
        "@bob:example.com",
        "@bob:example.com",
        vec!["$creator_join"],
        json!({ "membership": "join" }),
        None,
    );

    let auth_events = derive_auth_events_from_state_dag(&bob_join, &state_at_tip, &events, "12.1")
        .expect("derive auth events");

    // In V2.1+ / V2.2, create is omitted.
    // Member join requires: sender member (none yet for @bob), power_levels ($pl), join_rules ($jr)
    assert!(auth_events.contains(&"$pl".to_string()));
    assert!(auth_events.contains(&"$jr".to_string()));
    assert!(!auth_events.contains(&"$create".to_string()));
}

#[test]
fn test_derive_auth_events_rejects_if_auth_event_is_rejected() {
    let mut events = HashMap::new();
    let empty_key = String::new();

    let create = make_state_event(
        "$create",
        M_ROOM_CREATE,
        "",
        "@creator:example.com",
        vec![],
        json!({}),
        None,
    );
    let mut pl = make_state_event(
        "$pl_rejected",
        M_ROOM_POWER_LEVELS,
        "",
        "@creator:example.com",
        vec!["$create"],
        json!({}),
        None,
    );
    pl.rejected = true;

    events.insert("$create".to_string(), create);
    events.insert("$pl_rejected".to_string(), pl);

    let mut state = rezzy::state::at::SharedState::new();
    state.insert(
        (EventType::from(M_ROOM_POWER_LEVELS), empty_key.clone()),
        "$pl_rejected".to_string(),
    );

    let msg = make_timeline_event(
        "$msg",
        "m.room.message",
        "@creator:example.com",
        vec!["$pl_rejected"],
        json!({}),
        None,
    );

    let err = derive_auth_events_from_state_dag(&msg, &state, &events, "12.1").unwrap_err();
    assert_eq!(
        err,
        rezzy::auth::AuthError::RejectedAuthEvent {
            event_id: "$msg".to_string(),
            auth_event_id: "$pl_rejected".to_string(),
        }
    );
}

/// Builds a `RoomState` (event-keyed) from a `SharedState` (id-keyed) result by
/// resolving each state tuple's id back to its full event via `events_map`.
fn room_state_from_shared(
    shared: &rezzy::state::at::SharedState<String, String>,
    events_map: &HashMap<String, LeanEvent>,
) -> RoomState {
    let mut room_state = RoomState::new();
    for ((event_type, state_key), event_id) in shared {
        let event = events_map
            .get(event_id)
            .expect("state tuple must reference a known event")
            .clone();
        room_state.insert((event_type.to_string(), state_key.clone()), event);
    }
    room_state
}

/// End-to-end companion to `test_v2_1_strictness_future_v2_2_should_pass` in
/// `test_traversal.rs`. That test shows V2.1 rightfully rejects a join whose
/// flat `auth_events` list omits a required type (here: `m.room.power_levels`),
/// because in V2.1 the client itself must separately enumerate every required
/// auth type's event id. V2.2 removes that flat list entirely: a state event
/// cites only its true state parent via `prev_state_events`, and the receiver
/// *derives* every required auth event from `state_before` (walked from that
/// single citation), rather than trusting a client-supplied enumeration. This
/// test shows the derived set is correct — and sufficient for authorization —
/// from Bob's single, honest `prev_state_events` citation alone, with no flat
/// auth-type list for a client to get wrong in the first place. `state_at(e)`
/// is a pure function of the DAG, so the verdict is determined by the DAG
/// shape a validated citation resolves to, not by an auth-type enumeration.
#[test]
fn test_v2_2_derives_auth_from_single_state_parent_citation() {
    let mut events = HashMap::new();
    let empty_key = String::new();

    let create = make_state_event(
        "$create",
        M_ROOM_CREATE,
        "",
        "@alice:example.com",
        vec![],
        json!({ "creator": "@alice:example.com" }),
        None,
    );
    let pl = make_state_event(
        "$pl",
        M_ROOM_POWER_LEVELS,
        "",
        "@alice:example.com",
        vec!["$create"],
        json!({ "users": { "@alice:example.com": 100 } }),
        None,
    );
    let join_rules = make_state_event(
        "$jr",
        M_ROOM_JOIN_RULES,
        "",
        "@alice:example.com",
        vec!["$pl"],
        json!({ "join_rule": "public" }),
        None,
    );

    events.insert("$create".to_string(), create);
    events.insert("$pl".to_string(), pl);
    events.insert("$jr".to_string(), join_rules.clone());

    // Bob joins. He is allowed because the room is public. Unlike the V2.1
    // fixture, Bob does not enumerate `$create`/`$pl`/`$jr` himself at all —
    // he cites only his one true state parent, `$jr`.
    let bob_join = make_state_event(
        "$bob_join",
        M_ROOM_MEMBER,
        "@bob:example.com",
        "@bob:example.com",
        vec!["$jr"],
        json!({ "membership": "join" }),
        None,
    );

    let state_before =
        compute_state_before_from_dag(&bob_join, &events, StateResVersion::V2_2, &empty_key)
            .expect("state before bob's join");

    // Both power_levels and join_rules are reachable via the validated
    // prev_state_events DAG, even though Bob cited neither directly.
    assert_eq!(
        state_before.get(&(EventType::from(M_ROOM_POWER_LEVELS), empty_key.clone())),
        Some(&"$pl".to_string())
    );
    assert_eq!(
        state_before.get(&(EventType::from(M_ROOM_JOIN_RULES), empty_key.clone())),
        Some(&"$jr".to_string())
    );

    let derived_auth = derive_auth_events_from_state_dag(&bob_join, &state_before, &events, "12.1")
        .expect("derive auth events from state DAG");
    assert!(
        derived_auth.contains(&"$pl".to_string()),
        "derived auth events must include power_levels, though Bob never cited it"
    );
    assert!(
        derived_auth.contains(&"$jr".to_string()),
        "derived auth events must include join_rules"
    );
    assert!(
        !derived_auth.contains(&"$create".to_string()),
        "create is never a V2.1+ auth event"
    );

    // Authorize using the DAG-derived auth events (what a V2.2 receiver
    // actually authorizes against), not a client-supplied flat list.
    let mut authorized_bob_join = bob_join;
    authorized_bob_join.auth_events = derived_auth;

    let room_state = room_state_from_shared(&state_before, &events);

    let result = check_auth_with_context(
        &authorized_bob_join,
        &room_state,
        StateResVersion::V2_2,
        None,
        Some(&events),
    );
    assert!(
        result.is_ok(),
        "V2.2 should accept the join once auth is derived from the validated State DAG: {result:?}"
    );
}
