use crate::utils;
use std::collections::HashMap;
extern crate alloc;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::too_many_lines, clippy::type_complexity, clippy::similar_names)]
mod tests {

    use super::alloc::string::ToString;
    use super::alloc::vec;
    use super::utils;
    use core::cmp::Ordering;
    use rezzy::*;

    #[cfg(not(feature = "std"))]
    use hashbrown::HashMap;
    #[cfg(feature = "std")]
    #[test]
    fn test_leanevent_deserialization_defaults() {
        let json = r#"{
			"event_id": "$test",
			"type": "m.room.message",
			"origin_server_ts": 12345
		}"#;
        let ev: LeanEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.event_id, "$test");
        assert_eq!(ev.event_type, "m.room.message");
        assert_eq!(ev.origin_server_ts, 12345);
        assert_eq!(ev.state_key, None);
        assert_eq!(ev.power_level, 0);
        assert_eq!(ev.sender, "");
        assert_eq!(ev.prev_events.len(), 0);
        assert_eq!(ev.auth_events.len(), 0);
        assert_eq!(ev.depth, 0);
    }

    #[test]
    #[should_panic(expected = "fixture auth_context must contain exactly one m.room.create event")]
    fn test_missing_create_event_panics() {
        let auth_context = std::collections::HashMap::new();
        utils::build_unconflicted_state_test_helper(&auth_context);
    }

    #[test]
    fn test_is_ban_or_kick_self_leave_and_kick() {
        use serde_json::json;

        // Ban event: state_key doesn't matter (though typically is the target), is_ban_or_kick should be true
        let ban_event: LeanEvent = LeanEvent {
            event_id: "$ban".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@alice:example.com".into(),
            content: json!({ "membership": "ban" }),
            ..Default::default()
        };
        assert!(ban_event.is_ban_or_kick());

        // Self-leave event: state_key == sender, is_ban_or_kick should be false
        let self_leave_event: LeanEvent = LeanEvent {
            event_id: "$self_leave".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            sender: "@alice:example.com".into(),
            content: json!({ "membership": "leave" }),
            ..Default::default()
        };
        assert!(!self_leave_event.is_ban_or_kick());

        // Kick event: state_key != sender, is_ban_or_kick should be true
        let kick_event: LeanEvent = LeanEvent {
            event_id: "$kick".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@alice:example.com".into(),
            content: json!({ "membership": "leave" }),
            ..Default::default()
        };
        assert!(kick_event.is_ban_or_kick());

        // Leave event with state_key missing: is_ban_or_kick should be false
        let leave_no_state_key_event: LeanEvent = LeanEvent {
            event_id: "$leave_no_sk".into(),
            event_type: "m.room.member".into(),
            state_key: None,
            sender: "@alice:example.com".into(),
            content: json!({ "membership": "leave" }),
            ..Default::default()
        };
        assert!(!leave_no_state_key_event.is_ban_or_kick());

        // Non-member leave event: is_ban_or_kick should be false
        let non_member_event: LeanEvent = LeanEvent {
            event_id: "$non_member".into(),
            event_type: "m.room.message".into(),
            state_key: None,
            sender: "@alice:example.com".into(),
            content: json!({ "membership": "leave" }),
            ..Default::default()
        };
        assert!(!non_member_event.is_ban_or_kick());
    }

    #[test]
    fn test_route_power_events_excludes_third_party_invite() {
        use serde_json::json;
        use std::collections::HashMap;

        let mut sort_set = HashMap::new();

        let create_ev: LeanEvent<String, serde_json::Value, String> = LeanEvent {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            ..Default::default()
        };
        let pl_ev = LeanEvent {
            event_id: "$pl".into(),
            event_type: "m.room.power_levels".into(),
            ..Default::default()
        };
        let jr_ev = LeanEvent {
            event_id: "$jr".into(),
            event_type: "m.room.join_rules".into(),
            ..Default::default()
        };
        let tpi_ev = LeanEvent {
            event_id: "$tpi".into(),
            event_type: "m.room.third_party_invite".into(),
            ..Default::default()
        };
        let kick_ev = LeanEvent {
            event_id: "$kick".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@alice:example.com".into(),
            content: json!({ "membership": "leave" }),
            ..Default::default()
        };

        sort_set.insert("$create".to_string(), create_ev);
        sort_set.insert("$pl".to_string(), pl_ev);
        sort_set.insert("$jr".to_string(), jr_ev);
        sort_set.insert("$tpi".to_string(), tpi_ev);
        sort_set.insert("$kick".to_string(), kick_ev);

        let mut power_events = HashMap::new();
        let mut non_power_events = HashMap::new();
        rezzy::route_power_events(
            &sort_set,
            &mut power_events,
            &mut non_power_events,
            rezzy::StateResVersion::V2_1_1,
        );

        // create, power_levels, join_rules, and kick are power events
        assert!(power_events.contains_key("$create"));
        assert!(power_events.contains_key("$pl"));
        assert!(power_events.contains_key("$jr"));
        assert!(power_events.contains_key("$kick"));

        // m.room.third_party_invite MUST be a non-power event
        assert!(non_power_events.contains_key("$tpi"));
        assert!(!power_events.contains_key("$tpi"));
    }

    #[test]
    fn test_expand_v2_power_events_auth_chains_functionality() {
        use std::collections::HashMap;

        let mut sort_set = HashMap::new();

        // Let's have a kick event whose auth chain contains an event in the conflicted set ($auth_in_set).
        // Since $kick is a power event, $auth_in_set should be promoted to a power event as well.
        let kick_ev: LeanEvent<String, serde_json::Value, String> = LeanEvent {
            event_id: "$kick".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@alice:example.com".into(),
            content: serde_json::json!({ "membership": "leave" }),
            auth_events: vec!["$auth_in_set".to_string()],
            ..Default::default()
        };
        let auth_in_set = LeanEvent {
            event_id: "$auth_in_set".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            sender: "@alice:example.com".into(),
            content: serde_json::json!({ "membership": "join" }),
            auth_events: vec!["$deep_auth_in_set".to_string()],
            ..Default::default()
        };
        let deep_auth_in_set = LeanEvent {
            event_id: "$deep_auth_in_set".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@charlie:example.com".into()),
            sender: "@charlie:example.com".into(),
            content: serde_json::json!({ "membership": "join" }),
            ..Default::default()
        };

        sort_set.insert("$kick".to_string(), kick_ev);
        sort_set.insert("$auth_in_set".to_string(), auth_in_set);
        sort_set.insert("$deep_auth_in_set".to_string(), deep_auth_in_set);

        let mut power_events = HashMap::new();
        let mut non_power_events = HashMap::new();
        rezzy::route_power_events(
            &sort_set,
            &mut power_events,
            &mut non_power_events,
            rezzy::StateResVersion::V2_1_1,
        );

        // Before expansion, only $kick is a power event. $auth_in_set and $deep_auth_in_set are non-power.
        assert!(power_events.contains_key("$kick"));
        assert!(non_power_events.contains_key("$auth_in_set"));
        assert!(non_power_events.contains_key("$deep_auth_in_set"));

        // Run recursive V2 expansion
        rezzy::expand_v2_power_events_auth_chains(
            &mut power_events,
            &mut non_power_events,
            &sort_set,
        );

        // After expansion, $auth_in_set and $deep_auth_in_set are promoted to power events!
        assert!(power_events.contains_key("$kick"));
        assert!(power_events.contains_key("$auth_in_set"));
        assert!(power_events.contains_key("$deep_auth_in_set"));
        assert!(!non_power_events.contains_key("$auth_in_set"));
        assert!(!non_power_events.contains_key("$deep_auth_in_set"));
    }

    #[test]
    fn test_sort_priority_v2_tie_break() {
        let e_base: LeanEvent = LeanEvent {
            event_id: "$1".into(),
            power_level: 100,
            origin_server_ts: 10,
            ..Default::default()
        };
        let e_worst_pl: LeanEvent = LeanEvent {
            event_id: "$2".into(),
            power_level: 50,
            origin_server_ts: 10,
            ..Default::default()
        };
        let p_base = SortPriority {
            power_level: e_base.power_level,
            event: &e_base,
            version: rezzy::StateResVersion::V2,
        };
        let p_worst_pl = SortPriority {
            power_level: e_worst_pl.power_level,
            event: &e_worst_pl,
            version: rezzy::StateResVersion::V2,
        };

        // Higher PL is GREATER (pops first, loses for same key, but sets auth context first).
        assert_eq!(p_base.cmp(&p_worst_pl), Ordering::Greater); // p_base 100 > p_worst_pl 50.

        let e_later_ts: LeanEvent = LeanEvent {
            event_id: "$3".into(),
            power_level: 100,
            origin_server_ts: 20,
            ..Default::default()
        };
        let p_later_ts = SortPriority {
            power_level: e_later_ts.power_level,
            event: &e_later_ts,
            version: rezzy::StateResVersion::V2,
        };
        // p_later_ts has ts 20 (better — wins); later ts pops LAST = is Smaller.
        // p_base has ts 10 (worse) = Greater (pops first, loses).
        assert_eq!(p_base.cmp(&p_later_ts), Ordering::Greater);

        let e_larger_id: LeanEvent = LeanEvent {
            event_id: "$2".into(),
            power_level: 100,
            origin_server_ts: 10,
            ..Default::default()
        };
        let p_larger_id = SortPriority {
            power_level: e_larger_id.power_level,
            event: &e_larger_id,
            version: rezzy::StateResVersion::V2,
        };
        // p_larger_id has id "$2" (better — wins); larger id pops LAST = is Smaller.
        // p_base has id "$1" (worse) = Greater (pops first, loses).
        assert_eq!(p_base.cmp(&p_larger_id), Ordering::Greater);
    }

    #[test]
    fn test_sort_priority_clone() {
        let evs = utils::parse_jsonl_events(
            r#"
            {"event_id": "$a", "type": "m.room.member", "sender": "@a:x", "origin_server_ts": 10}
        "#,
        );
        let p = SortPriority {
            power_level: 50,
            event: &evs[0],
            version: rezzy::StateResVersion::V2_1_1,
        };
        #[allow(clippy::clone_on_copy)]
        let p2 = p.clone();
        assert_eq!(p.cmp(&p2), Ordering::Equal);
    }

    #[test]
    fn test_sort_priority_cross_version_ordering_is_symmetric() {
        let event: LeanEvent = LeanEvent {
            event_id: "$a".into(),
            depth: 1,
            origin_server_ts: 1,
            ..Default::default()
        };
        let p_v1 = SortPriority {
            power_level: 0,
            event: &event,
            version: rezzy::StateResVersion::V1,
        };
        let p_v2 = SortPriority {
            power_level: 0,
            event: &event,
            version: rezzy::StateResVersion::V2,
        };

        assert_ne!(p_v1, p_v2);
        assert_eq!(p_v1.eq(&p_v2), p_v2.eq(&p_v1));
        assert_eq!(p_v1.cmp(&p_v2), p_v2.cmp(&p_v1).reverse());
    }

    /// `cmp_by_depth`: depth ascending, then `event_id` ascending.
    #[test]
    fn test_cmp_by_depth() {
        let evs = utils::parse_jsonl_events(
            r#"
            {"event_id": "$a",  "type": "m.room.member", "sender": "@a:x", "depth": 5,  "origin_server_ts": 0}
            {"event_id": "$b",  "type": "m.room.member", "sender": "@a:x", "depth": 10, "origin_server_ts": 0}
            {"event_id": "$a2", "type": "m.room.member", "sender": "@a:x", "depth": 5,  "origin_server_ts": 0}
        "#,
        );
        // Different depth: lower depth comes first.
        assert_eq!(evs[0].cmp_by_depth(&evs[1]), Ordering::Less);
        assert_eq!(evs[1].cmp_by_depth(&evs[0]), Ordering::Greater);
        // Same depth: lexicographic event_id tie-break.
        assert_eq!(evs[0].cmp_by_depth(&evs[2]), Ordering::Less);
        assert_eq!(evs[0].cmp_by_depth(&evs[0]), Ordering::Equal);
    }

    #[test]
    fn test_v1_resolution_happy_path() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 0,
                origin_server_ts: 100,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 0,
                origin_server_ts: 50,
                prev_events: vec![],
                auth_events: vec!["A".into()],
                depth: 2,
                ..Default::default()
            },
        );
        let sorted = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V1,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(sorted, vec!["A", "B"]);
    }

    #[test]
    fn test_v2_1_strict_resolution() {
        let mut unconflicted = imbl::OrdMap::new();
        unconflicted.insert(
            (
                rezzy::basespec::event_types::EventType::from("m.room.member"),
                "@alice:example.com".into(),
            ),
            "A".into(),
        );

        let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
        conflicted.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 50,
                origin_server_ts: 100,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        conflicted.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 100,
                origin_server_ts: 50,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );

        // In V2.1, A should win because B (higher PL=100) is applied first and then
        // overwritten by A (lower PL=50) — lower PL pops last and wins for same-key conflicts.
        let resolved = resolve_iterative_sort(
            unconflicted,
            conflicted.clone(),
            &conflicted,
            rezzy::StateResVersion::V2_1,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(
            resolved.get(&(
                rezzy::basespec::event_types::EventType::from("m.room.member"),
                "@alice:example.com".into()
            )),
            Some(&"A".into())
        );
    }

    #[test]
    fn test_v1_tie_break_by_id() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 0,
                origin_server_ts: 100,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 0,
                origin_server_ts: 100,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V1,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(sorted, vec!["B", "A"]);
    }

    #[test]
    fn test_v2_resolution_happy_path() {
        let mut auth: HashMap<String, LeanEvent> = HashMap::new();
        let create_ev: LeanEvent = LeanEvent {
            event_id: "create".into(),
            event_type: "m.room.create".into(),
            sender: "@creator:example.com".into(),
            ..Default::default()
        };
        auth.insert("create".into(), create_ev.clone());

        let pl_ev: LeanEvent = LeanEvent {
            event_id: "pl".into(),
            event_type: "m.room.power_levels".into(),
            sender: "@creator:example.com".into(),
            content: serde_json::json!({
                "users": {
                    "@alice:example.com": 100,
                    "@bob:example.com": 50
                }
            }),
            ..Default::default()
        };
        auth.insert("pl".into(), pl_ev.clone());

        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        let ev_a: LeanEvent = LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            sender: "@alice:example.com".into(),
            origin_server_ts: 100,
            prev_events: vec![],
            auth_events: vec!["pl".into()],
            depth: 10,
            ..Default::default()
        };
        let ev_b: LeanEvent = LeanEvent {
            event_id: "B".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@bob:example.com".into(),
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec!["pl".into()],
            depth: 1,
            ..Default::default()
        };
        events.insert("A".into(), ev_a.clone());
        events.insert("B".into(), ev_b.clone());

        auth.insert("A".into(), ev_a);
        auth.insert("B".into(), ev_b);

        let sorted = rezzy::lean_kahn_sort(
            &events,
            &auth,
            Some(&create_ev),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        // B (lower PL=50) pops first (worst event first). A pops last, wins.
        assert_eq!(sorted, vec!["B", "A"]);
    }

    #[test]
    fn test_v2_deep_tie_break() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        // Best (B, larger ID) comes LAST.
        assert_eq!(sorted, vec!["A", "B"]);
    }

    #[test]
    fn test_v1_v2_v2_1_comparison_determinism() {
        let mut auth: HashMap<String, LeanEvent> = HashMap::new();
        let create_ev: LeanEvent = LeanEvent {
            event_id: "create".into(),
            event_type: "m.room.create".into(),
            sender: "@creator:example.com".into(),
            ..Default::default()
        };
        auth.insert("create".into(), create_ev.clone());

        let pl_ev: LeanEvent = LeanEvent {
            event_id: "pl".into(),
            event_type: "m.room.power_levels".into(),
            sender: "@creator:example.com".into(),
            content: serde_json::json!({
                "users": {
                    "@alice:example.com": 10,
                    "@bob:example.com": 100
                }
            }),
            ..Default::default()
        };
        auth.insert("pl".into(), pl_ev.clone());

        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        let ev_a: LeanEvent = LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            sender: "@alice:example.com".into(),
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec!["pl".into()],
            depth: 1,
            ..Default::default()
        };
        let ev_b: LeanEvent = LeanEvent {
            event_id: "B".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@bob:example.com".into(),
            origin_server_ts: 100,
            prev_events: vec![],
            auth_events: vec!["pl".into()],
            depth: 10,
            ..Default::default()
        };
        events.insert("A".into(), ev_a.clone());
        events.insert("B".into(), ev_b.clone());

        auth.insert("A".into(), ev_a);
        auth.insert("B".into(), ev_b);

        let sorted_v1 = rezzy::lean_kahn_sort(
            &events,
            &auth,
            Some(&create_ev),
            rezzy::StateResVersion::V1,
            &mut std::collections::HashMap::new(),
        );
        let sorted_v2 = rezzy::lean_kahn_sort(
            &events,
            &auth,
            Some(&create_ev),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        let sorted_v2_1 = rezzy::lean_kahn_sort(
            &events,
            &auth,
            Some(&create_ev),
            rezzy::StateResVersion::V2_1,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(sorted_v1, vec!["B", "A"]);
        // A (lower power level) pops FIRST in V2 and V2.1 — applied first, loses for same key.
        assert_eq!(sorted_v2, vec!["A", "B"]);
        assert_eq!(sorted_v2_1, vec!["A", "B"]);
    }

    #[test]
    fn test_unhappy_path_cycle_detection() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec!["B".into()],
                auth_events: vec!["B".into()],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec!["A".into()],
                auth_events: vec!["A".into()],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        assert!(!sorted.is_empty());
        assert_eq!(sorted, vec!["A", "B"]);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let event: LeanEvent = LeanEvent {
            event_id: "$abc".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            power_level: 100,
            origin_server_ts: 12345,
            prev_events: vec![],
            auth_events: vec![],
            depth: 5,
            ..Default::default()
        };
        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: LeanEvent = serde_json::from_str(&serialized).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_serialization_roundtrip_state_key_none() {
        // A LeanEvent with no state_key: the Serialize impl's
        // `if let Some(state_key)` branch is skipped, exercising the None
        // fall-through.
        let event: LeanEvent = LeanEvent {
            event_id: "$abc".into(),
            event_type: "m.room.message".into(),
            state_key: None,
            power_level: 100,
            origin_server_ts: 12345,
            prev_events: vec![],
            auth_events: vec![],
            depth: 5,
            ..Default::default()
        };
        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: LeanEvent = serde_json::from_str(&serialized).unwrap();
        assert_eq!(event, deserialized);
        assert_eq!(deserialized.state_key, None);
    }

    #[test]
    fn test_redacts_top_level_is_promoted_into_content() {
        let event_json = r#"{
            "event_id": "$redact",
            "type": "m.room.redaction",
            "sender": "@alice:example.com",
            "content": {},
            "redacts": "$target:example.com"
        }"#;
        let event: LeanEvent = serde_json::from_str(event_json).unwrap();
        assert_eq!(event.get_redacts(), Some("$target:example.com"));
    }

    #[test]
    fn test_redaction_accepts_matching_top_level_and_content_redacts() {
        // Both the top-level `redacts` field and `content.redacts` are present
        // and agree: `from_value` takes the equality fall-through rather than
        // the mismatch error branch.
        let event_json = r#"{
            "event_id": "$redact",
            "type": "m.room.redaction",
            "sender": "@alice:example.com",
            "content": { "redacts": "$target:example.com" },
            "redacts": "$target:example.com"
        }"#;
        let event: LeanEvent = serde_json::from_str(event_json).unwrap();
        assert_eq!(event.get_redacts(), Some("$target:example.com"));
    }

    #[test]
    fn test_partial_ord_implementations() {
        let e1: LeanEvent = LeanEvent {
            event_id: "a".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let e2: LeanEvent = LeanEvent {
            event_id: "b".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        assert!(e1.partial_cmp(&e2).is_some());

        let p1 = SortPriority {
            power_level: e1.power_level,
            event: &e1,
            version: rezzy::StateResVersion::V2,
        };
        let p2 = SortPriority {
            power_level: e2.power_level,
            event: &e2,
            version: rezzy::StateResVersion::V2,
        };
        assert!(p1.partial_cmp(&p2).is_some());
    }

    #[test]
    fn test_trait_coverage() {
        let v = rezzy::StateResVersion::V2;
        assert_eq!(v, rezzy::StateResVersion::V2);
        let _ = format!("{v:?}");

        let e: LeanEvent = LeanEvent {
            event_id: "a".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let _ = e.clone();
        let _ = format!("{e:?}");
    }

    #[test]
    fn test_complex_dag_sort() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "1".into(),
            LeanEvent {
                event_id: "1".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "2".into(),
            LeanEvent {
                event_id: "2".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 50,
                origin_server_ts: 20,
                prev_events: vec!["1".into()],
                auth_events: vec!["1".into()],
                depth: 2,
                ..Default::default()
            },
        );
        events.insert(
            "3".into(),
            LeanEvent {
                event_id: "3".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 50,
                origin_server_ts: 15,
                prev_events: vec!["1".into()],
                auth_events: vec!["1".into()],
                depth: 2,
                ..Default::default()
            },
        );
        events.insert(
            "4".into(),
            LeanEvent {
                event_id: "4".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 10,
                origin_server_ts: 30,
                prev_events: vec!["2".into(), "3".into()],
                auth_events: vec!["2".into(), "3".into()],
                depth: 3,
                ..Default::default()
            },
        );
        let sorted_ids = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        // 1 pops first (only one with in-degree 0).
        // Then 2 and 3 are in queue. 3 has earlier TS (15, worse) so it pops FIRST.
        // Then 2 (TS 20, better — later wins) pops LAST.
        // Then 4 pops.
        assert_eq!(sorted_ids, vec!["1", "3", "2", "4"]);
    }

    #[test]
    fn test_kahn_missing_parents() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec!["MISSING".into()],
                auth_events: vec!["MISSING".into()],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(sorted, vec!["A"]);
    }

    #[test]
    fn test_resolve_iterative_sort_functionality() {
        let mut unconflicted = imbl::OrdMap::new();
        unconflicted.insert(
            (
                rezzy::basespec::event_types::EventType::from("type"),
                "key".into(),
            ),
            "id".into(),
        );
        let conflicted: HashMap<String, LeanEvent> = HashMap::new();
        let resolved = resolve_iterative_sort(
            unconflicted.clone(),
            conflicted.clone(),
            &conflicted,
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(resolved, unconflicted);
    }

    #[test]
    fn test_resolve_iterative_sort_v2_1_overlay() {
        use serde_json::json;

        // Uncontested state: Alice is already joined, Bob's old event is the prior state.
        let mut unconflicted = imbl::OrdMap::new();
        unconflicted.insert(
            (
                rezzy::basespec::event_types::EventType::from("m.room.member"),
                "@alice:example.com".into(),
            ),
            "id1".into(),
        );
        unconflicted.insert(
            (
                rezzy::basespec::event_types::EventType::from("m.room.member"),
                "@bob:example.com".into(),
            ),
            "id2".into(),
        );

        // Auth context: uncontested background events needed to validate the conflicted ones.
        let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();
        auth_context.insert(
            "create".into(),
            LeanEvent {
                event_id: "create".into(),
                event_type: "m.room.create".into(),
                state_key: Some(String::new()),
                sender: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 1,
                content: json!({}),
                ..Default::default()
            },
        );
        auth_context.insert(
            "join_rules".into(),
            LeanEvent {
                event_id: "join_rules".into(),
                event_type: "m.room.join_rules".into(),
                state_key: Some(String::new()),
                sender: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 2,
                content: json!({"join_rule": "public"}),
                auth_events: vec!["create".into()],
                ..Default::default()
            },
        );
        auth_context.insert(
            "id1".into(),
            LeanEvent {
                event_id: "id1".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                sender: "@alice:example.com".into(),
                power_level: 50,
                origin_server_ts: 500,
                content: json!({"membership": "join"}),
                auth_events: vec!["create".into()],
                ..Default::default()
            },
        );

        auth_context.insert(
            "pl_old".into(),
            LeanEvent {
                event_id: "pl_old".into(),
                event_type: "m.room.power_levels".into(),
                state_key: Some(String::new()),
                sender: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 3,
                content: json!({
                    "users": {
                        "@bob:example.com": 50
                    }
                }),
                ..Default::default()
            },
        );
        auth_context.insert(
            "pl_new".into(),
            LeanEvent {
                event_id: "pl_new".into(),
                event_type: "m.room.power_levels".into(),
                state_key: Some(String::new()),
                sender: "@alice:example.com".into(),
                power_level: 100,
                origin_server_ts: 4,
                content: json!({
                    "users": {
                        "@bob:example.com": 100
                    }
                }),
                ..Default::default()
            },
        );

        // The conflict: two competing versions of Bob's membership.
        let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
        conflicted.insert(
            "id2".into(),
            LeanEvent {
                event_id: "id2".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@bob:example.com".into()),
                sender: "@bob:example.com".into(),
                power_level: 50,
                origin_server_ts: 500,
                content: json!({"membership": "join"}),
                auth_events: vec![
                    "create".into(),
                    "join_rules".into(),
                    "id1".into(),
                    "pl_old".into(),
                ],
                ..Default::default()
            },
        );
        conflicted.insert(
            "id2_new".into(),
            LeanEvent {
                event_id: "id2_new".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@bob:example.com".into()),
                sender: "@bob:example.com".into(),
                power_level: 100,
                origin_server_ts: 1000,
                content: json!({"membership": "join"}),
                auth_events: vec![
                    "create".into(),
                    "join_rules".into(),
                    "id1".into(),
                    "pl_new".into(),
                ],
                ..Default::default()
            },
        );

        let resolved = resolve_iterative_sort(
            unconflicted.clone(),
            conflicted,
            &auth_context,
            rezzy::StateResVersion::V2_1,
            &mut std::collections::HashMap::new(),
        );

        assert_eq!(
            resolved.get(&(
                rezzy::basespec::event_types::EventType::from("m.room.member"),
                "@alice:example.com".into()
            )),
            Some(&"id1".into())
        );
        assert_eq!(
            resolved.get(&(
                rezzy::basespec::event_types::EventType::from("m.room.member"),
                "@bob:example.com".into()
            )),
            Some(&"id2_new".into()) // id2_new wins because voluntary joins are non-power events sorted chronologically.
        );
    }

    fn run_batch_test(
        version: rezzy::StateResVersion,
        rows: &[(&str, i64, u64, u64, &[&str])],
        expected: &[&str],
    ) {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        for r in rows {
            events.insert(
                r.0.to_string(),
                LeanEvent {
                    event_id: r.0.to_string(),
                    event_type: "m.room.member".into(),
                    state_key: Some("@alice:example.com".into()),
                    power_level: r.1,
                    origin_server_ts: r.2,
                    depth: r.3,
                    prev_events: r.4.iter().map(ToString::to_string).collect(),
                    auth_events: r.4.iter().map(ToString::to_string).collect(),
                    ..Default::default()
                },
            );
        }
        let result = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            version,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(
            result,
            expected.iter().map(ToString::to_string).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_resolution_batch() {
        run_batch_test(
            rezzy::StateResVersion::V2,
            &[("Alice", 100, 500, 1, &[]), ("Bob", 50, 100, 1, &[])],
            &["Alice", "Bob"], // Alice is better (PL 100), pops first.
        );
        run_batch_test(
            rezzy::StateResVersion::V1,
            &[("Deep", 100, 100, 10, &[]), ("Shallow", 10, 100, 1, &[])],
            &["Deep", "Shallow"],
        );
    }

    #[test]
    fn test_native_resolution_bootstrap_parity() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "1".into(),
            LeanEvent {
                event_id: "1".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@user:example.com".into()),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "2".into(),
            LeanEvent {
                event_id: "2".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@user:example.com".into()),
                power_level: 0,
                origin_server_ts: 20,
                prev_events: vec!["1".into()],
                auth_events: vec!["1".into()],
                depth: 2,
                ..Default::default()
            },
        );
        let sorted = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        let mut resolved_state = imbl::OrdMap::new();
        for id in sorted {
            let ev = &events[&id];
            let key = (ev.event_type.clone(), ev.state_key.clone().unwrap());
            resolved_state.insert(key, ev.event_id.clone());
        }
        assert_eq!(
            resolved_state.get(&("m.room.member".to_string(), "@user:example.com".to_string())),
            Some(&"2".to_string())
        );
    }

    #[test]
    fn test_enum_coverage() {
        let v = rezzy::StateResVersion::V2;
        let v2 = v;
        assert_eq!(v, v2);
        let debug_str = format!("{v:?}");
        assert!(debug_str.contains("V2"));
    }

    #[test]
    fn test_event_traits_coverage() {
        let e: LeanEvent = LeanEvent {
            event_id: "a".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let e2 = e.clone();
        assert_eq!(e, e2);
        let debug_str = format!("{e:?}");
        assert!(debug_str.contains("event_id"));
    }

    #[test]
    fn test_sort_priority_traits() {
        let e: LeanEvent = LeanEvent {
            event_id: "a".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let p = SortPriority {
            power_level: e.power_level,
            event: &e,
            version: rezzy::StateResVersion::V2,
        };
        let p2 = p;
        assert_eq!(p, p2);
        let debug_str = format!("{p:?}");
        assert!(debug_str.contains("version"));
    }

    #[test]
    fn test_v1_equal_depth_tie_break() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 0,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 0,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V1,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(sorted, vec!["B", "A"]);
    }

    #[test]
    fn test_kahn_no_neighbors() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "1".into(),
            LeanEvent {
                event_id: "1".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(sorted, vec!["1"]);
    }

    #[test]
    fn test_v2_1_full_coverage() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2_1,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(sorted, vec!["A"]);
    }

    /// Regression test: `V2_1` uses the same "later timestamp wins" tie-break as V2.
    /// Earlier events are sorted first (popped first from heap), later events
    /// come last and win via last-write-wins. This matches the Matrix spec.
    #[test]
    fn test_v2_1_later_timestamp_wins() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "$early".into(),
            LeanEvent {
                event_id: "$early".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@user:example.com".into()),
                power_level: 100,
                origin_server_ts: 1000,
                auth_events: vec![],
                ..Default::default()
            },
        );
        events.insert(
            "$late".into(),
            LeanEvent {
                event_id: "$late".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@user:example.com".into()),
                power_level: 100,
                origin_server_ts: 2000,
                auth_events: vec![],
                ..Default::default()
            },
        );
        // Earlier ts pops first (worse), later ts comes last (wins).
        let sorted = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2_1,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(sorted, vec!["$early", "$late"]);

        // V2 must match V2_1
        let sorted_v2 = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(sorted_v2, vec!["$early", "$late"]);
    }

    /// Regression test: millisecond-close Draupnir ban races resolve identically
    /// in V2 and `V2_1` when processed through Kahn sort alone.
    #[test]
    fn test_v2_1_millisecond_race_tiebreak() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "$ban_a".into(),
            LeanEvent {
                event_id: "$ban_a".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@spammer:evil.com".into()),
                power_level: 50,
                origin_server_ts: 1_772_724_243_891,
                auth_events: vec![],
                ..Default::default()
            },
        );
        events.insert(
            "$ban_b".into(),
            LeanEvent {
                event_id: "$ban_b".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@spammer:evil.com".into()),
                power_level: 50,
                origin_server_ts: 1_772_724_243_893, // 2ms later
                auth_events: vec![],
                ..Default::default()
            },
        );
        // $ban_a (earlier ts) pops first (loses), $ban_b (later ts) comes last = wins.
        let sorted_v2 = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(sorted_v2, vec!["$ban_a", "$ban_b"]);

        let sorted_v2_1 = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2_1,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(sorted_v2_1, vec!["$ban_a", "$ban_b"]);
    }

    #[test]
    fn test_total_order_properties() {
        let e1: LeanEvent = LeanEvent {
            event_id: "a".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let e2: LeanEvent = LeanEvent {
            event_id: "b".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let e3: LeanEvent = LeanEvent {
            event_id: "c".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            power_level: 50,
            origin_server_ts: 10,
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            ..Default::default()
        };
        assert_eq!(e1.cmp(&e1), Ordering::Equal);
        assert!(e1 <= e1);
        assert!(e1 <= e2 || e2 <= e1);
        if e1 <= e2 && e2 <= e3 {
            assert!(e1 <= e3);
        }
        let e1_copy = e1.clone();
        if e1 <= e1_copy && e1_copy <= e1 {
            assert_eq!(e1, e1_copy);
        }
    }

    #[test]
    fn test_coverage_booster_all_branches() {
        let e_base: LeanEvent = LeanEvent {
            event_id: "m".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            power_level: 50,
            origin_server_ts: 50,
            prev_events: vec![],
            auth_events: vec![],
            depth: 50,
            ..Default::default()
        };
        let p_base = SortPriority {
            power_level: e_base.power_level,
            event: &e_base,
            version: rezzy::StateResVersion::V2,
        };
        let e_high_power: LeanEvent = LeanEvent {
            power_level: 100,
            ..e_base.clone()
        };
        let p_high_power = SortPriority {
            power_level: e_high_power.power_level,
            event: &e_high_power,
            version: rezzy::StateResVersion::V2,
        };
        // p_base is WORSE (PL 50 < 100). Higher PL is Greater (pops first). So p_base < p_high_power.
        assert_eq!(p_base.cmp(&p_high_power), Ordering::Less);
        let e_best: LeanEvent = LeanEvent {
            origin_server_ts: 100,
            ..e_base.clone()
        };
        let p_best = SortPriority {
            power_level: e_best.power_level,
            event: &e_best,
            version: rezzy::StateResVersion::V2,
        };
        // p_best has TS 100 (better: later wins). Better must be Smaller (pops last).
        // So p_base > p_best.
        assert_eq!(p_base.cmp(&p_best), Ordering::Greater);
        let e_early_id: LeanEvent = LeanEvent {
            event_id: "a".into(),
            ..e_base.clone()
        };
        let p_early_id = SortPriority {
            power_level: e_early_id.power_level,
            event: &e_early_id,
            version: rezzy::StateResVersion::V2,
        };
        // p_base has ID "m" (better — larger id wins). Better must be Smaller (pops last). So p_base < p_early_id.
        assert_eq!(p_base.cmp(&p_early_id), Ordering::Less);
        let p_v1_base = SortPriority {
            power_level: e_base.power_level,
            event: &e_base,
            version: rezzy::StateResVersion::V1,
        };
        let e_shallow: LeanEvent = LeanEvent {
            depth: 1,
            ..e_base.clone()
        };
        let p_shallow = SortPriority {
            power_level: e_shallow.power_level,
            event: &e_shallow,
            version: rezzy::StateResVersion::V1,
        };
        // V1: shallow depth (1) is better. Better must be Smaller (pops last). So p_v1_base > p_shallow.
        assert_eq!(p_v1_base.cmp(&p_shallow), Ordering::Greater);
        let p_v1_early_id = SortPriority {
            power_level: e_early_id.power_level,
            event: &e_early_id,
            version: rezzy::StateResVersion::V1,
        };
        // V1: early ID "a" is better. Better must be Smaller (pops last). So p_v1_base > p_v1_early_id.
        assert_eq!(p_v1_base.cmp(&p_v1_early_id), Ordering::Greater);
        assert_eq!(p_v1_base.cmp(&p_v1_base), Ordering::Equal);
    }

    // ========================================================================
    // Phase 2: Battle-Hardening Tests
    // ========================================================================

    #[test]
    fn test_cycle_detection_detailed() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                auth_events: vec!["B".into()],
                ..Default::default()
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                auth_events: vec!["A".into()],
                ..Default::default()
            },
        );
        let result = rezzy::lean_kahn_sort_with_cycle_diagnostics(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        match result {
            KahnSortResult::CycleDetected { sorted, stuck } => {
                assert!(sorted.is_empty());
                assert_eq!(stuck.len(), 2);
                let mut stuck_sorted = stuck.clone();
                stuck_sorted.sort();
                assert_eq!(stuck_sorted, vec!["A", "B"]);
            }
            KahnSortResult::Ok(_) => panic!("Expected cycle detection"),
        }
    }

    #[test]
    fn test_cycle_detection_partial_sort() {
        // C -> A -> B -> A (cycle), but C is reachable
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "C".into(),
            LeanEvent {
                event_id: "C".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                auth_events: vec![],
                ..Default::default()
            },
        );
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                auth_events: vec!["B".into(), "C".into()],
                ..Default::default()
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                auth_events: vec!["A".into()],
                ..Default::default()
            },
        );
        let result = rezzy::lean_kahn_sort_with_cycle_diagnostics(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        match result {
            KahnSortResult::CycleDetected { sorted, stuck } => {
                assert_eq!(sorted, vec!["C"]);
                assert_eq!(stuck.len(), 2);
            }
            KahnSortResult::Ok(_) => panic!("Expected cycle detection"),
        }
    }

    #[test]
    fn test_kahn_sort_result_api() {
        let ok: KahnSortResult<String> = KahnSortResult::Ok(vec!["A".into()]);
        assert!(ok.is_ok());
        assert_eq!(ok.into_sorted(), vec!["A".to_string()]);

        let cycle: KahnSortResult<String> = KahnSortResult::CycleDetected {
            sorted: vec!["C".into()],
            stuck: vec!["A".into(), "B".into()],
        };
        assert!(!cycle.is_ok());
        assert!(cycle.into_sorted().is_empty());
    }

    #[test]
    fn test_lean_kahn_sort_empty_vec_on_cycles() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "C".into(),
            LeanEvent {
                event_id: "C".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                auth_events: vec![],
                ..Default::default()
            },
        );
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                auth_events: vec!["B".into(), "C".into()],
                ..Default::default()
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                auth_events: vec!["A".into()],
                ..Default::default()
            },
        );
        let sorted = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        assert!(
            !sorted.is_empty(),
            "rezzy::lean_kahn_sort must fall back and resolve stuck events on cycles instead of returning an empty Vec"
        );
        assert_eq!(sorted, vec!["C", "A", "B"]);
    }

    #[test]
    fn test_power_level_coercion_integer() {
        let json = r#"{"event_id": "$1", "type": "m.room.member", "origin_server_ts": 1, "power_level": 100}"#;
        let ev: LeanEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.power_level, 100);
    }

    #[test]
    fn test_power_level_coercion_string() {
        let json = r#"{"event_id": "$1", "type": "m.room.member", "origin_server_ts": 1, "power_level": "100"}"#;
        let ev: LeanEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.power_level, 100);
    }

    #[test]
    fn test_power_level_coercion_float() {
        let json = r#"{"event_id": "$1", "type": "m.room.member", "origin_server_ts": 1, "power_level": 100.0}"#;
        let res: Result<LeanEvent, _> = serde_json::from_str(json);
        assert!(res.is_err());
    }

    #[test]
    fn test_power_level_coercion_invalid_string() {
        let json = r#"{"event_id": "$1", "type": "m.room.member", "origin_server_ts": 1, "power_level": "abc"}"#;
        let ev: LeanEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.power_level, 0);
    }

    #[test]
    fn test_deep_chain_stack_safety() {
        // 1000-event deep chain: ev_0 <- ev_1 <- ev_2 <- ... <- ev_999
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        for i in 0..1000u32 {
            let id = format!("ev_{i}");
            let auth = if i > 0 {
                vec![format!("ev_{}", i - 1)]
            } else {
                vec![]
            };
            events.insert(
                id.clone(),
                LeanEvent {
                    event_id: id,
                    event_type: "m.room.member".into(),
                    state_key: Some("@alice:example.com".into()),
                    power_level: 100,
                    origin_server_ts: u64::from(i),
                    auth_events: auth,
                    depth: u64::from(i),
                    ..Default::default()
                },
            );
        }
        let sorted = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(sorted.len(), 1000);
        // First element must be ev_0 (in-degree 0)
        assert_eq!(sorted[0], "ev_0");
        // Last element must be ev_999 (deepest)
        assert_eq!(sorted[999], "ev_999");
    }

    #[test]
    fn test_subgraph_bounded_depth() {
        // Chain: A <- B <- C <- D (all in conflicted set for proper subgraph)
        let mut graph: HashMap<String, LeanEvent> = HashMap::new();
        for (id, auths) in [
            ("A", vec![]),
            ("B", vec!["A"]),
            ("C", vec!["B"]),
            ("D", vec!["C"]),
        ] {
            graph.insert(
                id.to_string(),
                LeanEvent {
                    event_id: id.into(),
                    event_type: "m.room.member".into(),
                    state_key: Some("@alice:example.com".into()),
                    auth_events: auths.iter().map(ToString::to_string).collect(),
                    ..Default::default()
                },
            );
        }
        // Unbounded with A and D as conflicted: full intersection includes all
        let full = compute_v2_1_conflicted_subgraph_bounded(
            &graph,
            &["A".to_string(), "D".to_string()],
            None,
        );
        assert!(full.subgraph.contains_key("A"));
        assert!(full.subgraph.contains_key("D"));

        // Bounded to depth 1: backwards from D only reaches C (depth 1),
        // so the backwards set is {A, D, C} (A + D from seeds, C from D's auth).
        // But A is not reachable forward from any of these at depth 1 only.
        let bounded = compute_v2_1_conflicted_subgraph_bounded(
            &graph,
            &["A".to_string(), "D".to_string()],
            Some(1),
        );
        // D at depth 0, C at depth 1 from D's backwards walk
        assert!(bounded.subgraph.contains_key("D"));
        assert!(bounded.subgraph.contains_key("A"));
        // B is NOT reachable within depth 1 from D (it's at depth 2)
        assert!(!bounded.subgraph.contains_key("B"));
    }

    #[test]
    fn test_subgraph_missing_auth_detection() {
        let mut graph: HashMap<String, LeanEvent> = HashMap::new();
        graph.insert(
            "X".to_string(),
            LeanEvent {
                event_id: "X".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                auth_events: vec!["MISSING_1".into(), "MISSING_2".into()],
                ..Default::default()
            },
        );
        let result = compute_v2_1_conflicted_subgraph_bounded(&graph, &["X".to_string()], None);
        let mut missing = result.missing_auth_events.clone();
        missing.sort();
        assert_eq!(missing, vec!["MISSING_1", "MISSING_2"]);
    }

    #[test]
    fn test_subgraph_missing_event_in_intersection() {
        let mut graph: HashMap<String, LeanEvent> = HashMap::new();
        graph.insert(
            "X".to_string(),
            LeanEvent {
                event_id: "X".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                auth_events: vec!["MISSING_1".into()],
                ..Default::default()
            },
        );
        // By including "MISSING_1" in the conflicted_set, it enters `forwards_reachable`.
        // Because "X" references it, it also enters `backwards_reachable`.
        // This ensures the intersection contains "MISSING_1", triggering the `continue`
        // when `auth_graph.get("MISSING_1")` returns None in the final loop.
        let result = compute_v2_1_conflicted_subgraph_bounded(
            &graph,
            &["X".to_string(), "MISSING_1".to_string()],
            None,
        );
        assert!(result
            .missing_auth_events
            .contains(&"MISSING_1".to_string()));
        assert!(!result.subgraph.contains_key("MISSING_1"));
    }

    #[test]
    fn test_subgraph_bounded_depth_off_by_one() {
        // Graph structure: E <- C <- D
        // E has no auth events.
        // C auths: E
        // D auths: C
        // conflicted_set: [D, E]
        // max_depth: 1
        let mut graph: HashMap<String, LeanEvent> = HashMap::new();
        graph.insert(
            "E".to_string(),
            LeanEvent {
                event_id: "E".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                auth_events: vec![],
                ..Default::default()
            },
        );
        graph.insert(
            "C".to_string(),
            LeanEvent {
                event_id: "C".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                auth_events: vec!["E".to_string()],
                ..Default::default()
            },
        );
        graph.insert(
            "D".to_string(),
            LeanEvent {
                event_id: "D".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                auth_events: vec!["C".to_string()],
                ..Default::default()
            },
        );

        let result = compute_v2_1_conflicted_subgraph_bounded(
            &graph,
            &["D".to_string(), "E".to_string()],
            Some(1),
        );

        // Under the new correct behavior, C (at depth 1) is included in the backwards set,
        // and therefore included in the subgraph intersection.
        assert!(result.subgraph.contains_key("D"));
        assert!(result.subgraph.contains_key("E"));
        assert!(result.subgraph.contains_key("C"));
    }

    #[test]
    fn test_subgraph_empty_input() {
        let mut graph: HashMap<String, LeanEvent> = HashMap::new();
        graph.insert(
            "A".to_string(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                ..Default::default()
            },
        );
        let result = compute_v2_1_conflicted_subgraph_bounded(&graph, &[], Some(1));
        assert!(result.subgraph.is_empty());
        assert!(result.missing_auth_events.is_empty());
    }

    fn default_test_event(id: &str, pl: i64, ts: u64, auth: Vec<&str>) -> LeanEvent {
        LeanEvent {
            rejected: false,
            soft_fail: false,
            event_id: id.into(),
            event_type: "m.room.message".into(), // not power
            state_key: None,
            power_level: pl,
            origin_server_ts: ts,
            prev_events: vec![],
            auth_events: auth.into_iter().map(ToString::to_string).collect(),
            depth: 1,
            sender: "@user:example.com".into(),
            content: serde_json::Value::Object(serde_json::Map::new()),
            room_id: None,
        }
    }

    #[test]
    fn test_mainline_sort_no_pl_ancestor_sorts_first() {
        // PL mainline: pl-3 -> pl-2 -> pl-1
        let mainline = vec![
            "$pl-3".to_string(),
            "$pl-2".to_string(),
            "$pl-1".to_string(),
        ];

        let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();
        // Mock auth context to build the paths
        auth_context.insert(
            "$msg-old".into(),
            default_test_event("$msg-old", 0, 20, vec!["$pl-1"]),
        );
        auth_context.insert(
            "$msg-new".into(),
            default_test_event("$msg-new", 0, 30, vec!["$pl-3"]),
        );
        auth_context.insert(
            "$msg-no-pl".into(),
            default_test_event("$msg-no-pl", 0, 10, vec![]),
        );

        // Add PL events themselves to auth context
        auth_context.insert(
            "$pl-3".into(),
            default_test_event("$pl-3", 100, 3, vec!["$pl-2"]),
        );
        auth_context.insert(
            "$pl-2".into(),
            default_test_event("$pl-2", 100, 2, vec!["$pl-1"]),
        );
        auth_context.insert("$pl-1".into(), default_test_event("$pl-1", 100, 1, vec![]));

        let ev_old = &auth_context["$msg-old"];
        let ev_new = &auth_context["$msg-new"];
        let ev_no_pl = &auth_context["$msg-no-pl"];

        let mut events_to_sort = vec![ev_old, ev_new, ev_no_pl];

        mainline_sort(&mut events_to_sort, &mainline, &auth_context);

        let sorted_ids: Vec<String> = events_to_sort.iter().map(|e| e.event_id.clone()).collect();
        // Per spec, an event with i = ∞ (no mainline ancestor) sorts before all
        // chain-rooted events under "x < y if x.position is greater than y's".
        assert_eq!(sorted_ids, vec!["$msg-no-pl", "$msg-old", "$msg-new"]);
    }

    #[test]
    fn test_reverse_topological_power_sort() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        // Graph structure from Ruma test:
        // l -> o
        // m -> n, o
        // n -> o
        // p -> o
        // We use V2 which uses PL, TS, and ID. To match Ruma exactly, we just use defaults.
        // Wait, the Ruma test passes `int!(0)` for all power levels and TS.
        events.insert("$l".into(), default_test_event("$l", 0, 0, vec!["$o"]));
        events.insert(
            "$m".into(),
            default_test_event("$m", 0, 0, vec!["$n", "$o"]),
        );
        events.insert("$n".into(), default_test_event("$n", 0, 0, vec!["$o"]));
        events.insert("$o".into(), default_test_event("$o", 0, 0, vec![]));
        events.insert("$p".into(), default_test_event("$p", 0, 0, vec!["$o"]));

        let sorted_ids = rezzy::lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        // All events have same PL=0 and ts=0, so tie-break is by event_id.
        // Smaller id pops first (loses). Sorted: $o (root), then $l < $n < $p in id order,
        // $m waits for $n. After $n pops, $m becomes eligible and beats $p ("m" > "p"? no:
        // "$m" < "$p" -> $m pops first). So order: [$o, $l, $n, $m, $p].
        assert_eq!(sorted_ids, vec!["$o", "$l", "$n", "$m", "$p"]);
    }

    #[test]
    fn test_cdo_causal_domination_filter() {
        use serde_json::json;

        let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
        let mut auth: HashMap<String, LeanEvent> = HashMap::new();

        let root: LeanEvent = LeanEvent {
            event_id: "$root".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            origin_server_ts: 1000,
            ..Default::default()
        };
        auth.insert(root.event_id.clone(), root.clone());

        let alice_join: LeanEvent = LeanEvent {
            event_id: "$alice_join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            sender: "@alice:example.com".into(),
            origin_server_ts: 1100,
            prev_events: vec!["$root".into()],
            auth_events: vec!["$root".into()],
            ..Default::default()
        };
        auth.insert(alice_join.event_id.clone(), alice_join.clone());

        let bob_join: LeanEvent = LeanEvent {
            event_id: "$bob_join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@bob:example.com".into(),
            origin_server_ts: 1200,
            prev_events: vec!["$alice_join".into()],
            auth_events: vec!["$root".into(), "$alice_join".into()],
            ..Default::default()
        };
        auth.insert(bob_join.event_id.clone(), bob_join.clone());

        // Concurrent events (conflicted)
        let alice_bans_bob: LeanEvent = LeanEvent {
            event_id: "$alice_bans_bob".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@alice:example.com".into(),
            origin_server_ts: 1300,
            prev_events: vec!["$bob_join".into()],
            auth_events: vec!["$root".into(), "$alice_join".into(), "$bob_join".into()],
            content: json!({ "membership": "ban" }),
            ..Default::default()
        };
        conflicted.insert(alice_bans_bob.event_id.clone(), alice_bans_bob.clone());

        let bob_name_change: LeanEvent = LeanEvent {
            event_id: "$bob_name_change".into(),
            event_type: "m.room.name".into(),
            state_key: Some(String::new()),
            sender: "@bob:example.com".into(),
            origin_server_ts: 1350,
            prev_events: vec!["$bob_join".into()],
            auth_events: vec!["$root".into(), "$alice_join".into(), "$bob_join".into()],
            content: json!({ "name": "Bob's Malicious Name" }),
            ..Default::default()
        };
        conflicted.insert(bob_name_change.event_id.clone(), bob_name_change.clone());

        // In rezzy::StateResVersion::V2_2, Bob's name change is causally dominated by Alice's ban and filtered out.
        let filtered = apply_cdo_filter(&conflicted, &auth);

        assert!(filtered.contains_key("$alice_bans_bob"));
        assert!(!filtered.contains_key("$bob_name_change"));
    }

    // Coverage: build_adjacency_structures multi-hop transitive closure
    // (cdo.rs:212, 215). A conflicted event whose auth chain extends >=2 hops
    // into auth_context forces the `while let Some(aid) = queue.pop_front()`
    // loop to iterate and push grandparents. The chain also gives $P3 in-degree
    // 0, exercising the Kahn source promotion (cdo.rs:244, 268).
    #[test]
    fn test_cdo_multihop_auth_chain_closure() {
        use serde_json::json;

        let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
        let mut auth: HashMap<String, LeanEvent> = HashMap::new();

        let make_pl = |id: &str, parents: Vec<String>| LeanEvent {
            event_id: id.into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            prev_events: parents.clone(),
            auth_events: parents,
            content: json!({ "users": { "@alice:example.com": 100 } }),
            ..Default::default()
        };

        let p3 = make_pl("$P3", vec![]);
        let p2 = make_pl("$P2", vec!["$P3".into()]);
        let p1 = make_pl("$P1", vec!["$P2".into()]);
        auth.insert(p3.event_id.clone(), p3);
        auth.insert(p2.event_id.clone(), p2);
        auth.insert(p1.event_id.clone(), p1);

        let join: LeanEvent = LeanEvent {
            event_id: "$join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@bob:example.com".into(),
            prev_events: vec!["$P1".into()],
            auth_events: vec!["$P1".into()],
            content: json!({ "membership": "join" }),
            ..Default::default()
        };
        conflicted.insert(join.event_id.clone(), join);

        // No admin action among the conflicted set, so nothing is dropped; the
        // deep chain is still pulled in via the multi-hop closure and the
        // topological sort completes without a leftover cycle fallback.
        let safe = apply_cdo_filter(&conflicted, &auth);
        assert_eq!(safe.len(), 1, "only the join survives: {:?}", safe.keys());
        assert!(safe.contains_key("$join"));
    }

    // Coverage: sort_cdo_events / build_adjacency_structures defensive cycle
    // fallback (cdo.rs:277-285). A genuine prev/auth cycle leaves some ids never
    // reaching in-degree 0; the leftover branch must append them in sorted
    // order rather than dropping them from the sweep.
    #[test]
    fn test_cdo_cycle_leftover_fallback() {
        use serde_json::json;

        let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
        let auth: HashMap<String, LeanEvent> = HashMap::new();

        let a: LeanEvent = LeanEvent {
            event_id: "$A".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@bob:example.com".into(),
            prev_events: vec!["$B".into()],
            auth_events: vec!["$B".into()],
            content: json!({ "membership": "join" }),
            ..Default::default()
        };
        let b: LeanEvent = LeanEvent {
            event_id: "$B".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@carol:example.com".into()),
            sender: "@carol:example.com".into(),
            prev_events: vec!["$A".into()],
            auth_events: vec!["$A".into()],
            content: json!({ "membership": "join" }),
            ..Default::default()
        };
        conflicted.insert(a.event_id.clone(), a);
        conflicted.insert(b.event_id.clone(), b);

        // Mutual cycle: neither $A nor $B ever reaches in-degree 0, so the
        // topological sort falls through to the deterministic leftover append.
        // No admin action, so both events survive the filter without a panic.
        let safe = apply_cdo_filter(&conflicted, &auth);
        assert_eq!(safe.len(), 2, "both events must survive: {:?}", safe.keys());
        assert!(safe.contains_key("$A"));
        assert!(safe.contains_key("$B"));
    }

    // Regression for the cycle-leftover domination fix: an event that only
    // exists because Kahn's algorithm hit a cycle (an `unordered_id`) must
    // not be dropped as a domination target, because its array position is
    // not a real topological order. Here an admin ban dominates a cyclic
    // event by structural match; without the `unordered_ids` guard the sweep
    // would drop the cyclic event based on an unreliable ordering.
    #[test]
    fn test_cdo_cycle_leftover_not_dominated() {
        use serde_json::json;

        let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
        let auth: HashMap<String, LeanEvent> = HashMap::new();

        let alice_ban_bob: LeanEvent = LeanEvent {
            event_id: "$alice_ban_bob".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@alice:example.com".into(),
            power_level: 100,
            origin_server_ts: 1000,
            content: json!({ "membership": "ban" }),
            ..Default::default()
        };
        // $A and $B form a mutual prev/auth cycle; $B is a ban of Dave by
        // Bob (structurally matched by alice_ban_bob). Both are unordered.
        let a: LeanEvent = LeanEvent {
            event_id: "$A".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@alice:example.com".into(),
            prev_events: vec!["$B".into()],
            auth_events: vec!["$B".into()],
            content: json!({ "membership": "ban" }),
            ..Default::default()
        };
        let b: LeanEvent = LeanEvent {
            event_id: "$B".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@dave:example.com".into()),
            sender: "@bob:example.com".into(),
            prev_events: vec!["$A".into()],
            auth_events: vec!["$A".into()],
            power_level: 50,
            content: json!({ "membership": "ban" }),
            ..Default::default()
        };
        conflicted.insert(a.event_id.clone(), a);
        conflicted.insert(b.event_id.clone(), b);
        conflicted.insert(alice_ban_bob.event_id.clone(), alice_ban_bob);

        let safe = apply_cdo_filter(&conflicted, &auth);

        // The cyclic events are unordered: their array position carries no
        // causal meaning, so they must neither dominate nor be dominated.
        // They survive the filter (only the genuinely-ordered admin ban
        // could ever be used for domination, and even it is not trusted to
        // drop an unordered event).
        assert!(safe.contains_key("$A"), "unordered $A must not be dropped");
        assert!(safe.contains_key("$B"), "unordered $B must not be dropped");
    }

    // Dominator-validity gap — resolved. The CDO used to drop a candidate based
    // on a structurally-a-ban/kick admin action WITHOUT checking that the
    // dominator itself would pass auth. Here `@mallory` has PL 0 (below the
    // room's ban level), so `$evil_ban` is auth-INVALID; `$victim_join` (an
    // auth-valid join into the public room) is the correct winner for @bob.
    // The unsound CDO pre-filter is retired from `prepare_conflicted_and_keys`,
    // so V2.1.1 now rejects `$evil_ban` on auth and keeps the join, matching
    // V2.1. This test guards that the live path stays sound: if someone
    // re-connects the pre-filter, it fails loudly.
    #[test]
    fn test_cdo_dominator_validity_closed_v2_1_1_keeps_winner() {
        use rezzy::basespec::event_types::EventType;
        use serde_json::json;

        let mut ts = 1000u64;
        let create: LeanEvent = LeanEvent {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@admin:x".into(),
            origin_server_ts: ts,
            content: json!({ "room_version": "12.1", "creator": "@admin:x" }),
            ..Default::default()
        };
        ts += 1;
        let admin_join: LeanEvent = LeanEvent {
            event_id: "$admin_join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@admin:x".into()),
            sender: "@admin:x".into(),
            origin_server_ts: ts,
            prev_events: vec!["$create".into()],
            auth_events: vec!["$create".into()],
            depth: 2,
            ..Default::default()
        };
        ts += 1;
        let pl: LeanEvent = LeanEvent {
            event_id: "$pl".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@admin:x".into(),
            origin_server_ts: ts,
            content: json!({
                "users": { "@admin:x": 100 },
                "users_default": 0,
                "state_default": 50,
                "ban": 50
            }),
            auth_events: vec!["$create".into(), "$admin_join".into()],
            prev_events: vec!["$admin_join".into()],
            depth: 3,
            ..Default::default()
        };
        ts += 1;
        let jr: LeanEvent = LeanEvent {
            event_id: "$jr".into(),
            event_type: "m.room.join_rules".into(),
            state_key: Some(String::new()),
            sender: "@admin:x".into(),
            origin_server_ts: ts,
            content: json!({ "join_rule": "public" }),
            auth_events: vec!["$create".into(), "$admin_join".into(), "$pl".into()],
            prev_events: vec!["$pl".into()],
            depth: 4,
            ..Default::default()
        };

        let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();
        for ev in [&create, &admin_join, &pl, &jr] {
            auth_context.insert(ev.event_id.clone(), ev.clone());
        }
        let mut unconflicted: imbl::OrdMap<(EventType, String), String> = imbl::OrdMap::new();
        for ev in [&create, &admin_join, &pl, &jr] {
            let sk = ev.state_key.clone().unwrap_or_default();
            unconflicted.insert(
                (EventType::from(ev.event_type.as_str()), sk),
                ev.event_id.clone(),
            );
        }

        let evil_ban: LeanEvent = LeanEvent {
            event_id: "$evil_ban".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:x".into()),
            sender: "@mallory:x".into(),
            origin_server_ts: 2000,
            power_level: 100,
            content: json!({ "membership": "ban" }),
            auth_events: vec!["$create".into(), "$admin_join".into(), "$pl".into()],
            prev_events: vec!["$jr".into()],
            depth: 5,
            ..Default::default()
        };
        let victim_join: LeanEvent = LeanEvent {
            event_id: "$victim_join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:x".into()),
            sender: "@bob:x".into(),
            origin_server_ts: 2100,
            power_level: 0,
            content: json!({ "membership": "join" }),
            auth_events: vec![
                "$create".into(),
                "$admin_join".into(),
                "$pl".into(),
                "$jr".into(),
            ],
            prev_events: vec!["$jr".into()],
            depth: 5,
            ..Default::default()
        };

        let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
        conflicted.insert(evil_ban.event_id.clone(), evil_ban);
        conflicted.insert(victim_join.event_id.clone(), victim_join);

        // NOTE: this test guards the *live* V2.1.1 path. The CDO pre-filter
        // (which used to drop `$victim_join` on the strength of the auth-invalid
        // `$evil_ban`) is retired from `prepare_conflicted_and_keys` for exactly
        // this reason — the dominator-validity gap. Resolution must now reject
        // `$evil_ban` on auth and keep the join, so V2.1.1 must match V2.1. If
        // someone re-connects the unsound pre-filter, this test fails loudly.
        let bob_key = (EventType::from("m.room.member"), "@bob:x".to_string());
        let r21 = resolve_iterative_sort(
            unconflicted.clone(),
            conflicted.clone(),
            &auth_context,
            rezzy::StateResVersion::V2_1,
            &mut std::collections::HashMap::new(),
        );
        let r211 = resolve_iterative_sort(
            unconflicted.clone(),
            conflicted.clone(),
            &auth_context,
            rezzy::StateResVersion::V2_1_1,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(r21.get(&bob_key), Some(&"$victim_join".to_string()));
        assert_eq!(
            r211, r21,
            "V2.1.1 must not diverge: an auth-invalid dominator must not erase a \
             resolved winner"
        );
    }

    // Coverage: process_direct_domination_chunks "already-dropped event" skip
    // (cdo.rs:401). Requires a second chunk, which needs more admin actions than
    // `chunk_size = WORDS_PER_CHUNK * 64 = 512`. Alice's high-priority ban drops
    // every one of Bob's 513 bans during chunk 1; chunk 2 then re-visits those
    // already-dropped events and must skip them via `continue`.
    #[test]
    fn test_cdo_multichunk_revisits_dropped_event() {
        use serde_json::json;

        let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
        let auth: HashMap<String, LeanEvent> = HashMap::new();

        let alice_ban_bob: LeanEvent = LeanEvent {
            event_id: "$alice_ban_bob".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@alice:example.com".into(),
            power_level: 100,
            origin_server_ts: 1000,
            content: json!({ "membership": "ban" }),
            ..Default::default()
        };
        conflicted.insert(alice_ban_bob.event_id.clone(), alice_ban_bob);

        for i in 0..513u64 {
            let ban: LeanEvent = LeanEvent {
                event_id: format!("$bob_ban_{i}"),
                event_type: "m.room.member".into(),
                state_key: Some(format!("@target_{i}:example.com")),
                sender: "@bob:example.com".into(),
                power_level: 0,
                origin_server_ts: 2000 + i,
                content: json!({ "membership": "ban" }),
                ..Default::default()
            };
            conflicted.insert(ban.event_id.clone(), ban);
        }

        let safe = apply_cdo_filter(&conflicted, &auth);
        assert_eq!(
            safe.len(),
            1,
            "only Alice's surviving ban remains: {:?}",
            safe.keys()
        );
        assert!(safe.contains_key("$alice_ban_bob"));
    }

    #[test]
    fn test_anomaly_06b_mod_membership_evaporation() {
        let auth_evs = utils::parse_jsonl_events(
            r#"
            {"event_id": "$root",            "type": "m.room.create",       "state_key": "", "sender": "@alice:example.com", "origin_server_ts": 1000}
            {"event_id": "$alice_join",      "type": "m.room.member",       "state_key": "@alice:example.com", "sender": "@alice:example.com", "origin_server_ts": 1100, "prev_events": ["$root"], "auth_events": ["$root"], "content": {}}
            {"event_id": "$jr_pub",          "type": "m.room.join_rules",   "state_key": "", "sender": "@alice:example.com", "origin_server_ts": 1150, "prev_events": ["$alice_join"], "auth_events": ["$root", "$alice_join"], "content": {"join_rule": "public"}}
            {"event_id": "$pl_init",         "type": "m.room.power_levels", "state_key": "", "sender": "@alice:example.com", "origin_server_ts": 1200, "prev_events": ["$jr_pub"], "auth_events": ["$root", "$alice_join", "$jr_pub"], "content": {"users": {"@alice:example.com": 100}}}
            "#,
        );
        let conflicted_evs = utils::parse_jsonl_events(
            r#"
            {"event_id": "$rules_invite",     "type": "m.room.join_rules",   "state_key": "", "sender": "@alice:example.com", "origin_server_ts": 1300, "prev_events": ["$pl_init"], "auth_events": ["$root", "$alice_join", "$pl_init"], "content": {"join_rule": "invite"}}
            {"event_id": "$nexy_join",        "type": "m.room.member",       "state_key": "@nexy:example.com", "sender": "@nexy:example.com", "origin_server_ts": 1310, "prev_events": ["$pl_init"], "auth_events": ["$root", "$alice_join", "$jr_pub", "$pl_init"], "content": {"membership": "join"}}
            {"event_id": "$nexy_promo",       "type": "m.room.power_levels", "state_key": "", "sender": "@alice:example.com", "origin_server_ts": 1320, "prev_events": ["$nexy_join"], "auth_events": ["$root", "$alice_join", "$nexy_join", "$pl_init"], "content": {"users": {"@alice:example.com": 100, "@nexy:example.com": 50}}}
            {"event_id": "$nexy_bans_spammer", "type": "m.room.member",      "state_key": "@spammer:example.com", "sender": "@nexy:example.com", "origin_server_ts": 1330, "prev_events": ["$nexy_promo"], "auth_events": ["$root", "$alice_join", "$nexy_join", "$nexy_promo"], "content": {"membership": "ban"}}
            "#,
        );

        let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
        let mut auth: HashMap<String, LeanEvent> = HashMap::new();
        for ev in auth_evs {
            auth.insert(ev.event_id.clone(), ev);
        }
        for ev in conflicted_evs {
            conflicted.insert(ev.event_id.clone(), ev);
        }

        // Under v2.1.1, apply_cdo_filter is executed. $rules_invite (invite
        // lockdown) is concurrent with $nexy_join, but must NOT dominate it:
        // $nexy_join's own auth_events cite $jr_pub, a non-lockdown
        // (public) join_rules event, which is the state it was actually
        // authorized against. A lockdown on an unrelated causal branch does
        // not retroactively invalidate that authorization -- dropping
        // $nexy_join here (and cascading through $nexy_promo and
        // $nexy_bans_spammer) was the exact unsoundness
        // test_anomaly_17_sliced_dag_membership_desync and
        // test_anomaly_06b_mod_membership_evaporation caught at the
        // integration level; this is its unit-level counterpart.
        let filtered = apply_cdo_filter(&conflicted, &auth);

        assert!(filtered.contains_key("$rules_invite"));
        assert!(
            filtered.contains_key("$nexy_join"),
            "Nexy's join cites a non-lockdown join_rules event in its own auth_events, \
             so an unrelated-branch lockdown must not dominate it"
        );
        assert!(
            filtered.contains_key("$nexy_promo"),
            "Nexy's promotion must survive since $nexy_join was not dropped"
        );
        assert!(
            filtered.contains_key("$nexy_bans_spammer"),
            "Nexy's ban on spammer must survive since $nexy_promo was not dropped"
        );
    }

    #[test]
    fn test_coverage_booster_auth_cases() {
        use rezzy::auth::{check_auth, check_auth_chain, AuthError, RoomState};
        use serde_json::json;

        // 1. Format every single variant of AuthError to ensure 100% Display coverage
        let errs = vec![
            AuthError::NotMember {
                sender: "alice".into(),
                event_id: "1".into(),
            },
            AuthError::InsufficientPowerLevel {
                required: 100,
                actual: 50,
                event_type: "m.room.name".into(),
            },
            AuthError::BannedUser {
                sender: "bob".into(),
                event_id: "2".into(),
            },
            AuthError::InvalidStateKey {
                expected: "x".into(),
                actual: "y".into(),
            },
            AuthError::<String>::CreateWithPrevEvents,
            AuthError::MissingAuthEvent("3".into()),
            AuthError::InvalidSyntax("invalid JSON".into()),
        ];
        for err in errs {
            let formatted = format!("{err}");
            assert!(!formatted.is_empty());
        }

        // 2. StateKeyDyn comparisons, EQ, and Ord coverage
        let sk1 = (
            String::from("m.room.member"),
            Some(String::from("@alice:example.com")),
        );
        let sk2 = (
            String::from("m.room.member"),
            Some(String::from("@bob:example.com")),
        );
        assert_ne!(sk1, sk2);
        #[allow(clippy::double_comparisons)]
        {
            assert!(sk1 < sk2 || sk1 > sk2);
        }

        // 3. Test room_creators and additional_creators array parses in get_sender_power_level
        let mut state = RoomState::new();
        let create_ev: LeanEvent = LeanEvent {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            sender: "@alice:example.com".into(),
            content: json!({
                "creator": "@alice:example.com",
                "room_creators": ["@charlie:example.com"],
                "additional_creators": ["@dave:example.com"]
            }),
            ..Default::default()
        };
        state.insert(
            ("m.room.create".to_string(), String::new()),
            create_ev.clone(),
        );

        // Test check_auth for m.room.create with prev_events (should fail with CreateWithPrevEvents)
        let bad_create: LeanEvent = LeanEvent {
            event_id: "$bad_create".into(),
            event_type: "m.room.create".into(),
            prev_events: vec!["$create".into()],
            ..Default::default()
        };
        assert_eq!(
            check_auth(
                &bad_create,
                &state,
                rezzy::basespec::rezzy_types::StateResVersion::V2_1,
                None
            ),
            Err(AuthError::<String>::CreateWithPrevEvents)
        );

        // Test non-member rejection with RoomState containing no membership
        let name_change: LeanEvent = LeanEvent {
            event_id: "$name".into(),
            event_type: "m.room.name".into(),
            sender: "@bob:example.com".into(),
            ..Default::default()
        };
        assert_eq!(
            check_auth(
                &name_change,
                &state,
                rezzy::basespec::rezzy_types::StateResVersion::V2_1,
                None
            ),
            Err(AuthError::NotMember {
                sender: "@bob:example.com".into(),
                event_id: "$name".into()
            })
        );

        // Creator should be allowed implied join if no member event is present
        let creator_name_change: LeanEvent = LeanEvent {
            event_id: "$name2".into(),
            event_type: "m.room.name".into(),
            sender: "@alice:example.com".into(),
            ..Default::default()
        };
        assert!(check_auth(
            &creator_name_change,
            &state,
            rezzy::basespec::rezzy_types::StateResVersion::V2_1,
            None
        )
        .is_ok());

        // Banned user membership transition
        let mut state2 = RoomState::new();
        state2.insert(
            ("m.room.create".to_string(), String::new()),
            create_ev.clone(),
        );
        let banned_member: LeanEvent = LeanEvent {
            event_id: "$ban_member".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@bob:example.com".into(),
            content: json!({ "membership": "ban" }),
            ..Default::default()
        };
        state2.insert(
            ("m.room.member".to_string(), "@bob:example.com".into()),
            banned_member.clone(),
        );

        // A banned user cannot join or send events
        let join_ev: LeanEvent = LeanEvent {
            event_id: "$join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@bob:example.com".into(),
            content: json!({ "membership": "join" }),
            ..Default::default()
        };
        assert_eq!(
            check_auth(
                &join_ev,
                &state2,
                rezzy::basespec::rezzy_types::StateResVersion::V2_1,
                None
            ),
            Err(AuthError::BannedUser {
                sender: "@bob:example.com".into(),
                event_id: "$join".into()
            })
        );

        // Invalid state key self-invite
        let self_invite: LeanEvent = LeanEvent {
            event_id: "$invite".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            sender: "@alice:example.com".into(),
            content: json!({ "membership": "invite" }),
            ..Default::default()
        };
        assert!(check_auth(
            &self_invite,
            &state2,
            rezzy::basespec::rezzy_types::StateResVersion::V2_1,
            None
        )
        .is_err());

        // Invalid transition target user != sender for join
        let bad_join: LeanEvent = LeanEvent {
            event_id: "$bad_join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@alice:example.com".into(),
            content: json!({ "membership": "join" }),
            ..Default::default()
        };
        assert_eq!(
            check_auth(
                &bad_join,
                &state2,
                rezzy::basespec::rezzy_types::StateResVersion::V2_1,
                None
            ),
            Err(AuthError::InvalidStateKey {
                expected: "@alice:example.com".into(),
                actual: "@bob:example.com".into()
            })
        );

        // Missing PL event defaults testing
        let low_power_state_change: LeanEvent = LeanEvent {
            event_id: "$low_pl".into(),
            event_type: "m.room.name".into(),
            state_key: Some(String::new()),
            sender: "@bob:example.com".into(),
            ..Default::default()
        };
        // Should require PL 50 by default for state events if no PL event is present
        let mut state3 = RoomState::new();
        state3.insert(
            ("m.room.create".to_string(), String::new()),
            create_ev.clone(),
        );
        let bob_joined: LeanEvent = LeanEvent {
            event_id: "$bob_joined".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@bob:example.com".into(),
            content: json!({ "membership": "join" }),
            ..Default::default()
        };
        state3.insert(
            ("m.room.member".to_string(), "@bob:example.com".into()),
            bob_joined.clone(),
        );
        assert_eq!(
            check_auth(
                &low_power_state_change,
                &state3,
                rezzy::basespec::rezzy_types::StateResVersion::V2_1,
                None
            ),
            Err(AuthError::InsufficientPowerLevel {
                required: 50,
                actual: 0,
                event_type: "m.room.name".into()
            })
        );

        // Invite a banned user check
        let invite_banned: LeanEvent = LeanEvent {
            event_id: "$invite_banned".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@alice:example.com".into(),
            content: json!({ "membership": "invite" }),
            ..Default::default()
        };
        assert_eq!(
            check_auth(
                &invite_banned,
                &state2,
                rezzy::basespec::rezzy_types::StateResVersion::V2_1,
                None
            ),
            Err(AuthError::BannedUser {
                sender: "@bob:example.com".into(),
                event_id: "$invite_banned".into()
            })
        );

        // 4. Test check_auth_chain with m.room.create lacking state_key fallback
        let create_no_key: LeanEvent = LeanEvent {
            event_id: "$create_no_key".into(),
            event_type: "m.room.create".into(),
            sender: "@alice:example.com".into(),
            state_key: None, // lacks state_key
            ..Default::default()
        };
        let (accepted_ids, rejected_ids) = check_auth_chain(
            &[create_no_key],
            &RoomState::new(),
            rezzy::basespec::rezzy_types::StateResVersion::V2_1,
        );
        assert_eq!(accepted_ids, vec!["$create_no_key"]);
        assert!(rejected_ids.is_empty());
    }

    #[test]
    fn test_resolve_iterative_sort_cycle_power_events() {
        use std::collections::HashMap;

        let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
        let mut auth: HashMap<String, LeanEvent> = HashMap::new();

        let create: LeanEvent = LeanEvent {
            event_id: "CREATE".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            ..Default::default()
        };
        auth.insert("CREATE".into(), create);

        // Initial PL event from room creation — gives Alice explicit PL 100.
        // Pre-V12 auth rules have no implicit creator PL; the server puts
        // the creator in the PL event's `users` map at room creation.
        let initial_pl = LeanEvent {
            event_id: "INITIAL_PL".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            content: serde_json::from_value(serde_json::json!({
                "users": { "@alice:example.com": 100 }
            }))
            .unwrap(),
            auth_events: vec!["CREATE".into()],
            ..Default::default()
        };
        auth.insert("INITIAL_PL".into(), initial_pl);

        // Create cyclic power events: A auths B, B authed by A, etc.
        let a: LeanEvent = LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            auth_events: vec!["B".into(), "CREATE".into()],
            content: serde_json::from_value(serde_json::json!({
                "users": { "@alice:example.com": 100 }
            }))
            .unwrap(),
            ..Default::default()
        };
        let b: LeanEvent = LeanEvent {
            event_id: "B".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            auth_events: vec!["A".into(), "CREATE".into()],
            content: serde_json::from_value(serde_json::json!({
                "users": { "@alice:example.com": 100 }
            }))
            .unwrap(),
            ..Default::default()
        };
        conflicted.insert("A".into(), a);
        conflicted.insert("B".into(), b);

        // The unconflicted state includes the initial PL so sorting can
        // determine Alice's power level without relying on the cyclic
        // conflicted events.
        let mut unconflicted = imbl::OrdMap::new();
        unconflicted.insert(
            (
                rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
                String::new(),
            ),
            "INITIAL_PL".into(),
        );
        // This will run kahn sort on power_events, detect a cycle, and print/handle it safely.
        let resolved = resolve_iterative_sort(
            unconflicted,
            conflicted,
            &auth,
            rezzy::StateResVersion::V2,
            &mut std::collections::HashMap::new(),
        );
        assert!(!resolved.is_empty());
        // INITIAL_PL wins, not the cyclic A/B pair. A and B mutually auth each
        // other (a malformed/adversarial DAG shape) for the *same* key that
        // INITIAL_PL already holds unconflicted — real callers never produce
        // this shape for a genuinely agreed-upon key, so A/B can only be here
        // as auth-diff context for some other real conflict. A cyclic pair
        // reaching this state must not be able to hijack an already-settled
        // key over the legitimate unconflicted value.
        assert_eq!(
            &resolved[&(
                rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
                String::new()
            )],
            "INITIAL_PL"
        );
    }

    #[test]
    fn test_cdo_unbounded_stride_overflow() {
        use serde_json::json;

        let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
        let mut auth: HashMap<String, LeanEvent> = HashMap::new();

        let root: LeanEvent = LeanEvent {
            event_id: "$root".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            ..Default::default()
        };
        auth.insert(root.event_id.clone(), root.clone());

        // We create 65 admin actions (e.g. bans/demotions/lockdowns)
        for i in 0..65 {
            let admin_id = format!("$admin_{i}");
            let admin_ev: LeanEvent = LeanEvent {
                event_id: admin_id.clone(),
                event_type: "m.room.member".into(),
                state_key: Some(format!("@spammer_{i}:example.com")),
                sender: "@alice:example.com".into(),
                content: json!({ "membership": "ban" }),
                ..Default::default()
            };
            conflicted.insert(admin_id, admin_ev);
        }

        // Apply the filter. Since we have 65 admin actions, it will allocate 2 u64 words
        // per event, fully verifying the 1D stride matrix bounds and multi-word bitwise operations!
        let filtered = apply_cdo_filter(&conflicted, &auth);
        assert_eq!(filtered.len(), 65);
    }

    #[test]
    fn test_compute_state_at_with_missing_and_foreign_prev_events() {
        let mut events: HashMap<String, LeanEvent> = HashMap::new();

        // C is a valid create event
        let c: LeanEvent = LeanEvent {
            event_id: "C".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            ..Default::default()
        };
        // A has prev_events: B (missing) and C (existing)
        let a: LeanEvent = LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            prev_events: vec!["B".into(), "C".into()],
            ..Default::default()
        };

        events.insert("C".into(), c);
        events.insert("A".into(), a);

        // compute_state_at A must run cleanly and return A's state without panicking on missing event B!
        let state = compute_state_at("A", &events, StateResVersion::V2);
        assert!(state.is_some());
        let state_map = state.unwrap();

        // State should contain C (create) and A itself
        assert!(state_map.contains_key(&(
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new()
        )));
        assert_eq!(
            &state_map[&(
                rezzy::basespec::event_types::EventType::from("m.room.member"),
                "@alice:example.com".into()
            )],
            "A"
        );
    }

    #[test]
    fn test_msc4297_problem_b_regression() {
        let mut conflicted_events: HashMap<String, LeanEvent> = HashMap::new();
        let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();

        // Create room
        let create_ev: LeanEvent = LeanEvent {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            ..Default::default()
        };
        auth_context.insert("$create".into(), create_ev.clone());

        // Alice joins
        let join_alice: LeanEvent = LeanEvent {
            event_id: "$join_alice".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            sender: "@alice:example.com".into(),
            content: serde_json::json!({ "membership": "join" }),
            auth_events: vec!["$create".into()],
            ..Default::default()
        };
        auth_context.insert("$join_alice".into(), join_alice.clone());

        // Alice sets Bob to PL 50 (Unconflicted Ancestral PL Event)
        let pl_alice: LeanEvent = LeanEvent {
            event_id: "$pl_alice".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            content: serde_json::json!({
                "users": { "@bob:example.com": 50 }
            }),
            auth_events: vec!["$create".into(), "$join_alice".into()],
            ..Default::default()
        };
        auth_context.insert("$pl_alice".into(), pl_alice.clone());

        // Bob joins
        let join_bob: LeanEvent = LeanEvent {
            event_id: "$join_bob".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@bob:example.com".into(),
            content: serde_json::json!({ "membership": "join" }),
            auth_events: vec!["$create".into(), "$pl_alice".into()],
            ..Default::default()
        };
        auth_context.insert("$join_bob".into(), join_bob.clone());

        // Conflicted Power Level events sent by Bob
        let pl_bob_1: LeanEvent = LeanEvent {
            event_id: "$pl_bob_1".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@bob:example.com".into(),
            content: serde_json::json!({
                "users": { "@bob:example.com": 50, "@charlie:example.com": 50 }
            }),
            auth_events: vec!["$pl_alice".into(), "$join_bob".into()],
            ..Default::default()
        };

        let pl_bob_2: LeanEvent = LeanEvent {
            event_id: "$pl_bob_2".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@bob:example.com".into(),
            content: serde_json::json!({
                "users": { "@bob:example.com": 50, "@charlie:example.com": 100 }
            }),
            auth_events: vec!["$pl_alice".into(), "$join_bob".into()],
            ..Default::default()
        };

        conflicted_events.insert("$pl_bob_1".into(), pl_bob_1);
        conflicted_events.insert("$pl_bob_2".into(), pl_bob_2);

        // Resolve using V2_1 (MSC4297). This starts with an empty state.
        // It must successfully route and validate `$pl_alice` in order to authorize Bob's PL events.
        let resolved = resolve_iterative_sort(
            utils::build_unconflicted_state_test_helper(&auth_context),
            conflicted_events,
            &auth_context,
            rezzy::StateResVersion::V2_1,
            &mut std::collections::HashMap::new(),
        );

        // Assert that a power levels event is resolved, showing the ancestral PL event was correctly processed
        assert!(resolved.contains_key(&(
            rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
            String::new()
        )));
    }

    #[test]
    fn test_self_leave_vs_kick_classification() {
        // Self-leave (sender == state_key): not a kick/ban
        let self_leave: LeanEvent = LeanEvent {
            event_id: "1".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            sender: "@alice:example.com".into(),
            content: serde_json::json!({ "membership": "leave" }),
            ..Default::default()
        };
        assert!(!self_leave.is_ban_or_kick());

        // Kick (sender != state_key): is a kick/ban
        let kick: LeanEvent = LeanEvent {
            event_id: "2".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@alice:example.com".into(),
            content: serde_json::json!({ "membership": "leave" }),
            ..Default::default()
        };
        assert!(kick.is_ban_or_kick());

        // Ban (sender != state_key): is a kick/ban
        let ban: LeanEvent = LeanEvent {
            event_id: "3".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@alice:example.com".into(),
            content: serde_json::json!({ "membership": "ban" }),
            ..Default::default()
        };
        assert!(ban.is_ban_or_kick());
    }

    #[test]
    fn test_overflowing_power_level_coercion_values_clamping() {
        use rezzy::basespec::rezzy_types::coerce_json_to_i64;

        // Value beyond standard i64 should return None securely so it defaults/clamps to 0 (minimum power/most secure fallback)
        let large_positive = serde_json::Value::String("99999999999999999999999999999".to_string());
        let clamped_pos = coerce_json_to_i64(&large_positive);
        assert_eq!(clamped_pos, None);

        let large_negative =
            serde_json::Value::String("-99999999999999999999999999999".to_string());
        let clamped_neg = coerce_json_to_i64(&large_negative);
        assert_eq!(clamped_neg, None);
    }
}
use rezzy::{compute_state_at, KahnSortResult, LeanEvent, StateResVersion};

#[test]
fn test_types_kahn_sort_result_methods() {
    let ok = KahnSortResult::Ok(vec!["a".to_string()]);
    assert!(ok.is_ok());
    assert_eq!(ok.clone().into_sorted(), vec!["a".to_string()]);

    let cycle = KahnSortResult::CycleDetected {
        sorted: vec!["a".to_string()],
        stuck: vec!["b".to_string()],
    };
    assert!(!cycle.is_ok());
    assert_eq!(cycle.into_sorted(), Vec::<String>::new());
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_types_validate_syntactic() {
    let mut ev: LeanEvent = LeanEvent {
        event_id: "$valid_event_id:example.com".to_string(),
        event_type: "m.room.message".to_string(),
        sender: "@alice:example.com".to_string(),
        ..Default::default()
    };
    assert!(ev.validate_syntactic("11").is_ok());

    // Custom/unknown event types are allowed
    // (spec doesn't whitelist types for auth)
    ev.event_type = "org.custom.whatever".to_string();
    assert!(ev.validate_syntactic("11").is_ok());

    ev.event_type = "m.room.message".to_string();
    ev.prev_events = vec!["$a".to_string(); 21];
    assert!(ev.validate_syntactic("11").is_err());

    ev.prev_events = vec![];
    ev.auth_events = vec!["$a".to_string(); 11];
    assert!(ev.validate_syntactic("11").is_err());

    // Test event_id format validation (must start with '$' if non-empty)
    ev.auth_events = vec![];
    ev.event_id = "invalid_no_dollar".to_string();
    assert_eq!(
        ev.validate_syntactic("11"),
        Err("event_id must start with '$'")
    );
    ev.event_id = String::new();
    assert_eq!(
        ev.validate_syntactic("11"),
        Err("event_id must start with '$'")
    );
    ev.event_id = "$valid_event_id:example.com".to_string();
    assert!(ev.validate_syntactic("11").is_ok());

    // Test sender format validation (must start with '@' and contain ':')
    ev.sender = "user_without_at:example.com".to_string();
    assert!(ev.validate_syntactic("11").is_err());
    ev.sender = "@user_without_colon".to_string();
    assert!(ev.validate_syntactic("11").is_err());
    ev.sender = String::new();
    assert!(
        ev.validate_syntactic("11").is_err(),
        "empty sender must be rejected, not silently skipped"
    );
    ev.sender = "@alice:".to_string();
    assert!(
        ev.validate_syntactic("11").is_err(),
        "sender with an empty domain must be rejected"
    );
    ev.sender = "@alice:example.com".to_string();
    assert!(ev.validate_syntactic("11").is_ok());

    // Test sender localpart charset (only a-z, 0-9, '.', '_', '=', '-', '/', '+')
    ev.sender = "@Alice:example.com".to_string();
    assert!(
        ev.validate_syntactic("11").is_err(),
        "uppercase is not a valid localpart character"
    );
    ev.sender = "@:example.com".to_string();
    assert!(
        ev.validate_syntactic("11").is_err(),
        "empty localpart is invalid"
    );
    ev.sender = "@alice.1_2=3-4/5+6:example.com".to_string();
    assert!(
        ev.validate_syntactic("11").is_ok(),
        "all allowed localpart characters"
    );
    ev.sender = "@alice:example.com".to_string();

    // Test depth bounds check (<= 2^53 - 1, the canonical-JSON safe integer bound)
    ev.depth = (1u64 << 53) - 1;
    assert!(
        ev.validate_syntactic("11").is_ok(),
        "2^53 - 1 is the inclusive upper bound and must be accepted"
    );
    ev.depth = 1u64 << 53;
    assert_eq!(
        ev.validate_syntactic("11"),
        Err("depth exceeds maximum allowed value")
    );
    ev.depth = 100;
    assert!(ev.validate_syntactic("11").is_ok());

    // Test 255-byte length limit on event_id, hard-enforced only for v11+
    // (Synapse's `strict_event_byte_limits_room_versions`, false for v1-v10).
    ev.event_id = format!("${}", "a".repeat(255));
    assert_eq!(
        ev.validate_syntactic("11"),
        Err("event_id exceeds maximum allowed length of 255 bytes")
    );
    let pre_v11 = ev
        .validate_syntactic("10")
        .expect("pre-v11 rooms only warn on oversized event_id, never hard-fail");
    assert_eq!(
        pre_v11.warnings,
        vec![rezzy::warnings::Warning::OversizedFieldPreV11 {
            event_id: ev.event_id.clone(),
            field: "event_id",
            len: ev.event_id.len(),
            limit: 255,
        }],
        "the oversized-field condition is now surfaced structurally, not just tolerated"
    );
    assert_eq!(pre_v11.warnings[0].code(), "W002_OVERSIZED_FIELD_PRE_V11");
    assert_eq!(
        ev.validate_syntactic("12"),
        Err("event_id exceeds maximum allowed length of 255 bytes")
    );
    assert_eq!(
        ev.validate_syntactic("12.1"),
        Err("event_id exceeds maximum allowed length of 255 bytes")
    );
    assert_eq!(
        ev.validate_syntactic("not-a-version"),
        Err("unsupported room_version")
    );
    ev.event_id = "$valid_event_id:example.com".to_string();
    assert!(ev.validate_syntactic("11").is_ok());

    // Test 255-byte length limit on state_key (same v11+ gating as the other fields)
    ev.state_key = Some("a".repeat(256));
    assert_eq!(
        ev.validate_syntactic("11"),
        Err("state_key exceeds maximum allowed length of 255 bytes")
    );
    assert!(
        ev.validate_syntactic("10").is_ok(),
        "pre-v11 rooms only warn on oversized state_key, never hard-fail"
    );
    ev.state_key = Some("@alice:example.com".to_string());
    assert!(ev.validate_syntactic("11").is_ok());
}

#[test]
fn test_types_validate_syntactic_create_rules() {
    let mut ev: LeanEvent = LeanEvent {
        event_id: "$valid_event_id:example.com".to_string(),
        event_type: "m.room.create".to_string(),
        sender: "@alice:example.com".to_string(),
        ..Default::default()
    };

    // Rule 1.3: m.room.create must not declare an unrecognised content.room_version.
    ev.content = serde_json::json!({ "room_version": "999", "creator": "@alice:example.com" });
    assert_eq!(
        ev.validate_syntactic("11"),
        Err("m.room.create content.room_version is not a recognised room version")
    );
    ev.content = serde_json::json!({ "room_version": "11", "creator": "@alice:example.com" });
    assert!(ev.validate_syntactic("11").is_ok());
    ev.content = serde_json::json!({ "creator": "@alice:example.com" });
    assert!(
        ev.validate_syntactic("11").is_ok(),
        "absent room_version defaults to \"1\" per spec, not rejected"
    );

    // Rule 1.4 (pre-v12): m.room.create must have a `creator` property.
    ev.content = serde_json::json!({});
    assert_eq!(
        ev.validate_syntactic("11"),
        Err("m.room.create content must have a 'creator' property")
    );
    ev.content = serde_json::json!({ "creator": "not-a-mxid" });
    assert_eq!(
        ev.validate_syntactic("11"),
        Err("m.room.create content.creator must be a valid MXID string")
    );
    ev.content = serde_json::json!({ "creator": "@alice:example.com" });
    assert!(ev.validate_syntactic("11").is_ok());

    // Rule 1.4 (v12+): `creator` is no longer required, but any
    // `additional_creators` entries must pass the same MXID grammar as `sender`.
    ev.content = serde_json::json!({});
    assert!(
        ev.validate_syntactic("12").is_ok(),
        "v12+ derives creators from sender/additional_creators, not the creator field"
    );
    ev.content = serde_json::json!({ "additional_creators": ["@bob:example.com", "not-a-mxid"] });
    assert_eq!(
        ev.validate_syntactic("12"),
        Err("m.room.create content.additional_creators must be an array of valid MXID strings")
    );
    ev.content = serde_json::json!({ "additional_creators": ["@bob:example.com"] });
    assert!(ev.validate_syntactic("12").is_ok());
}

#[test]
fn test_soft_fail_vs_rejected_events_behavior() {
    use rezzy::EventLike;

    let normal_ev: LeanEvent = LeanEvent {
        event_id: "$normal".to_string(),
        event_type: "m.room.message".to_string(),
        sender: "@alice:example.com".to_string(),
        rejected: false,
        soft_fail: false,
        ..Default::default()
    };
    let mut soft_fail_ev = normal_ev.clone();
    soft_fail_ev.event_id = "$soft_failed".to_string();
    soft_fail_ev.soft_fail = true;

    let mut rejected_ev = normal_ev.clone();
    rejected_ev.event_id = "$rejected".to_string();
    rejected_ev.rejected = true;

    // Both soft-failed and rejected events are recognized as invalid for state resolution
    assert!(!normal_ev.rejected && !normal_ev.soft_fail);
    assert!(soft_fail_ev.soft_fail && !soft_fail_ev.rejected);
    assert!(rejected_ev.rejected && !rejected_ev.soft_fail);

    // Verify soft_fail trait getter
    assert!(!normal_ev.soft_fail());
    assert!(soft_fail_ev.soft_fail());
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_redaction_preserved_keys_matrix() {
    use rezzy::basespec::rezzy_types::{redaction_preserved_keys, RedactionRule};

    // Room version 1 (v1 baseline)
    assert_eq!(
        redaction_preserved_keys("m.room.create", "1"),
        RedactionRule::Keys(&["creator"])
    );
    assert_eq!(
        redaction_preserved_keys("m.room.member", "1"),
        RedactionRule::Keys(&["membership"])
    );
    assert_eq!(
        redaction_preserved_keys("m.room.join_rules", "1"),
        RedactionRule::Keys(&["join_rule"])
    );

    // Room versions 2-8: distinct `"N" => N` arms in the version-mapping match.
    // All are pre-v9 / pre-v11, so create keeps `creator` and member keeps only
    // `membership` -- identical rules to v1, but each version string must be
    // routed through its own arm (exercises the per-version mapping lines).
    for v in ["2", "3", "4", "5", "6", "7", "8"] {
        assert_eq!(
            redaction_preserved_keys("m.room.create", v),
            RedactionRule::Keys(&["creator"]),
            "create redaction for room {v}"
        );
        assert_eq!(
            redaction_preserved_keys("m.room.member", v),
            RedactionRule::Keys(&["membership"]),
            "member redaction for room {v}"
        );
    }
    // v10 is its own arm too; it has v9's join_authorised rules but not v11's.
    assert_eq!(
        redaction_preserved_keys("m.room.member", "10"),
        RedactionRule::Keys(&["membership", "join_authorised_via_users_server"])
    );

    // Room version 9 (adds join_authorised_via_users_server & allow)
    assert_eq!(
        redaction_preserved_keys("m.room.member", "9"),
        RedactionRule::Keys(&["membership", "join_authorised_via_users_server"])
    );
    assert_eq!(
        redaction_preserved_keys("m.room.join_rules", "9"),
        RedactionRule::Keys(&["join_rule", "allow"])
    );

    // Room version 11: m.room.create preserves ALL content, distinct from "no keys"
    assert_eq!(
        redaction_preserved_keys("m.room.create", "11"),
        RedactionRule::All
    );
    assert_eq!(
        redaction_preserved_keys("m.room.member", "11"),
        RedactionRule::Keys(&[
            "membership",
            "join_authorised_via_users_server",
            "third_party_invite.signed"
        ])
    );
    assert!(matches!(
        redaction_preserved_keys("m.room.power_levels", "11"),
        RedactionRule::Keys(keys) if keys.contains(&"invite")
    ));

    // Room version 12 inherits v11's redaction rules verbatim (v12.txt includes
    // the v11-redactions spec fragment rather than defining its own).
    assert_eq!(
        redaction_preserved_keys("m.room.create", "12"),
        RedactionRule::All
    );
    assert_eq!(
        redaction_preserved_keys("m.room.member", "12"),
        redaction_preserved_keys("m.room.member", "11")
    );
    assert_eq!(
        redaction_preserved_keys("m.room.power_levels", "12"),
        redaction_preserved_keys("m.room.power_levels", "11")
    );

    // Pre-v11 power_levels omits invite (only added in v11)
    assert_eq!(
        redaction_preserved_keys("m.room.power_levels", "1"),
        RedactionRule::Keys(&[
            "ban",
            "events",
            "events_default",
            "kick",
            "redact",
            "state_default",
            "users",
            "users_default",
        ])
    );

    // history_visibility and redaction are version-independent / version-gated
    assert_eq!(
        redaction_preserved_keys("m.room.history_visibility", "1"),
        RedactionRule::Keys(&["history_visibility"])
    );
    // `redacts` only moved into `content` in v11+; earlier versions preserve nothing.
    assert_eq!(
        redaction_preserved_keys("m.room.redaction", "1"),
        RedactionRule::None
    );
    assert_eq!(
        redaction_preserved_keys("m.room.redaction", "11"),
        RedactionRule::Keys(&["redacts"])
    );

    // m.room.aliases preserves `aliases` in v1-5, removed from v6 onward.
    assert_eq!(
        redaction_preserved_keys("m.room.aliases", "1"),
        RedactionRule::Keys(&["aliases"])
    );
    assert_eq!(
        redaction_preserved_keys("m.room.aliases", "5"),
        RedactionRule::Keys(&["aliases"])
    );
    assert_eq!(
        redaction_preserved_keys("m.room.aliases", "6"),
        RedactionRule::None
    );

    // Unknown event type falls through to the default arm
    assert_eq!(
        redaction_preserved_keys("m.room.unknown", "1"),
        RedactionRule::None
    );

    // Unsupported/malformed room versions must fail closed (preserve nothing),
    // never silently fall back to permissive v1 rules.
    assert_eq!(
        redaction_preserved_keys("m.room.power_levels", "not-a-version"),
        RedactionRule::None
    );
    assert_eq!(
        redaction_preserved_keys("m.room.power_levels", "999"),
        RedactionRule::None
    );
}

#[test]
fn test_redaction_application_strips_content() {
    use rezzy::apply_redaction;

    // A message redacts down to empty content.
    let msg: LeanEvent = LeanEvent {
        event_id: "$msg:example.com".into(),
        event_type: "m.room.message".into(),
        sender: "@bob:example.com".into(),
        origin_server_ts: 1000,
        content: serde_json::json!({ "body": "spam", "msgtype": "m.text" }),
        ..Default::default()
    };
    let redaction: LeanEvent = LeanEvent {
        event_id: "$redact:example.com".into(),
        event_type: "m.room.redaction".into(),
        sender: "@alice:example.com".into(),
        origin_server_ts: 1100,
        content: serde_json::json!({ "redacts": "$msg:example.com" }),
        ..Default::default()
    };
    let redacted = apply_redaction(&msg, &redaction, "12").expect("valid redaction should apply");
    assert_eq!(
        redacted.content,
        serde_json::json!({}),
        "m.room.message content is fully stripped"
    );
    // Envelope preserved.
    assert_eq!(redacted.event_id, "$msg:example.com");
    assert_eq!(redacted.sender, "@bob:example.com");
    assert_eq!(redacted.event_type, "m.room.message");

    // m.room.member preserves only `membership` (v12).
    let member: LeanEvent = LeanEvent {
        event_id: "$join:example.com".into(),
        event_type: "m.room.member".into(),
        state_key: Some("@bob:example.com".into()),
        sender: "@bob:example.com".into(),
        content: serde_json::json!({ "membership": "join", "displayname": "Bob" }),
        ..Default::default()
    };
    let redact_member: LeanEvent = LeanEvent {
        event_id: "$rm:example.com".into(),
        event_type: "m.room.redaction".into(),
        sender: "@alice:example.com".into(),
        content: serde_json::json!({ "redacts": "$join:example.com" }),
        ..Default::default()
    };
    let redacted_member =
        apply_redaction(&member, &redact_member, "12").expect("valid redaction should apply");
    assert_eq!(
        redacted_member.content,
        serde_json::json!({ "membership": "join" }),
        "only the membership key survives"
    );

    // m.room.power_levels preserves `users` (v12) — the anti-PL-wipeout invariant.
    let pl: LeanEvent = LeanEvent {
        event_id: "$pl:example.com".into(),
        event_type: "m.room.power_levels".into(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".into(),
        content: serde_json::json!({
            "users": { "@alice:example.com": 100 },
            "users_default": 0,
            "state_default": 50,
            "something_unrelated": true
        }),
        ..Default::default()
    };
    let redact_pl: LeanEvent = LeanEvent {
        event_id: "$rp:example.com".into(),
        event_type: "m.room.redaction".into(),
        sender: "@alice:example.com".into(),
        content: serde_json::json!({ "redacts": "$pl:example.com" }),
        ..Default::default()
    };
    let redacted_pl = apply_redaction(&pl, &redact_pl, "12").expect("valid redaction should apply");
    assert_eq!(
        redacted_pl.content,
        serde_json::json!({
            "users": { "@alice:example.com": 100 },
            "users_default": 0,
            "state_default": 50
        }),
        "power_levels redaction must preserve the users map and defaults"
    );

    // v11+ m.room.create preserves ALL content per the rule matrix
    // (redaction_preserved_keys; see also test_redaction_application_guards,
    // which shows a create is redactable and its content is preserved).
    // Exercise the rule directly via `redacted()`.
    let create: LeanEvent = LeanEvent {
        event_id: "$create:example.com".into(),
        event_type: "m.room.create".into(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".into(),
        content: serde_json::json!({ "room_version": "12", "creator": "@alice:example.com", "m.federate": true }),
        ..Default::default()
    };
    let redacted_create = create.redacted("12");
    assert_eq!(
        redacted_create.content,
        serde_json::json!({ "room_version": "12", "creator": "@alice:example.com", "m.federate": true }),
        "v11+ create preserves all content on redaction"
    );
}

#[test]
fn test_redaction_application_guards() {
    use rezzy::apply_redaction;

    let msg: LeanEvent = LeanEvent {
        event_id: "$msg:example.com".into(),
        event_type: "m.room.message".into(),
        sender: "@bob:example.com".into(),
        content: serde_json::json!({ "body": "spam" }),
        ..Default::default()
    };
    // Redaction targeting a DIFFERENT event -> None.
    let wrong: LeanEvent = LeanEvent {
        event_id: "$r:example.com".into(),
        event_type: "m.room.redaction".into(),
        sender: "@alice:example.com".into(),
        content: serde_json::json!({ "redacts": "$other:example.com" }),
        ..Default::default()
    };
    assert!(apply_redaction(&msg, &wrong, "12").is_none());

    // Redacting m.room.create is NOT forbidden. In v11+ all of its content is
    // preserved; before v11 only `creator` survives.
    let create: LeanEvent = LeanEvent {
        event_id: "$create:example.com".into(),
        event_type: "m.room.create".into(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".into(),
        content: serde_json::json!({ "room_version": "12", "creator": "@alice:example.com" }),
        ..Default::default()
    };
    let redact_create: LeanEvent = LeanEvent {
        event_id: "$rc:example.com".into(),
        event_type: "m.room.redaction".into(),
        sender: "@alice:example.com".into(),
        content: serde_json::json!({ "redacts": "$create:example.com" }),
        ..Default::default()
    };
    let redacted_v12 = apply_redaction(&create, &redact_create, "12").unwrap();
    assert_eq!(
        redacted_v12.content,
        serde_json::json!({ "room_version": "12", "creator": "@alice:example.com" })
    );
    // Pre-v11 create redaction preserves only `creator`.
    let redacted_v10 = apply_redaction(&create, &redact_create, "10").unwrap();
    assert_eq!(
        redacted_v10.content,
        serde_json::json!({ "creator": "@alice:example.com" })
    );
}

#[test]
fn test_content_hash_verification_on_raw_pdu() {
    use rezzy::{compute_content_hash, verify_content_hash};

    // A raw PDU carrying unsigned/signatures; hashes.sha256 covers the
    // UNREDACTED event with unsigned/signatures/hashes removed.
    let mut pdu = serde_json::json!({
        "event_id": "$1:example.com",
        "type": "m.room.message",
        "sender": "@bob:example.com",
        "origin_server_ts": 1,
        "depth": 2,
        "content": { "body": "hello" },
        "unsigned": { "age": 5 },
        "signatures": { "example.com": { "ed25519:1": "sig" } }
    });

    // A bogus hash fails.
    pdu["hashes"] = serde_json::json!({ "sha256": "abc123" });
    assert!(verify_content_hash(&pdu, "11").is_err());

    // A real content hash passes.
    let hash = compute_content_hash(&pdu, "11").unwrap();
    pdu["hashes"] = serde_json::json!({ "sha256": hash });
    assert!(verify_content_hash(&pdu, "11").is_ok());

    // Tampering with content breaks the commitment.
    pdu["content"] = serde_json::json!({ "body": "evil" });
    assert!(verify_content_hash(&pdu, "11").is_err());

    // Missing hashes dict -> nothing to verify -> Err.
    pdu.as_object_mut().unwrap().remove("hashes");
    assert!(verify_content_hash(&pdu, "11").is_err());
}

#[test]
fn test_ingest_events_applies_redaction_and_verifies_hashes() {
    use rezzy::{compute_content_hash, ingest_events};

    let msg = serde_json::json!({
        "event_id": "$msg:example.com",
        "type": "m.room.message",
        "sender": "@bob:example.com",
        "origin_server_ts": 10,
        "depth": 1,
        "content": { "body": "spam" }
    });
    let redaction = serde_json::json!({
        "event_id": "$r:example.com",
        "type": "m.room.redaction",
        "sender": "@alice:example.com",
        "origin_server_ts": 11,
        "depth": 2,
        "redacts": "$msg:example.com",
        "content": { "redacts": "$msg:example.com" }
    });

    // Ingest without hashes dicts -> parses both and applies the redaction to
    // the in-batch target (m.room.message content is stripped to {}).
    let events = ingest_events(&[msg.clone(), redaction.clone()], "11").unwrap();
    let redacted = events
        .iter()
        .find(|e| e.event_id == "$msg:example.com")
        .unwrap();
    assert_eq!(redacted.content, serde_json::json!({}));
    // The redaction event itself is retained.
    assert!(events.iter().any(|e| e.event_id == "$r:example.com"));

    // A valid content hash on the message -> verification passes at ingest.
    let mut hashed = msg.clone();
    let hash = compute_content_hash(&hashed, "11").unwrap();
    hashed["hashes"] = serde_json::json!({ "sha256": hash });
    let events = ingest_events(&[hashed.clone(), redaction.clone()], "11").unwrap();
    assert!(events.iter().any(|e| e.event_id == "$msg:example.com"));

    // A tampered content hash -> ingest rejects the batch.
    let mut tampered = hashed.clone();
    tampered["content"] = serde_json::json!({ "body": "evil" });
    assert!(ingest_events(&[tampered, redaction.clone()], "11").is_err());
}

/// Coverage: `ingest_events`'s redaction-application `split_at_mut` branch
/// where the target's position is *after* the redaction's (the redaction
/// appears first in the batch) -- the test above only ever puts the target
/// first, exercising the opposite branch.
#[test]
fn test_coverage_ingest_events_applies_redaction_when_redaction_precedes_target() {
    use rezzy::ingest_events;

    let redaction = serde_json::json!({
        "event_id": "$r:example.com",
        "type": "m.room.redaction",
        "sender": "@alice:example.com",
        "origin_server_ts": 10,
        "depth": 1,
        "redacts": "$msg:example.com",
        "content": { "redacts": "$msg:example.com" }
    });
    let msg = serde_json::json!({
        "event_id": "$msg:example.com",
        "type": "m.room.message",
        "sender": "@bob:example.com",
        "origin_server_ts": 11,
        "depth": 2,
        "content": { "body": "spam" }
    });

    // Redaction is at index 0, its target at index 1 -- target_pos > redaction_pos.
    let events = ingest_events(&[redaction, msg], "11").unwrap();
    let redacted = events
        .iter()
        .find(|e| e.event_id == "$msg:example.com")
        .unwrap();
    assert_eq!(redacted.content, serde_json::json!({}));
    assert!(events.iter().any(|e| e.event_id == "$r:example.com"));
}

/// Coverage: `ingest_events`'s per-PDU parse-error branch (the `?` on
/// `LeanEvent::from_value`). A malformed PDU that cannot be parsed into a lean
/// event aborts the whole batch with an `Err` instead of being silently
/// skipped.
#[test]
fn test_coverage_ingest_events_parse_error_aborts_batch() {
    use rezzy::ingest_events;

    // No "type" field -> `from_value` sees an empty event_type and returns
    // Err, surfacing through ingest_events' `map_err(|e| e.to_string())?`.
    let malformed = serde_json::json!({
        "event_id": "$bad:example.com",
        "sender": "@bob:example.com",
        "origin_server_ts": 10,
        "depth": 1,
        "content": {}
    });
    let err = ingest_events(&[malformed], "11").unwrap_err();
    assert!(
        err.contains("event_type"),
        "unexpected ingest parse error: {err}"
    );
}

#[test]
fn test_reference_hash_is_redaction_invariant() {
    use rezzy::{redact_json, reference_hash};

    // For room v4+, the event ID is the reference hash of the REDACTED event.
    // So redaction must not change the reference hash: event_id(e) ==
    // event_id(redact(e)). This is what lets a redaction be applied to an event
    // already in the DAG without breaking references to it.
    let pdu = serde_json::json!({
        "event_id": "$1:example.com",
        "type": "m.room.message",
        "sender": "@bob:example.com",
        "origin_server_ts": 1000,
        "depth": 2,
        "content": { "body": "spam" },
        "unsigned": { "age": 5 },
        "signatures": { "example.com": { "ed25519:1": "sig" } }
    });

    let h1 = reference_hash(&pdu, "11").unwrap();
    let h2 = reference_hash(&redact_json(&pdu, "11"), "11").unwrap();
    assert_eq!(h1, h2);

    // m.room.message preserves no content keys, so redaction empties it.
    let redacted = redact_json(&pdu, "11");
    assert_eq!(redacted["content"], serde_json::json!({}));
    assert_eq!(redacted["event_id"], "$1:example.com");
}

#[test]
fn test_types_deserialize_power_level_variants() {
    let json_int =
        r#"{"event_id":"$1","type":"m.room.message","origin_server_ts":1,"power_level":100}"#;
    let ev1: LeanEvent = serde_json::from_str(json_int).unwrap();
    assert_eq!(ev1.power_level, 100);

    let json_str =
        r#"{"event_id":"$1","type":"m.room.message","origin_server_ts":1,"power_level":"200"}"#;
    let ev2: LeanEvent = serde_json::from_str(json_str).unwrap();
    assert_eq!(ev2.power_level, 200);

    let json_str_invalid =
        r#"{"event_id":"$1","type":"m.room.message","origin_server_ts":1,"power_level":"invalid"}"#;
    let ev3: LeanEvent = serde_json::from_str(json_str_invalid).unwrap();
    assert_eq!(ev3.power_level, 0);

    let json_large = format!(
        r#"{{"event_id":"$1","type":"m.room.message","origin_server_ts":1,"power_level":{}}}"#,
        u64::MAX
    );
    let ev4: LeanEvent = serde_json::from_str(&json_large).unwrap();
    assert_eq!(ev4.power_level, rezzy::auth::MAX_POWER_LEVEL_JSON);
}

#[test]
fn test_types_deserialize_depth_and_redaction_validation() {
    let json_negative_depth =
        r#"{"event_id":"$1","type":"m.room.message","origin_server_ts":1,"depth":-1}"#;
    assert!(serde_json::from_str::<LeanEvent>(json_negative_depth).is_err());

    let json_fractional_depth =
        r#"{"event_id":"$1","type":"m.room.message","origin_server_ts":1,"depth":1.5}"#;
    assert!(serde_json::from_str::<LeanEvent>(json_fractional_depth).is_err());

    let json_redaction_mismatch = r#"{
        "event_id": "$redact",
        "type": "m.room.redaction",
        "sender": "@alice:example.com",
        "content": {"redacts": "$different:example.com"},
        "redacts": "$target:example.com"
    }"#;
    assert!(serde_json::from_str::<LeanEvent>(json_redaction_mismatch).is_err());

    let json_redaction_non_string_top_level_redacts = r#"{
        "event_id": "$redact",
        "type": "m.room.redaction",
        "sender": "@alice:example.com",
        "content": {},
        "redacts": 42
    }"#;
    assert!(
        serde_json::from_str::<LeanEvent>(json_redaction_non_string_top_level_redacts).is_err()
    );

    let json_redaction_non_string_content_redacts = r#"{
        "event_id": "$redact",
        "type": "m.room.redaction",
        "sender": "@alice:example.com",
        "content": {"redacts": 42},
        "redacts": "$target:example.com"
    }"#;
    assert!(serde_json::from_str::<LeanEvent>(json_redaction_non_string_content_redacts).is_err());

    let json_redaction_null_content = r#"{
        "event_id": "$redact",
        "type": "m.room.redaction",
        "sender": "@alice:example.com",
        "content": null,
        "redacts": "$target:example.com"
    }"#;
    let ev: LeanEvent = serde_json::from_str(json_redaction_null_content).unwrap();
    assert_eq!(ev.get_redacts(), Some("$target:example.com"));

    let json_redaction_no_redacts = r#"{
        "event_id": "$redact",
        "type": "m.room.redaction",
        "sender": "@alice:example.com",
        "content": {"reason": "cleanup"}
    }"#;
    let ev: LeanEvent = serde_json::from_str(json_redaction_no_redacts).unwrap();
    assert_eq!(ev.get_redacts(), None);

    let json_redaction_non_object_content = r#"{
        "event_id": "$redact",
        "type": "m.room.redaction",
        "sender": "@alice:example.com",
        "content": "invalid",
        "redacts": "$target:example.com"
    }"#;
    assert!(serde_json::from_str::<LeanEvent>(json_redaction_non_object_content).is_err());
}

#[test]
fn test_compute_state_at_missing_target() {
    let events_map: HashMap<String, LeanEvent> = HashMap::new();
    assert!(compute_state_at("missing", &events_map, StateResVersion::V2).is_none());
}

#[test]
fn test_compute_state_at_merge_divergence() {
    let mut events_map: HashMap<String, LeanEvent> = HashMap::new();

    events_map.insert(
        "A".into(),
        LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.message".into(),
            prev_events: vec![],
            ..Default::default()
        },
    );

    events_map.insert(
        "B".into(),
        LeanEvent {
            event_id: "B".into(),
            event_type: "m.room.name".into(),
            state_key: Some(String::new()),
            prev_events: vec!["A".into()],
            ..Default::default()
        },
    );

    events_map.insert(
        "C".into(),
        LeanEvent {
            event_id: "C".into(),
            event_type: "m.room.name".into(),
            state_key: Some(String::new()),
            prev_events: vec!["A".into()],
            ..Default::default()
        },
    );

    events_map.insert(
        "D".into(),
        LeanEvent {
            event_id: "D".into(),
            event_type: "m.room.message".into(),
            prev_events: vec!["B".into(), "C".into()],
            ..Default::default()
        },
    );

    let state = compute_state_at("D", &events_map, StateResVersion::V2).unwrap();
    assert!(state.is_empty());
}

#[test]
fn test_compute_state_at_merge_identical() {
    let mut events_map: HashMap<String, LeanEvent> = HashMap::new();

    events_map.insert(
        "A".into(),
        LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.message".into(),
            prev_events: vec![],
            ..Default::default()
        },
    );

    events_map.insert(
        "B".into(),
        LeanEvent {
            event_id: "B".into(),
            event_type: "m.room.message".into(),
            prev_events: vec!["A".into()],
            ..Default::default()
        },
    );

    events_map.insert(
        "C".into(),
        LeanEvent {
            event_id: "C".into(),
            event_type: "m.room.message".into(),
            prev_events: vec!["A".into()],
            ..Default::default()
        },
    );

    events_map.insert(
        "D".into(),
        LeanEvent {
            event_id: "D".into(),
            event_type: "m.room.message".into(),
            prev_events: vec!["B".into(), "C".into()],
            ..Default::default()
        },
    );

    let state = compute_state_at("D", &events_map, StateResVersion::V2).unwrap();
    assert!(state.is_empty());
}

#[test]
fn test_cdo_disconnected_child_missing_from_conflicted() {
    // apply_cdo_filter must not panic when a conflicted event cites an event
    // ("B") that exists only in the auth context, not in the conflicted set.
    // Such an event is never a direct-domination drop candidate and is kept.
    use rezzy::cdo;

    let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
    events_map.insert(
        "A".into(),
        LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.message".into(),
            ..Default::default()
        },
    );

    let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();
    // B is not in conflicted events, but it's an ancestor of A through auth context
    auth_context.insert(
        "B".into(),
        LeanEvent {
            event_id: "B".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            ..Default::default()
        },
    );

    // Set A to depend on B
    events_map.get_mut("A").unwrap().auth_events = vec!["B".into()];

    let filtered = cdo::apply_cdo_filter(&events_map, &auth_context);
    assert!(filtered.contains_key("A"));
}

#[test]
fn test_cdo_coverage_branches() {
    let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
    let auth_context: HashMap<String, LeanEvent> = HashMap::new();

    let admin_id = "admin1".to_string();
    let admin_ev: LeanEvent = LeanEvent {
        event_id: admin_id.clone(),
        event_type: "m.room.power_levels".into(),
        state_key: Some(String::new()),
        sender: "alice".into(),
        depth: 10,
        ..Default::default()
    };
    events_map.insert(admin_id.clone(), admin_ev.clone());

    let event_id = "event1".to_string();
    let ev1: LeanEvent = LeanEvent {
        event_id: event_id.clone(),
        event_type: "m.room.member".into(),
        state_key: Some("bob".into()),
        sender: "bob".into(),
        auth_events: vec![admin_id.clone()],
        depth: 5,
        ..Default::default()
    };
    events_map.insert(event_id.clone(), ev1);

    let _filtered = rezzy::resolve::cdo::apply_cdo_filter(&events_map, &auth_context);
}

#[test]
fn test_cdo_is_ancestor() {
    let mut ctx: HashMap<String, LeanEvent> = HashMap::new();

    // Equal IDs -> true
    assert!(rezzy::resolve::cdo::is_ancestor("A", "A", &ctx));

    // Missing child -> false
    ctx.insert(
        "B".into(),
        LeanEvent {
            depth: 10,
            ..Default::default()
        },
    );
    assert!(!rezzy::resolve::cdo::is_ancestor("missing", "B", &ctx));

    // Missing ancestor -> false
    ctx.insert(
        "C".into(),
        LeanEvent {
            depth: 5,
            ..Default::default()
        },
    );
    assert!(!rezzy::resolve::cdo::is_ancestor("C", "missing", &ctx));

    // Depth pruning - child depth > ancestor depth -> false
    let mut ev_child = LeanEvent {
        depth: 10,
        ..Default::default()
    };
    ev_child.auth_events.push("and".into());
    ctx.insert("child_pruned".into(), ev_child);

    ctx.insert(
        "and_shallow".into(),
        LeanEvent {
            depth: 5,
            ..Default::default()
        },
    );
    assert!(!rezzy::resolve::cdo::is_ancestor(
        "child_pruned",
        "and_shallow",
        &ctx
    ));

    // Valid path found
    let mut ev_valid_child = LeanEvent {
        depth: 5,
        ..Default::default()
    };
    ev_valid_child.prev_events.push("mid".into());
    ctx.insert("valid_child".into(), ev_valid_child);

    let mut ev_mid = LeanEvent {
        depth: 3,
        ..Default::default()
    };
    ev_mid.auth_events.push("valid_and".into());
    ctx.insert("mid".into(), ev_mid);

    ctx.insert(
        "valid_and".into(),
        LeanEvent {
            depth: 1,
            ..Default::default()
        },
    );

    assert!(rezzy::resolve::cdo::is_ancestor(
        "valid_child",
        "valid_and",
        &ctx
    ));
}

/// Regression coverage for the removed depth-based pruning in
/// `is_ancestor`: `$and` is a literal `auth_events` parent of `$child` (a
/// real graph edge), but `$and.depth` (5) is numerically >= `$child.depth`
/// (3) — an author-forgeable relationship that has nothing to do with the
/// actual graph. `is_ancestor` must resolve this from `prev_events`/
/// `auth_events` alone and correctly report `$and` as an ancestor; the old
/// depth-comparison short-circuit made this come back `false` regardless of
/// the real edge, which is the exact soundness gap this test now guards
/// against reintroducing.
#[test]
fn test_cdo_is_ancestor_ignores_forged_depth_relationship() {
    let events = utils::parse_jsonl_events(
        r#"
{"event_id":"$child","type":"m.room.member","state_key":"@a:x","sender":"@a:x","depth":3,"origin_server_ts":100,"content":{"membership":"join"},"prev_events":["$and"],"auth_events":["$and"]}
{"event_id":"$and","type":"m.room.member","state_key":"@b:x","sender":"@b:x","depth":5,"origin_server_ts":50,"content":{"membership":"join"},"prev_events":[],"auth_events":[]}
"#,
    );
    let ctx: HashMap<String, LeanEvent> = events
        .iter()
        .map(|e| (e.event_id.clone(), e.clone()))
        .collect();

    // $and is a genuine auth_events parent of $child, so it IS an ancestor
    // regardless of the (forged-looking) depth relationship.
    assert!(
        rezzy::resolve::cdo::is_ancestor("$child", "$and", &ctx),
        "a real auth_events edge must be honored even when the depth field disagrees with it"
    );
}

/// Coverage: `is_ancestor` correctly reports `false` for two events on
/// genuinely disconnected branches, with no real path between them via
/// `prev_events`/`auth_events` — regardless of their `depth` values.
#[test]
fn test_cdo_is_ancestor_disconnected_branch() {
    let events = utils::parse_jsonl_events(
        r#"
{"event_id":"$child","type":"m.room.member","state_key":"@a:x","sender":"@a:x","depth":10,"origin_server_ts":100,"content":{"membership":"join"},"prev_events":["$mid"],"auth_events":[]}
{"event_id":"$mid","type":"m.room.member","state_key":"@b:x","sender":"@b:x","depth":3,"origin_server_ts":50,"content":{"membership":"join"},"prev_events":["$deep"],"auth_events":[]}
{"event_id":"$deep","type":"m.room.member","state_key":"@c:x","sender":"@c:x","depth":1,"origin_server_ts":10,"content":{"membership":"join"},"prev_events":[],"auth_events":[]}
{"event_id":"$and","type":"m.room.member","state_key":"@d:x","sender":"@d:x","depth":5,"origin_server_ts":80,"content":{"membership":"join"},"prev_events":[],"auth_events":[]}
"#,
    );
    let ctx: HashMap<String, LeanEvent> = events
        .iter()
        .map(|e| (e.event_id.clone(), e.clone()))
        .collect();

    // Full traversal from $child reaches $mid then $deep via prev_events;
    // $and has no edge into that chain from either direction, so it's
    // correctly reported unreachable.
    assert!(
        !rezzy::resolve::cdo::is_ancestor("$child", "$and", &ctx),
        "$and is on a genuinely disconnected branch"
    );
}

/// Coverage: CDO `dropped_ids.contains(*event_id)` skip (cdo.rs:349-351).
/// Tests a genuine cascading-drop scenario:
///   - Alice (PL 100) bans Bob → admin action, should survive.
///   - Bob (PL 0) attempts a self-leave → restricted by Alice's ban
///     (ban `state_key` matches leave sender), gets dropped.
///   - Bob sets a topic → non-admin event that is also dropped by Alice's ban.
///
/// The `dropped_ids.contains(*event_id)` skip path fires in the priority
/// iteration: once `$bob_leave` is dropped by Alice's ban, subsequent iterations
/// encounter it in `dropped_ids` and skip it immediately.
#[test]
fn test_cdo_apply_filter_cascading_drops() {
    let events = utils::parse_jsonl_events(
        r#"
{"event_id":"$create","type":"m.room.create","state_key":"","sender":"@alice:a","depth":0,"origin_server_ts":1000,"content":{"creator":"@alice:a","room_version":"12"},"prev_events":[],"auth_events":[]}
{"event_id":"$alice_join","type":"m.room.member","state_key":"@alice:a","sender":"@alice:a","depth":1,"origin_server_ts":1001,"content":{"membership":"join"},"prev_events":["$create"],"auth_events":["$create"]}
{"event_id":"$pl","type":"m.room.power_levels","state_key":"","sender":"@alice:a","depth":2,"origin_server_ts":1002,"content":{"users":{"@alice:a":100},"ban":50,"kick":50},"prev_events":["$alice_join"],"auth_events":["$create","$alice_join"]}
{"event_id":"$bob_join","type":"m.room.member","state_key":"@bob:b","sender":"@bob:b","depth":3,"origin_server_ts":1003,"content":{"membership":"join"},"prev_events":["$pl"],"auth_events":["$create","$pl"]}
{"event_id":"$ban_bob","type":"m.room.member","state_key":"@bob:b","sender":"@alice:a","depth":4,"origin_server_ts":2000,"content":{"membership":"ban"},"prev_events":["$bob_join"],"auth_events":["$create","$alice_join","$pl"],"power_level":100}
{"event_id":"$bob_leave","type":"m.room.member","state_key":"@bob:b","sender":"@bob:b","depth":4,"origin_server_ts":2001,"content":{"membership":"leave"},"prev_events":["$bob_join"],"auth_events":["$create","$bob_join","$pl"],"power_level":0}
{"event_id":"$bob_topic","type":"m.room.topic","state_key":"","sender":"@bob:b","depth":4,"origin_server_ts":2002,"content":{"topic":"bad topic"},"prev_events":["$bob_join"],"auth_events":["$create","$bob_join","$pl"],"power_level":0}
"#,
    );
    let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
    let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();

    for ev in &events {
        match ev.event_id.as_str() {
            "$ban_bob" | "$bob_leave" | "$bob_topic" => {
                conflicted.insert(ev.event_id.clone(), ev.clone());
            }
            _ => {
                auth_context.insert(ev.event_id.clone(), ev.clone());
            }
        }
    }

    let safe = rezzy::resolve::cdo::apply_cdo_filter(&conflicted, &auth_context);

    // Alice's ban (PL 100) must survive — it's the highest-priority admin action.
    assert!(safe.contains_key("$ban_bob"), "admin ban must survive CDO");

    // Bob's leave (sender=@bob:b) is restricted by Alice's ban (state_key=@bob:b).
    assert!(
        !safe.contains_key("$bob_leave"),
        "bob_leave should be dropped by the ban"
    );

    // Bob's topic (sender=@bob:b) is also restricted by Alice's ban.
    assert!(
        !safe.contains_key("$bob_topic"),
        "bob_topic should be dropped by the ban"
    );

    // Exact survivor count: only $ban_bob should remain.
    assert_eq!(
        safe.len(),
        1,
        "only the ban should survive, got: {:?}",
        safe.keys().collect::<Vec<_>>()
    );
}

/// Mirrors `test_cdo_apply_filter_cascading_drops`' ban scenario, but for
/// `is_demotion()`'s domination path instead of `is_ban_or_kick()`'s: an
/// independent-branch `power_levels` event that demotes Bob to 0 must not
/// dominate a ban Bob issued on a *different* branch while still validly
/// PL-50, citing that PL grant in its own `auth_events`.
///
/// This is the same unsoundness `join_has_prior_authorization()` fixes for
/// join-rules lockdowns (see `resolve/cdo.rs`), applied to the
/// `is_demotion()` domination path via `sender_has_pre_demotion_pl()`.
#[test]
fn test_cdo_demotion_does_not_dominate_pre_demotion_authorized_action() {
    let events = utils::parse_jsonl_events(
        r#"
{"event_id":"$create","type":"m.room.create","state_key":"","sender":"@alice:a","depth":0,"origin_server_ts":1000,"content":{"creator":"@alice:a","room_version":"12"},"prev_events":[],"auth_events":[]}
{"event_id":"$alice_join","type":"m.room.member","state_key":"@alice:a","sender":"@alice:a","depth":1,"origin_server_ts":1001,"content":{"membership":"join"},"prev_events":["$create"],"auth_events":["$create"]}
{"event_id":"$pl_init","type":"m.room.power_levels","state_key":"","sender":"@alice:a","depth":2,"origin_server_ts":1002,"content":{"users":{"@alice:a":100},"ban":50,"kick":50},"prev_events":["$alice_join"],"auth_events":["$create","$alice_join"]}
{"event_id":"$bob_join","type":"m.room.member","state_key":"@bob:b","sender":"@bob:b","depth":3,"origin_server_ts":1003,"content":{"membership":"join"},"prev_events":["$pl_init"],"auth_events":["$create","$alice_join","$pl_init"]}
{"event_id":"$pl_demote_bob","type":"m.room.power_levels","state_key":"","sender":"@alice:a","depth":4,"origin_server_ts":2000,"content":{"users":{"@alice:a":100,"@bob:b":0},"ban":50,"kick":50},"prev_events":["$bob_join"],"auth_events":["$create","$alice_join","$pl_init"]}
{"event_id":"$pl_grant_bob","type":"m.room.power_levels","state_key":"","sender":"@alice:a","depth":4,"origin_server_ts":2000,"content":{"users":{"@alice:a":100,"@bob:b":50},"ban":50,"kick":50},"prev_events":["$bob_join"],"auth_events":["$create","$alice_join","$bob_join","$pl_init"]}
{"event_id":"$bob_bans_charlie","type":"m.room.member","state_key":"@charlie:c","sender":"@bob:b","depth":5,"origin_server_ts":2001,"content":{"membership":"ban"},"prev_events":["$pl_grant_bob"],"auth_events":["$create","$alice_join","$bob_join","$pl_grant_bob"]}
"#,
    );
    let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
    let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();

    for ev in &events {
        match ev.event_id.as_str() {
            "$pl_demote_bob" | "$pl_grant_bob" | "$bob_bans_charlie" => {
                conflicted.insert(ev.event_id.clone(), ev.clone());
            }
            _ => {
                auth_context.insert(ev.event_id.clone(), ev.clone());
            }
        }
    }

    let safe = rezzy::resolve::cdo::apply_cdo_filter(&conflicted, &auth_context);

    assert!(
        safe.contains_key("$pl_demote_bob"),
        "the demotion itself is an admin action and must survive"
    );

    // $bob_bans_charlie's own auth_events cite $pl_grant_bob (Bob at PL
    // 50), the state it was actually authorized against -- $pl_demote_bob
    // exists only on an independent branch and does not invalidate that
    // authorization, the same way join_has_prior_authorization() protects
    // an analogous join.
    assert!(
        safe.contains_key("$bob_bans_charlie"),
        "Bob's ban cites its own pre-demotion PL grant, so an independent-branch \
         demotion must not dominate it"
    );
}

/// Regression for the `sender_has_pre_demotion_pl()` soundness fix: a sender
/// **absent** from the cited PL event's `users` map must NOT be treated as
/// empowered. Per the spec, an absent user's power falls back to
/// `users_default` (and to 0 when that is also absent), so an independent-branch
/// demotion still dominates an action taken by such a sender.
///
/// Mirrors `test_cdo_demotion_does_not_dominate_pre_demotion_authorized_action`
/// but with Bob omitted from `$pl_grant_bob.users` (and no `users_default`),
/// so Bob's effective pre-demotion PL is 0 rather than 50.
#[test]
fn test_cdo_demotion_dominates_absent_sender() {
    let events = utils::parse_jsonl_events(
        r#"
{"event_id":"$create","type":"m.room.create","state_key":"","sender":"@alice:a","depth":0,"origin_server_ts":1000,"content":{"creator":"@alice:a","room_version":"12"},"prev_events":[],"auth_events":[]}
{"event_id":"$alice_join","type":"m.room.member","state_key":"@alice:a","sender":"@alice:a","depth":1,"origin_server_ts":1001,"content":{"membership":"join"},"prev_events":["$create"],"auth_events":["$create"]}
{"event_id":"$pl_init","type":"m.room.power_levels","state_key":"","sender":"@alice:a","depth":2,"origin_server_ts":1002,"content":{"users":{"@alice:a":100},"ban":50,"kick":50},"prev_events":["$alice_join"],"auth_events":["$create","$alice_join"]}
{"event_id":"$bob_join","type":"m.room.member","state_key":"@bob:b","sender":"@bob:b","depth":3,"origin_server_ts":1003,"content":{"membership":"join"},"prev_events":["$pl_init"],"auth_events":["$create","$alice_join","$pl_init"]}
{"event_id":"$pl_demote_bob","type":"m.room.power_levels","state_key":"","sender":"@alice:a","depth":4,"origin_server_ts":2000,"content":{"users":{"@alice:a":100,"@bob:b":0},"ban":50,"kick":50},"prev_events":["$bob_join"],"auth_events":["$create","$alice_join","$pl_init"]}
{"event_id":"$pl_grant_bob","type":"m.room.power_levels","state_key":"","sender":"@alice:a","depth":4,"origin_server_ts":2000,"content":{"users":{"@alice:a":100},"ban":50,"kick":50},"prev_events":["$bob_join"],"auth_events":["$create","$alice_join","$bob_join","$pl_init"]}
{"event_id":"$bob_bans_charlie","type":"m.room.member","state_key":"@charlie:c","sender":"@bob:b","depth":5,"origin_server_ts":2001,"content":{"membership":"ban"},"prev_events":["$pl_grant_bob"],"auth_events":["$create","$bob_join","$pl_grant_bob"]}
"#,
    );
    let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
    let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();

    for ev in &events {
        match ev.event_id.as_str() {
            "$pl_demote_bob" | "$pl_grant_bob" | "$bob_bans_charlie" => {
                conflicted.insert(ev.event_id.clone(), ev.clone());
            }
            _ => {
                auth_context.insert(ev.event_id.clone(), ev.clone());
            }
        }
    }

    let safe = rezzy::resolve::cdo::apply_cdo_filter(&conflicted, &auth_context);

    // Bob is absent from $pl_grant_bob.users (no users_default), so his
    // effective pre-demotion PL is 0 -- the demotion legitimately dominates
    // his ban of Charlie.
    assert!(
        !safe.contains_key("$bob_bans_charlie"),
        "Bob has no pre-demotion PL grant (absent from users, no users_default), \
         so an independent-branch demotion must dominate his ban"
    );
}

#[test]
fn test_sorting_coverage() {
    let events = utils::parse_jsonl_events(
        r#"
{"event_id":"create","type":"m.room.create","state_key":"","sender":"alice","content":{"creator":"alice"}}
{"event_id":"pl","type":"m.room.power_levels","state_key":"","sender":"alice","content":{"users_default":10}}
{"event_id":"missing_pl","type":"m.room.message","sender":"bob","auth_events":["pl"]}
{"event_id":"empty_auth","type":"m.room.message","sender":"alice","auth_events":[]}
"#,
    );
    let mut events_map: HashMap<String, LeanEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();

    let create_ev = events_map.remove("create").unwrap();
    let pl_ev = events_map.remove("pl").unwrap();

    let mut auth = HashMap::new();
    auth.insert("pl".into(), pl_ev);

    let _ = rezzy::lean_kahn_sort(
        &events_map,
        &auth,
        Some(&create_ev),
        rezzy::StateResVersion::V2_2,
        &mut std::collections::HashMap::new(),
    );
}

#[test]
fn test_msc4289_sorting_v2_creator_gets_pl_100() {
    let events = utils::parse_jsonl_events(
        r#"
{"event_id":"create","type":"m.room.create","state_key":"","sender":"alice","content":{"creator":"alice","room_version":"10"}}
{"event_id":"alice_msg","type":"m.room.message","sender":"alice","auth_events":[]}
{"event_id":"bob_msg","type":"m.room.message","sender":"bob","auth_events":[]}
"#,
    );

    let mut events_map: HashMap<String, LeanEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();

    let create_ev = events_map.remove("create").unwrap();
    let auth = HashMap::new();

    // Sort with V2 — creator gets PL 100
    let result = rezzy::lean_kahn_sort(
        &events_map,
        &auth,
        Some(&create_ev),
        rezzy::StateResVersion::V2,
        &mut std::collections::HashMap::new(),
    );
    // Creator alice should sort with higher power than bob (PL 0), meaning she comes LAST in the sorted list (since sorting is ascending)
    assert!(result.len() >= 2);
    let alice_pos = result.iter().position(|id| id == "alice_msg").unwrap();
    let bob_pos = result.iter().position(|id| id == "bob_msg").unwrap();
    // Since kahn sort orders highest-power to lowest-power, Alice (PL 100) should come before Bob (PL 0).
    assert!(
        alice_pos < bob_pos,
        "Creator Alice (PL 100) should be sorted before Bob (PL 0), meaning higher power popped first"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_resolve_iterative_sort_with_deltas_parity() {
    use rezzy::state::delta::ResolvePhase;
    use rezzy::{
        resolve_iterative_sort, resolve_iterative_sort_with_deltas, LeanEvent, StateResVersion,
    };
    use serde_json::json;
    use std::collections::HashMap;

    // Build auth context
    let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();
    auth_context.insert(
        "create".into(),
        LeanEvent {
            event_id: "create".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            power_level: 100,
            origin_server_ts: 1,
            content: json!({}),
            ..Default::default()
        },
    );
    auth_context.insert(
        "join_rules".into(),
        LeanEvent {
            event_id: "join_rules".into(),
            event_type: "m.room.join_rules".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            power_level: 100,
            origin_server_ts: 2,
            content: json!({"join_rule": "public"}),
            auth_events: vec!["create".into()],
            ..Default::default()
        },
    );
    auth_context.insert(
        "alice_join".into(),
        LeanEvent {
            event_id: "alice_join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            sender: "@alice:example.com".into(),
            power_level: 50,
            origin_server_ts: 500,
            content: json!({"membership": "join"}),
            auth_events: vec!["create".into()],
            ..Default::default()
        },
    );
    auth_context.insert(
        "pl".into(),
        LeanEvent {
            event_id: "pl".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            power_level: 100,
            origin_server_ts: 3,
            content: json!({"users": {"@bob:example.com": 50}}),
            ..Default::default()
        },
    );

    let mut unconflicted = imbl::OrdMap::new();
    unconflicted.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@alice:example.com".into(),
        ),
        "alice_join".into(),
    );

    // Two competing Bob membership events
    let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();
    conflicted.insert(
        "bob_old".into(),
        LeanEvent {
            event_id: "bob_old".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@bob:example.com".into(),
            power_level: 50,
            origin_server_ts: 500,
            content: json!({"membership": "join"}),
            auth_events: vec![
                "create".into(),
                "join_rules".into(),
                "alice_join".into(),
                "pl".into(),
            ],
            ..Default::default()
        },
    );
    conflicted.insert(
        "bob_new".into(),
        LeanEvent {
            event_id: "bob_new".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@bob:example.com".into(),
            power_level: 50,
            origin_server_ts: 1000,
            content: json!({"membership": "join"}),
            auth_events: vec![
                "create".into(),
                "join_rules".into(),
                "alice_join".into(),
                "pl".into(),
            ],
            ..Default::default()
        },
    );

    // resolve_iterative_sort
    let resolved_plain = resolve_iterative_sort(
        unconflicted.clone(),
        conflicted.clone(),
        &auth_context,
        StateResVersion::V2,
        &mut std::collections::HashMap::new(),
    );

    // resolve_iterative_sort_with_deltas
    let (resolved_with, deltas) = resolve_iterative_sort_with_deltas(
        unconflicted,
        conflicted,
        &auth_context,
        StateResVersion::V2,
        &mut std::collections::HashMap::new(),
    );

    // The resolved state must be identical
    assert_eq!(
        resolved_plain, resolved_with,
        "resolve_iterative_sort_with_deltas must produce identical resolved state"
    );

    // Should have at least one delta
    assert!(
        !deltas.is_empty(),
        "should have captured at least one resolution delta"
    );
    // All deltas should target the bob membership slot (only conflicted events)
    let bob_key = (
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        String::from("@bob:example.com"),
    );
    for delta in &deltas {
        assert_eq!(
            delta.key, bob_key,
            "unexpected non-Bob delta: {:?}",
            delta.event_id
        );
    }
    // At least one delta should be accepted
    let accepted_count = deltas.iter().filter(|d| d.accepted).count();
    assert!(
        accepted_count >= 1,
        "at least one delta should be accepted, got {accepted_count}"
    );

    // Verify all deltas have a valid phase
    let power_count = deltas
        .iter()
        .filter(|d| d.phase == ResolvePhase::Power)
        .count();
    let non_power_count = deltas
        .iter()
        .filter(|d| d.phase == ResolvePhase::NonPower)
        .count();
    assert_eq!(
        power_count + non_power_count,
        deltas.len(),
        "all deltas should have Power or NonPower phase"
    );
}

#[test]
fn test_resolve_iterative_sort_with_deltas_no_duplicate_power_events() {
    use rezzy::{resolve_iterative_sort_with_deltas, LeanEvent, StateResVersion};
    use std::collections::HashMap;

    let mut unconflicted = imbl::OrdMap::new();
    unconflicted.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "$create".into(),
    );

    let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();
    let create_ev = LeanEvent {
        event_id: "$create".into(),
        event_type: "m.room.create".into(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".into(),
        ..Default::default()
    };
    auth_context.insert("$create".into(), create_ev.clone());

    let join_alice = LeanEvent {
        event_id: "$join_alice".into(),
        event_type: "m.room.member".into(),
        state_key: Some("@alice:example.com".into()),
        sender: "@alice:example.com".into(),
        content: serde_json::json!({ "membership": "join" }),
        auth_events: vec!["$create".into()],
        ..Default::default()
    };
    auth_context.insert("$join_alice".into(), join_alice.clone());

    let pl_alice = LeanEvent {
        event_id: "$pl_alice".into(),
        event_type: "m.room.power_levels".into(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".into(),
        content: serde_json::json!({
            "users": { "@alice:example.com": 100 }
        }),
        auth_events: vec!["$create".into(), "$join_alice".into()],
        ..Default::default()
    };

    let mut conflicted = HashMap::new();
    conflicted.insert("$pl_alice".into(), pl_alice.clone());

    let (_, deltas) = resolve_iterative_sort_with_deltas(
        unconflicted,
        conflicted,
        &auth_context,
        StateResVersion::V2,
        &mut std::collections::HashMap::new(),
    );

    let power_deltas: Vec<_> = deltas
        .iter()
        .filter(|d| d.event_id == "$pl_alice")
        .collect();

    assert_eq!(
        power_deltas.len(),
        1,
        "The double replay bug is present! Power event $pl_alice was recorded {} times in the deltas",
        power_deltas.len()
    );
}

/// Coverage: the `or_else(|| auth_context.get(id))` fallback on line 565.
/// MSC4297 supplementation routes a PL from `auth_context` into the power phase.
/// It's NOT in `conflicted_events`, so `sort_set.get(id)` misses and the fallback fires.
#[test]
fn test_deltas_supplemental_power_event_from_auth_context() {
    use rezzy::{resolve_iterative_sort_with_deltas, LeanEvent, StateResVersion};

    // Two conflicting PLs (alice vs bob), both auth-chained through an ancestor PL
    // that lives only in auth_context. MSC4297 supplementation pulls $pl_ancestor
    // into power_events, but it's NOT in conflicted_events → or_else fires.
    let events = utils::parse_jsonl_events(
        r#"
{"event_id":"$create","type":"m.room.create","state_key":"","sender":"@alice:x.com","depth":0,"origin_server_ts":1000,"content":{"room_version":"12"},"prev_events":[],"auth_events":[]}
{"event_id":"$alice_join","type":"m.room.member","state_key":"@alice:x.com","sender":"@alice:x.com","depth":1,"origin_server_ts":1001,"content":{"membership":"join"},"prev_events":["$create"],"auth_events":["$create"]}
{"event_id":"$bob_join","type":"m.room.member","state_key":"@bob:x.com","sender":"@bob:x.com","depth":1,"origin_server_ts":1001,"content":{"membership":"join"},"prev_events":["$create"],"auth_events":["$create"]}
{"event_id":"$pl_ancestor","type":"m.room.power_levels","state_key":"","sender":"@alice:x.com","depth":2,"origin_server_ts":1002,"content":{"users":{"@alice:x.com":100,"@bob:x.com":50}},"prev_events":["$alice_join"],"auth_events":["$create","$alice_join"]}
{"event_id":"$pl_alice","type":"m.room.power_levels","state_key":"","sender":"@alice:x.com","depth":3,"origin_server_ts":2000,"content":{"users":{"@alice:x.com":100,"@bob:x.com":0}},"prev_events":["$pl_ancestor"],"auth_events":["$create","$alice_join","$pl_ancestor"]}
{"event_id":"$pl_bob","type":"m.room.power_levels","state_key":"","sender":"@bob:x.com","depth":3,"origin_server_ts":3000,"content":{"users":{"@alice:x.com":100,"@bob:x.com":100}},"prev_events":["$pl_ancestor"],"auth_events":["$create","$bob_join","$pl_ancestor"]}
    "#,
    );

    let map: std::collections::HashMap<String, LeanEvent> = events
        .iter()
        .map(|e| (e.event_id.clone(), e.clone()))
        .collect();

    // Unconflicted: create is settled
    let mut unconflicted = imbl::OrdMap::new();
    unconflicted.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "$create".into(),
    );

    // auth_context: everything EXCEPT the two conflicting PLs
    let mut auth_context = std::collections::HashMap::new();
    for id in &["$create", "$alice_join", "$bob_join", "$pl_ancestor"] {
        auth_context.insert((*id).to_string(), map[*id].clone());
    }

    // Conflicted: only the two competing PLs
    let mut conflicted = std::collections::HashMap::new();
    conflicted.insert("$pl_alice".into(), map["$pl_alice"].clone());
    conflicted.insert("$pl_bob".into(), map["$pl_bob"].clone());

    // V2.1 triggers MSC4297 supplementation, pulling $pl from auth_context
    // into the power phase. During the delta loop, sort_set.get("$pl") misses
    // (it's not in conflicted_events), so the or_else fallback to auth_context fires.
    let (resolved, deltas) = resolve_iterative_sort_with_deltas(
        unconflicted,
        conflicted,
        &auth_context,
        StateResVersion::V2_1,
        &mut std::collections::HashMap::new(),
    );

    // The PL slot must be resolved to one of the two conflicting PLs
    let pl_key = (
        rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
        String::new(),
    );
    let winner = resolved.get(&pl_key).expect("PL must be resolved");
    assert!(
        winner == "$pl_alice" || winner == "$pl_bob",
        "PL winner must be one of the conflicting PLs, got {winner}"
    );

    // Both conflicting PLs must appear in deltas
    assert!(
        deltas.iter().any(|d| d.event_id == "$pl_alice"),
        "$pl_alice must appear in deltas"
    );
    assert!(
        deltas.iter().any(|d| d.event_id == "$pl_bob"),
        "$pl_bob must appear in deltas"
    );
}

#[test]
fn test_types_empty_event_type() {
    use rezzy::LeanEvent;

    let json_missing_type = serde_json::json!({
        "event_id": "$missing_type",
        "sender": "@alice:example.com",
        "content": {}
    });

    let result: Result<LeanEvent, _> = serde_json::from_value(json_missing_type);
    assert!(result.is_err(), "Expected error for missing event_type");

    let json_empty_type = serde_json::json!({
        "event_id": "$empty_type",
        "type": "",
        "sender": "@alice:example.com",
        "content": {}
    });

    let result: Result<LeanEvent, _> = serde_json::from_value(json_empty_type);
    assert!(result.is_err(), "Expected error for empty event_type");
}

#[test]
fn test_types_clamp_power_levels() {
    use rezzy::LeanEvent;

    let json_pl = serde_json::json!({
        "event_id": "$pl",
        "type": "m.room.power_levels",
        "sender": "@alice:example.com",
        "content": {
            "users": {
                "@bob:example.com": 9_999_999_999_999_999_999_u64
            },
            "ban": 10_000_000_000_000_000_000_u64
        }
    });

    let ev: LeanEvent = serde_json::from_value(json_pl).unwrap();
    let max_pl = 9_007_199_254_740_991; // MAX_POWER_LEVEL

    assert_eq!(ev.get_user_power_level("@bob:example.com"), Some(max_pl));
    assert_eq!(ev.get_ban(), Some(max_pl));
}

#[test]
fn test_v2_vs_v2_1_member_power_event_classification() {
    use rezzy::{LeanEvent, StateResVersion};
    use std::collections::HashMap;

    let mut sort_set: HashMap<String, LeanEvent<String>> = HashMap::new();

    let self_join: LeanEvent<String> = LeanEvent {
        event_id: "$self_join".into(),
        event_type: "m.room.member".into(),
        state_key: Some("@alice:example.com".into()),
        sender: "@alice:example.com".into(),
        content: serde_json::json!({ "membership": "join" }),
        ..Default::default()
    };

    let kick = LeanEvent {
        event_id: "$kick".into(),
        event_type: "m.room.member".into(),
        state_key: Some("@bob:example.com".into()),
        sender: "@alice:example.com".into(),
        content: serde_json::json!({ "membership": "leave" }), // Kick is leave where sender != state_key
        ..Default::default()
    };

    let self_leave = LeanEvent {
        event_id: "$self_leave".into(),
        event_type: "m.room.member".into(),
        state_key: Some("@charlie:example.com".into()),
        sender: "@charlie:example.com".into(),
        content: serde_json::json!({ "membership": "leave" }), // Self-leave
        ..Default::default()
    };

    sort_set.insert("$self_join".into(), self_join);
    sort_set.insert("$kick".into(), kick);
    sort_set.insert("$self_leave".into(), self_leave);

    let msg_ev: LeanEvent<String> = LeanEvent {
        event_id: "$msg".into(),
        event_type: "m.room.message".into(),
        ..Default::default()
    };
    sort_set.insert("$msg".into(), msg_ev);

    // Test V2 (Rooms 2-11)
    let mut set1_v2_power = HashMap::new();
    let mut set1_v2_non_power = HashMap::new();
    rezzy::resolve::lattice::route_power_events(
        &sort_set,
        &mut set1_v2_power,
        &mut set1_v2_non_power,
        StateResVersion::V2,
    );

    assert!(
        set1_v2_non_power.contains_key("$msg"),
        "V2 should route message to non-power events"
    );

    // In V2, ALL member events are power events.
    assert!(
        set1_v2_power.contains_key("$self_join"),
        "V2 should treat self-join as power event"
    );
    assert!(
        set1_v2_power.contains_key("$kick"),
        "V2 should treat kick as power event"
    );
    assert!(
        set1_v2_power.contains_key("$self_leave"),
        "V2 should treat self-leave as power event"
    );
    assert!(
        set1_v2_non_power.contains_key("$msg"),
        "V2 should route message to non-power events"
    );

    // Test V2.1 (Room 12+)
    let mut set2_v21_power = HashMap::new();
    let mut set2_v21_non_power = HashMap::new();
    rezzy::resolve::lattice::route_power_events(
        &sort_set,
        &mut set2_v21_power,
        &mut set2_v21_non_power,
        StateResVersion::V2_1,
    );

    // In V2.1, only bans/kicks are power events!
    assert!(
        !set2_v21_power.contains_key("$self_join"),
        "V2.1 should NOT treat self-join as power event"
    );
    assert!(
        set2_v21_power.contains_key("$kick"),
        "V2.1 should treat kick as power event"
    );
    assert!(
        !set2_v21_power.contains_key("$self_leave"),
        "V2.1 should NOT treat self-leave as power event"
    );

    assert!(
        set2_v21_non_power.contains_key("$self_join")
            && set2_v21_non_power.contains_key("$self_leave")
            && set2_v21_non_power.contains_key("$msg"),
        "V2.1 routes regular memberships and messages to non-power events"
    );
}

#[test]
fn test_lean_event_serialize_roundtrip() {
    let ev = LeanEvent::<String> {
        event_id: "$test".into(),
        event_type: "m.room.message".into(),
        state_key: Some(String::new()),
        power_level: 0,
        sender: "@alice:x.com".into(),
        origin_server_ts: 1_234_567_890,
        content: serde_json::json!({"body": "hello"}),
        prev_events: vec!["$prev".into()],
        auth_events: vec!["$auth".into()],
        depth: 5,
        rejected: true,
        soft_fail: true,
        room_id: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: LeanEvent<String> = serde_json::from_str(&json).unwrap();
    assert_eq!(ev.event_id, back.event_id);
    assert_eq!(ev.event_type, back.event_type);
    assert_eq!(ev.state_key, back.state_key);
    assert_eq!(ev.power_level, back.power_level);
    assert_eq!(ev.sender, back.sender);
    assert_eq!(ev.origin_server_ts, back.origin_server_ts);
    assert_eq!(ev.depth, back.depth);
    assert_eq!(ev.content, back.content);
    assert_eq!(ev.prev_events, back.prev_events);
    assert_eq!(ev.auth_events, back.auth_events);
    assert_eq!(ev.rejected, back.rejected);
    assert_eq!(ev.soft_fail, back.soft_fail);
}

#[test]
fn test_lean_event_deserialize_accepts_legacy_rejection_flags() {
    let ev: LeanEvent<String> = serde_json::from_str(
        r#"{
            "event_id": "$test",
            "type": "m.room.message",
            "state_key": "",
            "power_level": 0,
            "sender": "@alice:x.com",
            "origin_server_ts": 1234567890,
            "content": {"body": "hello"},
            "prev_events": ["$prev"],
            "auth_events": ["$auth"],
            "depth": 5,
            "rejected": true,
            "soft_fail": true
        }"#,
    )
    .unwrap();

    assert!(ev.rejected);
    assert!(ev.soft_fail);
}

#[test]
fn test_event_content_blanket_impl_all_methods() {
    use rezzy::basespec::rezzy_types::EventContent;

    let content = serde_json::json!({
        "membership": "join",
        "join_rule": "public",
        "ban": 60,
        "kick": 55,
        "invite": 40,
        "redact": 70,
        "users_default": 10,
        "events_default": 15,
        "state_default": 20,
        "creator": "@creator:x.com",
        "additional_creators": ["@ac:x.com"],
        "users": {"@alice:x.com": 100}
    });
    assert_eq!(content.get_membership(), Some("join"));
    assert_eq!(content.get_join_rule(), Some("public"));
    assert_eq!(content.get_ban(), Some(60));
    assert_eq!(content.get_kick(), Some(55));
    assert_eq!(content.get_invite(), Some(40));
    assert_eq!(content.get_redact(), Some(70));
    assert_eq!(content.get_users_default(), Some(10));
    assert_eq!(content.get_events_default(), Some(15));
    assert_eq!(content.get_state_default(), Some(20));
    assert_eq!(content.get_creator(), Some("@creator:x.com"));
    assert_eq!(content.get_user_power_level("@alice:x.com"), Some(100));
    assert!(content.has_additional_creator("@ac:x.com"));
    assert!(!content.has_additional_creator("@nobody:x.com"));
}

#[test]
fn test_msc4289_additional_creators_version_gating() {
    use rezzy::basespec::rezzy_types::EventContent;
    let content = serde_json::json!({
        "additional_creators": ["@ac:x.com"]
    });
    // The TestContent wrapper correctly parses it regardless of version
    assert!(
        content.has_additional_creator("@ac:x.com"),
        "The TestContent wrapper correctly parses it"
    );
    // Note: The actual version-gating (V2 vs V2.1+) is enforced in `src/auth/mod.rs`
    // `get_sender_power_level` where `has_additional_creator` is only evaluated
    // if the version matches V2_1 | V2_1_1 | V2_2.
}

/// Hypothetical comparison: proves `resolve_iterative_sort` produces different resolved
/// state for V2 vs V2.1 given identical inputs.
///
/// NOTE: V2 and V2.1 are orthogonal due to the breaking changes between room
/// v11 and v12 PDU syntax. This test is performed purely for hypothetical
/// comparison to validate that the version parameter flows through and
/// changes resolution semantics.
///
/// Based on the Complement test `TestMSC4297StateResolutionV2_1_starts_from_empty_set`:
/// - Unconflicted: everyone agrees alice=leave, create, pl exist
/// - Conflicted: `join_rules` is disputed ($`jr_invite` vs $`jr_public`)
/// - $`jr_invite` was sent by alice while she was JOINED (`auth_events` prove this)
///
/// V2: Starts from unconflicted state (alice=leave) → alice's $`jr_invite` fails
///     auth → only $`jr_public` survives.
/// V2.1: Starts from empty state → `local_auth` fallback sees alice=joined from
///       her auth chain → $`jr_invite` passes auth → both survive, later one wins.
#[test]
#[allow(clippy::too_many_lines)]
fn test_compute_state_at_v2_vs_v2_1_divergence() {
    use rezzy::{resolve_iterative_sort, LeanEvent, StateResVersion};
    use std::collections::HashMap;

    // === Auth context: all events available for auth chain lookups ===
    let mut auth_context: HashMap<String, LeanEvent> = HashMap::new();

    auth_context.insert(
        "$create".into(),
        LeanEvent {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            content: serde_json::json!({ "creator": "@alice:example.com" }),
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            origin_server_ts: 1000,
            ..Default::default()
        },
    );

    auth_context.insert(
        "$pl".into(),
        LeanEvent {
            event_id: "$pl".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            content: serde_json::json!({
                "users": { "@alice:example.com": 100 },
                "users_default": 0,
                "state_default": 50,
                "events_default": 0
            }),
            prev_events: vec!["$create".into()],
            auth_events: vec!["$create".into()],
            depth: 2,
            origin_server_ts: 2000,
            ..Default::default()
        },
    );

    auth_context.insert(
        "$alice_join".into(),
        LeanEvent {
            event_id: "$alice_join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            sender: "@alice:example.com".into(),
            content: serde_json::json!({ "membership": "join" }),
            prev_events: vec!["$pl".into()],
            auth_events: vec!["$create".into(), "$pl".into()],
            depth: 3,
            origin_server_ts: 3000,
            ..Default::default()
        },
    );

    auth_context.insert(
        "$alice_leave".into(),
        LeanEvent {
            event_id: "$alice_leave".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            sender: "@alice:example.com".into(),
            content: serde_json::json!({ "membership": "leave" }),
            prev_events: vec!["$alice_join".into()],
            auth_events: vec!["$create".into(), "$pl".into(), "$alice_join".into()],
            depth: 10,
            origin_server_ts: 10000,
            ..Default::default()
        },
    );

    // === Unconflicted state: everyone agrees on these ===
    let mut unconflicted: imbl::OrdMap<(rezzy::basespec::event_types::EventType, String), String> =
        imbl::OrdMap::new();
    unconflicted.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "$create".into(),
    );
    unconflicted.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
            String::new(),
        ),
        "$pl".into(),
    );
    // KEY: alice is LEAVE in unconflicted — both sides agree she left
    unconflicted.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@alice:example.com".into(),
        ),
        "$alice_leave".into(),
    );

    // === Conflicted events: join_rules is disputed ===
    let mut conflicted: HashMap<String, LeanEvent> = HashMap::new();

    // Alice's join_rules="invite" — sent while she was still JOINED
    // (her auth_events include $alice_join, not $alice_leave)
    conflicted.insert(
        "$jr_invite".into(),
        LeanEvent {
            event_id: "$jr_invite".into(),
            event_type: "m.room.join_rules".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            content: serde_json::json!({ "join_rule": "invite" }),
            prev_events: vec!["$alice_join".into()],
            auth_events: vec!["$create".into(), "$pl".into(), "$alice_join".into()],
            depth: 5,
            origin_server_ts: 5000,
            ..Default::default()
        },
    );

    // Original join_rules="public" — from earlier
    conflicted.insert(
        "$jr_public".into(),
        LeanEvent {
            event_id: "$jr_public".into(),
            event_type: "m.room.join_rules".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            content: serde_json::json!({ "join_rule": "public" }),
            prev_events: vec!["$alice_join".into()],
            auth_events: vec!["$create".into(), "$pl".into(), "$alice_join".into()],
            depth: 4,
            origin_server_ts: 4000,
            ..Default::default()
        },
    );

    // Resolve with V2
    let state_v2 = resolve_iterative_sort(
        unconflicted.clone(),
        conflicted.clone(),
        &auth_context,
        StateResVersion::V2,
        &mut std::collections::HashMap::new(),
    );

    // Resolve with V2.1
    let state_v2_1 = resolve_iterative_sort(
        unconflicted,
        conflicted,
        &auth_context,
        StateResVersion::V2_1,
        &mut std::collections::HashMap::new(),
    );

    // V2: unconflicted alice=leave → alice's $jr_invite fails auth → $jr_public wins
    // V2.1: empty initial state + local_auth alice=joined → $jr_invite passes → later event wins
    let jr_key: (rezzy::basespec::event_types::EventType, String) = (
        rezzy::basespec::event_types::EventType::from("m.room.join_rules"),
        String::new(),
    );

    assert_ne!(
        state_v2.get(&jr_key),
        state_v2_1.get(&jr_key),
        "V2 and V2.1 must resolve join_rules differently.\n\
         V2 join_rules: {:?}\n\
         V2.1 join_rules: {:?}\n\
         V2 full state: {state_v2:?}\n\
         V2.1 full state: {state_v2_1:?}",
        state_v2.get(&jr_key),
        state_v2_1.get(&jr_key),
    );
}

#[test]
fn test_state_res_version_serde_roundtrip() {
    let versions = vec![
        StateResVersion::V1,
        StateResVersion::V2,
        StateResVersion::V2_1,
        StateResVersion::V2_1_1,
        StateResVersion::V2_2,
    ];
    for v in &versions {
        let json = serde_json::to_string(v).unwrap();
        let back: StateResVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back, "Roundtrip failed for {v:?}");
    }
    // Unknown variant must fail
    let invalid: Result<StateResVersion, _> = serde_json::from_str("\"V99\"");
    assert!(invalid.is_err());

    // Non-string type triggers `expecting`
    let wrong_type: Result<StateResVersion, _> = serde_json::from_str("42");
    assert!(
        wrong_type.is_err(),
        "Deserializing an integer must fail with 'expected a StateResVersion string'"
    );
    let err_msg = wrong_type.unwrap_err().to_string();
    assert!(
        err_msg.contains("StateResVersion"),
        "Error message must mention StateResVersion: {err_msg}"
    );
}

/// Coverage: default `EventContent` trait method impls (lines 299-316).
/// Uses a minimal struct that does NOT override the `third_party_invite` defaults.
#[test]
fn test_event_content_default_trait_methods() {
    use rezzy::basespec::rezzy_types::EventContent;

    /// Minimal type that relies on ALL default trait impls for `third_party_invite`.
    #[derive(Debug, Clone, Default)]
    struct MinimalContent;
    impl EventContent for MinimalContent {
        fn get_membership(&self) -> Option<&str> {
            None
        }
        fn get_join_rule(&self) -> Option<&str> {
            None
        }
        fn get_user_power_level(&self, _: &str) -> Option<i64> {
            None
        }
        fn get_event_power_level(&self, _: &str) -> Option<i64> {
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
        fn get_room_version(&self) -> Option<&str> {
            None
        }
        fn has_additional_creator(&self, _: &str) -> bool {
            false
        }
        fn get_join_authorised_via_users_server(&self) -> Option<&str> {
            None
        }
        fn visit_event_power_levels<'a>(&'a self, _v: &mut dyn FnMut(&'a str, i64)) {}
        fn visit_user_power_levels<'a>(&'a self, _v: &mut dyn FnMut(&'a str, i64)) {}
        fn visit_notification_power_levels<'a>(&'a self, _v: &mut dyn FnMut(&'a str, i64)) {}
        fn visit_user_keys<'a>(&'a self, _v: &mut dyn FnMut(&'a str)) {}
    }

    let c = MinimalContent;
    assert!(!c.has_third_party_invite());
    assert!(c.get_third_party_invite_token().is_none());
    assert!(c.get_third_party_invite_mxid().is_none());
    assert!(!c.has_third_party_invite_signatures());
    // Rule 10 defaults
    let mut ev_count = 0;
    c.visit_event_power_levels(&mut |_, _| ev_count += 1);
    assert_eq!(ev_count, 0);

    let mut user_count = 0;
    c.visit_user_power_levels(&mut |_, _| user_count += 1);
    assert_eq!(user_count, 0);

    let mut notif_count = 0;
    c.visit_notification_power_levels(&mut |_, _| notif_count += 1);
    assert_eq!(notif_count, 0);
    assert!(c.find_non_integer_scalar_pl().is_none());
    assert!(c.find_non_integer_map_pl().is_none());
    assert!(!c.has_non_integer_users_pl(true));
    assert!(!c.has_non_integer_users_pl(false));
    assert!(!c.has_user_in_users("@someone:x"));
    assert!(
        c.additional_creators_are_valid(),
        "default impl is permissive for content types that don't expose the raw array"
    );
}

/// Coverage: default `EventVerifier::verify_third_party_invite` (line 369-375).
#[test]
fn test_event_verifier_default_third_party_invite() {
    use rezzy::basespec::rezzy_types::EventVerifier;

    struct DefaultVerifier;
    impl EventVerifier<String> for DefaultVerifier {}

    let v = DefaultVerifier;
    assert!(
        v.verify_third_party_invite(&"$ev".to_string(), "some_token")
            .is_ok(),
        "Default verify_third_party_invite must return Ok"
    );
}

#[test]
fn test_state_res_version_from_room_version() {
    assert_eq!(
        StateResVersion::from_room_version("1"),
        Some(StateResVersion::V1)
    );
    for v in ["2", "3", "4", "5", "6", "7", "8", "9", "10", "11"] {
        assert_eq!(
            StateResVersion::from_room_version(v),
            Some(StateResVersion::V2),
            "room version {v} should map to V2"
        );
    }
    assert_eq!(
        StateResVersion::from_room_version("12"),
        Some(StateResVersion::V2_1)
    );
    assert_eq!(
        StateResVersion::from_room_version("12.1"),
        Some(StateResVersion::V2_1_1)
    );
    assert_eq!(StateResVersion::from_room_version("0"), None);
    assert_eq!(StateResVersion::from_room_version("99"), None);
    assert_eq!(StateResVersion::from_room_version(""), None);
}

#[test]
fn test_dag_node_trait_on_lean_event() {
    use rezzy::basespec::rezzy_types::DagNode;
    let ev = LeanEvent::<String> {
        event_id: "ev".into(),
        depth: 42,
        prev_events: vec!["p1".into(), "p2".into()],
        auth_events: vec!["a1".into()],
        ..Default::default()
    };
    assert_eq!(ev.depth(), 42);
    assert_eq!(ev.prev_events().len(), 2);
    assert_eq!(ev.auth_events().len(), 1);
}

#[test]
fn test_msc4289_lean_event_get_redact_and_creator() {
    let ev = LeanEvent::<String> {
        event_id: "ev".into(),
        event_type: "m.room.power_levels".into(),
        content: serde_json::json!({"redact": 50, "creator": "@bob:x.com"}),
        ..Default::default()
    };
    assert_eq!(ev.get_redact(), Some(50));
    assert_eq!(ev.get_creator(), Some("@bob:x.com"));

    let empty = LeanEvent::<String>::default();
    assert_eq!(empty.get_redact(), None);
    assert_eq!(empty.get_creator(), None);
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_coverage_sweeper_for_unreachable_edges() {
    use rezzy::basespec::rezzy_types::{EventProvider, SortPriority};
    use rezzy::resolve::cdo::is_ancestor;
    use rezzy::resolve::lattice::resolve_lattice_fold;
    use rezzy::state::at::StateComputationError;
    use rezzy::state::delta::{reconstruct_state_batch, CompactedCheckpoint};
    use rezzy::{resolve_iterative_sort_with_deltas, LeanEvent, StateResVersion};
    use std::collections::{BTreeMap, HashMap};

    // Cover StateComputationError Display
    let err_cycle: StateComputationError<String> = StateComputationError::CycleDetected;
    let err_cb: StateComputationError<String> = StateComputationError::Callback("test".into());
    assert!(format!("{err_cycle}").contains("Cycle detected"));
    assert!(format!("{err_cb}").contains("Callback error"));

    // Cover cdo::is_ancestor (Public API unused internally)
    let mut context = HashMap::new();
    let ev1: LeanEvent<String> = LeanEvent {
        event_id: "A".to_string(),
        ..Default::default()
    };
    let ev2: LeanEvent<String> = LeanEvent {
        event_id: "B".to_string(),
        auth_events: vec!["A".to_string()],
        ..Default::default()
    };
    context.insert("A".to_string(), ev1.clone());
    context.insert("B".to_string(), ev2.clone());
    assert!(is_ancestor(&"B".to_string(), &"A".to_string(), &context));
    assert!(!is_ancestor(&"A".to_string(), &"B".to_string(), &context));

    // Cover resolve_lattice_fold
    let lattice_res = resolve_lattice_fold(
        imbl::OrdMap::new(),
        context.clone(),
        &HashMap::new(),
        StateResVersion::V2,
    );
    assert!(lattice_res.is_empty());

    // Cover get_initial_resolved_state for V1
    let mut unconf = imbl::OrdMap::new();
    unconf.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "123".into(),
    );
    let v1_resolved = rezzy::resolve::resolve_iterative_sort(
        unconf.clone(),
        HashMap::<String, LeanEvent<String>>::new(),
        &HashMap::<String, LeanEvent<String>>::new(),
        StateResVersion::V1,
        &mut std::collections::HashMap::new(),
    );
    assert_eq!(v1_resolved.len(), 1);

    // Cover SortPriority tie-breakers (sorting.rs)
    let ev1_v1 = LeanEvent::<String> {
        event_id: "A".into(),
        depth: 5,
        ..Default::default()
    };
    let ev2_v1 = LeanEvent::<String> {
        event_id: "B".into(),
        depth: 5,
        ..Default::default()
    };
    let p1_v1 = SortPriority {
        event: &ev1_v1,
        power_level: 0,
        version: StateResVersion::V1,
    };
    let p2_v1 = SortPriority {
        event: &ev2_v1,
        power_level: 0,
        version: StateResVersion::V1,
    };
    assert_eq!(p1_v1.cmp(&p2_v1), core::cmp::Ordering::Less); // A < B

    let ev1_v2 = LeanEvent::<String> {
        event_id: "A".into(),
        origin_server_ts: 100,
        ..Default::default()
    };
    let ev2_v2 = LeanEvent::<String> {
        event_id: "B".into(),
        origin_server_ts: 100,
        ..Default::default()
    };
    let p1_v2 = SortPriority {
        event: &ev1_v2,
        power_level: 0,
        version: StateResVersion::V2,
    };
    let p2_v2 = SortPriority {
        event: &ev2_v2,
        power_level: 0,
        version: StateResVersion::V2,
    };
    assert_eq!(p1_v2.cmp(&p2_v2), core::cmp::Ordering::Greater); // A > B (inverted)

    // Cover rejected events in resolve_iterative_sort_with_deltas
    let create: LeanEvent<String> = LeanEvent {
        event_id: "$create".into(),
        event_type: "m.room.create".into(),
        state_key: Some(String::new()),
        sender: "@alice:x.com".into(),
        ..Default::default()
    };

    let pl: LeanEvent<String> = LeanEvent {
        event_id: "$pl".into(),
        event_type: "m.room.power_levels".into(),
        state_key: Some(String::new()),
        sender: "@alice:x.com".into(),
        content: serde_json::json!({"users": {"@alice:x.com": 100}}),
        auth_events: vec!["$create".into()],
        ..Default::default()
    };

    let mut auth = HashMap::new();
    auth.insert("$create".into(), create.clone());
    auth.insert("$pl".into(), pl.clone());

    let bogus_power: LeanEvent<String> = LeanEvent {
        event_id: "$bogus_pl".into(),
        event_type: "m.room.power_levels".into(),
        state_key: Some(String::new()),
        sender: "@bob:x.com".into(), // not a member (no join): rejected for non-membership
        content: serde_json::json!({"users": {"@bob:x.com": 100}}),
        auth_events: vec!["$create".into(), "$pl".into()],
        ..Default::default()
    };

    let bogus_topic: LeanEvent<String> = LeanEvent {
        event_id: "$bogus_topic".into(),
        event_type: "m.room.topic".into(),
        state_key: Some(String::new()),
        sender: "@bob:x.com".into(), // not a member (no join): rejected for non-membership
        auth_events: vec!["$create".into(), "$pl".into()],
        ..Default::default()
    };

    let mut conflicted = HashMap::new();
    conflicted.insert("$bogus_pl".into(), bogus_power.clone());
    conflicted.insert("$bogus_topic".into(), bogus_topic.clone());

    let (resolved, deltas) = resolve_iterative_sort_with_deltas(
        imbl::OrdMap::new(),
        conflicted.clone(),
        &auth,
        StateResVersion::V2,
        &mut std::collections::HashMap::new(),
    );

    assert!(!resolved.contains_key(&(
        rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
        String::new()
    )));
    assert!(!resolved.contains_key(&(
        rezzy::basespec::event_types::EventType::from("m.room.topic"),
        String::new()
    )));
    assert!(deltas
        .iter()
        .any(|d| d.event_id == "$bogus_pl" && !d.accepted));
    assert!(deltas
        .iter()
        .any(|d| d.event_id == "$bogus_topic" && !d.accepted));

    // Cover BTreeMap EventProvider (types.rs)
    let btree_provider: BTreeMap<String, LeanEvent<String, serde_json::Value>> = BTreeMap::new();
    assert!(btree_provider.get_event(&"$none".to_string()).is_none());

    // Cover reconstruct_state_batch broken chain branches
    let orphan_cp: CompactedCheckpoint<String> = CompactedCheckpoint {
        state_hash: [0x11; 32],
        parent_hash: None,
        event_id: "E1".into(),
        deltas: vec![],
        snapshot: None, // Missing snapshot!
    };
    let missing_parent_cp: CompactedCheckpoint<String> = CompactedCheckpoint {
        state_hash: [0x22; 32],
        parent_hash: Some([0xFF; 32]),
        event_id: "E2".into(),
        deltas: vec![],
        snapshot: None,
    };
    let missing_grandparent_cp = CompactedCheckpoint {
        state_hash: [0x33; 32],
        parent_hash: Some([0x22; 32]), // H2 exists, but it failed to reconstruct
        event_id: "E3".into(),
        deltas: vec![],
        snapshot: None,
    };

    // Attempting to reconstruct all three will hit all 3 `continue` bailouts
    let broken_batch = reconstruct_state_batch(
        &[orphan_cp, missing_parent_cp, missing_grandparent_cp],
        &[0, 1, 2],
    );
    assert!(broken_batch.is_empty());

    // Cover lean_kahn_sort CycleDetected branch
    let mut cyclic_kahn_events: HashMap<String, LeanEvent<String>> = HashMap::new();
    let ev_a: LeanEvent<String> = LeanEvent {
        event_id: "A".into(),
        auth_events: vec!["B".into()],
        ..Default::default()
    };
    let ev_b: LeanEvent<String> = LeanEvent {
        event_id: "B".into(),
        auth_events: vec!["A".into()],
        ..Default::default()
    };
    cyclic_kahn_events.insert("A".into(), ev_a.clone());
    cyclic_kahn_events.insert("B".into(), ev_b.clone());

    let sorted_cyclic = rezzy::resolve::sorting::lean_kahn_sort(
        &cyclic_kahn_events,
        &HashMap::new(),
        None,
        StateResVersion::V2,
        &mut std::collections::HashMap::new(),
    );
    assert_eq!(sorted_cyclic.len(), 2);
}

// ── Coverage: ParsedEvent + RawEvent adapter ────────────────────────

/// Minimal `RawEvent` impl for coverage testing.
struct TestRawEvent {
    id: String,
    event_type: String,
    sender: String,
    state_key: Option<String>,
    content_json: String,
    prev_events: Vec<String>,
    auth_events: Vec<String>,
    depth: u64,
    origin_server_ts: u64,
    rejected: bool,
    soft_fail: bool,
}

impl rezzy::RawEvent for TestRawEvent {
    type Id = String;
    fn raw_event_id(&self) -> &String {
        &self.id
    }
    fn raw_event_type(&self) -> std::borrow::Cow<'_, str> {
        std::borrow::Cow::Borrowed(&self.event_type)
    }
    fn raw_sender(&self) -> &str {
        &self.sender
    }
    fn raw_state_key(&self) -> Option<&str> {
        self.state_key.as_deref()
    }
    fn raw_content_json(&self) -> &str {
        &self.content_json
    }
    fn raw_prev_events(&self) -> &[String] {
        &self.prev_events
    }
    fn raw_auth_events(&self) -> &[String] {
        &self.auth_events
    }
    fn raw_depth(&self) -> u64 {
        self.depth
    }
    fn raw_origin_server_ts(&self) -> u64 {
        self.origin_server_ts
    }
    fn raw_rejected(&self) -> bool {
        self.rejected
    }
    fn raw_soft_fail(&self) -> bool {
        self.soft_fail
    }
    // raw_power_level uses the default impl (returns 0) — exercises line 463-465
}

/// Exercises `ParsedEvent::new`, `try_new`, all `DagNode` + `EventLike`
/// delegations, and the `RawEvent::raw_power_level` default.
#[test]
fn test_parsed_event_full_coverage() {
    use rezzy::basespec::rezzy_types::{DagNode, EventLike};

    let raw = TestRawEvent {
        id: "$test1".into(),
        event_type: "m.room.member".into(),
        sender: "@alice:x".into(),
        state_key: Some("@bob:x".into()),
        content_json: r#"{"membership":"invite"}"#.into(),
        prev_events: vec!["$prev1".into()],
        auth_events: vec!["$auth1".into(), "$auth2".into()],
        depth: 42,
        origin_server_ts: 1_700_000_000,
        rejected: false,
        soft_fail: false,
    };
    let parsed_default_flags = rezzy::ParsedEvent::new(&raw);
    assert!(!parsed_default_flags.rejected());
    assert!(!parsed_default_flags.soft_fail());

    // ParsedEvent::new (line 502-508)
    // Use a PL-like event so we can test all EventLike default methods
    let raw_pl = TestRawEvent {
        id: "$pl".into(),
        event_type: "m.room.power_levels".into(),
        sender: "@admin:x".into(),
        state_key: Some(String::new()),
        content_json: r#"{
            "ban": 50, "kick": 50, "invite": 25, "redact": 50,
            "users_default": 0, "events_default": 0, "state_default": 50,
            "creator": "@admin:x", "room_version": "11",
            "users": {"@mod:x": 50},
            "events": {"m.room.topic": 25},
            "membership": "join",
            "join_rule": "public",
            "join_authorised_via_users_server": "@auth:x",
            "additional_creators": ["@ac:x"]
        }"#
        .into(),
        prev_events: vec!["$prev1".into()],
        auth_events: vec!["$auth1".into(), "$auth2".into()],
        depth: 42,
        origin_server_ts: 1_700_000_000,
        rejected: true,
        soft_fail: true,
    };
    let parsed = rezzy::ParsedEvent::new(&raw_pl);

    // DagNode impl (lines 514-528)
    assert_eq!(parsed.event_id(), "$pl");
    assert_eq!(parsed.depth(), 42);
    assert_eq!(parsed.prev_events(), &["$prev1"]);
    assert_eq!(parsed.auth_events().len(), 2);

    // EventLike required methods (lines 534-556)
    assert_eq!(parsed.event_type().as_ref(), "m.room.power_levels");
    assert_eq!(parsed.sender(), "@admin:x");
    assert_eq!(parsed.state_key(), Some(""));
    assert_eq!(parsed.power_level(), 0); // raw_power_level default
    assert_eq!(parsed.origin_server_ts(), 1_700_000_000);
    assert!(parsed.rejected());
    assert!(parsed.soft_fail());

    // EventLike DEFAULT methods (lines 279-337) — no inherent shadowing on ParsedEvent
    assert_eq!(parsed.get_membership(), Some("join"));
    assert_eq!(parsed.get_join_rule(), Some("public"));
    assert_eq!(parsed.get_user_power_level("@mod:x"), Some(50));
    assert_eq!(parsed.get_user_power_level("@nobody:x"), None);
    assert_eq!(parsed.get_event_power_level("m.room.topic"), Some(25));
    assert_eq!(parsed.get_event_power_level("m.room.message"), None);
    assert_eq!(parsed.get_users_default(), Some(0));
    assert_eq!(parsed.get_events_default(), Some(0));
    assert_eq!(parsed.get_state_default(), Some(50));
    assert_eq!(parsed.get_ban(), Some(50));
    assert_eq!(parsed.get_kick(), Some(50));
    assert_eq!(parsed.get_invite(), Some(25));
    assert_eq!(parsed.get_redact(), Some(50));
    assert_eq!(parsed.get_creator(), Some("@admin:x"));
    assert_eq!(parsed.get_room_version(), Some("11"));
    assert!(!parsed.has_additional_creator("@nobody:x"));
    assert!(parsed.has_additional_creator("@ac:x"));
    assert_eq!(
        parsed.get_join_authorised_via_users_server(),
        Some("@auth:x")
    );
}

/// Exercises `ParsedEvent::try_new` success and error paths (lines 488-494).
#[test]
fn test_parsed_event_try_new() {
    let valid = TestRawEvent {
        id: "$ok".into(),
        event_type: "m.room.message".into(),
        sender: "@a:x".into(),
        state_key: None,
        content_json: r#"{"body":"hi"}"#.into(),
        prev_events: vec![],
        auth_events: vec![],
        depth: 1,
        origin_server_ts: 0,
        rejected: false,
        soft_fail: false,
    };
    assert!(rezzy::ParsedEvent::try_new(&valid).is_ok());

    let invalid = TestRawEvent {
        id: "$bad".into(),
        event_type: "m.room.message".into(),
        sender: "@a:x".into(),
        state_key: None,
        content_json: "NOT VALID JSON {{".into(),
        prev_events: vec![],
        auth_events: vec![],
        depth: 1,
        origin_server_ts: 0,
        rejected: false,
        soft_fail: false,
    };
    assert!(rezzy::ParsedEvent::try_new(&invalid).is_err());
}

// ── Coverage: EventContent default accessors ────────────────────────

#[test]
fn test_event_content_get_room_version() {
    use rezzy::basespec::rezzy_types::EventContent;

    #[derive(Clone, Debug, Default)]
    struct CustomContent;
    impl EventContent for CustomContent {
        fn get_membership(&self) -> Option<&str> {
            None
        }
        fn get_join_rule(&self) -> Option<&str> {
            None
        }
        fn get_user_power_level(&self, _u: &str) -> Option<i64> {
            None
        }
        fn get_event_power_level(&self, _e: &str) -> Option<i64> {
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
        fn has_additional_creator(&self, _s: &str) -> bool {
            false
        }
        fn get_join_authorised_via_users_server(&self) -> Option<&str> {
            None
        }
        fn visit_event_power_levels<'a>(&'a self, _v: &mut dyn FnMut(&'a str, i64)) {}
        fn visit_user_power_levels<'a>(&'a self, _v: &mut dyn FnMut(&'a str, i64)) {}
        fn visit_notification_power_levels<'a>(&'a self, _v: &mut dyn FnMut(&'a str, i64)) {}
        fn visit_user_keys<'a>(&'a self, _v: &mut dyn FnMut(&'a str)) {}
    }

    let with_version = serde_json::json!({"room_version": "11"});
    assert_eq!(with_version.get_room_version(), Some("11"));

    let without = serde_json::json!({"membership": "join"});
    assert_eq!(without.get_room_version(), None);

    let non_string = serde_json::json!({"room_version": 42});
    assert_eq!(non_string.get_room_version(), None);

    // Verify the default trait implementation returns None
    assert_eq!(CustomContent.get_room_version(), None);
    assert_eq!(CustomContent.get_redacts(), None);

    let lean = LeanEvent::<String, CustomContent> {
        event_id: "$c".into(),
        event_type: "m.room.redaction".into(),
        sender: "@a:x".into(),
        content: CustomContent,
        ..Default::default()
    };
    assert_eq!(lean.get_redacts(), None);
}

// ── Coverage: LeanEvent inherent methods ────────────────────────────

#[test]
fn test_lean_event_get_room_version() {
    let event = LeanEvent::<String> {
        event_id: "$c".into(),
        event_type: "m.room.create".into(),
        state_key: Some(String::new()),
        sender: "@a:x".into(),
        content: serde_json::json!({"room_version": "10"}),
        ..Default::default()
    };
    assert_eq!(event.get_room_version(), Some("10"));
}

#[test]
fn test_lean_event_get_join_authorised_via_users_server() {
    let event = LeanEvent::<String> {
        event_id: "$j".into(),
        event_type: "m.room.member".into(),
        state_key: Some("@bob:x".into()),
        sender: "@bob:x".into(),
        content: serde_json::json!({
            "membership": "join",
            "join_authorised_via_users_server": "@alice:x"
        }),
        ..Default::default()
    };
    assert_eq!(
        event.get_join_authorised_via_users_server(),
        Some("@alice:x")
    );

    let without = LeanEvent::<String> {
        content: serde_json::json!({"membership": "join"}),
        ..event.clone()
    };
    assert_eq!(without.get_join_authorised_via_users_server(), None);
}

#[test]
fn test_lean_event_borrowed_view_roundtrip() {
    let event = LeanEvent::<String> {
        event_id: "$test".into(),
        event_type: "m.room.message".into(),
        state_key: Some(String::new()),
        power_level: 42,
        origin_server_ts: 1_234_567_890,
        sender: "@alice:x.com".into(),
        content: serde_json::json!({"body": "hello"}),
        prev_events: vec!["$prev".into()],
        auth_events: vec!["$auth".into()],
        depth: 5,
        rejected: true,
        soft_fail: false,
        room_id: None,
    };

    let view = event.as_ref();
    assert_eq!(view.event_id, &event.event_id);
    assert_eq!(view.event_type, event.event_type);
    assert_eq!(view.state_key, event.state_key.as_ref());
    assert_eq!(view.power_level, event.power_level);
    assert_eq!(view.origin_server_ts, event.origin_server_ts);
    assert_eq!(view.sender, event.sender);
    assert_eq!(view.content, &event.content);
    assert_eq!(view.prev_events, event.prev_events.as_slice());
    assert_eq!(view.auth_events, event.auth_events.as_slice());
    assert_eq!(view.depth, event.depth);
    assert_eq!(view.rejected, event.rejected);
    assert_eq!(view.soft_fail, event.soft_fail);

    let owned = view.to_owned();
    assert_eq!(owned.event_id, event.event_id);
    assert_eq!(owned.event_type, event.event_type);
    assert_eq!(owned.state_key, event.state_key);
    assert_eq!(owned.power_level, event.power_level);
    assert_eq!(owned.origin_server_ts, event.origin_server_ts);
    assert_eq!(owned.sender, event.sender);
    assert_eq!(owned.content, event.content);
    assert_eq!(owned.prev_events, event.prev_events);
    assert_eq!(owned.auth_events, event.auth_events);
    assert_eq!(owned.depth, event.depth);
    assert_eq!(owned.rejected, event.rejected);
    assert_eq!(owned.soft_fail, event.soft_fail);
}

#[test]
fn test_lean_event_borrowed_view_accessors() {
    use rezzy::basespec::rezzy_types::{DagNode, EventLike};

    let event = LeanEvent::<String> {
        event_id: "$test".into(),
        event_type: "m.room.message".into(),
        state_key: Some(String::new()),
        power_level: 7,
        origin_server_ts: 1_234_567_890,
        sender: "@alice:x.com".into(),
        content: serde_json::json!({"body": "hello"}),
        prev_events: vec!["$prev".into()],
        auth_events: vec!["$auth".into()],
        depth: 5,
        rejected: true,
        soft_fail: false,
        room_id: None,
    };

    let view = event.as_ref();
    assert_eq!(view.event_id(), &event.event_id);
    assert_eq!(view.depth(), event.depth);
    assert_eq!(view.prev_events(), event.prev_events.as_slice());
    assert_eq!(view.auth_events(), event.auth_events.as_slice());
    assert_eq!(view.event_type().as_ref(), event.event_type);
    assert_eq!(view.sender(), event.sender);
    assert_eq!(view.state_key(), event.state_key.as_deref());
    assert_eq!(view.power_level(), event.power_level);
    assert_eq!(view.origin_server_ts(), event.origin_server_ts);
    assert_eq!(view.content(), &event.content);
    assert_eq!(view.rejected(), event.rejected);
    assert_eq!(view.soft_fail(), event.soft_fail);
}

#[test]
fn test_event_like_default_rejection_flags() {
    use rezzy::basespec::rezzy_types::{DagNode, EventLike};

    struct MinimalEventLike {
        id: String,
        content: serde_json::Value,
    }

    impl DagNode for MinimalEventLike {
        type Id = String;

        fn event_id(&self) -> &String {
            &self.id
        }
        fn depth(&self) -> u64 {
            0
        }
        fn prev_events(&self) -> &[String] {
            &[]
        }
        fn auth_events(&self) -> &[String] {
            &[]
        }
    }

    impl EventLike for MinimalEventLike {
        type Content = serde_json::Value;

        fn event_type(&self) -> std::borrow::Cow<'_, str> {
            std::borrow::Cow::Borrowed("m.room.message")
        }
        fn sender(&self) -> &'static str {
            "@alice:x"
        }
        fn state_key(&self) -> Option<&str> {
            None
        }
        fn power_level(&self) -> i64 {
            0
        }
        fn origin_server_ts(&self) -> u64 {
            0
        }
        fn content(&self) -> &serde_json::Value {
            &self.content
        }
    }

    let event = MinimalEventLike {
        id: "$default-flags".into(),
        content: serde_json::json!({}),
    };

    assert!(!event.rejected());
    assert!(!event.soft_fail());
}

// ── Coverage: EventLike default methods + LeanEvent pl/ts ───────────

/// Exercises all `EventLike` default methods (lines 279-337) via trait
/// dispatch, plus `LeanEvent`'s `power_level` and `origin_server_ts`
/// (lines 377-382).
#[test]
fn test_event_like_default_methods_on_lean_event() {
    use rezzy::basespec::rezzy_types::EventLike;

    let pl_event = LeanEvent::<String> {
        event_id: "$pl".into(),
        event_type: "m.room.power_levels".into(),
        state_key: Some(String::new()),
        sender: "@admin:x".into(),
        power_level: 100,
        origin_server_ts: 1_700_000_000,
        content: serde_json::json!({
            "ban": 50,
            "kick": 50,
            "invite": 25,
            "redact": 50,
            "users_default": 0,
            "events_default": 0,
            "state_default": 50,
            "creator": "@admin:x",
            "room_version": "11",
            "users": {"@mod:x": 50},
            "events": {"m.room.topic": 25}
        }),
        ..Default::default()
    };

    // LeanEvent EventLike impl: power_level, origin_server_ts (lines 377-382)
    assert_eq!(pl_event.power_level(), 100);
    assert_eq!(pl_event.origin_server_ts(), 1_700_000_000);

    // EventLike default methods (lines 279-337)
    assert_eq!(pl_event.get_user_power_level("@mod:x"), Some(50));
    assert_eq!(pl_event.get_user_power_level("@nobody:x"), None);
    assert_eq!(pl_event.get_event_power_level("m.room.topic"), Some(25));
    assert_eq!(pl_event.get_event_power_level("m.room.message"), None);
    assert_eq!(pl_event.get_users_default(), Some(0));
    assert_eq!(pl_event.get_events_default(), Some(0));
    assert_eq!(pl_event.get_state_default(), Some(50));
    assert_eq!(pl_event.get_ban(), Some(50));
    assert_eq!(pl_event.get_kick(), Some(50));
    assert_eq!(pl_event.get_invite(), Some(25));
    assert_eq!(pl_event.get_redact(), Some(50));
    assert_eq!(pl_event.get_creator(), Some("@admin:x"));
    assert_eq!(pl_event.get_room_version(), Some("11"));
    assert!(!pl_event.has_additional_creator("@admin:x"));
}

// ── Coverage: restricts_sender false fallback (line 1216-1217) ──────

#[test]
fn test_restricts_sender_false_for_non_admin_event() {
    // A regular message event is neither ban/kick nor demotion
    let msg = LeanEvent::<String> {
        event_id: "$msg".into(),
        event_type: "m.room.message".into(),
        state_key: None,
        sender: "@alice:x".into(),
        content: serde_json::json!({"body": "hello"}),
        ..Default::default()
    };
    // Should return false — not a ban/kick/demotion
    assert!(!msg.restricts_sender("@alice:x"));
    assert!(!msg.restricts_sender("@bob:x"));
}

// ── Coverage: local_auth_cache version invalidation ─────────────────

/// Exercises iterative.rs:424-425 — when an external cache has a stale
/// version, it must be cleared before use.
#[test]
fn test_local_auth_cache_version_invalidation() {
    use rezzy::state::at::LocalAuthCache;

    /// Build a minimal conflicted-state fixture for cache invalidation tests.
    #[allow(clippy::type_complexity)]
    fn make_fixture() -> (
        imbl::OrdMap<(rezzy::basespec::event_types::EventType, String), String>,
        HashMap<String, LeanEvent<String>>,
        HashMap<String, LeanEvent<String>>,
    ) {
        let all = utils::parse_jsonl_events(
            r#"
{"event_id":"$create","type":"m.room.create","state_key":"","sender":"@alice:x","depth":1,"origin_server_ts":0,"prev_events":[],"auth_events":[],"content":{"room_version":"10","creator":"@alice:x"}}
{"event_id":"$join","type":"m.room.member","state_key":"@alice:x","sender":"@alice:x","depth":2,"origin_server_ts":0,"prev_events":[],"auth_events":["$create"],"content":{"membership":"join"}}
{"event_id":"$topicA","type":"m.room.topic","state_key":"","sender":"@alice:x","depth":3,"origin_server_ts":0,"prev_events":[],"auth_events":["$create","$join"],"content":{"topic":"A"}}
{"event_id":"$topicB","type":"m.room.topic","state_key":"","sender":"@alice:x","depth":3,"origin_server_ts":1,"prev_events":[],"auth_events":["$create","$join"],"content":{"topic":"B"}}
        "#,
        );

        let by_id: HashMap<String, LeanEvent> =
            all.into_iter().map(|e| (e.event_id.clone(), e)).collect();

        let unconflicted = [
            (
                (
                    rezzy::basespec::event_types::EventType::from("m.room.create"),
                    String::new(),
                ),
                String::from("$create"),
            ),
            (
                (
                    rezzy::basespec::event_types::EventType::from("m.room.member"),
                    "@alice:x".into(),
                ),
                String::from("$join"),
            ),
        ]
        .into_iter()
        .collect();

        let conflicted = [
            ("$topicA".into(), by_id["$topicA"].clone()),
            ("$topicB".into(), by_id["$topicB"].clone()),
        ]
        .into_iter()
        .collect();

        let auth_context = [
            ("$create".into(), by_id["$create"].clone()),
            ("$join".into(), by_id["$join"].clone()),
        ]
        .into_iter()
        .collect();

        (unconflicted, conflicted, auth_context)
    }

    // ── resolve_iterative_sort_with_cache (iterative.rs:419-426) ──
    let (unconflicted, conflicted, auth_context) = make_fixture();
    let mut cache = LocalAuthCache::new(StateResVersion::V2);
    cache
        .map
        .insert("stale_key".into(), std::collections::BTreeMap::new());
    assert_eq!(cache.version, StateResVersion::V2);
    assert!(!cache.map.is_empty(), "cache should have stale entry");

    let _result = rezzy::resolve_iterative_sort_with_cache(
        unconflicted,
        conflicted,
        &auth_context,
        Some(&mut cache),
        StateResVersion::V2_1,
        &mut std::collections::HashMap::new(),
    );
    assert_eq!(cache.version, StateResVersion::V2_1);
    assert!(!cache.map.contains_key("stale_key"));

    // ── resolve_iterative_sort_with_cache_and_deltas (iterative.rs:551-559) ──
    let (unconflicted, conflicted, auth_context) = make_fixture();
    let mut cache2 = LocalAuthCache::new(StateResVersion::V2);
    cache2
        .map
        .insert("stale2".into(), std::collections::BTreeMap::new());

    let (_result2, _deltas) = rezzy::resolve_iterative_sort_with_cache_and_deltas(
        unconflicted,
        conflicted,
        &auth_context,
        Some(&mut cache2),
        StateResVersion::V2_1,
        &mut std::collections::HashMap::new(),
    );
    assert_eq!(cache2.version, StateResVersion::V2_1);
    assert!(!cache2.map.contains_key("stale2"));
}

/// Tests that the trivial-conflict fast path resolves a 1-key non-power fork
/// correctly by picking the later-timestamp winner.
///
/// DAG:
///   CREATE → JOIN → PL → A (topic ts=100) ─┐
///                       └→ B (topic ts=200) ─┴→ D (merge)
#[test]
fn test_trivial_conflict_fast_path_picks_later_ts() {
    let events: Vec<LeanEvent> = utils::parse_jsonl_events(
        r#"
{"event_id":"CREATE","type":"m.room.create","state_key":"","sender":"@alice:example.com","origin_server_ts":1,"prev_events":[],"auth_events":[],"content":{}}
{"event_id":"JOIN","type":"m.room.member","state_key":"@alice:example.com","sender":"@alice:example.com","origin_server_ts":2,"prev_events":["CREATE"],"auth_events":["CREATE"],"content":{"membership":"join"}}
{"event_id":"PL","type":"m.room.power_levels","state_key":"","sender":"@alice:example.com","origin_server_ts":3,"prev_events":["JOIN"],"auth_events":["CREATE","JOIN"],"content":{"users":{"@alice:example.com":100}}}
{"event_id":"A","type":"m.room.topic","state_key":"","sender":"@alice:example.com","origin_server_ts":100,"prev_events":["PL"],"auth_events":["CREATE","JOIN","PL"],"content":{}}
{"event_id":"B","type":"m.room.topic","state_key":"","sender":"@alice:example.com","origin_server_ts":200,"prev_events":["PL"],"auth_events":["CREATE","JOIN","PL"],"content":{}}
{"event_id":"D","type":"m.room.message","sender":"@alice:example.com","origin_server_ts":300,"prev_events":["A","B"],"auth_events":["CREATE","JOIN","PL"],"content":{}}
    "#,
    );
    let events_map: HashMap<String, LeanEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();
    let state = compute_state_at("D", &events_map, StateResVersion::V2).unwrap();
    // B (ts=200) should win the topic slot
    assert_eq!(
        state.get(&(
            rezzy::basespec::event_types::EventType::from("m.room.topic"),
            String::new()
        )),
        Some(&"B".to_string()),
        "Later timestamp should win in trivial conflict fast path"
    );
}

/// Tests that when `origin_server_ts` ties, the lexicographically larger
/// `event_id` wins (spec tie-breaking rule).
///
/// Both A and B have ts=100, but "B" > "A" lexicographically → B wins.
#[test]
fn test_trivial_conflict_fast_path_ts_tie_falls_back_to_event_id() {
    let events: Vec<LeanEvent> = utils::parse_jsonl_events(
        r#"
{"event_id":"CREATE","type":"m.room.create","state_key":"","sender":"@alice:example.com","origin_server_ts":1,"prev_events":[],"auth_events":[],"content":{}}
{"event_id":"JOIN","type":"m.room.member","state_key":"@alice:example.com","sender":"@alice:example.com","origin_server_ts":2,"prev_events":["CREATE"],"auth_events":["CREATE"],"content":{"membership":"join"}}
{"event_id":"PL","type":"m.room.power_levels","state_key":"","sender":"@alice:example.com","origin_server_ts":3,"prev_events":["JOIN"],"auth_events":["CREATE","JOIN"],"content":{"users":{"@alice:example.com":100}}}
{"event_id":"A","type":"m.room.topic","state_key":"","sender":"@alice:example.com","origin_server_ts":100,"prev_events":["PL"],"auth_events":["CREATE","JOIN","PL"],"content":{}}
{"event_id":"B","type":"m.room.topic","state_key":"","sender":"@alice:example.com","origin_server_ts":100,"prev_events":["PL"],"auth_events":["CREATE","JOIN","PL"],"content":{}}
{"event_id":"D","type":"m.room.message","sender":"@alice:example.com","origin_server_ts":300,"prev_events":["A","B"],"auth_events":["CREATE","JOIN","PL"],"content":{}}
    "#,
    );
    let events_map: HashMap<String, LeanEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();
    let state = compute_state_at("D", &events_map, StateResVersion::V2).unwrap();
    // Same ts=100, so event_id tiebreak: "B" > "A" → B wins
    assert_eq!(
        state.get(&(
            rezzy::basespec::event_types::EventType::from("m.room.topic"),
            String::new()
        )),
        Some(&"B".to_string()),
        "Equal timestamps should fall back to lexicographic event_id comparison"
    );
}

/// Tests that a power event conflict (e.g., competing PL events) correctly
/// falls through to the full resolution pipeline, NOT the trivial fast path.
#[test]
fn test_trivial_conflict_power_event_fallthrough() {
    let events: Vec<LeanEvent> = utils::parse_jsonl_events(
        r#"
{"event_id":"CREATE","type":"m.room.create","state_key":"","sender":"@alice:example.com","origin_server_ts":1,"prev_events":[],"auth_events":[],"content":{}}
{"event_id":"JOIN","type":"m.room.member","state_key":"@alice:example.com","sender":"@alice:example.com","origin_server_ts":2,"prev_events":["CREATE"],"auth_events":["CREATE"],"content":{"membership":"join"}}
{"event_id":"PL_A","type":"m.room.power_levels","state_key":"","sender":"@alice:example.com","origin_server_ts":100,"prev_events":["JOIN"],"auth_events":["CREATE","JOIN"],"content":{"users":{"@alice:example.com":100}}}
{"event_id":"PL_B","type":"m.room.power_levels","state_key":"","sender":"@alice:example.com","origin_server_ts":200,"prev_events":["JOIN"],"auth_events":["CREATE","JOIN"],"content":{"users":{"@alice:example.com":100}}}
{"event_id":"D","type":"m.room.message","sender":"@alice:example.com","origin_server_ts":300,"prev_events":["PL_A","PL_B"],"auth_events":["CREATE","JOIN"],"content":{}}
    "#,
    );
    let events_map: HashMap<String, LeanEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();
    let state = compute_state_at("D", &events_map, StateResVersion::V2).unwrap();
    // PL_B (ts=200) should win over PL_A (ts=100) via the full pipeline's
    // Kahn sort + iterative auth. The trivial fast path skips power events
    // entirely, so getting the correct winner proves fallthrough occurred.
    assert_eq!(
        state.get(&(
            rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
            String::new()
        )),
        Some(&"PL_B".to_string()),
        "Full pipeline must resolve competing PLs — later ts wins"
    );
}

/// Tests that forks with no create event in unconflicted state bail to
/// full resolution (the fast path can't auth-check without create).
#[test]
fn test_trivial_conflict_no_create_bails_to_full_pipeline() {
    let events: Vec<LeanEvent> = utils::parse_jsonl_events(
        r#"
{"event_id":"A","type":"m.room.message","sender":"@alice:example.com","origin_server_ts":1,"prev_events":[],"auth_events":[],"content":{}}
{"event_id":"B","type":"m.room.name","state_key":"","sender":"@alice:example.com","origin_server_ts":100,"prev_events":["A"],"auth_events":[],"content":{}}
{"event_id":"C","type":"m.room.name","state_key":"","sender":"@alice:example.com","origin_server_ts":200,"prev_events":["A"],"auth_events":[],"content":{}}
{"event_id":"D","type":"m.room.message","sender":"@alice:example.com","origin_server_ts":300,"prev_events":["B","C"],"auth_events":[],"content":{}}
    "#,
    );
    let events_map: HashMap<String, LeanEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();
    let state = compute_state_at("D", &events_map, StateResVersion::V2).unwrap();
    assert!(
        state.is_empty(),
        "Missing create event should result in empty state (fast path bails, full pipeline rejects all)"
    );
}

/// Complete linear DAG with all parents present → no backward extremities.
#[test]
fn test_find_backward_extremities_no_gaps() {
    use std::collections::HashMap;

    let events = utils::parse_jsonl_events(
        r#"
        {"event_id":"$create","type":"m.room.create","sender":"@a:x","origin_server_ts":0,"depth":1,"prev_events":[],"content":{}}
        {"event_id":"$join","type":"m.room.member","state_key":"@a:x","sender":"@a:x","origin_server_ts":1,"depth":2,"prev_events":["$create"],"content":{"membership":"join"}}
        {"event_id":"$msg","type":"m.room.message","sender":"@a:x","origin_server_ts":2,"depth":3,"prev_events":["$join"],"content":{}}
    "#,
    );
    let events_map: HashMap<String, LeanEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();

    let gaps = rezzy::find_backward_extremities(&events_map, |_| false);
    assert!(
        gaps.is_empty(),
        "Complete DAG should have no backward extremities"
    );
}

/// One event references a parent not in the map → single backward extremity.
#[test]
fn test_find_backward_extremities_single_gap() {
    use std::collections::HashMap;

    let events = utils::parse_jsonl_events(
        r#"
        {"event_id":"$msg","type":"m.room.message","sender":"@a:x","origin_server_ts":2,"depth":3,"prev_events":["$missing_parent"],"content":{}}
    "#,
    );
    let events_map: HashMap<String, LeanEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();

    let gaps = rezzy::find_backward_extremities(&events_map, |_| false);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].event_id, "$msg");
    assert_eq!(
        gaps[0].missing_prev_events,
        vec!["$missing_parent".to_string()]
    );
}

/// Forked DAG: two events each reference different missing parents.
/// Also tests that an event with multiple `prev_events` only reports the missing ones.
#[test]
fn test_find_backward_extremities_multiple_gaps() {
    use std::collections::HashMap;

    let events = utils::parse_jsonl_events(
        r#"
        {"event_id":"$create","type":"m.room.create","sender":"@a:x","origin_server_ts":0,"depth":1,"prev_events":[],"content":{}}
        {"event_id":"$fork_a","type":"m.room.message","sender":"@a:x","origin_server_ts":1,"depth":2,"prev_events":["$create","$ghost_a"],"content":{}}
        {"event_id":"$fork_b","type":"m.room.message","sender":"@b:x","origin_server_ts":1,"depth":2,"prev_events":["$ghost_b"],"content":{}}
    "#,
    );
    let events_map: HashMap<String, LeanEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();

    let mut gaps = rezzy::find_backward_extremities(&events_map, |_| false);
    // Sort for deterministic assertion (HashMap iteration order is random)
    gaps.sort_by(|a, b| a.event_id.cmp(&b.event_id));

    assert_eq!(gaps.len(), 2);

    assert_eq!(gaps[0].event_id, "$fork_a");
    assert_eq!(gaps[0].missing_prev_events, vec!["$ghost_a".to_string()]);

    assert_eq!(gaps[1].event_id, "$fork_b");
    assert_eq!(gaps[1].missing_prev_events, vec!["$ghost_b".to_string()]);
}

/// The `exists` oracle recognizes a parent that isn't in the events map,
/// so it should NOT be reported as a gap.
#[test]
fn test_find_backward_extremities_with_exists_oracle() {
    use std::collections::HashMap;

    let events = utils::parse_jsonl_events(
        r#"
        {"event_id":"$msg1","type":"m.room.message","sender":"@a:x","origin_server_ts":1,"depth":2,"prev_events":["$in_db"],"content":{}}
        {"event_id":"$msg2","type":"m.room.message","sender":"@a:x","origin_server_ts":2,"depth":3,"prev_events":["$truly_missing"],"content":{}}
    "#,
    );
    let events_map: HashMap<String, LeanEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();

    // Simulate: "$in_db" exists in the database but wasn't loaded into the map
    let gaps = rezzy::find_backward_extremities(&events_map, |id| id == "$in_db");

    assert_eq!(
        gaps.len(),
        1,
        "Only the truly missing parent should be reported"
    );
    assert_eq!(gaps[0].event_id, "$msg2");
    assert_eq!(
        gaps[0].missing_prev_events,
        vec!["$truly_missing".to_string()]
    );
}

/// Regression test: non-power events from fork branches with divergent PL
/// ancestor distances must be resolved via mainline sort, not raw timestamp.
///
/// DAG (timeline):
///   $create → $join → $`pl_v1` → $`pl_v2` ──┬── $`topic_old_pl` (ts=500, `auth→$pl_v1`)
///                                           └── $`topic_new_pl` (ts=400, `auth→$pl_v2`)
///                                                              │
///                                                           $merge
///
/// Mainline after power phase: [$`pl_v2` (pos 0), $`pl_v1` (pos 1)]
///
/// $`topic_old_pl` → nearest PL ancestor = $`pl_v1` (pos 1, farther)
/// $`topic_new_pl` → nearest PL ancestor = $`pl_v2` (pos 0, closer)
///
/// Full pipeline (mainline sort): farther events applied first, closer applied
/// last → **$`topic_new_pl` wins** (last-write-wins).
///
/// Raw timestamp: **$`topic_old_pl` wins** (ts 500 > 400) — WRONG.
///
/// This catches the bug where a "trivial conflict" fast path bypasses mainline
/// sort and uses raw timestamp, producing incorrect resolution when auth chains
/// diverge across fork branches (e.g. network partitions).
#[test]
fn test_mainline_position_beats_timestamp_on_divergent_auth_chains() {
    use std::collections::HashMap;

    let events = utils::parse_jsonl_events(
        r#"
{"event_id":"$create","type":"m.room.create","state_key":"","sender":"@alice:x","origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],"content":{"creator":"@alice:x"}}
{"event_id":"$join","type":"m.room.member","state_key":"@alice:x","sender":"@alice:x","origin_server_ts":2,"depth":2,"prev_events":["$create"],"auth_events":["$create"],"content":{"membership":"join"}}
{"event_id":"$pl_v1","type":"m.room.power_levels","state_key":"","sender":"@alice:x","origin_server_ts":3,"depth":3,"prev_events":["$join"],"auth_events":["$create","$join"],"content":{"users":{"@alice:x":100}}}
{"event_id":"$pl_v2","type":"m.room.power_levels","state_key":"","sender":"@alice:x","origin_server_ts":4,"depth":4,"prev_events":["$pl_v1"],"auth_events":["$create","$join","$pl_v1"],"content":{"users":{"@alice:x":100}}}
{"event_id":"$topic_old_pl","type":"m.room.topic","state_key":"","sender":"@alice:x","origin_server_ts":500,"depth":5,"prev_events":["$pl_v2"],"auth_events":["$create","$join","$pl_v1"],"content":{}}
{"event_id":"$topic_new_pl","type":"m.room.topic","state_key":"","sender":"@alice:x","origin_server_ts":400,"depth":5,"prev_events":["$pl_v2"],"auth_events":["$create","$join","$pl_v2"],"content":{}}
{"event_id":"$merge","type":"m.room.message","sender":"@alice:x","origin_server_ts":600,"depth":6,"prev_events":["$topic_old_pl","$topic_new_pl"],"auth_events":["$create","$join","$pl_v2"],"content":{}}
    "#,
    );
    let events_map: HashMap<String, LeanEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();

    let state = compute_state_at("$merge", &events_map, StateResVersion::V2).unwrap();

    // $topic_new_pl (ts=400) must win because it's closer to the current PL
    // in the mainline (position 0). $topic_old_pl (ts=500) is farther
    // (position 1) and gets applied first, then overwritten.
    // A raw timestamp comparison would incorrectly pick $topic_old_pl.
    assert_eq!(
        state.get(&(
            rezzy::basespec::event_types::EventType::from("m.room.topic"),
            String::new()
        )),
        Some(&"$topic_new_pl".to_string()),
        "Mainline position (closeness to current PL) must beat raw timestamp"
    );
}

/// MSC4297 Problem B parity: `resolve_state_maps` vs `resolve_iterative_sort`.
///
/// Problem B has two forks with different PL events. In V2.1+, the subgraph
/// computation adds `$pl_bob_1` (an intermediate PL in the auth chain of
/// `$pl_bob_2`) to the conflicted set. The reviewer flagged that
/// `resolve_state_maps` might miss this step since it doesn't call
/// `compute_v2_1_conflicted_subgraph` explicitly.
///
/// This test settles the question: if both APIs produce identical results,
/// the full `events_map` as `event_context` implicitly satisfies the subgraph
/// requirement via auth-chain expansion inside `resolve_iterative_sort`.
#[test]
#[allow(clippy::too_many_lines)]
fn test_msc4297_problem_b_resolve_state_maps_parity() {
    // MSC4297 Problem B events (from fixtures/MSC4297-problem-B/pdus-v12.json)
    let all_evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$create",    "type": "m.room.create",       "state_key": "", "sender": "@alice:x", "origin_server_ts": 0, "content": {"room_version": "12"}}
        {"event_id": "$join_a",    "type": "m.room.member",       "state_key": "@alice:x", "sender": "@alice:x", "origin_server_ts": 1, "content": {"membership": "join"}, "auth_events": ["$create"]}
        {"event_id": "$pl0",       "type": "m.room.power_levels", "state_key": "", "sender": "@alice:x", "origin_server_ts": 2, "content": {}, "auth_events": ["$join_a"]}
        {"event_id": "$jr",        "type": "m.room.join_rules",   "state_key": "", "sender": "@alice:x", "origin_server_ts": 3, "content": {"join_rule": "public"}, "auth_events": ["$join_a", "$pl0"]}
        {"event_id": "$join_b",    "type": "m.room.member",       "state_key": "@bob:x", "sender": "@bob:x", "origin_server_ts": 4, "content": {"membership": "join"}, "auth_events": ["$pl0", "$jr"]}
        {"event_id": "$join_c",    "type": "m.room.member",       "state_key": "@charlie:x", "sender": "@charlie:x", "origin_server_ts": 5, "content": {"membership": "join"}, "auth_events": ["$pl0", "$jr"]}
        {"event_id": "$pl1",       "type": "m.room.power_levels", "state_key": "", "sender": "@alice:x", "origin_server_ts": 6, "content": {"users": {"@bob:x": 50}}, "auth_events": ["$pl0", "$join_a"]}
        {"event_id": "$pl2",       "type": "m.room.power_levels", "state_key": "", "sender": "@bob:x",   "origin_server_ts": 7, "content": {"users": {"@bob:x": 50, "@charlie:x": 50}}, "auth_events": ["$pl1", "$join_b"]}
        {"event_id": "$join_z",    "type": "m.room.member",       "state_key": "@zara:x", "sender": "@zara:x", "origin_server_ts": 8, "content": {"membership": "join"}, "auth_events": ["$pl2", "$jr"]}
        {"event_id": "$join_e",    "type": "m.room.member",       "state_key": "@eve:x", "sender": "@eve:x", "origin_server_ts": 9, "content": {"membership": "join"}, "auth_events": ["$pl2", "$jr"]}
        {"event_id": "$eve_dn",    "type": "m.room.member",       "state_key": "@eve:x", "sender": "@eve:x", "origin_server_ts": 9, "content": {"displayname": "eve++", "membership": "join"}, "auth_events": ["$pl2", "$join_e", "$jr"]}
    "#,
    );

    let mut events_map: std::collections::HashMap<String, rezzy::LeanEvent> =
        std::collections::HashMap::new();
    for ev in all_evs {
        events_map.insert(ev.event_id.clone(), ev);
    }

    // Fork "Eve": sees $pl0 as PL, has eve's display-name change
    let mut state_eve = imbl::OrdMap::new();
    state_eve.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "$create".into(),
    );
    state_eve.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@alice:x".into(),
        ),
        "$join_a".into(),
    );
    state_eve.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
            String::new(),
        ),
        "$pl0".into(),
    );
    state_eve.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.join_rules"),
            String::new(),
        ),
        "$jr".into(),
    );
    state_eve.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@bob:x".into(),
        ),
        "$join_b".into(),
    );
    state_eve.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@charlie:x".into(),
        ),
        "$join_c".into(),
    );
    state_eve.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@eve:x".into(),
        ),
        "$eve_dn".into(),
    );

    // Fork "Zara": sees $pl2 as PL (Bob promoted Charlie), has zara's join
    let mut state_zara = imbl::OrdMap::new();
    state_zara.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "$create".into(),
    );
    state_zara.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@alice:x".into(),
        ),
        "$join_a".into(),
    );
    state_zara.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.join_rules"),
            String::new(),
        ),
        "$jr".into(),
    );
    state_zara.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@bob:x".into(),
        ),
        "$join_b".into(),
    );
    state_zara.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@charlie:x".into(),
        ),
        "$join_c".into(),
    );
    state_zara.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
            String::new(),
        ),
        "$pl2".into(),
    );
    state_zara.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@zara:x".into(),
        ),
        "$join_z".into(),
    );

    // Path A: resolve_state_maps (new library API)
    let state_maps = vec![state_eve.clone(), state_zara.clone()];
    let resolved_api =
        rezzy::resolve_state_maps(&state_maps, &events_map, rezzy::StateResVersion::V2_1);

    // Path B: manual partition + subgraph + resolve_iterative_sort (old binary path)
    let (unconflicted, conflicted_ids) =
        rezzy::partition_state_maps(state_maps.iter().map(|m| m.iter()), state_maps.len());
    let mut conflicted_events: std::collections::HashMap<String, rezzy::LeanEvent> =
        std::collections::HashMap::new();
    for id in &conflicted_ids {
        if let Some(ev) = events_map.get(id) {
            conflicted_events.insert(id.clone(), ev.clone());
        }
    }
    // Explicitly add subgraph events (what the old binary path did)
    let subgraph = rezzy::compute_v2_1_conflicted_subgraph(&events_map, &conflicted_ids);
    for (id, ev) in subgraph {
        conflicted_events.insert(id, ev);
    }
    let resolved_manual = rezzy::resolve_iterative_sort(
        unconflicted,
        conflicted_events,
        &events_map,
        rezzy::StateResVersion::V2_1,
        &mut std::collections::HashMap::new(),
    );

    // The decisive assertion: both paths must produce identical results
    assert_eq!(
        resolved_api, resolved_manual,
        "resolve_state_maps must produce the same result as manual \
         partition + subgraph + resolve_iterative_sort for MSC4297 Problem B.\n\
         API result: {resolved_api:?}\n\
         Manual result: {resolved_manual:?}"
    );

    // Sanity: PL should be resolved (not dropped)
    let pl_key = (
        rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
        String::new(),
    );
    assert!(
        resolved_api.contains_key(&pl_key),
        "MSC4297 Problem B: power_levels must be present in resolved state"
    );
}

/// Adversarial dense-bifurcation stress test for state resolution.
///
/// Generates K forks, each with D cascading power-level mutations and M
/// non-power membership events.  This is the worst case for the resolver:
///
/// - **Deep mainlines**: each fork builds a PL chain of depth D, forcing
///   `build_mainline` to walk the full chain for every non-power event.
/// - **Massive subgraph**: all K×D PL events share auth-chain ancestors,
///   creating a dense intersection that `compute_v2_1_conflicted_subgraph`
///   must BFS through in both directions.
/// - **Large conflicted set**: K×(D+M) conflicted events all need mainline
///   positioning and auth-checked.
/// - **Cascading auth**: each PL on a fork is authorized by the previous one
///   on that fork, so auth-chain expansion recurses to depth D per fork.
///
/// Asserts:
/// 1. Resolution is deterministic (two runs produce identical output).
/// 2. `resolve_state_maps` matches `resolve_iterative_sort` (parity).
/// 3. Both V2 and V2.1 produce valid state (create event present).
/// 4. V2.1 includes subgraph events that V2 might miss.
#[test]
#[allow(clippy::too_many_lines)]
fn test_performance_and_correctness_dense_bifurcations() {
    const NUM_FORKS: usize = 8; // K: number of parallel forks
    const PL_DEPTH: usize = 16; // D: PL chain depth per fork
    const MEMBERS_PER_FORK: usize = 4; // M: non-power events per fork

    // ── Bootstrap: create room with NUM_FORKS users ──
    let mut events: Vec<rezzy::LeanEvent> = Vec::new();
    let mut ts: u64 = 0;

    let users: Vec<String> = (0..NUM_FORKS).map(|i| format!("@user{i}:x")).collect();

    // Create event
    events.push(rezzy::LeanEvent {
        event_id: "$create".into(),
        event_type: "m.room.create".into(),
        state_key: Some(String::new()),
        sender: users[0].clone(),
        origin_server_ts: ts,
        content: serde_json::json!({"room_version": "12"}),
        ..Default::default()
    });
    ts += 1;

    // User 0 joins
    events.push(rezzy::LeanEvent {
        event_id: "$join_0".into(),
        event_type: "m.room.member".into(),
        state_key: Some(users[0].clone()),
        sender: users[0].clone(),
        origin_server_ts: ts,
        content: serde_json::json!({"membership": "join"}),
        auth_events: vec!["$create".into()],
        ..Default::default()
    });
    ts += 1;

    // Initial PL: user0 = 100, all others = 50 (so each fork user can
    // issue PL changes — the key ingredient for a PL war)
    let mut users_pl = serde_json::Map::new();
    for (i, u) in users.iter().enumerate() {
        users_pl.insert(u.clone(), serde_json::json!(if i == 0 { 100 } else { 50 }));
    }
    events.push(rezzy::LeanEvent {
        event_id: "$pl_root".into(),
        event_type: "m.room.power_levels".into(),
        state_key: Some(String::new()),
        sender: users[0].clone(),
        origin_server_ts: ts,
        content: serde_json::json!({"users": users_pl}),
        auth_events: vec!["$join_0".into()],
        ..Default::default()
    });
    ts += 1;

    // Join rules (public)
    events.push(rezzy::LeanEvent {
        event_id: "$jr".into(),
        event_type: "m.room.join_rules".into(),
        state_key: Some(String::new()),
        sender: users[0].clone(),
        origin_server_ts: ts,
        content: serde_json::json!({"join_rule": "public"}),
        auth_events: vec!["$join_0".into(), "$pl_root".into()],
        ..Default::default()
    });
    ts += 1;

    // All other users join
    for (i, user) in users.iter().enumerate().skip(1) {
        events.push(rezzy::LeanEvent {
            event_id: format!("$join_{i}"),
            event_type: "m.room.member".into(),
            state_key: Some(user.clone()),
            sender: user.clone(),
            origin_server_ts: ts,
            content: serde_json::json!({"membership": "join"}),
            auth_events: vec!["$pl_root".into(), "$jr".into()],
            ..Default::default()
        });
        ts += 1;
    }

    // ── Build K forks, each with D cascading PL changes ──
    // Each fork k is "owned" by user k, who issues PL changes that
    // promote/demote other users differently on each fork.
    let mut fork_state_maps: Vec<
        imbl::OrdMap<(rezzy::basespec::event_types::EventType, String), String>,
    > = Vec::new();

    for fork in 0..NUM_FORKS {
        let fork_user = &users[fork];
        let mut prev_pl_id = "$pl_root".to_string();

        for depth in 0..PL_DEPTH {
            let ev_id = format!("$pl_f{fork}_d{depth}");
            // Each level shuffles PLs: user at (fork+depth)%K gets 50+depth,
            // creating unique PL configurations per fork×depth combo
            let mut fork_users_pl = serde_json::Map::new();
            for (i, u) in users.iter().enumerate() {
                let pl = if i == fork {
                    50 // fork owner keeps 50
                } else if i == (fork + depth + 1) % NUM_FORKS {
                    // Target user gets increasing PL each level
                    #[allow(clippy::cast_possible_wrap)]
                    {
                        (50 + depth as i64).min(99)
                    }
                } else {
                    50
                };
                fork_users_pl.insert(u.clone(), serde_json::json!(pl));
            }
            // user0 always 100 (room admin)
            fork_users_pl.insert(users[0].clone(), serde_json::json!(100));

            events.push(rezzy::LeanEvent {
                event_id: ev_id.clone(),
                event_type: "m.room.power_levels".into(),
                state_key: Some(String::new()),
                sender: fork_user.clone(),
                origin_server_ts: ts,
                content: serde_json::json!({"users": fork_users_pl}),
                auth_events: vec![prev_pl_id.clone(), format!("$join_{fork}")],
                ..Default::default()
            });
            ts += 1;
            prev_pl_id = ev_id;
        }

        // Non-power events: membership display-name changes on each fork
        // These force mainline_sort to walk the full PL chain
        let extra_users: Vec<String> = (0..MEMBERS_PER_FORK)
            .map(|m| format!("@extra_f{fork}_m{m}:x"))
            .collect();

        for (m, extra_user) in extra_users.iter().enumerate() {
            // Extra user joins (authed against the fork's last PL)
            let join_id = format!("$mem_f{fork}_m{m}");
            events.push(rezzy::LeanEvent {
                event_id: join_id.clone(),
                event_type: "m.room.member".into(),
                state_key: Some(extra_user.clone()),
                sender: extra_user.clone(),
                origin_server_ts: ts,
                content: serde_json::json!({"membership": "join"}),
                auth_events: vec![prev_pl_id.clone(), "$jr".into()],
                ..Default::default()
            });
            ts += 1;
        }

        // Build state map for this fork
        let mut state = imbl::OrdMap::new();
        state.insert(
            (
                rezzy::basespec::event_types::EventType::from("m.room.create"),
                String::new(),
            ),
            "$create".into(),
        );
        state.insert(
            (
                rezzy::basespec::event_types::EventType::from("m.room.member"),
                users[0].clone(),
            ),
            "$join_0".into(),
        );
        state.insert(
            (
                rezzy::basespec::event_types::EventType::from("m.room.join_rules"),
                String::new(),
            ),
            "$jr".into(),
        );
        for (i, user) in users.iter().enumerate().skip(1) {
            state.insert(
                (
                    rezzy::basespec::event_types::EventType::from("m.room.member"),
                    user.clone(),
                ),
                format!("$join_{i}"),
            );
        }
        // Fork's final PL
        state.insert(
            (
                rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
                String::new(),
            ),
            prev_pl_id,
        );
        // Fork's extra members
        for (m, extra_user) in extra_users.iter().enumerate() {
            state.insert(
                (
                    rezzy::basespec::event_types::EventType::from("m.room.member"),
                    extra_user.clone(),
                ),
                format!("$mem_f{fork}_m{m}"),
            );
        }
        fork_state_maps.push(state);
    }

    // ── Build events map ──
    let events_map: std::collections::HashMap<String, rezzy::LeanEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();

    let total_events = events_map.len();
    let conflicted_estimate = NUM_FORKS * (PL_DEPTH + MEMBERS_PER_FORK);
    eprintln!(
        "Dense bifurcation stress: {NUM_FORKS} forks × {PL_DEPTH} PL depth × \
         {MEMBERS_PER_FORK} members = {total_events} events, ~{conflicted_estimate} conflicted"
    );

    // ── Correctness: determinism ──
    let start = std::time::Instant::now();
    let resolved_v2 =
        rezzy::resolve_state_maps(&fork_state_maps, &events_map, rezzy::StateResVersion::V2);
    let dur_v2 = start.elapsed();

    let resolved_v2_again =
        rezzy::resolve_state_maps(&fork_state_maps, &events_map, rezzy::StateResVersion::V2);
    assert_eq!(
        resolved_v2, resolved_v2_again,
        "V2 resolution must be deterministic"
    );

    // ── Correctness: V2.1 ──
    let start = std::time::Instant::now();
    let resolved_v2_1 =
        rezzy::resolve_state_maps(&fork_state_maps, &events_map, rezzy::StateResVersion::V2_1);
    let dur_v2_1 = start.elapsed();

    // Both must have create event
    let create_key = (
        rezzy::basespec::event_types::EventType::from("m.room.create"),
        String::new(),
    );
    assert!(resolved_v2.contains_key(&create_key), "V2 must have create");
    assert!(
        resolved_v2_1.contains_key(&create_key),
        "V2.1 must have create"
    );

    // Both must resolve a PL event
    let pl_key = (
        rezzy::basespec::event_types::EventType::from("m.room.power_levels"),
        String::new(),
    );
    assert!(
        resolved_v2.contains_key(&pl_key),
        "V2 must have power_levels"
    );
    assert!(
        resolved_v2_1.contains_key(&pl_key),
        "V2.1 must have power_levels"
    );

    // ── Correctness: V2.1.1 (CDO filtering) ──
    let start = std::time::Instant::now();
    let resolved_v2_1_1 = rezzy::resolve_state_maps(
        &fork_state_maps,
        &events_map,
        rezzy::StateResVersion::V2_1_1,
    );
    let dur_v2_1_1 = start.elapsed();

    assert!(
        resolved_v2_1_1.contains_key(&create_key),
        "V2.1.1 must have create"
    );
    assert!(
        resolved_v2_1_1.contains_key(&pl_key),
        "V2.1.1 must have power_levels"
    );

    let resolved_v2_1_1_again = rezzy::resolve_state_maps(
        &fork_state_maps,
        &events_map,
        rezzy::StateResVersion::V2_1_1,
    );
    assert_eq!(
        resolved_v2_1_1, resolved_v2_1_1_again,
        "V2.1.1 must be deterministic"
    );

    // ── Correctness: resolve_state_maps parity with manual path ──
    let (unconflicted, conflicted_ids) = rezzy::partition_state_maps(
        fork_state_maps.iter().map(|m| m.iter()),
        fork_state_maps.len(),
    );
    let mut conflicted_events: std::collections::HashMap<String, rezzy::LeanEvent> =
        std::collections::HashMap::new();
    for id in &conflicted_ids {
        if let Some(ev) = events_map.get(id) {
            conflicted_events.insert(id.clone(), ev.clone());
        }
    }
    let subgraph = rezzy::compute_v2_1_conflicted_subgraph(&events_map, &conflicted_ids);
    let subgraph_size = subgraph.len();
    for (id, ev) in subgraph {
        conflicted_events.entry(id).or_insert(ev);
    }
    // V2.1 parity
    let resolved_manual = rezzy::resolve_iterative_sort(
        unconflicted.clone(),
        conflicted_events.clone(),
        &events_map,
        rezzy::StateResVersion::V2_1,
        &mut std::collections::HashMap::new(),
    );
    assert_eq!(
        resolved_v2_1, resolved_manual,
        "resolve_state_maps V2.1 must match manual path"
    );
    // V2.1.1 parity
    let resolved_manual_v2_1_1 = rezzy::resolve_iterative_sort(
        unconflicted,
        conflicted_events,
        &events_map,
        rezzy::StateResVersion::V2_1_1,
        &mut std::collections::HashMap::new(),
    );
    assert_eq!(
        resolved_v2_1_1, resolved_manual_v2_1_1,
        "resolve_state_maps V2.1.1 must match manual path"
    );

    // ── Report ──
    eprintln!("  V2     resolution: {dur_v2:?}");
    eprintln!("  V2.1   resolution: {dur_v2_1:?}");
    eprintln!("  V2.1.1 resolution: {dur_v2_1_1:?}");
    eprintln!("  Conflicted IDs:    {}", conflicted_ids.len());
    eprintln!("  Subgraph events:   {subgraph_size}");
    eprintln!("  V2     state keys: {}", resolved_v2.len());
    eprintln!("  V2.1   state keys: {}", resolved_v2_1.len());
    eprintln!("  V2.1.1 state keys: {}", resolved_v2_1_1.len());

    // All versions must agree on unconflicted state
    assert_eq!(
        resolved_v2.get(&create_key),
        resolved_v2_1.get(&create_key),
        "V2 and V2.1 must agree on create event"
    );
    for user in &users {
        let key = (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            user.clone(),
        );
        assert_eq!(
            resolved_v2.get(&key),
            resolved_v2_1.get(&key),
            "V2 and V2.1 must agree on bootstrap member {user}"
        );
        assert_eq!(
            resolved_v2.get(&key),
            resolved_v2_1_1.get(&key),
            "V2 and V2.1.1 must agree on bootstrap member {user}"
        );
    }
}

#[test]
fn test_lean_event_serialize_propagates_write_error() {
    // Accumulates everything written so far and searches the whole buffer on
    // every call, rather than assuming `state_key` arrives in a single
    // `write()` call. serde_json's chunking of a `write_all`/formatter call
    // into individual `write()` calls is an implementation detail that can
    // change across versions, so the match must be robust to the needle
    // landing on either side of a call boundary.
    struct FailingWriter {
        buffered: Vec<u8>,
    }
    impl std::io::Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buffered.extend_from_slice(buf);
            if self.buffered.windows(9).any(|w| w == b"state_key") {
                return Err(std::io::Error::other("simulated I/O failure"));
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let ev = LeanEvent::<String> {
        event_id: "$test".into(),
        event_type: "m.room.message".into(),
        state_key: Some("x".into()),
        power_level: 0,
        sender: "@alice:x.com".into(),
        origin_server_ts: 1,
        content: serde_json::json!({}),
        prev_events: vec![],
        auth_events: vec![],
        depth: 1,
        rejected: false,
        soft_fail: false,
        room_id: None,
    };

    let result = serde_json::to_writer(
        FailingWriter {
            buffered: Vec::new(),
        },
        &ev,
    );
    assert!(result.is_err());
}

/// Regression coverage for conflicted-key derivation before CDO filtering.
#[test]
fn test_conflicted_keys_derived_before_cdo() {
    use rezzy::basespec::event_types::EventType;
    use rezzy::{cdo, resolve_iterative_sort_with_deltas, LeanEvent, StateResVersion};
    use std::collections::HashMap;

    let events = utils::parse_jsonl_events(
        r#"
{"event_id":"$root","type":"m.room.create","state_key":"","sender":"@alice:example.com","depth":1,"origin_server_ts":1000,"prev_events":[],"auth_events":[],"content":{"room_version":"12.1","creator":"@alice:example.com"}}
{"event_id":"$alice_join","type":"m.room.member","state_key":"@alice:example.com","sender":"@alice:example.com","depth":2,"origin_server_ts":1100,"prev_events":[],"auth_events":["$root"],"content":{"membership":"join"}}
{"event_id":"$bob_join","type":"m.room.member","state_key":"@bob:example.com","sender":"@bob:example.com","depth":2,"origin_server_ts":1200,"prev_events":[],"auth_events":["$root"],"content":{"membership":"join"}}
{"event_id":"$pl_ancestor","type":"m.room.power_levels","state_key":"","sender":"@alice:example.com","power_level":100,"depth":3,"origin_server_ts":1300,"prev_events":[],"auth_events":["$root","$alice_join"],"content":{"users":{"@bob:example.com":50},"users_default":0,"events_default":0,"state_default":50,"ban":50}}
{"event_id":"$alice_bans_bob","type":"m.room.member","state_key":"@bob:example.com","sender":"@alice:example.com","power_level":100,"depth":4,"origin_server_ts":1400,"prev_events":["$pl_ancestor"],"auth_events":["$root","$alice_join","$bob_join","$pl_ancestor"],"content":{"membership":"ban"}}
{"event_id":"$bob_pl_dominated","type":"m.room.power_levels","state_key":"","sender":"@bob:example.com","power_level":50,"depth":5,"origin_server_ts":1500,"prev_events":["$pl_ancestor"],"auth_events":["$root","$alice_join","$bob_join","$pl_ancestor"],"content":{"users":{"@bob:example.com":50}}}
{"event_id":"$jr_1","type":"m.room.join_rules","state_key":"","sender":"@alice:example.com","power_level":100,"depth":6,"origin_server_ts":1600,"prev_events":["$pl_ancestor"],"auth_events":["$root","$alice_join","$pl_ancestor"],"content":{"join_rule":"public"}}
"#,
    );

    let by_id: HashMap<String, LeanEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();

    let mut auth = HashMap::new();
    for id in ["$root", "$alice_join", "$bob_join", "$pl_ancestor"] {
        auth.insert(id.to_string(), by_id[id].clone());
    }

    let mut conflicted = HashMap::new();
    for id in ["$alice_bans_bob", "$bob_pl_dominated", "$jr_1"] {
        conflicted.insert(id.to_string(), by_id[id].clone());
    }

    // Verify CDO filter actually drops $bob_pl_dominated when $alice_bans_bob is in conflicted set
    let cdo_filtered = cdo::apply_cdo_filter(&conflicted, &auth);
    assert!(cdo_filtered.contains_key("$alice_bans_bob"));
    assert!(!cdo_filtered.contains_key("$bob_pl_dominated"));

    let unconflicted = [
        (
            (EventType::from("m.room.create"), String::new()),
            "$root".to_string(),
        ),
        (
            (
                EventType::from("m.room.member"),
                "@alice:example.com".to_string(),
            ),
            "$alice_join".to_string(),
        ),
    ]
    .into_iter()
    .collect();

    let (resolved, deltas) = resolve_iterative_sort_with_deltas(
        unconflicted,
        conflicted,
        &auth,
        StateResVersion::V2_1_1,
        &mut HashMap::new(),
    );

    // Expected resolved keys: create, alice_join, bob member (ban), join_rules, power_levels.
    let mut keys: Vec<(String, String)> = resolved
        .keys()
        .map(|k| (k.0.as_str().to_string(), k.1.clone()))
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            ("m.room.create".to_string(), String::new()),
            ("m.room.join_rules".to_string(), String::new()),
            (
                "m.room.member".to_string(),
                "@alice:example.com".to_string()
            ),
            ("m.room.member".to_string(), "@bob:example.com".to_string()),
            ("m.room.power_levels".to_string(), String::new()),
        ]
    );

    // $bob_pl_dominated (bob's power_levels) is dropped by the retained CDO
    // operator (verified above — a *correct* drop here: @alice genuinely bans
    // bob, so the dominator is auth-valid). But the live V2.1.1 path no longer
    // runs the CDO pre-filter (retired from prepare_conflicted_and_keys; see the
    // dominator-validity soundness note there). So $bob_pl_dominated is now
    // processed by resolution and correctly REJECTED on auth — a banned user's
    // power_levels cannot be applied — surfacing as a rejected delta instead of
    // being absent. It still never wins the key.
    assert!(!resolved.values().any(|v| v == "$bob_pl_dominated"));
    assert!(deltas
        .iter()
        .any(|d| d.event_id == "$bob_pl_dominated" && !d.accepted));

    // Verify deltas for accepted conflicted events
    assert!(deltas.iter().any(|d| d.event_id == "$alice_bans_bob"
        && d.accepted
        && d.key.0.as_str() == "m.room.member"
        && d.key.1 == "@bob:example.com"));
    assert!(deltas
        .iter()
        .any(|d| d.event_id == "$jr_1" && d.accepted && d.key.0.as_str() == "m.room.join_rules"));

    // Verify $alice_bans_bob won member state for @bob:example.com
    assert_eq!(
        resolved.get(&(
            EventType::from("m.room.member"),
            "@bob:example.com".to_string()
        )),
        Some(&"$alice_bans_bob".to_string())
    );

    // $bob_pl_dominated (bob's power_levels, rejected since bob is banned) never
    // wins (m.room.power_levels, ""); the ancestral $pl_ancestor (routed by
    // MSC4297) is decided in resolved state instead.
    assert_eq!(
        resolved.get(&(EventType::from("m.room.power_levels"), String::new())),
        Some(&"$pl_ancestor".to_string())
    );
}
