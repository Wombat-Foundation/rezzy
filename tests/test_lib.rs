extern crate alloc;

#[cfg(test)]
#[allow(clippy::too_many_lines, clippy::type_complexity, clippy::similar_names)]
mod tests {

    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    use alloc::vec;
    use core::cmp::Ordering;
    use ruma_lean::*;

    #[cfg(not(feature = "std"))]
    use hashbrown::HashMap;
    #[cfg(feature = "std")]
    use std::collections::HashMap;

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
    fn test_sort_priority_v2_tie_break() {
        let e_base = LeanEvent {
            event_id: "$1".into(),
            power_level: 100,
            origin_server_ts: 10,
            ..Default::default()
        };
        let e_worst_pl = LeanEvent {
            event_id: "$2".into(),
            power_level: 50,
            origin_server_ts: 10,
            ..Default::default()
        };
        let p_base = SortPriority {
            power_level: e_base.power_level,
            event: &e_base,
            auth_chain_distance: 0,
            version: StateResVersion::V2,
        };
        let p_worst_pl = SortPriority {
            power_level: e_worst_pl.power_level,
            event: &e_worst_pl,
            auth_chain_distance: 0,
            version: StateResVersion::V2,
        };

        // Higher PL is GREATER (pops first, loses for same key, but sets auth context first).
        assert_eq!(p_base.cmp(&p_worst_pl), Ordering::Greater); // p_base 100 > p_worst_pl 50.

        let e_later_ts = LeanEvent {
            event_id: "$3".into(),
            power_level: 100,
            origin_server_ts: 20,
            ..Default::default()
        };
        let p_later_ts = SortPriority {
            power_level: e_later_ts.power_level,
            event: &e_later_ts,
            auth_chain_distance: 0,
            version: StateResVersion::V2,
        };
        // p_later_ts has ts 20 (better — wins); later ts pops LAST = is Smaller.
        // p_base has ts 10 (worse) = Greater (pops first, loses).
        assert_eq!(p_base.cmp(&p_later_ts), Ordering::Greater);

        let e_larger_id = LeanEvent {
            event_id: "$2".into(),
            power_level: 100,
            origin_server_ts: 10,
            ..Default::default()
        };
        let p_larger_id = SortPriority {
            power_level: e_larger_id.power_level,
            event: &e_larger_id,
            auth_chain_distance: 0,
            version: StateResVersion::V2,
        };
        // p_larger_id has id "$2" (better — wins); larger id pops LAST = is Smaller.
        // p_base has id "$1" (worse) = Greater (pops first, loses).
        assert_eq!(p_base.cmp(&p_larger_id), Ordering::Greater);
    }

    #[test]
    fn test_v1_resolution_happy_path() {
        let mut events = HashMap::new();
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
        let sorted = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V1,
        );
        assert_eq!(sorted, vec!["A", "B"]);
    }

    #[test]
    fn test_v2_1_strict_resolution() {
        let mut unconflicted = BTreeMap::new();
        unconflicted.insert(
            ("m.room.member".into(), Some("@alice:example.com".into())),
            "A".into(),
        );

        let mut conflicted = HashMap::new();
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
        let resolved = resolve_lean(
            unconflicted,
            conflicted.clone(),
            &conflicted,
            StateResVersion::V2_1,
        );
        assert_eq!(
            resolved.get(&("m.room.member".into(), Some("@alice:example.com".into()))),
            Some(&"A".into())
        );
    }

    #[test]
    fn test_v1_tie_break_by_id() {
        let mut events = HashMap::new();
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
        let sorted = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V1,
        );
        assert_eq!(sorted, vec!["B", "A"]);
    }

    #[test]
    fn test_v2_resolution_happy_path() {
        let mut events = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec![],
                auth_events: vec![],
                depth: 10,
                ..Default::default()
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 50,
                origin_server_ts: 10,
                prev_events: vec![],
                auth_events: vec![],
                depth: 1,
                ..Default::default()
            },
        );
        let sorted = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
        );
        // A (higher PL=100) pops first (applied first, loses for same key). B pops last, wins.
        assert_eq!(sorted, vec!["A", "B"]);
    }

    #[test]
    fn test_v2_deep_tie_break() {
        let mut events = HashMap::new();
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
        let sorted = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
        );
        // Best (B, larger ID) comes LAST.
        assert_eq!(sorted, vec!["A", "B"]);
    }

    #[test]
    fn test_v1_v2_v2_1_comparison_determinism() {
        let mut events = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.member".into(),
                state_key: Some("@alice:example.com".into()),
                power_level: 10,
                origin_server_ts: 10,
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
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec![],
                auth_events: vec![],
                depth: 10,
                ..Default::default()
            },
        );
        let sorted_v1 = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V1,
        );
        let sorted_v2 = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
        );
        let sorted_v2_1 = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2_1,
        );
        assert_eq!(sorted_v1, vec!["B", "A"]);
        // B (higher power level) pops FIRST in V2 and V2.1 — applied first, loses for same key.
        assert_eq!(sorted_v2, vec!["B", "A"]);
        assert_eq!(sorted_v2_1, vec!["B", "A"]);
    }

    #[test]
    fn test_unhappy_path_cycle_detection() {
        let mut events = HashMap::new();
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
        let sorted = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
        );
        assert!(sorted.is_empty());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let event = LeanEvent {
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
    fn test_partial_ord_implementations() {
        let e1 = LeanEvent {
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
        let e2 = LeanEvent {
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
            auth_chain_distance: 0,
            version: StateResVersion::V2,
        };
        let p2 = SortPriority {
            power_level: e2.power_level,
            event: &e2,
            auth_chain_distance: 0,
            version: StateResVersion::V2,
        };
        assert!(p1.partial_cmp(&p2).is_some());
    }

    #[test]
    fn test_trait_coverage() {
        let v = StateResVersion::V2;
        assert_eq!(v, StateResVersion::V2);
        let _ = alloc::format!("{v:?}");

        let e = LeanEvent {
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
        let _ = alloc::format!("{e:?}");
    }

    #[test]
    fn test_complex_dag_sort() {
        let mut events = HashMap::new();
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
        let sorted_ids = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
        );
        // 1 pops first (only one with in-degree 0).
        // Then 2 and 3 are in queue. 3 has earlier TS (15, worse) so it pops FIRST.
        // Then 2 (TS 20, better — later wins) pops LAST.
        // Then 4 pops.
        assert_eq!(sorted_ids, vec!["1", "3", "2", "4"]);
    }

    #[test]
    fn test_kahn_missing_parents() {
        let mut events = HashMap::new();
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
        let sorted = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
        );
        assert_eq!(sorted, vec!["A"]);
    }

    #[test]
    fn test_resolve_lean_functionality() {
        let mut unconflicted = BTreeMap::new();
        unconflicted.insert(("type".into(), Some("key".into())), "id".into());
        let conflicted = HashMap::new();
        let resolved = resolve_lean(
            unconflicted.clone(),
            conflicted.clone(),
            &conflicted,
            StateResVersion::V2,
        );
        assert_eq!(resolved, unconflicted);
    }

    #[test]
    fn test_resolve_lean_v2_1_overlay() {
        use serde_json::json;

        // Uncontested state: Alice is already joined, Bob's old event is the prior state.
        let mut unconflicted = BTreeMap::new();
        unconflicted.insert(
            ("m.room.member".into(), Some("@alice:example.com".into())),
            "id1".into(),
        );
        unconflicted.insert(
            ("m.room.member".into(), Some("@bob:example.com".into())),
            "id2".into(),
        );

        // Auth context: uncontested background events needed to validate the conflicted ones.
        let mut auth_context = HashMap::new();
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

        // The conflict: two competing versions of Bob's membership.
        let mut conflicted = HashMap::new();
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
                auth_events: vec!["create".into(), "join_rules".into(), "id1".into()],
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
                auth_events: vec!["create".into(), "join_rules".into(), "id1".into()],
                ..Default::default()
            },
        );

        let resolved = resolve_lean(
            unconflicted.clone(),
            conflicted,
            &auth_context,
            StateResVersion::V2_1,
        );

        assert_eq!(
            resolved.get(&("m.room.member".into(), Some("@alice:example.com".into()))),
            Some(&"id1".into())
        );
        assert_eq!(
            resolved.get(&("m.room.member".into(), Some("@bob:example.com".into()))),
            Some(&"id2".into()) // id2_new (PL=100) pops first, id2 (PL=50) pops last and wins.
        );
    }

    fn run_batch_test(
        version: StateResVersion,
        rows: &[(&str, i64, u64, u64, &[&str])],
        expected: &[&str],
    ) {
        let mut events = HashMap::new();
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
                    prev_events: r.4.iter().map(alloc::string::ToString::to_string).collect(),
                    auth_events: r.4.iter().map(alloc::string::ToString::to_string).collect(),
                    ..Default::default()
                },
            );
        }
        let result = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            version,
        );
        assert_eq!(
            result,
            expected
                .iter()
                .map(alloc::string::ToString::to_string)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_resolution_batch() {
        run_batch_test(
            StateResVersion::V2,
            &[("Alice", 100, 500, 1, &[]), ("Bob", 50, 100, 1, &[])],
            &["Alice", "Bob"], // Alice is better (PL 100), pops first.
        );
        run_batch_test(
            StateResVersion::V1,
            &[("Deep", 100, 100, 10, &[]), ("Shallow", 10, 100, 1, &[])],
            &["Deep", "Shallow"],
        );
    }

    #[test]
    fn test_native_resolution_bootstrap_parity() {
        let mut events = HashMap::new();
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
        let sorted = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
        );
        let mut resolved_state = BTreeMap::new();
        for id in sorted {
            let ev = events.get(&id).unwrap();
            let key = (ev.event_type.clone(), ev.state_key.clone());
            resolved_state.insert(key, ev.event_id.clone());
        }
        assert_eq!(
            resolved_state.get(&(
                "m.room.member".to_string(),
                Some("@user:example.com".to_string())
            )),
            Some(&"2".to_string())
        );
    }

    #[test]
    fn test_enum_coverage() {
        let v = StateResVersion::V2;
        let v2 = v;
        assert_eq!(v, v2);
        let debug_str = alloc::format!("{v:?}");
        assert!(debug_str.contains("V2"));
    }

    #[test]
    fn test_event_traits_coverage() {
        let e = LeanEvent {
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
        let debug_str = alloc::format!("{e:?}");
        assert!(debug_str.contains("event_id"));
    }

    #[test]
    fn test_sort_priority_traits() {
        let e = LeanEvent {
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
            auth_chain_distance: 0,
            version: StateResVersion::V2,
        };
        let p2 = p;
        assert_eq!(p, p2);
        let debug_str = alloc::format!("{p:?}");
        assert!(debug_str.contains("version"));
    }

    #[test]
    fn test_v1_equal_depth_tie_break() {
        let mut events = HashMap::new();
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
        let sorted = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V1,
        );
        assert_eq!(sorted, vec!["B", "A"]);
    }

    #[test]
    fn test_kahn_no_neighbors() {
        let mut events = HashMap::new();
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
        let sorted = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
        );
        assert_eq!(sorted, vec!["1"]);
    }

    #[test]
    fn test_v2_1_full_coverage() {
        let mut events = HashMap::new();
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
        let sorted = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2_1,
        );
        assert_eq!(sorted, vec!["A"]);
    }

    /// Regression test: `V2_1` uses the same "later timestamp wins" tie-break as V2.
    /// Earlier events are sorted first (popped first from heap), later events
    /// come last and win via last-write-wins. This matches the Matrix spec.
    #[test]
    fn test_v2_1_later_timestamp_wins() {
        let mut events = HashMap::new();
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
        let sorted = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2_1,
        );
        assert_eq!(sorted, vec!["$early", "$late"]);

        // V2 must match V2_1
        let sorted_v2 = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
        );
        assert_eq!(sorted_v2, vec!["$early", "$late"]);
    }

    /// Regression test: millisecond-close Draupnir ban races resolve identically
    /// in V2 and `V2_1` when processed through Kahn sort alone.
    #[test]
    fn test_v2_1_millisecond_race_tiebreak() {
        let mut events = HashMap::new();
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
        let sorted_v2 = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
        );
        assert_eq!(sorted_v2, vec!["$ban_a", "$ban_b"]);

        let sorted_v2_1 = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2_1,
        );
        assert_eq!(sorted_v2_1, vec!["$ban_a", "$ban_b"]);
    }

    #[test]
    fn test_total_order_properties() {
        let e1 = LeanEvent {
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
        let e2 = LeanEvent {
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
        let e3 = LeanEvent {
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
        let e_base = LeanEvent {
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
            auth_chain_distance: 0,
            version: StateResVersion::V2,
        };
        let e_high_power = LeanEvent {
            power_level: 100,
            ..e_base.clone()
        };
        let p_high_power = SortPriority {
            power_level: e_high_power.power_level,
            event: &e_high_power,
            auth_chain_distance: 0,
            version: StateResVersion::V2,
        };
        // p_base is WORSE (PL 50 < 100). Higher PL is Greater (pops first). So p_base < p_high_power.
        assert_eq!(p_base.cmp(&p_high_power), Ordering::Less);
        let e_best = LeanEvent {
            origin_server_ts: 100,
            ..e_base.clone()
        };
        let p_best = SortPriority {
            power_level: e_best.power_level,
            event: &e_best,
            auth_chain_distance: 0,
            version: StateResVersion::V2,
        };
        // p_best has TS 100 (better: later wins). Better must be Smaller (pops last).
        // So p_base > p_best.
        assert_eq!(p_base.cmp(&p_best), Ordering::Greater);
        let e_early_id = LeanEvent {
            event_id: "a".into(),
            ..e_base.clone()
        };
        let p_early_id = SortPriority {
            power_level: e_early_id.power_level,
            event: &e_early_id,
            auth_chain_distance: 0,
            version: StateResVersion::V2,
        };
        // p_base has ID "m" (better — larger id wins). Better must be Smaller (pops last). So p_base < p_early_id.
        assert_eq!(p_base.cmp(&p_early_id), Ordering::Less);
        let p_v1_base = SortPriority {
            power_level: e_base.power_level,
            event: &e_base,
            auth_chain_distance: 0,
            version: StateResVersion::V1,
        };
        let e_shallow = LeanEvent {
            depth: 1,
            ..e_base.clone()
        };
        let p_shallow = SortPriority {
            power_level: e_shallow.power_level,
            event: &e_shallow,
            auth_chain_distance: 0,
            version: StateResVersion::V1,
        };
        // V1: shallow depth (1) is better. Better must be Smaller (pops last). So p_v1_base > p_shallow.
        assert_eq!(p_v1_base.cmp(&p_shallow), Ordering::Greater);
        let p_v1_early_id = SortPriority {
            power_level: e_early_id.power_level,
            event: &e_early_id,
            auth_chain_distance: 0,
            version: StateResVersion::V1,
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
        let mut events = HashMap::new();
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
        let result = lean_kahn_sort_detailed(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
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
        let mut events = HashMap::new();
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
        let result = lean_kahn_sort_detailed(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
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
        let ok = KahnSortResult::Ok(vec!["A".into()]);
        assert!(ok.is_ok());
        assert_eq!(ok.into_sorted(), vec!["A"]);

        let cycle = KahnSortResult::CycleDetected {
            sorted: vec!["C".into()],
            stuck: vec!["A".into(), "B".into()],
        };
        assert!(!cycle.is_ok());
        assert!(cycle.into_sorted().is_empty());
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
        let ev: LeanEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.power_level, 100);
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
        let mut events = HashMap::new();
        for i in 0..1000u32 {
            let id = alloc::format!("ev_{i}");
            let auth = if i > 0 {
                vec![alloc::format!("ev_{}", i - 1)]
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
        let sorted = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
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
        let mut graph = HashMap::new();
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
                    auth_events: auths
                        .iter()
                        .map(alloc::string::ToString::to_string)
                        .collect(),
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
        let mut graph = HashMap::new();
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

    fn default_test_event(id: &str, pl: i64, ts: u64, auth: Vec<&str>) -> LeanEvent {
        LeanEvent {
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

        let mut auth_context = HashMap::new();
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

        let ev_old = auth_context.get("$msg-old").unwrap();
        let ev_new = auth_context.get("$msg-new").unwrap();
        let ev_no_pl = auth_context.get("$msg-no-pl").unwrap();

        let mut events_to_sort = vec![ev_old, ev_new, ev_no_pl];

        mainline_sort(&mut events_to_sort, &mainline, &auth_context);

        let sorted_ids: Vec<String> = events_to_sort.iter().map(|e| e.event_id.clone()).collect();
        // Per spec, an event with i = ∞ (no mainline ancestor) sorts before all
        // chain-rooted events under "x < y if x.position is greater than y's".
        assert_eq!(sorted_ids, vec!["$msg-no-pl", "$msg-old", "$msg-new"]);
    }

    #[test]
    fn test_reverse_topological_power_sort() {
        let mut events = HashMap::new();
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

        let sorted_ids = lean_kahn_sort(
            &events,
            &events,
            events.values().find(|ev| ev.event_type == "m.room.create"),
            StateResVersion::V2,
        );
        // All events have same PL=0 and ts=0, so tie-break is by event_id.
        // Smaller id pops first (loses). Sorted: $o (root), then $l < $n < $p in id order,
        // $m waits for $n. After $n pops, $m becomes eligible and beats $p ("m" > "p"? no:
        // "$m" < "$p" → $m pops first). So order: [$o, $l, $n, $m, $p].
        assert_eq!(sorted_ids, vec!["$o", "$l", "$n", "$m", "$p"]);
    }

    #[test]
    fn test_cdo_causal_domination_filter() {
        use serde_json::json;

        let mut conflicted = HashMap::new();
        let mut auth = HashMap::new();

        let root = LeanEvent {
            event_id: "$root".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            origin_server_ts: 1000,
            ..Default::default()
        };
        auth.insert(root.event_id.clone(), root.clone());

        let alice_join = LeanEvent {
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

        let bob_join = LeanEvent {
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
        let alice_bans_bob = LeanEvent {
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

        let bob_name_change = LeanEvent {
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

        // In StateResVersion::V2_2, Bob's name change is causally dominated by Alice's ban and filtered out.
        let filtered = apply_cdo_filter(&conflicted, &auth);

        assert!(filtered.contains_key("$alice_bans_bob"));
        assert!(!filtered.contains_key("$bob_name_change"));
    }

    #[test]
    fn test_anomaly_06b_mod_membership_evaporation() {
        use serde_json::json;

        let mut conflicted = HashMap::new();
        let mut auth = HashMap::new();

        let root = LeanEvent {
            event_id: "$root".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            origin_server_ts: 1000,
            ..Default::default()
        };
        auth.insert(root.event_id.clone(), root.clone());

        let alice_join = LeanEvent {
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

        let jr_pub = LeanEvent {
            event_id: "$jr_pub".into(),
            event_type: "m.room.join_rules".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            origin_server_ts: 1150,
            prev_events: vec!["$alice_join".into()],
            auth_events: vec!["$root".into(), "$alice_join".into()],
            content: json!({ "join_rule": "public" }),
            ..Default::default()
        };
        auth.insert(jr_pub.event_id.clone(), jr_pub.clone());

        let pl_init = LeanEvent {
            event_id: "$pl_init".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            origin_server_ts: 1200,
            prev_events: vec!["$jr_pub".into()],
            auth_events: vec!["$root".into(), "$alice_join".into(), "$jr_pub".into()],
            content: json!({ "users": { "@alice:example.com": 100 } }),
            ..Default::default()
        };
        auth.insert(pl_init.event_id.clone(), pl_init.clone());

        // Fork A: Lockdown to invite
        let rules_invite = LeanEvent {
            event_id: "$rules_invite".into(),
            event_type: "m.room.join_rules".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            origin_server_ts: 1300,
            prev_events: vec!["$pl_init".into()],
            auth_events: vec!["$root".into(), "$alice_join".into(), "$pl_init".into()],
            content: json!({ "join_rule": "invite" }),
            ..Default::default()
        };
        conflicted.insert(rules_invite.event_id.clone(), rules_invite.clone());

        // Fork B: Nexy's actions (dependent on public join rules)
        let nexy_join = LeanEvent {
            event_id: "$nexy_join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@nexy:example.com".into()),
            sender: "@nexy:example.com".into(),
            origin_server_ts: 1310,
            prev_events: vec!["$pl_init".into()],
            auth_events: vec![
                "$root".into(),
                "$alice_join".into(),
                "$jr_pub".into(),
                "$pl_init".into(),
            ],
            content: json!({ "membership": "join" }),
            ..Default::default()
        };
        conflicted.insert(nexy_join.event_id.clone(), nexy_join.clone());

        let nexy_promo = LeanEvent {
            event_id: "$nexy_promo".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@alice:example.com".into(),
            origin_server_ts: 1320,
            prev_events: vec!["$nexy_join".into()],
            auth_events: vec![
                "$root".into(),
                "$alice_join".into(),
                "$nexy_join".into(),
                "$pl_init".into(),
            ],
            content: json!({ "users": { "@alice:example.com": 100, "@nexy:example.com": 50 } }),
            ..Default::default()
        };
        conflicted.insert(nexy_promo.event_id.clone(), nexy_promo.clone());

        let nexy_bans_spammer = LeanEvent {
            event_id: "$nexy_bans_spammer".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@spammer:example.com".into()),
            sender: "@nexy:example.com".into(),
            origin_server_ts: 1330,
            prev_events: vec!["$nexy_promo".into()],
            auth_events: vec![
                "$root".into(),
                "$alice_join".into(),
                "$nexy_join".into(),
                "$nexy_promo".into(),
            ],
            content: json!({ "membership": "ban" }),
            ..Default::default()
        };
        conflicted.insert(
            nexy_bans_spammer.event_id.clone(),
            nexy_bans_spammer.clone(),
        );

        // Under v2.1.1, apply_cdo_filter is executed.
        // 1. $rules_invite (invite lockdown) is concurrent with $nexy_join, and restricts joins, dropping $nexy_join.
        // 2. $nexy_promo requires $nexy_join in its auth_events. Since $nexy_join was dropped, $nexy_promo is dropped transitively.
        // 3. $nexy_bans_spammer requires $nexy_promo. Since $nexy_promo was dropped, it is dropped transitively.
        let filtered = apply_cdo_filter(&conflicted, &auth);

        assert!(filtered.contains_key("$rules_invite"));
        assert!(
            !filtered.contains_key("$nexy_join"),
            "Nexy's join must be dropped by direct invite lockdown"
        );
        assert!(
            !filtered.contains_key("$nexy_promo"),
            "Nexy's promotion must be dropped by auth transitive closure"
        );
        assert!(
            !filtered.contains_key("$nexy_bans_spammer"),
            "Nexy's ban on spammer must be dropped by auth transitive closure cascade"
        );
    }
}
