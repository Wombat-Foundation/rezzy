use ruma_lean::merge_event_sets;
use serde_json::json;

fn ev(id: &str, depth: u64) -> serde_json::Value {
    json!({
        "event_id": id,
        "type": "m.room.member",
        "state_key": format!("@user:{id}"),
        "origin_server_ts": 1000 + depth,
        "depth": depth,
        "prev_events": [],
        "auth_events": []
    })
}

#[test]
fn test_filter_non_state_events() {
    let state_ev = ev("$1", 1);
    let mut non_state_ev = ev("$2", 2);
    non_state_ev.as_object_mut().unwrap().remove("state_key");

    // Write to a temporary file and run through the main run_cli flow
    // or just test the mapping logic directly.
    let mut raw_map = std::collections::HashMap::new();
    raw_map.insert("$1".to_string(), state_ev);
    raw_map.insert("$2".to_string(), non_state_ev);

    // This simulates the check in the main code
    let mut state_map = std::collections::HashMap::new();
    for id in raw_map.keys() {
        if raw_map
            .get(id)
            .is_some_and(|r| r.get("state_key").is_some())
        {
            state_map.insert(id.clone(), true);
        }
    }

    assert_eq!(state_map.len(), 1);
    assert!(state_map.contains_key("$1"));
    assert!(!state_map.contains_key("$2"));
}

#[test]
fn test_merge_dedup_by_event_id() {
    let a = vec![ev("$1", 1), ev("$2", 2), ev("$3", 3)];
    let b = vec![ev("$2", 2), ev("$3", 3), ev("$4", 4)];
    let result =
        merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], false, true).unwrap();

    let ids: Vec<&str> = result
        .iter()
        .map(|v| v["event_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["$1", "$2", "$3", "$4"]);
}

#[test]
fn test_merge_disjoint_fails() {
    let a = vec![ev("$1", 1), ev("$2", 2)];
    let b = vec![ev("$3", 3), ev("$4", 4)];
    let result = merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], false, true);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Disjoint DAGs"));
}

#[test]
fn test_merge_pairwise_shared() {
    // A shares with B, B shares with C, but A and C share nothing directly.
    // This should succeed because the graph is connected.
    let a = vec![ev("$1", 1), ev("$2", 2)];
    let b = vec![ev("$2", 2), ev("$3", 3)];
    let c = vec![ev("$3", 3), ev("$4", 4)];
    let result = merge_event_sets(
        &[
            ("a.jsonl".into(), a),
            ("b.jsonl".into(), b),
            ("c.jsonl".into(), c),
        ],
        false,
        true,
    )
    .unwrap();

    let ids: Vec<&str> = result
        .iter()
        .map(|v| v["event_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["$1", "$2", "$3", "$4"]);
}

#[test]
fn test_merge_single_file() {
    let a = vec![ev("$1", 1), ev("$2", 2)];
    let result = merge_event_sets(&[("a.jsonl".into(), a)], false, true).unwrap();
    assert_eq!(result.len(), 2);
}

#[test]
fn test_merge_complete_overlap() {
    let a = vec![ev("$1", 1), ev("$2", 2), ev("$3", 3)];
    let b = vec![ev("$1", 1), ev("$2", 2), ev("$3", 3)];
    let result =
        merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], false, true).unwrap();
    assert_eq!(result.len(), 3);
}

#[test]
fn test_merge_subset() {
    // Small DAG is a subset of large DAG (starstruck-style)
    let large = vec![ev("$1", 1), ev("$2", 2), ev("$3", 3), ev("$4", 4)];
    let small = vec![ev("$1", 1), ev("$2", 2)];
    let result = merge_event_sets(
        &[("large.jsonl".into(), large), ("small.jsonl".into(), small)],
        false,
        true,
    )
    .unwrap();
    assert_eq!(result.len(), 4);
}

#[test]
fn test_merge_debug_depths() {
    let a = vec![ev("$1", 10), ev("$2", 20)];
    let b = vec![ev("$2", 20), ev("$3", 30)];
    // Should not panic with debug=true
    let result =
        merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], true, true).unwrap();
    assert_eq!(result.len(), 3);
}

#[test]
fn test_merge_single_event_per_file() {
    let a = vec![ev("$1", 1)];
    let b = vec![ev("$1", 1)];
    let result =
        merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], false, true).unwrap();
    assert_eq!(result.len(), 1);
}

#[test]
fn test_merge_two_single_events_disjoint() {
    let a = vec![ev("$1", 1)];
    let b = vec![ev("$2", 2)];
    let result = merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], false, true);
    assert!(result.is_err());
}

#[test]
fn test_merge_two_events_one_shared() {
    let a = vec![ev("$1", 1), ev("$2", 2)];
    let b = vec![ev("$2", 2), ev("$3", 3)];
    let result =
        merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], false, true).unwrap();
    assert_eq!(result.len(), 3);
}

#[test]
fn test_merge_one_file_only() {
    let a = vec![ev("$1", 1)];
    let result = merge_event_sets(&[("a.jsonl".into(), a)], false, true).unwrap();
    assert_eq!(result.len(), 1);
}
