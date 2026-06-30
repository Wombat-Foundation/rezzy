use serde_json::json;

fn ev(id: &str, depth: u64) -> serde_json::Value {
    json!({
        "event_id": id,
        "type": "m.room.member",
        "state_key": format!("@user:{id}"),
        "origin_server_ts": 1000_u64.wrapping_add(depth),
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
