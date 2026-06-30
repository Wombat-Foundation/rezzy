use rezzy::auth::RoomState;
use rezzy::basespec::rezzy_types::LeanEvent;
use std::collections::HashMap;

/// Builds an initial unconflicted state map containing only the `m.room.create` event
/// extracted from the provided `auth_context`. This avoids needing a massive `auth_context`
/// fallback in the production state resolution algorithm just for test fixtures.
#[allow(dead_code)]
pub fn build_unconflicted_state_test_helper(
    auth_context: &HashMap<String, LeanEvent>,
) -> imbl::OrdMap<(String, String), String> {
    let mut unconflicted = imbl::OrdMap::new();

    // Find the create event in the auth_context
    let mut create_events = auth_context
        .values()
        .filter(|ev| ev.event_type == rezzy::basespec::event_types::M_ROOM_CREATE);
    let create_ev = create_events
        .next()
        .expect("fixture auth_context must contain exactly one m.room.create event");
    assert!(
        create_events.next().is_none(),
        "fixture auth_context must contain exactly one m.room.create event",
    );

    unconflicted.insert(
        (
            create_ev.event_type.clone(),
            create_ev
                .state_key
                .clone()
                .expect("create must have state_key"),
        ),
        create_ev.event_id.clone(),
    );

    unconflicted
}

/// Parses a multiline JSONL string into a vector of `LeanEvents`.
/// Blank lines and lines starting with "//" are ignored.
#[allow(dead_code)]
pub fn parse_jsonl_events(input: &str) -> Vec<LeanEvent> {
    let mut events = Vec::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line).expect("Invalid JSONL line");

        let event_id = value
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let event_type = value
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let state_key = value
            .get("state_key")
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string);
        let sender = value
            .get("sender")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let content = value
            .get("content")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        events.push(LeanEvent {
            event_id,
            event_type,
            state_key,
            power_level: value
                .get("power_level")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            origin_server_ts: value
                .get("origin_server_ts")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            sender,
            content,
            prev_events: value
                .get("prev_events")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            auth_events: value
                .get("auth_events")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            depth: value
                .get("depth")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        });
    }
    events
}

/// Parses a multiline JSONL string directly into a `RoomState`.
#[allow(dead_code)]
pub fn parse_jsonl_state(input: &str) -> RoomState {
    let mut state = RoomState::new();
    let events = parse_jsonl_events(input);
    for event in events {
        if let Some(sk) = &event.state_key {
            state.insert((event.event_type.clone(), sk.clone()), event);
        }
    }
    state
}

/// A debug utility: computes a SHA-256 content hash of a raw JSON event string
/// after stripping `event_id`, `unsigned`, and `signatures`. This is an
/// approximation of the Matrix V3+ reference hash — it does NOT perform the
/// full spec-mandated redaction step, so the output may differ from a real
/// event ID for events with non-allowed content keys.
/// TODO: Full redaction compliance across room versions.
#[cfg(feature = "hashing")]
#[allow(dead_code)]
pub fn print_canonical_hash(json_str: &str) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};

    fn sort_keys(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                let mut sorted = std::collections::BTreeMap::new();
                for (k, mut v) in core::mem::take(map) {
                    sort_keys(&mut v);
                    sorted.insert(k, v);
                }
                for (k, v) in sorted {
                    map.insert(k, v);
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    sort_keys(v);
                }
            }
            _ => {}
        }
    }

    let mut value: serde_json::Value = serde_json::from_str(json_str).expect("Invalid JSON");
    if let Some(obj) = value.as_object_mut() {
        obj.remove("event_id");
        obj.remove("unsigned");
        obj.remove("signatures");
    }

    sort_keys(&mut value);
    let canonical = serde_json::to_string(&value).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();

    std::println!("=== CANONICAL HASH DEBUG ===");
    std::println!("Canonical JSON: {canonical}");
    let encoded_hash = URL_SAFE_NO_PAD.encode(hash);
    std::println!("Computed Event ID: ${encoded_hash}");
    std::println!("============================");
}

/// Asserts that a given `RoomState` exactly matches the state defined in a JSONL string.
#[allow(dead_code)]
pub fn assert_jsonl_state_eq(actual: &RoomState, expected_jsonl: &str) {
    let expected = parse_jsonl_state(expected_jsonl);

    // First, assert the lengths are the same
    assert_eq!(
        actual.len(),
        expected.len(),
        "State lengths differ. Expected {}, got {}",
        expected.len(),
        actual.len()
    );

    // Then, assert each element matches precisely
    for (key, expected_event) in &expected {
        let actual_event = actual.get(key).unwrap_or_else(|| {
            panic!("Actual state missing expected event at key {key:?}");
        });

        assert_eq!(
            actual_event, expected_event,
            "Event mismatch at key {key:?}"
        );
    }
}

/// Asserts that a given slice of `LeanEvents` exactly matches the events defined in a JSONL string.
#[allow(dead_code)]
pub fn assert_jsonl_events_eq(actual: &[LeanEvent], expected_jsonl: &str) {
    let expected = parse_jsonl_events(expected_jsonl);

    // First, assert the lengths are the same
    assert_eq!(
        actual.len(),
        expected.len(),
        "Events lengths differ. Expected {}, got {}",
        expected.len(),
        actual.len()
    );

    // Then, assert each element matches precisely
    for (i, (actual_event, expected_event)) in actual.iter().zip(expected.iter()).enumerate() {
        assert_eq!(actual_event, expected_event, "Event mismatch at index {i}");
    }
}

/// Computes and assigns the topological depth for a set of events based on their `prev_events`.
/// The depth of an event is 1 if it has no `prev_events`, or 1 greater than the maximum depth
/// of its `prev_events` otherwise.
#[allow(dead_code)]
pub fn compute_local_naive_topological_depth(events: &mut [LeanEvent]) {
    let mut event_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (i, ev) in events.iter().enumerate() {
        event_map.insert(ev.event_id.clone(), i);
    }

    let mut depths: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

    fn get_depth(
        event_id: &str,
        event_map: &std::collections::HashMap<String, usize>,
        events: &[LeanEvent],
        depths: &mut std::collections::HashMap<String, u64>,
    ) -> u64 {
        if let Some(&d) = depths.get(event_id) {
            return d;
        }

        let idx = match event_map.get(event_id) {
            Some(&i) => i,
            None => return 1, // Unknown prev_event, assume depth 1
        };

        let ev = &events[idx];
        if ev.prev_events.is_empty() {
            depths.insert(event_id.to_string(), 1);
            return 1;
        }

        let mut max_prev_depth = 0;
        for prev_id in &ev.prev_events {
            max_prev_depth = max_prev_depth.max(get_depth(prev_id, event_map, events, depths));
        }

        let d = max_prev_depth + 1;
        depths.insert(event_id.to_string(), d);
        d
    }

    for i in 0..events.len() {
        let ev_id = events[i].event_id.clone();
        events[i].depth = get_depth(&ev_id, &event_map, events, &mut depths);
    }
}
