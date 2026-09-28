use rezzy::basespec::rezzy_types::LeanEvent;
use rezzy::basespec::rezzy_types::RoomId;
use std::collections::HashMap;

/// Builds an initial unconflicted state map containing only the `m.room.create` event
/// extracted from the provided `auth_context`. This avoids needing a massive `auth_context`
/// fallback in the production state resolution algorithm just for test fixtures.
pub fn build_unconflicted_state_test_helper(
    auth_context: &HashMap<String, LeanEvent>,
) -> imbl::OrdMap<(rezzy::basespec::event_types::EventType, String), String> {
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
            rezzy::basespec::event_types::EventType::from(create_ev.event_type.as_str()),
            create_ev
                .state_key
                .clone()
                .expect("create must have state_key"),
        ),
        create_ev.event_id.clone(),
    );

    unconflicted
}

/// Parses a multiline JSONL string into a vector of [`LeanEvent`]s.
/// Blank lines and lines starting with "//" are ignored.
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
            .expect("JSONL event must contain string 'event_id'")
            .to_string();
        let event_type = value
            .get("type")
            .and_then(|v| v.as_str())
            .expect("JSONL event must contain string 'type'")
            .to_string();
        let state_key = value
            .get("state_key")
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string);
        let sender = value
            .get("sender")
            .and_then(|v| v.as_str())
            .expect("JSONL event must contain string 'sender'")
            .to_string();
        let content = value
            .get("content")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        let rejected = value
            .get("__rejected")
            .or_else(|| value.get("rejected"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let soft_fail = value
            .get("__soft_fail")
            .or_else(|| value.get("soft_fail"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        events.push(LeanEvent {
            rejected,
            soft_fail,
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
            room_id: value
                .get("room_id")
                .and_then(serde_json::Value::as_str)
                .map(RoomId::from),
        });
    }
    events
}

/// Loads a JSONL fixture file and returns events as a `HashMap` keyed by `event_id`.
#[allow(dead_code)]
pub fn load_jsonl_fixture(path: &str) -> HashMap<String, LeanEvent> {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {path}: {e}"));
    parse_jsonl_events(&content)
        .into_iter()
        .map(|ev| (ev.event_id.clone(), ev))
        .collect()
}

/// A debug utility: computes a SHA-256 content hash of a raw JSON event string
/// after stripping `event_id`, `unsigned`, and `signatures`. This is an
/// approximation of the Matrix V3+ reference hash — it does NOT perform the
/// full spec-mandated redaction step, so the output may differ from a real
/// event ID for events with non-allowed content keys.
/// TODO: Full redaction compliance across room versions.
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
