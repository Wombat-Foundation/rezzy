use rezzy::basespec::rezzy_types::LeanEvent;
use std::collections::HashMap;

/// Builds an initial unconflicted state map containing only the `m.room.create` event
/// extracted from the provided `auth_context`. This avoids needing a massive `auth_context`
/// fallback in the production state resolution algorithm just for test fixtures.
pub fn build_unconflicted_state_test_helper(
    auth_context: &HashMap<String, LeanEvent>,
) -> imbl::OrdMap<(String, Option<String>), String> {
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
        (create_ev.event_type.clone(), create_ev.state_key.clone()),
        create_ev.event_id.clone(),
    );

    unconflicted
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
