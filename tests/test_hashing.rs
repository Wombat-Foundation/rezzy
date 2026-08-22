#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
use rezzy::{redact_json, reference_hash, LeanEvent};
use serde_json::json;

#[test]
fn test_from_value_derives_reference_hash_event_id() {
    // A PDU with NO `event_id`. For room v4+ the event ID is the reference hash
    // of the REDACTED event. `from_value` threads the room version to derive it.
    let payload = json!({
        "type": "m.room.message",
        "sender": "@user:example.com",
        "origin_server_ts": 1000,
        "content": { "body": "Test 1" },
        "unsigned": { "age": 123 },
        "signatures": { "example.com": { "ed25519:1": "a_signature" } }
    });
    let ev = LeanEvent::from_value(&payload, Some("11")).unwrap();
    let expected = format!("${}", reference_hash(&payload, "11").unwrap());
    assert_eq!(ev.event_id, expected);
    assert!(ev.event_id.starts_with('$'));
}

#[test]
fn test_from_value_requires_event_id_or_room_version() {
    let payload = json!({
        "type": "m.room.message",
        "sender": "@user:example.com",
        "origin_server_ts": 1,
        "content": { "body": "x" }
    });
    // Neither an `event_id` nor a room version -> the ID cannot be derived.
    assert!(LeanEvent::from_value(&payload, None).is_err());
    // With a room version the reference hash is derived.
    assert!(LeanEvent::from_value(&payload, Some("11")).is_ok());
    // An explicit event_id is used as-is regardless of room version.
    let with_id = json!({ "event_id": "$explicit:example.com", "type": "m.room.message" });
    let ev = LeanEvent::from_value(&with_id, None).unwrap();
    assert_eq!(ev.event_id, "$explicit:example.com");
}

#[test]
fn test_reference_hash_rejects_v1_v2() {
    // v1/v2 event IDs are opaque server-assigned strings, not reference hashes.
    let pdu = json!({
        "event_id": "$1:example.com",
        "type": "m.room.message",
        "sender": "@user:example.com",
        "origin_server_ts": 1000,
        "content": { "body": "x" }
    });
    assert!(reference_hash(&pdu, "1").is_err());
    assert!(reference_hash(&pdu, "2").is_err());
    assert!(reference_hash(&pdu, "3").is_ok());
    assert!(reference_hash(&pdu, "4").is_ok());
}

#[test]
fn test_reference_hash_is_redaction_invariant_and_keeps_hashes() {
    // Reference hash (room v4+) = SHA-256 of the canonical JSON of the REDACTED
    // event, with `signatures`/`unsigned` removed but `hashes` retained. Because
    // it covers the redacted form, redaction must not change it — this is what
    // lets a redaction be applied to an event already in the DAG.
    let pdu = json!({
        "event_id": "$1:example.com",
        "type": "m.room.message",
        "sender": "@user:example.com",
        "origin_server_ts": 2000,
        "content": { "body": "hello" },
        "unsigned": { "age": 5 },
        "signatures": { "example.com": { "ed25519:1": "sig" } },
        "hashes": { "sha256": "somehash" }
    });
    let h1 = reference_hash(&pdu, "11").unwrap();
    let redacted = redact_json(&pdu, "11");
    let h2 = reference_hash(&redacted, "11").unwrap();
    assert_eq!(h1, h2);

    // m.room.message content is emptied by redaction, but `hashes` survives.
    assert_eq!(redacted["content"], json!({}));
    assert_eq!(redacted["hashes"], json!({ "sha256": "somehash" }));

    // Canonical key sorting + base64url-unpadded output is deterministic.
    assert!(h1
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
}

/// Coverage: `sort_json_value_keys` walks the Array arm when a surviving
/// content value is an array (`m.room.join_rules.allow` in v9+).
#[test]
fn test_reference_hash_canonicalizes_array_content() {
    let pdu = json!({
        "event_id": "$1:example.com",
        "type": "m.room.join_rules",
        "state_key": "",
        "sender": "@user:example.com",
        "origin_server_ts": 2000,
        "content": {
            "join_rule": "restricted",
            "allow": [ {"type": "m.room_membership", "room_id": "!z:example.com", "via": ["z.example.com"]} ]
        }
    });
    // join_rules preserves `join_rule` and `allow` in v9+; the array survives
    // redaction and exercises the key-sorter's Array arm deterministically.
    let redacted = redact_json(&pdu, "11");
    assert_eq!(redacted["content"]["allow"], pdu["content"]["allow"]);
    let h = reference_hash(&pdu, "11").unwrap();
    assert!(h
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    assert!(!h.is_empty());
}

#[test]
fn test_hash_base64_alphabet_differs_v3_vs_v4() {
    // The base64 alphabet is a room-version attribute: v3 uses the STANDARD
    // alphabet (+ and /), v4+ uses URL-safe (- and _). Both unpadded.
    let pdu = json!({
        "event_id": "$1:example.com",
        "type": "m.room.message",
        "sender": "@u:example.com",
        "origin_server_ts": 1,
        "depth": 1,
        "content": { "body": "hello" }
    });
    let v3 = reference_hash(&pdu, "3").unwrap();
    let v4 = reference_hash(&pdu, "4").unwrap();
    assert!(v4
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    assert!(v3
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
    assert_ne!(v3, v4);
}
