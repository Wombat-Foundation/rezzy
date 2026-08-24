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
fn test_reference_hash_rejects_unsupported_room_version() {
    // A room version with major > 2 (so it is not the opaque-ID v1/v2 case) but
    // unrecognized by `from_room_version` has undefined event-ID hash rules and
    // must fail closed rather than producing a hash.
    let pdu = json!({
        "event_id": "$13:example.com",
        "type": "m.room.message",
        "sender": "@user:example.com",
        "origin_server_ts": 1000,
        "content": { "body": "x" }
    });
    let err = reference_hash(&pdu, "13").unwrap_err();
    assert!(
        err.contains("unsupported room version 13"),
        "expected an unsupported-version error, got: {err}"
    );
    assert!(reference_hash(&pdu, "999").is_err());
    // Supported versions still hash.
    assert!(reference_hash(&pdu, "11").is_ok());
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

/// Coverage: `redact_content`'s dotted-path accumulation branch. v11+
/// `m.room.member` preserves `third_party_invite.signed` -- a nested key
/// under a parent object -- which is the only path in `redact_json` that
/// exercises `inner.get(rest)` and builds a fresh parent object in `out`.
#[test]
fn test_redact_json_preserves_dotted_nested_key() {
    let pdu = json!({
        "event_id": "$1:example.com",
        "type": "m.room.member",
        "state_key": "@bob:example.com",
        "sender": "@alice:example.com",
        "origin_server_ts": 1000,
        "content": {
            "membership": "invite",
            "third_party_invite": {
                "signed": { "mxid": "@bob:example.com", "token": "abc" },
                "display_name": "Bob"
            }
        }
    });
    let redacted = redact_json(&pdu, "11");
    // `membership` (top-level key) and `third_party_invite.signed` (nested)
    // both survive; the sibling `display_name` under the same parent does not.
    assert_eq!(
        redacted["content"]["third_party_invite"],
        json!({ "signed": { "mxid": "@bob:example.com", "token": "abc" } })
    );
    assert_eq!(redacted["content"]["membership"], "invite");
}

/// Coverage: `redact_top_level`'s non-`Value::Object` early return. A
/// non-object top-level value (e.g. a JSON array or scalar) has no keys to
/// preserve at all, so `redact_json` must produce an empty object rather
/// than panicking on `.get()`.
#[test]
fn test_redact_json_non_object_top_level_yields_empty_object() {
    let redacted = redact_json(&json!([1, 2, 3]), "11");
    assert_eq!(redacted, json!({ "content": {} }));
    let redacted = redact_json(&json!("not an object"), "11");
    assert_eq!(redacted, json!({ "content": {} }));
}

/// Coverage: MSC4291 (room IDs as hashes, v12+) drops `room_id` from a
/// redacted `m.room.create`, but only for v12+ -- exercises both the
/// `is_v12_create` short-circuit and `room_version_is_v12_or_later` itself.
#[test]
fn test_redact_json_drops_room_id_on_v12_create_only() {
    let pdu = json!({
        "event_id": "$1:example.com",
        "type": "m.room.create",
        "room_id": "!room:example.com",
        "state_key": "",
        "sender": "@creator:example.com",
        "origin_server_ts": 1000,
        "content": { "room_version": "12" }
    });
    let redacted_v12 = redact_json(&pdu, "12");
    assert!(redacted_v12.get("room_id").is_none());

    // Pre-v12, `room_id` is a normal top-level key and survives.
    let redacted_v11 = redact_json(&pdu, "11");
    assert_eq!(redacted_v11["room_id"], "!room:example.com");

    // v12+ but NOT a create event: `room_id` is preserved (only an
    // `m.room.create` event drops it in v12+), so this exercises the
    // `event_type != create` short-circuit.
    let msg = json!({
        "event_id": "$2:example.com",
        "type": "m.room.message",
        "room_id": "!room:example.com",
        "sender": "@alice:example.com",
        "origin_server_ts": 1000,
        "content": { "body": "hi" }
    });
    let redacted_msg = redact_json(&msg, "12");
    assert_eq!(redacted_msg["room_id"], "!room:example.com");
}

/// Coverage: `redact_json`'s fallback when `content` is entirely absent from
/// the input PDU -- must yield an empty object rather than panicking.
#[test]
fn test_redact_json_missing_content_yields_empty_object() {
    let pdu = json!({
        "event_id": "$1:example.com",
        "type": "m.room.message",
        "sender": "@alice:example.com",
        "origin_server_ts": 1000
    });
    let redacted = redact_json(&pdu, "11");
    assert_eq!(redacted["content"], json!({}));
}
