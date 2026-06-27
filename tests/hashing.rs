use ruma_lean::LeanEvent;
use serde_json::json;

#[cfg(feature = "hashing")]
#[test]
fn test_event_id_hashing_sequence_and_stripping() {
    // Event 1 has signatures and unsigned fields that must be completely stripped
    // before the hash is computed.
    let payload1 = json!({
        "type": "m.room.message",
        "sender": "@user:example.com",
        "origin_server_ts": 1000,
        "content": {
            "body": "Test 1"
        },
        "unsigned": {
            "age": 123
        },
        "signatures": {
            "example.com": {
                "ed25519:1": "a_signature"
            }
        }
    });

    let ev1: LeanEvent = serde_json::from_value(payload1).unwrap();

    // The canonical JSON representation of Event 1 (after stripping unsigned and signatures) is:
    // {"content":{"body":"Test 1"},"origin_server_ts":1000,"sender":"@user:example.com","type":"m.room.message"}
    //
    // The SHA-256 Base64 (URL-safe, no pad) of that string is:
    // $5-xYBxvIkOkpDW26blsujk76Zky8RMPLnoQD5fz6wY8
    assert_eq!(ev1.event_id, "$5-xYBxvIkOkpDW26blsujk76Zky8RMPLnoQD5fz6wY8");

    // Event 2 is clean without any extra fields, just varying the timestamp and body
    let payload2 = json!({
        "type": "m.room.message",
        "sender": "@user:example.com",
        "origin_server_ts": 1001,
        "content": {
            "body": "Test 2"
        }
    });

    let ev2: LeanEvent = serde_json::from_value(payload2).unwrap();

    // The canonical JSON representation of Event 2 is:
    // {"content":{"body":"Test 2"},"origin_server_ts":1001,"sender":"@user:example.com","type":"m.room.message"}
    //
    // The expected Matrix-spec hash is:
    assert_eq!(ev2.event_id, "$BQIRGBlb9b0LAYcQ0eiXWOiiVdEjZ2yKx9jMLrxejI0");
}

#[cfg(not(feature = "hashing"))]
#[test]
fn test_missing_event_id_fails_without_hashing() {
    let json_payload = json!({
        "type": "m.room.message",
        "sender": "@alice:example.com",
        "origin_server_ts": 123456789,
        "content": {
            "body": "Hello, world!"
        }
    });

    let result: Result<LeanEvent, _> = serde_json::from_value(json_payload);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("event_id is missing"));
}
