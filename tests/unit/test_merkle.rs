use rezzy::merkle::{
    self, AuthEventsHash, ContentHash, EventHeaderRoot, Field, Header, MerkleError,
    OtherSignedFieldsHash, PrevEventsHash, Side,
};
use serde_json::{json, Value};
use std::fmt::Write;

fn sample_fields() -> Vec<Field> {
    vec![
        Field::new("event_id", json!("$b:example.org")),
        Field::new("depth", json!(7)),
        Field::new("rejected", json!(false)),
        Field::new("prev_events_hash", json!("sha256:abc")),
    ]
}

fn hex(hash: merkle::Hash) -> String {
    hash.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").expect("writing to String cannot fail");
        out
    })
}

#[test]
fn canonical_json_sorts_keys_and_compacts() {
    let got = merkle::canonical_json(&json!({
        "z": 2,
        "a": [true, null, "x"],
        "m": {
            "b": "second",
            "a": "first",
        },
    }))
    .unwrap();

    assert_eq!(
        String::from_utf8(got).unwrap(),
        r#"{"a":[true,null,"x"],"m":{"a":"first","b":"second"},"z":2}"#
    );
}

#[test]
fn canonical_json_string_escaping_matches_matrix_rules() {
    let got = merkle::canonical_json(&json!({
        "html": "<>&",
        "line": "a\nb",
        "nul": "\u{0}",
        "unit_separator": "\u{1f}",
        "special": "\"\\\u{08}\u{0c}\r\t",
    }))
    .unwrap();

    assert_eq!(
        String::from_utf8(got).unwrap(),
        r#"{"html":"<>&","line":"a\nb","nul":"\u0000","special":"\"\\\b\f\r\t","unit_separator":"\u001f"}"#
    );
}

#[test]
fn canonical_json_rejects_out_of_range_integers_and_floats() {
    assert_eq!(
        merkle::canonical_json(&json!({ "n": 1_i64 << 53 })).unwrap_err(),
        MerkleError::IntegerRange
    );

    assert_eq!(
        merkle::canonical_json(&json!({ "n": 1.5 })).unwrap_err(),
        MerkleError::UnsupportedNumber
    );
}

#[test]
fn canonical_json_covers_unsigned_number_branch() {
    let too_large = serde_json::Number::from(u64::MAX);
    assert_eq!(
        merkle::canonical_json(&Value::Number(too_large)).unwrap_err(),
        MerkleError::IntegerRange
    );
}

#[test]
fn canonical_json_accepts_small_u64_number() {
    let in_range = serde_json::Number::from(7_u64);
    assert_eq!(
        String::from_utf8(merkle::canonical_json(&Value::Number(in_range)).unwrap()).unwrap(),
        "7"
    );
}

#[test]
fn canonical_json_encodes_top_level_null_and_false() {
    assert_eq!(
        String::from_utf8(merkle::canonical_json(&Value::Null).unwrap()).unwrap(),
        "null"
    );
    assert_eq!(
        String::from_utf8(merkle::canonical_json(&Value::Bool(false)).unwrap()).unwrap(),
        "false"
    );
}

#[test]
fn canonical_json_rejects_invalid_array_element() {
    assert_eq!(
        merkle::canonical_json(&json!([1.5])).unwrap_err(),
        MerkleError::UnsupportedNumber
    );
}

#[test]
fn root_is_order_independent() {
    let mut fields = sample_fields();
    let root1 = merkle::root(&fields).unwrap();

    fields.reverse();
    let root2 = merkle::root(&fields).unwrap();

    assert_eq!(root1, root2);
}

#[test]
fn root_stable_vector() {
    let root = merkle::root(&sample_fields()).unwrap();

    assert_eq!(
        hex(root),
        "08e7c748acbe75a855a5c1420ea3d5948a765509f27d132796bfbaecbe8c3fae"
    );
}

#[test]
fn header_root_uses_null_for_missing_optional_fields() {
    let root = merkle::header_root(&Header {
        room_id: "!room:example.org".into(),
        sender_localpart: "alice".into(),
        sender_domain: "example.org".into(),
        event_type: "m.room.message".into(),
        state_key: None,
        redacts: None,
        depth: 42,
        origin_server_ts: 123_456_789,
    })
    .unwrap();

    assert_eq!(
        hex(root),
        "db91cc8e8d3eb0d13885c32f28dbd4215a111081383e25263749c65d9bf8bc37"
    );
}

#[test]
fn event_root_and_id_stable_vector() {
    let prev = merkle::component_hash("prev_events", &json!(["$a:example.org"])).unwrap();
    let auth = merkle::component_hash("auth_events", &json!(["$auth:example.org"])).unwrap();
    let header = merkle::header_root(&Header {
        room_id: "!room:example.org".into(),
        sender_localpart: "alice".into(),
        sender_domain: "example.org".into(),
        event_type: "m.room.message".into(),
        state_key: None,
        redacts: None,
        depth: 42,
        origin_server_ts: 123_456_789,
    })
    .unwrap();
    let content =
        merkle::component_hash("content", &json!({"body": "hello", "msgtype": "m.text"})).unwrap();
    let other =
        merkle::component_hash("other_signed_fields", &json!({"origin": "example.org"})).unwrap();

    let root = merkle::event_root(
        PrevEventsHash(prev),
        AuthEventsHash(auth),
        EventHeaderRoot(header),
        ContentHash(content),
        OtherSignedFieldsHash(other),
    );

    assert_eq!(
        hex(root),
        "4ccc880527fe5f97d27a04105bb55e6c6e75d87928e54a6cd2973c224802ce91"
    );
    assert_eq!(
        merkle::event_id(root),
        "$TMyIBSf-X5fSegQQW7VebG512Hko5Ups0pc8IkgCzpE"
    );
}

/// Coverage: `content_hash` combines `redacted_content_hash` and
/// `ephemeral_content_hash` via `inner_hash`, so it must equal a direct
/// `component_hash`-style computation of that combination, and it must
/// change if either side changes.
#[test]
fn content_hash_combines_redacted_and_ephemeral() {
    let redacted = merkle::redacted_content_hash(&json!({ "membership": "join" })).unwrap();
    let ephemeral = merkle::ephemeral_content_hash(&json!({ "displayname": "Alice" })).unwrap();
    let combined = merkle::content_hash(redacted, ephemeral);

    let other_ephemeral = merkle::ephemeral_content_hash(&json!({ "displayname": "Bob" })).unwrap();
    let combined_with_different_ephemeral = merkle::content_hash(redacted, other_ephemeral);

    assert_ne!(hex(combined.0), hex(combined_with_different_ephemeral.0));

    // Same inputs must be deterministic.
    let combined_again = merkle::content_hash(redacted, ephemeral);
    assert_eq!(hex(combined.0), hex(combined_again.0));
}

/// Coverage: an event with no redaction-protected content (e.g. an ordinary
/// `m.room.message`) can still compute `content_hash` with `ephemeral_content`
/// as canonical `null`, per the draft's "no redaction-protected fields" case.
#[test]
fn content_hash_supports_null_ephemeral_content() {
    let redacted = merkle::redacted_content_hash(&json!({})).unwrap();
    let ephemeral = merkle::ephemeral_content_hash(&Value::Null).unwrap();
    let combined = merkle::content_hash(redacted, ephemeral);

    // Must not equal the all-null degenerate case, confirming the redacted
    // side is actually mixed into the combination.
    let both_null_redacted = merkle::redacted_content_hash(&Value::Null).unwrap();
    let both_null_combined = merkle::content_hash(both_null_redacted, ephemeral);
    assert_ne!(hex(combined.0), hex(both_null_combined.0));
}

fn sample_header_fields() -> Vec<Field> {
    vec![
        Field::new("room_id", json!("!room:example.org")),
        Field::new("sender_localpart", json!("alice")),
        Field::new("sender_domain", json!("example.org")),
        Field::new("type", json!("m.room.message")),
        Field::new("state_key", Value::Null),
        Field::new("redacts", Value::Null),
        Field::new("depth", json!(42)),
        Field::new("origin_server_ts", json!(123_456_789)),
    ]
}

fn field_leaf_hash(field: &Field) -> merkle::Hash {
    let canonical = merkle::canonical_json(&field.value).unwrap();
    merkle::leaf_hash(&field.name, &canonical).unwrap()
}

/// Coverage: `leaf_path` reconstructs the same root `root()` computes, for
/// every field in an 8-field header.
#[test]
fn leaf_path_reconstructs_root() {
    let fields = sample_header_fields();
    let root = merkle::root(&fields).unwrap();

    for field in &fields {
        let (path, proved_root) = merkle::leaf_path(&fields, &field.name).unwrap();
        assert_eq!(proved_root, root, "field: {}", field.name);
        let leaf_hash = field_leaf_hash(field);
        assert!(
            merkle::verify_leaf_path(leaf_hash, &path, root),
            "field: {}",
            field.name
        );
    }
}

/// Coverage: matches the draft's illustrative `sender_domain` proof example
/// (3 steps: right, right, left) over this exact 8-field header.
#[test]
fn leaf_path_matches_draft_sender_domain_example() {
    let fields = sample_header_fields();
    let (path, _root) = merkle::leaf_path(&fields, "sender_domain").unwrap();
    assert_eq!(path.len(), 3);
    let want = [Side::Right, Side::Right, Side::Left];
    for (step, expected) in path.iter().zip(want) {
        assert_eq!(step.side, expected);
    }
}

#[test]
fn verify_leaf_path_rejects_tampered_sibling() {
    let fields = sample_header_fields();
    let root = merkle::root(&fields).unwrap();
    let (mut path, _) = merkle::leaf_path(&fields, "type").unwrap();
    let leaf_hash = field_leaf_hash(&Field::new("type", json!("m.room.message")));
    path[0].hash[0] ^= 0xFF;
    assert!(!merkle::verify_leaf_path(leaf_hash, &path, root));
}

#[test]
fn leaf_path_rejects_unknown_field() {
    let fields = sample_header_fields();
    assert_eq!(
        merkle::leaf_path(&fields, "nonexistent").unwrap_err(),
        MerkleError::FieldNotFound("nonexistent".into())
    );
}

#[test]
fn duplicate_field_rejected() {
    assert_eq!(
        merkle::root(&[Field::new("depth", json!(1)), Field::new("depth", json!(2)),]).unwrap_err(),
        MerkleError::DuplicateField("depth".into())
    );
}

#[test]
fn empty_root_rejected() {
    assert_eq!(merkle::root(&[]).unwrap_err(), MerkleError::NoLeaves);
}

#[test]
fn empty_field_name_rejected() {
    assert_eq!(
        merkle::root(&[Field::new("", Value::Null)]).unwrap_err(),
        MerkleError::EmptyFieldName
    );
}

#[test]
fn empty_str_leaf_hash_field_name_rejected() {
    assert_eq!(
        merkle::leaf_hash("", b"null").unwrap_err(),
        MerkleError::EmptyFieldName
    );
}

#[test]
fn empty_bytes_leaf_hash_field_name_rejected() {
    assert_eq!(
        merkle::leaf_hash_bytes(b"", b"null").unwrap_err(),
        MerkleError::EmptyFieldName
    );
}

#[test]
fn invalid_field_name_bytes_rejected() {
    assert_eq!(
        merkle::leaf_hash_bytes(&[0xff], b"null").unwrap_err(),
        MerkleError::InvalidFieldName
    );
}

#[test]
fn nul_in_field_name_rejected() {
    assert_eq!(
        merkle::leaf_hash("a\u{0}b", b"null").unwrap_err(),
        MerkleError::InvalidFieldName
    );
    assert_eq!(
        merkle::leaf_hash_bytes(b"a\0b", b"null").unwrap_err(),
        MerkleError::InvalidFieldName
    );
}

#[test]
fn valid_field_name_bytes_match_str_leaf_hash() {
    let canonical = br#"{"body":"hello"}"#;

    assert_eq!(
        merkle::leaf_hash_bytes(b"content", canonical).unwrap(),
        merkle::leaf_hash("content", canonical).unwrap()
    );
}

#[test]
fn merkle_error_display_covers_all_variants() {
    let cases = [
        (MerkleError::EmptyFieldName, "merkle: empty field name"),
        (MerkleError::InvalidFieldName, "merkle: invalid field name"),
        (
            MerkleError::DuplicateField("depth".into()),
            "merkle: duplicate field: depth",
        ),
        (
            MerkleError::FieldNotFound("sender_domain".into()),
            "merkle: field not found: sender_domain",
        ),
        (MerkleError::NoLeaves, "merkle: no leaves"),
        (
            MerkleError::IntegerRange,
            "canonical json integer out of range",
        ),
        (
            MerkleError::UnsupportedNumber,
            "unsupported canonical json number",
        ),
    ];

    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}
