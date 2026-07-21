use rezzy::merkle::{
    self, AuthEventsHash, ContentHash, EventHeaderRoot, Field, Header, MerkleError,
    OtherSignedFieldsHash, PrevEventsHash,
};
use serde_json::{Value, json};
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
        sender: "@alice:example.org".into(),
        event_type: "m.room.message".into(),
        state_key: None,
        redacts: None,
        depth: 42,
        origin_server_ts: 123_456_789,
    })
    .unwrap();

    assert_eq!(
        hex(root),
        "f4f5f542c8adb6ba354328dfeda66fd069b77981a5514bb86cb22072d5117324"
    );
}

#[test]
fn event_root_and_id_stable_vector() {
    let prev = merkle::component_hash("prev_events", &json!(["$a:example.org"])).unwrap();
    let auth = merkle::component_hash("auth_events", &json!(["$auth:example.org"])).unwrap();
    let header = merkle::header_root(&Header {
        room_id: "!room:example.org".into(),
        sender: "@alice:example.org".into(),
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
        "734aaf66da440dfbbe445bfe7874014983beafe7682b456f40973f7e8e0a2e4d"
    );
    assert_eq!(
        merkle::event_id(root),
        "$c0qvZtpEDfu-RFv-eHQBSYO-r-doK0VvQJc_fo4KLk0"
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
