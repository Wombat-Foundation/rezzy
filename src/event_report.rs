//! Per-event hashing reports for JSONL event files.
//!
//! One record per event: its ID under a room version, whether its content hash
//! holds, and its links. Callers that only need to know whether an event is
//! what it claims to be (a bounty's CI, the `rezzy hash events` command, the C
//! ABI) share this instead of reimplementing the redaction and hashing rules of
//! every room version. A line that cannot be hashed yields an `error` record
//! rather than failing the whole run.

use crate::JsonValue;
use std::string::String;
use std::vec::Vec;

/// The event IDs in `prev_events` or `auth_events`: bare strings (v3+) or the
/// `[id, {hashes}]` pairs older versions use.
fn linked_ids(event: &JsonValue, field: &str) -> Result<JsonValue, String> {
    let Some(value) = event.get(field) else {
        return Ok(JsonValue::Array(Vec::new()));
    };
    let Some(items) = value.as_array() else {
        return Err(std::format!("`{field}` must be an array"));
    };
    let mut ids = Vec::with_capacity(items.len());
    for item in items {
        let id = item.as_str().or_else(|| {
            let tuple = item.as_array()?;
            tuple.first()?.as_str()
        });
        let Some(id) = id else {
            return Err(std::format!(
                "`{field}` contains a malformed event reference"
            ));
        };
        ids.push(JsonValue::String(String::from(id)));
    }
    Ok(JsonValue::Array(ids))
}

/// The event as the hashes see it. From v3 on, the `event_id` field of an
/// export is derived data, so it is dropped; v1/v2 keep it because the content
/// hash covers it.
#[must_use]
pub fn wire_event(event: &JsonValue, room_version: &str) -> JsonValue {
    let mut wire = event.clone();
    if !crate::has_opaque_event_ids(room_version) {
        if let Some(object) = wire.as_object_mut() {
            let _ = object.remove("event_id");
        }
    }
    wire
}

/// Describes one parsed event under `room_version`, including its reference
/// ID, claimed ID, content-hash result, metadata, and normalized event links.
/// Opaque-ID versions omit the derived ID. Nonobjects, malformed links, and
/// reference-hash failures produce an `error` record; content-hash failures
/// instead set `content_hash_ok` to false and include `content_hash_error`
/// and the redacted event. Missing link fields become empty arrays.
#[must_use]
pub fn describe_event(event: &JsonValue, room_version: &str) -> JsonValue {
    let mut record = crate::json!({});
    if !event.is_object() {
        let _ = record.insert(
            String::from("error"),
            JsonValue::String(String::from("event must be a JSON object")),
        );
        return record;
    }
    let mut links = Vec::new();
    for field in ["prev_events", "auth_events"] {
        match linked_ids(event, field) {
            Ok(value) => links.push((field, value)),
            Err(error) => {
                let _ = record.insert(String::from("error"), JsonValue::String(error));
                return record;
            }
        }
    }
    let wire = wire_event(event, room_version);
    if !crate::has_opaque_event_ids(room_version) {
        match crate::reference_hash(&wire, room_version) {
            Ok(hash) => {
                let _ = record.insert(
                    String::from("event_id"),
                    JsonValue::String(std::format!("${hash}")),
                );
            }
            Err(error) => {
                let _ = record.insert(String::from("error"), JsonValue::String(error));
                return record;
            }
        }
    }
    let content_hash = crate::verify_content_hash(&wire, room_version);
    let content_hash_ok = content_hash.is_ok();
    let _ = record.insert(
        String::from("claimed_event_id"),
        event.get("event_id").cloned().unwrap_or(JsonValue::Null),
    );
    let _ = record.insert(
        String::from("content_hash_ok"),
        JsonValue::Bool(content_hash_ok),
    );
    if let Err(error) = content_hash {
        let _ = record.insert(String::from("content_hash_error"), JsonValue::String(error));
    }
    for field in ["room_id", "type", "state_key", "depth"] {
        let _ = record.insert(
            String::from(field),
            event.get(field).cloned().unwrap_or(JsonValue::Null),
        );
    }
    for (field, value) in links {
        let _ = record.insert(String::from(field), value);
    }
    if !content_hash_ok {
        // The form to keep when the content hash does not cover the content.
        let _ = record.insert(
            String::from("redacted"),
            crate::redact_json(event, room_version),
        );
    }
    record
}

/// Describes every non-blank line of `jsonl`. Each record carries its
/// 1-based `line` number; unparsable lines become `error` records.
#[must_use]
pub fn describe_jsonl(jsonl: &str, room_version: &str) -> Vec<JsonValue> {
    let mut records = Vec::new();
    for (index, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut record = match JsonValue::parse(line.trim()) {
            Ok(event) => describe_event(&event, room_version),
            Err(error) => {
                let mut bad = crate::json!({});
                let _ = bad.insert(
                    String::from("error"),
                    JsonValue::String(std::format!("{error}")),
                );
                bad
            }
        };
        let _ = record.insert(
            String::from("line"),
            crate::json!(u64::try_from(index.saturating_add(1)).unwrap_or(u64::MAX)),
        );
        records.push(record);
    }
    records
}

/// The report document: `{"room_version": …, "events": [records]}`.
#[must_use]
pub fn report(records: Vec<JsonValue>, room_version: &str) -> JsonValue {
    let mut result = crate::json!({});
    let _ = result.insert(
        String::from("room_version"),
        JsonValue::String(String::from(room_version)),
    );
    let _ = result.insert(String::from("events"), JsonValue::Array(records));
    result
}

#[cfg(test)]
mod tests {
    use super::describe_event;
    use crate::JsonValue;

    #[test]
    fn malformed_event_links_produce_an_error_record() {
        for event in [
            r#"{"prev_events":{}}"#,
            r#"{"auth_events":["$valid",7]}"#,
            r#"{"prev_events":[[]]}"#,
        ] {
            let event = JsonValue::parse(event).unwrap();
            let record = describe_event(&event, "12");
            assert!(record.get("error").and_then(JsonValue::as_str).is_some());
            assert!(record.get("event_id").is_none());
            assert!(record.get("content_hash_ok").is_none());
        }
    }

    #[test]
    fn legacy_room_versions_keep_claimed_ids_and_do_not_derive_them() {
        let event = JsonValue::parse(r#"{"event_id":"$opaque","content":{}}"#).unwrap();
        for version in ["1", "2"] {
            let wire = super::wire_event(&event, version);
            assert_eq!(
                wire.get("event_id").and_then(JsonValue::as_str),
                Some("$opaque")
            );
            let record = describe_event(&event, version);
            assert!(record.get("event_id").is_none());
            assert_eq!(
                record.get("claimed_event_id").and_then(JsonValue::as_str),
                Some("$opaque")
            );
            assert!(record.get("content_hash_error").is_some());
        }
    }
}
