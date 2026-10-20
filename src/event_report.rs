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
fn linked_ids(event: &JsonValue, field: &str) -> JsonValue {
    let ids = event
        .get(field)
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_str().or_else(|| item.as_array()?.first()?.as_str()))
        .map(|id| JsonValue::String(String::from(id)))
        .collect();
    JsonValue::Array(ids)
}

/// The event as it travels on the wire: the `event_id` field of an export is
/// derived data, so it is not part of what the hashes cover.
fn without_event_id(event: &JsonValue) -> JsonValue {
    let mut wire = event.clone();
    if let Some(object) = wire.as_object_mut() {
        let _ = object.remove("event_id");
    }
    wire
}

/// Describes one parsed event under `room_version`.
#[must_use]
pub fn describe_event(event: &JsonValue, room_version: &str) -> JsonValue {
    let mut record = crate::json!({});
    let wire = without_event_id(event);
    let reference = match crate::reference_hash(&wire, room_version) {
        Ok(hash) => hash,
        Err(error) => {
            let _ = record.insert(String::from("error"), JsonValue::String(error));
            return record;
        }
    };
    let content_hash_ok = crate::verify_content_hash(&wire, room_version).is_ok();
    let _ = record.insert(
        String::from("event_id"),
        JsonValue::String(std::format!("${reference}")),
    );
    let _ = record.insert(
        String::from("claimed_event_id"),
        event.get("event_id").cloned().unwrap_or(JsonValue::Null),
    );
    let _ = record.insert(
        String::from("content_hash_ok"),
        JsonValue::Bool(content_hash_ok),
    );
    for field in ["room_id", "type", "state_key", "depth"] {
        let _ = record.insert(
            String::from(field),
            event.get(field).cloned().unwrap_or(JsonValue::Null),
        );
    }
    for field in ["prev_events", "auth_events"] {
        let _ = record.insert(String::from(field), linked_ids(event, field));
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
                    JsonValue::String(std::format!("invalid JSON: {error}")),
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
