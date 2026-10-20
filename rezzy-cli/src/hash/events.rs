//! `rezzy hash events`: per-event IDs, content-hash checks and links for a JSONL
//! file, under one room version.
//!
//! Callers that only need to know whether an event is what it claims to be
//! (for example a bounty's CI) can ask this instead of reimplementing the
//! redaction and hashing rules of every room version. Each input line yields
//! one record; a line that cannot be hashed yields an `error` record instead of
//! failing the whole run.

use crate::error::{AppError, ErrorCode};
use clap::{Arg, ArgMatches, Command};
use rezzy::JsonValue;
use std::io::Read;
use std::path::PathBuf;

pub(super) fn command() -> Command {
    Command::new("events")
        .about("Compute each event's reference hash, content-hash check and links")
        .arg(
            Arg::new("input")
                .long("input")
                .short('i')
                .required(true)
                .value_parser(clap::value_parser!(PathBuf))
                .help("JSONL file of events; '-' reads stdin"),
        )
        .arg(
            Arg::new("room-version")
                .long("room-version")
                .required(true)
                .help("Room version whose hashing and redaction rules apply"),
        )
}

/// The event IDs in `prev_events` or `auth_events`: bare strings (v3+) or the
/// `[id, {hashes}]` pairs older versions use.
fn linked_ids(event: &JsonValue, field: &str) -> JsonValue {
    let ids = event
        .get(field)
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_str().or_else(|| item.as_array()?.first()?.as_str()))
        .map(|id| JsonValue::String(id.to_owned()))
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

fn describe(event: &JsonValue, room_version: &str) -> JsonValue {
    let mut record = rezzy::json!({});
    let wire = without_event_id(event);
    let reference = match rezzy::reference_hash(&wire, room_version) {
        Ok(hash) => hash,
        Err(error) => {
            let _ = record.insert(String::from("error"), JsonValue::String(error));
            return record;
        }
    };
    let content_hash_ok = rezzy::verify_content_hash(&wire, room_version).is_ok();
    let _ = record.insert(
        String::from("event_id"),
        JsonValue::String(format!("${reference}")),
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
            rezzy::redact_json(event, room_version),
        );
    }
    record
}

fn read_input(path: &PathBuf) -> Result<String, AppError> {
    if path.as_os_str() == "-" {
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text)?;
        Ok(text)
    } else {
        Ok(std::fs::read_to_string(path)?)
    }
}

pub(super) fn run(m: &ArgMatches) -> Result<JsonValue, AppError> {
    let path = m.get_one::<PathBuf>("input").expect("required");
    let room_version = m.get_one::<String>("room-version").expect("required");
    let text = read_input(path)?;
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut record = match JsonValue::parse(line.trim()) {
            Ok(event) => describe(&event, room_version),
            Err(error) => {
                let mut bad = rezzy::json!({});
                let _ = bad.insert(
                    String::from("error"),
                    JsonValue::String(format!("invalid JSON: {error}")),
                );
                bad
            }
        };
        let _ = record.insert(
            String::from("line"),
            rezzy::json!(u64::try_from(index.saturating_add(1)).unwrap_or(u64::MAX)),
        );
        records.push(record);
    }
    if records.is_empty() {
        return Err(AppError::new(ErrorCode::EmptyInput, "no events in input"));
    }
    let mut result = rezzy::json!({});
    let _ = result.insert(
        String::from("room_version"),
        JsonValue::String(room_version.clone()),
    );
    let _ = result.insert(String::from("events"), JsonValue::Array(records));
    Ok(result)
}
