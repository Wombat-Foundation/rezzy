//! Room-scoped provenance sidecar for `rezzy aggregate`.
//!
//! The aggregate output keeps the full Matrix event envelope (including
//! `signatures` and `unsigned`). Non-envelope top-level fields, Rezzy
//! ingestion markers, and per-source facts such as `rejected`/`soft_failed`
//! and stream order are recorded here instead, keyed by `event_id`, one
//! observation per source file/line. Disagreements between sources are
//! reported as `source_disagreement`; no observation is silently dropped.
//!
//! The sidecar is an index over the raw evidence, not a replacement for the
//! `unmerged/` inputs.

use crate::error::{AppError, ErrorCode};
use rezzy::{JsonObject, JsonValue};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Sidecar schema identifier written in the manifest record.
pub const SCHEMA: &str = "rezzy.room-metadata";
/// Sidecar schema version written in the manifest record.
pub const SCHEMA_VERSION: u64 = 1;
/// Suffix appended to the aggregate filename stem for the sidecar.
pub const SIDECAR_SUFFIX: &str = ".rezzy-meta.jsonl";

/// Stream-order aliases accepted from raw input events, in preferred order.
pub const STREAM_ORDERING_ALIASES: [&str; 4] = [
    "__stream_ordering",
    "__stream_order",
    "__pdu_count",
    "__pducount",
];

/// Recognized top-level Matrix event envelope fields, sorted for lookup.
///
/// Anything outside this list (including every `__`-prefixed key) is
/// preserved per source in the sidecar and removed from the merged output.
const MATRIX_ENVELOPE_FIELDS: [&str; 18] = [
    "auth_events",
    "content",
    "depth",
    "event_id",
    "hashes",
    "membership",
    "origin",
    "origin_server_ts",
    "prev_events",
    "prev_state",
    "prev_state_events",
    "redacts",
    "room_id",
    "sender",
    "signatures",
    "state_key",
    "type",
    "unsigned",
];

/// Returns whether `key` is part of the recognized Matrix event envelope.
#[must_use]
pub fn is_matrix_envelope_key(key: &str) -> bool {
    MATRIX_ENVELOPE_FIELDS.contains(&key)
}

/// The sidecar path for an aggregate output, e.g. `merged-room.jsonl` ->
/// `merged-room.rezzy-meta.jsonl`.
#[must_use]
pub fn sidecar_path(output: &Path) -> PathBuf {
    let stem = output.file_stem().map_or_else(
        || output.as_os_str().to_os_string(),
        std::ffi::OsStr::to_os_string,
    );
    let mut name = stem;
    name.push(SIDECAR_SUFFIX);
    output.with_file_name(name)
}

/// Lowercase hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// A `sha256:<hex>` identity string for `bytes`.
#[must_use]
pub fn sha256_id(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// One input file's identity and filename-derived provenance.
#[derive(Debug, Clone)]
pub struct SourceInfo {
    /// Lowercase hex SHA-256 of the whole input file.
    pub sha256: String,
    /// Path label as it appeared to the aggregator.
    pub filename: String,
    /// Filename-derived kind, e.g. `remote-dag`, `local`, `unknown`.
    pub source_kind: String,
    /// Filename-derived server/domain hint, if any. Provenance, not identity.
    pub server_hint: Option<String>,
    /// Number of events parsed from the file.
    pub event_count: usize,
}

impl SourceInfo {
    /// The `sha256:<hex>` identity used to reference this source.
    #[must_use]
    pub fn source_id(&self) -> String {
        format!("sha256:{}", self.sha256)
    }
}

/// A single source file/line observation of one event.
#[derive(Debug, Clone)]
pub struct RawObservation {
    /// The event's `event_id` (post repair, if repair ran).
    pub event_id: String,
    /// 1-based physical line number in the source file.
    pub line: usize,
    /// `sha256:<hex>` of the raw JSON line as read.
    pub raw_line_sha256: String,
    /// Normalized stream order, set only when all present aliases agree.
    pub stream_ordering: Option<u64>,
    /// The alias that supplied [`Self::stream_ordering`].
    pub stream_ordering_key: Option<String>,
    /// True when multiple aliases were present and disagreed.
    pub stream_ordering_conflict: bool,
    /// Observed `rejected`/`__rejected` claim, if present.
    pub rejected: Option<bool>,
    /// Observed `soft_fail`/`__soft_fail` claim, if present.
    pub soft_failed: Option<bool>,
    /// Observed rejection reason, if present.
    pub rejection_reason: Option<String>,
    /// The source's `signatures` object, kept as evidence.
    pub signatures: Option<JsonValue>,
    /// The source's `unsigned` object, kept as evidence.
    pub unsigned: Option<JsonValue>,
    /// Exact values of every non-envelope top-level field removed from output.
    pub stripped: JsonObject,
}

/// Reads one observation off a raw (pre-strip) event.
#[must_use]
pub fn observe_raw_event(
    raw: &JsonValue,
    event_id: String,
    line: usize,
    raw_line_sha256: String,
) -> RawObservation {
    let object = raw.as_object();
    let get = |key: &str| object.and_then(|obj| obj.get(key));

    let rejected = ["__rejected", "rejected"]
        .iter()
        .find_map(|key| get(key).and_then(JsonValue::as_bool));
    let soft_failed = ["__soft_fail", "soft_fail"]
        .iter()
        .find_map(|key| get(key).and_then(JsonValue::as_bool));
    let rejection_reason = ["__rejection_reason", "rejection_reason"]
        .iter()
        .find_map(|key| get(key).and_then(JsonValue::as_str).map(str::to_owned));

    let mut alias_values: Vec<(&str, u64)> = Vec::new();
    for alias in STREAM_ORDERING_ALIASES {
        if let Some(value) = get(alias).and_then(JsonValue::as_u64) {
            alias_values.push((alias, value));
        }
    }
    let stream_ordering_conflict = alias_values
        .first()
        .is_some_and(|(_, first)| alias_values.iter().any(|(_, value)| value != first));
    let (stream_ordering, stream_ordering_key) = if stream_ordering_conflict {
        (None, None)
    } else {
        alias_values.first().map_or((None, None), |(key, value)| {
            (Some(*value), Some((*key).to_owned()))
        })
    };

    let mut stripped = JsonObject::new();
    if let Some(obj) = object {
        for (key, value) in obj {
            if !is_matrix_envelope_key(key) {
                stripped.insert(key.clone(), value.clone());
            }
        }
    }

    RawObservation {
        event_id,
        line,
        raw_line_sha256,
        stream_ordering,
        stream_ordering_key,
        stream_ordering_conflict,
        rejected,
        soft_failed,
        rejection_reason,
        signatures: get("signatures").cloned(),
        unsigned: get("unsigned").cloned(),
        stripped,
    }
}

/// Removes every non-envelope top-level field from an event in place.
pub fn strip_non_envelope_fields(event: &mut JsonValue) {
    if let Some(object) = event.as_object_mut() {
        object.retain(|key, _| is_matrix_envelope_key(key));
    }
}

/// Serializes the sidecar: a manifest record followed by one record per
/// merged event, in the order the events appear in the aggregate.
///
/// # Errors
/// Returns [`ErrorCode::MalformedJson`] if a record cannot be serialized.
pub fn build_sidecar(
    sources: &[SourceInfo],
    observations: &[(usize, RawObservation)],
    events: &[JsonValue],
    room_id: Option<&str>,
    room_version: Option<&str>,
) -> Result<Vec<u8>, AppError> {
    build_sidecar_bound(sources, observations, events, room_id, room_version, None)
}

/// Serializes a sidecar and binds its manifest to the aggregate bytes.
///
/// The binding lets readers reject a sidecar published beside a different
/// aggregate generation after a crash or interrupted two-file commit.
///
/// # Errors
/// Returns an error when a record cannot be written or an event cannot be
/// serialized to canonical JSON.
pub fn build_sidecar_bound(
    sources: &[SourceInfo],
    observations: &[(usize, RawObservation)],
    events: &[JsonValue],
    room_id: Option<&str>,
    room_version: Option<&str>,
    aggregate_sha256: Option<&str>,
) -> Result<Vec<u8>, AppError> {
    let mut out = Vec::new();
    write_record(
        &mut out,
        &manifest_record(sources, room_id, room_version, aggregate_sha256),
    )?;

    let mut by_event: BTreeMap<&str, Vec<(usize, &RawObservation)>> = BTreeMap::new();
    for (source_index, observation) in observations {
        if !observation.event_id.is_empty() {
            by_event
                .entry(observation.event_id.as_str())
                .or_default()
                .push((*source_index, observation));
        }
    }

    for event in events {
        let event_id = event
            .get("event_id")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        if event_id.is_empty() {
            continue;
        }
        let mut group = by_event.get(event_id).cloned().unwrap_or_default();
        // Do not emit an empty record for every ordinary event in a large
        // aggregate. The sidecar is for retained provenance, not a second
        // copy of the aggregate's event index.
        if group.is_empty() {
            continue;
        }
        group.sort_by_key(|(source_index, observation)| (*source_index, observation.line));
        let serialized = rezzy::json::write_string_value(event).map_err(sidecar_error)?;
        let record = event_record(event_id, &sha256_id(serialized.as_bytes()), &group, sources);
        write_record(&mut out, &record)?;
    }
    Ok(out)
}

fn manifest_record(
    sources: &[SourceInfo],
    room_id: Option<&str>,
    room_version: Option<&str>,
    aggregate_sha256: Option<&str>,
) -> JsonValue {
    let mut manifest = JsonObject::new();
    manifest.insert(
        String::from("record_type"),
        JsonValue::String(String::from("manifest")),
    );
    manifest.insert(String::from("schema"), JsonValue::String(SCHEMA.to_owned()));
    manifest.insert(String::from("schema_version"), rezzy::json!(SCHEMA_VERSION));
    manifest.insert(String::from("room_id"), optional_string(room_id));
    manifest.insert(String::from("room_version"), optional_string(room_version));
    manifest.insert(
        String::from("aggregate_sha256"),
        optional_string(aggregate_sha256),
    );
    manifest.insert(
        String::from("inputs"),
        JsonValue::Array(sources.iter().map(source_record).collect()),
    );
    JsonValue::Object(manifest)
}

fn source_record(source: &SourceInfo) -> JsonValue {
    let mut record = JsonObject::new();
    record.insert(
        String::from("source_id"),
        JsonValue::String(source.source_id()),
    );
    record.insert(
        String::from("sha256"),
        JsonValue::String(format!("sha256:{}", source.sha256)),
    );
    record.insert(
        String::from("filename"),
        JsonValue::String(source.filename.clone()),
    );
    record.insert(
        String::from("source_kind"),
        JsonValue::String(source.source_kind.clone()),
    );
    record.insert(
        String::from("server_hint"),
        optional_string(source.server_hint.as_deref()),
    );
    record.insert(
        String::from("event_count"),
        rezzy::json!(source.event_count),
    );
    JsonValue::Object(record)
}

fn event_record(
    event_id: &str,
    payload_sha256: &str,
    group: &[(usize, &RawObservation)],
    sources: &[SourceInfo],
) -> JsonValue {
    let (metadata_status, local_policy, disagreement_fields) = derive(group);
    let mut record = JsonObject::new();
    record.insert(
        String::from("record_type"),
        JsonValue::String(String::from("event")),
    );
    record.insert(
        String::from("event_id"),
        JsonValue::String(event_id.to_owned()),
    );
    record.insert(
        String::from("payload_sha256"),
        JsonValue::String(payload_sha256.to_owned()),
    );
    record.insert(
        String::from("observations"),
        JsonValue::Array(
            group
                .iter()
                .map(|(source_index, observation)| {
                    observation_record(sources.get(*source_index), observation)
                })
                .collect(),
        ),
    );
    let mut derived = JsonObject::new();
    derived.insert(
        String::from("metadata_status"),
        JsonValue::String(metadata_status.to_owned()),
    );
    derived.insert(
        String::from("local_policy"),
        JsonValue::String(local_policy.to_owned()),
    );
    derived.insert(
        String::from("disagreement_fields"),
        JsonValue::Array(
            disagreement_fields
                .into_iter()
                .map(JsonValue::String)
                .collect(),
        ),
    );
    record.insert(String::from("derived"), JsonValue::Object(derived));
    JsonValue::Object(record)
}

fn observation_record(source: Option<&SourceInfo>, observation: &RawObservation) -> JsonValue {
    let mut record = JsonObject::new();
    record.insert(
        String::from("source_id"),
        JsonValue::String(source.map_or_else(String::new, SourceInfo::source_id)),
    );
    record.insert(String::from("line"), rezzy::json!(observation.line));
    record.insert(
        String::from("raw_line_sha256"),
        JsonValue::String(observation.raw_line_sha256.clone()),
    );
    if let Some(value) = observation.stream_ordering {
        record.insert(String::from("stream_ordering"), rezzy::json!(value));
    }
    if let Some(key) = &observation.stream_ordering_key {
        record.insert(
            String::from("stream_ordering_key"),
            JsonValue::String(key.clone()),
        );
    }
    if observation.stream_ordering_conflict {
        record.insert(
            String::from("stream_ordering_conflict"),
            JsonValue::Bool(true),
        );
    }
    if let Some(value) = observation.rejected {
        record.insert(String::from("rejected"), JsonValue::Bool(value));
    }
    if let Some(value) = observation.soft_failed {
        record.insert(String::from("soft_failed"), JsonValue::Bool(value));
    }
    if let Some(reason) = &observation.rejection_reason {
        record.insert(
            String::from("rejection_reason"),
            JsonValue::String(reason.clone()),
        );
    }
    if let Some(signatures) = &observation.signatures {
        record.insert(String::from("signatures"), signatures.clone());
    }
    if let Some(unsigned) = &observation.unsigned {
        record.insert(String::from("unsigned"), unsigned.clone());
    }
    if !observation.stripped.is_empty() {
        record.insert(
            String::from("stripped"),
            JsonValue::Object(observation.stripped.clone()),
        );
    }
    JsonValue::Object(record)
}

/// Derives the provenance status for one event from its observations.
///
/// Returns `(metadata_status, local_policy, disagreement_fields)`.
fn derive(group: &[(usize, &RawObservation)]) -> (&'static str, &'static str, Vec<String>) {
    let mut disagreements: BTreeSet<&'static str> = BTreeSet::new();
    if group
        .iter()
        .any(|(_, observation)| observation.stream_ordering_conflict)
    {
        disagreements.insert("stream_ordering");
    }
    if group.len() > 1 {
        if differing(group, |observation| observation.rejected) {
            disagreements.insert("rejected");
        }
        if differing(group, |observation| observation.soft_failed) {
            disagreements.insert("soft_failed");
        }
        let mut stream = BTreeSet::new();
        for (_, observation) in group {
            if let Some(value) = observation.stream_ordering {
                stream.insert(value);
            }
        }
        if stream.len() > 1 {
            disagreements.insert("stream_ordering");
        }
        let mut signatures = BTreeSet::new();
        for (_, observation) in group {
            if let Some(value) = &observation.signatures {
                if let Ok(serialized) = rezzy::json::write_string_value(value) {
                    signatures.insert(serialized);
                }
            }
        }
        if signatures.len() > 1 {
            disagreements.insert("signatures");
        }
    }
    if disagreements.is_empty() {
        let status = if group.len() <= 1 {
            "single_source"
        } else {
            "consistent"
        };
        (status, "accepted", Vec::new())
    } else {
        (
            "source_disagreement",
            "adjudication_pending",
            disagreements.into_iter().map(str::to_owned).collect(),
        )
    }
}

/// Returns whether `field` has more than one distinct present value.
fn differing(
    group: &[(usize, &RawObservation)],
    field: impl Fn(&RawObservation) -> Option<bool>,
) -> bool {
    let mut seen = BTreeSet::new();
    for (_, observation) in group {
        if let Some(value) = field(observation) {
            seen.insert(value);
        }
    }
    seen.len() > 1
}

fn optional_string(value: Option<&str>) -> JsonValue {
    value.map_or(JsonValue::Null, |value| JsonValue::String(value.to_owned()))
}

fn write_record(out: &mut Vec<u8>, value: &JsonValue) -> Result<(), AppError> {
    let line = rezzy::json::write_string_value(value).map_err(sidecar_error)?;
    out.extend_from_slice(line.as_bytes());
    out.push(b'\n');
    Ok(())
}

fn sidecar_error(error: impl core::fmt::Display) -> AppError {
    AppError::new(
        ErrorCode::MalformedJson,
        format!("cannot serialize provenance sidecar: {error}"),
    )
}

/// One event's stream-order facts read from a sidecar.
#[derive(Debug, Clone)]
pub struct SidecarEvent {
    /// `sha256:<hex>` of the merged event this record describes.
    pub payload_sha256: String,
    /// Unambiguous stream order, or `None` when absent or conflicting.
    pub stream_ordering: Option<u64>,
}

/// Parsed contents of a `.rezzy-meta.jsonl` sidecar.
#[derive(Debug, Clone)]
pub struct LoadedSidecar {
    /// The sidecar file this came from.
    pub path: PathBuf,
    /// Manifest `room_id`, if present.
    pub room_id: Option<String>,
    /// Manifest `room_version`, if present.
    pub room_version: Option<String>,
    /// SHA-256 of the aggregate file this sidecar was generated with.
    pub aggregate_sha256: Option<String>,
    /// Event records by `event_id`.
    pub events: BTreeMap<String, SidecarEvent>,
}

/// A validated `event_id -> stream_ordering` index for timeline ordering.
#[derive(Debug, Clone, Default)]
pub struct StreamOrderIndex {
    /// Stream order by `event_id`.
    pub by_event: BTreeMap<String, u64>,
}

impl StreamOrderIndex {
    /// The stream order for `event_id`, if known.
    #[must_use]
    pub fn get(&self, event_id: &str) -> Option<u64> {
        self.by_event.get(event_id).copied()
    }

    /// Whether no event has a known stream order.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_event.is_empty()
    }
}

/// Reads a `.rezzy-meta.jsonl` sidecar.
///
/// # Errors
/// Returns [`ErrorCode::IoError`] if the file cannot be read, or
/// [`ErrorCode::MalformedJson`] if a line is not a JSON object.
pub fn load_sidecar(path: &Path) -> Result<LoadedSidecar, AppError> {
    let bytes = std::fs::read(path)?;
    let mut loaded = LoadedSidecar {
        path: path.to_owned(),
        room_id: None,
        room_version: None,
        aggregate_sha256: None,
        events: BTreeMap::new(),
    };
    for (index, segment) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line = std::str::from_utf8(segment)
            .map_err(|error| malformed_sidecar(path, index, error))?
            .trim();
        if line.is_empty() {
            continue;
        }
        let value =
            JsonValue::parse(line).map_err(|error| malformed_sidecar(path, index, error))?;
        match value.get("record_type").and_then(JsonValue::as_str) {
            Some("manifest") => {
                loaded.room_id = value
                    .get("room_id")
                    .and_then(JsonValue::as_str)
                    .map(str::to_owned);
                loaded.room_version = value
                    .get("room_version")
                    .and_then(JsonValue::as_str)
                    .map(str::to_owned);
                loaded.aggregate_sha256 = value
                    .get("aggregate_sha256")
                    .and_then(JsonValue::as_str)
                    .map(str::to_owned);
            }
            Some("event") => {
                if let Some((event_id, event)) = sidecar_event(&value) {
                    loaded.events.insert(event_id, event);
                }
            }
            _ => {}
        }
    }
    Ok(loaded)
}

fn sidecar_event(value: &JsonValue) -> Option<(String, SidecarEvent)> {
    let event_id = value
        .get("event_id")
        .and_then(JsonValue::as_str)?
        .to_owned();
    let payload_sha256 = value
        .get("payload_sha256")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_owned();
    let mut values = BTreeSet::new();
    let mut conflicted = false;
    if let Some(observations) = value.get("observations").and_then(JsonValue::as_array) {
        for observation in observations {
            if observation
                .get("stream_ordering_conflict")
                .and_then(JsonValue::as_bool)
                .unwrap_or(false)
            {
                conflicted = true;
            }
            if let Some(stream) = observation
                .get("stream_ordering")
                .and_then(JsonValue::as_u64)
            {
                values.insert(stream);
            }
        }
    }
    let stream_ordering = if conflicted || values.len() > 1 {
        None
    } else {
        values.into_iter().next()
    };
    Some((
        event_id,
        SidecarEvent {
            payload_sha256,
            stream_ordering,
        },
    ))
}

fn malformed_sidecar(path: &Path, index: usize, error: impl core::fmt::Display) -> AppError {
    AppError::new(
        ErrorCode::MalformedJson,
        format!("{}:{}: {error}", path.display(), index.saturating_add(1)),
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn source(sha: &str, filename: &str) -> SourceInfo {
        SourceInfo {
            sha256: sha.to_owned(),
            filename: filename.to_owned(),
            source_kind: String::from("remote-dag"),
            server_hint: Some(String::from("matrix.org")),
            event_count: 1,
        }
    }

    fn observation(id: &str, line: usize, rejected: Option<bool>) -> RawObservation {
        RawObservation {
            event_id: id.to_owned(),
            line,
            raw_line_sha256: String::from("sha256:raw"),
            stream_ordering: Some(7),
            stream_ordering_key: Some(String::from("__stream_ordering")),
            stream_ordering_conflict: false,
            rejected,
            soft_failed: None,
            rejection_reason: None,
            signatures: None,
            unsigned: None,
            stripped: JsonObject::new(),
        }
    }

    #[test]
    fn sidecar_path_swaps_the_extension() {
        assert_eq!(
            sidecar_path(Path::new("merged/merged-room.jsonl")),
            PathBuf::from("merged/merged-room.rezzy-meta.jsonl")
        );
    }

    #[test]
    fn envelope_detection_rejects_dunder_fields() {
        assert!(is_matrix_envelope_key("signatures"));
        assert!(is_matrix_envelope_key("unsigned"));
        assert!(!is_matrix_envelope_key("__rejected"));
        assert!(!is_matrix_envelope_key("custom"));
    }

    #[test]
    fn strip_keeps_envelope_and_drops_everything_else() {
        let mut event = rezzy::json!({
            "event_id": "$a",
            "signatures": {"x": {"ed25519:0": "sig"}},
            "unsigned": {"age": 1},
            "content": {"body": "hi"},
            "__rejected": true,
            "custom": 9
        });
        strip_non_envelope_fields(&mut event);
        assert!(event.get("signatures").is_some());
        assert!(event.get("unsigned").is_some());
        assert!(event.get("content").is_some());
        assert!(event.get("__rejected").is_none());
        assert!(event.get("custom").is_none());
    }

    #[test]
    fn observe_normalizes_stream_ordering_aliases() {
        let raw = rezzy::json!({
            "event_id": "$a",
            "__pdu_count": 42,
            "__rejected": true,
            "unsigned": {"age": 1}
        });
        let observation = observe_raw_event(&raw, String::from("$a"), 3, String::from("sha256:r"));
        assert_eq!(observation.stream_ordering, Some(42));
        assert_eq!(
            observation.stream_ordering_key.as_deref(),
            Some("__pdu_count")
        );
        assert_eq!(observation.rejected, Some(true));
        assert!(observation.unsigned.is_some());
        assert!(observation.stripped.contains_key("__pdu_count"));
    }

    #[test]
    fn observe_flags_conflicting_stream_aliases() {
        let raw = rezzy::json!({"event_id": "$a", "__pdu_count": 1, "__stream_ordering": 2});
        let observation = observe_raw_event(&raw, String::from("$a"), 1, String::from("sha256:r"));
        assert!(observation.stream_ordering_conflict);
        assert_eq!(observation.stream_ordering, None);
    }

    #[test]
    fn sidecar_reports_source_disagreement() {
        let sources = vec![source("aa", "a.jsonl"), source("bb", "b.jsonl")];
        let observations = vec![
            (0, observation("$a", 1, Some(true))),
            (1, observation("$a", 5, Some(false))),
        ];
        let events = vec![rezzy::json!({"event_id": "$a", "depth": 1, "origin_server_ts": 1})];
        let bytes =
            build_sidecar(&sources, &observations, &events, Some("!r:x"), Some("12")).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "manifest plus one event");
        assert!(lines[0].contains("\"record_type\":\"manifest\""));
        assert!(lines[1].contains("\"metadata_status\":\"source_disagreement\""));
        assert!(lines[1].contains("\"local_policy\":\"adjudication_pending\""));
        assert!(lines[1].contains("\"rejected\""));
    }

    #[test]
    fn sidecar_marks_single_source() {
        let sources = vec![source("aa", "a.jsonl")];
        let observations = vec![(0, observation("$a", 1, Some(true)))];
        let events = vec![rezzy::json!({"event_id": "$a"})];
        let bytes = build_sidecar(&sources, &observations, &events, None, None).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("\"metadata_status\":\"single_source\""));
    }

    #[test]
    fn sidecar_omits_events_without_observations() {
        let sources = vec![source("aa", "a.jsonl")];
        let observations = vec![(0, observation("$a", 1, Some(true)))];
        let events = vec![
            rezzy::json!({"event_id": "$a"}),
            rezzy::json!({"event_id": "$b"}),
        ];
        let bytes = build_sidecar(&sources, &observations, &events, None, None).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap().lines().count(), 2);
    }

    #[test]
    fn load_sidecar_round_trips_manifest_and_stream_order() {
        let sources = vec![source("aa", "a.jsonl")];
        let observations = vec![(0, observation("$a", 1, Some(true)))];
        let events = vec![rezzy::json!({"event_id": "$a"})];
        let bytes =
            build_sidecar(&sources, &observations, &events, Some("!r:x"), Some("12")).unwrap();
        let path = write_temp_sidecar("round-trip", &bytes);

        let loaded = load_sidecar(&path).unwrap();
        assert_eq!(loaded.room_id.as_deref(), Some("!r:x"));
        assert_eq!(loaded.room_version.as_deref(), Some("12"));
        assert_eq!(
            loaded
                .events
                .get("$a")
                .and_then(|event| event.stream_ordering),
            Some(7)
        );

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn load_sidecar_drops_conflicting_stream_order() {
        let sources = vec![source("aa", "a.jsonl"), source("bb", "b.jsonl")];
        let mut first = observation("$a", 1, Some(true));
        first.stream_ordering = Some(1);
        let mut second = observation("$a", 2, Some(false));
        second.stream_ordering = Some(2);
        let observations = vec![(0, first), (1, second)];
        let events = vec![rezzy::json!({"event_id": "$a"})];
        let bytes = build_sidecar(&sources, &observations, &events, None, None).unwrap();
        let path = write_temp_sidecar("conflict", &bytes);

        let loaded = load_sidecar(&path).unwrap();
        assert_eq!(
            loaded
                .events
                .get("$a")
                .and_then(|event| event.stream_ordering),
            None,
            "conflicting stream order must not be guessed"
        );

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    fn write_temp_sidecar(name: &str, bytes: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rezzy-sidecar-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("merged-room.rezzy-meta.jsonl");
        std::fs::write(&path, bytes).unwrap();
        path
    }
}
