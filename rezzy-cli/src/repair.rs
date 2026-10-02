//! Small repair utilities for federation JSONL exports.

use crate::error::{AppError, ErrorCode};
use clap::{Arg, ArgMatches, Command};
use rezzy::JsonValue;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

#[must_use]
/// Builds the `repair-ids` subcommand.
pub fn command() -> Command {
    Command::new("repair-ids")
        .about("Fill missing Matrix event IDs in a JSONL export")
        .arg(input_arg())
        .arg(output_arg(true))
}

/// Reject an `output` that names the same file as `input`.
///
/// A bare relative output resolves against the current directory, and an output
/// whose parent does not exist yet cannot alias an existing input.
///
/// # Errors
/// Returns an error if `input` cannot be resolved or both paths name one file.
pub(crate) fn ensure_distinct_paths(input: &Path, output: &Path) -> Result<(), AppError> {
    let input_identity = fs::canonicalize(input)?;
    let output_identity = if output.exists() {
        fs::canonicalize(output)?
    } else {
        let parent = output
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let Ok(parent) = fs::canonicalize(parent) else {
            return Ok(());
        };
        parent.join(
            output
                .file_name()
                .ok_or_else(|| AppError::new(ErrorCode::IoError, "output path has no file name"))?,
        )
    };
    if input_identity == output_identity {
        return Err(AppError::new(
            ErrorCode::IoError,
            "--input and --output must be different files",
        ));
    }
    Ok(())
}

/// The shared required `-i/--input` JSONL path argument.
#[must_use]
pub fn input_arg() -> Arg {
    Arg::new("input")
        .long("input")
        .short('i')
        .required(true)
        .value_parser(clap::value_parser!(PathBuf))
}

/// The shared `-o/--output` path argument; `required` makes it mandatory.
#[must_use]
pub fn output_arg(required: bool) -> Arg {
    Arg::new("output")
        .long("output")
        .short('o')
        .required(required)
        .value_parser(clap::value_parser!(PathBuf))
}

///
/// # Errors
/// Returns an error if the arguments, input, JSONL contents, room version, or
/// output file are invalid.
///
/// # Panics
/// Panics if the required arguments are absent; clap guarantees their presence
/// after successful command-line parsing.
pub fn run_from_matches(matches: &ArgMatches) -> Result<JsonValue, AppError> {
    let input = matches.get_one::<PathBuf>("input").expect("required");
    let output = matches.get_one::<PathBuf>("output").expect("required");
    ensure_distinct_paths(input, output)?;
    let room_version = infer_room_version(input)?;
    validate_repair_room_version(&room_version)?;

    let reader = BufReader::new(File::open(input)?);
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut writer = BufWriter::new(File::create(output)?);
    let mut total = 0_usize;
    let mut repaired = 0_usize;

    for (line_number, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let mut event = JsonValue::parse(&line).map_err(|e| {
            AppError::new(
                ErrorCode::MalformedJson,
                format!("{}:{}: {e}", input.display(), line_number.saturating_add(1)),
            )
        })?;
        repaired = repaired.saturating_add(fill_missing_event_id(
            &mut event,
            &room_version,
            &format!("{}:{}", input.display(), line_number.saturating_add(1)),
        )?);
        let encoded = rezzy::json::write_string_value(&event)
            .map_err(|e| AppError::new(ErrorCode::MalformedJson, e.to_string()))?;
        writeln!(writer, "{encoded}")?;
        total = total.saturating_add(1);
    }
    writer.flush()?;
    Ok(rezzy::json!({
        "input": input.to_string_lossy().to_string(),
        "output": output.to_string_lossy().to_string(),
        "events": total,
        "repaired": repaired,
    }))
}

///
/// # Errors
/// Returns an error if the event cannot be hashed or is not a JSON object.
pub fn fill_missing_event_id(
    event: &mut JsonValue,
    room_version: &str,
    label: &str,
) -> Result<usize, AppError> {
    let has_valid_event_id = event
        .get("event_id")
        .and_then(JsonValue::as_str)
        .is_some_and(|id| !id.is_empty());
    if has_valid_event_id {
        return Ok(0);
    }
    // Remove invalid or empty event_id before hashing so the hash
    // identifies the repaired event correctly.
    if let Some(obj) = event.as_object_mut() {
        obj.remove("event_id");
    }
    let hash = rezzy::reference_hash(event, room_version).map_err(|e| {
        AppError::new(
            ErrorCode::UnsupportedVersion,
            format!("{label}: cannot derive event ID: {e}"),
        )
    })?;
    event
        .as_object_mut()
        .ok_or_else(|| AppError::new(ErrorCode::UnexpectedFormat, "event is not a JSON object"))?
        .insert("event_id".to_owned(), JsonValue::String(format!("${hash}")));
    Ok(1)
}

///
/// # Errors
/// Returns an error if the room version is unsupported.
pub fn validate_repair_room_version(room_version: &str) -> Result<(), AppError> {
    let major = room_version
        .split('.')
        .next()
        .and_then(|part| part.parse::<u32>().ok());
    if major.is_some_and(|version| version <= 2) {
        return Err(AppError::new(
            ErrorCode::UnsupportedVersion,
            format!(
                "room version {room_version} has opaque event IDs; missing IDs cannot be repaired"
            ),
        ));
    }
    if rezzy::StateResVersion::from_room_version(room_version).is_none() {
        return Err(AppError::new(
            ErrorCode::UnsupportedVersion,
            format!("unknown room version {room_version}"),
        ));
    }
    Ok(())
}

fn infer_room_version(path: &Path) -> Result<String, AppError> {
    let name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::UnsupportedVersion,
                "cannot infer room version from filename",
            )
        })?;
    // Require a non-alphanumeric delimiter after the digit run (matching aggregation).
    let marker = name.rmatch_indices("-v").find_map(|(offset, _)| {
        let rest = &name[offset..];
        let after_marker = &rest[2..];
        let digits: String = after_marker
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let next = after_marker.chars().nth(digits.chars().count());
        if !digits.is_empty() && !next.is_some_and(|c| c.is_ascii_alphanumeric()) {
            Some(digits)
        } else {
            None
        }
    });
    marker.ok_or_else(|| {
        AppError::new(
            ErrorCode::UnsupportedVersion,
            format!("cannot infer room version from filename {}", path.display()),
        )
    })
}

/// Parse every non-empty line of a JSONL file into a JSON value.
///
/// # Errors
///
/// Returns an error when the file cannot be read, a line is malformed JSON, or
/// the contents are not valid UTF-8.
pub fn read_jsonl_events(path: &Path) -> Result<Vec<JsonValue>, AppError> {
    let text = fs::read_to_string(path)?;
    let mut events = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        events.push(JsonValue::parse(line).map_err(|e| {
            AppError::new(
                ErrorCode::MalformedJson,
                format!("{}:{}: {e}", path.display(), index.saturating_add(1)),
            )
        })?);
    }
    Ok(events)
}

/// Read newline-delimited event IDs from `path`, or standard input when `path`
/// is `-`.
///
/// Blank lines and `#` comments are skipped, and only `$…` tokens are kept, so
/// an emitted ID stream that also carries a JSON summary stays safe to feed
/// back in.
///
/// # Errors
///
/// Returns an error when the file cannot be read or contains invalid UTF-8.
pub fn read_event_ids(path: &Path) -> Result<Vec<String>, AppError> {
    let text = if path == Path::new("-") {
        let mut buffer = String::new();
        std::io::stdin().read_to_string(&mut buffer)?;
        buffer
    } else {
        fs::read_to_string(path)?
    };
    let mut seen = BTreeSet::new();
    let mut ids = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for token in event_id_tokens(line) {
            if seen.insert(token.clone()) {
                ids.push(token);
            }
        }
    }
    Ok(ids)
}

/// Write one event ID per line, creating parent directories as needed.
///
/// # Errors
///
/// Returns an error when the destination cannot be created or written.
pub fn write_event_ids(path: &Path, ids: &[String]) -> Result<(), AppError> {
    let mut text = String::new();
    for id in ids {
        text.push_str(id);
        text.push('\n');
    }
    if path == Path::new("-") {
        let mut stdout = std::io::stdout();
        stdout.write_all(text.as_bytes())?;
        stdout.flush()?;
        return Ok(());
    }
    if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text)?;
    Ok(())
}

/// Which reference list an event ID came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceKind {
    /// The `prev_events` field.
    PrevEvents,
    /// The `auth_events` field.
    AuthEvents,
}

impl ReferenceKind {
    /// The Matrix field this kind reads.
    #[must_use]
    pub const fn field(self) -> &'static str {
        match self {
            Self::PrevEvents => "prev_events",
            Self::AuthEvents => "auth_events",
        }
    }
}

/// References from one event, by kind, that no scanned event defines.
#[derive(Debug, Clone)]
pub struct MissingReference {
    /// The referencing event (empty when it has no usable `event_id`).
    pub event_id: String,
    /// Which reference list the missing IDs came from.
    pub kind: ReferenceKind,
    /// Referenced event IDs absent from the scanned events.
    pub missing: Vec<String>,
}

/// Local DAG gap report over a set of events.
#[derive(Debug, Default)]
pub struct GapReport {
    /// Event IDs defined by the scanned events.
    pub present: BTreeSet<String>,
    /// Referenced-but-absent IDs from `prev_events`.
    pub missing_prev: BTreeSet<String>,
    /// Referenced-but-absent IDs from `auth_events`.
    pub missing_auth: BTreeSet<String>,
    /// Per-event, per-kind breakdown of the missing references.
    pub references: Vec<MissingReference>,
}

impl GapReport {
    /// Every missing ID across both kinds, sorted.
    #[must_use]
    pub fn missing(&self) -> Vec<String> {
        self.missing_prev
            .union(&self.missing_auth)
            .cloned()
            .collect()
    }

    /// True when both reference lists are fully covered.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.missing_prev.is_empty() && self.missing_auth.is_empty()
    }
}

/// Scan `events` for IDs referenced by `prev_events`/`auth_events` that no
/// event in the set defines.
#[must_use]
pub fn scan_gaps(events: &[JsonValue]) -> GapReport {
    let present: BTreeSet<String> = events.iter().filter_map(event_id_of).collect();
    let mut report = GapReport {
        present: present.clone(),
        ..GapReport::default()
    };
    for event in events {
        let event_id = event_id_of(event).unwrap_or_default();
        for kind in [ReferenceKind::PrevEvents, ReferenceKind::AuthEvents] {
            let missing: Vec<String> = refs_for(event, kind)
                .into_iter()
                .filter(|id| !present.contains(id))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            if missing.is_empty() {
                continue;
            }
            match kind {
                ReferenceKind::PrevEvents => report.missing_prev.extend(missing.iter().cloned()),
                ReferenceKind::AuthEvents => report.missing_auth.extend(missing.iter().cloned()),
            }
            report.references.push(MissingReference {
                event_id: event_id.clone(),
                kind,
                missing,
            });
        }
    }
    report
}

/// The event IDs referenced by `prev_events`/`auth_events` of `events` that no
/// event in `events` defines, sorted and de-duplicated.
#[must_use]
pub fn referenced_but_absent(events: &[JsonValue]) -> Vec<String> {
    scan_gaps(events).missing()
}

fn refs_for(event: &JsonValue, kind: ReferenceKind) -> Vec<String> {
    event
        .get(kind.field())
        .and_then(JsonValue::as_array)
        .map(|items| items.iter().filter_map(reference_id).collect())
        .unwrap_or_default()
}

pub(crate) fn event_id_of(event: &JsonValue) -> Option<String> {
    event
        .get("event_id")
        .and_then(JsonValue::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
}

fn reference_id(item: &JsonValue) -> Option<String> {
    let id = item.as_str().or_else(|| {
        item.as_array()
            .and_then(|entries| entries.first())
            .and_then(JsonValue::as_str)
    })?;
    (!id.is_empty()).then(|| id.to_owned())
}

fn event_id_tokens(line: &str) -> impl Iterator<Item = String> + '_ {
    line.split(|c: char| c.is_whitespace() || matches!(c, '"' | ',' | '[' | ']' | '{' | '}'))
        .filter(|token| token.starts_with('$') && token.len() > 1)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::ensure_distinct_paths;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rezzy-repair-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rejects_output_that_is_the_input_file() {
        let dir = scratch("same");
        let input = dir.join("in.jsonl");
        std::fs::write(&input, "").unwrap();
        assert!(ensure_distinct_paths(&input, &input).is_err());
        assert!(ensure_distinct_paths(&input, &dir.join(".").join("in.jsonl")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accepts_distinct_and_not_yet_existing_outputs() {
        let dir = scratch("distinct");
        let input = dir.join("in.jsonl");
        std::fs::write(&input, "").unwrap();
        assert!(ensure_distinct_paths(&input, &dir.join("out.jsonl")).is_ok());
        assert!(ensure_distinct_paths(&input, &dir.join("missing").join("out.jsonl")).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bare_relative_output_resolves_against_current_directory() {
        let dir = scratch("bare");
        let input = dir.join("in.jsonl");
        std::fs::write(&input, "").unwrap();
        // Bare name resolves to the cwd, which is not the scratch dir.
        assert!(
            ensure_distinct_paths(&input, std::path::Path::new("out-does-not-exist.jsonl")).is_ok()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
