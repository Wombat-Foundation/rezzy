//! Deterministic raw-JSONL aggregation with provenance and stale checks.

use crate::error::{AppError, ErrorCode};
use crate::jsonl_merge::merge_event_sets;
use clap::{Arg, ArgAction, ArgMatches, Command};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MANIFEST_VERSION: u64 = 2;

#[derive(Debug)]
struct Options {
    input_dir: PathBuf,
    room: Option<String>,
    output: PathBuf,
    manifest: PathBuf,
    check: bool,
    quiet: bool,
}

#[must_use]
pub fn command() -> Command {
    Command::new("aggregate")
        .about("Aggregate raw Matrix event JSONL files without changing them")
        .arg(
            Arg::new("input-dir")
                .long("input-dir")
                .value_parser(clap::value_parser!(PathBuf))
                .default_value("unmerged"),
        )
        .arg(
            Arg::new("room")
                .long("room")
                .help("Filter filenames by a delimiter-bounded room slug"),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("manifest")
                .long("manifest")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(Arg::new("check").long("check").action(ArgAction::SetTrue))
        .arg(
            Arg::new("quiet")
                .long("quiet")
                .short('q')
                .action(ArgAction::SetTrue),
        )
}

fn options_from_matches(matches: &ArgMatches) -> Options {
    let output = matches.get_one::<PathBuf>("output").unwrap().clone();
    let manifest = matches
        .get_one::<PathBuf>("manifest")
        .cloned()
        .unwrap_or_else(|| {
            let stem = output
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("aggregate");
            output.with_file_name(format!("{stem}.manifest.json"))
        });
    Options {
        input_dir: matches.get_one::<PathBuf>("input-dir").unwrap().clone(),
        room: matches.get_one::<String>("room").cloned(),
        output,
        manifest,
        check: matches.get_flag("check"),
        quiet: matches.get_flag("quiet"),
    }
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn json_bytes(value: &rz_core::JsonValue) -> Result<Vec<u8>, AppError> {
    rz_core::json::write_string_value(value)
        .map(String::into_bytes)
        .map_err(|e| AppError::new(ErrorCode::MalformedJson, e.to_string()))
}

fn filename_matches_room(path: &Path, room: &str) -> bool {
    let Some(name) = path.file_name().map(|name| name.to_string_lossy()) else {
        return false;
    };
    let is_word = |byte: Option<u8>| byte.is_some_and(|b| b.is_ascii_alphanumeric());
    let mut offset = 0;
    while let Some(relative_start) = name[offset..].find(room) {
        let start = offset.saturating_add(relative_start);
        let end = start.saturating_add(room.len());
        if !is_word(
            start
                .checked_sub(1)
                .and_then(|index| name.as_bytes().get(index).copied()),
        ) && !is_word(name.as_bytes().get(end).copied())
        {
            return true;
        }
        offset = end;
        if offset >= name.len() {
            break;
        }
    }
    false
}

fn input_files(dir: &Path, room: Option<&str>) -> Result<Vec<PathBuf>, AppError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file()
            && path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
            && room.map_or(true, |needle| filename_matches_room(&path, needle))
        {
            files.push(path);
        }
    }
    files.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    if files.is_empty() {
        return Err(AppError::new(
            ErrorCode::EmptyInput,
            format!("No matching .jsonl files found in {}", dir.display()),
        ));
    }
    Ok(files)
}

fn validate_sort_metadata(events: &[rz_core::JsonValue], label: &str) -> Result<(), AppError> {
    for event in events {
        if event["depth"].as_u64().is_none() {
            return Err(AppError::new(
                ErrorCode::MalformedJson,
                format!("{label}: event is missing an unsigned numeric depth"),
            ));
        }
        if event["origin_server_ts"].as_u64().is_none() {
            return Err(AppError::new(
                ErrorCode::MalformedJson,
                format!("{label}: event is missing an unsigned numeric origin_server_ts"),
            ));
        }
    }
    Ok(())
}

fn sort_events(events: &mut [rz_core::JsonValue]) -> Result<(), AppError> {
    validate_sort_metadata(events, "merged aggregate")?;
    events.sort_by(|a, b| {
        let depth = |v: &rz_core::JsonValue| v["depth"].as_u64().unwrap();
        let ts = |v: &rz_core::JsonValue| v["origin_server_ts"].as_u64().unwrap();
        let id = |v: &rz_core::JsonValue| {
            v.get("event_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_owned()
        };
        depth(a)
            .cmp(&depth(b))
            .then_with(|| ts(a).cmp(&ts(b)))
            .then_with(|| id(a).cmp(&id(b)))
    });
    Ok(())
}

fn output_bytes(events: &[rz_core::JsonValue]) -> Result<Vec<u8>, AppError> {
    let mut bytes = Vec::new();
    for event in events {
        bytes.extend(json_bytes(event)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

struct RawInput {
    label: String,
    bytes: Vec<u8>,
    lines: usize,
    events: Vec<rz_core::JsonValue>,
}

fn read_raw_input(path: &Path, input_dir: &Path) -> Result<RawInput, AppError> {
    let bytes = fs::read(path)?;
    let label = path
        .strip_prefix(input_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned();
    let mut events = Vec::new();
    let mut lines = 0usize;
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = std::str::from_utf8(line)
            .map_err(|e| AppError::new(ErrorCode::MalformedJson, format!("{label}: {e}")))?
            .trim();
        if !line.is_empty() {
            lines = lines.saturating_add(1);
            events.push(rz_core::JsonValue::parse(line)?);
        }
    }
    if events.is_empty() {
        return Err(AppError::new(
            ErrorCode::EmptyInput,
            format!("No input data provided in {label}"),
        ));
    }
    validate_sort_metadata(&events, &label)?;
    Ok(RawInput {
        label,
        bytes,
        lines,
        events,
    })
}

fn manifest_value(
    inputs: &[RawInput],
    room: Option<&str>,
    output: &[u8],
    event_count: usize,
    duplicate_count: usize,
) -> rz_core::JsonValue {
    let files: Vec<rz_core::JsonValue> = inputs
        .iter()
        .map(|input| {
            rz_core::json!({
                "path": input.label.clone(),
                "sha256": sha256(&input.bytes),
                "bytes": input.bytes.len(),
                "lines": input.lines
            })
        })
        .collect();
    rz_core::json!({
        "manifest_version": MANIFEST_VERSION,
        "algorithm": "deduplicate by event_id; sort by depth, origin_server_ts, event_id",
        "room_filter": room.unwrap_or(""),
        "inputs": files,
        "unique_events": event_count,
        "duplicate_event_copies": duplicate_count,
        "output": {"sha256": sha256(output), "bytes": output.len()}
    })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("aggregate");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temp = parent.join(format!(".{name}.tmp-{}-{nonce}", std::process::id()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(AppError::from)
}

fn aggregate(options: &Options) -> Result<rz_core::JsonValue, AppError> {
    let files = input_files(&options.input_dir, options.room.as_deref())?;
    let inputs: Vec<RawInput> = files
        .iter()
        .map(|path| read_raw_input(path, &options.input_dir))
        .collect::<Result<_, _>>()?;
    let sets: Vec<(String, Vec<rz_core::JsonValue>)> = inputs
        .iter()
        .map(|input| (input.label.clone(), input.events.clone()))
        .collect();
    let mut events = merge_event_sets(&sets, false, options.quiet)?;
    let input_event_count: usize = inputs.iter().map(|input| input.events.len()).sum();
    sort_events(&mut events)?;
    let duplicate_count = input_event_count.saturating_sub(events.len());
    let output = output_bytes(&events)?;
    let manifest = manifest_value(
        &inputs,
        options.room.as_deref(),
        &output,
        events.len(),
        duplicate_count,
    );

    if options.check {
        let existing_output = fs::read(&options.output).map_err(|e| {
            AppError::new(
                ErrorCode::AggregateStale,
                format!("aggregate is unavailable: {e}"),
            )
        })?;
        let existing_manifest = fs::read(&options.manifest).map_err(|e| {
            AppError::new(
                ErrorCode::AggregateStale,
                format!("manifest is unavailable: {e}"),
            )
        })?;
        let parsed = rz_core::JsonValue::parse_bytes(&existing_manifest).map_err(|e| {
            AppError::new(
                ErrorCode::AggregateStale,
                format!("manifest is invalid: {e}"),
            )
        })?;
        if parsed["manifest_version"].as_u64() != Some(MANIFEST_VERSION) {
            return Err(AppError::new(
                ErrorCode::AggregateStale,
                "manifest version is outdated; rerun without --check to regenerate it",
            ));
        }
        if existing_output != output || parsed != manifest {
            return Err(AppError::new(
                ErrorCode::AggregateStale,
                format!(
                    "{} is stale; rerun without --check to regenerate it",
                    options.output.display()
                ),
            ));
        }
        return Ok(rz_core::json!({"status": "current", "unique_events": events.len()}));
    }
    if let Some(parent) = options.output.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = options.manifest.parent() {
        fs::create_dir_all(parent)?;
    }
    write_atomic(&options.output, &output)?;
    write_atomic(&options.manifest, &json_bytes(&manifest)?)?;
    Ok(
        rz_core::json!({"status": "written", "output": options.output.to_string_lossy().to_string(), "manifest": options.manifest.to_string_lossy().to_string(), "unique_events": events.len(), "input_files": files.len(), "duplicate_event_copies": duplicate_count}),
    )
}

/// Run the aggregation command from parsed arguments.
///
/// # Errors
///
/// Returns an error when an input is malformed, duplicate event IDs conflict,
/// files cannot be read or written, or an existing aggregate is stale.
pub fn run_from_matches(matches: &ArgMatches) -> Result<rz_core::JsonValue, AppError> {
    aggregate(&options_from_matches(matches))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn event(id: &str, depth: u64, ts: u64, prev_events: &[&str]) -> rz_core::JsonValue {
        rz_core::json!({"event_id": id, "type": "m.room.message", "sender": "@alice:example.org", "origin_server_ts": ts, "depth": depth, "prev_events": prev_events, "auth_events": []})
    }
    fn unique_test_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rezzy-aggregate-test-{}-{nanos}",
            std::process::id()
        ))
    }
    fn options(root: &Path, check: bool) -> Options {
        Options {
            input_dir: root.join("unmerged"),
            room: Some("room".to_owned()),
            output: root.join("merged/room.jsonl"),
            manifest: root.join("merged/room.manifest.json"),
            check,
            quiet: true,
        }
    }
    #[test]
    fn sorting_rejects_missing_metadata_and_uses_event_id_tiebreaker() {
        let mut events = vec![event("$b", 2, 100, &["$a"]), event("$a", 1, 200, &[])];
        sort_events(&mut events).unwrap();
        assert_eq!(events[0]["event_id"], "$a");
        let mut missing = vec![rz_core::json!({"event_id": "$bad"})];
        assert!(validate_sort_metadata(&missing, "test").is_err());
        missing[0]["depth"] = rz_core::json!(1);
        assert!(validate_sort_metadata(&missing, "test").is_err());
    }
    #[test]
    fn room_filter_is_delimiter_bounded() {
        assert!(filename_matches_room(
            Path::new("remote-room-v12.jsonl"),
            "room"
        ));
        assert!(!filename_matches_room(
            Path::new("remote-roommate-v12.jsonl"),
            "room"
        ));
    }
    #[test]
    fn aggregate_preserves_raw_manifest_roundtrip_and_detects_stale_inputs() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        fs::create_dir_all(&raw_dir).unwrap();
        let first = event("$a", 1, 100, &[]);
        let second = event("$b", 2, 200, &["$a"]);
        let first_line = format!("{}\n", rz_core::json::write_string_value(&first).unwrap());
        let second_line = format!("{}\n", rz_core::json::write_string_value(&second).unwrap());
        let first_path = raw_dir.join("room-a.jsonl");
        let second_path = raw_dir.join("room-b.jsonl");
        fs::write(&first_path, &first_line).unwrap();
        fs::write(&second_path, &second_line).unwrap();
        assert!(filename_matches_room(&first_path, "room"));
        assert_eq!(input_files(&raw_dir, Some("room")).unwrap().len(), 2);
        let raw_before = fs::read(&first_path).unwrap();
        aggregate(&options(&root, false)).unwrap();
        assert_eq!(fs::read(&first_path).unwrap(), raw_before);
        let manifest = rz_core::JsonValue::parse_bytes(
            &fs::read(root.join("merged/room.manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            manifest["inputs"].as_array().unwrap()[0]["lines"].as_u64(),
            Some(1)
        );
        assert_eq!(
            aggregate(&options(&root, true)).unwrap()["status"],
            "current"
        );
        fs::write(root.join("merged/room.jsonl"), b"tampered\n").unwrap();
        assert_eq!(
            aggregate(&options(&root, true)).unwrap_err().code(),
            ErrorCode::AggregateStale
        );
        aggregate(&options(&root, false)).unwrap();
        let third = event("$c", 3, 300, &["$b"]);
        let third_line = format!("{}\n", rz_core::json::write_string_value(&third).unwrap());
        fs::write(&second_path, format!("{second_line}{third_line}")).unwrap();
        assert_eq!(
            aggregate(&options(&root, true)).unwrap_err().code(),
            ErrorCode::AggregateStale
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_directory_is_rejected() {
        let root = unique_test_dir();
        fs::create_dir_all(root.join("unmerged")).unwrap();
        assert_eq!(
            aggregate(&options(&root, false)).unwrap_err().code(),
            ErrorCode::EmptyInput
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_write_requires_a_valid_parent() {
        let root = unique_test_dir();
        let error = write_atomic(&root.join("missing/aggregate.jsonl"), b"test").unwrap_err();
        assert_eq!(error.code(), ErrorCode::IoError);
    }
    #[test]
    fn conflicting_duplicate_ids_fail() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        fs::create_dir_all(&raw_dir).unwrap();
        let a = event("$same", 1, 100, &[]);
        let mut b = a.clone();
        b["origin_server_ts"] = rz_core::json!(101);
        fs::write(
            raw_dir.join("room-a.jsonl"),
            format!("{}\n", rz_core::json::write_string_value(&a).unwrap()),
        )
        .unwrap();
        fs::write(
            raw_dir.join("room-b.jsonl"),
            format!("{}\n", rz_core::json::write_string_value(&b).unwrap()),
        )
        .unwrap();
        assert_eq!(
            aggregate(&options(&root, false)).unwrap_err().code(),
            ErrorCode::AggregateConflict
        );
        fs::remove_dir_all(root).unwrap();
    }
}
