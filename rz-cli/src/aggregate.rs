//! Deterministic raw-JSONL aggregation with stale checks.

use crate::error::{AppError, ErrorCode};
use crate::jsonl_merge::merge_event_slices;
use clap::{Arg, ArgAction, ArgMatches, Command};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
struct Options {
    input_dir: PathBuf,
    room: String,
    output: PathBuf,
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
                .required(true)
                .help("Room slug used to select inputs and name the aggregate"),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .conflicts_with("output-dir")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("output-dir")
                .long("output-dir")
                .default_value("merged")
                .conflicts_with("output")
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
    let room = matches.get_one::<String>("room").unwrap().clone();
    let output = matches
        .get_one::<PathBuf>("output")
        .cloned()
        .unwrap_or_else(|| {
            matches
                .get_one::<PathBuf>("output-dir")
                .unwrap()
                .join(format!("merged-{room}.jsonl"))
        });
    Options {
        input_dir: matches.get_one::<PathBuf>("input-dir").unwrap().clone(),
        room,
        output,
        check: matches.get_flag("check"),
        quiet: matches.get_flag("quiet"),
    }
}

fn json_bytes(value: &rz_core::JsonValue) -> Result<Vec<u8>, AppError> {
    rz_core::json::write_string_value(value)
        .map(String::into_bytes)
        .map_err(|e| AppError::new(ErrorCode::MalformedJson, e.to_string()))
}

fn filename_matches_room(path: &Path, room: &str) -> bool {
    let Some(name) = path.file_stem().map(|name| name.to_string_lossy()) else {
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

fn filename_version(path: &Path) -> Option<String> {
    let name = path.file_stem()?.to_string_lossy();
    for (start, _) in name.match_indices("-v") {
        let suffix = name.get(start..)?.strip_prefix("-v")?;
        let digits: String = suffix.chars().take_while(char::is_ascii_digit).collect();
        let next = suffix.chars().nth(digits.chars().count());
        if !digits.is_empty() && !next.is_some_and(|character| character.is_ascii_alphanumeric()) {
            return Some(format!("-v{digits}"));
        }
    }
    None
}

fn normalized_path(path: &Path) -> Option<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    fs::canonicalize(&absolute).ok().or_else(|| {
        let parent = fs::canonicalize(absolute.parent()?).ok()?;
        Some(parent.join(absolute.file_name()?))
    })
}

fn same_path(left: &Path, right: &Path) -> bool {
    match (normalized_path(left), normalized_path(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn input_files(dir: &Path, room: &str, output: &Path) -> Result<Vec<PathBuf>, AppError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file()
            && !same_path(&path, output)
            && path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
            && filename_matches_room(&path, room)
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
    let versions: BTreeSet<String> = files
        .iter()
        .map(|path| filename_version(path).unwrap_or_else(|| "<none>".to_owned()))
        .collect();
    if versions.len() > 1 {
        return Err(AppError::new(
            ErrorCode::AggregateConflict,
            format!(
                "room slug {room} mixes versioned and unversioned or multiple versioned input filenames: {}",
                versions.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    Ok(files)
}

fn validate_event_ids(events: &[rz_core::JsonValue], label: &str) -> Result<(), AppError> {
    for event in events {
        if event["event_id"].as_str().map_or(true, str::is_empty) {
            return Err(AppError::new(
                ErrorCode::MalformedJson,
                format!("{label}: event is missing a non-empty string event_id"),
            ));
        }
    }
    Ok(())
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
        depth(a)
            .cmp(&depth(b))
            .then_with(|| ts(a).cmp(&ts(b)))
            .then_with(|| event_id(a).cmp(event_id(b)))
    });
    Ok(())
}

fn event_id(value: &rz_core::JsonValue) -> &str {
    value
        .get("event_id")
        .and_then(|value| value.as_str())
        .unwrap_or("")
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
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = std::str::from_utf8(line)
            .map_err(|e| AppError::new(ErrorCode::MalformedJson, format!("{label}: {e}")))?
            .trim();
        if !line.is_empty() {
            events.push(rz_core::JsonValue::parse(line)?);
        }
    }
    if events.is_empty() {
        return Err(AppError::new(
            ErrorCode::EmptyInput,
            format!("No input data provided in {label}"),
        ));
    }
    validate_event_ids(&events, &label)?;
    validate_sort_metadata(&events, &label)?;
    Ok(RawInput { label, events })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
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
        let _ = fs::File::open(parent).and_then(|directory| directory.sync_all());
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(AppError::from)
}

fn aggregate(options: &Options) -> Result<rz_core::JsonValue, AppError> {
    let files = input_files(&options.input_dir, &options.room, &options.output)?;
    let inputs: Vec<RawInput> = files
        .iter()
        .map(|path| read_raw_input(path, &options.input_dir))
        .collect::<Result<_, _>>()?;
    let sets: Vec<(String, &[rz_core::JsonValue])> = inputs
        .iter()
        .map(|input| (input.label.clone(), input.events.as_slice()))
        .collect();
    let merge = merge_event_slices(&sets, false, options.quiet)?;
    let mut events = merge.events;
    sort_events(&mut events)?;
    let output = output_bytes(&events)?;
    if options.check {
        let existing_output = fs::read(&options.output).map_err(|e| {
            AppError::new(
                ErrorCode::AggregateStale,
                format!("aggregate is unavailable: {e}"),
            )
        })?;
        if existing_output != output {
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
    write_atomic(&options.output, &output)?;
    Ok(
        rz_core::json!({"status": "written", "output": options.output.to_string_lossy().to_string(), "unique_events": events.len(), "input_files": files.len(), "duplicate_event_copies": merge.duplicate_copies}),
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
        rz_core::json!({
            "event_id": id,
            "type": "m.room.message",
            "sender": "@alice:example.org",
            "origin_server_ts": ts,
            "depth": depth,
            "prev_events": prev_events,
            "auth_events": []
        })
    }
    fn unique_test_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rezzy-aggregate-test-{}-{nanos}",
            std::process::id()
        ))
    }
    fn options(root: &Path, check: bool) -> Options {
        Options {
            input_dir: root.join("unmerged"),
            room: "room".to_owned(),
            output: root.join("merged/room.jsonl"),
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
        assert!(filename_matches_room(
            Path::new("remote-房间-v12.jsonl"),
            "房间"
        ));
    }

    #[test]
    fn version_detection_requires_a_delimited_numeric_token() {
        assert_eq!(
            filename_version(Path::new("room-v12-federated.jsonl")),
            Some("-v12".to_owned())
        );
        assert_eq!(filename_version(Path::new("room-v2Abc.jsonl")), None);
    }

    #[test]
    fn multiple_room_versions_are_rejected() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        fs::create_dir_all(&raw_dir).unwrap();
        fs::write(raw_dir.join("room-v11.jsonl"), b"{}\n").unwrap();
        fs::write(raw_dir.join("room-v12.jsonl"), b"{}\n").unwrap();
        let error = input_files(&raw_dir, "room", &root.join("merged-room.jsonl"))
            .expect_err("multiple versions should not share an aggregate");
        assert_eq!(error.code(), ErrorCode::AggregateConflict);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn versioned_and_unversioned_inputs_are_rejected() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        fs::create_dir_all(&raw_dir).unwrap();
        fs::write(raw_dir.join("room-v12.jsonl"), b"{}\n").unwrap();
        fs::write(raw_dir.join("room-other.jsonl"), b"{}\n").unwrap();
        let error = input_files(&raw_dir, "room", &root.join("merged-room.jsonl"))
            .expect_err("versioned and unversioned inputs should not mix");
        assert!(error.to_string().contains("versioned and unversioned"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_normalized_paths_are_not_equal() {
        let root = std::env::temp_dir().join(format!(
            "rezzy-missing-paths-{}-{}",
            std::process::id(),
            UNIX_EPOCH.elapsed().unwrap().as_nanos()
        ));
        assert!(!same_path(&root.join("a.jsonl"), &root.join("b.jsonl")));
    }

    #[test]
    fn relative_and_absolute_first_run_paths_match() {
        let root = PathBuf::from(format!(
            ".rezzy-relative-path-{}-{}",
            std::process::id(),
            UNIX_EPOCH.elapsed().unwrap().as_nanos()
        ));
        fs::create_dir_all(root.join("raw")).unwrap();
        let relative = root.join("raw/aggregate.jsonl");
        let absolute = std::env::current_dir().unwrap().join(&relative);
        assert!(!relative.exists());
        assert!(!absolute.exists());
        assert!(same_path(&relative, &absolute));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn output_name_uses_room_when_no_override_is_given() {
        let matches = command()
            .try_get_matches_from(["aggregate", "--room", "room"])
            .expect("room-only aggregate arguments should parse");
        let options = options_from_matches(&matches);
        assert_eq!(options.output, PathBuf::from("merged/merged-room.jsonl"));
    }
    #[test]
    fn aggregate_preserves_raw_and_detects_stale_inputs() {
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
        assert_eq!(
            input_files(&raw_dir, "room", &options(&root, false).output)
                .unwrap()
                .len(),
            2
        );
        let raw_before = fs::read(&first_path).unwrap();
        aggregate(&options(&root, false)).unwrap();
        assert_eq!(fs::read(&first_path).unwrap(), raw_before);
        assert!(root.join("merged/room.jsonl").exists());
        assert!(!root.join("merged/room.manifest.json").exists());
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
    fn output_file_is_not_reused_as_input() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        fs::create_dir_all(&raw_dir).unwrap();
        let output = raw_dir.join("merged-room.jsonl");
        fs::write(raw_dir.join("room-a.jsonl"), b"{}\n").unwrap();
        fs::write(&output, b"{}\n").unwrap();
        assert_eq!(input_files(&raw_dir, "room", &output).unwrap().len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_write_rejects_missing_parent_without_target() {
        let root = unique_test_dir();
        let error = write_atomic(&root.join("missing/aggregate.jsonl"), b"test").unwrap_err();
        assert_eq!(error.code(), ErrorCode::IoError);
        assert!(!root.join("missing/aggregate.jsonl").exists());
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

    #[test]
    fn conflicting_duplicate_ids_within_one_file_are_reported() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        fs::create_dir_all(&raw_dir).unwrap();
        let first = event("$same", 1, 100, &[]);
        let mut second = first.clone();
        second["origin_server_ts"] = rz_core::json!(101);
        let first_line = rz_core::json::write_string_value(&first).unwrap();
        let second_line = rz_core::json::write_string_value(&second).unwrap();
        fs::write(
            raw_dir.join("room-single.jsonl"),
            format!("{first_line}\n{second_line}\n"),
        )
        .unwrap();
        assert_eq!(
            aggregate(&options(&root, false)).unwrap_err().code(),
            ErrorCode::AggregateConflict
        );
        fs::remove_dir_all(root).unwrap();
    }
}
