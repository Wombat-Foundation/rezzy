//! Deterministic raw-JSONL aggregation with stale checks.

use crate::error::{AppError, ErrorCode};
use crate::jsonl_merge::merge_event_slices;
use clap::{Arg, ArgAction, ArgMatches, Command};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_INPUT_DIR: &str = "unmerged";
const DEFAULT_OUTPUT_DIR: &str = "merged";

/// Where an aggregate gets its raw inputs from.
#[derive(Debug)]
enum Source {
    /// Every matching `.jsonl` file in `input_dir` for one room slug.
    Dir { room: String },
    /// An explicit, already-grouped set of raw input files.
    Files(Vec<PathBuf>),
}

#[derive(Debug)]
struct Options {
    input_dir: PathBuf,
    source: Source,
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
                .default_value(DEFAULT_INPUT_DIR),
        )
        .arg(
            Arg::new("room")
                .long("room")
                .conflicts_with("input")
                .help("Room slug to select from --input-dir; omit to aggregate every room found there"),
        )
        .arg(
            Arg::new("input")
                .long("input")
                .short('i')
                .num_args(1..)
                .value_parser(clap::value_parser!(PathBuf))
                .help("Explicit input files; grouped by room slug (derived from filename) and each group aggregated"),
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
                .default_value(DEFAULT_OUTPUT_DIR)
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
    let room = matches
        .get_one::<String>("room")
        .cloned()
        .unwrap_or_default();
    let output = matches
        .get_one::<PathBuf>("output")
        .cloned()
        .unwrap_or_else(|| {
            matches
                .get_one::<PathBuf>("output-dir")
                .cloned()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT_DIR))
                .join(format!("merged-{room}.jsonl"))
        });
    Options {
        input_dir: matches
            .get_one::<PathBuf>("input-dir")
            .cloned()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_INPUT_DIR)),
        source: Source::Dir { room },
        output,
        check: matches.get_flag("check"),
        quiet: matches.get_flag("quiet"),
    }
}

/// The output directory an aggregate writes into.
fn output_dir(options: &Options) -> &Path {
    options
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
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
    version_token(&path.file_stem()?.to_string_lossy())
}

/// First delimited `-v<digits>` token in `name`: the byte offset of its
/// leading `-`, plus the digit run (without the `-v`).
fn version_token_at(name: &str) -> Option<(usize, String)> {
    for (start, _) in name.match_indices("-v") {
        let rest = &name[start..];
        let after_marker = &rest[2..];
        let digits: String = after_marker
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let next = after_marker.chars().nth(digits.chars().count());
        if !digits.is_empty() && !next.is_some_and(|character| character.is_ascii_alphanumeric()) {
            return Some((start, digits));
        }
    }
    None
}

fn version_token(name: &str) -> Option<String> {
    let (_, digits) = version_token_at(name)?;
    Some(format!("-v{digits}"))
}

/// Room slug from a raw filename: drops `local-`/`remote-` and `dag-`
/// prefixes and the per-server suffix following the `-v<number>` token.
///
/// The returned slug is the filename truncated after the *matching* version
/// token, so `remote-room-v12-merged.jsonl` and `local-dag-room-v12.jsonl`
/// both yield `room-v12`. Returns `None` when no version token is present.
fn room_slug_from_filename(path: &Path) -> Option<String> {
    let name = path.file_stem()?.to_string_lossy();
    let name = name
        .strip_prefix("local-")
        .or_else(|| name.strip_prefix("remote-"))
        .unwrap_or(&name);
    let name = name.strip_prefix("dag-").unwrap_or(name);
    let (start, digits) = version_token_at(name)?;
    Some(format!("{}-v{}", &name[..start], digits))
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

fn input_files(dir: &Path, room: &str) -> Result<Vec<PathBuf>, AppError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if is_jsonl(&path) && filename_matches_room(&path, room) {
            files.push(path);
        }
    }
    files.sort();
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

fn is_jsonl(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
}

/// Every `.jsonl` file directly inside `dir`, sorted for deterministic grouping.
///
/// Errors distinguish an unreadable/missing directory from one with no JSONL
/// files at all. Symlinks to files count (`is_file` follows them); duplicate
/// links to one file are harmless because the merge dedupes by event id.
fn directory_inputs(dir: &Path) -> Result<Vec<PathBuf>, AppError> {
    let entries = fs::read_dir(dir).map_err(|e| {
        AppError::new(
            ErrorCode::IoError,
            format!("cannot read input directory {}: {e}", dir.display()),
        )
    })?;
    let mut files = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if is_jsonl(&path) {
            files.push(path);
        }
    }
    files.sort();
    if files.is_empty() {
        return Err(AppError::new(
            ErrorCode::EmptyInput,
            format!("no .jsonl files found in {}", dir.display()),
        ));
    }
    Ok(files)
}

/// Room groups plus the files a scan skipped because they carried no slug.
#[derive(Debug)]
struct Grouping {
    rooms: BTreeMap<String, Vec<PathBuf>>,
    skipped: Vec<PathBuf>,
}

/// Group raw input files by derived room slug.
///
/// Explicit `-i` files must all yield a slug (`skip_unslugged == false`);
/// directory scans skip unversioned filenames with a warning instead, since a
/// user cannot hand-pick what a scan happens to see. Skipped files are still
/// returned so the report can surface them even under `--quiet`.
fn group_by_room(
    files: impl IntoIterator<Item = PathBuf>,
    skip_unslugged: bool,
    quiet: bool,
) -> Result<Grouping, AppError> {
    let mut rooms: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    let mut skipped = Vec::new();
    for path in files {
        match room_slug_from_filename(&path) {
            Some(slug) => rooms.entry(slug).or_default().push(path),
            None if skip_unslugged => {
                if !quiet {
                    eprintln!(
                        "[WARN] skipping {}: no versioned room slug in filename",
                        path.display()
                    );
                }
                skipped.push(path);
            }
            None => {
                return Err(AppError::new(
                    ErrorCode::AggregateConflict,
                    format!(
                        "cannot derive a versioned room slug from {}",
                        path.display()
                    ),
                ));
            }
        }
    }
    Ok(Grouping { rooms, skipped })
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

fn reject_input_output_overlap(options: &Options) -> Result<(), AppError> {
    if same_path(&options.input_dir, output_dir(options)) {
        return Err(AppError::new(
            ErrorCode::AggregateConflict,
            format!(
                "input directory {} and output directory {} must be different",
                options.input_dir.display(),
                output_dir(options).display()
            ),
        ));
    }
    Ok(())
}

/// Reject explicit `-i` inputs that would collide with, or be rewritten as,
/// the aggregate output.
///
/// This mirrors the directory-mode check but only rejects inputs that are the
/// output itself or a direct child of its directory: directory discovery is
/// non-recursive, so deeper subdirectories cannot be swept back in. Symlinked
/// paths compare by their [`normalized_path`] resolution.
fn reject_explicit_output_overlap(options: &Options, files: &[PathBuf]) -> Result<(), AppError> {
    let destination = output_dir(options);
    for file in files {
        if same_path(file, &options.output) {
            return Err(AppError::new(
                ErrorCode::AggregateConflict,
                format!(
                    "input file {} is the same as the output file {}",
                    file.display(),
                    options.output.display()
                ),
            ));
        }
        let parent_matches = normalized_path(file)
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .zip(normalized_path(destination))
            .is_some_and(|(parent, output)| parent == output);
        if parent_matches {
            return Err(AppError::new(
                ErrorCode::AggregateConflict,
                format!(
                    "input file {} is inside output directory {}; use a different --output-dir",
                    file.display(),
                    destination.display()
                ),
            ));
        }
    }
    Ok(())
}

fn aggregate(options: &Options) -> Result<rz_core::JsonValue, AppError> {
    let (files, label_base) = match &options.source {
        Source::Files(files) => {
            reject_explicit_output_overlap(options, files)?;
            (files.clone(), Path::new(""))
        }
        Source::Dir { room } => {
            reject_input_output_overlap(options)?;
            (
                input_files(&options.input_dir, room)?,
                options.input_dir.as_path(),
            )
        }
    };
    let inputs: Vec<RawInput> = files
        .iter()
        .map(|path| read_raw_input(path, label_base))
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

/// Outcome of an aggregate command.
#[derive(Debug)]
pub enum AggregateOutcome {
    /// Every requested room aggregated successfully.
    Complete(rz_core::JsonValue),
    /// Some rooms failed; the JSON still carries every per-room result and a
    /// structured error entry for each failure.
    Partial(rz_core::JsonValue),
}

/// Run the aggregation command from parsed arguments.
///
/// Three input modes:
///
/// - `--room <slug>`: directory mode, returns the bare single-room result.
/// - `-i FILES...`: group explicit files; every file must yield a slug.
/// - neither: scan `--input-dir`, group every `.jsonl` by derived slug, and
///   skip unversioned filenames with a warning.
///
/// `-i` and scan mode always return the report object
/// (`status`/`failed`/`skipped`/`rooms`), even for a single room. `-i` never
/// skips, so its `skipped` array is always empty; only scan mode fills it.
///
/// `--room` and scan mode select differently by design. `--room` matches a
/// delimiter-bounded substring in the filename and names the output from the
/// token as given, so it also accepts unversioned files. Scan mode requires a
/// `-v<number>` token and names the output from the derived slug, which
/// includes that version. Passing a derived slug to `--room` selects the same
/// inputs and writes the same output name.
///
/// Explicit `-i` slug failures abort the whole run before any room is
/// processed; per-room aggregation failures are reported in the `Partial`
/// outcome, so a bad room never discards a good one.
///
/// # Errors
///
/// Returns an error when an input is malformed, duplicate event IDs conflict,
/// files cannot be read or written, an existing aggregate is stale, an explicit
/// `-i` filename has no derivable room slug, `--input-dir` has no versioned
/// inputs, or `-o` is combined with multi-room input.
pub fn run_from_matches(matches: &ArgMatches) -> Result<AggregateOutcome, AppError> {
    let base = options_from_matches(matches);
    let (inputs, skip_unslugged, scanning) =
        if let Some(inputs) = matches.get_many::<PathBuf>("input") {
            (inputs.cloned().collect::<Vec<_>>(), false, false)
        } else if matches.get_one::<String>("room").is_some() {
            return aggregate(&base).map(AggregateOutcome::Complete);
        } else {
            // `base.output` carries the empty-room placeholder `merged-.jsonl`;
            // only its parent directory is meaningful here, for the overlap
            // check. Every room below rebuilds its own output path.
            reject_input_output_overlap(&base)?;
            (directory_inputs(&base.input_dir)?, true, true)
        };
    let grouping = group_by_room(inputs, skip_unslugged, base.quiet)?;
    if scanning && grouping.rooms.is_empty() {
        return Err(AppError::new(
            ErrorCode::EmptyInput,
            format!(
                "no versioned .jsonl files found in {}; expected a `-v<number>` token in filenames",
                base.input_dir.display()
            ),
        ));
    }
    let skipped: Vec<rz_core::JsonValue> = grouping
        .skipped
        .iter()
        .map(|path| rz_core::json!(path.to_string_lossy().into_owned()))
        .collect();
    let groups = grouping.rooms;
    let output_override = matches.get_one::<PathBuf>("output").cloned();
    let default_output_dir = matches
        .get_one::<PathBuf>("output-dir")
        .cloned()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT_DIR));
    if output_override.is_some() && groups.len() > 1 {
        return Err(AppError::new(
            ErrorCode::AggregateConflict,
            format!(
                "-o needs a single room, but inputs span {} rooms",
                groups.len()
            ),
        ));
    }
    let mut rooms = Vec::new();
    let mut failed = 0_usize;
    for (room, files) in groups {
        let output = output_override
            .clone()
            .unwrap_or_else(|| default_output_dir.join(format!("merged-{room}.jsonl")));
        let options = Options {
            source: Source::Files(files),
            input_dir: base.input_dir.clone(),
            output,
            check: base.check,
            quiet: base.quiet,
        };
        match aggregate(&options) {
            Ok(mut result) => {
                debug_assert!(
                    result.is_object(),
                    "aggregate result is a JSON object, so the room tag lands"
                );
                let _ = result.insert("room".to_owned(), rz_core::json!(room));
                rooms.push(result);
            }
            Err(e) => {
                failed = failed.saturating_add(1);
                rooms.push(rz_core::json!({
                    "room": room,
                    "status": "error",
                    "code": e.code().code(),
                    "error": e.to_string(),
                }));
            }
        }
    }
    let report = rz_core::json!({
        "status": if failed == 0 { "written" } else { "partial" },
        "failed": failed,
        "skipped": skipped,
        "rooms": rooms,
    });
    if failed > 0 {
        Ok(AggregateOutcome::Partial(report))
    } else {
        Ok(AggregateOutcome::Complete(report))
    }
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
            source: Source::Dir {
                room: "room".to_owned(),
            },
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
        let error = input_files(&raw_dir, "room")
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
        let error = input_files(&raw_dir, "room")
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
        let relative = PathBuf::from(".rezzy-nonexistent-aggregate.jsonl");
        let absolute = std::env::current_dir().unwrap().join(&relative);
        assert!(!relative.exists());
        assert!(!absolute.exists());
        assert!(same_path(&relative, &absolute));
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
        assert_eq!(input_files(&raw_dir, "room").unwrap().len(), 2);
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
    fn input_and_output_directories_must_differ() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        fs::create_dir_all(&raw_dir).unwrap();
        let mut overlapping = options(&root, false);
        overlapping.output = raw_dir.join("merged-room.jsonl");
        let error = aggregate(&overlapping).expect_err("directory overlap should be rejected");
        assert_eq!(error.code(), ErrorCode::AggregateConflict);
        assert!(error.to_string().contains("must be different"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bare_output_name_rejects_current_directory_input() {
        let options = Options {
            input_dir: PathBuf::from("."),
            source: Source::Dir {
                room: "room".to_owned(),
            },
            output: PathBuf::from("out.jsonl"),
            check: false,
            quiet: true,
        };
        let error = reject_input_output_overlap(&options)
            .expect_err("a bare output name belongs to the current directory");
        assert_eq!(error.code(), ErrorCode::AggregateConflict);
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

    #[test]
    fn room_slug_truncates_at_the_matching_version_token() {
        assert_eq!(
            room_slug_from_filename(Path::new("remote-room-v12x-v12-merged.jsonl")),
            Some("room-v12x-v12".to_owned())
        );
        assert_eq!(
            room_slug_from_filename(Path::new("local-room-v12.jsonl")),
            Some("room-v12".to_owned())
        );
    }

    #[test]
    fn room_slug_is_shared_across_raw_filename_styles() {
        let expected = Some("room-v12".to_owned());
        for name in [
            "local-room-v12.jsonl",
            "remote-room-v12.jsonl",
            "remote-dag-room-v12-merged.jsonl",
            "local-dag-room-v12.jsonl",
        ] {
            assert_eq!(room_slug_from_filename(Path::new(name)), expected, "{name}");
        }
    }

    #[test]
    fn room_slug_requires_a_version_token() {
        assert_eq!(room_slug_from_filename(Path::new("room.jsonl")), None);
        assert_eq!(
            room_slug_from_filename(Path::new("remote-room.jsonl")),
            None
        );
    }

    #[test]
    fn explicit_input_labels_keep_the_full_path() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        fs::create_dir_all(&raw_dir).unwrap();
        let path = raw_dir.join("remote-room-v12.jsonl");
        let only = event("$a", 1, 100, &[]);
        fs::write(
            &path,
            format!("{}\n", rz_core::json::write_string_value(&only).unwrap()),
        )
        .unwrap();
        let input = read_raw_input(&path, Path::new("")).unwrap();
        assert_eq!(input.label, path.to_string_lossy());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_input_inside_output_directory_is_rejected() {
        let root = unique_test_dir();
        let existing = root.join("merged/local-room-v12.jsonl");
        fs::create_dir_all(existing.parent().unwrap()).unwrap();
        fs::write(&existing, b"{}\n").unwrap();
        let mut options = options(&root, false);
        options.source = Source::Files(vec![existing]);
        options.output = root.join("merged/merged-room.jsonl");
        let error = aggregate(&options).expect_err("input inside output dir should be rejected");
        assert_eq!(error.code(), ErrorCode::AggregateConflict);
        assert!(error.to_string().contains("inside output directory"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_input_equal_to_output_is_rejected() {
        let root = unique_test_dir();
        let output = root.join("merged/merged-room.jsonl");
        fs::create_dir_all(output.parent().unwrap()).unwrap();
        fs::write(&output, b"{}\n").unwrap();
        let mut options = options(&root, false);
        options.source = Source::Files(vec![output.clone()]);
        options.output = output;
        let error = aggregate(&options).expect_err("input equal to output should be rejected");
        assert_eq!(error.code(), ErrorCode::AggregateConflict);
        assert!(error.to_string().contains("same as the output file"));
        fs::remove_dir_all(root).unwrap();
    }

    fn explicit_matches(paths: &[&Path], extra: &[&str]) -> ArgMatches {
        let mut args: Vec<String> = vec!["aggregate".to_owned(), "-i".to_owned()];
        args.extend(paths.iter().map(|path| path.to_string_lossy().into_owned()));
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        command()
            .try_get_matches_from(args)
            .expect("explicit aggregate arguments should parse")
    }

    fn scan_matches(input_dir: &Path, extra: &[&str]) -> ArgMatches {
        let mut args: Vec<String> = vec![
            "aggregate".to_owned(),
            "--input-dir".to_owned(),
            input_dir.to_string_lossy().into_owned(),
        ];
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        command()
            .try_get_matches_from(args)
            .expect("scan aggregate arguments should parse")
    }

    fn room_matches(input_dir: &Path, room: &str, extra: &[&str]) -> ArgMatches {
        let mut args: Vec<String> = vec![
            "aggregate".to_owned(),
            "--input-dir".to_owned(),
            input_dir.to_string_lossy().into_owned(),
            "--room".to_owned(),
            room.to_owned(),
        ];
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        command()
            .try_get_matches_from(args)
            .expect("room aggregate arguments should parse")
    }

    fn room_file(dir: &Path, name: &str, id: &str) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        let only = event(id, 1, 100, &[]);
        fs::write(
            &path,
            format!("{}\n", rz_core::json::write_string_value(&only).unwrap()),
        )
        .unwrap();
        path
    }

    #[test]
    fn explicit_inputs_group_by_room_and_write_each_aggregate() {
        let root = unique_test_dir();
        let raw_dir = root.join("raw");
        let first = room_file(&raw_dir, "remote-room-a-v12.jsonl", "$a");
        let second = room_file(&raw_dir, "local-room-b-v12.jsonl", "$b");
        let out_dir = root.join("merged");
        let out_dir_lossy = out_dir.to_string_lossy();
        let matches = explicit_matches(
            &[first.as_path(), second.as_path()],
            &["--output-dir", out_dir_lossy.as_ref()],
        );
        let report = match run_from_matches(&matches).unwrap() {
            AggregateOutcome::Complete(report) => report,
            AggregateOutcome::Partial(report) => panic!("unexpected partial: {report:?}"),
        };
        assert_eq!(report["status"].as_str(), Some("written"));
        assert_eq!(report["failed"].as_u64(), Some(0));
        assert_eq!(report["rooms"].as_array().unwrap().len(), 2);
        assert!(out_dir.join("merged-room-a-v12.jsonl").exists());
        assert!(out_dir.join("merged-room-b-v12.jsonl").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn output_override_requires_a_single_room() {
        let root = unique_test_dir();
        let first = root.join("room-a-v12.jsonl");
        let second = root.join("room-b-v12.jsonl");
        let matches = explicit_matches(&[first.as_path(), second.as_path()], &["-o", "out.jsonl"]);
        let error = run_from_matches(&matches).expect_err("multi-room -o should fail");
        assert_eq!(error.code(), ErrorCode::AggregateConflict);
        assert!(error.to_string().contains("single room"));
    }

    #[test]
    fn distinct_raw_names_for_one_room_are_grouped() {
        let root = unique_test_dir();
        let raw_dir = root.join("raw");
        fs::create_dir_all(&raw_dir).unwrap();
        let first = raw_dir.join("local-room-v12.jsonl");
        let second = raw_dir.join("remote-room-v12-federated.jsonl");
        let event_a = event("$a", 1, 100, &[]);
        let event_b = event("$b", 2, 200, &["$a"]);
        fs::write(
            &first,
            format!("{}\n", rz_core::json::write_string_value(&event_a).unwrap()),
        )
        .unwrap();
        fs::write(
            &second,
            format!("{}\n", rz_core::json::write_string_value(&event_b).unwrap()),
        )
        .unwrap();
        let out_dir = root.join("merged");
        let out_dir_lossy = out_dir.to_string_lossy();
        let matches = explicit_matches(
            &[first.as_path(), second.as_path()],
            &["--output-dir", out_dir_lossy.as_ref()],
        );
        let report = match run_from_matches(&matches).unwrap() {
            AggregateOutcome::Complete(report) => report,
            AggregateOutcome::Partial(report) => panic!("unexpected partial: {report:?}"),
        };
        let rooms = report["rooms"].as_array().unwrap();
        assert_eq!(rooms.len(), 1, "both raw names belong to room-v12");
        assert_eq!(rooms[0]["room"].as_str(), Some("room-v12"));
        assert_eq!(rooms[0]["input_files"].as_u64(), Some(2));
        assert!(out_dir.join("merged-room-v12.jsonl").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn check_mode_in_explicit_mode_uses_content_not_labels() {
        let root = unique_test_dir();
        let raw_dir = root.join("raw");
        let raw = room_file(&raw_dir, "remote-room-a-v12.jsonl", "$a");
        let out_dir = root.join("merged");
        let out_dir_lossy = out_dir.to_string_lossy();
        let write_matches =
            explicit_matches(&[raw.as_path()], &["--output-dir", out_dir_lossy.as_ref()]);
        assert!(matches!(
            run_from_matches(&write_matches).unwrap(),
            AggregateOutcome::Complete(_)
        ));
        let check_matches = explicit_matches(
            &[raw.as_path()],
            &["--check", "--output-dir", out_dir_lossy.as_ref()],
        );
        let report = match run_from_matches(&check_matches).unwrap() {
            AggregateOutcome::Complete(report) => report,
            AggregateOutcome::Partial(report) => panic!("unexpected partial: {report:?}"),
        };
        assert_eq!(
            report["rooms"].as_array().unwrap()[0]["status"].as_str(),
            Some("current")
        );
        // A changed input makes the same check stale, proving labels are not
        // part of the compared aggregate bytes.
        let changed = event("$a", 1, 101, &[]);
        fs::write(
            &raw,
            format!("{}\n", rz_core::json::write_string_value(&changed).unwrap()),
        )
        .unwrap();
        let stale = match run_from_matches(&check_matches).unwrap() {
            AggregateOutcome::Partial(report) => report,
            AggregateOutcome::Complete(report) => panic!("expected partial: {report:?}"),
        };
        assert_eq!(
            stale["rooms"].as_array().unwrap()[0]["code"].as_str(),
            Some("E015_AGGREGATE_STALE")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn partial_failure_preserves_successful_rooms() {
        let root = unique_test_dir();
        let raw_dir = root.join("raw");
        let good = room_file(&raw_dir, "remote-room-a-v12.jsonl", "$a");
        let bad = raw_dir.join("local-room-b-v12.jsonl");
        fs::write(&bad, b"not json\n").unwrap();
        let out_dir = root.join("merged");
        let out_dir_lossy = out_dir.to_string_lossy();
        let matches = explicit_matches(
            &[good.as_path(), bad.as_path()],
            &["--output-dir", out_dir_lossy.as_ref()],
        );
        let report = match run_from_matches(&matches).unwrap() {
            AggregateOutcome::Partial(report) => report,
            AggregateOutcome::Complete(report) => panic!("expected partial: {report:?}"),
        };
        assert_eq!(report["status"].as_str(), Some("partial"));
        assert_eq!(report["failed"].as_u64(), Some(1));
        let rooms = report["rooms"].as_array().unwrap();
        let failures: Vec<_> = rooms
            .iter()
            .filter(|room| room["status"].as_str() == Some("error"))
            .collect();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0]["room"].as_str(), Some("room-b-v12"));
        assert_eq!(failures[0]["code"].as_str(), Some("E006_MALFORMED_JSON"));
        assert!(out_dir.join("merged-room-a-v12.jsonl").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bare_invocation_groups_input_dir_by_slug() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        room_file(&raw_dir, "remote-room-a-v12.jsonl", "$a");
        room_file(&raw_dir, "local-room-b-v12.jsonl", "$b");
        let out_dir = root.join("merged");
        let out_dir_lossy = out_dir.to_string_lossy();
        let matches = scan_matches(&raw_dir, &["--output-dir", out_dir_lossy.as_ref()]);
        let report = match run_from_matches(&matches).unwrap() {
            AggregateOutcome::Complete(report) => report,
            AggregateOutcome::Partial(report) => panic!("unexpected partial: {report:?}"),
        };
        assert_eq!(report["status"].as_str(), Some("written"));
        assert_eq!(report["rooms"].as_array().unwrap().len(), 2);
        assert!(out_dir.join("merged-room-a-v12.jsonl").exists());
        assert!(out_dir.join("merged-room-b-v12.jsonl").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bare_invocation_skips_unversioned_files() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        room_file(&raw_dir, "remote-room-a-v12.jsonl", "$a");
        fs::write(raw_dir.join("notes.jsonl"), b"{}\n").unwrap();
        let out_dir = root.join("merged");
        let out_dir_lossy = out_dir.to_string_lossy();
        let matches = scan_matches(&raw_dir, &["--output-dir", out_dir_lossy.as_ref()]);
        let report = match run_from_matches(&matches).unwrap() {
            AggregateOutcome::Complete(report) => report,
            AggregateOutcome::Partial(report) => panic!("unexpected partial: {report:?}"),
        };
        let rooms = report["rooms"].as_array().unwrap();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0]["room"].as_str(), Some("room-a-v12"));
        let skipped = report["skipped"].as_array().unwrap();
        assert_eq!(skipped.len(), 1, "the unversioned file is surfaced");
        assert!(skipped[0].as_str().unwrap().ends_with("notes.jsonl"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bare_invocation_rejects_empty_directory() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        fs::create_dir_all(&raw_dir).unwrap();
        let matches = scan_matches(&raw_dir, &[]);
        let error = run_from_matches(&matches).expect_err("empty directory should error");
        assert_eq!(error.code(), ErrorCode::EmptyInput);
        assert!(error.to_string().contains("no .jsonl files found"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bare_invocation_rejects_missing_directory() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        let matches = scan_matches(&raw_dir, &[]);
        let error = run_from_matches(&matches).expect_err("missing directory should error");
        assert_eq!(error.code(), ErrorCode::IoError);
        assert!(error.to_string().contains("cannot read input directory"));
    }

    #[test]
    fn bare_invocation_rejects_all_unversioned_directory() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        fs::create_dir_all(&raw_dir).unwrap();
        fs::write(raw_dir.join("notes.jsonl"), b"{}\n").unwrap();
        let matches = scan_matches(&raw_dir, &[]);
        let error = run_from_matches(&matches).expect_err("all-unversioned directory should error");
        assert_eq!(error.code(), ErrorCode::EmptyInput);
        assert!(error.to_string().contains("no versioned .jsonl files"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bare_invocation_output_override_requires_a_single_room() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        room_file(&raw_dir, "room-a-v12.jsonl", "$a");
        room_file(&raw_dir, "room-b-v12.jsonl", "$b");
        let matches = scan_matches(&raw_dir, &["-o", "out.jsonl"]);
        let error = run_from_matches(&matches).expect_err("multi-room -o should fail");
        assert_eq!(error.code(), ErrorCode::AggregateConflict);
        assert!(error.to_string().contains("single room"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bare_invocation_rejects_output_dir_overlapping_input_dir() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        room_file(&raw_dir, "room-a-v12.jsonl", "$a");
        let raw_dir_lossy = raw_dir.to_string_lossy();
        let matches = scan_matches(&raw_dir, &["--output-dir", raw_dir_lossy.as_ref()]);
        let error = run_from_matches(&matches).expect_err("overlap should be rejected");
        assert_eq!(error.code(), ErrorCode::AggregateConflict);
        assert!(error.to_string().contains("must be different"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bare_invocation_single_room_honors_output_override() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        room_file(&raw_dir, "room-a-v12.jsonl", "$a");
        let out = root.join("custom.jsonl");
        let out_lossy = out.to_string_lossy();
        let matches = scan_matches(&raw_dir, &["-o", out_lossy.as_ref()]);
        let report = match run_from_matches(&matches).unwrap() {
            AggregateOutcome::Complete(report) => report,
            AggregateOutcome::Partial(report) => panic!("unexpected partial: {report:?}"),
        };
        assert_eq!(
            report["rooms"].as_array().unwrap()[0]["output"].as_str(),
            Some(out_lossy.as_ref())
        );
        assert!(out.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scan_and_room_modes_agree_for_a_canonical_slug() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        room_file(&raw_dir, "remote-dag-room-v12-merged.jsonl", "$a");
        let out_dir = root.join("merged");
        let out_dir_lossy = out_dir.to_string_lossy();
        let room = room_matches(
            &raw_dir,
            "room-v12",
            &["--output-dir", out_dir_lossy.as_ref()],
        );
        let room_result = match run_from_matches(&room).unwrap() {
            AggregateOutcome::Complete(result) => result,
            AggregateOutcome::Partial(result) => panic!("unexpected partial: {result:?}"),
        };
        let scan = scan_matches(&raw_dir, &["--output-dir", out_dir_lossy.as_ref()]);
        let scan_result = match run_from_matches(&scan).unwrap() {
            AggregateOutcome::Complete(result) => result,
            AggregateOutcome::Partial(result) => panic!("unexpected partial: {result:?}"),
        };
        let scanned = &scan_result["rooms"].as_array().unwrap()[0];
        assert_eq!(room_result["output"], scanned["output"]);
        assert_eq!(room_result["unique_events"], scanned["unique_events"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_symlinked_inputs_dedupe_without_conflict() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        let original = room_file(&raw_dir, "room-v12.jsonl", "$a");
        let link = raw_dir.join("remote-room-v12.jsonl");
        std::os::unix::fs::symlink(&original, &link).unwrap();
        let out_dir = root.join("merged");
        let out_dir_lossy = out_dir.to_string_lossy();
        let matches = scan_matches(&raw_dir, &["--output-dir", out_dir_lossy.as_ref()]);
        let report = match run_from_matches(&matches).unwrap() {
            AggregateOutcome::Complete(report) => report,
            AggregateOutcome::Partial(report) => panic!("unexpected partial: {report:?}"),
        };
        let rooms = report["rooms"].as_array().unwrap();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0]["input_files"].as_u64(), Some(2));
        assert_eq!(rooms[0]["unique_events"].as_u64(), Some(1));
        assert_eq!(rooms[0]["duplicate_event_copies"].as_u64(), Some(1));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scan_partial_report_includes_skipped_files() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        room_file(&raw_dir, "room-a-v12.jsonl", "$a");
        fs::write(raw_dir.join("room-b-v12.jsonl"), b"not json\n").unwrap();
        fs::write(raw_dir.join("notes.jsonl"), b"{}\n").unwrap();
        let out_dir = root.join("merged");
        let out_dir_lossy = out_dir.to_string_lossy();
        let matches = scan_matches(&raw_dir, &["--output-dir", out_dir_lossy.as_ref()]);
        let report = match run_from_matches(&matches).unwrap() {
            AggregateOutcome::Partial(report) => report,
            AggregateOutcome::Complete(report) => panic!("expected partial: {report:?}"),
        };
        assert_eq!(report["failed"].as_u64(), Some(1));
        assert_eq!(report["skipped"].as_array().unwrap().len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn room_mode_accepts_unversioned_while_scan_skips_it() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        room_file(&raw_dir, "room.jsonl", "$a");
        let out_dir = root.join("merged");
        let out_dir_lossy = out_dir.to_string_lossy();
        let room = room_matches(&raw_dir, "room", &["--output-dir", out_dir_lossy.as_ref()]);
        assert!(matches!(
            run_from_matches(&room).unwrap(),
            AggregateOutcome::Complete(_)
        ));
        assert!(out_dir.join("merged-room.jsonl").exists());
        let scan = scan_matches(&raw_dir, &[]);
        let error = run_from_matches(&scan).expect_err("scan skips unversioned inputs");
        assert_eq!(error.code(), ErrorCode::EmptyInput);
        fs::remove_dir_all(root).unwrap();
    }
}
