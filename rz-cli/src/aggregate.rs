//! Deterministic raw-JSONL aggregation with provenance and stale checks.

use crate::error::{AppError, ErrorCode};
use crate::jsonl_merge::merge_event_sets;
use crate::utils::load_file;
use clap::{Arg, ArgAction, Command};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST_VERSION: u64 = 1;

#[derive(Debug)]
struct Options {
    input_dir: PathBuf,
    room: Option<String>,
    output: PathBuf,
    manifest: PathBuf,
    check: bool,
    quiet: bool,
}

fn parse_options() -> Options {
    let matches = Command::new("rezzy aggregate")
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
                .help("Only include JSONL filenames containing this room slug"),
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
        .get_matches_from(std::env::args().skip(1));

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
        .map(|s| s.into_bytes())
        .map_err(|e| AppError::new(ErrorCode::MalformedJson, e.to_string()))
}

fn input_files(dir: &Path, room: Option<&str>) -> Result<Vec<PathBuf>, AppError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file()
            && path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
            && room.map_or(true, |needle| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().contains(needle))
            })
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

fn sort_events(events: &mut [rz_core::JsonValue]) {
    events.sort_by(|a, b| {
        let depth = |v: &rz_core::JsonValue| v.get("depth").and_then(|x| x.as_u64()).unwrap_or(0);
        let ts = |v: &rz_core::JsonValue| {
            v.get("origin_server_ts")
                .and_then(|x| x.as_u64())
                .unwrap_or(0)
        };
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
}

fn output_bytes(events: &[rz_core::JsonValue]) -> Result<Vec<u8>, AppError> {
    let mut bytes = Vec::new();
    for event in events {
        bytes.extend(json_bytes(event)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn manifest_value(
    files: &[PathBuf],
    input_dir: &Path,
    output: &[u8],
    event_count: usize,
) -> Result<rz_core::JsonValue, AppError> {
    let mut inputs = Vec::with_capacity(files.len());
    for path in files {
        let bytes = fs::read(path)?;
        let lines = bytes.iter().filter(|&&b| b == b'\n').count();
        let name = path
            .strip_prefix(input_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        inputs.push(rz_core::json!({"path": name, "sha256": sha256(&bytes), "bytes": bytes.len(), "lines": lines}));
    }
    Ok(rz_core::json!({
        "manifest_version": MANIFEST_VERSION,
        "algorithm": "deduplicate by event_id; sort by depth, origin_server_ts, event_id",
        "input_dir": input_dir.to_string_lossy().to_string(),
        "inputs": inputs,
        "unique_events": event_count,
        "output": {"sha256": sha256(output), "bytes": output.len()}
    }))
}

fn aggregate(options: &Options) -> Result<rz_core::JsonValue, AppError> {
    let files = input_files(&options.input_dir, options.room.as_deref())?;
    let mut sets = Vec::with_capacity(files.len());
    for path in &files {
        let label = path
            .strip_prefix(&options.input_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        sets.push((label, load_file(path)?));
    }
    let mut events = merge_event_sets(&sets, false, options.quiet)?;
    sort_events(&mut events);
    let output = output_bytes(&events)?;
    let manifest = manifest_value(&files, &options.input_dir, &output, events.len())?;

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
    fs::write(&options.output, &output)?;
    fs::write(&options.manifest, json_bytes(&manifest)?)?;
    Ok(
        rz_core::json!({"status": "written", "output": options.output.to_string_lossy().to_string(), "manifest": options.manifest.to_string_lossy().to_string(), "unique_events": events.len(), "input_files": files.len()}),
    )
}

/// Parse and run `rezzy aggregate ...`.
pub fn run_from_process_args() -> Result<rz_core::JsonValue, AppError> {
    aggregate(&parse_options())
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

    #[test]
    fn sorting_is_deterministic_with_event_id_tiebreaker() {
        let mut events = vec![
            event("$b", 2, 100, &["$a"]),
            event("$a", 1, 200, &[]),
            event("$c", 2, 100, &["$a"]),
        ];
        sort_events(&mut events);
        let ids: Vec<&str> = events
            .iter()
            .map(|value| value["event_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["$a", "$b", "$c"]);
    }

    #[test]
    fn aggregate_writes_manifest_preserves_raw_and_detects_stale_inputs() {
        let root = unique_test_dir();
        let raw_dir = root.join("unmerged");
        let output = root.join("merged/room.jsonl");
        let manifest = root.join("merged/room.manifest.json");
        fs::create_dir_all(&raw_dir).unwrap();

        let first = event("$a", 1, 100, &[]);
        let second = event("$b", 2, 200, &["$a"]);
        let first_line = format!("{}\n", rz_core::json::write_string_value(&first).unwrap());
        let second_line = format!("{}\n", rz_core::json::write_string_value(&second).unwrap());
        let first_path = raw_dir.join("room-a.jsonl");
        let second_path = raw_dir.join("room-b.jsonl");
        fs::write(&first_path, &first_line).unwrap();
        fs::write(&second_path, &second_line).unwrap();
        let raw_before = fs::read(&first_path).unwrap();

        let options = Options {
            input_dir: raw_dir.clone(),
            room: Some("room".to_owned()),
            output: output.clone(),
            manifest: manifest.clone(),
            check: false,
            quiet: true,
        };
        let result = aggregate(&options).unwrap();
        assert_eq!(result["status"], "written");
        assert_eq!(result["unique_events"].as_u64(), Some(2));
        assert_eq!(fs::read(&first_path).unwrap(), raw_before);
        assert!(output.is_file());
        assert!(manifest.is_file());

        let mut check_options = options;
        check_options.check = true;
        assert_eq!(aggregate(&check_options).unwrap()["status"], "current");

        let third = event("$c", 3, 300, &["$b"]);
        let third_line = format!("{}\n", rz_core::json::write_string_value(&third).unwrap());
        fs::write(&second_path, format!("{second_line}{third_line}")).unwrap();
        let stale = aggregate(&check_options).unwrap_err();
        assert_eq!(stale.code(), ErrorCode::AggregateStale);

        fs::remove_dir_all(root).unwrap();
    }
}
