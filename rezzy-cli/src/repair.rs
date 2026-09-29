//! Small repair utilities for federation JSONL exports.

use crate::error::{AppError, ErrorCode};
use clap::{Arg, ArgMatches, Command};
use rezzy::JsonValue;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

pub fn command() -> Command {
    Command::new("repair-ids")
        .about("Fill missing Matrix event IDs in a JSONL export")
        .arg(
            Arg::new("input")
                .long("input")
                .short('i')
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(Arg::new("room-version").long("room-version").required(true))
}

pub fn run_from_matches(matches: &ArgMatches) -> Result<JsonValue, AppError> {
    let input = matches.get_one::<PathBuf>("input").expect("required");
    let output = matches.get_one::<PathBuf>("output").expect("required");
    let room_version = matches.get_one::<String>("room-version").expect("required");

    let reader = BufReader::new(File::open(input)?);
    if input == output {
        return Err(AppError::new(
            ErrorCode::IoError,
            "--input and --output must be different files",
        ));
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
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
                format!("{}:{}: {e}", input.display(), line_number + 1),
            )
        })?;
        let missing = event
            .get("event_id")
            .and_then(JsonValue::as_str)
            .map_or(true, str::is_empty);
        if missing {
            let hash = rezzy::reference_hash(&event, room_version).map_err(|e| {
                AppError::new(
                    ErrorCode::UnsupportedVersion,
                    format!(
                        "{}:{}: cannot derive event ID: {e}",
                        input.display(),
                        line_number + 1
                    ),
                )
            })?;
            event
                .as_object_mut()
                .ok_or_else(|| {
                    AppError::new(ErrorCode::UnexpectedFormat, "event is not a JSON object")
                })?
                .insert("event_id".to_owned(), JsonValue::String(format!("${hash}")));
            repaired = repaired.saturating_add(1);
        }
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
