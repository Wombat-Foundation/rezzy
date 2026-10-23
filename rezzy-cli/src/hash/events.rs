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
use std::path::PathBuf;

/// Builds the event-hashing subcommand arguments.
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

/// Reads event JSONL and returns a report under the selected room version.
/// `-` reads stdin; blank lines are ignored and per-event failures become records.
///
/// # Errors
/// Returns an error for an unsupported room version, unreadable or invalid UTF-8
/// input, or input with no nonblank lines.
pub(super) fn run(m: &ArgMatches) -> Result<JsonValue, AppError> {
    let path = m.get_one::<PathBuf>("input").expect("required");
    let room_version = m.get_one::<String>("room-version").expect("required");
    // A typo'd version should fail the run, not turn every event into an error record.
    crate::utils::parse_room_version(room_version)?;
    let text = super::read_input(path)?;
    let records = rezzy::event_report::describe_jsonl(&text, room_version);
    if records.is_empty() {
        return Err(AppError::new(ErrorCode::EmptyInput, "no events in input"));
    }
    Ok(rezzy::event_report::report(records, room_version))
}
