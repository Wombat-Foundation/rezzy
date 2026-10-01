//! Local inspection commands for Matrix JSONL exports.

use crate::error::{AppError, ErrorCode};
use crate::repair::{input_arg, output_arg, read_jsonl_events, scan_gaps, write_event_ids};
use clap::{Arg, ArgAction, ArgMatches, Command};
use std::path::{Path, PathBuf};

#[must_use]
/// Brief public API.
pub fn command() -> Command {
    Command::new("inspect")
        .about("Inspect local Matrix JSONL exports")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("gaps")
                .about(
                    "List event IDs referenced by prev_events/auth_events but absent from the input",
                )
                .arg(input_arg())
                .arg(output_arg(false).help("Write output to a file instead of stdout"))
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Emit a structured report instead of one ID per line"),
                ),
        )
}

/// Run an inspection command, writing its own output and returning `()`.
///
/// # Errors
///
/// Returns an error for an unknown subcommand, unreadable or malformed input,
/// or an unwritable destination.
///
/// # Panics
///
/// Panics only if clap did not enforce the `gaps` subcommand's required
/// arguments, which cannot happen through the normal CLI path.
pub fn run_from_matches(matches: &ArgMatches) -> Result<(), AppError> {
    match matches.subcommand() {
        Some(("gaps", gaps)) => run_gaps(
            gaps.get_one::<PathBuf>("input").expect("required"),
            gaps.get_one::<PathBuf>("output").map(PathBuf::as_path),
            gaps.get_flag("json"),
        ),
        _ => Err(AppError::new(ErrorCode::MissingInputFlag, "choose `gaps`")),
    }
}

fn run_gaps(input: &Path, output: Option<&Path>, json: bool) -> Result<(), AppError> {
    let events = read_jsonl_events(input)?;
    let report = scan_gaps(&events);
    if json {
        let references: Vec<rezzy::JsonValue> = report
            .references
            .iter()
            .map(|reference| {
                rezzy::json!({
                    "event_id": reference.event_id.clone(),
                    "kind": reference.kind.field(),
                    "missing": reference.missing.clone(),
                })
            })
            .collect();
        let value = rezzy::json!({
            "input": input.to_string_lossy().to_string(),
            "events": events.len(),
            "missing_events": report.missing().len(),
            "prev_events": report.missing_prev.iter().cloned().collect::<Vec<_>>(),
            "auth_events": report.missing_auth.iter().cloned().collect::<Vec<_>>(),
            "references": references,
        });
        let text = rezzy::json::write_string_pretty(&value)
            .map_err(|e| AppError::new(ErrorCode::UnexpectedFormat, e.to_string()))?;
        match output {
            Some(path) => std::fs::write(path, format!("{text}\n"))?,
            None => println!("{text}"),
        }
        return Ok(());
    }
    let missing = report.missing();
    write_event_ids(output.unwrap_or(Path::new("-")), &missing)?;
    if let Some(path) = output {
        eprintln!(
            "{} missing event ID(s) written to {}",
            missing.len(),
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run_gaps;
    use crate::repair::{scan_gaps, ReferenceKind};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "rezzy-inspect-{name}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_events() -> Vec<rezzy::JsonValue> {
        vec![
            rezzy::json!({
                "event_id": "$a",
                "prev_events": [["$absent_prev", "h"]],
                "auth_events": ["$b", "$absent_auth"],
            }),
            rezzy::json!({"event_id": "$b", "prev_events": [], "auth_events": []}),
            rezzy::json!({"event_id": "$absent_prev", "prev_events": [], "auth_events": []}),
        ]
    }

    #[test]
    fn scan_gaps_separates_prev_and_auth_and_ignores_present() {
        let report = scan_gaps(&sample_events());
        assert_eq!(
            report.missing_prev.iter().cloned().collect::<Vec<_>>(),
            Vec::<String>::new(),
            "the referenced prev event is present in the set"
        );
        assert_eq!(
            report.missing_auth.iter().cloned().collect::<Vec<_>>(),
            vec!["$absent_auth".to_owned()]
        );
        assert_eq!(report.missing(), vec!["$absent_auth".to_owned()]);
        assert_eq!(report.references.len(), 1);
        assert_eq!(report.references[0].event_id, "$a");
        assert_eq!(report.references[0].kind, ReferenceKind::AuthEvents);
    }

    #[test]
    fn gaps_command_writes_flat_ids_and_json() {
        let dir = temp_dir("gaps");
        let input = dir.join("room.jsonl");
        let mut text = String::new();
        for event in sample_events() {
            text.push_str(&rezzy::json::write_string_value(&event).unwrap());
            text.push('\n');
        }
        std::fs::write(&input, text).unwrap();

        let flat = dir.join("missing.txt");
        run_gaps(&input, Some(&flat), false).unwrap();
        assert_eq!(std::fs::read_to_string(&flat).unwrap(), "$absent_auth\n");

        let json_out = dir.join("gaps.json");
        run_gaps(&input, Some(&json_out), true).unwrap();
        let value = rezzy::JsonValue::parse(&std::fs::read_to_string(&json_out).unwrap()).unwrap();
        assert_eq!(value["missing_events"].as_u64(), Some(1));
        assert_eq!(value["prev_events"], rezzy::json!([]));
        assert_eq!(value["auth_events"], rezzy::json!(["$absent_auth"]));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
