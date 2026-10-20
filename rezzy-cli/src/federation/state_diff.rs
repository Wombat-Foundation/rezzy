//! `rezzy federation state-diff`: ask two or more servers for the room state
//! and auth chain they report at one event, and compare.
//!
//! Each server is asked `GET /_matrix/federation/v1/state_ids/{room}?event_id=`
//! once. The IDs it returns are compared with the events you already hold
//! (`--known`) and with each other. Only IDs are compared, so this is cheap
//! compared with crawling, and it reaches state events that are not reachable
//! by walking `prev_events`.

use super::{
    get_remote_dag_with_known, known_events_arg, load_known_ids, origin_arg, quote, request,
    signing_key_args, signing_key_path, validate_room_id, DagRequest, NO_BACKFILL,
};
use crate::error::AppError;
use clap::{Arg, ArgAction, ArgMatches, Command};
use rezzy::JsonValue;
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

pub(super) fn command() -> Command {
    Command::new("state-diff")
        .about("Compare the room state and auth chain servers report at one event")
        .arg(origin_arg())
        .arg(Arg::new("room").long("room").required(true))
        .arg(
            Arg::new("event")
                .long("event")
                .required(true)
                .help("Event ID the servers hold; state is compared at this event"),
        )
        .arg(
            Arg::new("destination")
                .long("destination")
                .required(true)
                .action(ArgAction::Append)
                .help("Server to ask; repeat for each"),
        )
        .arg(
            Arg::new("room-version")
                .long("room-version")
                .default_value("12"),
        )
        .arg(known_events_arg())
        .arg(
            Arg::new("output-dir")
                .long("output-dir")
                .default_value("state-diff")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("fetch")
                .long("fetch")
                .action(ArgAction::SetTrue)
                .help("Fetch the events you lack from each server with /event/{id}"),
        )
        .args(signing_key_args())
}

/// A file-name-safe form of a destination such as `http://127.0.0.1:8448`.
fn file_stem(destination: &str) -> String {
    destination
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-._".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn ids_in(response: &JsonValue, key: &str) -> impl Iterator<Item = String> {
    response
        .get(key)
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>()
        .into_iter()
}

fn count(n: usize) -> JsonValue {
    rezzy::json!(u64::try_from(n).unwrap_or(u64::MAX))
}

fn write_lines(path: &Path, ids: &BTreeSet<String>) -> Result<(), AppError> {
    let mut text = String::new();
    for id in ids {
        text.push_str(id);
        text.push('\n');
    }
    fs::write(path, text)?;
    Ok(())
}

/// In the order the `--destination` flags were given, so "first" and "second"
/// in the output mean what the command line says.
type Reported = Vec<(String, BTreeSet<String>)>;

/// Ask each destination for its state IDs; write `<stem>.ids` / `<stem>.missing`.
/// Returns what each reported and a per-server summary (or its error).
fn ask_servers(
    m: &ArgMatches,
    uri: &str,
    out_dir: &Path,
    known: &HashSet<String>,
) -> Result<(Reported, JsonValue), AppError> {
    let origin = m.get_one::<String>("origin").expect("default");
    let mut reported = Reported::new();
    let mut servers = rezzy::json!({});
    for dest in m.get_many::<String>("destination").expect("required") {
        let mut entry = rezzy::json!({});
        match request(
            origin,
            dest,
            "GET",
            uri,
            &rezzy::json!({}),
            signing_key_path(m),
        ) {
            Ok(response) => {
                let ids: BTreeSet<String> = ids_in(&response, "pdu_ids")
                    .chain(ids_in(&response, "auth_chain_ids"))
                    .collect();
                let missing: BTreeSet<String> = ids
                    .iter()
                    .filter(|id| !known.contains(*id))
                    .cloned()
                    .collect();
                let stem = file_stem(dest);
                write_lines(&out_dir.join(format!("{stem}.ids")), &ids)?;
                write_lines(&out_dir.join(format!("{stem}.missing")), &missing)?;
                let _ = entry.insert(String::from("state_and_auth"), count(ids.len()));
                let _ = entry.insert(String::from("missing_locally"), count(missing.len()));
                reported.push((dest.clone(), ids));
            }
            Err(error) => {
                let message: String = error.to_string().chars().take(200).collect();
                let _ = entry.insert(String::from("error"), JsonValue::String(message));
            }
        }
        let _ = servers.insert(dest.clone(), entry);
    }
    Ok((reported, servers))
}

/// Compare every pair of servers that answered; write the one-sided ID lists.
fn compare_pairs(reported: &Reported, out_dir: &Path) -> Result<JsonValue, AppError> {
    let mut pairs = rezzy::json!({});
    for (i, (a, set_a)) in reported.iter().enumerate() {
        for (b, set_b) in reported.iter().skip(i.saturating_add(1)) {
            let only_a: BTreeSet<String> = set_a.difference(set_b).cloned().collect();
            let only_b: BTreeSet<String> = set_b.difference(set_a).cloned().collect();
            let stem = format!("{}__vs__{}", file_stem(a), file_stem(b));
            write_lines(&out_dir.join(format!("{stem}.only-first")), &only_a)?;
            write_lines(&out_dir.join(format!("{stem}.only-second")), &only_b)?;
            let mut pair = rezzy::json!({});
            let _ = pair.insert(String::from("only_first"), count(only_a.len()));
            let _ = pair.insert(String::from("only_second"), count(only_b.len()));
            let common = set_a.intersection(set_b).count();
            let _ = pair.insert(String::from("common"), count(common));
            let _ = pairs.insert(format!("{a} vs {b}"), pair);
        }
    }
    Ok(pairs)
}

/// `--fetch`: get each server's missing events with `/event/{id}`.
fn fetch_missing(
    m: &ArgMatches,
    reported: &Reported,
    out_dir: &Path,
    known: &HashSet<String>,
) -> JsonValue {
    let origin = m.get_one::<String>("origin").expect("default");
    let room = m.get_one::<String>("room").expect("required");
    let room_version = m.get_one::<String>("room-version").expect("default");
    // The IDs are known exactly, so ask for them directly.
    NO_BACKFILL.store(true, Ordering::Relaxed);
    let mut fetched = rezzy::json!({});
    for (dest, ids) in reported {
        let starts: Vec<String> = ids
            .iter()
            .filter(|id| !known.contains(*id))
            .cloned()
            .collect();
        if starts.is_empty() {
            continue;
        }
        let output = out_dir.join(format!("{}.state.jsonl", file_stem(dest)));
        let dag = DagRequest {
            origin,
            destination: dest,
            room_id: room,
            starts: &starts,
            room_version,
            limit: -1,
            output: &output,
            key_path: signing_key_path(m),
            no_fallback: false,
            emit_missing: None,
        };
        let outcome = match get_remote_dag_with_known(&dag, Some(known)) {
            Ok(result) => result.get("count").cloned().unwrap_or(JsonValue::Null),
            Err(error) => JsonValue::String(error.to_string().chars().take(200).collect()),
        };
        let _ = fetched.insert(dest.clone(), outcome);
    }
    fetched
}

pub(super) fn run(m: &ArgMatches) -> Result<JsonValue, AppError> {
    let room = m.get_one::<String>("room").expect("required");
    validate_room_id(room)?;
    let event = m.get_one::<String>("event").expect("required");
    let room_version = m.get_one::<String>("room-version").expect("default");
    let out_dir = m.get_one::<PathBuf>("output-dir").expect("default");
    fs::create_dir_all(out_dir)?;
    let known = load_known_ids(m, out_dir, None, room_version)?;
    let uri = format!(
        "/_matrix/federation/v1/state_ids/{}?event_id={}",
        quote(room),
        quote(event)
    );
    let (reported, servers) = ask_servers(m, &uri, out_dir, &known)?;
    let pairs = compare_pairs(&reported, out_dir)?;
    let fetched = if m.get_flag("fetch") {
        fetch_missing(m, &reported, out_dir, &known)
    } else {
        rezzy::json!({})
    };
    let mut result = rezzy::json!({
        "event": event.clone(),
        "output_dir": out_dir.display().to_string(),
    });
    let _ = result.insert(String::from("servers"), servers);
    let _ = result.insert(String::from("pairs"), pairs);
    let _ = result.insert(String::from("fetched"), fetched);
    Ok(result)
}
