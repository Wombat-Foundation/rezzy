//! `rezzy federation state-diff`: ask two or more servers for the room state
//! and auth chain they report at one event, and compare.
//!
//! Each server is asked `GET /_matrix/federation/v1/state_ids/{room}?event_id=`
//! once. The IDs it returns are compared with the events you already hold
//! (`--known`) and with each other. Only IDs are compared, so this is cheap
//! compared with crawling, and it reaches state events that are not reachable
//! by walking `prev_events`.

use super::{
    get_remote_events_by_id, known_events_arg, load_known_ids, origin_arg, quote, request,
    signing_key_args, signing_key_path, validate_room_id, DagRequest,
};
use crate::error::AppError;
use clap::{Arg, ArgAction, ArgMatches, Command};
use rezzy::JsonValue;
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

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
            Arg::new("max-depth")
                .long("max-depth")
                .value_parser(clap::value_parser!(u64))
                .help(
                    "Ignore IDs whose depth is above N. /state_ids carries no depth, \
                     so only events in --known can be judged; unknown IDs are kept",
                ),
        )
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

/// What one server reported: the state event IDs and, separately, the IDs of
/// the auth chain behind them. They answer different questions (what the state
/// is, versus the history that justifies it), so they are never merged.
struct Reported {
    state: BTreeSet<String>,
    auth_chain: BTreeSet<String>,
}

/// In the order the `--destination` flags were given, so "first" and "second"
/// in the output mean what the command line says.
type Answers = Vec<(String, Reported)>;

/// IDs in the `--known` files deeper than `--max-depth`. Empty without the flag.
fn too_deep_ids(m: &ArgMatches) -> Result<HashSet<String>, AppError> {
    let mut deep = HashSet::new();
    let Some(cap) = m.get_one::<u64>("max-depth").copied() else {
        return Ok(deep);
    };
    for path in m.get_many::<PathBuf>("known").into_iter().flatten() {
        for event in crate::repair::read_jsonl_events(path)? {
            let too_deep = event
                .get("depth")
                .and_then(JsonValue::as_u64)
                .is_some_and(|depth| depth > cap);
            if too_deep {
                deep.extend(crate::repair::event_id_of(&event));
            }
        }
    }
    Ok(deep)
}

fn without(ids: impl Iterator<Item = String>, deep: &HashSet<String>) -> BTreeSet<String> {
    ids.filter(|id| !deep.contains(id)).collect()
}

fn not_held(ids: &BTreeSet<String>, known: &HashSet<String>) -> BTreeSet<String> {
    ids.iter()
        .filter(|id| !known.contains(*id))
        .cloned()
        .collect()
}

/// `{"ids": n, "missing_locally": m}` for one list, and write both lists.
fn summarize_list(
    out_dir: &Path,
    stem: &str,
    kind: &str,
    ids: &BTreeSet<String>,
    known: &HashSet<String>,
) -> Result<JsonValue, AppError> {
    let missing = not_held(ids, known);
    write_lines(&out_dir.join(format!("{stem}.{kind}.ids")), ids)?;
    write_lines(&out_dir.join(format!("{stem}.{kind}.missing")), &missing)?;
    let mut entry = rezzy::json!({});
    let _ = entry.insert(String::from("ids"), count(ids.len()));
    let _ = entry.insert(String::from("missing_locally"), count(missing.len()));
    Ok(entry)
}

/// Ask each destination for its state IDs. Returns what each reported and a
/// per-server summary (or its error).
fn ask_servers(
    m: &ArgMatches,
    uri: &str,
    out_dir: &Path,
    known: &HashSet<String>,
    deep: &HashSet<String>,
) -> Result<(Answers, JsonValue), AppError> {
    let origin = m.get_one::<String>("origin").expect("default");
    let mut answers = Answers::new();
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
                let reported = Reported {
                    state: without(ids_in(&response, "pdu_ids"), deep),
                    auth_chain: without(ids_in(&response, "auth_chain_ids"), deep),
                };
                let stem = file_stem(dest);
                let state = summarize_list(out_dir, &stem, "state", &reported.state, known)?;
                let auth =
                    summarize_list(out_dir, &stem, "auth_chain", &reported.auth_chain, known)?;
                let _ = entry.insert(String::from("state"), state);
                let _ = entry.insert(String::from("auth_chain"), auth);
                answers.push((dest.clone(), reported));
            }
            Err(error) => {
                let message: String = error.to_string().chars().take(200).collect();
                let _ = entry.insert(String::from("error"), JsonValue::String(message));
            }
        }
        let _ = servers.insert(dest.clone(), entry);
    }
    Ok((answers, servers))
}

/// Compare one kind of list between two servers; write the one-sided IDs.
fn compare_lists(
    out_dir: &Path,
    stem: &str,
    kind: &str,
    first: &BTreeSet<String>,
    second: &BTreeSet<String>,
) -> Result<JsonValue, AppError> {
    let only_first: BTreeSet<String> = first.difference(second).cloned().collect();
    let only_second: BTreeSet<String> = second.difference(first).cloned().collect();
    write_lines(
        &out_dir.join(format!("{stem}.{kind}.only-first")),
        &only_first,
    )?;
    write_lines(
        &out_dir.join(format!("{stem}.{kind}.only-second")),
        &only_second,
    )?;
    let mut entry = rezzy::json!({});
    let _ = entry.insert(String::from("only_first"), count(only_first.len()));
    let _ = entry.insert(String::from("only_second"), count(only_second.len()));
    let _ = entry.insert(
        String::from("common"),
        count(first.intersection(second).count()),
    );
    Ok(entry)
}

/// Compare every pair of servers that answered, state against state and auth
/// chain against auth chain.
fn compare_pairs(answers: &Answers, out_dir: &Path) -> Result<JsonValue, AppError> {
    let mut pairs = rezzy::json!({});
    for (i, (a, left)) in answers.iter().enumerate() {
        for (b, right) in answers.iter().skip(i.saturating_add(1)) {
            let stem = format!("{}__vs__{}", file_stem(a), file_stem(b));
            let state = compare_lists(out_dir, &stem, "state", &left.state, &right.state)?;
            let auth = compare_lists(
                out_dir,
                &stem,
                "auth_chain",
                &left.auth_chain,
                &right.auth_chain,
            )?;
            let mut pair = rezzy::json!({});
            let _ = pair.insert(String::from("state"), state);
            let _ = pair.insert(String::from("auth_chain"), auth);
            let _ = pairs.insert(format!("{a} vs {b}"), pair);
        }
    }
    Ok(pairs)
}

/// `--fetch`: get each server's missing events (state and auth chain) with
/// `/event/{id}`.
fn fetch_missing(
    m: &ArgMatches,
    answers: &Answers,
    out_dir: &Path,
    known: &HashSet<String>,
) -> JsonValue {
    let origin = m.get_one::<String>("origin").expect("default");
    let room = m.get_one::<String>("room").expect("required");
    let room_version = m.get_one::<String>("room-version").expect("default");
    // The IDs are known exactly, so ask for them directly and do not follow
    // `prev_events` from what comes back.
    let mut fetched = rezzy::json!({});
    for (dest, reported) in answers {
        let starts: Vec<String> = reported
            .state
            .union(&reported.auth_chain)
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
        let outcome = match get_remote_events_by_id(&dag, Some(known)) {
            Ok(result) => result.get("count").cloned().unwrap_or(JsonValue::Null),
            Err(error) => JsonValue::String(error.to_string().chars().take(200).collect()),
        };
        let _ = fetched.insert(dest.clone(), outcome);
    }
    fetched
}

/// Plain one-line-per-number summary on stderr, so stdout stays pure JSON.
fn print_summary(answers: &Answers) {
    for (dest, r) in answers {
        eprintln!(
            "{dest}: {} state IDs, {} auth chain IDs",
            r.state.len(),
            r.auth_chain.len()
        );
    }
    for (i, (a, ra)) in answers.iter().enumerate() {
        for (b, rb) in answers.iter().skip(i.saturating_add(1)) {
            for (kind, x, y) in [
                ("state", &ra.state, &rb.state),
                ("auth chain", &ra.auth_chain, &rb.auth_chain),
            ] {
                eprintln!(
                    "{a} vs {b}, {kind}: {} in both, {} only on {a}, {} only on {b}",
                    x.intersection(y).count(),
                    x.difference(y).count(),
                    y.difference(x).count()
                );
            }
        }
    }
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
    let (answers, servers) = ask_servers(m, &uri, out_dir, &known, &too_deep_ids(m)?)?;
    let pairs = compare_pairs(&answers, out_dir)?;
    let fetched = if m.get_flag("fetch") {
        fetch_missing(m, &answers, out_dir, &known)
    } else {
        rezzy::json!({})
    };
    print_summary(&answers);
    let mut result = rezzy::json!({
        "event": event.clone(),
        "output_dir": out_dir.display().to_string(),
    });
    let _ = result.insert(String::from("servers"), servers);
    let _ = result.insert(String::from("pairs"), pairs);
    let _ = result.insert(String::from("fetched"), fetched);
    Ok(result)
}
