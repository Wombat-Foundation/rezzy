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

/// The strings in `response[key]`. A missing field, a non-array, or a
/// non-string entry is a malformed answer, not an empty one.
fn ids_in(response: &JsonValue, key: &str) -> Result<Vec<String>, String> {
    let list = response
        .get(key)
        .and_then(JsonValue::as_array)
        .ok_or_else(|| {
            format!("malformed /state_ids answer: `{key}` is missing or not an array")
        })?;
    list.iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                format!("malformed /state_ids answer: `{key}` has a non-string entry")
            })
        })
        .collect()
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
fn too_deep_ids(m: &ArgMatches, room_version: &str) -> Result<HashSet<String>, AppError> {
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
                // Same derivation as `load_known_ids`, so wire events count too.
                deep.extend(crate::repair::event_id_of(&event).or_else(|| {
                    rezzy::reference_hash(&event, room_version)
                        .ok()
                        .map(|hash| format!("${hash}"))
                }));
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
                let lists = ids_in(&response, "pdu_ids").and_then(|state| {
                    ids_in(&response, "auth_chain_ids").map(|auth_chain| (state, auth_chain))
                });
                let (state_ids, auth_ids) = match lists {
                    Ok(lists) => lists,
                    Err(message) => {
                        eprintln!("{dest}: {message}");
                        let _ = entry.insert(String::from("error"), JsonValue::String(message));
                        let _ = servers.insert(dest.clone(), entry);
                        continue;
                    }
                };
                let reported = Reported {
                    state: without(state_ids.into_iter(), deep),
                    auth_chain: without(auth_ids.into_iter(), deep),
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
                eprintln!("{dest}: {message}");
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
) -> Result<JsonValue, AppError> {
    let origin = m.get_one::<String>("origin").expect("default");
    let room = m.get_one::<String>("room").expect("required");
    let room_version = m.get_one::<String>("room-version").expect("default");
    super::MAX_DEPTH.store(
        m.get_one::<u64>("max-depth").copied().unwrap_or(u64::MAX),
        std::sync::atomic::Ordering::Relaxed,
    );
    let mut fetched = rezzy::json!({});
    let mut attempted = 0_usize;
    let mut succeeded = 0_usize;
    let mut first_error = None;
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
        attempted = attempted.saturating_add(1);
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
            // Keep the whole summary: failures and the unresolved frontier say
            // whether the fetch was complete.
            Ok(result) => {
                succeeded = succeeded.saturating_add(1);
                result
            }
            Err(error) => {
                let message = error.to_string().chars().take(200).collect::<String>();
                first_error.get_or_insert_with(|| format!("{dest}: {message}"));
                rezzy::json!({
                    "count": 0,
                    "error": message,
                    "remaining_frontier": starts,
                })
            }
        };
        let _ = fetched.insert(dest.clone(), outcome);
    }
    if attempted > 0 && succeeded == 0 {
        return Err(AppError::new(
            crate::error::ErrorCode::NetworkError,
            format!(
                "state-diff could not fetch missing events from any destination: {}",
                first_error.unwrap_or_else(|| String::from("all requests failed"))
            ),
        ));
    }
    Ok(fetched)
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

/// Every file this command may write under `out_dir` for the given
/// destinations, so none of them can be a `--known` input.
fn generated_paths<'a>(
    out_dir: &Path,
    destinations: impl Iterator<Item = &'a String>,
    fetch: bool,
) -> Vec<PathBuf> {
    const KINDS: [&str; 2] = ["state", "auth_chain"];
    let stems: Vec<String> = destinations.map(|d| file_stem(d)).collect();
    let mut paths = Vec::new();
    for stem in &stems {
        for kind in KINDS {
            for ext in ["ids", "missing"] {
                paths.push(out_dir.join(format!("{stem}.{kind}.{ext}")));
            }
        }
        if fetch {
            paths.push(out_dir.join(format!("{stem}.state.jsonl")));
        }
    }
    for (i, a) in stems.iter().enumerate() {
        for b in stems.iter().skip(i.saturating_add(1)) {
            for kind in KINDS {
                for side in ["only-first", "only-second"] {
                    paths.push(out_dir.join(format!("{a}__vs__{b}.{kind}.{side}")));
                }
            }
        }
    }
    paths
}

/// Rejects a `--known` file that this run would overwrite, such as the
/// `<destination>.state.jsonl` of an earlier `--fetch`.
fn ensure_known_not_overwritten(m: &ArgMatches, out_dir: &Path) -> Result<(), AppError> {
    let destinations = m.get_many::<String>("destination").into_iter().flatten();
    let outputs = generated_paths(out_dir, destinations, m.get_flag("fetch"));
    for known in m.get_many::<PathBuf>("known").into_iter().flatten() {
        for output in &outputs {
            crate::repair::ensure_paths_distinct(known, output)?;
        }
    }
    Ok(())
}

pub(super) fn run(m: &ArgMatches) -> Result<JsonValue, AppError> {
    let room = m.get_one::<String>("room").expect("required");
    validate_room_id(room)?;
    let event = m.get_one::<String>("event").expect("required");
    let room_version = m.get_one::<String>("room-version").expect("default");
    let out_dir = m.get_one::<PathBuf>("output-dir").expect("default");
    ensure_known_not_overwritten(m, out_dir)?;
    fs::create_dir_all(out_dir)?;
    let known = load_known_ids(m, out_dir, None, room_version)?;
    let uri = format!(
        "/_matrix/federation/v1/state_ids/{}?event_id={}",
        quote(room),
        quote(event)
    );
    let (answers, servers) =
        ask_servers(m, &uri, out_dir, &known, &too_deep_ids(m, room_version)?)?;
    let pairs = compare_pairs(&answers, out_dir)?;
    let fetched = if m.get_flag("fetch") {
        fetch_missing(m, &answers, out_dir, &known)?
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

#[cfg(test)]
mod tests {
    use super::{generated_paths, ids_in};
    use rezzy::JsonValue;
    use std::path::Path;

    #[test]
    fn generated_paths_include_the_fetch_output_a_known_file_could_alias() {
        let dests = [String::from("a.org"), String::from("b.org")];
        let paths = generated_paths(Path::new("out"), dests.iter(), true);
        assert!(paths.contains(&Path::new("out").join("a.org.state.jsonl")));
        assert!(paths.contains(&Path::new("out").join("a.org__vs__b.org.state.only-first")));
    }

    #[test]
    fn malformed_state_ids_answers_are_errors_not_empty_lists() {
        let empty = JsonValue::parse("{}").unwrap();
        assert!(ids_in(&empty, "pdu_ids").is_err());
        let bad = JsonValue::parse(r#"{"pdu_ids":["$a",1]}"#).unwrap();
        assert!(ids_in(&bad, "pdu_ids").is_err());
        let good = JsonValue::parse(r#"{"pdu_ids":["$a"]}"#).unwrap();
        assert_eq!(ids_in(&good, "pdu_ids").unwrap(), vec![String::from("$a")]);
    }
}
