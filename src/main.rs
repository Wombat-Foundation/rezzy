use clap::{Parser, ValueEnum};
use ruma_lean::{lean_kahn_sort, LeanEvent, StateResVersion};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    input: Vec<PathBuf>,

    #[arg(short, long)]
    room: Option<String>,

    #[arg(long, env = "MATRIX_HOMESERVER")]
    homeserver: Option<String>,

    #[arg(long, env = "MATRIX_TOKEN")]
    token: Option<String>,

    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(short, long, value_enum)]
    state_res: Option<StateResVersion>,

    #[arg(short, long, value_enum, default_value = "default")]
    format: OutputFormat,

    #[arg(long)]
    debug: bool,

    #[arg(long, default_value = "matrix.org")]
    origin: String,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq, Default)]
enum OutputFormat {
    #[default]
    Events,
    Default,
    Federation,
}

fn parse_room_version(ver: &str) -> anyhow::Result<StateResVersion> {
    match ver {
        "1" => Ok(StateResVersion::V1),
        "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10" | "11" => Ok(StateResVersion::V2),
        "12" => Ok(StateResVersion::V2_1),
        _ => anyhow::bail!("Unsupported room version: {ver}"),
    }
}

fn detect_version(events: &[serde_json::Value], debug: bool) -> anyhow::Result<StateResVersion> {
    // First pass: look for a top-level m.room.create event
    for ev in events {
        if ev.get("type").and_then(|t| t.as_str()) == Some("m.room.create") {
            if let Some(ver) = ev
                .get("content")
                .and_then(|c| c.get("room_version"))
                .and_then(|v| v.as_str())
            {
                if debug {
                    eprintln!("[DEBUG] Found m.room.create with version: {}", ver);
                }
                return parse_room_version(ver);
            }
        }
    }

    anyhow::bail!(
        "No m.room.create event found — cannot detect room version. \
         Use --state-res to specify the algorithm manually."
    )
}

fn fetch_room_state(
    homeserver: &str,
    room_id: &str,
    token: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    let base = if homeserver.starts_with("http://") || homeserver.starts_with("https://") {
        homeserver.to_string()
    } else {
        format!("https://{}", homeserver)
    };
    let url = format!("{}/_matrix/client/v3/rooms/{}/state", base, room_id);
    eprintln!("Fetching {}", url);
    let mut request = ureq::get(&url);
    if let Some(t) = token {
        request = request.set("Authorization", &format!("Bearer {}", t));
    }

    let response = match request.call() {
        Ok(resp) => resp,
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            anyhow::bail!("HTTP {}: {}", code, body);
        }
        Err(e) => anyhow::bail!("Request failed: {}", e),
    };
    let body = response.into_string()?;

    let val: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse JSON: {}. Response: {}",
            e,
            &body[..body.len().min(500)]
        )
    })?;
    Ok(val)
}

/// Load events from a single file path. Returns a Vec of raw JSON values.
fn load_file(input_path: &PathBuf) -> anyhow::Result<Vec<serde_json::Value>> {
    let input_reader: Box<dyn Read> = if input_path.to_str() == Some("-") {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(input_path)?)
    };

    let is_jsonl = input_path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"));

    let mut reader = BufReader::new(input_reader);

    if is_jsonl {
        let mut values = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let val: serde_json::Value = serde_json::from_str(&line)?;
            values.push(val);
        }
        if values.is_empty() {
            anyhow::bail!("No input data provided in JSONL file.");
        }
        Ok(values)
    } else {
        let mut input_data = Vec::new();
        loop {
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line)?;
            if bytes_read == 0 {
                break;
            }
            if line.trim().is_empty() {
                continue;
            }
            input_data.extend_from_slice(line.as_bytes());
        }
        if input_data.is_empty() {
            anyhow::bail!("No input data provided before empty line or EOF.");
        }
        let val: serde_json::Value = serde_json::from_slice(&input_data)?;
        match val {
            serde_json::Value::Array(arr) => Ok(arr),
            other => Ok(vec![other]),
        }
    }
}

/// Merge multiple event sets by event_id (first-seen wins, PDUs are immutable).
/// Returns the merged events and reports stats to stderr.
fn merge_event_sets(
    file_sets: Vec<(String, Vec<serde_json::Value>)>,
    debug: bool,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let num_files = file_sets.len();
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut merged: Vec<serde_json::Value> = Vec::new();
    let mut per_file_ids: Vec<HashSet<String>> = Vec::with_capacity(num_files);

    for (label, events) in &file_sets {
        let mut file_ids = HashSet::with_capacity(events.len());
        let mut added = 0usize;
        let mut dupes = 0usize;

        for val in events {
            let event_id = val
                .get("event_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            file_ids.insert(event_id.clone());
            if seen_ids.insert(event_id) {
                merged.push(val.clone());
                added += 1;
            } else {
                dupes += 1;
            }
        }

        eprintln!(
            "[merge] {}: {} events ({} new, {} shared)",
            label,
            events.len(),
            added,
            dupes
        );
        per_file_ids.push(file_ids);
    }

    // Merge-base check: verify each file shares at least one event with another
    if num_files >= 2 {
        let mut any_shared = false;
        for i in 0..num_files {
            for j in (i + 1)..num_files {
                let pair_shared = per_file_ids[i].intersection(&per_file_ids[j]).count();
                if pair_shared > 0 {
                    any_shared = true;
                    break;
                }
            }
            if any_shared {
                break;
            }
        }

        if !any_shared {
            anyhow::bail!(
                "Disjoint DAGs: no shared events found across inputs. \
                 Cannot compute meaningful merge — the DAGs share no history."
            );
        }

        // Report total shared count (union of all pairwise intersections)
        let total_shared: usize = {
            let mut shared_ids: HashSet<&String> = HashSet::new();
            for i in 0..num_files {
                for j in (i + 1)..num_files {
                    shared_ids.extend(per_file_ids[i].intersection(&per_file_ids[j]));
                }
            }
            shared_ids.len()
        };

        eprintln!(
            "[merge] merge-base: {} shared events across {} inputs",
            total_shared, num_files
        );

        if debug {
            // Find the merge-base frontier: shared events with the highest depths
            let shared_all: HashSet<&String> = {
                let mut s: HashSet<&String> = HashSet::new();
                for i in 0..num_files {
                    for j in (i + 1)..num_files {
                        s.extend(per_file_ids[i].intersection(&per_file_ids[j]));
                    }
                }
                s
            };
            let mut shared_depths: Vec<(&String, u64)> = shared_all
                .iter()
                .filter_map(|id| {
                    merged.iter().find_map(|v| {
                        let eid = v.get("event_id")?.as_str()?;
                        if eid == id.as_str() {
                            Some((*id, v.get("depth")?.as_u64().unwrap_or(0)))
                        } else {
                            None
                        }
                    })
                })
                .collect();
            shared_depths.sort_by_key(|b| std::cmp::Reverse(b.1));
            eprintln!(
                "[merge] highest shared depths: {:?}",
                &shared_depths[..shared_depths.len().min(5)]
            );
        }
    }

    eprintln!("[merge] total: {} unique events", merged.len());
    Ok(merged)
}

fn run_cli(args: &Args) -> anyhow::Result<serde_json::Value> {
    let input_val: serde_json::Value = if let Some(room_id) = &args.room {
        let homeserver = args
            .homeserver
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--homeserver is required when using --room"))?;

        // Token priority: --token / MATRIX_TOKEN > MTOKEN_{SERVER} > None
        let token = args.token.clone().or_else(|| {
            let env_key = format!(
                "MTOKEN_{}",
                homeserver
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .to_uppercase()
                    .replace(['.', '-'], "_")
            );
            std::env::var(&env_key).ok()
        });
        fetch_room_state(homeserver, room_id, token.as_deref())?
    } else if !args.input.is_empty() {
        if args.input.len() == 1 {
            // Single input: preserve existing behavior (supports {events, heads} wrapper)
            let events = load_file(&args.input[0])?;
            serde_json::Value::Array(events)
        } else {
            // Multiple inputs: merge DAGs by event_id
            let mut file_sets = Vec::with_capacity(args.input.len());
            for path in &args.input {
                let label = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| path.display().to_string());
                let events = load_file(path)?;
                file_sets.push((label, events));
            }
            let merged = merge_event_sets(file_sets, args.debug)?;
            serde_json::Value::Array(merged)
        }
    } else {
        anyhow::bail!("Either --input or --room must be provided.");
    };

    let (raw_events, heads) = if let Some(obj) = input_val.as_object() {
        if obj.contains_key("events") && obj.contains_key("heads") {
            let evs = obj
                .get("events")
                .unwrap()
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("'events' field must be a JSON array"))?
                .clone();
            let hds_arr = obj
                .get("heads")
                .unwrap()
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("'heads' field must be a JSON array"))?;
            let mut hds = Vec::with_capacity(hds_arr.len());
            for v in hds_arr {
                hds.push(
                    v.as_str()
                        .ok_or_else(|| anyhow::anyhow!("each 'head' must be a string"))?
                        .to_string(),
                );
            }
            (evs, hds)
        } else {
            (vec![input_val], Vec::new())
        }
    } else if let Some(arr) = input_val.as_array() {
        (arr.clone(), Vec::new())
    } else {
        anyhow::bail!("Unexpected JSON format");
    };

    let event_count = raw_events.len();
    let version = match args.state_res {
        Some(v) => v,
        None => detect_version(&raw_events, args.debug)?,
    };

    let mut raw_map = HashMap::with_capacity(event_count);
    let mut events_map = HashMap::with_capacity(event_count);
    let mut creator_user_id = String::new();

    for val in raw_events {
        match serde_json::from_value::<LeanEvent>(val.clone()) {
            Ok(ev) => {
                if ev.event_type == "m.room.create" {
                    creator_user_id = ev.sender.clone();
                }
                raw_map.insert(ev.event_id.clone(), val);
                events_map.insert(ev.event_id.clone(), ev);
            }
            Err(e) => {
                if args.debug {
                    eprintln!("[DEBUG] Failed to parse event: {:?}. Error: {}", val, e);
                }
                let _ = serde_json::from_value::<LeanEvent>(val)?;
            }
        }
    }

    // Auto-compute heads from prev_events graph when none provided
    let heads = if heads.is_empty() {
        let all_ids: std::collections::HashSet<String> = events_map.keys().cloned().collect();
        let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
        for ev in events_map.values() {
            for pe in &ev.prev_events {
                referenced.insert(pe.clone());
            }
        }
        let mut auto_heads: Vec<String> = all_ids.difference(&referenced).cloned().collect();
        auto_heads.sort();
        if args.debug {
            eprintln!(
                "[DEBUG] Auto-computed {} heads: {:?}",
                auto_heads.len(),
                auto_heads
            );
        }
        auto_heads
    } else {
        heads
    };

    let state_maps = if heads.len() <= 1 {
        // Single head (or no heads): forward walk — sort by Matrix depth ascending,
        // keep the highest-depth (most recent) event for each (type, state_key).
        // This correctly matches production server state resolution for linear DAGs.
        let reachable: std::collections::HashSet<String> = if heads.len() == 1 {
            // Only include events reachable from the head via prev_events
            let mut visited = std::collections::HashSet::new();
            let mut stack = vec![heads[0].clone()];
            while let Some(ev_id) = stack.pop() {
                if visited.insert(ev_id.clone()) {
                    if let Some(ev) = events_map.get(&ev_id) {
                        for pe in &ev.prev_events {
                            stack.push(pe.clone());
                        }
                    }
                }
            }
            visited
        } else {
            events_map.keys().cloned().collect()
        };

        let mut sorted_events: Vec<&LeanEvent> = events_map
            .values()
            .filter(|ev| reachable.contains(&ev.event_id))
            .collect();
        sorted_events.sort_by(|a, b| a.cmp_by_depth(b));

        let mut state_map = std::collections::HashMap::new();
        for ev in sorted_events {
            let key = (ev.event_type.clone(), ev.state_key.clone());
            // Later (higher depth) events overwrite earlier ones
            state_map.insert(key, ev.event_id.clone());
        }
        vec![state_map]
    } else {
        // Multi-head (forked DAG): compute separate state sets per head
        // via backward walk, then let resolve_lean handle conflicts.
        let mut maps = Vec::new();
        for head_id in &heads {
            let mut reachable: Vec<&LeanEvent> = Vec::new();
            let mut visited = std::collections::HashSet::new();
            let mut stack = vec![head_id.clone()];

            while let Some(ev_id) = stack.pop() {
                if visited.insert(ev_id.clone()) {
                    if let Some(ev) = events_map.get(&ev_id) {
                        reachable.push(ev);
                        for prev_ev_id in &ev.prev_events {
                            stack.push(prev_ev_id.clone());
                        }
                    }
                }
            }

            // Sort by depth ascending, keep latest for each key
            reachable.sort_by(|a, b| a.cmp_by_depth(b));
            let mut state_map = std::collections::HashMap::new();
            for ev in reachable {
                let key = (ev.event_type.clone(), ev.state_key.clone());
                state_map.insert(key, ev.event_id.clone());
            }
            maps.push(state_map);
        }
        maps
    };

    let mut power_events = HashMap::new();
    let power_event_types = [
        "m.room.create",
        "m.room.power_levels",
        "m.room.join_rules",
        "m.room.member",
    ];
    for ev in events_map.values() {
        if power_event_types.contains(&ev.event_type.as_str()) {
            let mut power_ev = ev.clone();
            if (!creator_user_id.is_empty() && ev.sender == creator_user_id)
                || ev.event_type == "m.room.create"
            {
                power_ev.power_level = 100;
            } else {
                power_ev.power_level = 0;
            }
            power_events.insert(ev.event_id.clone(), power_ev);
        }
    }

    let sorted_power_ids = lean_kahn_sort(&power_events, version);
    let mut resolved_power_state = std::collections::BTreeMap::new();
    for id in sorted_power_ids {
        let ev = power_events.get(&id).unwrap();
        resolved_power_state.insert((ev.event_type.clone(), ev.state_key.clone()), id);
    }

    let mut user_power_levels = HashMap::new();
    let mut default_power_level = 0;
    if let Some(id) = resolved_power_state.get(&("m.room.power_levels".to_string(), "".to_string()))
    {
        if let Some(ev) = events_map.get(id) {
            if let Some(users) = ev.content.get("users").and_then(|u| u.as_object()) {
                for (user_id, pl) in users {
                    if let Some(pl_val) = pl.as_i64() {
                        user_power_levels.insert(user_id.clone(), pl_val);
                    }
                }
            }
            if let Some(pl_val) = ev.content.get("users_default").and_then(|v| v.as_i64()) {
                default_power_level = pl_val;
            }
        }
    }

    for ev in events_map.values_mut() {
        ev.power_level = *user_power_levels
            .get(&ev.sender)
            .unwrap_or(&default_power_level);
    }

    let start = Instant::now();
    let mut occurrences: HashMap<(String, String), HashMap<String, usize>> = HashMap::new();
    let num_sets = state_maps.len();
    for map in &state_maps {
        for (key, id) in map {
            *occurrences
                .entry(key.clone())
                .or_default()
                .entry(id.clone())
                .or_insert(0) += 1;
        }
    }

    let mut unconflicted_state = std::collections::BTreeMap::new();
    let mut conflicted_events = HashMap::new();
    for (key, ids) in occurrences {
        if ids.len() == 1 && ids.values().next().unwrap() == &num_sets {
            // All heads agree on this event ID for this key
            let id = ids.keys().next().unwrap();
            unconflicted_state.insert(key, id.clone());
            if version == StateResVersion::V2_1 {
                if let Some(ev) = events_map.get(id) {
                    conflicted_events.insert(id.clone(), ev.clone());
                }
            }
        } else {
            // Heads disagree, add all events for this key to the conflicted set
            for id in ids.keys() {
                if let Some(ev) = events_map.get(id) {
                    conflicted_events.insert(id.clone(), ev.clone());
                }
            }
        }
    }

    let final_state_map =
        ruma_lean::resolve_lean(unconflicted_state, conflicted_events.clone(), version);

    let duration = start.elapsed();

    let resolved_state_list: Vec<String> = final_state_map.values().cloned().collect();
    let auth_chain_ids = compute_auth_chain(&resolved_state_list, &events_map);

    match args.format {
        OutputFormat::Events => {
            let state_events: Vec<&serde_json::Value> = resolved_state_list
                .iter()
                .filter_map(|id| raw_map.get(id))
                .collect();
            Ok(serde_json::json!(state_events))
        }
        OutputFormat::Federation => {
            let state_events: Vec<&serde_json::Value> = resolved_state_list
                .iter()
                .filter_map(|id| raw_map.get(id))
                .collect();
            let auth_chain_events: Vec<&serde_json::Value> = auth_chain_ids
                .iter()
                .filter_map(|id| raw_map.get(id))
                .collect();

            Ok(serde_json::json!({
                "origin": args.origin,
                "state": state_events,
                "auth_chain": auth_chain_events
            }))
        }
        OutputFormat::Default => Ok(serde_json::json!({
            "status": "success",
            "version": version,
            "duration_ms": duration.as_millis(),
            "resolved_state_size": resolved_state_list.len(),
            "auth_chain_size": auth_chain_ids.len(),
            "state_event_ids": resolved_state_list
        })),
    }
}

fn compute_auth_chain(
    resolved_ids: &[String],
    events_map: &HashMap<String, LeanEvent>,
) -> Vec<String> {
    let mut auth_chain = std::collections::BTreeSet::new();
    let mut stack = Vec::new();

    for id in resolved_ids {
        stack.push(id.clone());
    }

    while let Some(event_id) = stack.pop() {
        if let Some(event) = events_map.get(&event_id) {
            for auth_id in &event.auth_events {
                if !auth_chain.contains(auth_id) {
                    auth_chain.insert(auth_id.clone());
                    stack.push(auth_id.clone());
                }
            }
        }
    }
    auth_chain.into_iter().collect()
}

fn main() {
    let args = Args::parse();
    match run_cli(&args) {
        Ok(output) => {
            let output_writer: Box<dyn Write> = match args.output {
                Some(path) => Box::new(BufWriter::new(
                    File::create(path).expect("Failed to create output file"),
                )),
                None => Box::new(BufWriter::new(io::stdout())),
            };
            let mut buffered_out = output_writer;
            serde_json::to_writer_pretty(&mut buffered_out, &output)
                .expect("Failed to write output");
            if let Err(e) = writeln!(buffered_out) {
                if e.kind() != std::io::ErrorKind::BrokenPipe {
                    panic!("Failed to write trailing newline: {}", e);
                }
            }
            buffered_out.flush().expect("Failed to flush output buffer");
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            let err_json = serde_json::json!({
                "status": "error",
                "error": e.to_string()
            });
            serde_json::to_writer_pretty(io::stderr(), &err_json).ok();
            eprintln!();
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(id: &str, depth: u64) -> serde_json::Value {
        json!({
            "event_id": id,
            "type": "m.room.member",
            "state_key": format!("@user:{}", id),
            "origin_server_ts": 1000 + depth,
            "depth": depth,
            "prev_events": [],
            "auth_events": []
        })
    }

    #[test]
    fn test_merge_dedup_by_event_id() {
        let a = vec![ev("$1", 1), ev("$2", 2), ev("$3", 3)];
        let b = vec![ev("$2", 2), ev("$3", 3), ev("$4", 4)];
        let result =
            merge_event_sets(vec![("a.jsonl".into(), a), ("b.jsonl".into(), b)], false).unwrap();

        let ids: Vec<&str> = result
            .iter()
            .map(|v| v["event_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["$1", "$2", "$3", "$4"]);
    }

    #[test]
    fn test_merge_disjoint_fails() {
        let a = vec![ev("$1", 1), ev("$2", 2)];
        let b = vec![ev("$3", 3), ev("$4", 4)];
        let result = merge_event_sets(vec![("a.jsonl".into(), a), ("b.jsonl".into(), b)], false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Disjoint DAGs"));
    }

    #[test]
    fn test_merge_pairwise_shared() {
        // A shares with B, B shares with C, but A and C share nothing directly.
        // This should succeed because the graph is connected.
        let a = vec![ev("$1", 1), ev("$2", 2)];
        let b = vec![ev("$2", 2), ev("$3", 3)];
        let c = vec![ev("$3", 3), ev("$4", 4)];
        let result = merge_event_sets(
            vec![
                ("a.jsonl".into(), a),
                ("b.jsonl".into(), b),
                ("c.jsonl".into(), c),
            ],
            false,
        )
        .unwrap();

        let ids: Vec<&str> = result
            .iter()
            .map(|v| v["event_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["$1", "$2", "$3", "$4"]);
    }

    #[test]
    fn test_merge_single_file() {
        let a = vec![ev("$1", 1), ev("$2", 2)];
        let result = merge_event_sets(vec![("a.jsonl".into(), a)], false).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_merge_complete_overlap() {
        let a = vec![ev("$1", 1), ev("$2", 2), ev("$3", 3)];
        let b = vec![ev("$1", 1), ev("$2", 2), ev("$3", 3)];
        let result =
            merge_event_sets(vec![("a.jsonl".into(), a), ("b.jsonl".into(), b)], false).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_merge_subset() {
        // Small DAG is a subset of large DAG (starstruck-style)
        let large = vec![ev("$1", 1), ev("$2", 2), ev("$3", 3), ev("$4", 4)];
        let small = vec![ev("$1", 1), ev("$2", 2)];
        let result = merge_event_sets(
            vec![("large.jsonl".into(), large), ("small.jsonl".into(), small)],
            false,
        )
        .unwrap();
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_merge_debug_depths() {
        let a = vec![ev("$1", 10), ev("$2", 20)];
        let b = vec![ev("$2", 20), ev("$3", 30)];
        // Should not panic with debug=true
        let result =
            merge_event_sets(vec![("a.jsonl".into(), a), ("b.jsonl".into(), b)], true).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_merge_single_event_per_file() {
        let a = vec![ev("$1", 1)];
        let b = vec![ev("$1", 1)];
        let result =
            merge_event_sets(vec![("a.jsonl".into(), a), ("b.jsonl".into(), b)], false).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_merge_two_single_events_disjoint() {
        let a = vec![ev("$1", 1)];
        let b = vec![ev("$2", 2)];
        let result = merge_event_sets(vec![("a.jsonl".into(), a), ("b.jsonl".into(), b)], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_two_events_one_shared() {
        let a = vec![ev("$1", 1), ev("$2", 2)];
        let b = vec![ev("$2", 2), ev("$3", 3)];
        let result =
            merge_event_sets(vec![("a.jsonl".into(), a), ("b.jsonl".into(), b)], false).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_merge_one_file_only() {
        let a = vec![ev("$1", 1)];
        let result = merge_event_sets(vec![("a.jsonl".into(), a)], false).unwrap();
        assert_eq!(result.len(), 1);
    }
}
