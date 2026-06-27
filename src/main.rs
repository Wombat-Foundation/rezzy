use clap::{Parser, ValueEnum};
use ruma_lean::{LeanEvent, StateResVersion};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, num_args(1..))]
    input: Vec<PathBuf>,

    #[arg(short, long)]
    room: Option<String>,

    #[arg(long, env = "MATRIX_HOMESERVER")]
    homeserver: Option<String>,

    /// Matrix access token. Falls back to per-domain env var (e.g. `MTOKEN_MATRIX_UNREDACTED_ORG`)
    #[arg(long, env = "MATRIX_TOKEN", hide_env_values = true)]
    token: Option<String>,

    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(short, long, value_enum)]
    state_res: Option<StateResVersion>,

    #[arg(short, long, value_enum, default_value = "default")]
    format: OutputFormat,

    #[arg(long)]
    debug: bool,

    #[arg(short, long)]
    quiet: bool,

    #[arg(long, default_value = "matrix.org")]
    origin: String,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq, Default)]
enum OutputFormat {
    #[default]
    Events,
    Default,
    Deltas,
    Federation,
    Summary,
    Timeline,
}

fn parse_room_version(ver: &str) -> anyhow::Result<StateResVersion> {
    match ver {
        "1" => Ok(StateResVersion::V1),
        "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10" | "11" => Ok(StateResVersion::V2),
        "12" => Ok(StateResVersion::V2_1),
        "12.1" => Ok(StateResVersion::V2_1_1),
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
                    eprintln!("[DEBUG] Found m.room.create with version: {ver}");
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

fn compute_state_hash(
    state: &std::collections::BTreeMap<(String, Option<String>), String>,
) -> String {
    let mut hash: u64 = 14_695_981_039_346_656_037; // FNV offset basis
    for ((event_type, state_key), event_id) in state {
        for &byte in event_type.as_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(1_099_511_628_211); // FNV prime
        }
        hash ^= 0x00;
        hash = hash.wrapping_mul(1_099_511_628_211);
        if let Some(key) = state_key {
            for &byte in key.as_bytes() {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(1_099_511_628_211);
            }
        }
        hash ^= 0x00;
        hash = hash.wrapping_mul(1_099_511_628_211);
        for &byte in event_id.as_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(1_099_511_628_211);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(1_099_511_628_211);
    }
    format!("{hash:016x}")
}

fn fetch_room_state(
    homeserver: &str,
    room_id: &str,
    token: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    let base = if homeserver.starts_with("http://") || homeserver.starts_with("https://") {
        homeserver.to_string()
    } else {
        format!("https://{homeserver}")
    };
    let url = format!("{base}/_matrix/client/v3/rooms/{room_id}/state");
    eprintln!("Fetching {url}");
    let mut request = ureq::get(&url);
    if let Some(t) = token {
        request = request.set("Authorization", &format!("Bearer {t}"));
    }

    let response = match request.call() {
        Ok(resp) => resp,
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            anyhow::bail!("HTTP {code}: {body}");
        }
        Err(e) => anyhow::bail!("Request failed: {e}"),
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

/// Merge multiple event sets by `event_id` (first-seen wins, PDUs are immutable).
/// Returns the merged events and reports stats to stderr.
fn merge_event_sets(
    file_sets: &[(String, Vec<serde_json::Value>)],
    debug: bool,
    quiet: bool,
) -> anyhow::Result<Vec<serde_json::Value>> {
    ruma_lean::merge_event_sets(file_sets, debug, quiet)
}

fn load_or_fetch_input_value(args: &Args) -> anyhow::Result<serde_json::Value> {
    if let Some(room_id) = &args.room {
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
        fetch_room_state(homeserver, room_id, token.as_deref())
    } else if !args.input.is_empty() {
        if args.input.len() == 1 {
            let input_path = &args.input[0];
            let is_jsonl = input_path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"));
            if is_jsonl {
                let events = load_file(input_path)?;
                Ok(serde_json::Value::Array(events))
            } else {
                let content = std::fs::read(input_path)?;
                let val: serde_json::Value = serde_json::from_slice(&content)?;
                Ok(val)
            }
        } else {
            // Multiple inputs: merge DAGs by event_id
            let mut file_sets = Vec::with_capacity(args.input.len());
            for path in &args.input {
                let label = path.file_name().map_or_else(
                    || path.display().to_string(),
                    |n| n.to_string_lossy().to_string(),
                );
                let events = load_file(path)?;
                file_sets.push((label, events));
            }
            let merged = merge_event_sets(&file_sets, args.debug, args.quiet)?;
            Ok(serde_json::Value::Array(merged))
        }
    } else {
        anyhow::bail!("Either --input or --room must be provided.");
    }
}

fn parse_and_extract_heads(
    input_val: &serde_json::Value,
) -> anyhow::Result<(Vec<serde_json::Value>, Vec<String>)> {
    let (raw_events, heads) = if let Some(obj) = input_val.as_object() {
        if obj.contains_key("events") {
            let evs = obj
                .get("events")
                .unwrap()
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("'events' field must be a JSON array"))?
                .clone();
            let mut hds = Vec::new();
            if let Some(hds_arr) = obj.get("heads").and_then(|h| h.as_array()) {
                for v in hds_arr {
                    hds.push(
                        v.as_str()
                            .ok_or_else(|| anyhow::anyhow!("each 'head' must be a string"))?
                            .to_string(),
                    );
                }
            }
            (evs, hds)
        } else if obj.contains_key("event_id") || obj.contains_key("type") {
            (vec![input_val.clone()], Vec::new())
        } else {
            anyhow::bail!("Unrecognized JSON object structure. Top-level object must either contain 'events' or represent a single event with 'event_id' or 'type'.");
        }
    } else if let Some(arr) = input_val.as_array() {
        (arr.clone(), Vec::new())
    } else {
        anyhow::bail!("Unexpected JSON format: expected object or array");
    };
    Ok((raw_events, heads))
}

fn compute_state_maps(
    heads: &[String],
    events_map: &HashMap<String, LeanEvent>,
    raw_map: &HashMap<String, serde_json::Value>,
) -> Vec<HashMap<(String, Option<String>), String>> {
    if heads.len() <= 1 {
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
            if raw_map
                .get(&ev.event_id)
                .is_some_and(|r| r.get("state_key").is_some())
            {
                let key = (ev.event_type.clone(), ev.state_key.clone());
                // Later (higher depth) events overwrite earlier ones
                state_map.insert(key, ev.event_id.clone());
            }
        }
        vec![state_map]
    } else {
        // Multi-head (forked DAG): compute separate state sets per head
        // via backward walk, then let resolve_lean handle conflicts.
        let mut maps = Vec::new();
        for head_id in heads {
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
                if raw_map
                    .get(&ev.event_id)
                    .is_some_and(|r| r.get("state_key").is_some())
                {
                    let key = (ev.event_type.clone(), ev.state_key.clone());
                    state_map.insert(key, ev.event_id.clone());
                }
            }
            maps.push(state_map);
        }
        maps
    }
}

struct FormattingContext<'a> {
    args: &'a Args,
    events_map: &'a HashMap<String, LeanEvent>,
    raw_map: &'a HashMap<String, serde_json::Value>,
    heads: &'a [String],
    final_state_map: &'a std::collections::BTreeMap<(String, Option<String>), String>,
    resolved_state_list: &'a [String],
    auth_chain_ids: &'a [String],
    version: StateResVersion,
    duration: std::time::Duration,
    event_count: usize,
}

type SharedStateMap = std::sync::Arc<std::collections::BTreeMap<(String, Option<String>), String>>;

fn resolve_parent_states(
    parent_states: &[SharedStateMap],
    events_map: &HashMap<String, LeanEvent>,
    version: StateResVersion,
) -> SharedStateMap {
    let mut all_identical = true;
    let first_state = &parent_states[0];
    for state in &parent_states[1..] {
        if !std::sync::Arc::ptr_eq(state, first_state) && state != first_state {
            all_identical = false;
            break;
        }
    }

    if all_identical {
        first_state.clone()
    } else {
        // Run state-res on parent states
        let num_sets = parent_states.len();
        let mut occurrences: HashMap<(String, Option<String>), HashMap<String, usize>> =
            HashMap::new();
        for map in parent_states {
            for (key, id) in map.as_ref() {
                *occurrences
                    .entry(key.clone())
                    .or_default()
                    .entry(id.clone())
                    .or_insert(0) += 1;
            }
        }

        let mut unconflicted_state = std::collections::BTreeMap::new();
        let mut conflicted_state_set = Vec::new();

        for (key, ids) in occurrences {
            if ids.len() == 1 && ids.values().next().unwrap() == &num_sets {
                let id = ids.keys().next().unwrap();
                unconflicted_state.insert(key, id.clone());
            } else {
                for id in ids.keys() {
                    conflicted_state_set.push(id.clone());
                }
            }
        }

        let mut conflicted_events = HashMap::new();
        for id in &conflicted_state_set {
            if let Some(parent_ev) = events_map.get(id) {
                conflicted_events.insert(id.clone(), parent_ev.clone());
            }
        }

        // Optimize resolve_lean by only passing the transitively pruned
        // conflicted auth subgraph instead of the entire events_map.
        let auth_context =
            ruma_lean::compute_v2_1_conflicted_subgraph(events_map, &conflicted_state_set);

        let resolved = ruma_lean::resolve_lean(
            unconflicted_state,
            conflicted_events,
            &auth_context,
            version,
        );
        std::sync::Arc::new(resolved)
    }
}

fn format_deltas_output(ctx: &FormattingContext) -> serde_json::Value {
    let mut sorted_events: Vec<&LeanEvent> = ctx.events_map.values().collect();
    sorted_events.sort_by(|a, b| a.cmp_by_depth(b));

    let mut state_after_map: HashMap<String, SharedStateMap> = HashMap::new();
    let mut state_hash_map: HashMap<String, String> = HashMap::new();
    let mut checkpoints = Vec::new();

    for ev in &sorted_events {
        let mut state_before = std::sync::Arc::new(std::collections::BTreeMap::new());
        let mut parent_hash = None;

        if ev.prev_events.is_empty() {
            // Empty state before
        } else if ev.prev_events.len() == 1 {
            let prev_id = &ev.prev_events[0];
            if let Some(prev_state) = state_after_map.get(prev_id) {
                state_before = prev_state.clone();
                parent_hash = state_hash_map.get(prev_id).cloned();
            }
        } else {
            // Multi-head merge
            let mut parent_states = Vec::new();
            for prev_id in &ev.prev_events {
                if let Some(prev_state) = state_after_map.get(prev_id) {
                    parent_states.push(prev_state.clone());
                }
            }

            if !parent_states.is_empty() {
                if parent_states.len() == 1 {
                    state_before = parent_states[0].clone();
                    parent_hash = ev
                        .prev_events
                        .first()
                        .and_then(|prev_id| state_hash_map.get(prev_id))
                        .cloned();
                } else {
                    state_before =
                        resolve_parent_states(&parent_states, ctx.events_map, ctx.version);
                    parent_hash = Some(compute_state_hash(state_before.as_ref()));
                }
            }
        }

        let mut state_after = state_before.clone();
        if ev.state_key.is_some() {
            let mut modified = state_before.as_ref().clone();
            modified.insert(
                (ev.event_type.clone(), ev.state_key.clone()),
                ev.event_id.clone(),
            );
            state_after = std::sync::Arc::new(modified);
        }

        let hash_str = compute_state_hash(&state_after);
        state_after_map.insert(ev.event_id.clone(), state_after.clone());
        state_hash_map.insert(ev.event_id.clone(), hash_str.clone());

        let mut deltas = Vec::new();
        if ev.prev_events.is_empty() {
            for (key, event_id) in state_after.as_ref() {
                deltas.push(serde_json::json!({
                    "type": key.0,
                    "state_key": key.1,
                    "event_id": event_id,
                }));
            }
        } else {
            let parent_state = state_before.as_ref();
            for (key, event_id) in state_after.as_ref() {
                match parent_state.get(key) {
                    Some(parent_event_id) if parent_event_id == event_id => {}
                    _ => {
                        deltas.push(serde_json::json!({
                            "type": key.0,
                            "state_key": key.1,
                            "event_id": event_id,
                        }));
                    }
                }
            }
            for key in parent_state.keys() {
                if !state_after.contains_key(key) {
                    deltas.push(serde_json::json!({
                        "type": key.0,
                        "state_key": key.1,
                        "event_id": serde_json::Value::Null,
                    }));
                }
            }
        }

        checkpoints.push(serde_json::json!({
            "hash": hash_str,
            "parent": parent_hash,
            "event_id": ev.event_id,
            "deltas": deltas,
        }));
    }

    serde_json::json!(checkpoints)
}

fn compute_component_roots(
    events_map: &HashMap<String, LeanEvent>,
    include_prev: bool,
    include_auth: bool,
) -> Vec<String> {
    let mut component_roots = Vec::new();
    if !events_map.is_empty() {
        let mut parent: Vec<usize> = (0..events_map.len()).collect();
        let mut id_to_index: HashMap<&str, usize> = HashMap::with_capacity(events_map.len());
        let mut index_to_ev: Vec<&LeanEvent> = Vec::with_capacity(events_map.len());
        for (i, ev) in events_map.values().enumerate() {
            id_to_index.insert(ev.event_id.as_str(), i);
            index_to_ev.push(ev);
        }
        for ev in events_map.values() {
            if let Some(&u) = id_to_index.get(ev.event_id.as_str()) {
                if include_prev {
                    for prev in &ev.prev_events {
                        if let Some(&v) = id_to_index.get(prev.as_str()) {
                            let mut root_u = u;
                            while parent[root_u] != root_u {
                                parent[root_u] = parent[parent[root_u]];
                                root_u = parent[root_u];
                            }
                            let mut root_v = v;
                            while parent[root_v] != root_v {
                                parent[root_v] = parent[parent[root_v]];
                                root_v = parent[root_v];
                            }
                            if root_u != root_v {
                                parent[root_u] = root_v;
                            }
                        }
                    }
                }
                if include_auth {
                    for auth in &ev.auth_events {
                        if let Some(&v) = id_to_index.get(auth.as_str()) {
                            let mut root_u = u;
                            while parent[root_u] != root_u {
                                parent[root_u] = parent[parent[root_u]];
                                root_u = parent[root_u];
                            }
                            let mut root_v = v;
                            while parent[root_v] != root_v {
                                parent[root_v] = parent[parent[root_v]];
                                root_v = parent[root_v];
                            }
                            if root_u != root_v {
                                parent[root_u] = root_v;
                            }
                        }
                    }
                }
            }
        }
        let mut comp_roots_map: HashMap<usize, &LeanEvent> = HashMap::new();
        for (i, &ev) in index_to_ev.iter().enumerate() {
            let mut u = i;
            while parent[u] != u {
                parent[u] = parent[parent[u]];
                u = parent[u];
            }
            comp_roots_map
                .entry(u)
                .and_modify(|e| {
                    if ev.depth < e.depth || (ev.depth == e.depth && ev.event_id < e.event_id) {
                        *e = ev;
                    }
                })
                .or_insert(ev);
        }
        component_roots = comp_roots_map
            .values()
            .map(|e| e.event_id.clone())
            .collect();
        component_roots.sort();
    }
    component_roots
}

fn format_summary_output(ctx: &FormattingContext) -> serde_json::Value {
    let mut state_entries: Vec<serde_json::Value> = Vec::new();
    let mut members: HashMap<String, Vec<serde_json::Value>> = HashMap::new();

    for ((typ, sk), eid) in ctx.final_state_map {
        let ev = ctx.events_map.get(eid);
        if typ == "m.room.member" {
            let membership = ev
                .and_then(|e| e.content.get("membership"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            let displayname = ev
                .and_then(|e| e.content.get("displayname"))
                .and_then(|d| d.as_str())
                .unwrap_or("");
            members
                .entry(membership.to_string())
                .or_default()
                .push(serde_json::json!({
                    "user_id": sk,
                    "displayname": displayname,
                    "event_id": eid,
                    "depth": ev.map_or(0, |e| e.depth),
                }));
        } else {
            state_entries.push(serde_json::json!({
                "type": typ,
                "state_key": sk,
                "event_id": eid,
                "sender": ev.map_or("?", |e| e.sender.as_str()),
                "depth": ev.map_or(0, |e| e.depth),
            }));
        }
    }

    state_entries.sort_by(|a, b| {
        let ta = a["type"].as_str().unwrap_or("");
        let tb = b["type"].as_str().unwrap_or("");
        ta.cmp(tb).then_with(|| {
            let sa = a["state_key"].as_str().unwrap_or("");
            let sb = b["state_key"].as_str().unwrap_or("");
            sa.cmp(sb)
        })
    });

    // Sort members within each group by user_id
    for list in members.values_mut() {
        list.sort_by(|a, b| {
            let ua = a["user_id"].as_str().unwrap_or("");
            let ub = b["user_id"].as_str().unwrap_or("");
            ua.cmp(ub)
        });
    }

    // Build ordered membership object
    let membership_order = ["join", "invite", "knock", "leave", "ban"];
    let mut membership_obj = serde_json::Map::new();
    for status in &membership_order {
        if let Some(list) = members.get(*status) {
            membership_obj.insert(
                status.to_string(),
                serde_json::json!({
                    "count": list.len(),
                    "users": list
                }),
            );
        }
    }
    // Include any unexpected membership values
    for (status, list) in &members {
        if !membership_order.contains(&status.as_str()) {
            membership_obj.insert(
                status.clone(),
                serde_json::json!({
                    "count": list.len(),
                    "users": list
                }),
            );
        }
    }

    let min_depth = ctx.events_map.values().map(|e| e.depth).min().unwrap_or(0);
    let max_depth = ctx.events_map.values().map(|e| e.depth).max().unwrap_or(0);
    let root_event_id = ctx
        .events_map
        .values()
        .min_by_key(|e| e.depth)
        .map_or("", |e| e.event_id.as_str());

    let component_roots_prev = compute_component_roots(ctx.events_map, true, false);
    let component_roots_auth = compute_component_roots(ctx.events_map, false, true);
    let component_roots_union = compute_component_roots(ctx.events_map, true, true);

    serde_json::json!({
        "status": "success",
        "version": ctx.version,
        "duration_ms": ctx.duration.as_millis(),
        "total_events": ctx.event_count,
        "resolved_state_size": state_entries.len() + members.values().map(std::vec::Vec::len).sum::<usize>(),
        "auth_chain_size": ctx.auth_chain_ids.len(),
        "min_depth": min_depth,
        "max_depth": max_depth,
        "root_event_id": root_event_id,
        "n_components": component_roots_union.len(),
        "n_components_prev": component_roots_prev.len(),
        "n_components_auth": component_roots_auth.len(),
        "component_roots_prev": component_roots_prev,
        "heads": ctx.heads,
        "membership": membership_obj,
        "state": state_entries
    })
}

fn get_user_displayname(user_id: &str, displaynames: &HashMap<String, String>) -> String {
    displaynames.get(user_id).cloned().unwrap_or_else(|| {
        user_id
            .split(':')
            .next()
            .unwrap_or(user_id)
            .trim_start_matches('@')
            .to_string()
    })
}

fn format_event_description(
    ev: &LeanEvent,
    sender: &str,
    displaynames: &HashMap<String, String>,
) -> Option<String> {
    match ev.event_type.as_str() {
        "m.room.create" => Some(format!("{sender} sent m.room.create state event")),
        "m.room.member" => {
            let membership = ev
                .content
                .get("membership")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let target =
                get_user_displayname(ev.state_key.as_deref().unwrap_or_default(), displaynames);
            let reason = ev
                .content
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match membership {
                "join" => Some(format!("{target} joined the room")),
                "leave" if ev.state_key.as_ref() == Some(&ev.sender) => {
                    Some(format!("{target} left the room"))
                }
                "leave" => Some(format!(
                    "{} kicked {}{}",
                    sender,
                    target,
                    if reason.is_empty() {
                        String::new()
                    } else {
                        format!(" {reason}")
                    }
                )),
                "ban" => Some(format!(
                    "{} banned {}{}",
                    sender,
                    target,
                    if reason.is_empty() {
                        String::new()
                    } else {
                        format!(" {reason}")
                    }
                )),
                "invite" => Some(format!("{sender} invited {target}")),
                "knock" => Some(format!("{target} knocked")),
                _ => Some(format!(
                    "{sender} set {target}'s membership to {membership}"
                )),
            }
        }
        "m.room.message" => {
            let body = ev
                .content
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let msgtype = ev
                .content
                .get("msgtype")
                .and_then(|v| v.as_str())
                .unwrap_or("m.text");
            match msgtype {
                "m.text" | "m.notice" => Some(format!("{sender}: {body}")),
                "m.image" => Some(format!("{sender} sent an image")),
                "m.video" => Some(format!("{sender} sent a video")),
                "m.audio" => Some(format!("{sender} sent an audio file")),
                "m.file" => Some(format!("{sender} sent a file")),
                "m.emote" => Some(format!("* {sender} {body}")),
                _ => Some(format!("{sender} sent {msgtype}")),
            }
        }
        "m.room.name" => {
            let name = ev
                .content
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            Some(format!("{sender} changed room name to \"{name}\""))
        }
        "m.room.topic" => {
            let topic = ev
                .content
                .get("topic")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            Some(format!("{sender} changed room topic to \"{topic}\""))
        }
        "m.room.avatar" => Some(format!("{sender} changed room avatar")),
        "m.room.redaction" => Some(format!("{sender} redacted an event")),
        "m.reaction" => None,
        "m.sticker" => Some(format!("{sender} sent a sticker")),
        typ => Some(format!("{sender} sent {typ} state event")),
    }
}

fn format_timeline_output(ctx: &FormattingContext) -> serde_json::Value {
    // Build displayname lookup from m.room.member events
    let mut displaynames: HashMap<String, String> = HashMap::new();
    let mut sorted_events: Vec<&LeanEvent> = ctx.events_map.values().collect();
    sorted_events.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.event_id.cmp(&b.event_id)));

    // First pass: collect displaynames
    for ev in &sorted_events {
        if ev.event_type == "m.room.member" {
            if let Some(dn) = ev.content.get("displayname").and_then(|v| v.as_str()) {
                if !dn.is_empty() {
                    displaynames.insert(ev.state_key.clone().unwrap_or_default(), dn.to_string());
                }
            }
        }
    }

    let mut output = String::new();
    let mut last_date = String::new();

    for ev in &sorted_events {
        let sender = get_user_displayname(&ev.sender, &displaynames);
        let Some(desc) = format_event_description(ev, &sender, &displaynames) else {
            continue;
        };

        let ts_ms = ev.origin_server_ts;
        let ts_secs = i64::try_from(ts_ms / 1000).unwrap();
        let time_of_day = u64::try_from((ts_secs % 86_400 + 86_400) % 86_400).unwrap();
        let hours = time_of_day / 3_600;
        let minutes = (time_of_day % 3_600) / 60;
        let days = ts_secs.div_euclid(86_400);

        let (y, m, d) = epoch_days_to_ymd(days);
        let month_names = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let month_str = month_names.get((m - 1) as usize).unwrap_or(&"???");
        let ampm = if hours < 12 { "AM" } else { "PM" };
        let h12 = if hours == 0 {
            12
        } else if hours > 12 {
            hours - 12
        } else {
            hours
        };
        let date = format!("{d} {month_str} {y} {h12:02}:{minutes:02} {ampm}");

        if date != last_date {
            if !last_date.is_empty() {
                output.push('\n');
            }
            last_date.clone_from(&date);
        }

        output.push_str(&desc);
        output.push('\n');
        output.push_str(&date);
        output.push('\n');
    }

    eprint!("{output}");
    serde_json::json!({
        "status": "success",
        "format": "timeline",
        "events": ctx.event_count
    })
}

fn format_cli_output(ctx: &FormattingContext) -> serde_json::Value {
    match ctx.args.format {
        OutputFormat::Deltas => format_deltas_output(ctx),
        OutputFormat::Summary => format_summary_output(ctx),
        OutputFormat::Timeline => format_timeline_output(ctx),
        OutputFormat::Events => {
            let mut state_events: Vec<&serde_json::Value> = ctx
                .resolved_state_list
                .iter()
                .filter_map(|id| ctx.raw_map.get(id))
                .collect();
            state_events.sort_by(|a, b| {
                let a_ev = a
                    .get("event_id")
                    .and_then(|id| id.as_str())
                    .and_then(|id| ctx.events_map.get(id));
                let b_ev = b
                    .get("event_id")
                    .and_then(|id| id.as_str())
                    .and_then(|id| ctx.events_map.get(id));

                let a_depth = a_ev.map_or(0, |e| e.depth);
                let b_depth = b_ev.map_or(0, |e| e.depth);

                a_depth.cmp(&b_depth).then_with(|| {
                    let a_id = a_ev.map_or("", |e| e.event_id.as_str());
                    let b_id = b_ev.map_or("", |e| e.event_id.as_str());
                    a_id.cmp(b_id)
                })
            });
            serde_json::json!(state_events)
        }
        OutputFormat::Federation => {
            let state_events: Vec<&serde_json::Value> = ctx
                .resolved_state_list
                .iter()
                .filter_map(|id| ctx.raw_map.get(id))
                .collect();
            let auth_chain_events: Vec<&serde_json::Value> = ctx
                .auth_chain_ids
                .iter()
                .filter_map(|id| ctx.raw_map.get(id))
                .collect();

            serde_json::json!({
                "origin": ctx.args.origin,
                "state": state_events,
                "auth_chain": auth_chain_events
            })
        }
        OutputFormat::Default => serde_json::json!({
            "status": "success",
            "version": ctx.version,
            "duration_ms": ctx.duration.as_millis(),
            "resolved_state_size": ctx.resolved_state_list.len(),
            "auth_chain_size": ctx.auth_chain_ids.len(),
            "state_event_ids": ctx.resolved_state_list
        }),
    }
}

fn partition_and_resolve_state(
    heads: &[String],
    events_map: &HashMap<String, LeanEvent>,
    state_maps: &[HashMap<(String, Option<String>), String>],
    version: StateResVersion,
    auth_graph: &ruma_lean::roaring_auth::AuthGraph,
) -> (
    std::collections::BTreeMap<(String, Option<String>), String>,
    std::time::Duration,
) {
    let start = Instant::now();
    let mut occurrences: HashMap<(String, Option<String>), HashMap<String, usize>> = HashMap::new();
    let num_sets = state_maps.len();
    for map in state_maps {
        for (key, id) in map {
            *occurrences
                .entry(key.clone())
                .or_default()
                .entry(id.clone())
                .or_insert(0) += 1;
        }
    }

    let mut unconflicted_state = std::collections::BTreeMap::new();
    let mut conflicted_state_set = Vec::new();

    for (key, ids) in occurrences {
        if ids.len() == 1 && ids.values().next().unwrap() == &num_sets {
            // All heads agree on this event ID for this key
            let id = ids.keys().next().unwrap();
            unconflicted_state.insert(key, id.clone());
        } else {
            // Heads disagree, add all events for this key to the conflicted set
            for id in ids.keys() {
                conflicted_state_set.push(id.clone());
            }
        }
    }

    // Auth difference: events in the auth chain of at least one head, but not all heads.
    let mut auth_difference = std::collections::HashSet::new();
    if !heads.is_empty() {
        let mut union = roaring::RoaringBitmap::new();
        let mut intersection = roaring::RoaringBitmap::new();
        let mut first = true;

        for head_id in heads {
            if let Some(&idx) = auth_graph.id_to_index.get(head_id) {
                let chain_bitmap = &auth_graph.auth_bitmaps[idx as usize];
                if first {
                    union.clone_from(chain_bitmap);
                    intersection.clone_from(chain_bitmap);
                    first = false;
                } else {
                    union |= chain_bitmap;
                    intersection &= chain_bitmap;
                }
            }
        }

        let diff = union - intersection;
        for idx in diff {
            auth_difference.insert(auth_graph.index_to_id[idx as usize].clone());
        }
    }

    let mut conflicted_events = HashMap::new();
    // Add conflicted state set
    for id in &conflicted_state_set {
        if let Some(ev) = events_map.get(id) {
            conflicted_events.insert(id.clone(), ev.clone());
        }
    }

    // Add auth difference
    for id in &auth_difference {
        if let Some(ev) = events_map.get(id) {
            conflicted_events.insert(id.clone(), ev.clone());
        }
    }

    // Add conflicted state subgraph (MSC4297 / v2.1+)
    if version == StateResVersion::V2_1 || version == StateResVersion::V2_1_1 {
        let subgraph =
            ruma_lean::compute_v2_1_conflicted_subgraph(events_map, &conflicted_state_set);
        for (id, ev) in subgraph {
            conflicted_events.insert(id, ev);
        }
    }

    let final_state_map =
        ruma_lean::resolve_lean(unconflicted_state, conflicted_events, events_map, version);

    let duration = start.elapsed();
    (final_state_map, duration)
}

fn run_cli(args: &Args) -> anyhow::Result<serde_json::Value> {
    let input_val = load_or_fetch_input_value(args)?;
    let (raw_events, heads) = parse_and_extract_heads(&input_val)?;

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
                    creator_user_id.clone_from(&ev.sender);
                }
                raw_map.insert(ev.event_id.clone(), val);
                events_map.insert(ev.event_id.clone(), ev);
            }
            Err(e) => {
                if args.debug {
                    eprintln!("[DEBUG] Failed to parse event: {val:?}. Error: {e}");
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

    let state_maps = compute_state_maps(&heads, &events_map, &raw_map);

    if version != ruma_lean::StateResVersion::V2_1 && version != ruma_lean::StateResVersion::V2_1_1
    {
        apply_global_power_levels(&mut events_map, &creator_user_id, version);
    }

    let auth_graph = ruma_lean::roaring_auth::AuthGraph::build(&events_map);

    let (final_state_map, duration) =
        partition_and_resolve_state(&heads, &events_map, &state_maps, version, &auth_graph);

    let resolved_state_list: Vec<String> = final_state_map.values().cloned().collect();
    let mut auth_chain_bitmap = roaring::RoaringBitmap::new();
    for id in &resolved_state_list {
        if let Some(&idx) = auth_graph.id_to_index.get(id) {
            auth_chain_bitmap |= &auth_graph.auth_bitmaps[idx as usize];
        }
    }
    let auth_chain_ids: Vec<String> = auth_chain_bitmap
        .into_iter()
        .map(|idx| auth_graph.index_to_id[idx as usize].clone())
        .collect();

    let ctx = FormattingContext {
        args,
        events_map: &events_map,
        raw_map: &raw_map,
        heads: &heads,
        final_state_map: &final_state_map,
        resolved_state_list: &resolved_state_list,
        auth_chain_ids: &auth_chain_ids,
        version,
        duration,
        event_count,
    };

    Ok(format_cli_output(&ctx))
}

/// Convert days since Unix epoch to (year, month, day).
fn epoch_days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Civil calendar algorithm from Howard Hinnant
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = u64::try_from(z - era * 146_097).unwrap();
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = i64::try_from(yoe).unwrap() + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap();
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap();
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
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
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    return;
                }
                panic!("Failed to write trailing newline: {e}");
            }
            buffered_out.flush().expect("Failed to flush output buffer");
        }
        Err(e) => {
            eprintln!("Error: {e}");
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

fn apply_global_power_levels(
    events_map: &mut HashMap<String, ruma_lean::LeanEvent>,
    creator_user_id: &str,
    version: ruma_lean::StateResVersion,
) {
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

    let create_ev = events_map
        .values()
        .find(|ev| ev.event_type == "m.room.create");
    let sorted_power_ids = ruma_lean::lean_kahn_sort(&power_events, events_map, create_ev, version);
    let mut resolved_power_state = std::collections::BTreeMap::new();
    for id in sorted_power_ids {
        if let Some(ev) = power_events.get(&id) {
            resolved_power_state.insert((ev.event_type.clone(), ev.state_key.clone()), id);
        }
    }

    let mut user_power_levels = HashMap::new();
    let mut default_power_level = 0;
    if let Some(id) =
        resolved_power_state.get(&("m.room.power_levels".to_string(), Some(String::new())))
    {
        if let Some(ev) = events_map.get(id) {
            if let Some(users) = ev.content.get("users").and_then(|u| u.as_object()) {
                for (user_id, pl) in users {
                    if let Some(pl_val) = pl.as_i64() {
                        user_power_levels.insert(user_id.clone(), pl_val);
                    }
                }
            }
            if let Some(pl_val) = ev
                .content
                .get("users_default")
                .and_then(serde_json::Value::as_i64)
            {
                default_power_level = pl_val;
            }
        }
    }

    for ev in events_map.values_mut() {
        ev.power_level = *user_power_levels
            .get(&ev.sender)
            .unwrap_or(&default_power_level);
    }
}
