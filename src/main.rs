use clap::{Parser, ValueEnum};
use ruma_lean::{lean_kahn_sort, LeanEvent, StateResVersion};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    input: Option<PathBuf>,

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

    #[arg(long)]
    benchmark_trace: bool,

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

fn detect_version(events: &[serde_json::Value], debug: bool) -> anyhow::Result<StateResVersion> {
    for ev in events {
        if let Some(ev_type) = ev.get("type").and_then(|t| t.as_str()) {
            if ev_type == "m.room.create" {
                if let Some(content) = ev.get("content") {
                    if let Some(ver) = content.get("room_version").and_then(|v| v.as_str()) {
                        if debug {
                            eprintln!("[DEBUG] Found m.room.create with version: {}", ver);
                        }
                        match ver {
                            "1" => return Ok(StateResVersion::V1),
                            "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10" | "11" => {
                                return Ok(StateResVersion::V2)
                            }
                            "12" => return Ok(StateResVersion::V2_1),
                            _ => return Ok(StateResVersion::V2), // Default fallback
                        }
                    }
                }
            }
        }
    }
    Ok(StateResVersion::V2) // Default
}

fn fetch_room_state(
    homeserver: &str,
    room_id: &str,
    token: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    let url = format!("{}/_matrix/client/v3/rooms/{}/state", homeserver, room_id);
    let mut request = ureq::get(&url);
    if let Some(t) = token {
        request = request.set("Authorization", &format!("Bearer {}", t));
    }

    let response = request.call()?;
    if response.status() != 200 {
        anyhow::bail!(
            "Failed to fetch room state: {} {}",
            response.status(),
            response.into_string()?
        );
    }

    let val: serde_json::Value = response.into_json()?;
    Ok(val)
}

fn run_cli(args: &Args) -> anyhow::Result<serde_json::Value> {
    let input_val: serde_json::Value = if let Some(room_id) = &args.room {
        let homeserver = args
            .homeserver
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--homeserver is required when using --room"))?;
        fetch_room_state(homeserver, room_id, args.token.as_deref())?
    } else if let Some(input_path) = &args.input {
        let input_reader: Box<dyn Read> = if input_path.to_str() == Some("-") {
            Box::new(io::stdin())
        } else {
            Box::new(File::open(input_path)?)
        };

        let mut reader = BufReader::new(input_reader);
        let mut input_data = Vec::new();

        loop {
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line)?;
            if bytes_read == 0 {
                break; // EOF
            }
            if line.trim().is_empty() {
                continue;
            }
            input_data.extend_from_slice(line.as_bytes());
        }

        if input_data.is_empty() {
            anyhow::bail!("No input data provided before empty line or EOF.");
        }

        serde_json::from_slice(&input_data)?
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

    let state_maps = if heads.is_empty() {
        let mut state_map = std::collections::HashMap::new();
        for ev in events_map.values() {
            let key = (ev.event_type.clone(), ev.state_key.clone());
            match state_map.get(&key) {
                Some(existing_ev_id) if existing_ev_id >= &ev.event_id => {}
                _ => {
                    state_map.insert(key, ev.event_id.clone());
                }
            }
        }
        vec![state_map]
    } else {
        let mut maps = Vec::new();
        for head_id in &heads {
            let mut best_state = std::collections::HashMap::new();
            let mut visited_depth = std::collections::HashMap::new();
            let mut stack = vec![(head_id.clone(), 0usize)];

            while let Some((ev_id, depth)) = stack.pop() {
                if let Some(best_seen_depth) = visited_depth.get(&ev_id) {
                    if *best_seen_depth <= depth {
                        continue;
                    }
                }
                visited_depth.insert(ev_id.clone(), depth);

                if let Some(ev) = events_map.get(&ev_id) {
                    // Deterministic approximation: for each (type, state_key), keep the
                    // reachable event that is closest to the head. This avoids depending on
                    // DFS traversal order, which can otherwise retain an older event.
                    let key = (ev.event_type.clone(), ev.state_key.clone());
                    match best_state.get(&key) {
                        Some((best_depth, best_ev_id))
                            if *best_depth < depth
                                || (*best_depth == depth && *best_ev_id >= ev_id) => {}
                        _ => {
                            best_state.insert(key, (depth, ev_id.clone()));
                        }
                    }
                    for prev_ev_id in &ev.prev_events {
                        stack.push((prev_ev_id.clone(), depth + 1));
                    }
                }
            }
            let state_map = best_state
                .into_iter()
                .map(|(key, (_, ev_id))| (key, ev_id))
                .collect();
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

    if args.benchmark_trace {
        let compiler = ruma_lean::trace_compiler::TraceCompiler::new();
        let trace = compiler.compile_trace(&conflicted_events, version);

        let active_nodes = trace
            .iter()
            .filter(|r| {
                // In Plonky3 BabyBear 0.2, the field element can be cast to u32
                // if we are sure it fits, which it does for is_active (0 or 1).
                let active_val: u32 = unsafe { std::mem::transmute_copy(&r.is_active) };
                active_val == 1
            })
            .count();
        let routing_nodes = trace.len() - active_nodes;
        let routing_tax = if active_nodes > 0 {
            routing_nodes as f64 / active_nodes as f64
        } else {
            0.0
        };

        let output = serde_json::json!({
            "status": "benchmark_success",
            "active_nodes": active_nodes,
            "routing_nodes": routing_nodes,
            "total_trace_len": trace.len(),
            "routing_tax": routing_tax,
            "hypercube_dimension": compiler.hypercube.dimension,
            "hypercube_nodes": compiler.hypercube.num_nodes,
        });
        return Ok(output);
    }

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
            std::process::exit(1);
        }
    }
}
