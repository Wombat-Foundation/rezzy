// Standalone repro: mirrors continuwuity's rebuild_state.rs LeanEvent
// construction + target selection, then calls
// rezzy::compute_state_at_streaming_optimized directly and reports what
// m.room.join_rules resolves to, plus which of a set of watched members
// (and merge points) are present/agree.
//
// Usage: cargo run --release --example repro_streaming -- <path.jsonl>
//
// Optional env vars (no identities are hardcoded — pass whatever the DAG
// under test actually contains):
//   TRACE=1              print every target's join_rules resolution
//   CHECK_USERS=a,b,c     comma-separated `@user:server` MXIDs to track
//                         presence of an `m.room.member` key for
//   CHECK_MERGES=$e1,$e2  comma-separated event IDs of merge points to
//                         cross-check against rezzy::resolve_state_maps

use rezzy::{LeanEvent, StateResVersion, StateUpdate};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};

type StateMap = HashMap<(String, String), String>;

struct Meta {
    eid: String,
    prev: Vec<String>,
    is_state: bool,
}

fn env_id_list(var: &str) -> Vec<String> {
    std::env::var(var)
        .ok()
        .map(|v| v.split(',').map(str::trim).map(String::from).collect())
        .unwrap_or_default()
}

fn load_events(path: &str) -> Vec<serde_json::Value> {
    let file = File::open(path).expect("open jsonl");
    let reader = BufReader::new(file);
    let mut raw_events = Vec::new();
    for line in reader.lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        raw_events.push(serde_json::from_str(&line).unwrap());
    }
    raw_events
}

fn build_lean_events(
    raw_events: &[serde_json::Value],
) -> (Vec<Meta>, HashMap<String, LeanEvent>, String) {
    let mut metas = Vec::new();
    let mut lean_events: HashMap<String, LeanEvent> = HashMap::new();
    let mut room_version = String::new();

    for val in raw_events {
        let eid = val["event_id"].as_str().unwrap().to_string();
        let etype = val["type"].as_str().unwrap_or_default().to_string();
        let state_key = val
            .get("state_key")
            .and_then(|v| v.as_str())
            .map(String::from);
        let sender = val["sender"].as_str().unwrap_or_default().to_string();
        let content = val
            .get("content")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let prev: Vec<String> = val
            .get("prev_events")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let auth: Vec<String> = val
            .get("auth_events")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let depth = val
            .get("depth")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let is_state = state_key.is_some();

        if etype == "m.room.create" {
            if let Some(v) = content.get("room_version").and_then(|v| v.as_str()) {
                room_version = v.to_string();
            }
        }

        // Mirror rebuild_state.rs: state events get full LeanEvent w/ content,
        // non-state events get a content-less skeleton (DAG traversal only).
        let lean = if is_state {
            LeanEvent {
                event_id: eid.clone(),
                event_type: etype.clone(),
                state_key: state_key.clone(),
                sender,
                content,
                prev_events: prev.clone(),
                auth_events: auth.clone(),
                depth,
                ..Default::default()
            }
        } else {
            LeanEvent {
                event_id: eid.clone(),
                prev_events: prev.clone(),
                auth_events: auth.clone(),
                depth,
                rejected: false,
                soft_fail: false,
                ..Default::default()
            }
        };
        lean_events.insert(eid.clone(), lean);
        metas.push(Meta {
            eid,
            prev,
            is_state,
        });
    }

    (metas, lean_events, room_version)
}

fn forward_extremities(metas: &[Meta]) -> Vec<String> {
    let all_ids: HashSet<&str> = metas.iter().map(|m| m.eid.as_str()).collect();
    let referenced: HashSet<&str> = metas
        .iter()
        .flat_map(|m| m.prev.iter().map(String::as_str))
        .collect();
    let mut heads: Vec<String> = all_ids
        .difference(&referenced)
        .map(|s| (*s).to_string())
        .collect();
    heads.sort();
    heads
}

fn run_streaming(
    target_refs: &[&String],
    lean_events: &HashMap<String, LeanEvent>,
    version: StateResVersion,
    check_users: &[String],
    trace: bool,
) -> (HashMap<String, StateMap>, bool) {
    let mut resolved_state_at: HashMap<String, StateMap> = HashMap::new();

    let completed = rezzy::compute_state_at_streaming_optimized(
        target_refs,
        lean_events,
        version,
        |id, update| match update {
            StateUpdate::New { state, .. } => {
                let m: StateMap = state
                    .iter()
                    .map(|(k, v)| ((k.0.as_str().to_string(), k.1.clone()), v.clone()))
                    .collect();
                if trace {
                    if let Some(jr) = m.get(&("m.room.join_rules".to_string(), String::new())) {
                        let depth = lean_events.get(&id).map_or(0, |e| e.depth);
                        let jr_depth = lean_events.get(jr).map_or(0, |e| e.depth);
                        println!(
                            "target {id} (depth {depth}): join_rules -> {jr} (depth {jr_depth})"
                        );
                    }
                }
                for u in check_users {
                    let key = ("m.room.member".to_string(), u.clone());
                    let this_ev = lean_events.get(&id);
                    if this_ev.is_some_and(|e| {
                        e.event_type == "m.room.member"
                            && e.state_key.as_deref() == Some(u.as_str())
                    }) {
                        let depth = this_ev.map_or(0, |e| e.depth);
                        println!(
                            "target {id} (depth {depth}) IS join event for {u}; present-after-self={}",
                            m.contains_key(&key)
                        );
                    }
                }
                resolved_state_at.insert(id, m);
            }
            StateUpdate::Unchanged {
                parent_event_id, ..
            } => {
                // Chase to parent's already-resolved state, exactly like
                // rebuild_state.rs's event_ssh lookup (parent is guaranteed
                // to have been resolved first in topological order... but
                // parent itself might ALSO be non-target/inherited, so walk
                // via lean_events prev chain if needed).
                let mut cur = parent_event_id.clone();
                let mut visited = HashSet::new();
                loop {
                    if !visited.insert(cur.clone()) {
                        eprintln!(
                            "[WARN] Cycle detected at event {cur} during parent walk for {id}"
                        );
                        break;
                    }
                    if let Some(m) = resolved_state_at.get(&cur) {
                        resolved_state_at.insert(id.clone(), m.clone());
                        break;
                    }
                    if let Some(ev) = lean_events.get(&cur) {
                        if ev.prev_events.len() == 1 {
                            cur = ev.prev_events[0].clone();
                            continue;
                        }
                    }
                    eprintln!(
                        "[WARN] Failed to resolve parent state for event {id} (walk ended at {cur})"
                    );
                    break;
                }
            }
        },
    );

    (resolved_state_at, completed)
}

/// Cross-checks each requested merge event's two-parent states against
/// `rezzy::resolve_state_maps` (an independent implementation) to see
/// whether it agrees with what the streaming path picked for that merge.
fn cross_check_merges(
    check_ids: &[String],
    check_users: &[String],
    lean_events: &HashMap<String, LeanEvent>,
    resolved_state_at: &HashMap<String, StateMap>,
    version: StateResVersion,
) {
    for cid in check_ids {
        let Some(ev) = lean_events.get(cid) else {
            continue;
        };
        println!(
            "\n--- cross-check merge event {cid} ({} parents) ---",
            ev.prev_events.len()
        );
        let mut parent_maps: Vec<
            imbl::OrdMap<(rezzy::basespec::event_types::EventType, String), String>,
        > = Vec::new();
        for pe in &ev.prev_events {
            let mut cur = pe.clone();
            let mut visited = HashSet::new();
            let m = loop {
                if !visited.insert(cur.clone()) {
                    break None;
                }
                if let Some(m) = resolved_state_at.get(&cur) {
                    break Some(m);
                }
                if let Some(pev) = lean_events.get(&cur) {
                    if pev.prev_events.len() == 1 {
                        cur = pev.prev_events[0].clone();
                        continue;
                    }
                }
                break None;
            };
            let Some(m) = m else {
                println!("  parent {pe}: NOT in resolved_state_at (skipping)");
                continue;
            };
            let jr = m.get(&("m.room.join_rules".to_string(), String::new()));
            println!("  parent {pe}: join_rules -> {jr:?}");
            for u in check_users {
                let present = m.contains_key(&("m.room.member".to_string(), u.clone()));
                println!(
                    "    member {u}: {}",
                    if present { "present" } else { "absent" }
                );
            }
            let om: imbl::OrdMap<_, _> = m
                .iter()
                .map(|((t, sk), v)| {
                    (
                        (
                            rezzy::basespec::event_types::EventType::from(t.as_str()),
                            sk.clone(),
                        ),
                        v.clone(),
                    )
                })
                .collect();
            parent_maps.push(om);
        }
        if parent_maps.len() < 2 {
            continue;
        }
        let resolved = rezzy::resolve_state_maps(&parent_maps, lean_events, version);
        let jr = resolved.get(&(
            rezzy::basespec::event_types::EventType::from("m.room.join_rules"),
            String::new(),
        ));
        println!("  resolve_state_maps ground truth -> join_rules = {jr:?}");
        let streaming_pick = resolved_state_at
            .get(cid)
            .and_then(|m| m.get(&("m.room.join_rules".to_string(), String::new())));
        println!(
            "  compute_state_at_streaming_optimized picked  -> join_rules = {streaming_pick:?}"
        );
        for u in check_users {
            let key = (
                rezzy::basespec::event_types::EventType::from("m.room.member"),
                u.clone(),
            );
            let gt = resolved.get(&key).is_some();
            let sp = resolved_state_at
                .get(cid)
                .is_some_and(|m| m.contains_key(&("m.room.member".to_string(), u.clone())));
            println!(
                "    member {u}: resolve_state_maps={gt} streaming={sp} {}",
                if gt == sp { "" } else { "### DISAGREE ###" }
            );
        }
        if jr == streaming_pick {
            println!("  (agree)");
        } else {
            println!("  ### DISAGREEMENT ###");
        }
    }
}

fn print_tip_state(
    heads: &[String],
    check_users: &[String],
    lean_events: &HashMap<String, LeanEvent>,
    resolved_state_at: &HashMap<String, StateMap>,
    raw_events: &[serde_json::Value],
) {
    for tip in heads {
        let mut cur = tip.clone();
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(cur.clone()) {
                println!("could not resolve state for tip {tip} (cycle at {cur})");
                break;
            }
            if let Some(m) = resolved_state_at.get(&cur) {
                println!("\n=== state at tip {tip} (resolved via {cur}) ===");
                if let Some(jr) = m.get(&("m.room.join_rules".to_string(), String::new())) {
                    println!("m.room.join_rules -> {jr}");
                    if let Some(v) = raw_events.iter().find(|e| e["event_id"] == *jr) {
                        println!("  content: {}", v["content"]);
                    }
                } else {
                    println!("m.room.join_rules -> <absent>");
                }
                for u in check_users {
                    let present = m.contains_key(&("m.room.member".to_string(), u.clone()));
                    println!(
                        "  member {u}: {}",
                        if present { "present" } else { "MISSING" }
                    );
                }
                break;
            }
            if let Some(ev) = lean_events.get(&cur) {
                if ev.prev_events.len() == 1 {
                    cur = ev.prev_events[0].clone();
                    continue;
                }
            }
            println!("could not resolve state for tip {tip} (stuck at {cur})");
            break;
        }
    }
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: repro_streaming <path.jsonl>");
    let raw_events = load_events(&path);
    eprintln!("loaded {} raw events", raw_events.len());

    let (metas, lean_events, room_version) = build_lean_events(&raw_events);
    let room_version = if room_version.is_empty() {
        "1".to_string()
    } else {
        room_version
    };
    eprintln!("room_version = {room_version:?}");
    let Some(version) = StateResVersion::from_room_version(&room_version) else {
        eprintln!("unsupported room version: {room_version}");
        return;
    };

    let heads = forward_extremities(&metas);
    eprintln!("forward extremities ({}): {:?}", heads.len(), heads);

    // Exactly rebuild_state.rs's target selection.
    let target_ids: Vec<String> = metas
        .iter()
        .filter(|m| m.is_state || m.prev.len() != 1)
        .map(|m| m.eid.clone())
        .collect();
    eprintln!("targets: {} / {}", target_ids.len(), metas.len());
    let target_refs: Vec<&String> = target_ids.iter().collect();

    let trace = std::env::var("TRACE").is_ok();
    let check_users = env_id_list("CHECK_USERS");
    let check_merges = env_id_list("CHECK_MERGES");

    let (resolved_state_at, completed) =
        run_streaming(&target_refs, &lean_events, version, &check_users, trace);
    eprintln!("compute_state_at_streaming_optimized completed = {completed}");

    if !completed {
        eprintln!("traversal detected cycle / uncompleted; stopping before derived reporting");
        return;
    }

    cross_check_merges(
        &check_merges,
        &check_users,
        &lean_events,
        &resolved_state_at,
        version,
    );
    print_tip_state(
        &heads,
        &check_users,
        &lean_events,
        &resolved_state_at,
        &raw_events,
    );
}
