use rezzy::{resolve_lean, LeanEvent, StateResVersion};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

type ResolvedStateMap = HashMap<(String, String), String>;
type EventMap = HashMap<String, LeanEvent>;

fn load_fixture(path: &std::path::Path) -> Vec<LeanEvent> {
    let content =
        std::fs::read_to_string(path).unwrap_or_else(|_| panic!("Missing {}", path.display()));
    if path.extension().and_then(|s| s.to_str()) == Some("jsonl") {
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("Failed to parse line in {}: {e}", path.display()))
            })
            .collect()
    } else {
        let val: Value = serde_json::from_str(&content).unwrap();
        if val.is_array() {
            serde_json::from_value(val).unwrap()
        } else {
            serde_json::from_value(val["events"].clone()).unwrap()
        }
    }
}

fn to_event_map(events: &[LeanEvent]) -> EventMap {
    events
        .iter()
        .map(|e| (e.event_id.clone(), e.clone()))
        .collect()
}

fn get_heads(events: &[LeanEvent]) -> Vec<String> {
    // Look for the merge event (which has multiple prev_events)
    if let Some(merge_event) = events.iter().find(|e| e.prev_events.len() > 1) {
        merge_event.prev_events.clone()
    } else {
        // Fallback: overall leaf events of the DAG
        let mut prevs = HashSet::new();
        for e in events {
            for p in &e.prev_events {
                prevs.insert(p.clone());
            }
        }
        events
            .iter()
            .filter(|e| !prevs.contains(&e.event_id))
            .map(|e| e.event_id.clone())
            .collect()
    }
}

fn get_state_map_for_head(head: &str, events_map: &EventMap) -> HashMap<(String, String), String> {
    let mut visited = HashSet::new();
    let mut stack = vec![head.to_string()];
    let mut ancestors = Vec::new();
    while let Some(id) = stack.pop() {
        if visited.insert(id.clone()) {
            if let Some(ev) = events_map.get(&id) {
                ancestors.push(ev.clone());
                for p in &ev.prev_events {
                    stack.push(p.clone());
                }
            }
        }
    }
    // Sort ancestors to build state chronologically/topologically
    ancestors.sort_by(|a, b| {
        a.depth
            .cmp(&b.depth)
            .then_with(|| a.origin_server_ts.cmp(&b.origin_server_ts))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });
    let mut state = HashMap::new();
    for ev in ancestors {
        if ev.state_key.is_some() {
            state.insert(
                (ev.event_type.clone(), ev.state_key.clone().unwrap()),
                ev.event_id.clone(),
            );
        }
    }
    state
}

fn get_auth_chain(event_id: &str, events_map: &EventMap, visited: &mut HashSet<String>) {
    if visited.insert(event_id.to_string()) {
        if let Some(ev) = events_map.get(event_id) {
            for a in &ev.auth_events {
                get_auth_chain(a, events_map, visited);
            }
        }
    }
}

fn resolve_full(events: &[LeanEvent], version: StateResVersion) -> ResolvedStateMap {
    let events_map = to_event_map(events);
    let heads = get_heads(events);
    let mut state_maps = Vec::new();
    for h in &heads {
        state_maps.push(get_state_map_for_head(h, &events_map));
    }

    let num_sets = state_maps.len();
    let mut occurrences: HashMap<(String, String), HashMap<String, usize>> = HashMap::new();
    for map in &state_maps {
        for (key, id) in map {
            let val = occurrences
                .entry(key.clone())
                .or_default()
                .entry(id.clone())
                .or_insert(0);
            *val = val.wrapping_add(1);
        }
    }

    let mut unconflicted_state = imbl::OrdMap::new();
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

    // Auth difference: events in the auth chain of at least one head, but not all heads.
    let mut union = HashSet::new();
    let mut intersection = HashSet::new();
    let mut first = true;

    for head_id in &heads {
        let mut chain = HashSet::new();
        get_auth_chain(head_id, &events_map, &mut chain);
        if first {
            union.clone_from(&chain);
            intersection = chain;
            first = false;
        } else {
            union.extend(chain.clone());
            intersection = intersection.intersection(&chain).cloned().collect();
        }
    }

    let auth_difference: HashSet<String> = union.difference(&intersection).cloned().collect();

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
        let subgraph = rezzy::compute_v2_1_conflicted_subgraph(&events_map, &conflicted_state_set);
        for (id, ev) in subgraph {
            conflicted_events.insert(id, ev);
        }
    }

    let resolved = resolve_lean(
        unconflicted_state.clone(),
        conflicted_events,
        &events_map,
        version,
    );

    let mut full_state = HashMap::new();
    for (k, v) in unconflicted_state {
        full_state.insert(k, v);
    }
    for (k, v) in resolved {
        full_state.insert(k, v);
    }
    full_state
}

fn get_user_power_level(resolved: &ResolvedStateMap, map: &EventMap, user_id: &str) -> i64 {
    let key = ("m.room.power_levels".to_string(), String::new());
    if let Some(event_id) = resolved.get(&key) {
        if let Some(ev) = map.get(event_id) {
            if let Some(users) = ev.content.get("users").and_then(|u| u.as_object()) {
                if let Some(pl) = users.get(user_id).and_then(serde_json::Value::as_i64) {
                    return pl;
                }
            }
        }
    }
    0
}

fn get_membership(resolved: &ResolvedStateMap, map: &EventMap, user_id: &str) -> String {
    let key = ("m.room.member".to_string(), user_id.to_string());
    if let Some(event_id) = resolved.get(&key) {
        if let Some(ev) = map.get(event_id) {
            if let Some(m) = ev.content.get("membership").and_then(|v| v.as_str()) {
                return m.to_string();
            }
        }
    }
    "none".to_string()
}

fn resolve_pathology(jsonl_filename: &str) -> (ResolvedStateMap, EventMap) {
    let absolute_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/critique_data")
        .join(jsonl_filename);
    let events = load_fixture(&absolute_path);
    let map = to_event_map(&events);
    let resolved = resolve_full(&events, StateResVersion::V2_1_1);
    (resolved, map)
}

fn assert_benign_convergence(jsonl_filename: &str) -> (ResolvedStateMap, EventMap) {
    let absolute_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/critique_data")
        .join(jsonl_filename);
    let events = load_fixture(&absolute_path);
    let map = to_event_map(&events);

    let mut resolved_v2_1 = resolve_full(&events, StateResVersion::V2_1);
    let mut resolved_v2_1_1 = resolve_full(&events, StateResVersion::V2_1_1);

    resolved_v2_1.retain(|k, _| !k.1.is_empty());
    resolved_v2_1_1.retain(|k, _| !k.1.is_empty());

    assert_eq!(
        resolved_v2_1_1, resolved_v2_1,
        "Causal Domination pre-filter violated Benign Convergence parity for {jsonl_filename}"
    );
    (resolved_v2_1_1, map)
}

#[test]
fn test_anomaly_01_state_reset() {
    let (resolved, map) = assert_benign_convergence("01_state_reset.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(get_user_power_level(&resolved, &map, "@bob:example.com"), 0);
}

#[test]
fn test_anomaly_02_admin_lockout() {
    let (resolved, map) = assert_benign_convergence("02_admin_lockout.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(get_user_power_level(&resolved, &map, "@bob:example.com"), 0);
}

#[test]
fn test_anomaly_03_phantom_join_rules() {
    let (resolved, map) = resolve_pathology("03_phantom_join_rules.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@charlie:example.com"),
        "none"
    );
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
}

#[test]
fn test_anomaly_04_ban_evasion() {
    let (resolved, map) = resolve_pathology("04_ban_evasion.jsonl");
    assert_eq!(get_membership(&resolved, &map, "@bob:ServerB"), "ban");
    assert_eq!(get_membership(&resolved, &map, "@alice:ServerA"), "join");
}

#[test]
fn test_anomaly_05_timestamp_spoofing() {
    let (resolved, map) = assert_benign_convergence("05_timestamp_spoofing.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(
        get_user_power_level(&resolved, &map, "@bob:example.com"),
        50
    );
}

#[test]
fn test_anomaly_06_action_evaporation() {
    let (resolved, map) = assert_benign_convergence("06_action_evaporation.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(get_user_power_level(&resolved, &map, "@bob:example.com"), 0);
}

#[test]
fn test_anomaly_06b_mod_membership_evaporation() {
    let (resolved, map) = resolve_pathology("06b_mod_membership_evaporation.jsonl");
    assert_eq!(get_membership(&resolved, &map, "@nexy:example.com"), "none");
    assert_eq!(
        get_membership(&resolved, &map, "@spammer:example.com"),
        "join"
    );
    // Honest members are unaffected.
    assert_eq!(
        get_membership(&resolved, &map, "@charlie:example.com"),
        "join"
    );
}

#[test]
fn test_anomaly_06c_zombie_invite_reset() {
    let (resolved, map) = assert_benign_convergence("06c_zombie_invite_reset.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@admin:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@nexy:example.com"), "join");
    assert_eq!(
        get_membership(&resolved, &map, "@spammer:example.com"),
        "ban"
    );
}

#[test]
fn test_anomaly_07_state_baseline_pollution() {
    let (resolved, map) = assert_benign_convergence("07_state_baseline_pollution.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "leave"
    );
}

#[test]
fn test_anomaly_08_problem_b() {
    let (resolved, map) = assert_benign_convergence("08_problem_b.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(
        get_user_power_level(&resolved, &map, "@alice:example.com"),
        100
    );
    assert_eq!(
        get_user_power_level(&resolved, &map, "@bob:example.com"),
        50
    );
}

#[test]
fn test_anomaly_09_moderator_disappearance() {
    let (resolved, map) = assert_benign_convergence("09_moderator_disappearance.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(
        get_membership(&resolved, &map, "@charlie:example.com"),
        "none"
    );
}

#[test]
fn test_anomaly_10_vanishing_timelines() {
    let (resolved, map) = assert_benign_convergence("10_vanishing_timelines.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "none");
}

#[test]
fn test_anomaly_11_auth_chain_truncation() {
    let (resolved, map) = assert_benign_convergence("11_auth_chain_truncation.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "none");
}

#[test]
fn test_anomaly_12_zombie_resurrection() {
    let (resolved, map) = assert_benign_convergence("12_zombie_resurrection.jsonl");
    assert_eq!(get_membership(&resolved, &map, "@alice:ServerA"), "join");
    assert_eq!(get_membership(&resolved, &map, "@bob:ServerB"), "join");
    assert_eq!(get_membership(&resolved, &map, "@charlie:ServerA"), "join");
}

#[test]
fn test_anomaly_13_large_cascading_lockout() {
    let (resolved, map) = resolve_pathology("13_large_cascading_lockout.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@david:example.com"),
        "join"
    );
}

#[test]
fn test_anomaly_14_state_reset_via_redactions() {
    let (resolved, map) = assert_benign_convergence("14_state_reset_via_redactions.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
}

#[test]
fn test_anomaly_15_dos_traversal_bfs() {
    let (resolved, map) = assert_benign_convergence("15_dos_traversal_bfs.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(
        get_user_power_level(&resolved, &map, "@bob:example.com"),
        50
    );
}

#[test]
fn test_anomaly_16_causality_leakage() {
    let (resolved, map) = assert_benign_convergence("16_causality_leakage.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "leave"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(
        get_user_power_level(&resolved, &map, "@bob:example.com"),
        100
    );
}

#[test]
fn test_anomaly_17_sliced_dag_membership_desync() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/critique_data")
        .join("17_sliced_dag_membership_desync.jsonl");
    let events = load_fixture(&path);
    println!("PARSED EVENTS COUNT: {}", events.len());

    let (resolved, map) = resolve_pathology("17_sliced_dag_membership_desync.jsonl");
    println!("=== RESOLVED STATE ({} entries) ===", resolved.len());
    for (k, v) in &resolved {
        println!("  ({}, {:?}) -> {}", k.0, k.1, v);
    }
    assert_eq!(
        get_membership(&resolved, &map, "@logn:unredacted.org"),
        "leave"
    );
    assert_eq!(
        get_membership(&resolved, &map, "@reminder:maunium.net"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@cat:maunium.net"), "join");
    assert_eq!(
        get_membership(&resolved, &map, "@reminder:codestorm.net"),
        "leave"
    );
    assert_eq!(get_membership(&resolved, &map, "@logn:zirco.dev"), "join");
}

#[test]
fn test_anomaly_18_unauthorized_admin_amplification() {
    let (resolved, map) = resolve_pathology("18_unauthorized_admin_amplification.jsonl");
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "ban");
}
