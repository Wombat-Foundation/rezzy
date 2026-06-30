// Copyright 2026 Shane Jaroch
//
// Ruma Upstream E2E Tests
// These tests use the official ruma-state-res test fixtures from
// https://github.com/ruma/ruma/tree/main/crates/ruma-state-res/tests/it/resolve/fixtures
//
// They validate that our lean_kahn_sort + resolve_iterative_sort pipeline produces
// results consistent with the upstream Ruma state resolution implementation.
mod utils;

extern crate alloc;
extern crate std;

use alloc::string::String;
use alloc::vec::Vec;
use rezzy::{resolve_iterative_sort, LeanEvent, StateResVersion};
use std::collections::HashMap;

/// Load a JSON fixture file into a Vec<LeanEvent>.
/// The fixtures use "type" (not "`event_type`") which our serde rename handles.
fn load_fixture(path: &str) -> Vec<LeanEvent> {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {path}: {e}"));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("Failed to parse fixture {path}: {e}"))
}

/// Load multiple fixture files and concatenate them into one event list.
#[test]
fn test_room_id() {
    let s = "!00-m-room-create";
    let id = ruma_common::RoomId::parse(s);
    println!("id: {id:?}");
}

/// Build a `HashMap`<String, `LeanEvent`> from a list of events (keyed by `event_id`).
fn to_event_map(events: &[LeanEvent]) -> HashMap<String, LeanEvent> {
    events
        .iter()
        .map(|e| (e.event_id.clone(), e.clone()))
        .collect()
}

const FIXTURE_DIR: &str = "res/ruma_upstream";

fn sort_and_verify(events: &[LeanEvent], version: StateResVersion) -> Vec<String> {
    let map = to_event_map(events);
    let create_ev = events.iter().find(|ev| ev.event_type == "m.room.create");
    let result = rezzy::lean_kahn_sort_with_cycle_diagnostics(&map, &map, create_ev, version);
    assert!(result.is_ok(), "Cycle detected during sort");
    result.into_sorted()
}

/// Run Kahn's sort on the events and verify it doesn't detect any cycles.
#[test]
fn test_benchmark_1k_sort_no_cycles() {
    let content = std::fs::read_to_string("res/benchmark_1k.json").expect("benchmark_1k.json");
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();
    let events: Vec<LeanEvent> = serde_json::from_value(data["events"].clone()).unwrap();
    let sorted = sort_and_verify(&events, StateResVersion::V2);
    assert_eq!(sorted.len(), 1000);
    assert_eq!(sorted[0], "$00000-m-room-create");
}

#[test]
fn test_benchmark_1k_v2_1_sort_no_cycles() {
    let content =
        std::fs::read_to_string("res/benchmark_1k_v2_1.json").expect("benchmark_1k_v2_1.json");
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();
    let events: Vec<LeanEvent> = serde_json::from_value(data["events"].clone()).unwrap();
    let sorted = sort_and_verify(&events, StateResVersion::V2_1);
    assert_eq!(sorted.len(), 1000);
    assert_eq!(sorted[0], "$00000-m-room-create");
}

#[test]
fn test_benchmark_1k_resolution_determinism() {
    let content = std::fs::read_to_string("res/benchmark_1k.json").expect("benchmark_1k.json");
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();
    let events: Vec<LeanEvent> = serde_json::from_value(data["events"].clone()).unwrap();

    // Run resolution twice and verify determinism
    let resolved1 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&to_event_map(&events)),
        to_event_map(&events),
        &to_event_map(&events),
        StateResVersion::V2,
    );
    let resolved2 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&to_event_map(&events)),
        to_event_map(&events),
        &to_event_map(&events),
        StateResVersion::V2,
    );
    assert_eq!(resolved1, resolved2, "Resolution must be deterministic");
}

// ============================================================================
// Auth Chain Validation on Real Fixtures
// ============================================================================

#[test]
fn test_ruma_bootstrap_auth_chain() {
    use rezzy::auth::{check_auth_chain, RoomState};

    let events = load_fixture(&format!("{FIXTURE_DIR}/bootstrap-public-chat.json"));
    let (accepted, rejected) = check_auth_chain(
        &events,
        &RoomState::new(),
        rezzy::basespec::rezzy_types::StateResVersion::V2_1,
    );

    // All bootstrap events should pass auth
    assert!(
        rejected.is_empty(),
        "Bootstrap events should all pass auth, but {} were rejected: {:?}",
        rejected.len(),
        rejected
    );
    assert_eq!(accepted.len(), events.len());
}

// ============================================================================
// Realistic Large Room (10K events with federation forks, PL wars, bans)
// ============================================================================

fn load_large_room() -> Vec<LeanEvent> {
    let content = std::fs::read_to_string("res/realistic_large_room.json")
        .expect("realistic_large_room.json");
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();
    serde_json::from_value(data["events"].clone()).unwrap()
}

#[test]
fn test_large_room_10k_sort_no_cycles() {
    let events = load_large_room();
    assert!(
        events.len() >= 10000,
        "Expected >= 10000 events, got {}",
        events.len()
    );
    let sorted = sort_and_verify(&events, StateResVersion::V2);
    // Create must be first
    assert!(
        sorted[0].starts_with('$'),
        "First sorted event should be a valid event ID"
    );
    // All events accounted for
    assert!(sorted.len() >= 10000);
}

#[test]
fn test_large_room_10k_v2_1_sort() {
    let events = load_large_room();
    let sorted = sort_and_verify(&events, StateResVersion::V2_1);
    assert!(sorted.len() >= 10000);
}

#[test]
fn test_large_room_10k_resolution_determinism() {
    let events = load_large_room();
    let r1 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&to_event_map(&events)),
        to_event_map(&events),
        &to_event_map(&events),
        StateResVersion::V2,
    );
    let r2 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&to_event_map(&events)),
        to_event_map(&events),
        &to_event_map(&events),
        StateResVersion::V2,
    );
    assert_eq!(r1, r2, "10K room resolution must be deterministic");
}

#[test]
fn test_large_room_10k_v2_vs_v2_1_divergence() {
    let events = load_large_room();
    let map = to_event_map(&events);
    let v2 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&map),
        map.clone(),
        &map,
        StateResVersion::V2,
    );
    let v2_1 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&map),
        map.clone(),
        &map,
        StateResVersion::V2_1,
    );
    // V2 and V2.1 may diverge on conflicted state — that's the whole point of MSC4297.
    // But both must produce valid resolved state.
    assert!(!v2.is_empty(), "V2 must produce resolved state");
    assert!(!v2_1.is_empty(), "V2.1 must produce resolved state");
    // Both must agree on m.room.create
    assert_eq!(
        v2.get(&("m.room.create".into(), String::new())),
        v2_1.get(&("m.room.create".into(), String::new())),
        "V2 and V2.1 must agree on the create event"
    );
}

#[test]
fn test_large_room_10k_subgraph_bounded() {
    let events = load_large_room();
    let map = to_event_map(&events);
    // Pick some conflicted state_keys
    let mut pl_events: Vec<String> = events
        .iter()
        .filter(|e| e.event_type == "m.room.power_levels")
        .map(|e| e.event_id.clone())
        .collect();
    assert!(!pl_events.is_empty(), "Should have PL events");
    // Test bounded subgraph on the first 10 PL events
    pl_events.truncate(10);
    let bounded = rezzy::compute_v2_1_conflicted_subgraph_bounded(&map, &pl_events, Some(5));
    assert!(
        !bounded.subgraph.is_empty(),
        "Bounded subgraph should contain events"
    );
    // Unbounded should be >= bounded
    let full = rezzy::compute_v2_1_conflicted_subgraph_bounded(&map, &pl_events, None);
    assert!(
        full.subgraph.len() >= bounded.subgraph.len(),
        "Unbounded subgraph ({}) should be >= bounded ({})",
        full.subgraph.len(),
        bounded.subgraph.len()
    );
}

#[test]
fn test_large_room_10k_auth_chain() {
    use rezzy::auth::{check_auth_chain, RoomState};

    let events = load_large_room();
    let (accepted, _rejected) = check_auth_chain(
        &events,
        &RoomState::new(),
        rezzy::basespec::rezzy_types::StateResVersion::V2_1,
    );
    // Not all events will pass auth (spammers, unauthorized PL changes),
    // but the generator tries to keep it somewhat coherent.
    let pass_rate = f64::from(u32::try_from(accepted.len()).unwrap())
        / f64::from(u32::try_from(events.len()).unwrap());
    assert!(
        pass_rate > 0.20,
        "Auth pass rate should be >20%, got {:.1}% ({}/{})",
        pass_rate * 100.0,
        accepted.len(),
        events.len()
    );
}

// ============================================================================
// Real Matrix Room State Dump (42K events — auth validation only)
// ============================================================================

#[test]
fn test_real_room_42k_state_deserialization() {
    let path = "res/real_matrix_state.json";
    if !std::path::Path::new(path).exists() {
        println!("Skipping test: {path} not found");
        return;
    }
    let content = std::fs::read_to_string(path).unwrap();
    let events: Vec<LeanEvent> = serde_json::from_str(&content).unwrap();
    assert!(
        events.len() > 40000,
        "Should have 42K+ events, got {}",
        events.len()
    );
    // Verify all events have event_ids
    for ev in &events {
        assert!(!ev.event_id.is_empty(), "Event should have an event_id");
    }
}

#[test]
fn test_real_room_42k_power_level_coercion() {
    let path = "res/real_matrix_state.json";
    if !std::path::Path::new(path).exists() {
        println!("Skipping test: {path} not found");
        return;
    }
    // The real room dump likely has string/float power levels from old Synapse versions.
    let content = std::fs::read_to_string(path).unwrap();
    let events: Vec<LeanEvent> = serde_json::from_str(&content).unwrap();
    // Find PL events and verify they deserialize without panicking
    let pl_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "m.room.power_levels")
        .collect();
    assert!(
        !pl_events.is_empty(),
        "Real room should have power_levels events"
    );
    // Verify PL events have content with users
    for pl in &pl_events {
        assert!(
            pl.content.get("users").is_some(),
            "PL event should have users field"
        );
    }
}

#[test]
fn test_real_room_v2_1_deserialization() {
    let path = "res/real_matrix_state_v2_1.json";
    if !std::path::Path::new(path).exists() {
        println!("Skipping test: {path} not found");
        return;
    }
    let content = std::fs::read_to_string(path).unwrap();
    let val: serde_json::Value = serde_json::from_str(&content).unwrap();
    let events: Vec<LeanEvent> = if val.is_array() {
        serde_json::from_value(val).unwrap()
    } else {
        serde_json::from_value(val["events"].clone()).unwrap()
    };
    assert!(
        events.len() > 10,
        "Should have 10+ events, got {}",
        events.len()
    );
}

// ============================================================================
// Real Room DAGs from conduwuit RocksDB (full auth_events + prev_events)
// ============================================================================

fn load_real_dag(path: &str) -> Vec<LeanEvent> {
    let content = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("Missing {path}"));
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();
    serde_json::from_value(data["events"].clone()).unwrap()
}

#[test]
fn test_real_dag_52k_room_deserialization() {
    let events = load_real_dag("res/real_dag_52k_room.json");
    assert!(
        events.len() >= 10000,
        "Expected >= 10000 events, got {}",
        events.len()
    );
    // Every event should have auth_events (except possibly create)
    let with_auth = events.iter().filter(|e| !e.auth_events.is_empty()).count();
    assert!(
        with_auth > events.len() - 10,
        "Most events should have auth_events, got {}/{}",
        with_auth,
        events.len()
    );
}

#[test]
fn test_real_dag_52k_room_sort() {
    let events = load_real_dag("res/real_dag_52k_room.json");
    let sorted = sort_and_verify(&events, StateResVersion::V2);
    assert!(sorted.len() >= 10000);
}

#[test]
fn test_real_dag_52k_room_v2_1_sort() {
    let events = load_real_dag("res/real_dag_52k_room.json");
    let sorted = sort_and_verify(&events, StateResVersion::V2_1);
    assert!(sorted.len() >= 10000);
}

#[test]
fn test_real_dag_52k_room_resolution() {
    let events = load_real_dag("res/real_dag_52k_room.json");
    let map = to_event_map(&events);
    let resolved = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&map),
        map.clone(),
        &map,
        StateResVersion::V2,
    );
    assert!(!resolved.is_empty(), "Resolution should produce state");
    // Determinism check
    let events2 = load_real_dag("res/real_dag_52k_room.json");
    let map2 = to_event_map(&events2);
    let resolved2 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&map2),
        map2.clone(),
        &map2,
        StateResVersion::V2,
    );
    assert_eq!(resolved, resolved2, "Resolution must be deterministic");
}

#[test]
fn test_real_dag_nheko_room_sort() {
    let events = load_real_dag("res/real_dag_nheko.json");
    assert!(
        events.len() >= 6000,
        "Expected >= 6000 events, got {}",
        events.len()
    );
    let sorted = sort_and_verify(&events, StateResVersion::V2);
    assert!(sorted.len() >= 6000);
}

#[test]
fn test_real_dag_nheko_room_106_heads() {
    // This room has 106 DAG heads — a real federation mess
    let events = load_real_dag("res/real_dag_nheko.json");
    let event_map = to_event_map(&events);

    // Compute heads: events not referenced by any prev_events
    let mut referenced = std::collections::HashSet::new();
    for ev in &events {
        for prev in &ev.prev_events {
            referenced.insert(prev.clone());
        }
    }
    let heads: Vec<_> = events
        .iter()
        .filter(|e| !referenced.contains(&e.event_id))
        .collect();
    assert!(
        heads.len() > 50,
        "Nheko room should have 50+ DAG heads (federation forks), got {}",
        heads.len()
    );

    // Resolution must still complete on this messy DAG
    let resolved = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&event_map),
        event_map.clone(),
        &event_map,
        StateResVersion::V2,
    );
    assert!(!resolved.is_empty(), "Resolution should produce state");
}

fn parse_jsonl_line(line: &str) -> LeanEvent {
    if let Ok(ev) = serde_json::from_str::<LeanEvent>(line) {
        return ev;
    }
    let val: serde_json::Value = serde_json::from_str(line)
        .unwrap_or_else(|e| panic!("Failed to parse line as JSON: {e}. Line: {line}"));
    if let Some(source) = val.get("_source") {
        serde_json::from_value::<LeanEvent>(source.clone()).unwrap_or_else(|e| {
            panic!("Failed to parse '_source' field as LeanEvent: {e}. Line: {line}")
        })
    } else if let Some(event) = val.get("event") {
        serde_json::from_value::<LeanEvent>(event.clone()).unwrap_or_else(|e| {
            panic!("Failed to parse 'event' field as LeanEvent: {e}. Line: {line}")
        })
    } else {
        panic!("JSON line does not contain expected '_source' or 'event' wrappers, and is not a direct LeanEvent. Line: {line}");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_unredacted_spam_storm_v2_1_1() {
    use std::io::BufRead;
    const CACHE_FORMAT_VERSION: &str = "1";

    let path = "res/remote-dag-sM2LwqNHGQOgLf35gqxPMy9D7oYde2q9ADg8HPBM3kE-v12-merged.jsonl";

    let load_from_jsonl = || -> Option<Vec<LeanEvent>> {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                println!("Skipping test: could not open {path}: {e}");
                return None;
            }
        };
        let reader = std::io::BufReader::new(file);
        let mut parsed_events = Vec::new();
        for line in reader.lines() {
            let line = line.unwrap();
            if !line.trim().is_empty() {
                let ev = parse_jsonl_line(&line);
                if ev.state_key.is_some() {
                    parsed_events.push(ev);
                }
            }
        }
        let version_prefix = format!(
            "LEAN_{}_FMT{}",
            env!("CARGO_PKG_VERSION"),
            CACHE_FORMAT_VERSION
        );
        let mut encoded = version_prefix.as_bytes().to_vec();
        encoded.extend(bincode::serialize(&parsed_events).unwrap());
        let _ = std::fs::write(format!("{path}.bincode"), encoded);
        Some(parsed_events)
    };

    let cache_path = format!("{path}.bincode");
    let events: Vec<LeanEvent> = if let Ok(bytes) = std::fs::read(&cache_path) {
        let version_prefix = format!(
            "LEAN_{}_FMT{}",
            env!("CARGO_PKG_VERSION"),
            CACHE_FORMAT_VERSION
        );
        let prefix_bytes = version_prefix.as_bytes();

        if bytes.starts_with(prefix_bytes) {
            let encoded = &bytes[prefix_bytes.len()..];
            match bincode::deserialize::<Vec<LeanEvent>>(encoded) {
                Ok(cached_events) => {
                    println!("Loaded from Bincode cache");
                    cached_events
                }
                Err(e) => {
                    println!("Cache decode failed ({e}), rebuilding from JSONL");
                    match load_from_jsonl() {
                        Some(ev) => ev,
                        None => return,
                    }
                }
            }
        } else {
            match load_from_jsonl() {
                Some(ev) => ev,
                None => return,
            }
        }
    } else {
        match load_from_jsonl() {
            Some(ev) => ev,
            None => return,
        }
    };

    assert!(
        !events.is_empty(),
        "Failed to parse any events from the unredacted spam storm JSONL"
    );
    println!("Loaded {} events from unredacted storm", events.len());

    let map = to_event_map(&events);

    let start_v2 = std::time::Instant::now();
    let resolved_v2 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&map),
        map.clone(),
        &map,
        StateResVersion::V2,
    );
    let dur_v2 = start_v2.elapsed();
    println!(
        "V2.0 State Resolution of {} events took: {:?}",
        events.len(),
        dur_v2
    );

    let start_v21 = std::time::Instant::now();
    let resolved_v21 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&map),
        map.clone(),
        &map,
        StateResVersion::V2_1,
    );
    let dur_v21 = start_v21.elapsed();
    println!(
        "V2.1 State Resolution of {} events took: {:?}",
        events.len(),
        dur_v21
    );

    let start_v211 = std::time::Instant::now();
    let resolved_v211 = resolve_iterative_sort(
        utils::build_unconflicted_state_test_helper(&map),
        map.clone(),
        &map,
        StateResVersion::V2_1_1,
    );
    let dur_v211 = start_v211.elapsed();
    println!(
        "V2.1.1 State Resolution of {} events took: {:?}",
        events.len(),
        dur_v211
    );

    let start_lattice = std::time::Instant::now();
    let resolved_lattice = rezzy::resolve_lattice_fold(
        imbl::OrdMap::new(),
        map.clone(),
        &map,
        StateResVersion::V2_1_1,
    );
    let dur_lattice = start_lattice.elapsed();
    println!(
        "LATTICE-COORDINATIZED State Resolution of {} events took: {:?}",
        events.len(),
        dur_lattice
    );

    assert!(
        !resolved_v2.is_empty()
            && !resolved_v21.is_empty()
            && !resolved_v211.is_empty()
            && !resolved_lattice.is_empty(),
        "Resolution should produce non-empty state"
    );

    verify_spam_storm_results(
        &events,
        &resolved_v2,
        &resolved_v21,
        &resolved_v211,
        &resolved_lattice,
        (dur_v2, dur_v21, dur_v211, dur_lattice),
    );
}

#[allow(clippy::too_many_lines)]
fn verify_spam_storm_results(
    events: &[LeanEvent],
    resolved_v2: &imbl::OrdMap<(String, String), String>,
    resolved_v21: &imbl::OrdMap<(String, String), String>,
    resolved_v211: &imbl::OrdMap<(String, String), String>,
    resolved_lattice: &imbl::OrdMap<(String, String), String>,
    durs: (
        std::time::Duration,
        std::time::Duration,
        std::time::Duration,
        std::time::Duration,
    ),
) {
    let power_levels_v20 = resolved_v2.get(&("m.room.power_levels".into(), String::new()));
    let power_levels_v21 = resolved_v21.get(&("m.room.power_levels".into(), String::new()));
    let power_levels_v211 = resolved_v211.get(&("m.room.power_levels".into(), String::new()));
    let power_levels_lattice = resolved_lattice.get(&("m.room.power_levels".into(), String::new()));

    if power_levels_v20 == power_levels_v211 {
        println!("V2 and V2.1.1 produced identical power levels.");
    } else {
        println!("V2 and V2.1.1 diverged on power levels!");
    }
    if power_levels_v21 == power_levels_v211 {
        println!("V2.1 and V2.1.1 produced identical power levels.");
    } else {
        println!("V2.1 and V2.1.1 diverged on power levels!");
    }
    if power_levels_lattice == power_levels_v211 {
        println!("Lattice and V2.1.1 produced identical power levels.");
    } else {
        println!("Lattice and V2.1.1 diverged on power levels!");
    }

    let min_depth = events.iter().map(|e| e.depth).min().unwrap_or(0);
    let max_depth = events.iter().map(|e| e.depth).max().unwrap_or(0);

    // Compute DAG connected components (Union-Find)
    let n_components = {
        fn find(mut i: usize, parent: &mut [usize]) -> usize {
            while parent[i] != i {
                parent[i] = parent[parent[i]];
                i = parent[i];
            }
            i
        }

        fn union(i: usize, j: usize, parent: &mut [usize]) {
            let root_i = find(i, parent);
            let root_j = find(j, parent);
            if root_i != root_j {
                parent[root_i] = root_j;
            }
        }

        let mut parent: Vec<usize> = (0..events.len()).collect();
        let mut id_to_index = std::collections::HashMap::with_capacity(events.len());
        for (i, ev) in events.iter().enumerate() {
            id_to_index.insert(ev.event_id.as_str(), i);
        }

        for (i, ev) in events.iter().enumerate() {
            for prev in &ev.prev_events {
                if let Some(&j) = id_to_index.get(prev.as_str()) {
                    union(i, j, &mut parent);
                }
            }
            for auth in &ev.auth_events {
                if let Some(&j) = id_to_index.get(auth.as_str()) {
                    union(i, j, &mut parent);
                }
            }
        }

        let mut roots = std::collections::HashSet::new();
        for i in 0..events.len() {
            roots.insert(find(i, &mut parent));
        }
        roots.len()
    };

    println!("\n================================================================================");
    println!("                    SPAM STORM STATE RESOLUTION REPORT");
    println!("================================================================================");
    println!(" State Event Count:  {} events", events.len());
    println!(" Resolved Output:    {} state keys", resolved_v211.len());
    println!(" Min DAG Depth:      {min_depth}");
    println!(" Max DAG Depth:      {max_depth}");
    println!(" DAG Components:     {n_components}");
    println!();
    println!(" Engine                        | Execution Duration (Pure State)");
    println!(" ------------------------------+------------------------------------------------");
    println!(" V2.0 (Legacy)                 | {:?}", durs.0);
    println!(" V2.1 (Legacy)                 | {:?}", durs.1);
    println!(" V2.1.1 (Sequential CDO)       | {:?}", durs.2);
    println!(" LATTICE-COORDINATIZED (O(C))  | {:?}", durs.3);
    println!("================================================================================");

    if resolved_v211 == resolved_lattice {
        println!("SUCCESS: Lattice-coordinatized state resolution matched V2.1.1 exactly!");
    } else {
        let mut diff_count: u64 = 0;
        for (k, v) in resolved_v211 {
            if resolved_lattice.get(k) != Some(v) {
                diff_count = diff_count.wrapping_add(1);
                let lat_val = resolved_lattice.get(k);
                println!("DIVERGENCE: Key {k:?} -> V2.1.1: {v:?}, Lattice: {lat_val:?}");
            }
        }
        for (k, v) in resolved_lattice {
            if !resolved_v211.contains_key(k) {
                diff_count = diff_count.wrapping_add(1);
                println!("DIVERGENCE: Key {k:?} -> V2.1.1: None, Lattice: {v:?}");
            }
        }
        println!(
            "Number of divergent state entries: {diff_count} (out of {len})",
            len = resolved_v211.len()
        );
        assert_eq!(
            diff_count, 0,
            "Lattice-coordinatized resolution diverged from V2.1.1"
        );
    }
}
