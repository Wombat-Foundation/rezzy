//! Oracle cross-validation tests for ruma-lean state resolution.
//!
//! These tests compare ruma-lean's resolved state against ground-truth
//! oracle files extracted from the conduwuit database. If our engine
//! disagrees with the oracle ON EVENTS WE ACTUALLY HAVE, the test fails.
//!
//! NOTE: The current oracle is an approximation (highest-depth state event
//! per type+state_key from RocksDB scan). A proper oracle would come from
//! the live CS API or the server's actual shortstatehash chain.
//!
//! Run: `cargo test --features std --test snapshots`

use ruma_lean::{resolve_lean, LeanEvent, StateResVersion};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

fn to_event_map(events: &[LeanEvent]) -> HashMap<String, LeanEvent> {
    events
        .iter()
        .map(|e| (e.event_id.clone(), e.clone()))
        .collect()
}

fn load_fixture(path: &str) -> Vec<LeanEvent> {
    let content = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("Missing {path}"));
    let val: Value = serde_json::from_str(&content).unwrap();
    if val.is_array() {
        serde_json::from_value(val).unwrap()
    } else {
        serde_json::from_value(val["events"].clone()).unwrap()
    }
}

fn load_oracle(path: &str) -> HashMap<String, String> {
    let content = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("Missing {path}"));
    let val: Value = serde_json::from_str(&content).unwrap();
    let state = val["resolved_state"].as_array().unwrap();
    let mut map = HashMap::new();
    for entry in state {
        let event_type = entry["type"].as_str().unwrap().to_string();
        let state_key = entry["state_key"].as_str().unwrap().to_string();
        let event_id = entry["event_id"].as_str().unwrap().to_string();
        map.insert(format!("{event_type}|{state_key}"), event_id);
    }
    map
}

fn resolve_and_get_state(fixture_path: &str, version: StateResVersion) -> HashMap<String, String> {
    let events = load_fixture(fixture_path);
    let map = to_event_map(&events);
    let resolved = resolve_lean(BTreeMap::new(), map, version);
    resolved
        .into_iter()
        .map(|((t, sk), eid)| (format!("{t}|{sk}"), eid))
        .collect()
}

/// STRICT cross-validation: if the oracle's event_id IS in our fixture,
/// we MUST pick the same one. Mismatches where the oracle's event_id is
/// absent from our fixture are expected (incomplete export).
fn strict_oracle_check(fixture_path: &str, oracle_path: &str, room_label: &str) {
    let fixture_events = load_fixture(fixture_path);
    let our_eids: std::collections::HashSet<String> =
        fixture_events.iter().map(|e| e.event_id.clone()).collect();
    let oracle = load_oracle(oracle_path);
    let ours = resolve_and_get_state(fixture_path, StateResVersion::V2);

    let mut matched = 0;
    let mut mismatch_expected = 0; // oracle EID not in fixture — can't match
    let mut mismatch_real = 0; // oracle EID IS in fixture — REAL BUG
    let mut real_details = Vec::new();

    for (key, our_eid) in &ours {
        if let Some(oracle_eid) = oracle.get(key) {
            if our_eid == oracle_eid {
                matched += 1;
            } else if !our_eids.contains(oracle_eid) {
                // Oracle picked an event we don't have — expected
                mismatch_expected += 1;
            } else {
                // Oracle picked an event we DO have but we chose differently — BUG
                mismatch_real += 1;
                if real_details.len() < 10 {
                    real_details.push(format!("  BUG {key}: ours={our_eid}, oracle={oracle_eid}"));
                }
            }
        }
    }

    eprintln!("Oracle cross-validation ({room_label}):");
    eprintln!("  Matched:              {matched}");
    eprintln!("  Mismatch (expected):  {mismatch_expected} (oracle EID not in fixture)");
    eprintln!("  Mismatch (REAL BUG):  {mismatch_real}");
    eprintln!("  Our total:            {}", ours.len());
    eprintln!("  Oracle total:         {}", oracle.len());

    for d in &real_details {
        eprintln!("{d}");
    }

    assert!(matched > 0, "No state entries matched");
    assert_eq!(
        mismatch_real, 0,
        "Oracle ({room_label}): {mismatch_real} real mismatches — ruma-lean picked wrong event"
    );
}

// ============================================================================
// Oracle cross-validation (STRICT — fail on real discrepancies)
// ============================================================================

#[test]
fn oracle_52k_room_strict() {
    strict_oracle_check(
        "res/real_dag_52k_room.json",
        "res/expected/oracle_52k_room.json",
        "52K room",
    );
}

#[test]
fn oracle_nheko_room_strict() {
    strict_oracle_check(
        "res/real_dag_nheko.json",
        "res/expected/oracle_nheko_room.json",
        "nheko room",
    );
}

#[test]
fn oracle_v2_1_room_strict() {
    // v12 room — uses state resolution v2.1
    let fixture_path = "res/real_matrix_state_v2_1.json";
    let oracle_path = "res/expected/oracle_v2_1_room.json";

    let fixture_events = load_fixture(fixture_path);
    let our_eids: std::collections::HashSet<String> =
        fixture_events.iter().map(|e| e.event_id.clone()).collect();
    let oracle = load_oracle(oracle_path);

    // Resolve using V2.1 (the correct version for room v12)
    let ours = resolve_and_get_state(fixture_path, StateResVersion::V2_1);

    let mut matched = 0;
    let mut mismatch_expected = 0;
    let mut mismatch_real = 0;

    for (key, our_eid) in &ours {
        if let Some(oracle_eid) = oracle.get(key) {
            if our_eid == oracle_eid {
                matched += 1;
            } else if !our_eids.contains(oracle_eid) {
                mismatch_expected += 1;
            } else {
                mismatch_real += 1;
                eprintln!("  BUG {key}: ours={our_eid}, oracle={oracle_eid}");
            }
        }
    }

    eprintln!("Oracle cross-validation (v2.1 room):");
    eprintln!("  Matched:              {matched}");
    eprintln!("  Mismatch (expected):  {mismatch_expected}");
    eprintln!("  Mismatch (REAL BUG):  {mismatch_real}");

    assert!(matched > 0, "No state entries matched");
    assert_eq!(
        mismatch_real, 0,
        "v2.1 oracle: {mismatch_real} real mismatches (ruma-lean picks wrong event)"
    );
}

// ============================================================================
// Regression: determinism
// ============================================================================

#[test]
fn regression_52k_room_determinism() {
    let a = resolve_and_get_state("res/real_dag_52k_room.json", StateResVersion::V2);
    let b = resolve_and_get_state("res/real_dag_52k_room.json", StateResVersion::V2);
    assert_eq!(a, b, "Resolution must be deterministic across runs");
}

#[test]
fn regression_nheko_room_determinism() {
    let a = resolve_and_get_state("res/real_dag_nheko.json", StateResVersion::V2);
    let b = resolve_and_get_state("res/real_dag_nheko.json", StateResVersion::V2);
    assert_eq!(a, b, "Resolution must be deterministic across runs");
}

#[test]
fn regression_52k_room_v2_vs_v2_1() {
    let v2 = resolve_and_get_state("res/real_dag_52k_room.json", StateResVersion::V2);
    let v2_1 = resolve_and_get_state("res/real_dag_52k_room.json", StateResVersion::V2_1);
    // V2 and V2.1 may differ — log the differences
    let mut same = 0;
    let mut diff = 0;
    for (key, v2_eid) in &v2 {
        if let Some(v2_1_eid) = v2_1.get(key) {
            if v2_eid == v2_1_eid {
                same += 1;
            } else {
                diff += 1;
            }
        }
    }
    eprintln!("V2 vs V2.1 comparison (52K room):");
    eprintln!("  Same:  {same}");
    eprintln!("  Diff:  {diff}");
    eprintln!("  V2 total:   {}", v2.len());
    eprintln!("  V2.1 total: {}", v2_1.len());
}
