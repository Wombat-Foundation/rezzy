//! Bootstrap of the continuwuity `test_unredacted_lounge_dag_resolution` test.
//!
//! This loads a minimal 51-event subgraph extracted from the full 81K-event
//! Unredacted Lounge DAG and reproduces the state resolution mismatches
//! without needing to compile the full continuwuity project.
//!
//! The test exercises the same code path as continuwuity's `rebuild_state`:
//! for room version 12, it uses `compute_v2_1_conflicted_subgraph` to compute
//! the conflicted set, then calls `resolve_lean` with `StateResVersion::V2_1`.

use rezzy::{resolve_lean, LeanEvent, StateResVersion};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Parse a JSONL file into a list of `LeanEvent`s.
fn parse_jsonl_dag<P: AsRef<Path>>(path: P) -> Vec<LeanEvent> {
    let file = File::open(path).expect("Failed to open JSONL file");
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let val: Value = serde_json::from_str(&line).expect("Failed to parse JSON line");
        let ev = serde_json::from_value::<LeanEvent>(val).expect("Failed to convert to LeanEvent");
        events.push(ev);
    }
    events
}

/// Mimics continuwuity's `resolve_fork_with_states` for V2.1+ rooms.
///
/// Given all events in the subgraph and a list of event IDs that are directly
/// conflicted (appear in different fork state sets with different winners),
/// compute the V2.1 conflicted subgraph, separate `auth_context`, and resolve.
fn resolve_v2_1_from_subgraph(
    all_events: &[LeanEvent],
    conflicted_eids: &[String],
) -> std::collections::BTreeMap<(String, Option<String>), String> {
    // Build full context map
    let mut full_context: HashMap<String, LeanEvent> = HashMap::new();
    for ev in all_events {
        full_context.insert(ev.event_id.clone(), ev.clone());
    }

    // Use rezzy's conflicted subgraph computation (same as continuwuity)
    let v2_1_conflicted = rezzy::compute_v2_1_conflicted_subgraph(&full_context, conflicted_eids);

    // Auth context = everything NOT in the conflicted set
    let mut auth_context: HashMap<String, LeanEvent> = full_context;
    for id in v2_1_conflicted.keys() {
        auth_context.remove(id);
    }

    // Unconflicted state = empty for V2.1+ (MSC4297: start from empty)
    let unconflicted = std::collections::BTreeMap::new();

    resolve_lean(
        unconflicted,
        v2_1_conflicted,
        &auth_context,
        StateResVersion::V2_1,
    )
}

/// Find all m.room.member events for a given `state_key`, return them sorted by
/// `origin_server_ts` for diagnostic clarity.
fn find_member_events_for_user<'a>(events: &'a [LeanEvent], state_key: &str) -> Vec<&'a LeanEvent> {
    let mut matches: Vec<&LeanEvent> = events
        .iter()
        .filter(|ev| ev.event_type == "m.room.member" && ev.state_key.as_deref() == Some(state_key))
        .collect();
    matches.sort_by_key(|ev| ev.origin_server_ts);
    matches
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_unredacted_lounge_mismatch_subgraph() {
    let path = "res/pathology_data/unredacted_lounge_mismatch.jsonl";
    if !Path::new(path).exists() {
        println!("Skipping: {path} not found");
        return;
    }
    let events = parse_jsonl_dag(path);
    println!("Loaded {} events from subgraph", events.len());

    // Identify all state_keys that have competing m.room.member events
    let mut member_events_by_sk: HashMap<String, Vec<String>> = HashMap::new();
    for ev in &events {
        if ev.event_type == "m.room.member" {
            if let Some(ref sk) = ev.state_key {
                member_events_by_sk
                    .entry(sk.clone())
                    .or_default()
                    .push(ev.event_id.clone());
            }
        }
    }

    // All member events with >1 competing event for the same state_key are conflicted
    let conflicted_eids: Vec<String> = member_events_by_sk
        .values()
        .filter(|ids| ids.len() > 1)
        .flat_map(|ids| ids.iter().cloned())
        .collect();

    println!("Conflicted member event IDs ({}):", conflicted_eids.len());
    for id in &conflicted_eids {
        let ev = events.iter().find(|e| e.event_id == *id).unwrap();
        println!(
            "  {}: sk={}, sender={}, membership={}, ts={}",
            id,
            ev.state_key.as_deref().unwrap_or("?"),
            ev.sender,
            ev.content
                .get("membership")
                .and_then(|m| m.as_str())
                .unwrap_or("?"),
            ev.origin_server_ts,
        );
    }

    let resolved = resolve_v2_1_from_subgraph(&events, &conflicted_eids);

    println!("\nResolved state ({} entries):", resolved.len());
    for ((ty, sk), eid) in &resolved {
        if ty == "m.room.member" {
            let ev = events.iter().find(|e| e.event_id == *eid);
            let sender = ev.map_or("?", |e| e.sender.as_str());
            let membership = ev
                .and_then(|e| e.content.get("membership"))
                .and_then(|m| m.as_str())
                .unwrap_or("?");
            println!("  ({ty}, {sk:?}) -> {eid} (sender={sender}, membership={membership})");
        }
    }

    // Expected from the continuwuity test, adjusted for subgraph extraction:
    // @tobydave503 winner differs from full DAG (nex wins here due to Kahn sort last-writer-wins)
    let expected_present = [
        "$xqrfEc0vwvpDFN4laAkpvtniqlv1oV7kb-RfdT7mXCI",
        "$CITU5ramZfoRbG5NuEBd_kMm6f9a1UJB5TKRhMpVT6E",
        "$EhAnh9S3GYGd3tHSsoVhZAGbQt9fPgV_ketRNIQDc0s",
        "$DT2PAjF5OtuocQGMV_ekKgN68M6XaYYsO2TGQPGEZ_c",
    ];

    let expected_absent = [
        "$AJsK9SExNlblHbfse7eDhSNISk9E871gJzbkqoTA9Ds",
        "$mK__qhCzbLBUyb4IjkIxXKQpmdBwr8vxWwd40sXn1U4",
        "$rmb6V2Nb_UScP9htYUTPOy9LhbWgxb5wxgMEIfj8aFM",
        "$Hk-xXbs52DhNQI_Ca1E2DkyNMazBITKkepo8IuqC7EI",
    ];

    let resolved_eids: std::collections::HashSet<&String> = resolved.values().collect();

    let mut mismatches = 0u32;

    println!("\n=== Checking expected PRESENT ===");
    for id in &expected_present {
        if resolved_eids.contains(&id.to_string()) {
            println!("  OK: {id}");
        } else {
            // Find what actually won in that slot
            let ev = events.iter().find(|e| e.event_id == *id);
            let (ty, sk) = ev
                .map(|e| (e.event_type.clone(), e.state_key.clone()))
                .unwrap_or_default();
            let actual_winner = resolved.get(&(ty.clone(), sk.clone()));
            println!(
                "MISMATCH: expected PRESENT but MISSING: {id}\n  type={ty}, state_key={sk:?}\n  actual winner: {actual_winner:?}",
            );
            if let Some(winner_id) = actual_winner {
                if let Some(winner_ev) = events.iter().find(|e| e.event_id == *winner_id) {
                    println!(
                        "    winner details: sender={}, membership={}, ts={}",
                        winner_ev.sender,
                        winner_ev
                            .content
                            .get("membership")
                            .and_then(|m| m.as_str())
                            .unwrap_or("?"),
                        winner_ev.origin_server_ts,
                    );
                }
            }
            mismatches += 1;
        }
    }

    println!("\n=== Checking expected ABSENT ===");
    for id in &expected_absent {
        if resolved_eids.contains(&id.to_string()) {
            println!("MISMATCH: expected ABSENT but PRESENT: {id}");
            mismatches += 1;
        } else {
            println!("  OK (absent): {id}");
        }
    }

    assert!(
        mismatches == 0,
        "{mismatches} state resolution mismatches (see above)"
    );
}

/// Diagnostic variant: dump all events involved in each mismatched `state_key`
/// pair with their full auth chains for debugging.
#[test]
fn test_unredacted_lounge_diagnostic_dump() {
    let path = "res/pathology_data/unredacted_lounge_mismatch.jsonl";
    if !Path::new(path).exists() {
        println!("Skipping: {path} not found");
        return;
    }
    let events = parse_jsonl_dag(path);

    let mismatch_users = ["@tobydave503:matrix.org"];

    for user in &mismatch_users {
        println!("\n=== Events for {user} ===");
        let member_events = find_member_events_for_user(&events, user);
        for ev in &member_events {
            let membership = ev
                .content
                .get("membership")
                .and_then(|m| m.as_str())
                .unwrap_or("?");
            println!(
                "  {} sender={} membership={} ts={}",
                ev.event_id, ev.sender, membership, ev.origin_server_ts,
            );
            println!("    auth_events: {:?}", ev.auth_events);

            // Show auth chain details
            for aid in &ev.auth_events {
                if let Some(aev) = events.iter().find(|e| e.event_id == *aid) {
                    let amem = aev
                        .content
                        .get("membership")
                        .and_then(|m| m.as_str())
                        .unwrap_or("");
                    println!(
                        "      -> {} type={} sender={} {amem} ts={}",
                        aid, aev.event_type, aev.sender, aev.origin_server_ts,
                    );
                } else {
                    println!("      -> {aid} (NOT IN SUBGRAPH)");
                }
            }
        }
    }
}
