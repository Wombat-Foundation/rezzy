#![allow(clippy::too_many_lines, clippy::type_complexity, clippy::similar_names)]
use std::cmp::Ordering;
use std::collections::BinaryHeap;

#[derive(Debug, PartialEq, Eq)]
struct Item(i32);

impl Ord for Item {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher value is Smaller = Pops Last
        other.0.cmp(&self.0)
    }
}

impl PartialOrd for Item {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[test]
fn test_heap_order() {
    let mut heap = BinaryHeap::new();
    heap.push(Item(100));
    heap.push(Item(50));

    let first = heap.pop().unwrap();
    let second = heap.pop().unwrap();

    println!("First popped: {first:?}");
    println!("Second popped: {second:?}");

    assert_eq!(first.0, 50);
    assert_eq!(second.0, 100);
}

#[test]
fn test_compute_state_at_correctness_and_performance() {
    use rezzy::{compute_state_at, LeanEvent, StateResVersion};
    use std::collections::HashMap;
    use std::time::Instant;

    // Generate a synthetic chain of 1000 events: E_1 -> E_2 -> ... -> E_1000
    // Every 10th event is a state event: type "m.room.member", state_key "user_X"
    let mut events_map = HashMap::new();
    let total_events = 1000;

    for i in 1..=total_events {
        let event_id = format!("${i}");
        let prev_events = if i > 1 {
            vec![format!("${}", i - 1)]
        } else {
            Vec::new()
        };

        // Every 10th event is state
        let (state_key, event_type) = if i % 10 == 0 {
            (Some(format!("user_{i}")), "m.room.member".to_string())
        } else {
            (None, "m.room.message".to_string())
        };

        let u_i = u64::try_from(i).unwrap();
        let ev = LeanEvent {
            rejected: false,
            soft_fail: false,
            event_id: event_id.clone(),
            event_type,
            state_key,
            power_level: 0,
            origin_server_ts: u_i * 1000,
            sender: "alice".to_string(),
            content: serde_json::Value::Null,
            prev_events,
            auth_events: Vec::new(),
            depth: u_i,
            room_id: None,
        };

        events_map.insert(event_id, ev);
    }

    // Target events
    let early_id = "$100";
    let mid_id = "$500";
    let tip_id = "$1000";

    // Correctness Checks
    let early_state = compute_state_at(early_id, &events_map, StateResVersion::V2, &String::new())
        .expect("should compute");
    let mid_state = compute_state_at(mid_id, &events_map, StateResVersion::V2, &String::new())
        .expect("should compute");
    let tip_state = compute_state_at(tip_id, &events_map, StateResVersion::V2, &String::new())
        .expect("should compute");

    // Check sizes of the state maps
    // At $100, we should have exactly 10 state keys (100 / 10)
    assert_eq!(early_state.len(), 10);
    // At $500, we should have exactly 50 state keys (500 / 10)
    assert_eq!(mid_state.len(), 50);
    // At $1000, we should have exactly 100 state keys (1000 / 10)
    assert_eq!(tip_state.len(), 100);

    // Verify a specific key exists at mid and tip, but not early
    let test_key = (
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        "user_400".to_string(),
    );
    assert!(!early_state.contains_key(&test_key));
    assert_eq!(mid_state.get(&test_key), Some(&"$400".to_string()));
    assert_eq!(tip_state.get(&test_key), Some(&"$400".to_string()));

    // Performance Benchmark (average of 50 runs in debug, 500 in release)
    #[cfg(debug_assertions)]
    let runs = 50;
    #[cfg(not(debug_assertions))]
    let runs = 500;

    // Early
    let start_early = Instant::now();
    for _ in 0..runs {
        let _ = compute_state_at(early_id, &events_map, StateResVersion::V2, &String::new());
    }
    let dur_early = start_early.elapsed() / runs;

    // Mid
    let start_mid = Instant::now();
    for _ in 0..runs {
        let _ = compute_state_at(mid_id, &events_map, StateResVersion::V2, &String::new());
    }
    let dur_mid = start_mid.elapsed() / runs;

    // Tip
    let start_tip = Instant::now();
    for _ in 0..runs {
        let _ = compute_state_at(tip_id, &events_map, StateResVersion::V2, &String::new());
    }
    let dur_tip = start_tip.elapsed() / runs;

    println!("\n=== compute_state_at Performance (Synthetic 1k Chain, average of {runs} runs) ===");
    println!("Early Event (depth 100):  {dur_early:?}");
    println!("Mid Event (depth 500):    {dur_mid:?}");
    println!("Tip Event (depth 1000):   {dur_tip:?}");
}

#[test]
fn test_compute_state_at_batch() {
    use rezzy::{compute_state_at, compute_state_at_batch, LeanEvent, StateResVersion};
    use std::collections::HashMap;

    let mut events_map = HashMap::new();

    // Create 1000 events in a single linear chain
    for i in 1..=1000 {
        let event_id = format!("${i}");
        let prev_events = if i > 1 {
            vec![format!("${}", i - 1)]
        } else {
            Vec::new()
        };

        // Every 10th event is state
        let (state_key, event_type) = if i % 10 == 0 {
            (Some(format!("user_{i}")), "m.room.member".to_string())
        } else {
            (None, "m.room.message".to_string())
        };

        let u_i = u64::try_from(i).unwrap();
        let ev = LeanEvent {
            rejected: false,
            soft_fail: false,
            event_id: event_id.clone(),
            event_type,
            state_key,
            power_level: 0,
            origin_server_ts: u_i * 1000,
            sender: "alice".to_string(),
            content: serde_json::Value::Null,
            prev_events,
            auth_events: Vec::new(),
            depth: u_i,
            room_id: None,
        };

        events_map.insert(event_id, ev);
    }

    let early_id = "$100";
    let mid_id = "$500";
    let tip_id = "$1000";

    // 1. Correctness Checks
    let early_state = compute_state_at(early_id, &events_map, StateResVersion::V2, &String::new())
        .expect("should compute");
    let mid_state = compute_state_at(mid_id, &events_map, StateResVersion::V2, &String::new())
        .expect("should compute");
    let tip_state = compute_state_at(tip_id, &events_map, StateResVersion::V2, &String::new())
        .expect("should compute");

    // Run batch computation
    let batch_ids = vec![early_id, mid_id, tip_id];
    let batch_results =
        compute_state_at_batch(&batch_ids, &events_map, StateResVersion::V2, &String::new());

    // Verify batch results exactly match individual results
    assert_eq!(batch_results.len(), 3);
    assert_eq!(&batch_results[early_id], &early_state);
    assert_eq!(&batch_results[mid_id], &mid_state);
    assert_eq!(&batch_results[tip_id], &tip_state);

    // Check sizes of the state maps
    assert_eq!(batch_results[early_id].len(), 10);
    assert_eq!(batch_results[mid_id].len(), 50);
    assert_eq!(batch_results[tip_id].len(), 100);

    // Verify empty batch handles gracefully
    let empty_results = compute_state_at_batch::<String, serde_json::Value, str, _, _>(
        &[],
        &events_map,
        StateResVersion::V2,
        &String::new(),
    );
    assert!(empty_results.is_empty());

    // Verify missing / invalid IDs are ignored or skipped gracefully without panics
    let invalid_ids = vec!["$missing_1", early_id, "$missing_2"];
    let partial_results = compute_state_at_batch(
        &invalid_ids,
        &events_map,
        StateResVersion::V2,
        &String::new(),
    );
    assert_eq!(partial_results.len(), 1);
    assert_eq!(&partial_results[early_id], &early_state);
}

#[test]
fn test_streaming_correctness_with_branched_dag() {
    use rezzy::state::at::compute_state_at_streaming;
    use rezzy::{LeanEvent, StateResVersion};
    use std::collections::HashMap;

    let mut events_map = HashMap::new();

    // Create a DAG with a fork and a merge
    // Linear 1..=40
    for i in 1_u64..=40_u64 {
        let prev_events = if i > 1 {
            vec![format!("${}", i - 1)]
        } else {
            Vec::new()
        };

        let (state_key, event_type) = if i % 10 == 0 {
            (Some(format!("user_{i}")), "m.room.member".to_string())
        } else {
            (None, "m.room.message".to_string())
        };

        events_map.insert(
            format!("${i}"),
            LeanEvent {
                rejected: false,
                soft_fail: false,
                event_id: format!("${i}"),
                event_type,
                state_key,
                power_level: 0,
                origin_server_ts: i * 1000,
                sender: "alice".to_string(),
                content: serde_json::Value::Null,
                prev_events,
                auth_events: Vec::new(),
                depth: i,
                room_id: None,
            },
        );
    }

    // Fork A (41a..=49a)
    for i in 41_u64..=49_u64 {
        let prev = if i == 41 {
            "$40".to_string()
        } else {
            format!("${}a", i - 1)
        };
        events_map.insert(
            format!("${i}a"),
            LeanEvent {
                rejected: false,
                soft_fail: false,
                event_id: format!("${i}a"),
                event_type: "m.room.message".to_string(),
                state_key: None,
                power_level: 0,
                origin_server_ts: i * 1000,
                sender: "alice".to_string(),
                content: serde_json::Value::Null,
                prev_events: vec![prev],
                auth_events: Vec::new(),
                depth: i,
                room_id: None,
            },
        );
    }

    // Fork B (41b..=49b) - this branch has a state event at 45!
    for i in 41_u64..=49_u64 {
        let prev = if i == 41 {
            "$40".to_string()
        } else {
            format!("${}b", i - 1)
        };
        events_map.insert(
            format!("${i}b"),
            LeanEvent {
                rejected: false,
                soft_fail: false,
                event_id: format!("${i}b"),
                event_type: if i == 45 {
                    "m.room.member".to_string()
                } else {
                    "m.room.message".to_string()
                },
                state_key: if i == 45 {
                    Some("user_45b".to_string())
                } else {
                    None
                },
                power_level: 0,
                origin_server_ts: (i * 1000) + 500, // Slightly later TS
                sender: "bob".to_string(),
                content: serde_json::Value::Null,
                prev_events: vec![prev],
                auth_events: Vec::new(),
                depth: i,
                room_id: None,
            },
        );
    }

    // Merge at 50
    events_map.insert(
        "$50".to_string(),
        LeanEvent {
            rejected: false,
            soft_fail: false,
            event_id: "$50".to_string(),
            event_type: "m.room.member".to_string(),
            state_key: Some("user_50".to_string()),
            power_level: 0,
            origin_server_ts: 50000,
            sender: "charlie".to_string(),
            content: serde_json::Value::Null,
            prev_events: vec!["$49a".to_string(), "$49b".to_string()],
            auth_events: Vec::new(),
            depth: 50,
            room_id: None,
        },
    );

    // Oracle generation
    let mut expected_at_40 = imbl::OrdMap::new();
    for i in [10, 20, 30, 40] {
        expected_at_40.insert(
            (
                rezzy::basespec::event_types::EventType::from("m.room.member"),
                format!("user_{i}"),
            ),
            format!("${i}"),
        );
    }

    // At 50, we should have everything from 40, plus the state event at 50 itself.
    // Note: The state event at 45b is conflicted during the merge at 50. Since it has
    // no auth_events in this synthetic DAG, it fails iterative auth checks and is
    // correctly rejected by state resolution!
    let mut expected_at_50 = expected_at_40.clone();
    expected_at_50.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "user_50".to_string(),
        ),
        "$50".to_string(),
    );

    let batch_ids = vec!["$40", "$50"];
    let mut streaming_results = HashMap::new();
    compute_state_at_streaming(
        &batch_ids,
        &events_map,
        StateResVersion::V2,
        |id, state| {
            streaming_results.insert(
                id.clone(),
                state.into_iter().collect::<imbl::OrdMap<_, _>>(),
            );
        },
        &String::new(),
    );

    assert_eq!(&streaming_results["$40"], &expected_at_40);
    assert_eq!(&streaming_results["$50"], &expected_at_50);
}

fn make_chronological_test_events() -> Vec<rezzy::LeanEvent> {
    use rezzy::LeanEvent;
    // 1. Create three chronological events
    let ev1 = LeanEvent {
        event_id: "$1".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        depth: 1,
        ..Default::default()
    };
    let ev2 = LeanEvent {
        event_id: "$2".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@alice:example.com".to_string()),
        prev_events: vec!["$1".to_string()],
        depth: 2,
        ..Default::default()
    };
    let ev3 = LeanEvent {
        event_id: "$3".to_string(),
        event_type: "m.room.message".to_string(),
        state_key: None,
        prev_events: vec!["$2".to_string()],
        depth: 3,
        ..Default::default()
    };
    vec![ev1, ev2, ev3]
}

#[test]
fn test_delta_chain_generation_correctness() {
    use rezzy::state::delta::{compute_state_delta, compute_state_hash};
    use std::collections::HashMap;

    let events = make_chronological_test_events();

    // Perform delta-chain sequential processing using library functions
    let mut state_after_map: HashMap<
        String,
        imbl::OrdMap<(rezzy::basespec::event_types::EventType, String), String>,
    > = HashMap::new();
    let mut state_hash_map: HashMap<String, [u8; 32]> = HashMap::new();
    let mut checkpoints = Vec::new();

    for ev in &events {
        let mut state_before = imbl::OrdMap::new();
        let mut parent_hash = None;

        if !ev.prev_events.is_empty() {
            let prev_id = &ev.prev_events[0];
            if let Some(prev_state) = state_after_map.get(prev_id) {
                state_before = prev_state.clone();
                parent_hash = state_hash_map.get(prev_id).copied();
            }
        }

        let mut state_after = state_before.clone();
        if ev.state_key.is_some() {
            state_after.insert(
                (
                    rezzy::basespec::event_types::EventType::from(ev.event_type.as_str()),
                    ev.state_key.clone().unwrap(),
                ),
                ev.event_id.clone(),
            );
        }

        let hash_str = compute_state_hash(&state_after);
        state_after_map.insert(ev.event_id.clone(), state_after.clone());
        state_hash_map.insert(ev.event_id.clone(), hash_str);

        let deltas = compute_state_delta(&state_before, &state_after);
        checkpoints.push((hash_str, parent_hash, ev.event_id.clone(), deltas));
    }

    // Verification of Chaining logic
    assert_eq!(checkpoints.len(), 3);

    let (h1, p1, id1, d1) = &checkpoints[0];
    assert_eq!(id1, "$1");
    assert_eq!(p1, &None);
    assert_eq!(d1.len(), 1);
    assert_eq!(d1[0].event_type, "m.room.create");
    assert_eq!(d1[0].state_key, String::new());
    assert_eq!(d1[0].event_id, Some("$1".to_string()));

    let (h2, p2, id2, d2) = &checkpoints[1];
    assert_eq!(id2, "$2");
    assert_eq!(p2, &Some(*h1));
    assert_eq!(d2.len(), 1);
    assert_eq!(d2[0].event_type, "m.room.member");
    assert_eq!(d2[0].state_key, "@alice:example.com".to_string());
    assert_eq!(d2[0].event_id, Some("$2".to_string()));

    let (h3, p3, id3, d3) = &checkpoints[2];
    assert_eq!(id3, "$3");
    assert_eq!(p3, &Some(*h2));
    assert_eq!(h3, h2); // State hash must be identical because it's a non-state event
    assert_eq!(d3.as_slice(), []); // Delta list must be empty because state did not change
}

#[test]
fn test_state_delta_compression_robustness() {
    use rezzy::state::delta::{compute_state_delta, compute_state_hash};
    use rezzy::LeanEvent;
    use std::collections::HashMap;

    // Construct a micro-history with a merge where some state key gets deleted/overwritten
    // E1: Create room (state: m.room.create => $1)
    let ev1: LeanEvent = LeanEvent {
        event_id: "$1".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        depth: 1,
        ..Default::default()
    };

    // E2: Alice joins (state: m.room.create => $1, m.room.member:@alice => $2)
    let ev2 = LeanEvent {
        event_id: "$2".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@alice:example.com".to_string()),
        prev_events: vec!["$1".to_string()],
        depth: 2,
        ..Default::default()
    };

    // E3: Fork A - Bob joins (state: m.room.create => $1, m.room.member:@alice => $2, m.room.member:@bob => $3)
    let ev3 = LeanEvent {
        event_id: "$3".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@bob:example.com".to_string()),
        prev_events: vec!["$2".to_string()],
        depth: 3,
        ..Default::default()
    };

    // E4: Fork B - Alice leaves (state: m.room.create => $1, m.room.member:@alice => $4)
    let ev4 = LeanEvent {
        event_id: "$4".to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some("@alice:example.com".to_string()),
        prev_events: vec!["$2".to_string()],
        depth: 3,
        ..Default::default()
    };

    let mut state_after_map: HashMap<
        String,
        imbl::OrdMap<(rezzy::basespec::event_types::EventType, String), String>,
    > = HashMap::new();
    let mut state_hash_map: HashMap<String, [u8; 32]> = HashMap::new();
    let mut checkpoints = Vec::new();

    let events = vec![ev1, ev2, ev3, ev4];

    for ev in &events {
        let mut state_before = imbl::OrdMap::new();
        let mut parent_hash = None;

        if !ev.prev_events.is_empty() {
            let prev_id = &ev.prev_events[0];
            if let Some(prev_state) = state_after_map.get(prev_id) {
                state_before = prev_state.clone();
                parent_hash = state_hash_map.get(prev_id).copied();
            }
        }

        let mut state_after = state_before.clone();
        if ev.state_key.is_some() {
            state_after.insert(
                (
                    rezzy::basespec::event_types::EventType::from(ev.event_type.as_str()),
                    ev.state_key.clone().unwrap(),
                ),
                ev.event_id.clone(),
            );
        }

        let hash_str = compute_state_hash(&state_after);
        state_after_map.insert(ev.event_id.clone(), state_after.clone());
        state_hash_map.insert(ev.event_id.clone(), hash_str);

        let deltas = compute_state_delta(&state_before, &state_after);
        checkpoints.push((hash_str, parent_hash, ev.event_id.clone(), deltas));
    }

    // Verify checkpoints
    assert_eq!(checkpoints.len(), 4);

    // E1
    let (_, p1, id1, d1) = &checkpoints[0];
    assert_eq!(id1, "$1");
    assert_eq!(p1, &None);
    assert_eq!(d1.len(), 1);

    // E2
    let (_, p2, id2, d2) = &checkpoints[1];
    assert_eq!(id2, "$2");
    assert_eq!(p2, &Some(checkpoints[0].0));
    assert_eq!(d2.len(), 1);
    assert_eq!(d2[0].event_type, "m.room.member");
    assert_eq!(d2[0].state_key, "@alice:example.com".to_string());
    assert_eq!(d2[0].event_id, Some("$2".to_string()));

    // E3 (Fork A - Bob joins)
    let (_, p3, id3, d3) = &checkpoints[2];
    assert_eq!(id3, "$3");
    assert_eq!(p3, &Some(checkpoints[1].0));
    assert_eq!(d3.len(), 1);
    assert_eq!(d3[0].event_type, "m.room.member");
    assert_eq!(d3[0].state_key, "@bob:example.com".to_string());
    assert_eq!(d3[0].event_id, Some("$3".to_string()));

    // E4 (Fork B - Alice leaves)
    let (_, p4, id4, d4) = &checkpoints[3];
    assert_eq!(id4, "$4");
    assert_eq!(p4, &Some(checkpoints[1].0));
    assert_eq!(d4.len(), 1);
    assert_eq!(d4[0].event_type, "m.room.member");
    assert_eq!(d4[0].state_key, "@alice:example.com".to_string());
    assert_eq!(d4[0].event_id, Some("$4".to_string()));
}

// ─── Supplemental coverage tests for state/at.rs  ────────────────────

use crate::utils;

/// Coverage: `compute_merge_base` (at.rs) — diamond DAG.
/// Tests: empty extremities, single extremity, two-branch merge, disjoint DAGs.
#[test]
fn test_compute_merge_base_diamond() {
    use rezzy::{compute_merge_base, compute_merge_bases, LeanEvent, MERGE_BASE_MAX_STEPS};
    use std::collections::HashMap;

    let evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$root",  "type": "m.room.create", "state_key": "", "sender": "@a:x", "depth": 1, "prev_events": []}
        {"event_id": "$left",  "type": "m.room.topic",  "state_key": "", "sender": "@a:x", "depth": 2, "prev_events": ["$root"]}
        {"event_id": "$right", "type": "m.room.name",   "state_key": "", "sender": "@a:x", "depth": 2, "prev_events": ["$root"]}
        {"event_id": "$merge", "type": "m.room.message", "sender": "@a:x", "depth": 3, "prev_events": ["$left", "$right"]}
    "#,
    );

    let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
    for ev in evs {
        events_map.insert(ev.event_id.clone(), ev);
    }

    // Empty extremities → None
    let result = compute_merge_base::<String, str, _, _>(&[], &events_map);
    assert!(result.is_none(), "Empty extremities must return None");

    // Single extremity → returns itself
    let result = compute_merge_base(&["$merge"], &events_map);
    assert_eq!(result, Some(&"$merge".to_string()));

    // Two branches → merge base is $root
    let result = compute_merge_base(&["$left", "$right"], &events_map);
    assert_eq!(
        result,
        Some(&"$root".to_string()),
        "Merge base of $left and $right must be $root"
    );

    // Merge tip + one branch → merge base is the branch (it's an ancestor of $merge)
    let result = compute_merge_base(&["$merge", "$left"], &events_map);
    assert_eq!(
        result,
        Some(&"$left".to_string()),
        "Merge base of $merge and $left must be $left"
    );

    // Disjoint: add an orphan event
    let orphan = LeanEvent {
        event_id: "$orphan".to_string(),
        depth: 1,
        ..Default::default()
    };
    events_map.insert("$orphan".to_string(), orphan);
    let result = compute_merge_base(&["$left", "$orphan"], &events_map);
    assert!(result.is_none(), "Disjoint DAGs must return None");

    // --- Junction-level: diamond should have exactly one junction at $root ---
    let junctions = compute_merge_bases(&["$left", "$right"], &events_map, MERGE_BASE_MAX_STEPS);
    assert_eq!(junctions.len(), 1, "Diamond should have exactly 1 junction");
    assert_eq!(junctions[0].event_id, &"$root".to_string());
    assert_eq!(junctions[0].mask, 0b11);
    assert_eq!(junctions[0].depth, 1);

    // Disjoint → no junctions
    let junctions = compute_merge_bases(&["$left", "$orphan"], &events_map, MERGE_BASE_MAX_STEPS);
    assert!(
        junctions.is_empty(),
        "Disjoint branches must yield no junctions"
    );

    // < 2 extremities → empty
    let junctions =
        compute_merge_bases::<String, str, _, _>(&["$left"], &events_map, MERGE_BASE_MAX_STEPS);
    assert!(junctions.is_empty(), "Single extremity must return empty");
}

/// Coverage: `compute_merge_bases` — three extremities with staggered convergence.
///
/// ```text
/// $root(1) ← $ab_merge(2) ← $a(3) (extremity 0)
/// $root(1) ← $ab_merge(2) ← $b(3) (extremity 1)
/// $root(1) ← $c(2)                 (extremity 2)
/// ```
///
/// Expected junctions:
/// - `$ab_merge` mask=0b011 depth=2 (A+B converge, closer to tips)
/// - `$root`     mask=0b111 depth=1 (all three converge)
#[test]
fn test_compute_merge_bases_three_way() {
    use rezzy::{compute_merge_bases, LeanEvent, MERGE_BASE_MAX_STEPS};
    use std::collections::HashMap;

    let evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$root",     "type": "m.room.create",  "state_key": "", "sender": "@a:x", "depth": 1, "prev_events": []}
        {"event_id": "$ab_merge", "type": "m.room.message",                  "sender": "@a:x", "depth": 2, "prev_events": ["$root"]}
        {"event_id": "$c",        "type": "m.room.message",                  "sender": "@a:x", "depth": 2, "prev_events": ["$root"]}
        {"event_id": "$a",        "type": "m.room.message",                  "sender": "@a:x", "depth": 3, "prev_events": ["$ab_merge"]}
        {"event_id": "$b",        "type": "m.room.message",                  "sender": "@a:x", "depth": 3, "prev_events": ["$ab_merge"]}
    "#,
    );

    let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
    for ev in evs {
        events_map.insert(ev.event_id.clone(), ev);
    }

    let junctions = compute_merge_bases(&["$a", "$b", "$c"], &events_map, MERGE_BASE_MAX_STEPS);

    // Should have 2 junctions: $ab_merge (A+B) and $root (all)
    assert_eq!(
        junctions.len(),
        2,
        "Expected 2 primitive junctions, got {junctions:?}"
    );

    // Sorted by descending depth: $ab_merge first (depth 2), then $root (depth 1)
    assert_eq!(junctions[0].event_id, &"$ab_merge".to_string());
    assert_eq!(junctions[0].mask, 0b011); // bits 0+1 = A+B
    assert_eq!(junctions[0].depth, 2);

    assert_eq!(junctions[1].event_id, &"$root".to_string());
    assert_eq!(junctions[1].mask, 0b111); // all three
    assert_eq!(junctions[1].depth, 1);
}

/// Coverage: `compute_merge_bases` — superseding pruning.
///
/// All three extremities merge at $global (depth 3), and A+B also merge
/// at $ab (depth 2) — but $ab is BELOW $global, so it's superseded.
///
/// ```text
/// $root(1) ← $ab(2) ← $global(3) ← $a(4) (extremity 0)
///                      $global(3) ← $b(4) (extremity 1)
///                      $global(3) ← $c(4) (extremity 2)
/// ```
#[test]
fn test_compute_merge_bases_superseding() {
    use rezzy::{compute_merge_bases, LeanEvent, MERGE_BASE_MAX_STEPS};
    use std::collections::HashMap;

    let evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$root",   "type": "m.room.create",  "state_key": "", "sender": "@a:x", "depth": 1, "prev_events": []}
        {"event_id": "$ab",     "type": "m.room.message",                  "sender": "@a:x", "depth": 2, "prev_events": ["$root"]}
        {"event_id": "$global", "type": "m.room.message",                  "sender": "@a:x", "depth": 3, "prev_events": ["$ab"]}
        {"event_id": "$a",      "type": "m.room.message",                  "sender": "@a:x", "depth": 4, "prev_events": ["$global"]}
        {"event_id": "$b",      "type": "m.room.message",                  "sender": "@a:x", "depth": 4, "prev_events": ["$global"]}
        {"event_id": "$c",      "type": "m.room.message",                  "sender": "@a:x", "depth": 4, "prev_events": ["$global"]}
    "#,
    );

    let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
    for ev in evs {
        events_map.insert(ev.event_id.clone(), ev);
    }

    let junctions = compute_merge_bases(&["$a", "$b", "$c"], &events_map, MERGE_BASE_MAX_STEPS);

    // $ab (mask 0b011, depth 2) is superseded by $global (mask 0b111, depth 3)
    // because 0b111 ⊃ 0b011 and depth 3 ≥ 2. Only $global should remain.
    assert_eq!(
        junctions.len(),
        1,
        "Superseded junction must be pruned: {junctions:?}"
    );
    assert_eq!(junctions[0].event_id, &"$global".to_string());
    assert_eq!(junctions[0].mask, 0b111);
    assert_eq!(junctions[0].depth, 3);
}

/// Coverage: `compute_merge_bases` — `max_steps` hard cap.
#[test]
fn test_compute_merge_bases_max_steps() {
    use rezzy::{compute_merge_bases, LeanEvent};
    use std::collections::HashMap;

    // Build a deep linear chain: $0 ← $1 ← ... ← $999
    // Fork at the end: $999 ← $left, $999 ← $right
    let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
    for i in 0..1000u64 {
        let prev = if i > 0 {
            vec![format!("${}", i - 1)]
        } else {
            Vec::new()
        };
        events_map.insert(
            format!("${i}"),
            LeanEvent {
                event_id: format!("${i}"),
                depth: i + 1,
                prev_events: prev,
                ..Default::default()
            },
        );
    }
    events_map.insert(
        "$left".to_string(),
        LeanEvent {
            event_id: "$left".to_string(),
            depth: 1001,
            prev_events: vec!["$999".to_string()],
            ..Default::default()
        },
    );
    events_map.insert(
        "$right".to_string(),
        LeanEvent {
            event_id: "$right".to_string(),
            depth: 1001,
            prev_events: vec!["$999".to_string()],
            ..Default::default()
        },
    );

    // With enough steps, should find $999 as merge base
    let junctions = compute_merge_bases(&["$left", "$right"], &events_map, 5000);
    assert_eq!(junctions.len(), 1);
    assert_eq!(junctions[0].event_id, &"$999".to_string());

    // With max_steps=1, walk terminates before finding merge base
    let junctions = compute_merge_bases(&["$left", "$right"], &events_map, 1);
    assert!(junctions.is_empty(), "max_steps=1 should not find junction");
}

/// Coverage: `CycleDetected` in `run_state_pipeline_streaming` (at.rs:580)
/// and the handler in `compute_state_at_streaming` (at.rs:489-496).
///
/// Creates a `prev_events` cycle: $A→$B→$A. The topological sort detects the
/// cycle and returns `CycleDetected`, which `compute_state_at_streaming`
/// silently handles (prints to stderr).
#[test]
fn test_compute_state_at_prev_events_cycle() {
    use rezzy::state::at::{
        compute_state_at_streaming, try_compute_state_at_streaming, StateComputationError,
    };
    use rezzy::{LeanEvent, StateResVersion};
    use std::collections::HashMap;

    let evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$create", "type": "m.room.create", "state_key": "", "sender": "@a:x", "depth": 1, "prev_events": []}
        {"event_id": "$join",   "type": "m.room.member",  "state_key": "@a:x", "sender": "@a:x", "depth": 2, "prev_events": ["$create"]}
    "#,
    );

    let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
    for ev in &evs {
        events_map.insert(ev.event_id.clone(), ev.clone());
    }

    // Add a cycle: $A→$B→$A
    events_map.insert(
        "$A".to_string(),
        LeanEvent {
            event_id: "$A".to_string(),
            event_type: "m.room.topic".to_string(),
            state_key: Some(String::new()),
            sender: "@a:x".to_string(),
            depth: 3,
            prev_events: vec!["$join".to_string(), "$B".to_string()],
            ..Default::default()
        },
    );
    events_map.insert(
        "$B".to_string(),
        LeanEvent {
            event_id: "$B".to_string(),
            event_type: "m.room.name".to_string(),
            state_key: Some(String::new()),
            sender: "@a:x".to_string(),
            depth: 3,
            prev_events: vec!["$join".to_string(), "$A".to_string()],
            ..Default::default()
        },
    );

    // try_compute_state_at_streaming should return CycleDetected
    let result = try_compute_state_at_streaming(
        &["$A"],
        &events_map,
        StateResVersion::V2,
        |_id, _state| -> Result<(), std::convert::Infallible> { Ok(()) },
        &String::new(),
    );
    assert!(
        matches!(result, Err(StateComputationError::CycleDetected)),
        "Must detect prev_events cycle: {result:?}"
    );

    // compute_state_at_streaming should silently handle CycleDetected
    let mut callback_called = false;
    compute_state_at_streaming(
        &["$A"],
        &events_map,
        StateResVersion::V2,
        |_id, _state| {
            callback_called = true;
        },
        &String::new(),
    );
    assert!(
        !callback_called,
        "Callback must not be called when there's a cycle"
    );
}

/// Coverage: auth chain diff interleaving in `resolve_multiple_prev_states`
/// (at.rs:948-982). The dual-heap interleaving requires:
/// 1. Conflicted events whose auth chains include events NOT in unconflicted state
/// 2. Those non-unconflicted auth events at depths overlapping with `u_heap` entries
///
/// DAG topology:
/// ```text
///   $create(1)→$join_a(2)→$pl(3)→$join_b(4)→$join_c(5)→$join_d(6)
///                             \                              |
///                              $deep_auth(4)        Fork A: $topic_a(7) auth=[$create,$pl,$join_a,$deep_auth]
/// Key paths targeted:
/// - **Line 958-960**: U-side auth chain traversal. `$name` (depth 5, unconflicted)
///   has `$hidden_pl` (depth 3) in its `auth_events`, which is NOT in unconflicted
///   state. When U catches up, it pops `$name` and discovers `$hidden_pl` → pushes
///   onto `u_heap`.
/// - **Line 972**: C-side PRUNE EARLY. `$topic_a`'s auth includes `$create` and `$pl`,
///   which are already in `u_visited` → triggers `continue`.
#[test]
fn test_auth_chain_diff_interleaving() {
    use rezzy::{compute_state_at, LeanEvent, StateResVersion};
    use std::collections::HashMap;

    let evs = utils::parse_jsonl_events(
        r#"
        {"event_id": "$create",    "type": "m.room.create",       "state_key": "",     "sender": "@a:x", "depth": 1, "prev_events": [],           "auth_events": [],                                         "content": {"room_version": "10", "creator": "@a:x"}}
        {"event_id": "$join_a",    "type": "m.room.member",       "state_key": "@a:x", "sender": "@a:x", "depth": 2, "prev_events": ["$create"],  "auth_events": ["$create"],                                "content": {"membership": "join"}}
        {"event_id": "$pl",        "type": "m.room.power_levels", "state_key": "",     "sender": "@a:x", "depth": 3, "prev_events": ["$join_a"],  "auth_events": ["$create", "$join_a"],                      "content": {"users": {"@a:x": 100}}}
        {"event_id": "$hidden_pl", "type": "m.room.power_levels", "state_key": "",     "sender": "@a:x", "depth": 3, "prev_events": ["$pl"],      "auth_events": ["$create", "$join_a"],                      "content": {"users": {"@a:x": 100}}}
        {"event_id": "$join_b",    "type": "m.room.member",       "state_key": "@b:x", "sender": "@b:x", "depth": 4, "prev_events": ["$pl"],      "auth_events": ["$create", "$pl"],                          "content": {"membership": "join"}}
        {"event_id": "$name",      "type": "m.room.name",         "state_key": "",     "sender": "@a:x", "depth": 5, "prev_events": ["$pl"],      "auth_events": ["$create", "$pl", "$join_a", "$hidden_pl"], "content": {"name": "Test"}}
        {"event_id": "$topic_a",   "type": "m.room.topic",        "state_key": "",     "sender": "@a:x", "depth": 6, "prev_events": ["$name"],    "auth_events": ["$create", "$pl", "$join_a"],               "content": {"topic": "A"}}
        {"event_id": "$topic_b",   "type": "m.room.topic",        "state_key": "",     "sender": "@a:x", "depth": 6, "prev_events": ["$join_b"],  "auth_events": ["$create", "$pl", "$join_a"],               "content": {"topic": "B"}}
        {"event_id": "$merge",     "type": "m.room.message",                           "sender": "@a:x", "depth": 7, "prev_events": ["$topic_a", "$topic_b"], "auth_events": ["$create", "$pl", "$join_a"], "content": {}}
    "#,
    );

    let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
    for ev in evs {
        events_map.insert(ev.event_id.clone(), ev);
    }

    let state =
        compute_state_at("$merge", &events_map, StateResVersion::V2, &String::new()).unwrap();

    assert!(
        state.contains_key(&(
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new()
        )),
        "Must have create event"
    );
    assert!(
        state.contains_key(&(
            rezzy::basespec::event_types::EventType::from("m.room.topic"),
            String::new()
        )),
        "Must have resolved topic"
    );
}
