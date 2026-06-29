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
    use rezzy::{compute_state_at, LeanEvent};
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
        };

        events_map.insert(event_id, ev);
    }

    // Target events
    let early_id = "$100";
    let mid_id = "$500";
    let tip_id = "$1000";

    // Correctness Checks
    let early_state = compute_state_at(early_id, &events_map).expect("should compute");
    let mid_state = compute_state_at(mid_id, &events_map).expect("should compute");
    let tip_state = compute_state_at(tip_id, &events_map).expect("should compute");

    // Check sizes of the state maps
    // At $100, we should have exactly 10 state keys (100 / 10)
    assert_eq!(early_state.len(), 10);
    // At $500, we should have exactly 50 state keys (500 / 10)
    assert_eq!(mid_state.len(), 50);
    // At $1000, we should have exactly 100 state keys (1000 / 10)
    assert_eq!(tip_state.len(), 100);

    // Verify a specific key exists at mid and tip, but not early
    let test_key = ("m.room.member".to_string(), Some("user_400".to_string()));
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
        let _ = compute_state_at(early_id, &events_map);
    }
    let dur_early = start_early.elapsed() / runs;

    // Mid
    let start_mid = Instant::now();
    for _ in 0..runs {
        let _ = compute_state_at(mid_id, &events_map);
    }
    let dur_mid = start_mid.elapsed() / runs;

    // Tip
    let start_tip = Instant::now();
    for _ in 0..runs {
        let _ = compute_state_at(tip_id, &events_map);
    }
    let dur_tip = start_tip.elapsed() / runs;

    println!("\n=== compute_state_at Performance (Synthetic 1k Chain, average of {runs} runs) ===");
    println!("Early Event (depth 100):  {dur_early:?}");
    println!("Mid Event (depth 500):    {dur_mid:?}");
    println!("Tip Event (depth 1000):   {dur_tip:?}");
}

#[test]
fn test_compute_state_at_batch() {
    use rezzy::{compute_state_at, compute_state_at_batch, LeanEvent};
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
        };

        events_map.insert(event_id, ev);
    }

    let early_id = "$100";
    let mid_id = "$500";
    let tip_id = "$1000";

    // 1. Correctness Checks
    let early_state = compute_state_at(early_id, &events_map).expect("should compute");
    let mid_state = compute_state_at(mid_id, &events_map).expect("should compute");
    let tip_state = compute_state_at(tip_id, &events_map).expect("should compute");

    // Run batch computation
    let batch_ids = vec![early_id, mid_id, tip_id];
    let batch_results = compute_state_at_batch(&batch_ids, &events_map);

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
    let empty_results = compute_state_at_batch::<String, str, _>(&[], &events_map);
    assert!(empty_results.is_empty());

    // Verify missing / invalid IDs are ignored or skipped gracefully without panics
    let invalid_ids = vec!["$missing_1", early_id, "$missing_2"];
    let partial_results = compute_state_at_batch(&invalid_ids, &events_map);
    assert_eq!(partial_results.len(), 1);
    assert_eq!(&partial_results[early_id], &early_state);
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
    use rezzy::state_delta::{compute_state_delta, compute_state_hash};
    use std::collections::{BTreeMap, HashMap};

    let events = make_chronological_test_events();

    // Perform delta-chain sequential processing using library functions
    let mut state_after_map: HashMap<String, BTreeMap<(String, Option<String>), String>> =
        HashMap::new();
    let mut state_hash_map: HashMap<String, String> = HashMap::new();
    let mut checkpoints = Vec::new();

    for ev in &events {
        let mut state_before = BTreeMap::new();
        let mut parent_hash = None;

        if !ev.prev_events.is_empty() {
            let prev_id = &ev.prev_events[0];
            if let Some(prev_state) = state_after_map.get(prev_id) {
                state_before = prev_state.clone();
                parent_hash = state_hash_map.get(prev_id).cloned();
            }
        }

        let mut state_after = state_before.clone();
        if ev.state_key.is_some() {
            state_after.insert(
                (ev.event_type.clone(), ev.state_key.clone()),
                ev.event_id.clone(),
            );
        }

        let hash_str = compute_state_hash(&state_after);
        state_after_map.insert(ev.event_id.clone(), state_after.clone());
        state_hash_map.insert(ev.event_id.clone(), hash_str.clone());

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
    assert_eq!(d1[0].state_key, Some(String::new()));
    assert_eq!(d1[0].event_id, Some("$1".to_string()));

    let (h2, p2, id2, d2) = &checkpoints[1];
    assert_eq!(id2, "$2");
    assert_eq!(p2, &Some(h1.clone()));
    assert_eq!(d2.len(), 1);
    assert_eq!(d2[0].event_type, "m.room.member");
    assert_eq!(d2[0].state_key, Some("@alice:example.com".to_string()));
    assert_eq!(d2[0].event_id, Some("$2".to_string()));

    let (h3, p3, id3, d3) = &checkpoints[2];
    assert_eq!(id3, "$3");
    assert_eq!(p3, &Some(h2.clone()));
    assert_eq!(h3, h2); // State hash must be identical because it's a non-state event
    assert!(d3.is_empty()); // Delta list must be empty because state did not change
}

#[test]
fn test_state_delta_compression_robustness() {
    use rezzy::state_delta::{compute_state_delta, compute_state_hash};
    use rezzy::LeanEvent;
    use std::collections::{BTreeMap, HashMap};

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

    let mut state_after_map: HashMap<String, BTreeMap<(String, Option<String>), String>> =
        HashMap::new();
    let mut state_hash_map: HashMap<String, String> = HashMap::new();
    let mut checkpoints = Vec::new();

    let events = vec![ev1, ev2, ev3, ev4];

    for ev in &events {
        let mut state_before = BTreeMap::new();
        let mut parent_hash = None;

        if !ev.prev_events.is_empty() {
            let prev_id = &ev.prev_events[0];
            if let Some(prev_state) = state_after_map.get(prev_id) {
                state_before = prev_state.clone();
                parent_hash = state_hash_map.get(prev_id).cloned();
            }
        }

        let mut state_after = state_before.clone();
        if ev.state_key.is_some() {
            state_after.insert(
                (ev.event_type.clone(), ev.state_key.clone()),
                ev.event_id.clone(),
            );
        }

        let hash_str = compute_state_hash(&state_after);
        state_after_map.insert(ev.event_id.clone(), state_after.clone());
        state_hash_map.insert(ev.event_id.clone(), hash_str.clone());

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
    assert_eq!(p2, &Some(checkpoints[0].0.clone()));
    assert_eq!(d2.len(), 1);
    assert_eq!(d2[0].event_type, "m.room.member");
    assert_eq!(d2[0].state_key, Some("@alice:example.com".to_string()));
    assert_eq!(d2[0].event_id, Some("$2".to_string()));

    // E3 (Fork A - Bob joins)
    let (_, p3, id3, d3) = &checkpoints[2];
    assert_eq!(id3, "$3");
    assert_eq!(p3, &Some(checkpoints[1].0.clone()));
    assert_eq!(d3.len(), 1);
    assert_eq!(d3[0].event_type, "m.room.member");
    assert_eq!(d3[0].state_key, Some("@bob:example.com".to_string()));
    assert_eq!(d3[0].event_id, Some("$3".to_string()));

    // E4 (Fork B - Alice leaves)
    let (_, p4, id4, d4) = &checkpoints[3];
    assert_eq!(id4, "$4");
    assert_eq!(p4, &Some(checkpoints[1].0.clone()));
    assert_eq!(d4.len(), 1);
    assert_eq!(d4[0].event_type, "m.room.member");
    assert_eq!(d4[0].state_key, Some("@alice:example.com".to_string()));
    assert_eq!(d4[0].event_id, Some("$4".to_string()));
}
