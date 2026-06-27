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
    use ruma_lean::{compute_state_at, LeanEvent};
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

    // 1. Correctness Checks
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

    // 2. Performance Benchmark (average of 500 runs)
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

// Helper FNV-1a state hash calculation to match main.rs
fn compute_state_hash(
    state: &std::collections::BTreeMap<(String, Option<String>), String>,
) -> String {
    let mut hash: u64 = 14_695_981_039_346_656_037;
    for ((event_type, state_key), event_id) in state {
        for &byte in event_type.as_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(1_099_511_628_211);
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

fn make_chronological_test_events() -> Vec<ruma_lean::LeanEvent> {
    use ruma_lean::LeanEvent;
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
    use std::collections::{BTreeMap, HashMap};

    let events = make_chronological_test_events();

    // 2. Perform delta-chain sequential processing
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

        let mut deltas = Vec::new();
        let primary_parent_state = ev
            .prev_events
            .first()
            .and_then(|p_id| state_after_map.get(p_id));

        if let Some(parent_state) = primary_parent_state {
            for (key, event_id) in &state_after {
                match parent_state.get(key) {
                    Some(parent_event_id) if parent_event_id == event_id => {}
                    _ => {
                        deltas.push((key.0.clone(), key.1.clone(), event_id.clone()));
                    }
                }
            }
        } else {
            for (key, event_id) in &state_after {
                deltas.push((key.0.clone(), key.1.clone(), event_id.clone()));
            }
        }

        checkpoints.push((hash_str, parent_hash, ev.event_id.clone(), deltas));
    }

    // 3. Verification of Chaining logic
    assert_eq!(checkpoints.len(), 3);

    let (h1, p1, id1, d1) = &checkpoints[0];
    assert_eq!(id1, "$1");
    assert_eq!(p1, &None);
    assert_eq!(d1.len(), 1);
    assert_eq!(
        d1[0],
        (
            "m.room.create".to_string(),
            Some(String::new()),
            "$1".to_string()
        )
    );

    let (h2, p2, id2, d2) = &checkpoints[1];
    assert_eq!(id2, "$2");
    assert_eq!(p2, &Some(h1.clone()));
    assert_eq!(d2.len(), 1);
    assert_eq!(
        d2[0],
        (
            "m.room.member".to_string(),
            Some("@alice:example.com".to_string()),
            "$2".to_string()
        )
    );

    let (h3, p3, id3, d3) = &checkpoints[2];
    assert_eq!(id3, "$3");
    assert_eq!(p3, &Some(h2.clone()));
    assert_eq!(h3, h2); // State hash must be identical because it's a non-state event
    assert!(d3.is_empty()); // Delta list must be empty because state did not change
}

#[test]
fn test_state_delta_compression_robustness() {
    use ruma_lean::LeanEvent;
    use std::collections::{BTreeMap, HashMap};

    // Construct a micro-history with a merge where some state key gets deleted/overwritten
    // E1: Create room (state: m.room.create => $1)
    let ev1 = LeanEvent {
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

        let mut deltas = Vec::new();
        let primary_parent_state = ev
            .prev_events
            .first()
            .and_then(|p_id| state_after_map.get(p_id));

        if let Some(parent_state) = primary_parent_state {
            for (key, event_id) in &state_after {
                match parent_state.get(key) {
                    Some(parent_event_id) if parent_event_id == event_id => {}
                    _ => {
                        deltas.push((key.0.clone(), key.1.clone(), Some(event_id.clone())));
                    }
                }
            }
            // Detect key deletion/removal
            for key in parent_state.keys() {
                if !state_after.contains_key(key) {
                    deltas.push((key.0.clone(), key.1.clone(), None));
                }
            }
        } else {
            for (key, event_id) in &state_after {
                deltas.push((key.0.clone(), key.1.clone(), Some(event_id.clone())));
            }
        }

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
    assert_eq!(d2[0].0, "m.room.member");
    assert_eq!(d2[0].1, Some("@alice:example.com".to_string()));
    assert_eq!(d2[0].2, Some("$2".to_string()));

    // E3 (Fork A - Bob joins)
    let (_, p3, id3, d3) = &checkpoints[2];
    assert_eq!(id3, "$3");
    assert_eq!(p3, &Some(checkpoints[1].0.clone()));
    assert_eq!(d3.len(), 1);
    assert_eq!(d3[0].0, "m.room.member");
    assert_eq!(d3[0].1, Some("@bob:example.com".to_string()));
    assert_eq!(d3[0].2, Some("$3".to_string()));

    // E4 (Fork B - Alice leaves)
    let (_, p4, id4, d4) = &checkpoints[3];
    assert_eq!(id4, "$4");
    assert_eq!(p4, &Some(checkpoints[1].0.clone()));
    assert_eq!(d4.len(), 1);
    assert_eq!(d4[0].0, "m.room.member");
    assert_eq!(d4[0].1, Some("@alice:example.com".to_string()));
    assert_eq!(d4[0].2, Some("$4".to_string()));
}
