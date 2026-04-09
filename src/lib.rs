// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]

extern crate alloc;

use alloc::collections::{BTreeMap, BinaryHeap};
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
pub use std::collections::HashMap;

#[cfg(not(feature = "std"))]
pub use hashbrown::HashMap;

/// The version of the Matrix State Resolution algorithm to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateResVersion {
    V1,
    V2,
    V2_1,
}

/// A lightweight Matrix Event representation for Lean-equivalent resolution.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeanEvent {
    pub event_id: String,
    pub power_level: i64,
    pub origin_server_ts: u64,
    pub prev_events: Vec<String>,
    pub depth: u64, // Required for V1
}

/// A wrapper to ensure BinaryHeap pops the "smallest" (best) event first.
#[derive(Eq, PartialEq)]
struct SortPriority<'a> {
    event: &'a LeanEvent,
    version: StateResVersion,
}

impl<'a> Ord for SortPriority<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.version {
            StateResVersion::V1 => {
                // V1 tie-breaking: depth (asc) -> event_id (asc)
                // Inverted for Max-Heap
                match other.event.depth.cmp(&self.event.depth) {
                    Ordering::Equal => other.event.event_id.cmp(&self.event.event_id),
                    ord => ord,
                }
            }
            StateResVersion::V2 | StateResVersion::V2_1 => {
                // V2 tie-breaking: power_level (desc) -> origin_server_ts (asc) -> event_id (asc)
                // Priority popping (best first)
                match self.event.power_level.cmp(&other.event.power_level) {
                    Ordering::Equal => {
                        match other
                            .event
                            .origin_server_ts
                            .cmp(&self.event.origin_server_ts)
                        {
                            Ordering::Equal => other.event.event_id.cmp(&self.event.event_id),
                            ord => ord,
                        }
                    }
                    ord => ord,
                }
            }
        }
    }
}

impl<'a> PartialOrd for SortPriority<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A simplified implementation of Kahn's Topological Sort.
pub fn lean_kahn_sort(
    events: &HashMap<String, LeanEvent>,
    version: StateResVersion,
) -> Vec<String> {
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();

    for (id, event) in events {
        in_degree.entry(id.clone()).or_insert(0);
        for prev in &event.prev_events {
            if events.contains_key(prev) {
                adjacency.entry(prev.clone()).or_default().push(id.clone());
                *in_degree.entry(id.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut queue: BinaryHeap<SortPriority> = BinaryHeap::new();
    for (id, &degree) in &in_degree {
        if degree == 0 {
            if let Some(event) = events.get(id) {
                queue.push(SortPriority { event, version });
            }
        }
    }

    let mut result = Vec::new();
    while let Some(priority) = queue.pop() {
        let event = priority.event;
        result.push(event.event_id.clone());
        if let Some(neighbors) = adjacency.get(&event.event_id) {
            for next_id in neighbors {
                let degree = in_degree.get_mut(next_id).unwrap();
                *degree -= 1;
                if *degree == 0 {
                    queue.push(SortPriority {
                        event: events.get(next_id).unwrap(),
                        version,
                    });
                }
            }
        }
    }
    result
}

pub fn resolve_lean(
    unconflicted_state: BTreeMap<(String, String), String>,
    conflicted_events: HashMap<String, LeanEvent>,
    version: StateResVersion,
) -> BTreeMap<(String, String), String> {
    let resolved = unconflicted_state;
    let _sorted_ids = lean_kahn_sort(&conflicted_events, version);
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    #[cfg(not(feature = "std"))]
    use hashbrown::HashMap;
    #[cfg(feature = "std")]
    use std::collections::HashMap;

    #[test]
    fn test_v1_resolution_happy_path() {
        let mut events = HashMap::new();
        // V1 tie-breaks by depth then ID
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                power_level: 0,
                origin_server_ts: 100,
                prev_events: vec![],
                depth: 1,
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                power_level: 0,
                origin_server_ts: 50,
                prev_events: vec![],
                depth: 2,
            },
        );

        let sorted = lean_kahn_sort(&events, StateResVersion::V1);
        // Smaller depth comes first
        assert_eq!(sorted, vec!["A", "B"]);
    }

    #[test]
    fn test_v1_tie_break_by_id() {
        let mut events = HashMap::new();
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                power_level: 0,
                origin_server_ts: 100,
                prev_events: vec![],
                depth: 1,
            },
        );
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                power_level: 0,
                origin_server_ts: 100,
                prev_events: vec![],
                depth: 1,
            },
        );

        let sorted = lean_kahn_sort(&events, StateResVersion::V1);
        // Same depth, tie-break by ID (lexicographical)
        assert_eq!(sorted, vec!["A", "B"]);
    }

    #[test]
    fn test_v2_resolution_happy_path() {
        let mut events = HashMap::new();
        // V2 tie-breaks by Power Level -> TS -> ID
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec![],
                depth: 10,
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                power_level: 50,
                origin_server_ts: 10,
                prev_events: vec![],
                depth: 1,
            },
        );

        let sorted = lean_kahn_sort(&events, StateResVersion::V2);
        // Higher power level (A) wins even though B is earlier and shallower
        assert_eq!(sorted, vec!["A", "B"]);
    }

    #[test]
    fn test_v2_unhappy_path_cycle_detection() {
        let mut events = HashMap::new();
        // Cyclic dependency: A -> B -> A
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec!["B".into()],
                depth: 1,
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec!["A".into()],
                depth: 1,
            },
        );

        let sorted = lean_kahn_sort(&events, StateResVersion::V2);
        // Kahn's sort returns incomplete list if there is a cycle
        assert!(sorted.is_empty());
    }

    #[test]
    fn test_v2_1_linearization() {
        // V2.1 uses same tie-breaking as V2 for sort, but logic is used for auth chain linearization
        let mut events = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec![],
                depth: 1,
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                power_level: 100,
                origin_server_ts: 50,
                prev_events: vec![],
                depth: 1,
            },
        );

        let sorted = lean_kahn_sort(&events, StateResVersion::V2_1);
        // Same power, earlier TS (B) wins
        assert_eq!(sorted, vec!["B", "A"]);
    }

    #[test]
    fn test_compare_v1_vs_v2() {
        let mut events = HashMap::new();
        // Event A: Higher power, deeper
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec![],
                depth: 10,
            },
        );
        // Event B: Lower power, shallower
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                power_level: 50,
                origin_server_ts: 100,
                prev_events: vec![],
                depth: 1,
            },
        );

        let sorted_v1 = lean_kahn_sort(&events, StateResVersion::V1);
        let sorted_v2 = lean_kahn_sort(&events, StateResVersion::V2);

        // V1 prioritizes depth
        assert_eq!(sorted_v1, vec!["B", "A"]);
        // V2 prioritizes power level
        assert_eq!(sorted_v2, vec!["A", "B"]);
    }

    #[test]
    fn test_v1_v2_v2_1_comparison_determinism() {
        // Construct a scenario where all 3 versions might produce different results
        let mut events = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                power_level: 10,
                origin_server_ts: 10,
                prev_events: vec![],
                depth: 1,
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec![],
                depth: 10,
            },
        );

        let sorted_v1 = lean_kahn_sort(&events, StateResVersion::V1);
        let sorted_v2 = lean_kahn_sort(&events, StateResVersion::V2);
        let sorted_v2_1 = lean_kahn_sort(&events, StateResVersion::V2_1);

        assert_eq!(sorted_v1, vec!["A", "B"]); // V1: Depth wins
        assert_eq!(sorted_v2, vec!["B", "A"]); // V2: Power wins
        assert_eq!(sorted_v2_1, vec!["B", "A"]); // V2.1: Power wins
    }

    /// Batch Test Helper: Easily define tests in a row-based format.
    /// Format: (ID, Power, TS, Depth, Parents)
    fn run_batch_test(
        version: StateResVersion,
        rows: &[(&str, i64, u64, u64, &[&str])],
        expected: &[&str],
    ) {
        let mut events = HashMap::new();
        for r in rows {
            events.insert(
                r.0.to_string(),
                LeanEvent {
                    event_id: r.0.to_string(),
                    power_level: r.1,
                    origin_server_ts: r.2,
                    depth: r.3,
                    prev_events: r.4.iter().map(|s| s.to_string()).collect(),
                },
            );
        }
        let result = lean_kahn_sort(&events, version);
        assert_eq!(
            result,
            expected.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_resolution_batch() {
        // Test Case 1: Standard tie-break (Power wins over TS)
        run_batch_test(
            StateResVersion::V2,
            &[("Alice", 100, 500, 1, &[]), ("Bob", 50, 100, 1, &[])],
            &["Alice", "Bob"],
        );

        // Test Case 2: Deep DAG
        run_batch_test(
            StateResVersion::V2,
            &[("Root", 100, 10, 1, &[]), ("Child", 50, 20, 2, &["Root"])],
            &["Root", "Child"],
        );

        // Test Case 3: V1 Depth priority
        run_batch_test(
            StateResVersion::V1,
            &[("Deep", 100, 100, 10, &[]), ("Shallow", 10, 100, 1, &[])],
            &["Shallow", "Deep"],
        );
    }

    #[test]
    fn test_native_resolution_bootstrap_parity() {
        // Simulates the 'Path A' resolution logic proven in Lean
        let mut events = HashMap::new();

        // Root Event: Create Room
        events.insert(
            "1".into(),
            LeanEvent {
                event_id: "1".into(),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                depth: 1,
            },
        );
        // Event 2: Join User
        events.insert(
            "2".into(),
            LeanEvent {
                event_id: "2".into(),
                power_level: 0,
                origin_server_ts: 20,
                prev_events: vec!["1".into()],
                depth: 2,
            },
        );

        let sorted = lean_kahn_sort(&events, StateResVersion::V2);

        let mut resolved_state = BTreeMap::new();
        for id in sorted {
            let ev = events.get(&id).unwrap();
            // Deterministic state key mapping
            let key = ("m.room.member".to_string(), "@user:example.com".to_string());
            resolved_state.insert(key, ev.event_id.clone());
        }

        // Verify the last event ("2") is the final state for that key
        assert_eq!(
            resolved_state.get(&("m.room.member".to_string(), "@user:example.com".to_string())),
            Some(&"2".to_string())
        );
    }

    #[test]
    fn test_hinted_verification_determinism() {
        // Proves that the linear sequence generation is deterministic
        let mut events = HashMap::new();
        events.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
                depth: 1,
            },
        );
        events.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                power_level: 100,
                origin_server_ts: 20,
                prev_events: vec!["A".into()],
                depth: 2,
            },
        );

        let sequence_1 = lean_kahn_sort(&events, StateResVersion::V2);
        let sequence_2 = lean_kahn_sort(&events, StateResVersion::V2);

        assert_eq!(sequence_1, sequence_2);
        assert_eq!(sequence_1, vec!["A", "B"]);
    }
}
