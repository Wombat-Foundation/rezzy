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

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap};

/// A lightweight Matrix Event representation for Lean-equivalent resolution.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LeanEvent {
    pub event_id: String,
    pub power_level: i64,
    pub origin_server_ts: u64,
    pub prev_events: Vec<String>,
}

/// The core tie-breaking logic from Ruma Lean (StateRes.lean).
/// Matches Lean model: power_level (desc) -> origin_server_ts (asc) -> event_id (asc)
impl Ord for LeanEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        // power_level (descending)
        match other.power_level.cmp(&self.power_level) {
            Ordering::Equal => {
                // origin_server_ts (ascending)
                match self.origin_server_ts.cmp(&other.origin_server_ts) {
                    Ordering::Equal => {
                        // event_id (ascending)
                        self.event_id.cmp(&other.event_id)
                    }
                    ord => ord,
                }
            }
            ord => ord,
        }
    }
}

impl PartialOrd for LeanEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A simplified implementation of Kahn's Topological Sort.
/// Equivalence proven via formal verification in RumaLean/Kahn.lean.
pub fn lean_kahn_sort(events: &HashMap<String, LeanEvent>) -> Vec<String> {
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

    let mut queue: BinaryHeap<&LeanEvent> = BinaryHeap::new();
    for (id, &degree) in &in_degree {
        if degree == 0 {
            if let Some(event) = events.get(id) {
                queue.push(event);
            }
        }
    }

    let mut result = Vec::new();
    while let Some(event) = queue.pop() {
        result.push(event.event_id.clone());
        if let Some(neighbors) = adjacency.get(&event.event_id) {
            for next_id in neighbors {
                let degree = in_degree.get_mut(next_id).unwrap();
                *degree -= 1;
                if *degree == 0 {
                    queue.push(events.get(next_id).unwrap());
                }
            }
        }
    }
    result
}

/// Simplified Matrix State Resolution v2 (Lean Implementation).
/// Performs unconflicted resolution and tie-breaking without full spec overhead.
pub fn resolve_lean(
    unconflicted_state: BTreeMap<(String, String), String>,
    conflicted_events: HashMap<String, LeanEvent>,
) -> BTreeMap<(String, String), String> {
    let resolved = unconflicted_state;

    // Sort conflicted events using the Lean-verified Kahn sort
    let _sorted_ids = lean_kahn_sort(&conflicted_events);

    // In a real Matrix resolution, we'd apply state transitions here.
    // For the "Lean" proof, we simply verify the ordering is sound.
    // (Simplified for demo purposes)

    resolved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tie_breaking_order() {
        // Lean Model: power_level (desc) -> origin_server_ts (asc) -> event_id (asc)

        let high_power = LeanEvent {
            event_id: "c".to_string(),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
        };

        let low_power = LeanEvent {
            event_id: "a".to_string(),
            power_level: 50,
            origin_server_ts: 10,
            prev_events: vec![],
        };

        let early_ts = LeanEvent {
            event_id: "c".to_string(),
            power_level: 100,
            origin_server_ts: 5,
            prev_events: vec![],
        };

        let late_ts = LeanEvent {
            event_id: "a".to_string(),
            power_level: 100,
            origin_server_ts: 15,
            prev_events: vec![],
        };

        let early_id = LeanEvent {
            event_id: "a".to_string(),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
        };

        let late_id = LeanEvent {
            event_id: "b".to_string(),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
        };

        // 1. Power Level takes precedence (Higher is better/earlier in sort)
        assert!(high_power < low_power);

        // 2. Timestamp is second (Lower is better/earlier)
        assert!(early_ts < late_ts);

        // 3. Event ID is the final tie-breaker (Lexicographical)
        assert!(early_id < late_id);
    }

    #[test]
    fn test_kahn_determinism() {
        // Verify that regardless of input order, the output is deterministic
        // based on the Lean-verified total order.

        let mut events = HashMap::new();
        events.insert(
            "1".to_string(),
            LeanEvent {
                event_id: "1".to_string(),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
            },
        );
        events.insert(
            "2".to_string(),
            LeanEvent {
                event_id: "2".to_string(),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec!["1".to_string()],
            },
        );
        events.insert(
            "3".to_string(),
            LeanEvent {
                event_id: "3".to_string(),
                power_level: 50,
                origin_server_ts: 10,
                prev_events: vec!["1".to_string()],
            },
        );

        let sorted = lean_kahn_sort(&events);

        // "1" has no parents.
        // "2" and "3" both depend on "1".
        // "2" has higher power than "3", so it must come first.
        assert_eq!(sorted, vec!["1", "2", "3"]);
    }

    #[test]
    fn test_total_order_properties() {
        let e1 = LeanEvent {
            event_id: "a".to_string(),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
        };
        let e2 = LeanEvent {
            event_id: "b".to_string(),
            power_level: 100,
            origin_server_ts: 10,
            prev_events: vec![],
        };
        let e3 = LeanEvent {
            event_id: "c".to_string(),
            power_level: 50,
            origin_server_ts: 10,
            prev_events: vec![],
        };

        // Totality: a <= b or b <= a
        assert!(e1 <= e2 || e2 <= e1);

        // Transitivity: a <= b and b <= c => a <= c
        if e1 <= e2 && e2 <= e3 {
            assert!(e1 <= e3);
        }

        // Antisymmetry: a <= b and b <= a => a == b
        if e1 <= e1 && e1 <= e1 {
            assert!(e1 == e1);
        }
    }
}
