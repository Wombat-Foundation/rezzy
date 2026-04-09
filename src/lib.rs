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

/// A lightweight Matrix Event representation for Lean-equivalent resolution.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeanEvent {
    pub event_id: String,
    pub power_level: i64,
    pub origin_server_ts: u64,
    pub prev_events: Vec<String>,
}

/// The core tie-breaking logic from Ruma Lean (StateRes.lean).
impl Ord for LeanEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        match other.power_level.cmp(&self.power_level) {
            Ordering::Equal => match self.origin_server_ts.cmp(&other.origin_server_ts) {
                Ordering::Equal => self.event_id.cmp(&other.event_id),
                ord => ord,
            },
            ord => ord,
        }
    }
}

impl PartialOrd for LeanEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Eq, PartialEq)]
struct SortPriority<'a>(&'a LeanEvent);

impl<'a> Ord for SortPriority<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        other.0.cmp(self.0)
    }
}

impl<'a> PartialOrd for SortPriority<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

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

    let mut queue: BinaryHeap<SortPriority> = BinaryHeap::new();
    for (id, &degree) in &in_degree {
        if degree == 0 {
            if let Some(event) = events.get(id) {
                queue.push(SortPriority(event));
            }
        }
    }

    let mut result = Vec::new();
    while let Some(priority) = queue.pop() {
        let event = priority.0;
        result.push(event.event_id.clone());
        if let Some(neighbors) = adjacency.get(&event.event_id) {
            for next_id in neighbors {
                let degree = in_degree.get_mut(next_id).unwrap();
                *degree -= 1;
                if *degree == 0 {
                    queue.push(SortPriority(events.get(next_id).unwrap()));
                }
            }
        }
    }
    result
}

pub fn resolve_lean(
    unconflicted_state: BTreeMap<(String, String), String>,
    conflicted_events: HashMap<String, LeanEvent>,
) -> BTreeMap<(String, String), String> {
    let resolved = unconflicted_state;
    let _sorted_ids = lean_kahn_sort(&conflicted_events);
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
    fn test_tie_breaking_order() {
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
        assert!(high_power < low_power);
    }

    #[test]
    fn test_kahn_determinism() {
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
        assert_eq!(sorted, vec!["1", "2", "3"]);
    }

    #[test]
    fn test_complex_dag_sort() {
        // Diamond shape DAG
        //     1
        //    / \
        //   2   3
        //    \ /
        //     4
        let mut events = HashMap::new();
        events.insert(
            "1".into(),
            LeanEvent {
                event_id: "1".into(),
                power_level: 100,
                origin_server_ts: 10,
                prev_events: vec![],
            },
        );
        events.insert(
            "2".into(),
            LeanEvent {
                event_id: "2".into(),
                power_level: 50,
                origin_server_ts: 20,
                prev_events: vec!["1".into()],
            },
        );
        events.insert(
            "3".into(),
            LeanEvent {
                event_id: "3".into(),
                power_level: 50,
                origin_server_ts: 15,
                prev_events: vec!["1".into()],
            },
        );
        events.insert(
            "4".into(),
            LeanEvent {
                event_id: "4".into(),
                power_level: 10,
                origin_server_ts: 30,
                prev_events: vec!["2".into(), "3".into()],
            },
        );

        let sorted = lean_kahn_sort(&events);

        // Sorting Logic:
        // 1. Event '1' is the root (no dependencies).
        // 2. Events '2' and '3' both depend on '1'.
        // 3. Event '3' has an earlier timestamp (15) than '2' (20).
        // 4. Matrix spec mandates that for equal power levels, the earlier event takes precedence.
        // Expected Order: 1 -> 3 -> 2 -> 4
        assert_eq!(sorted, vec!["1", "3", "2", "4"]);
    }

    #[test]
    fn test_resolve_lean_with_conflicts() {
        let unconflicted = BTreeMap::new();

        let mut conflicted = HashMap::new();
        // Event A: Sets name to "Alpha", PL 100, TS 100
        conflicted.insert(
            "$A".into(),
            LeanEvent {
                event_id: "$A".into(),
                power_level: 100,
                origin_server_ts: 100,
                prev_events: vec![],
            },
        );
        // Event B: Sets name to "Beta", PL 50, TS 50
        conflicted.insert(
            "$B".into(),
            LeanEvent {
                event_id: "$B".into(),
                power_level: 50,
                origin_server_ts: 50,
                prev_events: vec![],
            },
        );

        // Although B is earlier, A has higher power level.
        let sorted = lean_kahn_sort(&conflicted);
        assert_eq!(sorted, vec!["$A", "$B"]);

        let resolved = resolve_lean(unconflicted, conflicted);
        assert!(resolved.is_empty()); // resolve_lean currently doesn't apply transitions
    }
}
