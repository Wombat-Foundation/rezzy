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

//! DAG health metrics, fork branch detection, and live frontier width guards
//! (`F-04-01`, `F-07-04`).

use alloc::collections::{BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::hash::BuildHasher;

use crate::basespec::rezzy_types::{DagNode, EventId, EventLike};
use crate::{FastMap, FastSet, HashMap};

/// Default maximum live frontier width permitted before triggering a hydra-DAG
/// resource guard (`F-04-01`).
pub const DEFAULT_MAX_FRONTIER_WIDTH: usize = 100;

/// Error returned by [`check_frontier_width`] when a DAG's peak live citation
/// frontier exceeds the caller's configured threshold (`F-04-01`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontierWidthError {
    /// Peak concurrent live frontier width observed across topological order.
    pub measured_width: usize,
    /// Maximum allowed frontier width configured by the caller.
    pub max_allowed_width: usize,
}

impl fmt::Display for FrontierWidthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DAG live frontier width {} exceeds maximum allowed width {}",
            self.measured_width, self.max_allowed_width
        )
    }
}

/// Summary health metrics for a Matrix room event DAG (`F-07-04`, `F-04-01`).
#[derive(Debug, Clone, PartialEq)]
pub struct DagHealth<Id = String> {
    /// Total number of events in the inspected DAG map.
    pub total_events: usize,
    /// Events not referenced as `prev_events` by any other event in the map.
    pub forward_extremities: Vec<Id>,
    /// Missing parent event IDs referenced in `prev_events` but absent from the map.
    pub backward_extremities: Vec<Id>,
    /// Maximum number of concurrent active branches / live frontier width (`F-04-01`).
    pub max_fork_width: usize,
    /// Mean `depth` across all events in the map.
    pub avg_depth: f64,
    /// Maximum `depth` across all events in the map.
    pub max_depth: u64,
    /// Non-root events whose `prev_events` are all absent from the map.
    pub orphaned_events: usize,
}

/// Descriptor for an unmerged fork branch starting from a forward extremity (`F-07-04`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkBranch<Id = String> {
    /// Forward extremity (branch head) event ID.
    pub head: Id,
    /// Nearest common ancestor / fork point shared with other branches, if found.
    pub fork_point: Option<Id>,
    /// Number of events unique to this branch since `fork_point`.
    pub length: usize,
    /// Number of state events unique to this branch.
    pub state_events: usize,
    /// Number of timeline (non-state) events unique to this branch.
    pub timeline_events: usize,
}

fn peak_live_frontier_width<Id, E, S>(events: &HashMap<Id, E, S>) -> usize
where
    Id: EventId,
    E: DagNode<Id = Id>,
    S: BuildHasher,
{
    if events.is_empty() {
        return 0;
    }

    let mut remaining_children: FastMap<&Id, usize> = FastMap::default();
    for id in events.keys() {
        remaining_children.insert(id, 0);
    }

    for ev in events.values() {
        let mut seen_parents: FastSet<&Id> = FastSet::default();
        for parent_id in ev.prev_events() {
            if seen_parents.insert(parent_id) {
                if let Some(count) = remaining_children.get_mut(parent_id) {
                    *count = count.saturating_add(1);
                }
            }
        }
    }

    let mut order: Vec<&E> = events.values().collect();
    order.sort_by(|a, b| {
        a.depth()
            .cmp(&b.depth())
            .then_with(|| a.event_id().cmp(b.event_id()))
    });

    let mut live_parents = 0_usize;
    let mut active_terminal_heads = 0_usize;
    let mut peak_width = 0_usize;

    for ev in order {
        let mut seen_parents: FastSet<&Id> = FastSet::default();
        for parent_id in ev.prev_events() {
            if seen_parents.insert(parent_id) {
                if let Some(rem) = remaining_children.get_mut(parent_id) {
                    if *rem > 0 {
                        *rem = rem.saturating_sub(1);
                        if *rem == 0 {
                            live_parents = live_parents.saturating_sub(1);
                        }
                    }
                }
            }
        }

        let own_children = remaining_children
            .get(ev.event_id())
            .copied()
            .unwrap_or(0);
        if own_children > 0 {
            live_parents = live_parents.saturating_add(1);
        } else {
            active_terminal_heads = active_terminal_heads.saturating_add(1);
        }

        let current_width = live_parents.saturating_add(active_terminal_heads);
        if current_width > peak_width {
            peak_width = current_width;
        }
    }

    peak_width
}

/// Computes peak live citation frontier width across topological order and
/// rejects DAGs that exceed `max_width` (`F-04-01`).
///
/// # Errors
///
/// Returns [`FrontierWidthError`] if the measured peak live frontier width
/// exceeds `max_width`.
pub fn check_frontier_width<Id, E, S>(
    events: &HashMap<Id, E, S>,
    max_width: usize,
) -> Result<usize, FrontierWidthError>
where
    Id: EventId,
    E: DagNode<Id = Id>,
    S: BuildHasher,
{
    let measured = peak_live_frontier_width(events);
    if measured > max_width {
        return Err(FrontierWidthError {
            measured_width: measured,
            max_allowed_width: max_width,
        });
    }
    Ok(measured)
}

/// Computes structural DAG health metrics including forward/backward extremities,
/// orphan counts, depth statistics, and peak fork/frontier width (`F-07-04`, `F-04-01`).
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn compute_dag_health<Id, E, S>(events: &HashMap<Id, E, S>) -> DagHealth<Id>
where
    Id: EventId,
    E: EventLike<Id = Id>,
    S: BuildHasher,
{
    let total_events = events.len();
    if total_events == 0 {
        return DagHealth {
            total_events: 0,
            forward_extremities: Vec::new(),
            backward_extremities: Vec::new(),
            max_fork_width: 0,
            avg_depth: 0.0,
            max_depth: 0,
            orphaned_events: 0,
        };
    }

    let mut referenced_prev: FastSet<&Id> = FastSet::default();
    let mut backward_set: BTreeSet<Id> = BTreeSet::new();
    let mut depth_sum = 0_u128;
    let mut max_depth = 0_u64;
    let mut orphaned_events = 0_usize;

    for ev in events.values() {
        let d = ev.depth();
        depth_sum = depth_sum.saturating_add(u128::from(d));
        if d > max_depth {
            max_depth = d;
        }

        let prev = ev.prev_events();
        if !prev.is_empty() {
            let mut any_present = false;
            for pid in prev {
                if events.contains_key(pid) {
                    any_present = true;
                    referenced_prev.insert(pid);
                } else {
                    backward_set.insert(pid.clone());
                }
            }
            if !any_present {
                orphaned_events = orphaned_events.saturating_add(1);
            }
        }
    }

    let mut forward_extremities: Vec<Id> = events
        .keys()
        .filter(|id| !referenced_prev.contains(id))
        .cloned()
        .collect();
    forward_extremities.sort();

    let backward_extremities: Vec<Id> = backward_set.into_iter().collect();
    let max_fork_width = peak_live_frontier_width(events).max(forward_extremities.len());
    let avg_depth = (depth_sum as f64) / (total_events as f64);

    DagHealth {
        total_events,
        forward_extremities,
        backward_extremities,
        max_fork_width,
        avg_depth,
        max_depth,
        orphaned_events,
    }
}

/// Detects unmerged fork branches when the DAG has multiple forward extremities (`F-07-04`).
///
/// If the DAG has 0 or 1 forward extremities, returns an empty vector (no fork).
/// When 2 or more forward extremities exist, returns one [`ForkBranch`] per
/// forward extremity (sorted by `head` ID), recording the events exclusive to
/// that branch and the deepest ancestor shared with another branch (`fork_point`).
#[must_use]
pub fn detect_forks<Id, E, S>(events: &HashMap<Id, E, S>) -> Vec<ForkBranch<Id>>
where
    Id: EventId,
    E: EventLike<Id = Id>,
    S: BuildHasher,
{
    let mut referenced_prev: FastSet<&Id> = FastSet::default();
    for ev in events.values() {
        for pid in ev.prev_events() {
            if events.contains_key(pid) {
                referenced_prev.insert(pid);
            }
        }
    }

    let mut heads: Vec<Id> = events
        .keys()
        .filter(|id| !referenced_prev.contains(id))
        .cloned()
        .collect();
    heads.sort();

    if heads.len() <= 1 {
        return Vec::new();
    }

    // For each head, collect its ancestor closure in `events` and count how many
    // heads reach each event.
    let mut reach_counts: FastMap<&Id, usize> = FastMap::default();
    let mut per_head_ancestors: Vec<Vec<&Id>> = Vec::with_capacity(heads.len());

    for head in &heads {
        let mut visited: FastSet<&Id> = FastSet::default();
        let mut queue: VecDeque<&Id> = VecDeque::new();
        if let Some((k, _)) = events.get_key_value(head) {
            visited.insert(k);
            queue.push_back(k);
        }
        while let Some(cur) = queue.pop_front() {
            if let Some(ev) = events.get(cur) {
                for pid in ev.prev_events() {
                    if let Some((pk, _)) = events.get_key_value(pid) {
                        if visited.insert(pk) {
                            queue.push_back(pk);
                        }
                    }
                }
            }
        }
        let anc: Vec<&Id> = visited.into_iter().collect();
        for &id in &anc {
            let entry = reach_counts.entry(id).or_insert(0);
            *entry = entry.saturating_add(1);
        }
        per_head_ancestors.push(anc);
    }

    let mut branches = Vec::with_capacity(heads.len());
    for (head, anc) in heads.into_iter().zip(per_head_ancestors) {
        let mut length = 0_usize;
        let mut state_events = 0_usize;
        let mut timeline_events = 0_usize;
        let mut fork_point: Option<(&Id, u64)> = None;

        for id in anc {
            let count = reach_counts.get(id).copied().unwrap_or(0);
            if let Some(ev) = events.get(id) {
                if count <= 1 {
                    length = length.saturating_add(1);
                    if ev.state_key().is_some() {
                        state_events = state_events.saturating_add(1);
                    } else {
                        timeline_events = timeline_events.saturating_add(1);
                    }
                } else {
                    let d = ev.depth();
                    let replace = match fork_point {
                        None => true,
                        Some((best_id, best_depth)) => {
                            d > best_depth || (d == best_depth && id < best_id)
                        }
                    };
                    if replace {
                        fork_point = Some((id, d));
                    }
                }
            }
        }

        branches.push(ForkBranch {
            head,
            fork_point: fork_point.map(|(id, _)| id.clone()),
            length,
            state_events,
            timeline_events,
        });
    }

    branches
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::basespec::event_types::{M_ROOM_CREATE, M_ROOM_MEMBER, M_ROOM_MESSAGE};
    use crate::basespec::rezzy_types::LeanEvent;
    use crate::json;
    use alloc::vec;

    fn make_ev(
        id: &str,
        event_type: &str,
        state_key: Option<&str>,
        prev: Vec<&str>,
        depth: u64,
    ) -> LeanEvent {
        LeanEvent {
            event_id: String::from(id),
            event_type: String::from(event_type),
            state_key: state_key.map(String::from),
            sender: String::from("@alice:example.org"),
            content: json!({}),
            prev_events: prev.into_iter().map(String::from).collect(),
            auth_events: vec![],
            depth,
            origin_server_ts: depth.saturating_mul(1000),
            ..LeanEvent::default()
        }
    }

    #[test]
    fn compute_dag_health_and_detect_forks_on_two_branch_dag() {
        let mut map: HashMap<String, LeanEvent> = HashMap::default();
        map.insert(
            String::from("$create"),
            make_ev("$create", M_ROOM_CREATE, Some(""), vec![], 1),
        );
        map.insert(
            String::from("$b1_state"),
            make_ev(
                "$b1_state",
                M_ROOM_MEMBER,
                Some("@alice:example.org"),
                vec!["$create"],
                2,
            ),
        );
        map.insert(
            String::from("$b1_msg"),
            make_ev("$b1_msg", M_ROOM_MESSAGE, None, vec!["$b1_state"], 3),
        );
        map.insert(
            String::from("$b2_msg"),
            make_ev("$b2_msg", M_ROOM_MESSAGE, None, vec!["$create"], 2),
        );
        map.insert(
            String::from("$orphan"),
            make_ev("$orphan", M_ROOM_MESSAGE, None, vec!["$missing_parent"], 5),
        );

        let health = compute_dag_health(&map);
        assert_eq!(health.total_events, 5);
        assert_eq!(
            health.forward_extremities,
            vec![
                String::from("$b1_msg"),
                String::from("$b2_msg"),
                String::from("$orphan")
            ]
        );
        assert_eq!(
            health.backward_extremities,
            vec![String::from("$missing_parent")]
        );
        assert_eq!(health.max_depth, 5);
        assert_eq!(health.orphaned_events, 1);
        assert!(health.max_fork_width >= 3);

        let forks = detect_forks(&map);
        assert_eq!(forks.len(), 3);
        let b1 = forks.iter().find(|f| f.head == "$b1_msg").unwrap();
        assert_eq!(b1.fork_point.as_deref(), Some("$create"));
        assert_eq!(b1.length, 2);
        assert_eq!(b1.state_events, 1);
        assert_eq!(b1.timeline_events, 1);
    }

    #[test]
    fn check_frontier_width_detects_hydra_fork_exceeding_threshold() {
        let mut map: HashMap<String, LeanEvent> = HashMap::default();
        map.insert(
            String::from("$root"),
            make_ev("$root", M_ROOM_CREATE, Some(""), vec![], 1),
        );
        // Create a 12-wide hydra diamond that merges back into a single head `$merge`
        let mut branch_ids = Vec::new();
        for i in 0..12_u64 {
            let id = alloc::format!("$branch_{i:02}");
            map.insert(
                id.clone(),
                make_ev(&id, M_ROOM_MESSAGE, None, vec!["$root"], 2),
            );
            branch_ids.push(id);
        }
        let branch_refs: Vec<&str> = branch_ids.iter().map(String::as_str).collect();
        map.insert(
            String::from("$merge"),
            make_ev("$merge", M_ROOM_MESSAGE, None, branch_refs, 3),
        );

        assert_eq!(
            check_frontier_width(&map, 8),
            Err(FrontierWidthError {
                measured_width: 12,
                max_allowed_width: 8,
            })
        );
        assert_eq!(check_frontier_width(&map, 12), Ok(12));
    }
}
