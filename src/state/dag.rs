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

//! State DAG primitives for MSC4242 (State Res V2.2).
//!
//! In rooms implementing [MSC4242](https://github.com/matrix-org/matrix-spec-proposals/pull/4242),
//! state transitions form an explicit **State DAG** via the `prev_state_events` field.
//!
//! This module provides the pure library-side primitives for:
//!
//! 1. **Traversal & Completeness**: Walking `prev_state_events` backwards, verifying that all
//!    paths terminate at `m.room.create`, and discovering missing frontier gaps.
//! 2. **Deterministic Missing Events Ordering**: Sorting missing state events by `(min_hops, event_id)`
//!    for `/get_missing_events` requests.
//! 3. **Validation**: Enforcing MSC4242 validation rules (20-event fanout, non-state rejection,
//!    foreign-room checks, rejected-event cascading, create event invariants).
//! 4. **State-from-DAG Computation**: Resolving room state at any point in the State DAG.
//! 5. **Auth Events Derivation**: Calculating the authoritative `auth_events` from the resolved
//!    state prior to an event.

use crate::auth::{auth_types_for_event_like, AuthError, StateKeyDyn};
use crate::basespec::event_types::{EventType, MAX_PREV_STATE_EVENTS, M_ROOM_CREATE};
use crate::basespec::rezzy_types::{EventContent, EventId, LeanEvent, StateKey, StateResVersion};
use crate::state::at::{resolve_merge_fast_path, LocalAuthCache, SharedState};
use crate::{DenseIndex, FastMap, FastSet, HashMap};
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

/// Status of a State DAG traversal starting from one or more events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateDagCompleteness<Id> {
    /// The state DAG is fully connected back to `m.room.create` along all paths.
    Complete {
        /// The discovered root `m.room.create` event ID.
        create_event_id: Id,
        /// Total count of unique state events in the reachable closure.
        state_event_count: usize,
    },
    /// The state DAG has missing events or disconnected roots preventing a complete path to `m.room.create`.
    Incomplete {
        /// Event IDs that are referenced in `prev_state_events` but missing from the local store/map.
        missing_event_ids: Vec<Id>,
        /// Non-create event IDs present in the store that have empty `prev_state_events` (disconnected root).
        disconnected_event_ids: Vec<Id>,
        /// Discovered reachable event IDs before hitting gaps.
        reachable_event_ids: Vec<Id>,
    },
}

/// Traversal options for State DAG queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateDagWalkOptions {
    /// Maximum number of events to visit before halting (defense-in-depth against runaway graphs).
    pub max_steps: Option<usize>,
    /// Whether to stop early as soon as the first missing gap is encountered.
    pub stop_on_first_missing: bool,
}

impl Default for StateDagWalkOptions {
    fn default() -> Self {
        Self {
            max_steps: Some(10_000),
            stop_on_first_missing: false,
        }
    }
}

/// Validation error for MSC4242 State DAG rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateDagValidationError<Id = String> {
    /// `prev_state_events` exceeds the maximum allowed fanout limit (20).
    FanoutExceeded { count: usize, limit: usize },
    /// `m.room.create` has `prev_state_events`, which is forbidden.
    CreateWithPrevStateEvents,
    /// A non-create event in an MSC4242 room has empty `prev_state_events`.
    NonCreateWithoutPrevStateEvents { event_id: Id },
    /// `prev_state_events` contains an event that is not a state event (missing `state_key`).
    ReferencedNonStateEvent {
        citing_event: Id,
        referenced_event: Id,
    },
    /// `prev_state_events` references an event belonging to a different room.
    ReferencedForeignRoom {
        citing_event: Id,
        referenced_event: Id,
        expected_room: String,
        actual_room: Option<String>,
    },
    /// `prev_state_events` references an event that was previously rejected.
    ReferencedRejectedEvent {
        citing_event: Id,
        referenced_event: Id,
    },
    /// An event referenced in `prev_state_events` is missing from the provided event context.
    MissingReferencedEvent { citing_event: Id, missing_id: Id },
}

impl<Id: fmt::Display> fmt::Display for StateDagValidationError<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FanoutExceeded { count, limit } => {
                write!(f, "prev_state_events count {count} exceeds limit {limit}")
            }
            Self::CreateWithPrevStateEvents => {
                write!(f, "m.room.create must not have prev_state_events")
            }
            Self::NonCreateWithoutPrevStateEvents { event_id } => {
                write!(
                    f,
                    "non-create event {event_id} in MSC4242 room must have prev_state_events"
                )
            }
            Self::ReferencedNonStateEvent {
                citing_event,
                referenced_event,
            } => {
                write!(
                    f,
                    "event {citing_event} references non-state event {referenced_event} in prev_state_events"
                )
            }
            Self::ReferencedForeignRoom {
                citing_event,
                referenced_event,
                expected_room,
                actual_room,
            } => match actual_room {
                Some(actual) => write!(
                    f,
                    "event {citing_event} (room {expected_room}) references event {referenced_event} from different room {actual}"
                ),
                None => write!(
                    f,
                    "event {citing_event} (room {expected_room}) references event {referenced_event} without room_id"
                ),
            },
            Self::ReferencedRejectedEvent {
                citing_event,
                referenced_event,
            } => {
                write!(
                    f,
                    "event {citing_event} references rejected event {referenced_event} in prev_state_events"
                )
            }
            Self::MissingReferencedEvent {
                citing_event,
                missing_id,
            } => {
                write!(
                    f,
                    "event {citing_event} references missing event {missing_id} in prev_state_events"
                )
            }
        }
    }
}

/// Error during State DAG computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateDagError<Id = String> {
    /// Validation of `prev_state_events` failed.
    Validation(StateDagValidationError<Id>),
    /// State DAG is incomplete / missing required ancestor events.
    IncompleteDag { missing_event_ids: Vec<Id> },
    /// Cycle detected in `prev_state_events` graph.
    CycleDetected,
}

impl<Id: fmt::Display> fmt::Display for StateDagError<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(v) => write!(f, "state DAG validation error: {v}"),
            Self::IncompleteDag { missing_event_ids } => {
                write!(
                    f,
                    "state DAG is incomplete; missing {} ancestor events",
                    missing_event_ids.len()
                )
            }
            Self::CycleDetected => write!(f, "cycle detected in state DAG"),
        }
    }
}

/// Validates MSC4242-specific constraints on `event.prev_state_events`:
///
/// 1. Fanout limit: `event.prev_state_events.len() <= 20`.
/// 2. `m.room.create` MUST NOT have `prev_state_events`.
/// 3. All referenced events in `prev_state_events` MUST be state events (`state_key.is_some()`).
/// 4. All referenced events MUST belong to the same room (when `room_id` is populated).
/// 5. All referenced events MUST NOT be rejected (`rejected == false`).
///
/// # Errors
/// Returns [`StateDagValidationError`] if any constraint is violated.
pub fn validate_msc4242_prev_state_events<Id, C, S, K>(
    event: &LeanEvent<Id, C, K>,
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
) -> Result<(), StateDagValidationError<Id>>
where
    Id: EventId,
    C: EventContent,
    K: StateKey,
    S: core::hash::BuildHasher,
{
    if event.event_type == M_ROOM_CREATE {
        if !event.prev_state_events.is_empty() {
            return Err(StateDagValidationError::CreateWithPrevStateEvents);
        }
        return Ok(());
    }

    if event.prev_state_events.is_empty() {
        return Err(StateDagValidationError::NonCreateWithoutPrevStateEvents {
            event_id: event.event_id.clone(),
        });
    }

    if event.prev_state_events.len() > MAX_PREV_STATE_EVENTS {
        return Err(StateDagValidationError::FanoutExceeded {
            count: event.prev_state_events.len(),
            limit: MAX_PREV_STATE_EVENTS,
        });
    }

    for pse_id in &event.prev_state_events {
        let Some(parent) = events_map.get(pse_id) else {
            return Err(StateDagValidationError::MissingReferencedEvent {
                citing_event: event.event_id.clone(),
                missing_id: pse_id.clone(),
            });
        };

        if parent.state_key.is_none() {
            return Err(StateDagValidationError::ReferencedNonStateEvent {
                citing_event: event.event_id.clone(),
                referenced_event: pse_id.clone(),
            });
        }

        if parent.rejected {
            return Err(StateDagValidationError::ReferencedRejectedEvent {
                citing_event: event.event_id.clone(),
                referenced_event: pse_id.clone(),
            });
        }

        if let Some(expected_room) = &event.room_id {
            match &parent.room_id {
                Some(parent_room) if parent_room == expected_room => {}
                Some(parent_room) => {
                    return Err(StateDagValidationError::ReferencedForeignRoom {
                        citing_event: event.event_id.clone(),
                        referenced_event: pse_id.clone(),
                        expected_room: expected_room.as_ref().to_string(),
                        actual_room: Some(parent_room.as_ref().to_string()),
                    });
                }
                None => {
                    return Err(StateDagValidationError::ReferencedForeignRoom {
                        citing_event: event.event_id.clone(),
                        referenced_event: pse_id.clone(),
                        expected_room: expected_room.as_ref().to_string(),
                        actual_room: None,
                    });
                }
            }
        }
    }

    Ok(())
}

/// Walks the State DAG backwards via `prev_state_events` starting from `start_events`.
///
/// Verifies that all paths terminate at `m.room.create`. If any path hits an unknown
/// event ID or non-create leaf, reports the missing events so the host homeserver
/// can fetch them (e.g. via `/get_missing_events?state_dag=true`).
#[must_use]
pub fn walk_state_dag<Id, C, S, K>(
    start_events: &[&Id],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    options: StateDagWalkOptions,
) -> StateDagCompleteness<Id>
where
    Id: EventId,
    C: EventContent,
    K: StateKey,
    S: core::hash::BuildHasher,
{
    let mut visited: FastSet<Id> = FastSet::default();
    let mut reachable: Vec<Id> = Vec::new();
    let mut missing_set: FastSet<Id> = FastSet::default();
    let mut missing: Vec<Id> = Vec::new();
    let mut disconnected_set: FastSet<Id> = FastSet::default();
    let mut disconnected: Vec<Id> = Vec::new();
    let mut queue: VecDeque<Id> = start_events.iter().map(|id| (*id).clone()).collect();
    let mut create_event_id: Option<Id> = None;
    let mut steps: usize = 0;

    while let Some(current_id) = queue.pop_front() {
        if visited.contains(&current_id) {
            continue;
        }

        let Some(ev) = events_map.get(&current_id) else {
            if missing_set.insert(current_id.clone()) {
                missing.push(current_id);
            }
            if options.stop_on_first_missing {
                return StateDagCompleteness::Incomplete {
                    missing_event_ids: missing,
                    disconnected_event_ids: disconnected,
                    reachable_event_ids: reachable,
                };
            }
            continue;
        };

        visited.insert(current_id.clone());
        reachable.push(current_id);
        steps = steps.saturating_add(1);

        if ev.event_type == M_ROOM_CREATE {
            if create_event_id.is_none() {
                create_event_id = Some(ev.event_id.clone());
            }
            continue;
        }

        if ev.prev_state_events.is_empty() {
            // Non-create event with no prev_state_events is disconnected from create.
            if disconnected_set.insert(ev.event_id.clone()) {
                disconnected.push(ev.event_id.clone());
            }
            if options.stop_on_first_missing {
                return StateDagCompleteness::Incomplete {
                    missing_event_ids: missing,
                    disconnected_event_ids: disconnected,
                    reachable_event_ids: reachable,
                };
            }
            continue;
        }

        for pe in &ev.prev_state_events {
            if !visited.contains(pe) {
                queue.push_back(pe.clone());
            }
        }

        if let Some(max) = options.max_steps {
            if steps >= max {
                break;
            }
        }
    }

    if missing.is_empty() && disconnected.is_empty() {
        if let Some(create_id) = create_event_id {
            return StateDagCompleteness::Complete {
                create_event_id: create_id,
                state_event_count: reachable.len(),
            };
        }
    }

    StateDagCompleteness::Incomplete {
        missing_event_ids: missing,
        disconnected_event_ids: disconnected,
        reachable_event_ids: reachable,
    }
}

/// Deterministically orders state events for MSC4242 `/get_missing_events` responses.
///
/// MSC4242 §390 Specification:
/// 1. Primary sort: Minimum number of hops away from any of `latest_events` (ascending).
/// 2. Secondary sort: `event_id` in lexicographical ASCII order (A-Z before a-z).
#[must_use]
pub fn order_missing_state_events_deterministic<Id, C, S, K>(
    latest_events: &[&Id],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    limit: usize,
) -> Vec<Id>
where
    Id: EventId,
    C: EventContent,
    K: StateKey,
    S: core::hash::BuildHasher,
{
    if latest_events.is_empty() || limit == 0 {
        return Vec::new();
    }

    let mut min_hops: FastMap<Id, usize> = FastMap::default();
    let mut queue: VecDeque<(Id, usize)> = VecDeque::new();
    let mut visited: FastSet<Id> = FastSet::default();

    for &lid in latest_events {
        if let Some(ev) = events_map.get(lid) {
            for pe in &ev.prev_state_events {
                queue.push_back((pe.clone(), 1));
            }
        }
    }

    while let Some((id, hops)) = queue.pop_front() {
        let entry = min_hops.entry(id.clone()).or_insert(hops);
        if hops < *entry {
            *entry = hops;
        }

        if visited.insert(id.clone()) {
            if let Some(ev) = events_map.get(&id) {
                if ev.event_type != M_ROOM_CREATE {
                    for pe in &ev.prev_state_events {
                        queue.push_back((pe.clone(), hops.saturating_add(1)));
                    }
                }
            }
        }
    }

    let mut ordered: Vec<(Id, usize)> = min_hops.into_iter().collect();
    ordered
        .sort_by(|(id_a, hops_a), (id_b, hops_b)| hops_a.cmp(hops_b).then_with(|| id_a.cmp(id_b)));

    if ordered.len() > limit {
        ordered.truncate(limit);
    }

    ordered.into_iter().map(|(id, _)| id).collect()
}

/// Collects all state DAG ancestors reachable from `targets` via `prev_state_events`.
fn collect_state_dag_ancestor_short_ids_batch<'a, Id, C, S, K>(
    targets: &[&'a Id],
    events_map: &'a HashMap<Id, LeanEvent<Id, C, K>, S>,
) -> Result<DenseIndex<&'a Id, usize>, Vec<Id>>
where
    Id: EventId,
    S: core::hash::BuildHasher,
{
    let mut index_to_id: Vec<&'a Id> = Vec::new();
    let mut seen: FastSet<&'a Id> = FastSet::default();
    let mut queue = Vec::new();
    let mut missing = Vec::new();
    let mut missing_set: FastSet<Id> = FastSet::default();

    for &target in targets {
        if let Some((k, _)) = events_map.get_key_value(target) {
            if seen.insert(k) {
                index_to_id.push(k);
                queue.push(k);
            }
        } else if missing_set.insert((*target).clone()) {
            missing.push((*target).clone());
        }
    }

    let mut head = 0;
    while head < queue.len() {
        let current_id = queue[head];
        head = head.saturating_add(1);
        if let Some(ev) = events_map.get(current_id) {
            for pe in &ev.prev_state_events {
                if let Some((k, _)) = events_map.get_key_value(pe) {
                    if seen.insert(k) {
                        index_to_id.push(k);
                        queue.push(k);
                    }
                } else if missing_set.insert(pe.clone()) {
                    missing.push(pe.clone());
                }
            }
        }
    }

    if missing.is_empty() {
        DenseIndex::try_build(index_to_id).map_err(|_| Vec::new())
    } else {
        Err(missing)
    }
}

/// Topologically sorts state DAG nodes (roots first, extremities last).
fn topological_sort_state_dag_short_ids<'a, Id, C, S, K>(
    index: &DenseIndex<&'a Id, usize>,
    events_map: &'a HashMap<Id, LeanEvent<Id, C, K>, S>,
) -> (Vec<usize>, Vec<usize>)
where
    Id: EventId,
    S: core::hash::BuildHasher,
{
    let n = index.len();
    let mut in_degree = vec![0_usize; n];
    let mut out_degree = vec![0_usize; n];
    let mut reverse_adj: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (node_idx, &id) in index.items().iter().enumerate() {
        if let Some(ev) = events_map.get(id) {
            for pe in &ev.prev_state_events {
                if let Some(pe_idx) = index.index_of(&pe) {
                    in_degree[node_idx] = in_degree[node_idx].saturating_add(1);
                    out_degree[pe_idx] = out_degree[pe_idx].saturating_add(1);
                    reverse_adj[pe_idx].push(node_idx);
                }
            }
        }
    }

    let mut queue = VecDeque::new();
    for (idx, &deg) in in_degree.iter().enumerate() {
        if deg == 0 {
            queue.push_back(idx);
        }
    }

    let mut sorted = Vec::with_capacity(n);
    while let Some(u) = queue.pop_front() {
        sorted.push(u);
        for &v in &reverse_adj[u] {
            in_degree[v] = in_degree[v].saturating_sub(1);
            if in_degree[v] == 0 {
                queue.push_back(v);
            }
        }
    }

    (sorted, out_degree)
}

/// Computes the resolved room state before an event using its `prev_state_events` State DAG.
///
/// - For `m.room.create`: returns an empty state map.
/// - For single `prev_state_event`: returns the state after that event.
/// - For multiple `prev_state_events`: resolves conflicting forks across parents using State Res V2.2.
///
/// # Errors
/// Returns [`StateDagError`] if validation fails, ancestor events are missing, or a cycle is detected.
#[allow(clippy::too_many_lines, clippy::missing_panics_doc)]
pub fn compute_state_before_from_dag<Id, C, S, K>(
    event: &LeanEvent<Id, C, K>,
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    version: StateResVersion,
    empty_key: &K,
) -> Result<SharedState<Id, K>, StateDagError<Id>>
where
    Id: EventId,
    C: EventContent,
    K: StateKey,
    S: core::hash::BuildHasher,
    for<'q> (EventType, K): core::borrow::Borrow<dyn StateKeyDyn + 'q>,
{
    if event.event_type == M_ROOM_CREATE {
        if !event.prev_state_events.is_empty() {
            return Err(StateDagError::Validation(
                StateDagValidationError::CreateWithPrevStateEvents,
            ));
        }
        return Ok(SharedState::new());
    }

    validate_msc4242_prev_state_events(event, events_map).map_err(StateDagError::Validation)?;

    if event.prev_state_events.is_empty() {
        return Err(StateDagError::Validation(
            StateDagValidationError::NonCreateWithoutPrevStateEvents {
                event_id: event.event_id.clone(),
            },
        ));
    }

    let parent_refs: Vec<&Id> = event.prev_state_events.iter().collect();
    let index = collect_state_dag_ancestor_short_ids_batch(&parent_refs, events_map).map_err(
        |missing| StateDagError::IncompleteDag {
            missing_event_ids: missing,
        },
    )?;

    let (sorted_ancestors, mut out_degree) =
        topological_sort_state_dag_short_ids(&index, events_map);

    if sorted_ancestors.len() != index.len() {
        return Err(StateDagError::CycleDetected);
    }

    // Allocate an extra out_degree ref for parents of target event
    for p_id in &event.prev_state_events {
        if let Some(idx) = index.index_of(&p_id) {
            out_degree[idx] = out_degree[idx].saturating_add(1);
        }
    }

    let mut global_auth_cache = LocalAuthCache::new(version);
    let mut mainline_cache: FastMap<Id, Option<Id>> = FastMap::default();

    let mut state_after_map: Vec<Option<SharedState<Id, K>>> =
        core::iter::repeat_with(|| None).take(index.len()).collect();

    for idx in sorted_ancestors {
        let id_val = index.items()[idx];
        let Some(ev) = events_map.get(id_val) else {
            continue;
        };

        let mut prev_states = Vec::with_capacity(ev.prev_state_events.len());
        for pe in &ev.prev_state_events {
            let Some(pe_idx) = index.index_of(&pe) else {
                continue;
            };
            if out_degree[pe_idx] == 0 {
                continue;
            }
            out_degree[pe_idx] = out_degree[pe_idx].saturating_sub(1);
            if out_degree[pe_idx] == 0 {
                if let Some(pe_state) = state_after_map[pe_idx].take() {
                    prev_states.push(pe_state);
                }
            } else if let Some(ref pe_state) = state_after_map[pe_idx] {
                prev_states.push(pe_state.clone());
            }
        }

        let mut state_before: SharedState<Id, K> = if prev_states.is_empty() {
            SharedState::new()
        } else if prev_states.len() == 1 {
            // `prev_states` only ever holds `Some` parent states, so the sole
            // element is guaranteed present (index 0 is valid for len == 1).
            prev_states.remove(0)
        } else {
            resolve_merge_fast_path(
                &prev_states,
                events_map,
                &mut global_auth_cache,
                &mut mainline_cache,
                version,
                empty_key,
            )
        };

        if ev.state_key.is_some() && !ev.rejected {
            state_before.insert(
                (
                    EventType::from(ev.event_type.as_str()),
                    ev.state_key.clone().unwrap_or_else(|| empty_key.clone()),
                ),
                ev.event_id.clone(),
            );
        }

        if out_degree[idx] > 0 {
            state_after_map[idx] = Some(state_before);
        }
    }

    let mut parent_states = Vec::with_capacity(event.prev_state_events.len());
    for pe in &event.prev_state_events {
        let Some(pe_idx) = index.index_of(&pe) else {
            return Err(StateDagError::IncompleteDag {
                missing_event_ids: vec![pe.clone()],
            });
        };
        if let Some(st) = &state_after_map[pe_idx] {
            parent_states.push(st.clone());
        }
    }

    if parent_states.is_empty() {
        Ok(SharedState::new())
    } else if parent_states.len() == 1 {
        // `parent_states` only ever holds `Some` states (see the loop above), so
        // the sole element is guaranteed present (index 0 is valid for len == 1).
        Ok(parent_states.remove(0))
    } else {
        Ok(resolve_merge_fast_path(
            &parent_states,
            events_map,
            &mut global_auth_cache,
            &mut mainline_cache,
            version,
            empty_key,
        ))
    }
}

/// Computes the resolved room state *after* an event using State DAG semantics.
///
/// If `event` is a state event (`state_key.is_some()`) and is not rejected,
/// inserts `(event.event_type, event.state_key) -> event.event_id` into the state.
///
/// # Errors
/// Returns [`StateDagError`] if state resolution fails.
pub fn compute_state_after_from_dag<Id, C, S, K>(
    event: &LeanEvent<Id, C, K>,
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    version: StateResVersion,
    empty_key: &K,
) -> Result<SharedState<Id, K>, StateDagError<Id>>
where
    Id: EventId,
    C: EventContent,
    K: StateKey,
    S: core::hash::BuildHasher,
    for<'q> (EventType, K): core::borrow::Borrow<dyn StateKeyDyn + 'q>,
{
    let mut state = compute_state_before_from_dag(event, events_map, version, empty_key)?;

    if event.state_key.is_some() && !event.rejected {
        state.insert(
            (
                EventType::from(event.event_type.as_str()),
                event.state_key.clone().unwrap_or_else(|| empty_key.clone()),
            ),
            event.event_id.clone(),
        );
    }

    Ok(state)
}

/// Derives the required `auth_events` for an event from the room state computed via its State DAG.
///
/// Looks up the required authorization tuples (`auth_types_for_event_like`) in `state_before`.
///
/// # Errors
/// Returns [`AuthError`] if any calculated auth event was itself rejected (MSC4242 Rule 4.3).
pub fn derive_auth_events_from_state_dag<Id, C, S, K>(
    event: &LeanEvent<Id, C, K>,
    state_before: &SharedState<Id, K>,
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    room_version: &str,
) -> Result<Vec<Id>, AuthError<Id>>
where
    Id: EventId,
    C: EventContent,
    K: StateKey,
    S: core::hash::BuildHasher,
    for<'q> (EventType, K): core::borrow::Borrow<dyn StateKeyDyn + 'q>,
{
    if event.event_type == M_ROOM_CREATE {
        return Ok(Vec::new());
    }

    let auth_tuples = auth_types_for_event_like(event, StateResVersion::V2_2, room_version);

    let mut derived_auth = Vec::with_capacity(auth_tuples.len());

    for (req_type, req_sk) in auth_tuples {
        let query: &dyn StateKeyDyn = &(req_type, req_sk);
        if let Some(auth_id) = state_before.get(query) {
            // MSC4242 Rule 4.3: Reject if auth event is rejected
            if let Some(auth_ev) = events_map.get(auth_id) {
                if auth_ev.rejected {
                    return Err(AuthError::RejectedAuthEvent {
                        event_id: event.event_id.clone(),
                        auth_event_id: auth_id.clone(),
                    });
                }
            }
            derived_auth.push(auth_id.clone());
        }
    }

    Ok(derived_auth)
}
