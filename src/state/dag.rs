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
use crate::basespec::rezzy_types::{
    DagNode, EventContent, EventId, LeanEvent, StateKey, StateResVersion,
};
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
    /// `m.room.create` is missing the required `state_key` field.
    CreateWithMissingStateKey,
    /// `m.room.create` has a non-empty `state_key` value.
    CreateWithNonEmptyStateKey { state_key: String },
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
    /// `compute_state_before_from_dag` was called with a pre-V2.2 room
    /// version.  State-DAG traversal requires `prev_state_events` edges
    /// that only exist in room versions 2.2 and later; earlier versions
    /// use auth-chain state resolution and should not call this function.
    UnsupportedVersionForDag { version: String },
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
            Self::CreateWithMissingStateKey => {
                write!(f, "m.room.create must have a state_key field")
            }
            Self::CreateWithNonEmptyStateKey { state_key } => {
                write!(
                    f,
                    "m.room.create must have an empty state_key, got {state_key}"
                )
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
            Self::UnsupportedVersionForDag { version } => {
                write!(
                    f,
                    "State-DAG traversal requires room version 2.2 or later, got {version}"
                )
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod validation_error_display_tests {
    use super::StateDagValidationError;
    use alloc::format;

    #[test]
    fn formats_every_state_dag_validation_error() {
        let cases = [
            (
                StateDagValidationError::FanoutExceeded { count: 21, limit: 20 },
                "prev_state_events count 21 exceeds limit 20",
            ),
            (
                StateDagValidationError::<&str>::CreateWithPrevStateEvents,
                "m.room.create must not have prev_state_events",
            ),
            (
                StateDagValidationError::<&str>::CreateWithMissingStateKey,
                "m.room.create must have a state_key field",
            ),
            (
                StateDagValidationError::CreateWithNonEmptyStateKey { state_key: "not-empty".into() },
                "m.room.create must have an empty state_key, got not-empty",
            ),
            (
                StateDagValidationError::NonCreateWithoutPrevStateEvents { event_id: "$e" },
                "non-create event $e in MSC4242 room must have prev_state_events",
            ),
            (
                StateDagValidationError::ReferencedNonStateEvent {
                    citing_event: "$c",
                    referenced_event: "$r",
                },
                "event $c references non-state event $r in prev_state_events",
            ),
            (
                StateDagValidationError::ReferencedForeignRoom {
                    citing_event: "$c",
                    referenced_event: "$r",
                    expected_room: "!expected:example.org".into(),
                    actual_room: Some("!actual:example.org".into()),
                },
                "event $c (room !expected:example.org) references event $r from different room !actual:example.org",
            ),
            (
                StateDagValidationError::ReferencedForeignRoom {
                    citing_event: "$c",
                    referenced_event: "$r",
                    expected_room: "!expected:example.org".into(),
                    actual_room: None,
                },
                "event $c (room !expected:example.org) references event $r without room_id",
            ),
            (
                StateDagValidationError::ReferencedRejectedEvent {
                    citing_event: "$c",
                    referenced_event: "$r",
                },
                "event $c references rejected event $r in prev_state_events",
            ),
            (
                StateDagValidationError::MissingReferencedEvent {
                    citing_event: "$c",
                    missing_id: "$m",
                },
                "event $c references missing event $m in prev_state_events",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(format!("{error}"), expected);
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
    /// Too many distinct ancestor events to index (exceeds `usize` capacity).
    AncestorIndexOverflow,
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
            Self::AncestorIndexOverflow => {
                write!(f, "too many distinct ancestor events to index")
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod state_dag_error_display_tests {
    use super::{StateDagError, StateDagValidationError};
    use alloc::{format, vec};

    #[test]
    fn formats_every_state_dag_error_variant() {
        let validation =
            StateDagError::<&str>::Validation(StateDagValidationError::CreateWithPrevStateEvents);
        assert_eq!(
            format!("{validation}"),
            "state DAG validation error: m.room.create must not have prev_state_events"
        );
        assert_eq!(
            format!(
                "{}",
                StateDagError::<&str>::IncompleteDag {
                    missing_event_ids: vec!["$a", "$b"]
                }
            ),
            "state DAG is incomplete; missing 2 ancestor events"
        );
        assert_eq!(
            format!("{}", StateDagError::<&str>::CycleDetected),
            "cycle detected in state DAG"
        );
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod state_dag_branch_coverage_tests {
    use super::*;
    use crate::basespec::rezzy_types::RoomId;
    use alloc::{format, string::String};
    use serde_json::Value;

    type TestEvent = LeanEvent<String, Value, String>;
    type TestMap = crate::HashMap<String, TestEvent>;

    fn event(id: &str, state_key: Option<&str>) -> LeanEvent<String, Value, String> {
        LeanEvent {
            event_id: id.into(),
            event_type: "m.room.message".into(),
            state_key: state_key.map(String::from),
            power_level: 0,
            origin_server_ts: 0,
            sender: "@alice:example.org".into(),
            content: Value::Null,
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            depth: 0,
            rejected: false,
            soft_fail: false,
            room_id: None,
        }
    }

    #[test]
    fn validates_foreign_room_without_parent_room_id() {
        let mut citing = event("$c", Some(""));
        citing.room_id = Some(RoomId::new("!room:example.org"));
        citing.auth_events.push("$p".into());
        let parent = event("$p", Some(""));
        let mut events: TestMap = crate::HashMap::default();
        events.insert(parent.event_id.clone(), parent);

        let error = validate_msc4242_prev_state_events(&citing, &events).unwrap_err();
        assert!(matches!(
            error,
            StateDagValidationError::ReferencedForeignRoom {
                actual_room: None,
                ..
            }
        ));
    }

    #[test]
    fn validates_matching_parent_and_rejects_excessive_fanout() {
        let mut citing = event("$c", Some(""));
        citing.room_id = Some(RoomId::new("!room:example.org"));
        citing.auth_events.push("$p".into());
        let mut parent = event("$p", Some(""));
        parent.room_id = citing.room_id.clone();
        let mut events: TestMap = crate::HashMap::default();
        events.insert(parent.event_id.clone(), parent);
        assert!(validate_msc4242_prev_state_events(&citing, &events).is_ok());

        citing.auth_events = (0..=MAX_PREV_STATE_EVENTS)
            .map(|i| format!("$parent{i}"))
            .collect();
        assert!(matches!(
            validate_msc4242_prev_state_events(&citing, &events),
            Err(StateDagValidationError::FanoutExceeded { .. })
        ));
    }

    #[test]
    fn validates_create_event_requires_present_and_empty_state_key() {
        let events: TestMap = crate::HashMap::default();

        // Valid create: empty prev_events, state_key = Some("")
        let mut valid_create = event("$vc", Some(""));
        valid_create.event_type = M_ROOM_CREATE.into();
        assert!(validate_msc4242_prev_state_events(&valid_create, &events).is_ok());

        // Create with missing state_key must be rejected.
        let mut no_sk = event("$no-sk", None);
        no_sk.event_type = M_ROOM_CREATE.into();
        assert!(matches!(
            validate_msc4242_prev_state_events(&no_sk, &events),
            Err(StateDagValidationError::CreateWithMissingStateKey)
        ));

        // Create with non-empty state_key must be rejected.
        let mut non_empty = event("$ne", Some("not-empty"));
        non_empty.event_type = M_ROOM_CREATE.into();
        assert!(matches!(
            validate_msc4242_prev_state_events(&non_empty, &events),
            Err(StateDagValidationError::CreateWithNonEmptyStateKey { .. })
        ));
    }

    #[test]
    fn walk_handles_duplicate_start_and_stop_on_missing() {
        let missing: String = "$missing".into();
        let mut events: TestMap = crate::HashMap::default();
        let mut root = event("$root", Some(""));
        root.auth_events.push(missing.clone());
        events.insert(root.event_id.clone(), root);
        let starts = [&"$root".to_string(), &"$root".to_string()];
        let result = walk_state_dag(
            &starts,
            &events,
            StateDagWalkOptions {
                max_steps: None,
                stop_on_first_missing: true,
            },
            StateResVersion::V2_2,
        );
        assert!(matches!(
            result,
            StateDagCompleteness::Incomplete {
                missing_event_ids,
                ..
            } if missing_event_ids == vec![missing]
        ));
    }

    #[test]
    fn walk_reports_truncation_and_cycles_as_incomplete() {
        let mut root = event("$root", Some(""));
        root.auth_events.push("$missing".into());
        let mut events: TestMap = crate::HashMap::default();
        events.insert(root.event_id.clone(), root);
        let start = "$root".to_string();
        let truncated = walk_state_dag(
            &[&start],
            &events,
            StateDagWalkOptions {
                max_steps: Some(1),
                stop_on_first_missing: false,
            },
            StateResVersion::V2_2,
        );
        assert!(matches!(truncated, StateDagCompleteness::Incomplete { .. }));

        let mut a = event("$a", Some(""));
        a.auth_events.push("$b".into());
        let mut b = event("$b", Some(""));
        b.auth_events.push("$a".into());
        let mut cyclic: TestMap = crate::HashMap::default();
        cyclic.insert(a.event_id.clone(), a);
        cyclic.insert(b.event_id.clone(), b);
        let cycle_start = "$a".to_string();
        assert!(matches!(
            walk_state_dag(
                &[&cycle_start],
                &cyclic,
                StateDagWalkOptions {
                    max_steps: None,
                    stop_on_first_missing: false,
                },
                StateResVersion::V2_2,
            ),
            StateDagCompleteness::Incomplete { .. }
        ));

        let disconnected = event("$disconnected", Some(""));
        let mut disconnected_map: TestMap = crate::HashMap::default();
        disconnected_map.insert(disconnected.event_id.clone(), disconnected);
        assert!(matches!(
            walk_state_dag(
                &[&"$disconnected".to_string()],
                &disconnected_map,
                StateDagWalkOptions {
                    max_steps: None,
                    stop_on_first_missing: true,
                },
                StateResVersion::V2_2,
            ),
            StateDagCompleteness::Incomplete { .. }
        ));

        let mut create = event("$shared-create", None);
        create.event_type = M_ROOM_CREATE.into();
        let mut left = event("$shared-left", Some("left"));
        left.auth_events.push(create.event_id.clone());
        let mut right = event("$shared-right", Some("right"));
        right.auth_events.push(create.event_id.clone());
        let mut tip = event("$shared-tip", Some("tip"));
        tip.auth_events
            .extend([left.event_id.clone(), right.event_id.clone()]);
        let mut shared: TestMap = crate::HashMap::default();
        for value in [create, left, right, tip.clone()] {
            shared.insert(value.event_id.clone(), value);
        }
        assert!(matches!(
            walk_state_dag(
                &[&tip.event_id],
                &shared,
                StateDagWalkOptions::default(),
                StateResVersion::V2_2
            ),
            StateDagCompleteness::Complete {
                state_event_count: 4,
                ..
            }
        ));
    }

    #[test]
    fn ordering_missing_events_ignores_unknown_latest_event() {
        let unknown = "$unknown".to_string();
        let events = crate::HashMap::<String, LeanEvent<String, Value, String>>::default();
        assert_eq!(
            order_missing_state_events_deterministic(&[&unknown], &events, 10),
            Vec::<String>::new()
        );
        assert_eq!(
            order_missing_state_events_deterministic(&[&unknown], &events, 0),
            Vec::<String>::new()
        );

        let mut latest = event("$latest", Some(""));
        latest.auth_events.push("$missing".into());
        let mut events: TestMap = crate::HashMap::default();
        events.insert(latest.event_id.clone(), latest);
        assert_eq!(
            order_missing_state_events_deterministic(&[&"$latest".to_string()], &events, 10),
            vec!["$missing".to_string()]
        );
    }

    #[test]
    fn state_before_rejects_invalid_create_and_non_create_shapes() {
        let empty_key = String::new();
        let mut create = event("$create", Some(""));
        create.event_type = M_ROOM_CREATE.into();
        create.auth_events.push("$parent".into());
        let events = crate::HashMap::<String, LeanEvent<String, Value, String>>::default();
        assert!(matches!(
            compute_state_before_from_dag(&create, &events, StateResVersion::V2_2, &empty_key),
            Err(StateDagError::Validation(
                StateDagValidationError::CreateWithPrevStateEvents
            ))
        ));

        let valid_create = event("$valid-create", Some(""));
        let mut valid_create = valid_create;
        valid_create.event_type = M_ROOM_CREATE.into();
        valid_create.state_key = Some(String::new());
        assert_eq!(
            compute_state_before_from_dag(
                &valid_create,
                &events,
                StateResVersion::V2_2,
                &empty_key
            )
            .unwrap(),
            SharedState::new()
        );

        // Create with missing state_key must be rejected.
        let mut no_state_key = event("$no-state-key", Some(""));
        no_state_key.event_type = M_ROOM_CREATE.into();
        no_state_key.state_key = None;
        assert!(matches!(
            compute_state_before_from_dag(
                &no_state_key,
                &events,
                StateResVersion::V2_2,
                &empty_key
            ),
            Err(StateDagError::Validation(
                StateDagValidationError::CreateWithMissingStateKey
            ))
        ));

        // Create with non-empty state_key must be rejected.
        let mut non_empty_sk = event("$non-empty-sk", Some("not-empty"));
        non_empty_sk.event_type = M_ROOM_CREATE.into();
        assert!(matches!(
            compute_state_before_from_dag(
                &non_empty_sk,
                &events,
                StateResVersion::V2_2,
                &empty_key
            ),
            Err(StateDagError::Validation(
                StateDagValidationError::CreateWithNonEmptyStateKey { .. }
            ))
        ));

        let non_create = event("$event", Some(""));
        assert!(matches!(
            compute_state_before_from_dag(&non_create, &events, StateResVersion::V2_2, &empty_key),
            Err(StateDagError::Validation(
                StateDagValidationError::NonCreateWithoutPrevStateEvents { .. }
            ))
        ));

        let mut missing_parent = event("$event", Some(""));
        missing_parent.auth_events.push("$missing".into());
        assert!(matches!(
            compute_state_before_from_dag(
                &missing_parent,
                &events,
                StateResVersion::V2_2,
                &empty_key
            ),
            Err(StateDagError::Validation(
                StateDagValidationError::MissingReferencedEvent { .. }
            ))
        ));
        assert!(matches!(
            validate_state_dag_ancestors(&missing_parent, &events),
            Err(StateDagError::IncompleteDag { missing_event_ids })
                if missing_event_ids == vec!["$missing".to_string()]
        ));
    }

    #[test]
    fn state_before_resolves_multiple_parent_states_and_detects_cycles() {
        let empty_key = String::new();
        let mut create = event("$create", Some(""));
        create.event_type = M_ROOM_CREATE.into();
        let mut left = event("$left", Some("@left:example.org"));
        left.auth_events.push("$create".into());
        let mut right = event("$right", Some("@right:example.org"));
        right.auth_events.push("$create".into());
        let mut target = event("$target", Some("@target:example.org"));
        target.auth_events.extend(["$left".into(), "$right".into()]);
        let mut events: TestMap = crate::HashMap::default();
        for value in [create, left, right, target.clone()] {
            events.insert(value.event_id.clone(), value);
        }
        assert!(
            compute_state_before_from_dag(&target, &events, StateResVersion::V2_2, &empty_key)
                .is_ok()
        );
        assert!(
            compute_state_after_from_dag(&target, &events, StateResVersion::V2_2, &empty_key)
                .is_ok()
        );

        let mut merge_create = event("$merge-create", Some(""));
        merge_create.event_type = M_ROOM_CREATE.into();
        let mut merge_left = event("$merge-left", Some("left"));
        merge_left.auth_events.push(merge_create.event_id.clone());
        let mut merge_right = event("$merge-right", Some("right"));
        merge_right.auth_events.push(merge_create.event_id.clone());
        let mut merge = event("$merge", Some("merge"));
        merge
            .auth_events
            .extend([merge_left.event_id.clone(), merge_right.event_id.clone()]);
        let mut merge_target = event("$merge-target", Some("target"));
        merge_target.auth_events.push(merge.event_id.clone());
        let mut merge_events: TestMap = crate::HashMap::default();
        for value in [
            merge_create,
            merge_left,
            merge_right,
            merge,
            merge_target.clone(),
        ] {
            merge_events.insert(value.event_id.clone(), value);
        }
        assert!(compute_state_before_from_dag(
            &merge_target,
            &merge_events,
            StateResVersion::V2_2,
            &empty_key,
        )
        .is_ok());

        let mut cycle = event("$cycle", Some("@cycle:example.org"));
        cycle.auth_events.push("$cycle".into());
        let mut cyclic: TestMap = crate::HashMap::default();
        cyclic.insert(cycle.event_id.clone(), cycle.clone());
        assert!(matches!(
            compute_state_before_from_dag(&cycle, &cyclic, StateResVersion::V2_2, &empty_key),
            Err(StateDagError::CycleDetected)
        ));
    }

    #[test]
    fn state_after_handles_single_parent_and_inserts_state_event() {
        let empty_key = String::new();
        let mut create = event("$single-create", Some(""));
        create.event_type = M_ROOM_CREATE.into();
        let mut parent = event("$single-parent", Some("parent"));
        parent.auth_events.push(create.event_id.clone());
        let mut target = event("$single-target", Some("target"));
        target.auth_events.push(parent.event_id.clone());
        let mut events: TestMap = crate::HashMap::default();
        for value in [create, parent, target.clone()] {
            events.insert(value.event_id.clone(), value);
        }

        let state =
            compute_state_after_from_dag(&target, &events, StateResVersion::V2_2, &empty_key)
                .unwrap();
        assert!(state.contains_key(&(EventType::from("m.room.message"), "target".to_string())));
    }

    #[test]
    fn state_after_finalization_handles_missing_and_empty_parent_sets() {
        let empty_key = String::new();
        let missing_id = "$missing-final-parent".to_string();
        let mut missing = event("$missing-final-target", Some("target"));
        missing.auth_events.push(missing_id.clone());
        let empty_events: TestMap = crate::HashMap::default();
        let empty_index: DenseIndex<&String, usize> = DenseIndex::try_build([]).unwrap();
        let empty_states: Vec<Option<SharedState<String, String>>> = Vec::new();
        let mut auth_cache = LocalAuthCache::new(StateResVersion::V2_2);
        let mut mainline_cache = FastMap::default();
        assert!(matches!(
            finish_state_after_from_dag(
                &missing,
                &empty_events,
                &empty_index,
                &empty_states,
                &mut auth_cache,
                &mut mainline_cache,
                StateResVersion::V2_2,
                &empty_key,
            ),
            Err(StateDagError::IncompleteDag { missing_event_ids })
                if missing_event_ids == vec![missing_id]
        ));

        let empty = event("$empty-final-target", Some("target"));
        assert_eq!(
            finish_state_after_from_dag(
                &empty,
                &empty_events,
                &empty_index,
                &empty_states,
                &mut auth_cache,
                &mut mainline_cache,
                StateResVersion::V2_2,
                &empty_key,
            )
            .unwrap(),
            SharedState::new()
        );
    }

    #[test]
    fn ancestor_collection_reports_missing_ids_and_deduplicates_them() {
        let unknown = "$unknown".to_string();
        let events = crate::HashMap::<String, LeanEvent<String, Value, String>>::default();
        let targets = [&unknown, &unknown];
        let missing = collect_state_dag_ancestor_short_ids_batch(&targets, &events).unwrap_err();
        assert_eq!(missing, AncestorCollectError::Missing(vec![unknown]));

        let mut parent = event("$parent", Some(""));
        parent.auth_events.push("$nested-missing".into());
        let mut events: TestMap = crate::HashMap::default();
        events.insert(parent.event_id.clone(), parent);
        let target = "$parent".to_string();
        assert_eq!(
            collect_state_dag_ancestor_short_ids_batch(&[&target], &events).unwrap_err(),
            AncestorCollectError::Missing(vec!["$nested-missing".to_string()])
        );

        let mut create = event("$create", None);
        create.event_type = M_ROOM_CREATE.into();
        let state = SharedState::new();
        assert_eq!(
            derive_auth_events_from_state_dag(&create, &state, &events, "12").unwrap(),
            Vec::<String>::new()
        );
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
        if !event.prev_state_events().is_empty() {
            return Err(StateDagValidationError::CreateWithPrevStateEvents);
        }
        match &event.state_key {
            None => return Err(StateDagValidationError::CreateWithMissingStateKey),
            Some(sk) if sk.as_ref().is_empty() => {}
            Some(sk) => {
                return Err(StateDagValidationError::CreateWithNonEmptyStateKey {
                    state_key: sk.as_ref().to_string(),
                });
            }
        }
        return Ok(());
    }

    if event.prev_state_events().is_empty() {
        return Err(StateDagValidationError::NonCreateWithoutPrevStateEvents {
            event_id: event.event_id.clone(),
        });
    }

    if event.prev_state_events().len() > MAX_PREV_STATE_EVENTS {
        return Err(StateDagValidationError::FanoutExceeded {
            count: event.prev_state_events().len(),
            limit: MAX_PREV_STATE_EVENTS,
        });
    }

    for pse_id in event.prev_state_events() {
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

/// Walks the `prev_state_events` graph backwards starting from `start_events`.
///
/// For MSC4242 (V2.2) rooms, this follows explicit `prev_state_events` edges.
/// For earlier room versions, it follows `prev_events` edges as a fallback,
/// matching the MSC4500 `state_predecessors` definition where the general
/// DAG predecessor edges double as the state-predecessor relation.
///
/// Verifies that all paths terminate at `m.room.create`. If any path hits an unknown
/// event ID or non-create leaf, reports the missing events so the host homeserver
/// can fetch them (e.g. via `/get_missing_events?state_dag=true`).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn walk_state_dag<Id, C, S, K>(
    start_events: &[&Id],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    options: StateDagWalkOptions,
    version: StateResVersion,
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
    let mut truncated = false;

    while let Some(current_id) = queue.pop_front() {
        if visited.contains(&current_id) {
            continue;
        }

        // Enforce max_steps BEFORE processing so that `Some(0)` is a
        // no-op: no event is dequeued, looked up, or added to `reachable`.
        if let Some(max) = options.max_steps {
            if steps >= max {
                // `current_id` was popped but not processed, so this walk is
                // incomplete even when it was the final queued event.
                truncated = true;
                break;
            }
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

        if ev.state_predecessors(version).is_empty() {
            // Non-create event with no state predecessors is disconnected from create.
            if disconnected_set.insert(ev.event_id.clone()) {
                disconnected.push(ev.event_id.clone());
            }
            continue;
        }

        for pe in ev.state_predecessors(version) {
            if !visited.contains(pe) {
                queue.push_back(pe.clone());
            }
        }
    }

    // `visited` prevents repeated work but is not a cycle detector: a back
    // edge can be skipped after the same node was reached through another
    // branch. Run an explicit colour walk over the discovered graph so a
    // cyclic ancestry can never be reported as complete.
    let reachable_set: FastSet<Id> = reachable.iter().cloned().collect();
    let mut done: FastSet<Id> = FastSet::default();
    let mut active: FastSet<Id> = FastSet::default();
    let mut has_cycle = false;
    for root in &reachable {
        if done.contains(root) {
            continue;
        }
        let mut stack = vec![(root.clone(), false)];
        while let Some((id, exiting)) = stack.pop() {
            if exiting {
                active.remove(&id);
                done.insert(id);
                continue;
            }
            if active.contains(&id) {
                has_cycle = true;
                break;
            }
            if done.contains(&id) {
                continue;
            }
            active.insert(id.clone());
            stack.push((id.clone(), true));
            if let Some(ev) = events_map.get(&id) {
                for parent in ev.prev_state_events().iter().rev() {
                    if reachable_set.contains(parent) {
                        stack.push((parent.clone(), false));
                    }
                }
            }
        }
        if has_cycle {
            break;
        }
    }

    if !truncated && !has_cycle && missing.is_empty() && disconnected.is_empty() {
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
            for pe in ev.prev_state_events() {
                queue.push_back((pe.clone(), 1));
            }
        }
    }

    while let Some((id, hops)) = queue.pop_front() {
        min_hops.entry(id.clone()).or_insert(hops);

        if visited.insert(id.clone()) {
            if let Some(ev) = events_map.get(&id) {
                if ev.event_type != M_ROOM_CREATE {
                    for pe in ev.prev_state_events() {
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

/// Error from [`collect_state_dag_ancestor_short_ids_batch`].
#[derive(Debug, PartialEq, Eq)]
enum AncestorCollectError<Id> {
    /// Required ancestor events are missing from `events_map`.
    Missing(Vec<Id>),
    /// Too many distinct ancestors to index (exceeds `usize` capacity).
    IndexOverflow,
}

/// Collects all state DAG ancestors reachable from `targets` via `prev_state_events`.
fn collect_state_dag_ancestor_short_ids_batch<'a, Id, C, S, K>(
    targets: &[&'a Id],
    events_map: &'a HashMap<Id, LeanEvent<Id, C, K>, S>,
) -> Result<DenseIndex<&'a Id, usize>, AncestorCollectError<Id>>
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
            for pe in ev.prev_state_events() {
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
        DenseIndex::try_build(index_to_id).map_err(|_| AncestorCollectError::IndexOverflow)
    } else {
        Err(AncestorCollectError::Missing(missing))
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
            for pe in ev.prev_state_events() {
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
    // State-DAG traversal (prev_state_events edges) is only defined for
    // room versions that use MSC4242 (V2.2). Earlier versions use auth-
    // chain state resolution and must not call this function.
    if version != StateResVersion::V2_2 {
        return Err(StateDagError::Validation(
            StateDagValidationError::UnsupportedVersionForDag {
                version: alloc::format!("{version:?}"),
            },
        ));
    }

    if event.event_type == M_ROOM_CREATE {
        if !event.prev_state_events().is_empty() {
            return Err(StateDagError::Validation(
                StateDagValidationError::CreateWithPrevStateEvents,
            ));
        }
        match &event.state_key {
            None => {
                return Err(StateDagError::Validation(
                    StateDagValidationError::CreateWithMissingStateKey,
                ));
            }
            Some(sk) if sk.as_ref().is_empty() => {}
            Some(sk) => {
                return Err(StateDagError::Validation(
                    StateDagValidationError::CreateWithNonEmptyStateKey {
                        state_key: sk.as_ref().to_string(),
                    },
                ));
            }
        }
        return Ok(SharedState::new());
    }

    validate_msc4242_prev_state_events(event, events_map).map_err(StateDagError::Validation)?;

    let parent_refs: Vec<&Id> = event.prev_state_events().iter().collect();
    validate_state_dag_ancestors(event, events_map)?;
    let index = collect_state_dag_ancestor_short_ids_batch(&parent_refs, events_map).map_err(
        |e| match e {
            AncestorCollectError::Missing(ids) => StateDagError::IncompleteDag {
                missing_event_ids: ids,
            },
            AncestorCollectError::IndexOverflow => StateDagError::AncestorIndexOverflow,
        },
    )?;

    let (sorted_ancestors, mut out_degree) =
        topological_sort_state_dag_short_ids(&index, events_map);

    if sorted_ancestors.len() != index.len() {
        return Err(StateDagError::CycleDetected);
    }

    // Allocate an extra out_degree ref for parents of target event
    for p_id in event.prev_state_events() {
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
        let ev = events_map
            .get(id_val)
            .expect("state DAG index contains only events from the event map");

        let mut prev_states = Vec::with_capacity(ev.prev_state_events().len());
        for pe in ev.prev_state_events() {
            let pe_idx = index
                .index_of(&pe)
                .expect("state DAG ancestor index contains every referenced parent");
            debug_assert!(out_degree[pe_idx] > 0);
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
                    ev.state_key
                        .clone()
                        .expect("state_key was checked to be present"),
                ),
                ev.event_id.clone(),
            );
        }

        if out_degree[idx] > 0 {
            state_after_map[idx] = Some(state_before);
        }
    }

    finish_state_after_from_dag(
        event,
        events_map,
        &index,
        &state_after_map,
        &mut global_auth_cache,
        &mut mainline_cache,
        version,
        empty_key,
    )
}

/// Validates the complete `prev_state_events` closure reachable from `event`.
///
/// This checks indirect ancestors too, so a malformed ancestor several hops
/// away cannot slip through just because the target's immediate parents are
/// valid.
fn validate_state_dag_ancestors<Id, C, S, K>(
    event: &LeanEvent<Id, C, K>,
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
) -> Result<(), StateDagError<Id>>
where
    Id: EventId,
    C: EventContent,
    K: StateKey,
    S: core::hash::BuildHasher,
{
    // Validate the complete reachable graph, not only the target's immediate
    // parents. Otherwise a malformed indirect ancestor can influence state.
    let mut pending: Vec<Id> = event.prev_state_events().to_vec();
    let mut checked: FastSet<Id> = FastSet::default();
    while let Some(id) = pending.pop() {
        if !checked.insert(id.clone()) {
            continue;
        }
        let Some(ancestor) = events_map.get(&id) else {
            return Err(StateDagError::IncompleteDag {
                missing_event_ids: vec![id],
            });
        };
        validate_msc4242_prev_state_events(ancestor, events_map)
            .map_err(StateDagError::Validation)?;
        pending.extend(ancestor.prev_state_events().iter().cloned());
    }
    Ok(())
}

/// Finalizes `compute_state_before_from_dag` by gathering the target's parent
/// states and resolving the fork if necessary.
#[allow(clippy::too_many_arguments)]
fn finish_state_after_from_dag<Id, C, S, K>(
    event: &LeanEvent<Id, C, K>,
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    index: &DenseIndex<&Id, usize>,
    state_after_map: &[Option<SharedState<Id, K>>],
    global_auth_cache: &mut LocalAuthCache<Id, C, K>,
    mainline_cache: &mut FastMap<Id, Option<Id>>,
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
    let mut parent_states = Vec::with_capacity(event.prev_state_events().len());
    for pe in event.prev_state_events() {
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
            global_auth_cache,
            mainline_cache,
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
///
/// # Panics
/// Panics only if the event's `state_key` changes between the presence check
/// and insertion, which cannot occur through this shared-reference API.
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
                event
                    .state_key
                    .clone()
                    .expect("state_key was checked to be present"),
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
            } else {
                return Err(AuthError::MissingAuthEvent(auth_id.clone()));
            }
            derived_auth.push(auth_id.clone());
        }
    }

    Ok(derived_auth)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod targeted_coverage_tests {
    use super::*;
    use serde_json::Value;

    fn event(
        id: &str,
        event_type: &str,
        state_key: Option<&str>,
    ) -> LeanEvent<String, Value, String> {
        LeanEvent {
            event_id: id.into(),
            event_type: event_type.into(),
            state_key: state_key.map(String::from),
            sender: "@alice:example.org".into(),
            content: Value::Null,
            ..Default::default()
        }
    }

    #[test]
    fn ancestor_collection_reports_dense_index_allocation_failure() {
        // Resets the thread-local force-allocation-failure hook on drop, even
        // if the assertion below panics -- otherwise a failing assertion
        // would leave the hook stuck on and spuriously fail every later test
        // in this thread that touches `DenseIndex`.
        struct ResetOnDrop;
        impl Drop for ResetOnDrop {
            fn drop(&mut self) {
                crate::dense_index::set_force_allocation_failure(false);
            }
        }

        let root = event("$root", M_ROOM_CREATE, Some(""));
        let mut events: HashMap<String, LeanEvent<String, Value, String>> = HashMap::default();
        events.insert(root.event_id.clone(), root);
        let target = "$root".to_string();

        crate::dense_index::set_force_allocation_failure(true);
        let _guard = ResetOnDrop;
        let result = collect_state_dag_ancestor_short_ids_batch(&[&target], &events);

        assert_eq!(result, Err(AncestorCollectError::IndexOverflow));
    }

    #[test]
    fn state_after_inserts_state_event_and_create_auth_is_empty() {
        let create = event("$create", M_ROOM_CREATE, Some(""));
        let mut events: HashMap<String, LeanEvent<String, Value, String>> = HashMap::default();
        events.insert(create.event_id.clone(), create.clone());
        let state =
            compute_state_after_from_dag(&create, &events, StateResVersion::V2_2, &String::new())
                .expect("create state is valid");

        assert_eq!(
            state.get(&(EventType::from(M_ROOM_CREATE), String::new())),
            Some(&"$create".to_string())
        );
        assert_eq!(
            derive_auth_events_from_state_dag(&create, &state, &events, "12").unwrap(),
            [] as [std::string::String; 0]
        );
    }
}
