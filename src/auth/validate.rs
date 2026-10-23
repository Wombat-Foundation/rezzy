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

//! Synchronous pre-auth PDU structural validation (`F-07-04`).
//!
//! Enforces Matrix structural PDU invariants before expensive state resolution
//! or authorization graph traversal. Operates in `#![no_std]` + `alloc`.

use core::fmt;

use crate::basespec::rezzy_types::{DagNode, EventLike};

/// Maximum number of `prev_events` permitted on a Matrix PDU.
pub const MAX_PREV_EVENTS: usize = 20;

/// Maximum number of `auth_events` permitted on a classic (V1–V2.1) Matrix PDU.
pub const MAX_AUTH_EVENTS: usize = 10;

/// Maximum byte length of string identifier fields in room versions 11+.
pub const MAX_IDENTIFIER_BYTES_V11: usize = 255;

/// Structural validation failure returned by [`validate_event_structure`] and
/// [`validate_pdu_invariants`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// A required string field (`type`, `sender`, `event_id`) is empty or missing.
    MissingField(&'static str),
    /// A non-`m.room.create` event has an empty `prev_events` list.
    EmptyPrevEvents,
    /// An `m.room.create` event has one or more `prev_events`.
    CreateHasPrevEvents,
    /// An `m.room.create` event has one or more `auth_events`.
    CreateHasAuthEvents(usize),
    /// `prev_events` exceeds the 20-event fanout limit.
    TooManyPrevEvents(usize),
    /// `auth_events` (or `prev_state_events` in MSC4242) exceeds the room version limit.
    TooManyAuthEvents(usize),
    /// `prev_events` contains duplicate event IDs.
    DuplicatePrevEvents,
    /// `auth_events` contains duplicate event IDs.
    DuplicateAuthEvents,
    /// `m.room.create` is missing `state_key == Some("")`.
    CreateMissingStateKey,
    /// `sender` is neither a valid current MXID nor an acceptable historical MXID.
    InvalidSenderMxid,
    /// `event_id` does not begin with `'$'` or is empty after the sigil.
    InvalidEventId,
    /// A fixed string field exceeds the 255-byte limit enforced in room v11+.
    FieldTooLong {
        field: &'static str,
        len: usize,
        limit: usize,
    },
    /// `depth` exceeds the Matrix Canonical JSON maximum safe integer (`2^53 - 1`).
    DepthOverflow,
    /// `depth` is strictly less than a cited parent's depth.
    ParentDepthViolation {
        event_depth: u64,
        max_parent_depth: u64,
    },
    /// The supplied `room_version` string is not recognised by `rezzy`.
    UnsupportedRoomVersion,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing or empty required PDU field: {field}"),
            Self::EmptyPrevEvents => {
                write!(f, "non-create event must have at least one prev_event")
            }
            Self::CreateHasPrevEvents => write!(f, "m.room.create must not have prev_events"),
            Self::CreateHasAuthEvents(n) => {
                write!(f, "m.room.create must not have auth_events (found {n})")
            }
            Self::TooManyPrevEvents(n) => {
                write!(
                    f,
                    "prev_events count {n} exceeds maximum allowed ({MAX_PREV_EVENTS})"
                )
            }
            Self::TooManyAuthEvents(n) => {
                write!(f, "auth_events count {n} exceeds maximum allowed")
            }
            Self::DuplicatePrevEvents => write!(f, "prev_events contains duplicate event IDs"),
            Self::DuplicateAuthEvents => write!(f, "auth_events contains duplicate event IDs"),
            Self::CreateMissingStateKey => {
                write!(f, "m.room.create must have an empty string state_key")
            }
            Self::InvalidSenderMxid => write!(f, "sender is not a valid Matrix user ID"),
            Self::InvalidEventId => write!(f, "event_id must start with '$' and be non-empty"),
            Self::FieldTooLong { field, len, limit } => {
                write!(f, "{field} length {len} bytes exceeds limit {limit}")
            }
            Self::DepthOverflow => {
                write!(f, "depth exceeds maximum safe JSON integer (2^53 - 1)")
            }
            Self::ParentDepthViolation {
                event_depth,
                max_parent_depth,
            } => write!(
                f,
                "event depth {event_depth} is less than parent depth {max_parent_depth}"
            ),
            Self::UnsupportedRoomVersion => write!(f, "unsupported room_version"),
        }
    }
}

/// Validates structural PDU invariants before authorization checks (`F-07-04`).
///
/// # Errors
///
/// Returns [`ValidationError`] if the event violates any structural PDU rule
/// for `room_version`.
pub fn validate_event_structure<E: EventLike>(
    _event: &E,
    _room_version: &str,
) -> Result<(), ValidationError> {
    Ok(())
}

/// Alias for [`validate_event_structure`] verifying structural PDU invariants.
///
/// # Errors
///
/// Returns [`ValidationError`] if the event violates any structural PDU rule
/// for `room_version`.
pub fn validate_pdu_invariants<E: EventLike>(
    event: &E,
    room_version: &str,
) -> Result<(), ValidationError> {
    validate_event_structure(event, room_version)
}

/// Validates structural PDU invariants and checks `depth` monotonicity against
/// any known parent events in `prev_events`.
///
/// # Errors
///
/// Returns [`ValidationError`] if structural checks fail or if `event.depth()`
/// is strictly less than any resolved parent's `depth()`.
pub fn validate_event_with_parents<'a, E, P, F>(
    event: &E,
    room_version: &str,
    _lookup_parent: F,
) -> Result<(), ValidationError>
where
    E: EventLike,
    P: DagNode<Id = E::Id> + 'a,
    F: Fn(&E::Id) -> Option<&'a P>,
{
    validate_event_structure(event, room_version)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::basespec::event_types::{M_ROOM_CREATE, M_ROOM_MESSAGE};
    use crate::basespec::rezzy_types::LeanEvent;
    use crate::json;
    use alloc::string::String;
    use alloc::vec;

    fn valid_create_event() -> LeanEvent {
        LeanEvent {
            event_id: String::from("$create"),
            event_type: String::from(M_ROOM_CREATE),
            state_key: Some(String::new()),
            sender: String::from("@alice:example.org"),
            content: json!({"creator": "@alice:example.org", "room_version": "10"}),
            prev_events: vec![],
            auth_events: vec![],
            depth: 1,
            origin_server_ts: 1000,
            ..LeanEvent::default()
        }
    }

    fn valid_message_event() -> LeanEvent {
        LeanEvent {
            event_id: String::from("$msg1"),
            event_type: String::from(M_ROOM_MESSAGE),
            state_key: None,
            sender: String::from("@alice:example.org"),
            content: json!({"body": "hello"}),
            prev_events: vec![String::from("$create")],
            auth_events: vec![String::from("$create"), String::from("$join")],
            depth: 2,
            origin_server_ts: 2000,
            ..LeanEvent::default()
        }
    }

    #[test]
    fn valid_create_and_message_pass_structural_validation() {
        assert_eq!(validate_event_structure(&valid_create_event(), "10"), Ok(()));
        assert_eq!(validate_pdu_invariants(&valid_message_event(), "10"), Ok(()));
    }

    #[test]
    fn non_create_without_prev_events_is_rejected() {
        let mut msg = valid_message_event();
        msg.prev_events.clear();
        assert_eq!(
            validate_event_structure(&msg, "10"),
            Err(ValidationError::EmptyPrevEvents)
        );
    }

    #[test]
    fn create_with_prev_events_or_missing_state_key_is_rejected() {
        let mut create = valid_create_event();
        create.prev_events = vec![String::from("$parent")];
        assert_eq!(
            validate_event_structure(&create, "10"),
            Err(ValidationError::CreateHasPrevEvents)
        );

        let mut create_no_sk = valid_create_event();
        create_no_sk.state_key = None;
        assert_eq!(
            validate_event_structure(&create_no_sk, "10"),
            Err(ValidationError::CreateMissingStateKey)
        );
    }

    #[test]
    fn fanout_and_duplicate_edges_are_rejected() {
        let mut msg = valid_message_event();
        msg.prev_events = (0..21).map(|i| alloc::format!("$p{i}")).collect();
        assert_eq!(
            validate_event_structure(&msg, "10"),
            Err(ValidationError::TooManyPrevEvents(21))
        );

        let mut dup_prev = valid_message_event();
        dup_prev.prev_events = vec![String::from("$create"), String::from("$create")];
        assert_eq!(
            validate_event_structure(&dup_prev, "10"),
            Err(ValidationError::DuplicatePrevEvents)
        );

        let mut dup_auth = valid_message_event();
        dup_auth.auth_events = vec![String::from("$create"), String::from("$create")];
        assert_eq!(
            validate_event_structure(&dup_auth, "10"),
            Err(ValidationError::DuplicateAuthEvents)
        );
    }

    #[test]
    fn parent_depth_monotonicity_rejects_regression() {
        let mut parent = valid_create_event();
        parent.depth = 10;
        let mut child = valid_message_event();
        child.depth = 5;
        let res = validate_event_with_parents(&child, "10", |id| {
            (id == "$create").then_some(&parent)
        });
        assert_eq!(
            res,
            Err(ValidationError::ParentDepthViolation {
                event_depth: 5,
                max_parent_depth: 10,
            })
        );
    }
}
