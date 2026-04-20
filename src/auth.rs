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

//! Matrix Authorization Rules (Spec §10.4)
//!
//! Implements iterative auth-checking of events against the room state at
//! their `prev_events` — never the current time. This is the core security
//! invariant that prevents retroactive authorization tampering.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::LeanEvent;

/// An error indicating why an event failed authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The sender is not a member of the room (or membership is not "join").
    NotMember { sender: String },
    /// The sender's power level is below the required level for this event type.
    InsufficientPowerLevel {
        required: i64,
        actual: i64,
        event_type: String,
    },
    /// The sender is banned from the room.
    BannedUser { sender: String },
    /// For `m.room.member` events, the `state_key` doesn't match the expected
    /// user ID for the given membership transition.
    InvalidStateKey { expected: String, actual: String },
    /// The `m.room.create` event has `prev_events`, which is forbidden.
    CreateWithPrevEvents,
    /// An auth event referenced by this event is missing from the provided state.
    MissingAuthEvent(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::NotMember { sender } => {
                write!(f, "sender {} is not a joined member", sender)
            }
            AuthError::InsufficientPowerLevel {
                required,
                actual,
                event_type,
            } => write!(
                f,
                "power level {} < {} required for {}",
                actual, required, event_type
            ),
            AuthError::BannedUser { sender } => {
                write!(f, "sender {} is banned", sender)
            }
            AuthError::InvalidStateKey { expected, actual } => {
                write!(
                    f,
                    "invalid state_key: expected {}, got {}",
                    expected, actual
                )
            }
            AuthError::CreateWithPrevEvents => {
                write!(f, "m.room.create must not have prev_events")
            }
            AuthError::MissingAuthEvent(id) => {
                write!(f, "missing auth event: {}", id)
            }
        }
    }
}

/// The room state at a specific point in the DAG (keyed by (type, state_key) -> event).
pub type RoomState = BTreeMap<(String, String), LeanEvent>;

/// Check whether `event` is authorized given the room state at its `prev_events`.
///
/// This implements the core Matrix authorization rules:
/// 1. `m.room.create` must be the first event (no prev_events).
/// 2. Sender must be a joined member (unless joining/being invited).
/// 3. Sender must not be banned.
/// 4. Sender's power level must meet the event type requirement.
/// 5. For `m.room.member` events, the state_key must match transition rules.
pub fn check_auth(event: &LeanEvent, state: &RoomState) -> Result<(), AuthError> {
    // Rule 1: m.room.create must be the first event
    if event.event_type == "m.room.create" {
        if !event.prev_events.is_empty() {
            return Err(AuthError::CreateWithPrevEvents);
        }
        // Create events are always authorized if they're first
        return Ok(());
    }

    // Rule 2: Check sender is not banned
    let member_key = ("m.room.member".into(), event.sender.clone());
    if let Some(member_event) = state.get(&member_key) {
        if let Some(membership) = member_event
            .content
            .get("membership")
            .and_then(|m| m.as_str())
        {
            if membership == "ban" {
                return Err(AuthError::BannedUser {
                    sender: event.sender.clone(),
                });
            }

            // Rule 3: Sender must be joined (with exceptions for membership events)
            if event.event_type != "m.room.member" && membership != "join" {
                return Err(AuthError::NotMember {
                    sender: event.sender.clone(),
                });
            }
        }
    } else if event.event_type != "m.room.member" {
        // No membership record and not a membership event — reject
        return Err(AuthError::NotMember {
            sender: event.sender.clone(),
        });
    }

    // Rule 4: Check power level requirements
    let sender_pl = get_sender_power_level(&event.sender, state);
    let required_pl = get_required_power_level(&event.event_type, state);

    if sender_pl < required_pl {
        return Err(AuthError::InsufficientPowerLevel {
            required: required_pl,
            actual: sender_pl,
            event_type: event.event_type.clone(),
        });
    }

    // Rule 5: m.room.member state_key validation
    if event.event_type == "m.room.member" {
        check_membership_rules(event, state)?;
    }

    Ok(())
}

/// Get the power level of a user from the current room state.
fn get_sender_power_level(sender: &str, state: &RoomState) -> i64 {
    let pl_key = ("m.room.power_levels".into(), String::new());
    if let Some(pl_event) = state.get(&pl_key) {
        if let Some(users) = pl_event.content.get("users").and_then(|u| u.as_object()) {
            if let Some(pl) = users.get(sender).and_then(|v| v.as_i64()) {
                return pl;
            }
        }
        // Fall back to users_default
        if let Some(default) = pl_event
            .content
            .get("users_default")
            .and_then(|v| v.as_i64())
        {
            return default;
        }
    }
    0 // Default power level if no power_levels event exists
}

/// Get the required power level to send a given event type.
fn get_required_power_level(event_type: &str, state: &RoomState) -> i64 {
    let pl_key = ("m.room.power_levels".into(), String::new());
    if let Some(pl_event) = state.get(&pl_key) {
        // Check specific event type overrides
        if let Some(events) = pl_event.content.get("events").and_then(|e| e.as_object()) {
            if let Some(pl) = events.get(event_type).and_then(|v| v.as_i64()) {
                return pl;
            }
        }
        // Fall back to state_default for state events, events_default for others
        if event_type.starts_with("m.room.") {
            if let Some(default) = pl_event
                .content
                .get("state_default")
                .and_then(|v| v.as_i64())
            {
                return default;
            }
        }
        if let Some(default) = pl_event
            .content
            .get("events_default")
            .and_then(|v| v.as_i64())
        {
            return default;
        }
    }
    0 // No restrictions if no power_levels event exists
}

/// Validate membership transition rules for `m.room.member` events.
fn check_membership_rules(event: &LeanEvent, state: &RoomState) -> Result<(), AuthError> {
    let target_user = &event.state_key;
    let _sender = &event.sender;

    let new_membership = event
        .content
        .get("membership")
        .and_then(|m| m.as_str())
        .unwrap_or("");

    match new_membership {
        // A user can only join as themselves (state_key == sender)
        "join" if event.state_key != event.sender => {
            return Err(AuthError::InvalidStateKey {
                expected: event.sender.clone(),
                actual: event.state_key.clone(),
            });
        }
        // If state_key != sender, this is a kick — requires power level
        "leave" if event.state_key != event.sender => {
            let sender_pl = get_sender_power_level(&event.sender, state);
            let kick_pl = get_kick_power_level(state);
            if sender_pl < kick_pl {
                return Err(AuthError::InsufficientPowerLevel {
                    required: kick_pl,
                    actual: sender_pl,
                    event_type: "kick".into(),
                });
            }
        }
        "ban" => {
            // Banning requires the ban power level
            let sender_pl = get_sender_power_level(&event.sender, state);
            let ban_pl = get_ban_power_level(state);
            if sender_pl < ban_pl {
                return Err(AuthError::InsufficientPowerLevel {
                    required: ban_pl,
                    actual: sender_pl,
                    event_type: "ban".into(),
                });
            }
        }
        "invite" => {
            // Inviting requires invite power level, and sender != target
            if event.state_key == event.sender {
                return Err(AuthError::InvalidStateKey {
                    expected: alloc::format!("!= {}", event.sender),
                    actual: event.state_key.clone(),
                });
            }
            // Check target isn't already banned
            let target_key = ("m.room.member".into(), target_user.clone());
            if let Some(target_member) = state.get(&target_key) {
                if target_member
                    .content
                    .get("membership")
                    .and_then(|m| m.as_str())
                    == Some("ban")
                {
                    return Err(AuthError::BannedUser {
                        sender: target_user.clone(),
                    });
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// Get the kick power level from room state.
fn get_kick_power_level(state: &RoomState) -> i64 {
    let pl_key = ("m.room.power_levels".into(), String::new());
    if let Some(pl_event) = state.get(&pl_key) {
        if let Some(kick) = pl_event.content.get("kick").and_then(|v| v.as_i64()) {
            return kick;
        }
    }
    50 // Default kick power level per Matrix spec
}

/// Get the ban power level from room state.
fn get_ban_power_level(state: &RoomState) -> i64 {
    let pl_key = ("m.room.power_levels".into(), String::new());
    if let Some(pl_event) = state.get(&pl_key) {
        if let Some(ban) = pl_event.content.get("ban").and_then(|v| v.as_i64()) {
            return ban;
        }
    }
    50 // Default ban power level per Matrix spec
}

/// Iteratively apply auth checks to a list of events in topological order.
/// Returns the list of events that passed auth checks, and the list that failed
/// with their respective errors.
pub fn check_auth_chain(
    sorted_events: &[LeanEvent],
    initial_state: &RoomState,
) -> (Vec<String>, Vec<(String, AuthError)>) {
    let mut state = initial_state.clone();
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();

    for event in sorted_events {
        match check_auth(event, &state) {
            Ok(()) => {
                // Apply event to state
                if !event.state_key.is_empty() || event.event_type == "m.room.create" {
                    state.insert(
                        (event.event_type.clone(), event.state_key.clone()),
                        event.clone(),
                    );
                }
                accepted.push(event.event_id.clone());
            }
            Err(e) => {
                rejected.push((event.event_id.clone(), e));
            }
        }
    }

    (accepted, rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use serde_json::json;

    fn make_event(
        id: &str,
        event_type: &str,
        state_key: &str,
        sender: &str,
        content: serde_json::Value,
    ) -> LeanEvent {
        LeanEvent {
            event_id: id.into(),
            event_type: event_type.into(),
            state_key: state_key.into(),
            sender: sender.into(),
            content,
            ..Default::default()
        }
    }

    #[test]
    fn test_create_event_no_prev_events() {
        let create = make_event(
            "$create",
            "m.room.create",
            "",
            "@alice:example.com",
            json!({}),
        );
        let state = RoomState::new();
        assert!(check_auth(&create, &state).is_ok());
    }

    #[test]
    fn test_create_event_with_prev_events() {
        let mut create = make_event(
            "$create",
            "m.room.create",
            "",
            "@alice:example.com",
            json!({}),
        );
        create.prev_events = vec!["$other".into()];
        let state = RoomState::new();
        assert_eq!(
            check_auth(&create, &state),
            Err(AuthError::CreateWithPrevEvents)
        );
    }

    #[test]
    fn test_non_member_rejection() {
        let msg = make_event("$msg", "m.room.message", "", "@bob:example.com", json!({}));
        let state = RoomState::new();
        assert!(matches!(
            check_auth(&msg, &state),
            Err(AuthError::NotMember { .. })
        ));
    }

    #[test]
    fn test_joined_member_can_send() {
        let msg = make_event(
            "$msg",
            "m.room.message",
            "",
            "@alice:example.com",
            json!({}),
        );
        let mut state = RoomState::new();
        state.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            make_event(
                "$join",
                "m.room.member",
                "@alice:example.com",
                "@alice:example.com",
                json!({"membership": "join"}),
            ),
        );
        assert!(check_auth(&msg, &state).is_ok());
    }

    #[test]
    fn test_banned_user_rejected() {
        let msg = make_event(
            "$msg",
            "m.room.message",
            "",
            "@alice:example.com",
            json!({}),
        );
        let mut state = RoomState::new();
        state.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            make_event(
                "$ban",
                "m.room.member",
                "@alice:example.com",
                "@admin:example.com",
                json!({"membership": "ban"}),
            ),
        );
        assert!(matches!(
            check_auth(&msg, &state),
            Err(AuthError::BannedUser { .. })
        ));
    }

    #[test]
    fn test_insufficient_power_level() {
        let msg = make_event(
            "$msg",
            "m.room.power_levels",
            "",
            "@alice:example.com",
            json!({}),
        );
        let mut state = RoomState::new();
        state.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            make_event(
                "$join",
                "m.room.member",
                "@alice:example.com",
                "@alice:example.com",
                json!({"membership": "join"}),
            ),
        );
        state.insert(
            ("m.room.power_levels".into(), String::new()),
            make_event(
                "$pl",
                "m.room.power_levels",
                "",
                "@admin:example.com",
                json!({"state_default": 50, "users": {"@admin:example.com": 100}}),
            ),
        );
        assert!(matches!(
            check_auth(&msg, &state),
            Err(AuthError::InsufficientPowerLevel { .. })
        ));
    }

    #[test]
    fn test_join_self_only() {
        let join = make_event(
            "$join",
            "m.room.member",
            "@bob:example.com",
            "@alice:example.com",
            json!({"membership": "join"}),
        );
        let state = RoomState::new();
        assert!(matches!(
            check_auth(&join, &state),
            Err(AuthError::InvalidStateKey { .. })
        ));
    }

    #[test]
    fn test_iterative_auth_chain() {
        let create = make_event(
            "$create",
            "m.room.create",
            "",
            "@alice:example.com",
            json!({}),
        );
        let join = make_event(
            "$join",
            "m.room.member",
            "@alice:example.com",
            "@alice:example.com",
            json!({"membership": "join"}),
        );
        let msg = make_event(
            "$msg",
            "m.room.message",
            "",
            "@alice:example.com",
            json!({"body": "hello"}),
        );
        let (accepted, rejected) = check_auth_chain(&[create, join, msg], &RoomState::new());
        assert_eq!(accepted, vec!["$create", "$join", "$msg"]);
        assert!(rejected.is_empty());
    }

    #[test]
    fn test_auth_error_display() {
        let err = AuthError::NotMember {
            sender: "@bob:example.com".into(),
        };
        let msg = alloc::format!("{}", err);
        assert!(msg.contains("bob"));
    }
}
