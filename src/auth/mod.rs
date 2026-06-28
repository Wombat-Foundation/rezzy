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

pub mod roaring;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::LeanEvent;

/// An error indicating why an event failed authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The sender is not a member of the room (or membership is not "join").
    NotMember { sender: String, event_id: String },
    /// The sender's power level is below the required level for this event type.
    InsufficientPowerLevel {
        required: i64,
        actual: i64,
        event_type: String,
    },
    /// The sender is banned from the room.
    BannedUser { sender: String, event_id: String },
    /// For `m.room.member` events, the `state_key` doesn't match the expected
    /// user ID for the given membership transition.
    InvalidStateKey { expected: String, actual: String },
    /// The `m.room.create` event has `prev_events`, which is forbidden.
    CreateWithPrevEvents,
    /// An auth event referenced by this event is missing from the provided state.
    MissingAuthEvent(String),
    /// The event failed basic syntactic validation (e.g. invalid event type, too many `prev_events`).
    InvalidSyntax(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::NotMember { sender, .. } => {
                write!(f, "sender {sender} is not joined")
            }
            AuthError::InsufficientPowerLevel {
                required,
                actual,
                event_type,
            } => write!(f, "PL {actual} < {required} for {event_type}"),
            AuthError::BannedUser { sender, .. } => {
                write!(f, "sender {sender} is banned")
            }
            AuthError::InvalidStateKey { expected, actual } => {
                write!(f, "invalid state_key: {actual} (expected {expected})")
            }
            AuthError::CreateWithPrevEvents => {
                write!(f, "m.room.create has prev_events")
            }
            AuthError::MissingAuthEvent(id) => {
                write!(f, "missing auth event: {id}")
            }
            AuthError::InvalidSyntax(reason) => {
                write!(f, "invalid syntax: {reason}")
            }
        }
    }
}

use core::borrow::Borrow;
use core::cmp::Ordering;

pub trait StateKeyDyn {
    fn ev_type(&self) -> &str;
    fn state_key(&self) -> Option<&str>;
}

impl StateKeyDyn for (String, Option<String>) {
    fn ev_type(&self) -> &str {
        &self.0
    }
    fn state_key(&self) -> Option<&str> {
        self.1.as_deref()
    }
}

impl<'a> StateKeyDyn for (&'a str, Option<&'a str>) {
    fn ev_type(&self) -> &str {
        self.0
    }
    fn state_key(&self) -> Option<&str> {
        self.1
    }
}

impl<'a> Borrow<dyn StateKeyDyn + 'a> for (String, Option<String>) {
    fn borrow(&self) -> &(dyn StateKeyDyn + 'a) {
        self
    }
}

impl PartialEq for dyn StateKeyDyn + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.ev_type() == other.ev_type() && self.state_key() == other.state_key()
    }
}

impl Eq for dyn StateKeyDyn + '_ {}

impl PartialOrd for dyn StateKeyDyn + '_ {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for dyn StateKeyDyn + '_ {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ev_type()
            .cmp(other.ev_type())
            .then_with(|| self.state_key().cmp(&other.state_key()))
    }
}

pub trait StateProvider {
    fn get_event(&self, event_type: &str, state_key: Option<&str>) -> Option<&LeanEvent>;
}

/// The room state at a specific point in the DAG (keyed by (type, `state_key`) -> event).
pub type RoomState = alloc::collections::BTreeMap<(String, Option<String>), LeanEvent>;

impl StateProvider for RoomState {
    fn get_event(&self, event_type: &str, state_key: Option<&str>) -> Option<&LeanEvent> {
        let query: &dyn StateKeyDyn = &(event_type, state_key);
        self.get(query)
    }
}

/// Check whether `event` is authorized given the room state at its `prev_events`.
///
/// This implements the core Matrix authorization rules:
/// 1. `m.room.create` must be the first event (no `prev_events`).
/// 2. Sender must be a joined member (unless joining/being invited).
/// 3. Sender must not be banned.
/// 4. Sender's power level must meet the event type requirement.
/// 5. For `m.room.member` events, the `state_key` must match transition rules.
///
/// # Errors
///
/// Returns an `AuthError` if the event fails authorization validation.
pub fn check_auth(event: &LeanEvent, state: &impl StateProvider) -> Result<(), AuthError> {
    // Rule 0: Custom syntactic validation
    event
        .validate_syntactic()
        .map_err(|e| AuthError::InvalidSyntax(e.into()))?;

    // Rule 1: m.room.create must be the first event
    if event.event_type == "m.room.create" {
        if !event.prev_events.is_empty() {
            return Err(AuthError::CreateWithPrevEvents);
        }
        // Create events are always authorized if they're first
        return Ok(());
    }

    // Rule 2: Check sender is not banned
    if let Some(member_event) = state.get_event("m.room.member", Some(&event.sender)) {
        if let Some(membership) = member_event
            .content
            .get("membership")
            .and_then(|m| m.as_str())
        {
            if membership == "ban" {
                return Err(AuthError::BannedUser {
                    sender: event.sender.clone(),
                    event_id: event.event_id.clone(),
                });
            }

            // Rule 3: Sender must be joined (with exceptions for membership events)
            if event.event_type != "m.room.member" && membership != "join" {
                return Err(AuthError::NotMember {
                    sender: event.sender.clone(),
                    event_id: event.event_id.clone(),
                });
            }
        }
    } else if event.event_type != "m.room.member" {
        // Room version 11: The creator of the room has an implied membership of "join"
        // if no explicit membership event exists for them.
        let is_creator = state
            .get_event("m.room.create", Some(""))
            .is_some_and(|create_ev| create_ev.sender == event.sender);

        if !is_creator {
            return Err(AuthError::NotMember {
                sender: event.sender.clone(),
                event_id: event.event_id.clone(),
            });
        }
    }

    // Rule 4: Check power level requirements
    if event.event_type != "m.room.member" {
        let sender_pl = get_sender_power_level(&event.sender, state);
        let required_pl = get_required_power_level(event, state);

        let _pl_ev_id = state
            .get_event("m.room.power_levels", Some(""))
            .map_or_else(|| "NONE".into(), |ev| ev.event_id.clone());

        if sender_pl < required_pl {
            return Err(AuthError::InsufficientPowerLevel {
                required: required_pl,
                actual: sender_pl,
                event_type: event.event_type.clone(),
            });
        }
    }

    // Rule 5: m.room.member state_key validation
    if event.event_type == "m.room.member" {
        check_membership_rules(event, state)?;
    }

    Ok(())
}

const MAX_POWER_LEVEL: i64 = 9_007_199_254_740_991; // 2^53 - 1

/// Get the power level of a user from the current room state.
fn get_sender_power_level(sender: &str, state: &impl StateProvider) -> i64 {
    // 1. Absolute Priority: Room Creator and additional creators (INFINITE power)
    if let Some(create_event) = state.get_event("m.room.create", Some("")) {
        let is_primary_creator = create_event.sender == sender;
        let mut is_additional_creator = false;

        if let Some(creators) = create_event
            .content
            .get("room_creators")
            .and_then(|c| c.as_array())
        {
            if creators.iter().any(|c| c.as_str() == Some(sender)) {
                is_additional_creator = true;
            }
        }
        if let Some(creators) = create_event
            .content
            .get("additional_creators")
            .and_then(|c| c.as_array())
        {
            if creators.iter().any(|c| c.as_str() == Some(sender)) {
                is_additional_creator = true;
            }
        }

        if is_primary_creator || is_additional_creator {
            return MAX_POWER_LEVEL;
        }
    }

    // 2. State-based Power Levels
    if let Some(pl_event) = state.get_event("m.room.power_levels", Some("")) {
        if let Some(users) = pl_event.content.get("users").and_then(|u| u.as_object()) {
            if let Some(pl) = users.get(sender).and_then(serde_json::Value::as_i64) {
                return pl;
            }
        }
        // Fall back to users_default
        if let Some(default) = pl_event
            .content
            .get("users_default")
            .and_then(serde_json::Value::as_i64)
        {
            return default;
        }
    }
    0 // Default power level if no power_levels event exists
}

/// Get the required power level to send an event based on room state.
fn get_required_power_level(event: &LeanEvent, state: &impl StateProvider) -> i64 {
    if let Some(pl_event) = state.get_event("m.room.power_levels", Some("")) {
        // Check specific event type overrides
        if let Some(events) = pl_event.content.get("events").and_then(|e| e.as_object()) {
            if let Some(pl) = events
                .get(&event.event_type)
                .and_then(serde_json::Value::as_i64)
            {
                return pl;
            }
        }
        // Fall back to state_default for state events, events_default for others
        if event.state_key.is_some() {
            return pl_event
                .content
                .get("state_default")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(50);
        }
        return pl_event
            .content
            .get("events_default")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
    }
    // No restrictions if no power_levels event exists
    // However, Matrix spec says if NO PL event exists, state events require 50.
    if event.state_key.is_some() {
        50
    } else {
        0
    }
}

/// Validate membership transition rules for `m.room.member` events.
fn check_membership_rules(event: &LeanEvent, state: &impl StateProvider) -> Result<(), AuthError> {
    let target_user = event.state_key.as_deref().unwrap_or("");
    let new_membership = event
        .content
        .get("membership")
        .and_then(|m| m.as_str())
        .unwrap_or("");

    match new_membership {
        "join" => check_join_rules(event, state, target_user)?,
        "leave"
            // If target_user != sender, this is a kick — requires power level
            if target_user != event.sender => {
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
            if target_user == event.sender {
                return Err(AuthError::InvalidStateKey {
                    expected: alloc::format!("!= {}", event.sender),
                    actual: target_user.into(),
                });
            }

            let sender_pl = get_sender_power_level(&event.sender, state);
            let invite_pl = get_invite_power_level(state);
            if sender_pl < invite_pl {
                return Err(AuthError::InsufficientPowerLevel {
                    required: invite_pl,
                    actual: sender_pl,
                    event_type: "invite".into(),
                });
            }

            // Check target isn't already banned
            if let Some(target_member) = state.get_event("m.room.member", Some(target_user)) {
                if target_member
                    .content
                    .get("membership")
                    .and_then(|m| m.as_str())
                    == Some("ban")
                {
                    return Err(AuthError::BannedUser {
                        sender: target_user.into(),
                        event_id: event.event_id.clone(),
                    });
                }
            }
        }
        _ => {}
    }

    // If target_user != event.sender and the transition is a kick, ban, or unban (membership is leave or ban),
    // check sender power level against target user and existing membership sender.
    if target_user != event.sender && (new_membership == "leave" || new_membership == "ban") {
        let sender_pl = get_sender_power_level(&event.sender, state);

        // 1. Sender power level must be strictly greater than target power level.
        let target_pl = get_sender_power_level(target_user, state);
        if sender_pl <= target_pl {
            return Err(AuthError::InsufficientPowerLevel {
                required: target_pl.saturating_add(1),
                actual: sender_pl,
                event_type: "m.rezzy.member_pl_greater_than_target".into(),
            });
        }

        // 2. If the target has a current active membership (joined, invited, or banned),
        // sender power level must be strictly greater than the power level of the user who set the current membership.
        if let Some(current_member_event) = state.get_event("m.room.member", Some(target_user)) {
            if let Some(current_membership) = current_member_event
                .content
                .get("membership")
                .and_then(|m| m.as_str())
            {
                if current_membership == "join"
                    || current_membership == "invite"
                    || current_membership == "ban"
                {
                    let current_sender_pl =
                        get_sender_power_level(&current_member_event.sender, state);
                    if sender_pl <= current_sender_pl {
                        return Err(AuthError::InsufficientPowerLevel {
                            required: current_sender_pl.saturating_add(1),
                            actual: sender_pl,
                            event_type: "m.rezzy.member_pl_greater_than_current_sender".into(),
                        });
                    }
                }
            }
        }
    }

    Ok(())
}

fn check_join_rules(
    event: &LeanEvent,
    state: &impl StateProvider,
    target_user: &str,
) -> Result<(), AuthError> {
    // A user can only join as themselves
    if target_user != event.sender {
        return Err(AuthError::InvalidStateKey {
            expected: event.sender.clone(),
            actual: target_user.into(),
        });
    }

    let current_membership = state
        .get_event("m.room.member", Some(target_user))
        .and_then(|ev| ev.content.get("membership"))
        .and_then(|m| m.as_str())
        .unwrap_or("");

    if current_membership == "ban" {
        return Err(AuthError::BannedUser {
            sender: event.sender.clone(),
            event_id: event.event_id.clone(),
        });
    }

    let join_rule = state
        .get_event("m.room.join_rules", Some(""))
        .and_then(|ev| ev.content.get("join_rule"))
        .and_then(|r| r.as_str())
        .unwrap_or("invite"); // Default to invite

    let is_creator = state
        .get_event("m.room.create", Some(""))
        .is_some_and(|ev| ev.sender == event.sender);

    if is_creator {
        // Room creator can always join
    } else if join_rule == "invite" || join_rule == "knock" {
        if current_membership == "invite" || current_membership == "join" {
            // Allowed
        } else {
            return Err(AuthError::NotMember {
                sender: event.sender.clone(),
                event_id: event.event_id.clone(),
            });
        }
    } else if join_rule != "public" {
        return Err(AuthError::NotMember {
            sender: event.sender.clone(),
            event_id: event.event_id.clone(),
        });
    }
    Ok(())
}

/// Get the kick power level from room state.
fn get_kick_power_level(state: &impl StateProvider) -> i64 {
    if let Some(pl_event) = state.get_event("m.room.power_levels", Some("")) {
        if let Some(kick) = pl_event
            .content
            .get("kick")
            .and_then(serde_json::Value::as_i64)
        {
            return kick;
        }
    }
    50 // Default kick power level per Matrix spec
}

/// Get the ban power level from room state.
fn get_invite_power_level(state: &impl StateProvider) -> i64 {
    if let Some(pl_event) = state.get_event("m.room.power_levels", Some("")) {
        if let Some(invite) = pl_event
            .content
            .get("invite")
            .and_then(serde_json::Value::as_i64)
        {
            return invite;
        }
    }
    0 // Default invite power level per Matrix spec (v12)
}

fn get_ban_power_level(state: &impl StateProvider) -> i64 {
    if let Some(pl_event) = state.get_event("m.room.power_levels", Some("")) {
        if let Some(ban) = pl_event
            .content
            .get("ban")
            .and_then(serde_json::Value::as_i64)
        {
            return ban;
        }
    }
    50 // Default ban power level per Matrix spec
}

/// Iteratively apply auth checks to a list of events in topological order.
/// Returns the list of events that passed auth checks, and the list that failed
/// with their respective errors.
#[must_use]
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
                // Apply event to state if it's a state event
                if let Some(state_key) = &event.state_key {
                    state.insert(
                        (event.event_type.clone(), Some(state_key.clone())),
                        event.clone(),
                    );
                } else if event.event_type == "m.room.create" {
                    // Fallback for m.room.create if it somehow lacks a state_key
                    state.insert(
                        (event.event_type.clone(), Some(String::new())),
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

/// Returns the state event types required to authorize an event.
/// Equivalent to Ruma's `state_res::auth_types_for_event`.
#[must_use]
pub fn auth_types_for_event(
    event_type: &str,
    sender: &str,
    state_key: Option<&str>,
    content: &serde_json::Value,
) -> Vec<(String, String)> {
    let mut auth_types = Vec::new();

    if event_type == "m.room.create" {
        return auth_types;
    }

    auth_types.push((String::from("m.room.create"), String::new()));
    auth_types.push((String::from("m.room.member"), String::from(sender)));
    auth_types.push((String::from("m.room.power_levels"), String::new()));

    if event_type == "m.room.member" {
        if let Some(sk) = state_key {
            if sender != sk {
                auth_types.push((String::from("m.room.member"), String::from(sk)));
            }
        }

        let membership = content.get("membership").and_then(|v| v.as_str());
        if membership == Some("join") || membership == Some("invite") {
            auth_types.push((String::from("m.room.join_rules"), String::new()));
        }

        let third_party_invite = content
            .get("third_party_invite")
            .and_then(|v| v.as_object());
        if let Some(tpi) = third_party_invite {
            if let Some(token) = tpi
                .get("signed")
                .and_then(|s| s.as_object())
                .and_then(|s| s.get("token"))
                .and_then(|t| t.as_str())
            {
                auth_types.push((
                    String::from("m.room.third_party_invite"),
                    String::from(token),
                ));
            }
        }
    }

    auth_types
}
