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
//! their `prev_events` — never the current time.

pub mod roaring;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::basespec::event_types::{
    DEFAULT_PL_BAN, DEFAULT_PL_INVITE, DEFAULT_PL_KICK, DEFAULT_PL_USER, FIELD_MEMBERSHIP,
    FIELD_SIGNED, FIELD_THIRD_PARTY_INVITE, FIELD_TOKEN, MEM_BAN, MEM_INVITE, MEM_JOIN, MEM_KNOCK,
    MEM_LEAVE, M_ROOM_CREATE, M_ROOM_JOIN_RULES, M_ROOM_MEMBER, M_ROOM_POWER_LEVELS,
    M_ROOM_THIRD_PARTY_INVITE, RULE_INVITE, RULE_KNOCK, RULE_KNOCK_RESTRICTED, RULE_PUBLIC,
    RULE_RESTRICTED,
};
use crate::basespec::rezzy_types::LeanEvent;
use crate::basespec::rezzy_types::StateResVersion;

/// An error indicating why an event failed authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError<Id = String> {
    /// The sender is not a member of the room (or membership is not "join").
    NotMember { sender: String, event_id: Id },
    /// The sender's power level is below the required level for this event type.
    InsufficientPowerLevel {
        required: i64,
        actual: i64,
        event_type: String,
    },
    /// The sender is banned from the room.
    BannedUser { sender: String, event_id: Id },
    /// For `m.room.member` events, the `state_key` doesn't match the expected
    /// user ID for the given membership transition.
    InvalidStateKey { expected: String, actual: String },
    /// The `m.room.create` event has `prev_events`, which is forbidden.
    CreateWithPrevEvents,
    /// An auth event referenced by this event is missing from the provided state.
    MissingAuthEvent(Id),
    /// The event failed basic syntactic validation (e.g. invalid event type, too many `prev_events`).
    InvalidSyntax(String),
}

impl<Id: fmt::Display> fmt::Display for AuthError<Id> {
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

/// Trait for zero-copy lookups into `BTreeMap<(String, String), _>`.
///
/// This enables querying a `BTreeMap` keyed by owned `(String, String)`
/// using borrowed `(&str, &str)` tuples — avoiding allocation for
/// every state lookup during auth checking.
pub trait StateKeyDyn {
    /// The event type (e.g. `"m.room.member"`).
    fn ev_type(&self) -> &str;
    /// The state key (e.g. `"@alice:example.com"` or `""`).
    fn state_key(&self) -> &str;
}

impl StateKeyDyn for (String, String) {
    fn ev_type(&self) -> &str {
        &self.0
    }
    fn state_key(&self) -> &str {
        &self.1
    }
}

impl<'a> StateKeyDyn for (&'a str, &'a str) {
    fn ev_type(&self) -> &str {
        self.0
    }
    fn state_key(&self) -> &str {
        self.1
    }
}

impl<'a> Borrow<dyn StateKeyDyn + 'a> for (String, String) {
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
            .then_with(|| self.state_key().cmp(other.state_key()))
    }
}

/// Trait for providing room state to the authorization engine.
///
/// Implementors supply state events by `(event_type, state_key)` lookups.
/// The built-in implementation is [`RoomState`] (a `BTreeMap`), but the
/// resolution engine uses a more complex `OverlayState` internally
/// that layers resolved state, local auth context, and the create event.
pub trait StateProvider<Id = String, C = serde_json::Value> {
    /// Look up a state event by its type and state key.
    fn get_event(&self, event_type: &str, state_key: &str) -> Option<&LeanEvent<Id, C>>;
}

/// The room state at a specific point in the DAG (keyed by (type, `state_key`) -> event).
pub type RoomState<Id = String, C = serde_json::Value> =
    alloc::collections::BTreeMap<(String, String), LeanEvent<Id, C>>;

impl<Id, C> StateProvider<Id, C> for RoomState<Id, C> {
    fn get_event(&self, event_type: &str, state_key: &str) -> Option<&LeanEvent<Id, C>> {
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
pub fn check_auth<Id: Clone, C: crate::basespec::rezzy_types::EventContent>(
    event: &LeanEvent<Id, C>,
    state: &impl StateProvider<Id, C>,
    version: StateResVersion,
    verifier: Option<&dyn crate::basespec::rezzy_types::EventVerifier<Id>>,
) -> Result<(), AuthError<Id>> {
    // Rule 0: Custom syntactic validation
    event
        .validate_syntactic()
        .map_err(|e| AuthError::InvalidSyntax(e.into()))?;

    // Optional verification pipeline (steps 1-3).
    // Callers pass None during state resolution; Some during PDU receipt.
    // TODO: different room versions use different hashing algorithms for event IDs:
    //   - v1-v3: event IDs are opaque (assigned by origin server, no hash verification)
    //   - v4:    SHA256 reference hash (URL-safe unpadded base64)
    //   - v5+:   SHA256 reference hash (URL-safe unpadded base64, but with different
    //            redaction rules affecting which fields are stripped before hashing)
    //   Pass `version` to the verifier once per-version hashing is supported.
    if let Some(v) = verifier {
        v.verify_event_id_hash(&event.event_id)
            .map_err(AuthError::InvalidSyntax)?;
        v.verify_signatures(&event.event_id)
            .map_err(AuthError::InvalidSyntax)?;
        v.verify_content_hash(&event.event_id)
            .map_err(AuthError::InvalidSyntax)?;
    }

    // Rule 1: m.room.create must be the first event
    if event.event_type == "m.room.create" {
        if !event.prev_events.is_empty() {
            return Err(AuthError::CreateWithPrevEvents);
        }
        // Create events are always authorized if they're first
        return Ok(());
    }

    // Rule 2: Check sender is not banned, and Rule 3: Sender must be joined
    let sender_member_event = state.get_event(M_ROOM_MEMBER, &event.sender);

    // Determine the effective membership string
    let mut membership = sender_member_event
        .and_then(|ev| ev.get_membership())
        .unwrap_or(MEM_LEAVE);

    // Exceptions: Room v11 implied creator join only applies when there is no membership event
    if sender_member_event.is_none() {
        let is_creator = state
            .get_event(M_ROOM_CREATE, "")
            .is_some_and(|create_ev| create_ev.sender == event.sender);
        if is_creator {
            membership = MEM_JOIN;
        }
    }

    if membership == MEM_BAN {
        return Err(AuthError::BannedUser {
            sender: event.sender.clone(),
            event_id: event.event_id.clone(),
        });
    }

    // Rule 3: Sender must be joined (with exceptions for self-membership events)
    if membership != MEM_JOIN {
        // Exceptions: Self-membership transitions (except ban).
        let is_self_membership = event.event_type == M_ROOM_MEMBER
            && event.state_key.as_deref() == Some(&event.sender)
            && event.get_membership() != Some(MEM_BAN);

        if !is_self_membership {
            return Err(AuthError::NotMember {
                sender: event.sender.clone(),
                event_id: event.event_id.clone(),
            });
        }
    }

    // Rule 4: Check power level requirements
    // Skip for m.room.member (handled separately in check_membership_rules).
    // Also skip for m.room.power_levels when no PL event exists in state:
    // the spec's Rule 10.2 says "If there is no previous m.room.power_levels
    // event in the room, allow", which takes precedence over Rule 8's generic
    // PL check. Without this, the bootstrap PL event can never pass auth.
    if event.event_type != M_ROOM_MEMBER {
        let no_pl_event = state.get_event(M_ROOM_POWER_LEVELS, "").is_none();
        let is_first_pl = no_pl_event && event.event_type == M_ROOM_POWER_LEVELS;

        if !is_first_pl {
            let sender_pl = get_sender_power_level(&event.sender, state, version);
            let required_pl = get_required_power_level(event, state);

            if sender_pl < required_pl {
                return Err(AuthError::InsufficientPowerLevel {
                    required: required_pl,
                    actual: sender_pl,
                    event_type: event.event_type.clone(),
                });
            }
        }
    }

    // Rule 4b (spec §rule 9, all versions): If the event has a state_key
    // that starts with '@' and does not match the sender, reject.
    if event.event_type != M_ROOM_MEMBER {
        if let Some(ref sk) = event.state_key {
            if sk.starts_with('@') && sk != &event.sender {
                return Err(AuthError::InvalidStateKey {
                    expected: event.sender.clone(),
                    actual: sk.clone(),
                });
            }
        }
    }

    // Rule 5: m.room.member state_key validation
    if event.event_type == M_ROOM_MEMBER {
        check_membership_rules(event, state, version, verifier)?;
    }

    Ok(())
}

/// Re-export from [`crate::basespec::event_types`] for backwards compatibility.
pub use crate::basespec::event_types::{MAX_POWER_LEVEL_JSON, MAX_POWER_LEVEL_RUST};

/// Get the power level of a user from the current room state.
fn get_sender_power_level<Id, C: crate::basespec::rezzy_types::EventContent>(
    sender: &str,
    state: &impl StateProvider<Id, C>,
    version: StateResVersion,
) -> i64 {
    // V12+ (MSC4289): creators have spec-mandated infinite power level,
    // immutable and not representable in the PL event.
    if matches!(
        version,
        StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2
    ) {
        if let Some(create_event) = state.get_event(M_ROOM_CREATE, "") {
            let is_creator =
                create_event.sender == sender || create_event.has_additional_creator(sender);

            if is_creator {
                // Use i64::MAX (not 2^53-1) so the creator always wins power
                // comparisons, even against a malicious PL event that sets a
                // user to the JSON-safe maximum. Incoming values are clamped
                // to MAX_POWER_LEVEL_JSON on deserialization, so this is
                // strictly unreachable by any wire value.
                return MAX_POWER_LEVEL_RUST;
            }
        }
    }

    // State-based Power Levels (all versions)
    // V1-V11: the auth rules have no implicit creator PL. The creator gets
    // PL 100 only because the server explicitly lists them in the PL event's
    // `users` map at room creation. If the PL event doesn't list them, they
    // fall through to `users_default` like any other user.
    if let Some(pl_event) = state.get_event(M_ROOM_POWER_LEVELS, "") {
        if let Some(pl) = pl_event.get_user_power_level(sender) {
            return pl;
        }
        // Fall back to users_default
        if let Some(default_pl) = pl_event.get_users_default() {
            return default_pl;
        }
    }
    return DEFAULT_PL_USER; // Default power level if no power_levels event exists
}

/// Get the required power level to send an event based on room state.
fn get_required_power_level<Id, C: crate::basespec::rezzy_types::EventContent>(
    event: &LeanEvent<Id, C>,
    state: &impl StateProvider<Id, C>,
) -> i64 {
    if let Some(pl_event) = state.get_event(M_ROOM_POWER_LEVELS, "") {
        // Spec Rule 7: m.room.third_party_invite events require the invite level
        if event.event_type == crate::basespec::event_types::M_ROOM_THIRD_PARTY_INVITE {
            return pl_event.get_invite().unwrap_or(0); // 0 is the default invite level
        }
        // Check specific event type overrides
        if let Some(pl) = pl_event.get_event_power_level(&event.event_type) {
            return pl;
        }
        // Fall back to state_default for state events, events_default for others
        if event.state_key.is_some() {
            return pl_event.get_state_default().unwrap_or(50);
        }
        return pl_event.get_events_default().unwrap_or(0);
    }
    // No restrictions if no power_levels event exists
    // However, Matrix spec says if NO PL event exists, state events require 50.
    if event.event_type == crate::basespec::event_types::M_ROOM_THIRD_PARTY_INVITE {
        0 // Spec Rule 7: m.room.third_party_invite defaults to 0
    } else if event.state_key.is_some() {
        50
    } else {
        0
    }
}

/// Validate leave/kick transition rules.
fn check_leave_rules<Id: Clone, C: crate::basespec::rezzy_types::EventContent>(
    event: &LeanEvent<Id, C>,
    state: &impl StateProvider<Id, C>,
    target_user: &str,
    current_membership: &str,
    version: StateResVersion,
) -> Result<(), AuthError<Id>> {
    // Rule 5.5.1: self-leave is allowed only from invite, join, or knock.
    if target_user == event.sender {
        return match current_membership {
            MEM_INVITE | MEM_JOIN | MEM_KNOCK => Ok(()),
            _ => Err(AuthError::NotMember {
                sender: event.sender.clone(),
                event_id: event.event_id.clone(),
            }),
        };
    }

    // If target_user != sender, this is a kick or unban — requires power level
    let sender_pl = get_sender_power_level(&event.sender, state, version);

    // Unban: requires ban_pl. Kick: requires kick_pl.
    // Mutually exclusive per spec §10.2.1.
    let (required, label) = if current_membership == "ban" {
        (get_ban_power_level(state), "unban")
    } else {
        (get_kick_power_level(state), "kick")
    };

    if sender_pl < required {
        return Err(AuthError::InsufficientPowerLevel {
            required,
            actual: sender_pl,
            event_type: label.into(),
        });
    }

    Ok(())
}

/// Validate ban transition rules.
fn check_ban_rules<Id: Clone, C: crate::basespec::rezzy_types::EventContent>(
    event: &LeanEvent<Id, C>,
    state: &impl StateProvider<Id, C>,
    version: StateResVersion,
) -> Result<(), AuthError<Id>> {
    // Banning requires the ban power level
    let sender_pl = get_sender_power_level(&event.sender, state, version);
    let ban_pl = get_ban_power_level(state);
    if sender_pl < ban_pl {
        return Err(AuthError::InsufficientPowerLevel {
            required: ban_pl,
            actual: sender_pl,
            event_type: "ban".into(),
        });
    }
    Ok(())
}

/// Validate invite transition rules.
fn check_invite_rules<Id: Clone, C: crate::basespec::rezzy_types::EventContent>(
    event: &LeanEvent<Id, C>,
    state: &impl StateProvider<Id, C>,
    target_user: &str,
    current_membership: &str,
    version: StateResVersion,
    verifier: Option<&dyn crate::basespec::rezzy_types::EventVerifier<Id>>,
) -> Result<(), AuthError<Id>> {
    // Inviting requires invite power level, and sender != target
    if target_user == event.sender {
        return Err(AuthError::InvalidStateKey {
            expected: alloc::format!("!= {}", event.sender),
            actual: target_user.into(),
        });
    }

    let invite_pl = get_invite_power_level(state);

    // Rule 5.4.1: If third_party_invite is present, check the issuer's power level.
    // It must strictly adhere to the rules, or be rejected. No fallback.
    if event.content.has_third_party_invite() {
        // Rule 5.4.1.1: If target user is banned, reject.
        if current_membership == MEM_BAN {
            return Err(AuthError::BannedUser {
                sender: target_user.into(),
                event_id: event.event_id.clone(),
            });
        }

        let token = event
            .content
            .get_third_party_invite_token()
            .ok_or_else(|| {
                AuthError::InvalidSyntax("invalid third_party_invite: missing signed.token".into())
            })?;

        let mxid = event.content.get_third_party_invite_mxid().ok_or_else(|| {
            AuthError::InvalidSyntax("invalid third_party_invite: missing signed.mxid".into())
        })?;

        if !event.content.has_third_party_invite_signatures() {
            return Err(AuthError::InvalidSyntax(
                "invalid third_party_invite: missing or empty signed.signatures".into(),
            ));
        }

        // Optional verification pipeline (step 4): 3PI signature verification.
        if let Some(v) = verifier {
            v.verify_third_party_invite(&event.event_id, token)
                .map_err(AuthError::InvalidSyntax)?;
        }

        if mxid != target_user {
            return Err(AuthError::InvalidStateKey {
                expected: alloc::format!("mxid == {target_user}"),
                actual: mxid.into(),
            });
        }

        let tpi_event = state
            .get_event(
                crate::basespec::event_types::M_ROOM_THIRD_PARTY_INVITE,
                token,
            )
            .ok_or_else(|| AuthError::InvalidStateKey {
                expected: "m.room.third_party_invite event exists".into(),
                actual: "missing".into(),
            })?;

        if tpi_event.sender != event.sender {
            return Err(AuthError::InvalidStateKey {
                expected: alloc::format!("sender == {}", tpi_event.sender),
                actual: event.sender.clone(),
            });
        }

        let issuer_pl = get_sender_power_level(&tpi_event.sender, state, version);
        if issuer_pl < invite_pl {
            return Err(AuthError::InsufficientPowerLevel {
                required: invite_pl,
                actual: issuer_pl,
                event_type: "invite".into(),
            });
        }

        return Ok(()); // 3PI validation passed! Do not fall through.
    }

    let sender_pl = get_sender_power_level(&event.sender, state, version);
    if sender_pl < invite_pl {
        return Err(AuthError::InsufficientPowerLevel {
            required: invite_pl,
            actual: sender_pl,
            event_type: "invite".into(),
        });
    }

    // Check target isn't already joined or banned
    if current_membership == MEM_JOIN {
        return Err(AuthError::NotMember {
            sender: target_user.into(),
            event_id: event.event_id.clone(),
        });
    }
    if current_membership == MEM_BAN {
        return Err(AuthError::BannedUser {
            sender: target_user.into(),
            event_id: event.event_id.clone(),
        });
    }
    Ok(())
}

/// Validate sender power level hierarchies (sender PL vs target PL, and previous sender rules).
fn check_membership_pl_hierarchies<Id: Clone, C: crate::basespec::rezzy_types::EventContent>(
    event: &LeanEvent<Id, C>,
    state: &impl StateProvider<Id, C>,
    target_user: &str,
    new_membership: &str,
    version: StateResVersion,
) -> Result<(), AuthError<Id>> {
    // 1. Kick/Ban power vs Target power: ONLY for "leave" (kick) or "ban" transitions.
    if target_user != event.sender && (new_membership == "leave" || new_membership == "ban") {
        let sender_pl = get_sender_power_level(&event.sender, state, version);
        let target_pl = get_sender_power_level(target_user, state, version);

        if sender_pl <= target_pl {
            return Err(AuthError::InsufficientPowerLevel {
                required: target_pl.saturating_add(1),
                actual: sender_pl,
                event_type: "m.rezzy.member_pl_greater_than_target".into(),
            });
        }
    }

    // NOTE: The spec does not mandate a "previous sender" check.
    // A moderator (PL 50) can unban or re-ban a user previously banned by an admin (PL 100),
    // as long as the moderator meets the standard ban/kick PL requirements and has PL > target PL.
    // See Matrix spec room v12 §5.5 (leave) and §5.6 (ban).

    Ok(())
}

/// Validate membership transition rules for `m.room.member` events.
fn check_membership_rules<Id: Clone, C: crate::basespec::rezzy_types::EventContent>(
    event: &LeanEvent<Id, C>,
    state: &impl StateProvider<Id, C>,
    version: StateResVersion,
    verifier: Option<&dyn crate::basespec::rezzy_types::EventVerifier<Id>>,
) -> Result<(), AuthError<Id>> {
    let target_user = event.state_key.as_deref().unwrap_or("");
    let new_membership = event.get_membership().unwrap_or("");

    let current_membership = state
        .get_event(M_ROOM_MEMBER, target_user)
        .and_then(|ev| ev.get_membership())
        .unwrap_or("");

    // Self-bans are nonsensical and forbidden by the spec.
    if new_membership == MEM_BAN && target_user == event.sender {
        return Err(AuthError::InvalidStateKey {
            expected: alloc::format!("!= {}", event.sender),
            actual: target_user.into(),
        });
    }

    match new_membership {
        MEM_JOIN => check_join_rules(event, state, target_user, version)?,
        MEM_LEAVE => check_leave_rules(event, state, target_user, current_membership, version)?,
        MEM_BAN => check_ban_rules(event, state, version)?,
        MEM_INVITE => check_invite_rules(
            event,
            state,
            target_user,
            current_membership,
            version,
            verifier,
        )?,
        MEM_KNOCK => check_knock_rules(event, state, target_user)?,
        // Rule 5.8: Unknown membership — reject
        _ => {
            return Err(AuthError::InvalidSyntax(alloc::format!(
                "unknown membership: {new_membership}"
            )));
        }
    }

    check_membership_pl_hierarchies(event, state, target_user, new_membership, version)?;

    Ok(())
}

fn check_join_rules<Id: Clone, C: crate::basespec::rezzy_types::EventContent>(
    event: &LeanEvent<Id, C>,
    state: &impl StateProvider<Id, C>,
    target_user: &str,
    version: StateResVersion,
) -> Result<(), AuthError<Id>> {
    // A user can only join as themselves
    if target_user != event.sender {
        return Err(AuthError::InvalidStateKey {
            expected: event.sender.clone(),
            actual: target_user.into(),
        });
    }

    let current_membership = state
        .get_event("m.room.member", target_user)
        .and_then(|ev| ev.get_membership())
        .unwrap_or("");

    if current_membership == MEM_BAN {
        return Err(AuthError::BannedUser {
            sender: event.sender.clone(),
            event_id: event.event_id.clone(),
        });
    }

    let join_rule = state
        .get_event(M_ROOM_JOIN_RULES, "")
        .and_then(|ev| ev.get_join_rule())
        .unwrap_or(RULE_INVITE); // Default to invite

    let is_creator = state
        .get_event(M_ROOM_CREATE, "")
        .is_some_and(|ev| ev.sender == event.sender);

    if is_creator {
        // Room creator can always join
    } else if join_rule == RULE_INVITE || join_rule == RULE_KNOCK {
        if current_membership == MEM_INVITE || current_membership == MEM_JOIN {
            // Allowed
        } else {
            return Err(AuthError::NotMember {
                sender: event.sender.clone(),
                event_id: event.event_id.clone(),
            });
        }
    } else if join_rule == RULE_RESTRICTED || join_rule == RULE_KNOCK_RESTRICTED {
        // Restricted/knock_restricted (room version 8+/10+):
        // Allow if user is already invited/joined. Otherwise, require a valid
        // join_authorised_via_users_server field whose referenced user is:
        //   1. Joined to the room, AND
        //   2. Has sufficient power level to invite.
        if current_membership == MEM_INVITE || current_membership == MEM_JOIN {
            // Already invited or joined — allowed without further checks.
        } else if let Some(authorising_user) = event.get_join_authorised_via_users_server() {
            check_authorising_user(event, state, authorising_user, version)?;
        } else {
            return Err(AuthError::NotMember {
                sender: event.sender.clone(),
                event_id: event.event_id.clone(),
            });
        }
    } else if join_rule != RULE_PUBLIC {
        return Err(AuthError::NotMember {
            sender: event.sender.clone(),
            event_id: event.event_id.clone(),
        });
    }
    Ok(())
}

/// Validate that the authorising user for a restricted join is joined to the
/// room and has sufficient power level to invite (MSC3083).
fn check_authorising_user<Id: Clone, C: crate::basespec::rezzy_types::EventContent>(
    event: &LeanEvent<Id, C>,
    state: &impl StateProvider<Id, C>,
    authorising_user: &str,
    version: StateResVersion,
) -> Result<(), AuthError<Id>> {
    let auth_membership = state
        .get_event(M_ROOM_MEMBER, authorising_user)
        .and_then(|ev| ev.get_membership())
        .unwrap_or("");

    if auth_membership != MEM_JOIN {
        return Err(AuthError::NotMember {
            sender: event.sender.clone(),
            event_id: event.event_id.clone(),
        });
    }

    // Use get_sender_power_level to correctly handle V12 implicit creator PL
    let auth_user_pl = get_sender_power_level(authorising_user, state, version);
    if auth_user_pl < get_invite_power_level(state) {
        return Err(AuthError::NotMember {
            sender: event.sender.clone(),
            event_id: event.event_id.clone(),
        });
    }

    Ok(())
}

/// Validate knock rules: knocking is only allowed when `join_rule` is
/// `knock` or `knock_restricted` (room versions 7+ / 10+).
fn check_knock_rules<Id: Clone, C: crate::basespec::rezzy_types::EventContent>(
    event: &LeanEvent<Id, C>,
    state: &impl StateProvider<Id, C>,
    target_user: &str,
) -> Result<(), AuthError<Id>> {
    // A user can only knock as themselves
    if target_user != event.sender {
        return Err(AuthError::InvalidStateKey {
            expected: event.sender.clone(),
            actual: target_user.into(),
        });
    }

    let current_membership = state
        .get_event(M_ROOM_MEMBER, target_user)
        .and_then(|ev| ev.get_membership())
        .unwrap_or("");

    // MSC2403 §f.iii: allow only if membership is NOT ban, invite, or join.
    if current_membership == MEM_BAN {
        return Err(AuthError::BannedUser {
            sender: event.sender.clone(),
            event_id: event.event_id.clone(),
        });
    }

    if current_membership == MEM_INVITE || current_membership == MEM_JOIN {
        return Err(AuthError::NotMember {
            sender: event.sender.clone(),
            event_id: event.event_id.clone(),
        });
    }

    let join_rule = state
        .get_event(M_ROOM_JOIN_RULES, "")
        .and_then(|ev| ev.get_join_rule())
        .unwrap_or(RULE_INVITE);

    if join_rule != RULE_KNOCK && join_rule != RULE_KNOCK_RESTRICTED {
        return Err(AuthError::NotMember {
            sender: event.sender.clone(),
            event_id: event.event_id.clone(),
        });
    }

    Ok(())
}

/// Get the kick power level from room state.
fn get_kick_power_level<Id, C: crate::basespec::rezzy_types::EventContent>(
    state: &impl StateProvider<Id, C>,
) -> i64 {
    if let Some(pl_event) = state.get_event(M_ROOM_POWER_LEVELS, "") {
        if let Some(kick) = pl_event.get_kick() {
            return kick;
        }
    }
    DEFAULT_PL_KICK // Default kick power level per Matrix spec
}

/// Get the ban power level from room state.
fn get_invite_power_level<Id, C: crate::basespec::rezzy_types::EventContent>(
    state: &impl StateProvider<Id, C>,
) -> i64 {
    if let Some(pl_event) = state.get_event(M_ROOM_POWER_LEVELS, "") {
        if let Some(invite) = pl_event.get_invite() {
            return invite;
        }
    }
    DEFAULT_PL_INVITE // Default invite power level per Matrix spec
}

fn get_ban_power_level<Id, C: crate::basespec::rezzy_types::EventContent>(
    state: &impl StateProvider<Id, C>,
) -> i64 {
    if let Some(pl_event) = state.get_event(M_ROOM_POWER_LEVELS, "") {
        if let Some(ban) = pl_event.get_ban() {
            return ban;
        }
    }
    DEFAULT_PL_BAN // Default ban power level per Matrix spec
}

/// Iteratively apply auth checks to a list of events in topological order.
/// Returns the list of events that passed auth checks, and the list that failed
/// with their respective errors.
#[must_use]
pub fn check_auth_chain<Id: Clone + Ord, C: crate::basespec::rezzy_types::EventContent>(
    sorted_events: &[LeanEvent<Id, C>],
    initial_state: &RoomState<Id, C>,
    version: StateResVersion,
) -> (Vec<Id>, Vec<(Id, AuthError<Id>)>) {
    let mut state = initial_state.clone();
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();

    for event in sorted_events {
        match check_auth(event, &state, version, None) {
            Ok(()) => {
                // Apply event to state if it's a state event
                if let Some(state_key) = &event.state_key {
                    state.insert((event.event_type.clone(), state_key.clone()), event.clone());
                } else if event.event_type == M_ROOM_CREATE {
                    // Fallback for m.room.create if it somehow lacks a state_key
                    state.insert((event.event_type.clone(), String::new()), event.clone());
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

/// Warns to stderr if an event's `auth_events` reference types outside the
/// spec-expected subset. For v12+, `m.room.create` in `auth_events` is a hard reject (spec rule 3.2).
#[cfg(all(feature = "std", not(test), not(tarpaulin)))]
pub fn warn_unexpected_auth_events<
    Id: core::fmt::Debug + Clone + Eq + core::hash::Hash,
    C: crate::basespec::rezzy_types::EventContent,
>(
    event: &LeanEvent<Id, C>,
    auth_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C>,
    version: StateResVersion,
) {
    const VALID_AUTH_TYPES: &[&str] = &[
        M_ROOM_CREATE, // NOTE: only valid pre-v12 rooms
        M_ROOM_MEMBER,
        M_ROOM_POWER_LEVELS,
        M_ROOM_JOIN_RULES,
        M_ROOM_THIRD_PARTY_INVITE,
    ];

    let v12_plus = matches!(
        version,
        StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2
    );

    for auth_id in &event.auth_events {
        if let Some(auth_ev) = auth_context.get_event(auth_id) {
            // Broken v12 invariant
            if v12_plus && auth_ev.event_type == M_ROOM_CREATE {
                std::eprintln!(
                    "REZZY_ERROR: event {:?} references m.room.create in auth_events (forbidden in v12+)",
                    event.event_id,
                );
            } else if !VALID_AUTH_TYPES.contains(&auth_ev.event_type.as_str()) {
                std::eprintln!(
                    "REZZY_WARN: event {:?} has unexpected auth type: {}",
                    event.event_id,
                    auth_ev.event_type,
                );
            }
        }
    }
}

/// Returns the state event types required to authorize an event.
///
/// For state resolution V2.1 and later, `m.room.create` is no longer
/// included in auth events. The room's existence is implied via `room_id`.
///
/// Equivalent to Ruma's `state_res::auth_types_for_event`.
#[must_use]
pub fn auth_types_for_event(
    event_type: &str,
    sender: &str,
    state_key: Option<&str>,
    content: &serde_json::Value,
    version: StateResVersion,
) -> Vec<(String, String)> {
    let mut auth_types = Vec::new();

    if event_type == M_ROOM_CREATE {
        return auth_types;
    }

    // V2.1+ omits m.room.create from auth events (spec change)
    if !matches!(
        version,
        StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2
    ) {
        auth_types.push((M_ROOM_CREATE.into(), String::new()));
    }
    auth_types.push((M_ROOM_MEMBER.into(), sender.into()));
    auth_types.push((M_ROOM_POWER_LEVELS.into(), String::new()));

    if event_type == M_ROOM_MEMBER {
        if let Some(sk) = state_key {
            if sk != sender {
                auth_types.push((M_ROOM_MEMBER.into(), sk.into()));
            }
        }

        let membership = content.get(FIELD_MEMBERSHIP).and_then(|v| v.as_str());

        if membership == Some(MEM_JOIN)
            || membership == Some(MEM_INVITE)
            || membership == Some(MEM_KNOCK)
        {
            auth_types.push((M_ROOM_JOIN_RULES.into(), String::new()));
        }

        if let Some(tpi) = content
            .get(FIELD_THIRD_PARTY_INVITE)
            .and_then(|t| t.as_object())
        {
            if let Some(token) = tpi
                .get(FIELD_SIGNED)
                .and_then(|s| s.as_object())
                .and_then(|s| s.get(FIELD_TOKEN))
                .and_then(|t| t.as_str())
            {
                auth_types.push((M_ROOM_THIRD_PARTY_INVITE.into(), token.into()));
            }
        }
    }

    auth_types
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_test_event(
        id: &str,
        ev_type: &str,
        sender: &str,
        content: serde_json::Value,
    ) -> LeanEvent {
        LeanEvent {
            event_id: id.into(),
            event_type: ev_type.into(),
            sender: sender.into(),
            content,
            ..Default::default()
        }
    }

    #[test]
    fn test_msc4289_creator_has_i64_max_power() {
        let mut state = RoomState::new();
        state.insert(
            (M_ROOM_CREATE.into(), String::new()),
            make_test_event(
                "$create",
                M_ROOM_CREATE,
                "@creator:example.com",
                json!({
                    "room_version": "12",
                    "creator": "@creator:example.com",
                    "additional_creators": ["@additional:example.com"]
                }),
            ),
        );

        // Assert that the primary creator gets i64::MAX
        let creator_pl =
            get_sender_power_level("@creator:example.com", &state, StateResVersion::V2_1);
        assert_eq!(
            creator_pl,
            i64::MAX,
            "Primary creator should have i64::MAX power"
        );

        // Assert that the additional creator gets i64::MAX
        let additional_pl =
            get_sender_power_level("@additional:example.com", &state, StateResVersion::V2_1);
        assert_eq!(
            additional_pl,
            i64::MAX,
            "Additional creator should have i64::MAX power"
        );

        // Normal user should have default (0)
        let normal_pl =
            get_sender_power_level("@normal:example.com", &state, StateResVersion::V2_1);
        assert_eq!(normal_pl, 0, "Normal user should have default 0 power");
    }
}
