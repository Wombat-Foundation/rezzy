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

#[cfg(feature = "std")]
pub mod roaring;
pub mod user;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::basespec::event_types::{
    DEFAULT_PL_BAN, DEFAULT_PL_INVITE, DEFAULT_PL_KICK, DEFAULT_PL_REDACT, FIELD_MEMBERSHIP,
    FIELD_SIGNED, FIELD_THIRD_PARTY_INVITE, FIELD_TOKEN, MEM_BAN, MEM_INVITE, MEM_JOIN, MEM_KNOCK,
    MEM_LEAVE, M_EMPTY_STATE_KEY, M_ROOM_CREATE, M_ROOM_JOIN_RULES, M_ROOM_MEMBER,
    M_ROOM_POWER_LEVELS, M_ROOM_REDACTION, M_ROOM_THIRD_PARTY_INVITE, RULE_INVITE, RULE_KNOCK,
    RULE_KNOCK_RESTRICTED, RULE_PUBLIC, RULE_RESTRICTED,
};
use crate::basespec::rezzy_types::{is_valid_mxid, EventLike, LeanEvent, StateResVersion};

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
    /// The `m.room.create` event is missing from the room state.
    ///
    /// This can occur during state resolution when walking DAG forks where
    /// the create event has not yet been accumulated into the local state.
    MissingCreate,
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
            AuthError::MissingCreate => {
                write!(f, "m.room.create is missing from state")
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

impl<K: AsRef<str>> StateKeyDyn for (String, K) {
    fn ev_type(&self) -> &str {
        &self.0
    }
    fn state_key(&self) -> &str {
        self.1.as_ref()
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

impl<'a, K: AsRef<str> + 'a> Borrow<dyn StateKeyDyn + 'a> for (String, K) {
    fn borrow(&self) -> &(dyn StateKeyDyn + 'a) {
        self
    }
}

impl<K: AsRef<str>> StateKeyDyn for (crate::basespec::event_types::EventType, K) {
    fn ev_type(&self) -> &str {
        self.0.as_str()
    }
    fn state_key(&self) -> &str {
        self.1.as_ref()
    }
}

// Sound only because `EventType`'s `Ord`/`Eq`/`Hash` are defined against
// `as_str()` (see its doc comment) and therefore agree with `dyn
// StateKeyDyn`'s lexicographic string ordering used below.
impl<'a, K: AsRef<str> + 'a> Borrow<dyn StateKeyDyn + 'a>
    for (crate::basespec::event_types::EventType, K)
{
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
pub trait StateProvider<Id = String, C = serde_json::Value, E = LeanEvent<Id, C>> {
    /// Look up a state event by its type and state key.
    fn get_event(&self, event_type: &str, state_key: &str) -> Option<&E>;
}

/// The room state at a specific point in the DAG (keyed by (type, `state_key`) -> event).
pub type RoomState<Id = String, C = serde_json::Value, K = String> =
    alloc::collections::BTreeMap<(String, K), LeanEvent<Id, C, K>>;

impl<Id, C, K> StateProvider<Id, C, LeanEvent<Id, C, K>> for RoomState<Id, C, K>
where
    K: Ord,
    for<'q> (String, K): Borrow<dyn StateKeyDyn + 'q>,
{
    fn get_event(&self, event_type: &str, state_key: &str) -> Option<&LeanEvent<Id, C, K>> {
        let query: &dyn StateKeyDyn = &(event_type, state_key);
        self.get(query)
    }
}

/// Get the numeric room version from the create event in state.
///
/// Returns 1 if the `room_version` field is absent (room V1 didn't have it).
///
/// # Errors
///
/// Returns [`AuthError::MissingCreate`] if the `m.room.create` event is not
/// present in the provided state. This can happen during state resolution
/// when walking DAG forks.
fn get_room_version_num<Id, C, E, S>(state: &S) -> Result<u32, AuthError<Id>>
where
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
    S: StateProvider<Id, C, E>,
{
    let Some(create) = state.get_event(M_ROOM_CREATE, "") else {
        return Err(AuthError::MissingCreate);
    };
    Ok(create
        .content()
        .get_room_version()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(1)) // V1 rooms didn't have a room_version field
}

fn reject_if_flagged_auth_state<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    state: &impl StateProvider<Id, C, E>,
    event_type: &str,
    state_key: &str,
) -> Result<(), AuthError<Id>> {
    if state
        .get_event(event_type, state_key)
        .is_some_and(|ev| ev.rejected() || ev.soft_fail())
    {
        return Err(AuthError::InvalidSyntax(alloc::format!(
            "rejected or soft-failed auth state event {event_type}/{state_key} must not be used"
        )));
    }
    Ok(())
}

fn reject_flagged_auth_state<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    event: &E,
    state: &impl StateProvider<Id, C, E>,
) -> Result<(), AuthError<Id>> {
    reject_if_flagged_auth_state(state, M_ROOM_CREATE, "")?;
    reject_if_flagged_auth_state(state, M_ROOM_POWER_LEVELS, "")?;
    reject_if_flagged_auth_state(state, M_ROOM_MEMBER, event.sender())?;

    if let Some(target_user) = event
        .state_key()
        .filter(|_| event.event_type() == M_ROOM_MEMBER)
    {
        reject_if_flagged_auth_state(state, M_ROOM_MEMBER, target_user)?;
    }
    let event_type = event.event_type();
    let membership = event.get_membership();

    if event_type == M_ROOM_MEMBER && matches!(membership, Some(MEM_JOIN | MEM_INVITE | MEM_KNOCK))
    {
        reject_if_flagged_auth_state(state, M_ROOM_JOIN_RULES, "")?;
    }
    if event_type == M_ROOM_MEMBER && membership == Some(MEM_JOIN) {
        if let Some(authorising_user) = event.get_join_authorised_via_users_server() {
            reject_if_flagged_auth_state(state, M_ROOM_MEMBER, authorising_user)?;
        }
    }
    if event_type == M_ROOM_MEMBER && membership == Some(MEM_INVITE) {
        if let Some(token) = event.get_third_party_invite_token() {
            reject_if_flagged_auth_state(
                state,
                crate::basespec::event_types::M_ROOM_THIRD_PARTY_INVITE,
                token,
            )?;
        }
    }

    Ok(())
}

/// The result of validating a new forward extremity event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardExtremityResult<Id = String> {
    /// The event is fully valid and updates the room state.
    Valid,
    /// The event is valid according to its own `auth_events`, but fails auth against the current room state.
    /// It must be accepted into the DAG (timeline) to prevent graph fragmentation, but must **not**
    /// update the room state.
    SoftFailed(AuthError<Id>),
    /// The event is completely invalid (fails auth against its own `auth_events`) and must be rejected.
    Rejected(AuthError<Id>),
}

/// Validates a new incoming event (forward extremity) according to Matrix rules.
///
/// This performs a dual-pass auth check:
/// 1. Checks the event against its declared `auth_events`. If this fails, the event is `Rejected`.
/// 2. Checks the event against the room's current state. If this fails, the event is `SoftFailed`.
/// 3. Otherwise, the event is `Valid`.
pub fn validate_forward_extremity<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    event: &E,
    auth_events_state: &impl StateProvider<Id, C, E>,
    current_room_state: &impl StateProvider<Id, C, E>,
    version: StateResVersion,
    verifier: Option<&dyn crate::basespec::rezzy_types::EventVerifier<Id>>,
) -> ForwardExtremityResult<Id> {
    if let Err(e) = check_auth(event, auth_events_state, version, verifier) {
        return ForwardExtremityResult::Rejected(e);
    }

    if let Err(e) = check_auth(event, current_room_state, version, None) {
        return ForwardExtremityResult::SoftFailed(e);
    }

    ForwardExtremityResult::Valid
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
pub fn check_auth<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    event: &E,
    state: &impl StateProvider<Id, C, E>,
    version: StateResVersion,
    verifier: Option<&dyn crate::basespec::rezzy_types::EventVerifier<Id>>,
) -> Result<(), AuthError<Id>> {
    check_auth_with_context(event, state, version, verifier, None)
}

/// Check whether `event` is authorized given the room state at its `prev_events`,
/// additionally validating `auth_events` rules (2.1–2.4) against an optional
/// [`crate::basespec::rezzy_types::EventProvider`].
///
/// # Errors
///
/// Returns an `AuthError` if the event fails authorization validation.
#[allow(clippy::too_many_lines)]
pub fn check_auth_with_context<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    event: &E,
    state: &impl StateProvider<Id, C, E>,
    version: StateResVersion,
    verifier: Option<&dyn crate::basespec::rezzy_types::EventVerifier<Id>>,
    auth_context: Option<&dyn crate::basespec::rezzy_types::EventProvider<Id, C, E>>,
) -> Result<(), AuthError<Id>> {
    // Rule 0: Basic syntactic validation
    if event.prev_events().len() > 20 {
        return Err(AuthError::InvalidSyntax(
            "prev_events exceeds maximum allowed length of 20".into(),
        ));
    }
    if event.auth_events().len() > 10 {
        return Err(AuthError::InvalidSyntax(
            "auth_events exceeds maximum allowed length of 10".into(),
        ));
    }

    // Cache event_type once — avoids repeated Cow allocations for
    // RawEvent impls that return Cow::Owned.
    let event_type = event.event_type();
    let event_type: &str = &event_type;

    if event_type.is_empty() {
        return Err(AuthError::InvalidSyntax(
            "event_type cannot be empty".into(),
        ));
    }

    if event.rejected() || event.soft_fail() {
        return Err(AuthError::InvalidSyntax(
            "rejected or soft-failed events must not be auth-checked".into(),
        ));
    }
    reject_flagged_auth_state(event, state)?;

    // Optional verification pipeline (steps 1-3).
    // Callers pass None during state resolution; Some during PDU receipt.
    // TODO: make the verifier version-aware once per-room-version hash
    // verification is implemented across the call sites.
    // Room-version-specific event ID hashing is delegated to the verifier
    // implementation; this layer only sequences the checks.
    if let Some(v) = verifier {
        v.verify_event_id_hash(event.event_id())
            .map_err(AuthError::InvalidSyntax)?;
        v.verify_signatures(event.event_id())
            .map_err(AuthError::InvalidSyntax)?;
        v.verify_content_hash(event.event_id())
            .map_err(AuthError::InvalidSyntax)?;
    }

    // Rule 1: m.room.create must be the first event
    if event_type == "m.room.create" {
        if !event.prev_events().is_empty() {
            return Err(AuthError::CreateWithPrevEvents);
        }
        // Rule 1.2: Check sender MXID validity for m.room.create
        if !is_valid_mxid(event.sender()) {
            return Err(AuthError::InvalidSyntax(
                "m.room.create sender must be a valid MXID".into(),
            ));
        }
        // Create events are always authorized if they're first
        return Ok(());
    }

    // Rule 3: m.federate check
    if let Some(create_ev) = state.get_event(M_ROOM_CREATE, "") {
        if create_ev.content().get_m_federate() == Some(false)
            && !crate::basespec::rezzy_types::domain_matches(event.sender(), create_ev.sender())
        {
            return Err(AuthError::InvalidSyntax(alloc::format!(
                "cross-domain event from sender {} rejected: room has m.federate=false",
                event.sender()
            )));
        }
    }

    // Rule 4 (V1–V5): m.room.aliases domain mismatch check. Removed starting
    // v6 (v6.txt: "Rule 4 ... is removed"). This must be read from the
    // m.room.create event's actual `content.room_version` (defaulting to "1"
    // per spec when absent), not the collapsed `StateResVersion` enum:
    // `StateResVersion::V2` covers real room versions 2-11 uniformly, so
    // gating on `version == StateResVersion::V1` would only ever match real
    // room version "1" and silently skip versions 2-5.
    if event_type == crate::basespec::event_types::M_ROOM_ALIASES {
        let room_version = state
            .get_event(M_ROOM_CREATE, "")
            .and_then(|create_ev| create_ev.content().get_room_version())
            .unwrap_or("1");
        if matches!(room_version, "1" | "2" | "3" | "4" | "5") {
            let Some(state_key) = event.state_key() else {
                return Err(AuthError::InvalidSyntax(
                    "m.room.aliases event must have a state_key".into(),
                ));
            };
            if !crate::basespec::rezzy_types::domain_matches(state_key, event.sender()) {
                return Err(AuthError::InvalidSyntax(
                    "m.room.aliases state_key domain must match sender domain".into(),
                ));
            }
        }
    }

    // Rule 11 (V1–V2): m.room.redaction — allow if sender PL >= redact
    // level, or if the redaction event and the event it redacts share a
    // domain; otherwise reject. Removed starting v3 (v3-auth-rules.txt has
    // no equivalent rule; spec_audit.md notes this as "removes
    // m.room.redaction auth rule"). Room version is read the same way as
    // Rule 4 above, from the m.room.create event's content, not the
    // collapsed `StateResVersion` enum.
    if event_type == M_ROOM_REDACTION {
        let room_version = state
            .get_event(M_ROOM_CREATE, "")
            .and_then(|create_ev| create_ev.content().get_room_version())
            .unwrap_or("1");
        if matches!(room_version, "1" | "2") {
            let sender_pl = user::get_sender_power_level(event.sender(), state, version);
            let redact_pl = get_redact_power_level(state);
            let same_domain = event.get_redacts().is_some_and(|target| {
                crate::basespec::rezzy_types::domain_matches(
                    target,
                    &alloc::format!("{}", event.event_id()),
                )
            });
            if sender_pl < redact_pl && !same_domain {
                return Err(AuthError::InvalidSyntax(
                    "m.room.redaction requires sender PL >= redact level, or same domain as the redacted event".into(),
                ));
            }
        }
    }

    // Rules 2.1, 2.2, 2.3, 2.4 checks via auth_context
    if let Some(provider) = auth_context {
        const VALID_AUTH_TYPES: &[&str] = &[
            M_ROOM_CREATE,
            M_ROOM_MEMBER,
            M_ROOM_POWER_LEVELS,
            M_ROOM_JOIN_RULES,
            M_ROOM_THIRD_PARTY_INVITE,
        ];

        // Rule 2.4 (V1–V11): auth_events must contain m.room.create
        if !version.is_v2_1_plus() {
            let Some(create_ev) = state.get_event(M_ROOM_CREATE, "") else {
                return Err(AuthError::InvalidSyntax(
                    "missing m.room.create in room state (cannot validate auth_events for v1-v11)"
                        .into(),
                ));
            };
            if !event
                .auth_events()
                .iter()
                .any(|id| id == create_ev.event_id())
            {
                return Err(AuthError::InvalidSyntax(
                    "auth_events must contain m.room.create in room versions 1-11".into(),
                ));
            }
        }

        let mut seen_tuples = crate::HashSet::new();

        for auth_id in event.auth_events() {
            let Some(auth_ev) = provider.get_event(auth_id) else {
                return Err(AuthError::MissingAuthEvent(auth_id.clone()));
            };

            if auth_ev.rejected() {
                return Err(AuthError::InvalidSyntax(alloc::format!(
                    "auth event {auth_id:?} was previously rejected"
                )));
            }

            let auth_type = auth_ev.event_type();

            if version.is_v2_1_plus() && auth_type == M_ROOM_CREATE {
                return Err(AuthError::InvalidSyntax(
                    "referencing m.room.create in auth_events is forbidden in room v12+".into(),
                ));
            }

            if !VALID_AUTH_TYPES.contains(&auth_type.as_ref()) {
                return Err(AuthError::InvalidSyntax(alloc::format!(
                    "unexpected event type in auth_events: {auth_type}"
                )));
            }

            let sk = auth_ev.state_key().unwrap_or("");
            let key = (auth_type.into_owned(), alloc::string::String::from(sk));
            if !seen_tuples.insert(key) {
                return Err(AuthError::InvalidSyntax(
                    "auth_events contains duplicate (type, state_key) pair".into(),
                ));
            }
        }
    }

    // Rule 2: Check sender is not banned, and Rule 3: Sender must be joined
    let sender_member_event = state.get_event(M_ROOM_MEMBER, event.sender());

    // Determine the effective membership string
    let mut membership = sender_member_event
        .and_then(EventLike::get_membership)
        .unwrap_or(MEM_LEAVE);

    // Exceptions: Room v11 implied creator join only applies when there is no membership event
    if sender_member_event.is_none() {
        let is_creator = state
            .get_event(M_ROOM_CREATE, "")
            .is_some_and(|create_ev| create_ev.sender() == event.sender());
        if is_creator {
            membership = MEM_JOIN;
        }
    }

    if membership == MEM_BAN {
        return Err(AuthError::BannedUser {
            sender: event.sender().into(),
            event_id: event.event_id().clone(),
        });
    }

    // Rule 3: Sender must be joined (with exceptions for self-membership events)
    if membership != MEM_JOIN {
        // Exceptions: Self-membership transitions (except ban).
        let is_self_membership = event_type == M_ROOM_MEMBER
            && event.state_key() == Some(event.sender())
            && event.get_membership() != Some(MEM_BAN);

        if !is_self_membership {
            return Err(AuthError::NotMember {
                sender: event.sender().into(),
                event_id: event.event_id().clone(),
            });
        }
    }

    // Rule 4: Check power level requirements
    // Skip for m.room.member (handled separately in check_membership_rules).
    // Also skip for m.room.power_levels when no PL event exists in state:
    // the spec's Rule 10.2 says "If there is no previous m.room.power_levels
    // event in the room, allow", which takes precedence over Rule 8's generic
    // PL check. Without this, the bootstrap PL event can never pass auth.
    if event_type != M_ROOM_MEMBER {
        let no_pl_event = state.get_event(M_ROOM_POWER_LEVELS, "").is_none();
        let is_first_pl = no_pl_event && event_type == M_ROOM_POWER_LEVELS;

        if !is_first_pl {
            let sender_pl = user::get_sender_power_level(event.sender(), state, version);
            let required_pl = get_required_power_level(event_type, event.state_key(), state);

            if sender_pl < required_pl {
                return Err(AuthError::InsufficientPowerLevel {
                    required: required_pl,
                    actual: sender_pl,
                    event_type: event_type.into(),
                });
            }
        }
    }

    // Rule 4b (spec §rule 9, all versions): If the event has a state_key
    // that starts with '@' and does not match the sender, reject.
    if event_type != M_ROOM_MEMBER {
        if let Some(sk) = event.state_key() {
            if sk.starts_with('@') && sk != event.sender() {
                return Err(AuthError::InvalidStateKey {
                    expected: event.sender().into(),
                    actual: sk.into(),
                });
            }
        }
    }

    // Rule 10: m.room.power_levels validation
    if event_type == M_ROOM_POWER_LEVELS {
        let new_content = event.content();

        let is_v12_plus = matches!(
            version,
            StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2
        );

        // Rules 10.1–10.3 were added in room version 10.
        let is_room_v10_plus = get_room_version_num(state)? >= 10;

        if is_room_v10_plus {
            // Rule 10.1 (V10+): Scalar PL properties must be integers.
            if let Some(field) = new_content.find_non_integer_scalar_pl() {
                return Err(AuthError::InvalidSyntax(alloc::format!(
                    "m.room.power_levels {field} is not an integer"
                )));
            }

            // Rule 10.2 (V10+): `events`/`notifications` must be objects with integer values.
            if let Some(field) = new_content.find_non_integer_map_pl() {
                return Err(AuthError::InvalidSyntax(alloc::format!(
                    "m.room.power_levels {field} is not an object with integer values"
                )));
            }
        }

        // Rule 10.4 (V12+ only): `users` must not contain creator or additional_creators.
        if is_v12_plus {
            if let Some(create_event) = state.get_event(M_ROOM_CREATE, "") {
                let create_content = create_event.content();
                if let Some(creator) = create_content.get_creator() {
                    if new_content.has_user_in_users(creator) {
                        return Err(AuthError::InvalidSyntax(alloc::format!(
                            "m.room.power_levels users contains creator {creator}"
                        )));
                    }
                }
                // Check additional_creators — use key-only iteration so non-integer
                // valued entries are still caught.
                let mut invalid_additional_creator = None;
                new_content.visit_user_keys(&mut |user_id| {
                    if create_content.has_additional_creator(user_id) {
                        invalid_additional_creator =
                            Some(AuthError::InvalidSyntax(alloc::format!(
                                "m.room.power_levels users contains additional_creator {user_id}"
                            )));
                    }
                });
                if let Some(e) = invalid_additional_creator {
                    return Err(e);
                }
            }
        }

        // Rule 10.3: `users` keys must be valid user IDs with integer values.
        // Applies to ALL versions. Strict JSON integers required in V10+, coercible strings allowed in V9-.
        if new_content.has_non_integer_users_pl(is_room_v10_plus) {
            return Err(AuthError::InvalidSyntax(
                "m.room.power_levels users contains non-integer value or is not an object".into(),
            ));
        }
        let mut invalid_user = None;
        new_content.visit_user_keys(&mut |user_id| {
            if !user_id.starts_with('@') || !user_id.contains(':') {
                invalid_user = Some(AuthError::InvalidSyntax(alloc::format!(
                    "users key is not a valid user ID: {user_id}"
                )));
            }
        });
        if let Some(e) = invalid_user {
            return Err(e);
        }

        // Rules 10.5–10.10: only when a previous PL event exists.
        // (Rule 10.5 — first PL event — is handled above by the is_first_pl skip.)
        if let Some(prev_pl_event) = state.get_event(M_ROOM_POWER_LEVELS, "") {
            let sender_pl = user::get_sender_power_level(event.sender(), state, version);
            check_power_levels_rules(
                event.sender(),
                new_content,
                prev_pl_event.content(),
                sender_pl,
            )?;
        }
    }

    // Rule 5: m.room.member state_key validation
    if event_type == M_ROOM_MEMBER {
        check_membership_rules(event, state, version, verifier)?;
    }

    Ok(())
}

/// Validate `m.room.power_levels` changes per spec Rules 10.6–10.10.
///
/// Called only when there is an existing PL event in state (Rule 10.5 is
/// handled by the `is_first_pl` skip in `check_auth`).  Rules 10.1–10.4
/// are checked unconditionally in `check_auth` before this function.
#[allow(clippy::too_many_lines)]
fn check_power_levels_rules<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
>(
    sender: &str,
    new_content: &C,
    prev_pl: &C,
    sender_pl: i64,
) -> Result<(), AuthError<Id>> {
    use alloc::collections::BTreeMap;

    // Rule 10.6: Scalar PL properties — reject if old or new value > sender PL.
    check_scalar_pl(
        "users_default",
        prev_pl.get_users_default(),
        new_content.get_users_default(),
        sender_pl,
    )?;
    check_scalar_pl(
        "events_default",
        prev_pl.get_events_default(),
        new_content.get_events_default(),
        sender_pl,
    )?;
    check_scalar_pl(
        "state_default",
        prev_pl.get_state_default(),
        new_content.get_state_default(),
        sender_pl,
    )?;
    check_scalar_pl("ban", prev_pl.get_ban(), new_content.get_ban(), sender_pl)?;
    check_scalar_pl(
        "redact",
        prev_pl.get_redact(),
        new_content.get_redact(),
        sender_pl,
    )?;
    check_scalar_pl(
        "kick",
        prev_pl.get_kick(),
        new_content.get_kick(),
        sender_pl,
    )?;
    check_scalar_pl(
        "invite",
        prev_pl.get_invite(),
        new_content.get_invite(),
        sender_pl,
    )?;

    // Rules 10.7–10.8: events map changes.
    let mut old_events: BTreeMap<&str, i64> = BTreeMap::new();
    prev_pl.visit_event_power_levels(&mut |k, v| {
        old_events.insert(k, v);
    });
    let mut new_events: BTreeMap<&str, i64> = BTreeMap::new();
    new_content.visit_event_power_levels(&mut |k, v| {
        new_events.insert(k, v);
    });

    // Rule 10.7: entries changed or removed — current value must not exceed sender PL.
    for (key, &old_val) in &old_events {
        let changed = new_events.get(key).map_or(true, |&nv| nv != old_val);
        if changed && old_val > sender_pl {
            return Err(AuthError::InvalidSyntax(alloc::format!(
                "cannot change events[{key}]: current value {old_val} > sender PL {sender_pl}"
            )));
        }
    }
    // Rule 10.8: entries added or changed — new value must not exceed sender PL.
    for (key, &new_val) in &new_events {
        let changed = old_events.get(key).map_or(true, |&ov| ov != new_val);
        if changed && new_val > sender_pl {
            return Err(AuthError::InvalidSyntax(alloc::format!(
                "cannot set events[{key}] to {new_val}: exceeds sender PL {sender_pl}"
            )));
        }
    }

    // Rules 10.7–10.8 also apply to `notifications` map.
    let mut old_notifications: BTreeMap<&str, i64> = BTreeMap::new();
    prev_pl.visit_notification_power_levels(&mut |k, v| {
        old_notifications.insert(k, v);
    });
    let mut new_notifications: BTreeMap<&str, i64> = BTreeMap::new();
    new_content.visit_notification_power_levels(&mut |k, v| {
        new_notifications.insert(k, v);
    });

    for (key, &old_val) in &old_notifications {
        let changed = new_notifications.get(key).map_or(true, |&nv| nv != old_val);
        if changed && old_val > sender_pl {
            return Err(AuthError::InvalidSyntax(alloc::format!(
                "cannot change notifications[{key}]: current value {old_val} > sender PL {sender_pl}"
            )));
        }
    }
    for (key, &new_val) in &new_notifications {
        let changed = old_notifications.get(key).map_or(true, |&ov| ov != new_val);
        if changed && new_val > sender_pl {
            return Err(AuthError::InvalidSyntax(alloc::format!(
                "cannot set notifications[{key}] to {new_val}: exceeds sender PL {sender_pl}"
            )));
        }
    }

    // Rules 10.9–10.10: users map changes.
    let mut old_users: BTreeMap<&str, i64> = BTreeMap::new();
    prev_pl.visit_user_power_levels(&mut |k, v| {
        old_users.insert(k, v);
    });
    let mut new_users: BTreeMap<&str, i64> = BTreeMap::new();
    new_content.visit_user_power_levels(&mut |k, v| {
        new_users.insert(k, v);
    });

    // Rule 10.9: entries changed or removed (excluding sender's own entry).
    // Current value must be strictly less than sender PL (i.e. >= is rejected).
    for (key, &old_val) in &old_users {
        if *key == sender {
            continue; // sender's own entry is exempt
        }
        let changed = new_users.get(key).map_or(true, |&nv| nv != old_val);
        if changed && old_val >= sender_pl {
            return Err(AuthError::InvalidSyntax(alloc::format!(
                "cannot change users[{key}]: current PL {old_val} >= sender PL {sender_pl}"
            )));
        }
    }
    // Rule 10.10: entries added or changed — new value must not exceed sender PL.
    for (key, &new_val) in &new_users {
        let changed = old_users.get(key).map_or(true, |&ov| ov != new_val);
        if changed && new_val > sender_pl {
            return Err(AuthError::InvalidSyntax(alloc::format!(
                "cannot set users[{key}] to {new_val}: exceeds sender PL {sender_pl}"
            )));
        }
    }

    Ok(())
}

/// Helper for Rule 10.6: reject if a scalar PL property was changed and
/// either the old or new value exceeds the sender's power level.
fn check_scalar_pl<Id>(
    field: &str,
    old: Option<i64>,
    new: Option<i64>,
    sender_pl: i64,
) -> Result<(), AuthError<Id>> {
    if old == new {
        return Ok(());
    }
    if let Some(old_val) = old {
        if old_val > sender_pl {
            return Err(AuthError::InvalidSyntax(alloc::format!(
                "cannot change {field}: current value {old_val} > sender PL {sender_pl}"
            )));
        }
    }
    if let Some(new_val) = new {
        if new_val > sender_pl {
            return Err(AuthError::InvalidSyntax(alloc::format!(
                "cannot set {field} to {new_val}: exceeds sender PL {sender_pl}"
            )));
        }
    }
    Ok(())
}

/// Re-export from [`crate::basespec::event_types`] for backwards compatibility.
pub use crate::basespec::event_types::{MAX_POWER_LEVEL_JSON, MAX_POWER_LEVEL_RUST};

/// Get the redact power level from room state.
pub(crate) fn get_redact_power_level<
    Id,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    state: &impl StateProvider<Id, C, E>,
) -> i64 {
    // The redact level is stored on the room power-level event at the empty state key.
    if let Some(pl_event) = state.get_event(M_ROOM_POWER_LEVELS, M_EMPTY_STATE_KEY) {
        if let Some(redact) = pl_event.get_redact() {
            return redact;
        }
    }
    DEFAULT_PL_REDACT
}

/// Get the required power level to send an event based on room state.
fn get_required_power_level<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    event_type: &str,
    state_key: Option<&str>,
    state: &impl StateProvider<Id, C, E>,
) -> i64 {
    if let Some(pl_event) = state.get_event(M_ROOM_POWER_LEVELS, "") {
        // Spec Rule 7: m.room.third_party_invite events require the invite level
        if event_type == crate::basespec::event_types::M_ROOM_THIRD_PARTY_INVITE {
            return pl_event.get_invite().unwrap_or(0); // 0 is the default invite level
        }
        // Check specific event type overrides
        if let Some(pl) = pl_event.get_event_power_level(event_type) {
            return pl;
        }
        // Fall back to state_default for state events, events_default for others
        if state_key.is_some() {
            return pl_event.get_state_default().unwrap_or(50);
        }
        return pl_event.get_events_default().unwrap_or(0);
    }
    // No restrictions if no power_levels event exists
    // However, Matrix spec says if NO PL event exists, state events require 50.
    if event_type == crate::basespec::event_types::M_ROOM_THIRD_PARTY_INVITE {
        0 // Spec Rule 7: m.room.third_party_invite defaults to 0
    } else if state_key.is_some() {
        50
    } else {
        0
    }
}

/// Validate leave/kick transition rules.
fn check_leave_rules<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    event: &E,
    state: &impl StateProvider<Id, C, E>,
    target_user: &str,
    current_membership: &str,
    version: StateResVersion,
) -> Result<(), AuthError<Id>> {
    // Rule 5.5.1: self-leave is allowed only from invite, join, or knock.
    if target_user == event.sender() {
        return match current_membership {
            MEM_INVITE | MEM_JOIN | MEM_KNOCK => Ok(()),
            _ => Err(AuthError::NotMember {
                sender: event.sender().into(),
                event_id: event.event_id().clone(),
            }),
        };
    }

    // If target_user != sender, this is a kick or unban — requires power level
    let sender_pl = user::get_sender_power_level(event.sender(), state, version);

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
fn check_ban_rules<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    event: &E,
    state: &impl StateProvider<Id, C, E>,
    version: StateResVersion,
) -> Result<(), AuthError<Id>> {
    // Banning requires the ban power level
    let sender_pl = user::get_sender_power_level(event.sender(), state, version);
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
fn check_invite_rules<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    event: &E,
    state: &impl StateProvider<Id, C, E>,
    target_user: &str,
    current_membership: &str,
    version: StateResVersion,
    verifier: Option<&dyn crate::basespec::rezzy_types::EventVerifier<Id>>,
) -> Result<(), AuthError<Id>> {
    // Inviting requires invite power level, and sender != target
    if target_user == event.sender() {
        return Err(AuthError::InvalidStateKey {
            expected: alloc::format!("!= {}", event.sender()),
            actual: target_user.into(),
        });
    }

    let invite_pl = get_invite_power_level(state);

    // Rule 5.4.1: If third_party_invite is present, check the issuer's power level.
    // It must strictly adhere to the rules, or be rejected. No fallback.
    //
    // NOTE: The spec (Room v10 §4.4.1) only checks for *banned* targets here,
    // NOT already-joined targets. The "target is join" check (§4.4.3) is in the
    // non-3PI path below and is never reached when third_party_invite is present.
    // This means 3PI invites to already-joined users are spec-valid, which allows
    // redundant invites. Arguably undesirable but matches the spec as written.
    if event.has_third_party_invite() {
        // Rule 5.4.1.1: If target user is banned, reject.
        if current_membership == MEM_BAN {
            return Err(AuthError::BannedUser {
                sender: target_user.into(),
                event_id: event.event_id().clone(),
            });
        }

        let token = event.get_third_party_invite_token().ok_or_else(|| {
            AuthError::InvalidSyntax("invalid third_party_invite: missing signed.token".into())
        })?;

        let mxid = event.get_third_party_invite_mxid().ok_or_else(|| {
            AuthError::InvalidSyntax("invalid third_party_invite: missing signed.mxid".into())
        })?;

        if !event.has_third_party_invite_signatures() {
            return Err(AuthError::InvalidSyntax(
                "invalid third_party_invite: missing or empty signed.signatures".into(),
            ));
        }

        // Optional verification pipeline (step 4): 3PI signature verification.
        if let Some(v) = verifier {
            v.verify_third_party_invite(event.event_id(), token)
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

        if tpi_event.sender() != event.sender() {
            return Err(AuthError::InvalidStateKey {
                expected: alloc::format!("sender == {}", tpi_event.sender()),
                actual: event.sender().into(),
            });
        }

        let issuer_pl = user::get_sender_power_level(tpi_event.sender(), state, version);
        if issuer_pl < invite_pl {
            return Err(AuthError::InsufficientPowerLevel {
                required: invite_pl,
                actual: issuer_pl,
                event_type: "invite".into(),
            });
        }

        return Ok(()); // 3PI validation passed! Do not fall through.
    }

    let sender_pl = user::get_sender_power_level(event.sender(), state, version);
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
            event_id: event.event_id().clone(),
        });
    }
    if current_membership == MEM_BAN {
        return Err(AuthError::BannedUser {
            sender: target_user.into(),
            event_id: event.event_id().clone(),
        });
    }
    Ok(())
}

/// Validate sender power level hierarchies (sender PL vs target PL, and previous sender rules).
fn check_membership_pl_hierarchies<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    event: &E,
    state: &impl StateProvider<Id, C, E>,
    target_user: &str,
    new_membership: &str,
    version: StateResVersion,
) -> Result<(), AuthError<Id>> {
    // 1. Kick/Ban power vs Target power: ONLY for "leave" (kick) or "ban" transitions.
    if target_user != event.sender() && (new_membership == "leave" || new_membership == "ban") {
        let sender_pl = user::get_sender_power_level(event.sender(), state, version);
        let target_pl = user::get_sender_power_level(target_user, state, version);

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
fn check_membership_rules<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    event: &E,
    state: &impl StateProvider<Id, C, E>,
    version: StateResVersion,
    verifier: Option<&dyn crate::basespec::rezzy_types::EventVerifier<Id>>,
) -> Result<(), AuthError<Id>> {
    let Some(target_user) = event.state_key() else {
        return Err(AuthError::InvalidSyntax(
            "m.room.member event missing state_key".into(),
        ));
    };
    let Some(new_membership) = event.get_membership() else {
        return Err(AuthError::InvalidSyntax(
            "m.room.member event missing membership field".into(),
        ));
    };

    let current_membership = state
        .get_event(M_ROOM_MEMBER, target_user)
        .and_then(EventLike::get_membership)
        .unwrap_or("");

    // Self-bans are nonsensical and forbidden by the spec.
    if new_membership == MEM_BAN && target_user == event.sender() {
        return Err(AuthError::InvalidStateKey {
            expected: alloc::format!("!= {}", event.sender()),
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

fn check_join_rules<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    event: &E,
    state: &impl StateProvider<Id, C, E>,
    target_user: &str,
    version: StateResVersion,
) -> Result<(), AuthError<Id>> {
    // A user can only join as themselves
    if target_user != event.sender() {
        return Err(AuthError::InvalidStateKey {
            expected: event.sender().into(),
            actual: target_user.into(),
        });
    }

    let current_membership = state
        .get_event("m.room.member", target_user)
        .and_then(EventLike::get_membership)
        .unwrap_or("");

    // Defense-in-depth: the outer `check_auth` (line 240) catches banned senders
    // before reaching this function. Since target_user == sender (enforced above),
    // this branch is normally unreachable but is kept in place for spec compliance.
    if current_membership == MEM_BAN {
        return Err(AuthError::BannedUser {
            sender: event.sender().into(),
            event_id: event.event_id().clone(),
        });
    }

    let join_rule = state
        .get_event(M_ROOM_JOIN_RULES, "")
        .and_then(EventLike::get_join_rule)
        .unwrap_or(RULE_INVITE); // Default to invite

    let is_creator = state
        .get_event(M_ROOM_CREATE, "")
        .is_some_and(|ev| ev.sender() == event.sender());

    if is_creator {
        // Room creator can always join
    } else if join_rule == RULE_INVITE || join_rule == RULE_KNOCK {
        if current_membership == MEM_INVITE || current_membership == MEM_JOIN {
            // Allowed
        } else {
            return Err(AuthError::NotMember {
                sender: event.sender().into(),
                event_id: event.event_id().clone(),
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
                sender: event.sender().into(),
                event_id: event.event_id().clone(),
            });
        }
    } else if join_rule != RULE_PUBLIC {
        return Err(AuthError::NotMember {
            sender: event.sender().into(),
            event_id: event.event_id().clone(),
        });
    }
    Ok(())
}

/// Validate that the authorising user for a restricted join is joined to the
/// room and has sufficient power level to invite (MSC3083).
fn check_authorising_user<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    event: &E,
    state: &impl StateProvider<Id, C, E>,
    authorising_user: &str,
    version: StateResVersion,
) -> Result<(), AuthError<Id>> {
    let auth_membership = state
        .get_event(M_ROOM_MEMBER, authorising_user)
        .and_then(EventLike::get_membership)
        .unwrap_or("");

    if auth_membership != MEM_JOIN {
        return Err(AuthError::NotMember {
            sender: event.sender().into(),
            event_id: event.event_id().clone(),
        });
    }

    // Use get_sender_power_level to correctly handle V12 implicit creator PL
    let auth_user_pl = user::get_sender_power_level(authorising_user, state, version);
    if auth_user_pl < get_invite_power_level(state) {
        return Err(AuthError::NotMember {
            sender: event.sender().into(),
            event_id: event.event_id().clone(),
        });
    }

    Ok(())
}

/// Validate knock rules: knocking is only allowed when `join_rule` is
/// `knock` or `knock_restricted` (room versions 7+ / 10+).
fn check_knock_rules<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    event: &E,
    state: &impl StateProvider<Id, C, E>,
    target_user: &str,
) -> Result<(), AuthError<Id>> {
    // A user can only knock as themselves.
    // Defense-in-depth: state_key != sender is already caught by check_auth line 254.
    if target_user != event.sender() {
        return Err(AuthError::InvalidStateKey {
            expected: event.sender().into(),
            actual: target_user.into(),
        });
    }

    let current_membership = state
        .get_event(M_ROOM_MEMBER, target_user)
        .and_then(EventLike::get_membership)
        .unwrap_or("");

    // MSC2403 §f.iii: allow only if membership is NOT ban, invite, or join.
    // Defense-in-depth: banned senders are caught by check_auth line 240 before reaching here.
    if current_membership == MEM_BAN {
        return Err(AuthError::BannedUser {
            sender: event.sender().into(),
            event_id: event.event_id().clone(),
        });
    }

    if current_membership == MEM_INVITE || current_membership == MEM_JOIN {
        return Err(AuthError::NotMember {
            sender: event.sender().into(),
            event_id: event.event_id().clone(),
        });
    }

    let join_rule = state
        .get_event(M_ROOM_JOIN_RULES, "")
        .and_then(EventLike::get_join_rule)
        .unwrap_or(RULE_INVITE);

    if join_rule != RULE_KNOCK && join_rule != RULE_KNOCK_RESTRICTED {
        return Err(AuthError::NotMember {
            sender: event.sender().into(),
            event_id: event.event_id().clone(),
        });
    }

    Ok(())
}

/// Get the kick power level from room state.
pub(crate) fn get_kick_power_level<
    Id,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    state: &impl StateProvider<Id, C, E>,
) -> i64 {
    if let Some(pl_event) = state.get_event(M_ROOM_POWER_LEVELS, "") {
        if let Some(kick) = pl_event.get_kick() {
            return kick;
        }
    }
    DEFAULT_PL_KICK // Default kick power level per Matrix spec
}

/// Get the ban power level from room state.
pub(crate) fn get_invite_power_level<
    Id,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    state: &impl StateProvider<Id, C, E>,
) -> i64 {
    if let Some(pl_event) = state.get_event(M_ROOM_POWER_LEVELS, "") {
        if let Some(invite) = pl_event.get_invite() {
            return invite;
        }
    }
    DEFAULT_PL_INVITE // Default invite power level per Matrix spec
}

pub(crate) fn get_ban_power_level<
    Id,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    state: &impl StateProvider<Id, C, E>,
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
pub fn check_auth_chain<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
>(
    sorted_events: &[LeanEvent<Id, C>],
    initial_state: &RoomState<Id, C>,
    version: StateResVersion,
) -> (Vec<Id>, Vec<(Id, AuthError<Id>)>) {
    let mut state = initial_state.clone();
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();

    let event_map: crate::HashMap<Id, LeanEvent<Id, C>> = sorted_events
        .iter()
        .map(|ev| (ev.event_id.clone(), ev.clone()))
        .collect();

    let mut rejected_ids = crate::HashSet::new();

    for event in sorted_events {
        // Rule 2.3: Check if any auth event was previously rejected
        let has_rejected_auth_event = event
            .auth_events
            .iter()
            .any(|auth_id| rejected_ids.contains(auth_id));

        if has_rejected_auth_event {
            let err = AuthError::InvalidSyntax("auth_event was previously rejected".into());
            rejected.push((event.event_id.clone(), err));
            rejected_ids.insert(event.event_id.clone());
            continue;
        }

        match check_auth_with_context(event, &state, version, None, Some(&event_map)) {
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
                rejected_ids.insert(event.event_id.clone());
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
        if let Some(sk) = state_key.filter(|sk| *sk != sender) {
            auth_types.push((M_ROOM_MEMBER.into(), sk.into()));
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

        if membership == Some(MEM_JOIN) {
            if let Some(authorising_user) = content
                .get(crate::basespec::event_types::FIELD_JOIN_AUTHORISED_VIA_USERS_SERVER)
                .and_then(|v| v.as_str())
            {
                auth_types.push((M_ROOM_MEMBER.into(), authorising_user.into()));
            }
        }
    }

    auth_types
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
            user::get_sender_power_level("@creator:example.com", &state, StateResVersion::V2_1);
        assert_eq!(
            creator_pl,
            i64::MAX,
            "Primary creator should have i64::MAX power"
        );

        // Assert that the additional creator gets i64::MAX
        let additional_pl =
            user::get_sender_power_level("@additional:example.com", &state, StateResVersion::V2_1);
        assert_eq!(
            additional_pl,
            i64::MAX,
            "Additional creator should have i64::MAX power"
        );

        // Normal user should have default (0)
        let normal_pl =
            user::get_sender_power_level("@normal:example.com", &state, StateResVersion::V2_1);
        assert_eq!(normal_pl, 0, "Normal user should have default 0 power");
    }

    /// Coverage: `check_knock_rules` — `target_user` != sender.
    /// Defense-in-depth path unreachable via `check_auth` (caught at line 254).
    #[test]
    fn test_knock_state_key_mismatch_direct() {
        let knock_event: LeanEvent<String> = LeanEvent {
            event_id: "$knock".into(),
            event_type: M_ROOM_MEMBER.into(),
            state_key: Some("@alice:x".into()),
            sender: "@alice:x".into(),
            content: json!({"membership": "knock"}),
            ..Default::default()
        };

        let state: RoomState = RoomState::new();

        // Call check_knock_rules directly with mismatched target_user
        let result = check_knock_rules(&knock_event, &state, "@bob:x");
        assert!(
            matches!(result, Err(AuthError::InvalidStateKey { .. })),
            "Must reject knock with mismatched target: {result:?}"
        );
    }

    /// Coverage: `check_knock_rules` — banned target user.
    /// Defense-in-depth path unreachable via `check_auth` (caught at line 240).
    #[test]
    fn test_knock_banned_target_direct() {
        let knock_event: LeanEvent<String> = LeanEvent {
            event_id: "$knock".into(),
            event_type: M_ROOM_MEMBER.into(),
            state_key: Some("@evil:x".into()),
            sender: "@evil:x".into(),
            content: json!({"membership": "knock"}),
            ..Default::default()
        };

        let mut state = RoomState::new();
        state.insert(
            (M_ROOM_MEMBER.into(), "@evil:x".into()),
            LeanEvent {
                event_id: "$ban".into(),
                event_type: M_ROOM_MEMBER.into(),
                state_key: Some("@evil:x".into()),
                sender: "@admin:x".into(),
                content: json!({"membership": "ban"}),
                ..Default::default()
            },
        );

        let result = check_knock_rules(&knock_event, &state, "@evil:x");
        assert!(
            matches!(result, Err(AuthError::BannedUser { .. })),
            "Must reject knock from banned user: {result:?}"
        );
    }

    /// Coverage: `check_join_rules` — banned target user.
    /// Defense-in-depth path unreachable via `check_auth`.
    #[test]
    fn test_join_banned_target_direct() {
        let join_event: LeanEvent<String> = LeanEvent {
            event_id: "$join".into(),
            event_type: M_ROOM_MEMBER.into(),
            state_key: Some("@evil:x".into()),
            sender: "@evil:x".into(),
            content: json!({"membership": "join"}),
            ..Default::default()
        };

        let mut state = RoomState::new();
        state.insert(
            (M_ROOM_MEMBER.into(), "@evil:x".into()),
            LeanEvent {
                event_id: "$ban".into(),
                event_type: M_ROOM_MEMBER.into(),
                state_key: Some("@evil:x".into()),
                sender: "@admin:x".into(),
                content: json!({"membership": "ban"}),
                ..Default::default()
            },
        );

        let result = check_join_rules(&join_event, &state, "@evil:x", StateResVersion::V2);
        assert!(
            matches!(result, Err(AuthError::BannedUser { .. })),
            "Must reject join from banned user: {result:?}"
        );
    }

    /// Coverage: `reject_flagged_auth_state` - invite must reject flagged `m.room.join_rules`.
    #[test]
    fn test_invite_rejects_flagged_join_rules() {
        let invite_event: LeanEvent<String> = LeanEvent {
            event_id: "$invite".into(),
            event_type: M_ROOM_MEMBER.into(),
            state_key: Some("@target:x".into()),
            sender: "@sender:x".into(),
            content: json!({"membership": "invite"}),
            ..Default::default()
        };

        let mut state = RoomState::new();
        state.insert(
            (M_ROOM_CREATE.into(), String::new()),
            make_test_event("$create", M_ROOM_CREATE, "@creator:x", json!({})),
        );
        state.insert(
            (M_ROOM_POWER_LEVELS.into(), String::new()),
            make_test_event("$pl", M_ROOM_POWER_LEVELS, "@creator:x", json!({})),
        );
        state.insert(
            (M_ROOM_MEMBER.into(), "@sender:x".into()),
            make_test_event(
                "$sender_join",
                M_ROOM_MEMBER,
                "@sender:x",
                json!({"membership": "join"}),
            ),
        );
        state.insert(
            (M_ROOM_MEMBER.into(), "@target:x".into()),
            make_test_event(
                "$target_leave",
                M_ROOM_MEMBER,
                "@target:x",
                json!({"membership": "leave"}),
            ),
        );
        state.insert(
            (M_ROOM_JOIN_RULES.into(), String::new()),
            LeanEvent {
                event_id: "$jr".into(),
                event_type: M_ROOM_JOIN_RULES.into(),
                sender: "@creator:x".into(),
                content: json!({"join_rule": "invite"}),
                rejected: false,
                soft_fail: true,
                ..Default::default()
            },
        );

        let result = reject_flagged_auth_state(&invite_event, &state);
        assert!(
            matches!(result, Err(AuthError::InvalidSyntax(_))),
            "Invite must reject flagged join_rules auth state: {result:?}"
        );
    }
}
