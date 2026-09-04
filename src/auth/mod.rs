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
pub mod user;

use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use crate::basespec::event_types::{
    DEFAULT_PL_BAN, DEFAULT_PL_INVITE, DEFAULT_PL_KICK, DEFAULT_PL_REDACT, FIELD_MEMBERSHIP,
    FIELD_SIGNED, FIELD_THIRD_PARTY_INVITE, FIELD_TOKEN, MEM_BAN, MEM_INVITE, MEM_JOIN, MEM_KNOCK,
    MEM_LEAVE, M_EMPTY_STATE_KEY, M_ROOM_CREATE, M_ROOM_JOIN_RULES, M_ROOM_MEMBER,
    M_ROOM_POWER_LEVELS, M_ROOM_REDACTION, M_ROOM_THIRD_PARTY_INVITE, RULE_INVITE, RULE_KNOCK,
    RULE_KNOCK_RESTRICTED, RULE_PUBLIC, RULE_RESTRICTED,
};
use crate::basespec::rezzy_types::{
    apply_redaction, domain_matches, is_valid_mxid, EventLike, LeanEvent, StateResVersion,
};

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
    /// Rule 2.2: `auth_events` omits a `(type, state_key)` pair required by
    /// the auth-events selection algorithm (e.g. the target member event for
    /// a membership change, or the room's power levels) -- **or** cites a
    /// *stale* event ID for that pair (one that isn't the room's current
    /// state entry for the tuple). Both are the same failure from the
    /// selection algorithm's point of view: the event doesn't cite what the
    /// algorithm currently requires. This variant doesn't distinguish
    /// "missing" from "stale citation" -- both name the same `(event_type,
    /// state_key)`.
    IncompleteAuthEvents {
        event_type: String,
        state_key: String,
    },
    /// Rule 2.5: an `auth_events` entry carries a [`RoomId`](crate::RoomId)
    /// that doesn't match the citing event's own room, OR carries no
    /// `room_id` at all. Defense-in-depth against a rogue foreign-room event
    /// leaking into `auth_context`/the event map this check runs over.
    ///
    /// Opt-in only on the *citing* side: this only fires when the citing
    /// event itself has `Some(room_id)` populated -- a citing event with
    /// `None` (the default, unless a caller explicitly populates it) never
    /// triggers this check, so it's not a new hard requirement on every
    /// event. But once the citing side opts in, an `auth_events` entry with
    /// `None` is treated the same as a mismatch (`actual: None`), not given
    /// a free pass: a foreign event that leaked in without ever being
    /// tagged is exactly the case this check exists to catch, and letting
    /// an absent tag silently skip the check would defeat it entirely.
    ForeignRoomEvent {
        event_id: Id,
        auth_event_id: Id,
        expected: String,
        /// `None` if the cited auth event carries no `room_id` at all
        /// (rather than a populated, differing one).
        actual: Option<String>,
    },
    /// MSC4242 Rule 4.3: an auth event derived from state was rejected during PDU receipt.
    RejectedAuthEvent { event_id: Id, auth_event_id: Id },
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
            AuthError::IncompleteAuthEvents {
                event_type,
                state_key,
            } => {
                write!(
                    f,
                    "auth_events omits required ({event_type}, {state_key:?})"
                )
            }
            AuthError::ForeignRoomEvent {
                event_id,
                auth_event_id,
                expected,
                actual,
            } => match actual {
                Some(actual) => write!(
                    f,
                    "event {event_id} in room {expected} cites auth event {auth_event_id} from foreign room {actual}"
                ),
                None => write!(
                    f,
                    "event {event_id} in room {expected} cites auth event {auth_event_id} with no room_id"
                ),
            },
            AuthError::RejectedAuthEvent {
                event_id,
                auth_event_id,
            } => {
                write!(
                    f,
                    "event {event_id} cites rejected auth event {auth_event_id}"
                )
            }
        }
    }
}

use core::borrow::Borrow;
use core::cmp::Ordering;

/// Trait for zero-copy lookups into state maps.
///
/// This enables querying [`SharedState`](crate::state::at::SharedState) or `BTreeMap`
/// maps keyed by owned `(EventType, K)` or `(String, K)` tuples using borrowed `(&str, &str)`
/// tuples — avoiding allocation for state lookups during auth checking.
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
/// Returns [`AuthError::MissingCreate`] when the `m.room.create` event is not
/// present. Join/knock partial-state handling uses the literal-version helper
/// below, so it can retain its protocol-defined v1 fallback without weakening
/// power-level authorization.
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
    let Some(v) = create.content().get_room_version() else {
        return Ok(1);
    };
    if StateResVersion::from_room_version(v).is_none() {
        return Err(AuthError::InvalidSyntax(
            "m.room.create content.room_version is not a recognised room version".into(),
        ));
    }
    if let Ok(num) = v.parse::<u32>() {
        return Ok(num);
    }
    if StateResVersion::from_room_version(v).is_some_and(|r| r.is_v2_1_plus()) {
        return Ok(12);
    }
    // A create event without `room_version` is the historical v1 default.
    Ok(1)
}

/// Returns whether the room's explicit version supports a feature introduced
/// in `minimum_version`.
fn room_version_at_least<Id, C, E, S>(
    state: &S,
    minimum_version: u32,
) -> Result<bool, AuthError<Id>>
where
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
    S: StateProvider<Id, C, E>,
{
    Ok(get_room_version_num(state)? >= minimum_version)
}

/// Returns a present, supported create-event room version, or `None` for the
/// spec-defined v1 default when create state or its version field is absent.
///
/// This is the authorization boundary for a create event already present in
/// state. Without it, an unsupported label could fall through legacy literal
/// version checks (notably redaction Rule 11).
fn validated_room_version_or_v1<'s, Id, C, E, S>(
    state: &'s S,
) -> Result<Option<&'s str>, AuthError<Id>>
where
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent + 's,
    E: EventLike<Id = Id, Content = C> + 's,
    S: StateProvider<Id, C, E>,
{
    let Some(create) = state.get_event(M_ROOM_CREATE, "") else {
        return Ok(None);
    };
    let Some(version) = create.content().get_room_version() else {
        // A present-but-non-string `room_version` (e.g. a JSON number) must
        // not be silently treated as "absent" and fall back to v1 — that
        // would let a malformed label sneak past this rejection boundary.
        if create.content().has_malformed_room_version() {
            return Err(AuthError::InvalidSyntax(
                "m.room.create content.room_version is not a recognised room version".into(),
            ));
        }
        return Ok(None);
    };
    if StateResVersion::from_room_version(version).is_none() {
        return Err(AuthError::InvalidSyntax(
            "m.room.create content.room_version is not a recognised room version".into(),
        ));
    }
    Ok(Some(version))
}

/// Reads the validated version label needed by literal version-keyed rules.
fn room_version_str_or_v1<'s, Id, C, E, S>(state: &'s S) -> Result<&'s str, AuthError<Id>>
where
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent + 's,
    E: EventLike<Id = Id, Content = C> + 's,
    S: StateProvider<Id, C, E>,
{
    Ok(validated_room_version_or_v1(state)?.unwrap_or("1"))
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
    // Only `rejected` disqualifies state as auth material. Soft-failed events
    // are NOT rejected here: per the server-server spec's "Soft failure"
    // section, "Soft failed events participate in state resolution as normal
    // if further events are received which reference it" and "it is possible
    // for such events to appear in the current state of the room" -- once a
    // soft-failed event is legitimately resolved into state, later events are
    // meant to be able to build on it like any other state, not be blanket
    // rejected for doing so.
    if state
        .get_event(event_type, state_key)
        .is_some_and(EventLike::rejected)
    {
        return Err(AuthError::InvalidSyntax(alloc::format!(
            "rejected auth state event {event_type}/{state_key} must not be used"
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
    let is_msc4242 = matches!(version, StateResVersion::V2_2);
    if !is_msc4242 && event.auth_events().len() > 10 {
        return Err(AuthError::InvalidSyntax(
            "auth_events exceeds maximum allowed length of 10".into(),
        ));
    }
    if is_msc4242
        && event.prev_state_events().len() > crate::basespec::event_types::MAX_PREV_STATE_EVENTS
    {
        return Err(AuthError::InvalidSyntax(alloc::format!(
            "prev_state_events exceeds maximum allowed length of {}",
            crate::basespec::event_types::MAX_PREV_STATE_EVENTS
        )));
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

    // Rejected events must not be auth-checked (spec rooms/v9). Soft-failed events are
    // auth-checked as normal and participate in state resolution (spec server-server-api
    // "Soft failure"); they are not blanket-rejected here.
    if event.rejected() {
        return Err(AuthError::InvalidSyntax(
            "rejected events must not be auth-checked".into(),
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
        if event.content().has_malformed_room_version()
            || event
                .content()
                .get_room_version()
                .is_some_and(|room_version| {
                    StateResVersion::from_room_version(room_version).is_none()
                })
        {
            return Err(AuthError::InvalidSyntax(
                "m.room.create content.room_version is not a recognised room version".into(),
            ));
        }
        // Create events are always authorized if they're first
        return Ok(());
    }

    // Reject a present unsupported room-version label before any
    // authorization rule interprets it as a legacy version. Missing create
    // state remains valid for partial-state resolution.
    validated_room_version_or_v1(state)?;

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
        let room_version = room_version_str_or_v1(state)?;
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
        let room_version = room_version_str_or_v1(state)?;
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
    //
    // MSC4242 (V2.2) does not apply here: `LeanEvent` has no separate
    // `prev_state_events` storage, so `DagNode::prev_state_events` aliases
    // `auth_events` (see its impl above) and `event.auth_events()` returns
    // that same shared field. Running this block against it would validate
    // the wire-level `prev_state_events` list — up to `MAX_PREV_STATE_EVENTS`
    // (20) entries of arbitrary state-event types — against the classic
    // auth_events selection algorithm (`VALID_AUTH_TYPES` whitelist,
    // `required_auth_types_for`), incorrectly rejecting valid State DAG
    // events. MSC4242's own auth-relevant checks live in
    // `validate_msc4242_prev_state_events` (`src/state/dag.rs`), which
    // operates on `prev_state_events()` directly rather than through this
    // legacy citation-selection path.
    if let Some(provider) = auth_context.filter(|_| version != StateResVersion::V2_2) {
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

        let mut seen_tuples = crate::HashMap::new();

        for auth_id in event.auth_events() {
            let Some(auth_ev) = provider.get_event(auth_id) else {
                return Err(AuthError::MissingAuthEvent(auth_id.clone()));
            };

            // MSC4242 Rule 4.3: an event citing an auth event that was
            // itself rejected during PDU receipt is rejected in turn.
            if auth_ev.rejected() {
                return Err(AuthError::RejectedAuthEvent {
                    event_id: event.event_id().clone(),
                    auth_event_id: auth_id.clone(),
                });
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
            if seen_tuples.insert(key, auth_id.clone()).is_some() {
                return Err(AuthError::InvalidSyntax(
                    "auth_events contains duplicate (type, state_key) pair".into(),
                ));
            }
        }

        // Rule 2.2: auth_events must cite every (type, state_key) pair the
        // selection algorithm requires *and that actually exists in the
        // room's current state* — not just valid, non-duplicate entries.
        // A required type with no state entry yet (e.g. m.room.power_levels
        // before the room has ever set one) is correctly absent from
        // auth_events, so it's excluded here rather than demanded. Omitting
        // a citation that *does* exist in state (e.g. the target member
        // event for a membership change) previously passed silently; see
        // `required_auth_types_for` and `docs/spec_audit.md` rule 2.2.
        // The selection is room-version-aware (the v8+ restricted-join
        // authorising member), so read the actual version from the create
        // event rather than the collapsed `StateResVersion` enum.
        let room_version = room_version_str_or_v1(state)?;
        for (req_type, req_key) in required_auth_types_for(event, event_type, version, room_version)
        {
            let Some(state_ev) = state.get_event(req_type, req_key) else {
                continue;
            };
            // Rule 2.2/2.3: a citation must name the exact event selected
            // from this event's auth context, not merely its state tuple.
            // A stale/superseded event ID is equivalent to an omitted
            // required auth event.
            match seen_tuples.get(&(req_type.to_string(), req_key.to_string())) {
                Some(cited_id) if cited_id == state_ev.event_id() => {}
                _ => {
                    return Err(AuthError::IncompleteAuthEvents {
                        event_type: req_type.to_string(),
                        state_key: req_key.to_string(),
                    });
                }
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
            StateResVersion::V2_1
                | StateResVersion::V2_1_1
                | StateResVersion::V2_2
                | StateResVersion::V3
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

/// Whether `redaction` is authorized to redact `target`, given the room state.
///
/// Mirrors the spec's redaction rule:
/// - the target's own sender may always redact their own event;
/// - a sender whose power level is at least the `redact` level may redact
///   others' events;
/// - room versions 1–2 additionally allow a redaction whose `redacts` target
///   event ID shares a domain with the redaction's own event ID (federation
///   rule 11).
fn redaction_is_authorized<Id, C, E, K>(
    redaction: &LeanEvent<Id, C, K>,
    target: &LeanEvent<Id, C, K>,
    state: &impl StateProvider<Id, C, E>,
    version: StateResVersion,
    room_version: &str,
) -> bool
where
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
    K: crate::basespec::rezzy_types::StateKey,
{
    if redaction.sender() == target.sender() {
        return true;
    }
    let sender_pl = user::get_sender_power_level(redaction.sender(), state, version);
    if sender_pl >= get_redact_power_level(state) {
        return true;
    }
    // Legacy rule 11 (room v1/v2): allowed if the domain of the redacted
    // event (its `redacts` target) matches the domain of the redaction's own
    // event_id — matching `check_auth`'s rule, NOT the senders' domains.
    if matches!(room_version, "1" | "2") {
        return redaction.get_redacts().is_some_and(|target| {
            domain_matches(target, &alloc::format!("{}", redaction.event_id))
        });
    }
    false
}

/// The outcome of applying redactions to a batch of events.
///
/// Reports, for each `m.room.redaction` event in the batch, what happened to
/// its target so callers can surface or re-drive the redaction work without
/// re-deriving the authorization decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionReport<Id> {
    /// `(redaction_id, target_id)` pairs whose redaction was authorized and the
    /// target stripped in place.
    pub applied: Vec<(Id, Id)>,
    /// `(redaction_id, target_id)` pairs rejected because the redaction's
    /// sender was not authorized to redact the target.
    pub skipped_unauthorized: Vec<(Id, Id)>,
    /// `(redaction_id, target_id)` pairs whose target was absent from the
    /// current batch, so the redaction was deferred. The target is kept as a
    /// `String` because an out-of-batch target may not be representable as
    /// `Id` (e.g. an interned/numeric id that can only be resolved in storage).
    pub target_not_in_batch: Vec<(Id, String)>,
    /// `(redaction_id, target_id)` pairs that were authorized AND had their
    /// target present in this batch, but still failed to apply -- e.g. the
    /// target's `redacts` field was already stripped by an earlier redaction
    /// in the same batch (a redaction cycle). Distinct from
    /// `target_not_in_batch`: a caller should not retry these by waiting for
    /// the target to "arrive", since it's already here and won't change.
    pub failed_to_apply: Vec<(Id, Id)>,
}

impl<Id> Default for RedactionReport<Id> {
    fn default() -> Self {
        RedactionReport {
            applied: Vec::new(),
            skipped_unauthorized: Vec::new(),
            target_not_in_batch: Vec::new(),
            failed_to_apply: Vec::new(),
        }
    }
}

#[inline]
pub(crate) fn event_id_to_wire_cow<Id: core::fmt::Display + 'static>(
    id: &Id,
) -> alloc::borrow::Cow<'_, str> {
    if let Some(s) = (id as &dyn core::any::Any).downcast_ref::<alloc::string::String>() {
        return alloc::borrow::Cow::Borrowed(s.as_str());
    }
    if let Some(s) = (id as &dyn core::any::Any).downcast_ref::<alloc::sync::Arc<str>>() {
        return alloc::borrow::Cow::Borrowed(s.as_ref());
    }
    if let Some(s) = (id as &dyn core::any::Any).downcast_ref::<alloc::boxed::Box<str>>() {
        return alloc::borrow::Cow::Borrowed(s.as_ref());
    }
    alloc::borrow::Cow::Owned(alloc::string::ToString::to_string(id))
}

/// Apply each `m.room.redaction` event to its in-set target, but only when the
/// redaction is **authorized** against the provided room state.
///
/// This is the authorization-checked redaction step that belongs *after* state
/// resolution: unlike [`crate::basespec::rezzy_types::ingest_events`] (which
/// parses and verifies content hashes only and must not strip content), this
/// function has the resolved state needed to check the redact power level and
/// the target's sender. Unauthorized redactions leave the target untouched.
///
/// # Memory contract
/// This is a pure, in-memory transform — it performs no I/O and owns no state.
/// The caller must already hold, in memory:
/// - `events`: the slice of events to redact, including both the redaction
///   events and their targets. Targets outside `events` are left for a later
///   pass (a redaction and its target may arrive in different batches).
/// - `state`: the room state used to authorize *every* redaction in the
///   batch, against the *same* snapshot.
///
/// # Event-time state (single-state caveat)
/// This entry point authorizes every redaction against the one `state`
/// snapshot passed in, which is correct **only** when that snapshot equals
/// the state at each redaction's own `prev_events` for every redaction in
/// the batch (e.g. a batch of redactions with no intervening power-level or
/// membership changes at the time each was sent). If a sender's power level
/// changed between sending a redaction and the snapshot `state` represents,
/// this can incorrectly accept or reject that redaction — the Matrix spec
/// requires redaction authorization to use the state as of each redaction's
/// own `prev_events`, not a single shared snapshot. When callers can
/// reconstruct a per-redaction snapshot (e.g. by replaying `sorted_events`
/// forward the way [`check_auth_chain`] does), use
/// [`apply_authorized_redactions_with_state_at`] instead.
///
/// The function mutates `events` in place, replacing each authorized target
/// with its redacted form. Callers can use
/// [`LeanEvent::is_redaction`](crate::basespec::rezzy_types::LeanEvent::is_redaction)
/// to cheaply detect whether a batch contains any redaction work before
/// calling this.
///
/// Rejected or soft-failed redaction events are never applied.
#[must_use]
pub fn apply_authorized_redactions<Id, E, K>(
    events: &mut [LeanEvent<Id, serde_json::Value, K>],
    state: &impl StateProvider<Id, serde_json::Value, E>,
    version: StateResVersion,
    room_version: &str,
) -> RedactionReport<Id>
where
    Id: crate::basespec::rezzy_types::EventId + Clone + 'static,
    E: EventLike<Id = Id, Content = serde_json::Value>,
    K: crate::basespec::rezzy_types::StateKey + Clone,
{
    apply_authorized_redactions_with_state_at(
        events,
        |_redaction_id| Some(state),
        version,
        room_version,
    )
}

/// Like [`apply_authorized_redactions`], but authorizes each redaction
/// against the state **as of that redaction's own `prev_events`** (per the
/// Matrix spec), rather than a single shared snapshot.
///
/// `state_at(redaction_event_id)` is called once per redaction event whose
/// target is present in this batch (a redaction deferred because its target
/// is absent never triggers a lookup) and must return the room state at
/// that redaction's `prev_events`. Returning `None` (no event-time state
/// available for that redaction) is
/// treated the same as authorization failing: the redaction is recorded in
/// [`RedactionReport::skipped_unauthorized`] and its target is left
/// untouched, rather than guessing or falling back to another snapshot.
///
/// See [`apply_authorized_redactions`] for the rest of the memory contract
/// (the `events` slice, in-place mutation, rejected/soft-failed handling).
#[must_use]
pub fn apply_authorized_redactions_with_state_at<'s, Id, E, K, S>(
    events: &mut [LeanEvent<Id, serde_json::Value, K>],
    state_at: impl Fn(&Id) -> Option<&'s S>,
    version: StateResVersion,
    room_version: &str,
) -> RedactionReport<Id>
where
    Id: crate::basespec::rezzy_types::EventId + Clone + 'static,
    E: EventLike<Id = Id, Content = serde_json::Value>,
    K: crate::basespec::rezzy_types::StateKey + Clone,
    S: StateProvider<Id, serde_json::Value, E> + 's,
{
    // Collect active redaction positions first. If there are no redactions
    // in this batch, return immediately without constructing the index map.
    let redaction_positions: Vec<usize> = events
        .iter()
        .enumerate()
        // A rejected redaction is categorically invalid (failed auth against
        // its own auth_events) and must never strip content. Soft-failed
        // redactions are also excluded from being applied.
        .filter(|(_, e)| e.event_type == M_ROOM_REDACTION && !e.rejected && !e.soft_fail())
        .map(|(i, _)| i)
        .collect();

    if redaction_positions.is_empty() {
        return RedactionReport::default();
    }

    // Build the wire ID index map. For string-backed IDs (String, Arc<str>, Box<str>),
    // `event_id_to_wire_cow` borrows directly without allocating.
    let pos_by_id: alloc::collections::BTreeMap<alloc::borrow::Cow<'_, str>, usize> = events
        .iter()
        .enumerate()
        .map(|(i, e)| (event_id_to_wire_cow(&e.event_id), i))
        .collect();

    let mut pairs: Vec<(usize, usize)> = Vec::new();
    let mut deferred: Vec<(usize, alloc::string::String)> = Vec::new();
    for &rp in &redaction_positions {
        let Some(target_id) = events[rp].get_redacts() else {
            continue;
        };
        match pos_by_id.get(target_id) {
            Some(&tp) if tp != rp => pairs.push((rp, tp)),
            // Self-redaction (tp == rp): treat as a no-op, not a deferred
            // target. The target is present in the batch, so the catch-all
            // should not apply.
            Some(_) => {}
            _ => deferred.push((rp, target_id.to_string())),
        }
    }

    let mut report = RedactionReport::default();

    // Order pairs so a redaction is spent as a redactor before it can be
    // replaced as a target (redaction-of-redaction chains). If pair B targets
    // the redactor used by pair A, A must run first; otherwise the in-place
    // `*target = redacted` replaces the redaction source before it's used, and
    // `apply_redaction` returns None (its `redacts` field was stripped),
    // silently losing the outer redaction.
    //
    // Each pair's redactor position (`rp`) is unique -- `redaction_positions`
    // draws from distinct event indices -- so at most one other pair can
    // block a given pair (the one whose `rp` equals this pair's `tp`). That
    // makes the dependency graph a forest (plus, pathologically, cycles): a
    // linear-time topological sort (Kahn's algorithm) reproduces the same
    // order the old O(n^2)/O(n^3) repeated-scan (`position` + nested `any`
    // over the shrinking `remaining` list, once per pair) computed, without
    // rescanning on every pair. A genuine cycle (pathological: a redaction
    // chain that loops back on itself) leaves its members with a permanently
    // nonzero in-degree; append them in original order, matching the old
    // code's `unwrap_or(0)` fallback of just taking the next one when stuck.
    //
    // `crate::HashMap`, not `BTreeMap`: only point lookups happen below, its
    // iteration order is never relied on, and the keys are plain `usize`
    // positions -- so there's no reason to pay `BTreeMap`'s O(log n) per
    // insert/lookup when O(1) amortized is available, which keeps the whole
    // sort O(n) instead of O(n log n).
    let blocked_by: crate::HashMap<usize, usize> = pairs
        .iter()
        .enumerate()
        .map(|(i, &(rp, _))| (rp, i))
        .collect();
    let mut children: Vec<Vec<usize>> = alloc::vec![Vec::new(); pairs.len()];
    let mut in_degree: Vec<u8> = alloc::vec![0; pairs.len()];
    for (i, &(_, tp)) in pairs.iter().enumerate() {
        if let Some(&parent) = blocked_by.get(&tp) {
            children[parent].push(i);
            in_degree[i] = 1;
        }
    }
    let mut queue: VecDeque<usize> = (0..pairs.len()).filter(|&i| in_degree[i] == 0).collect();
    let mut order: Vec<usize> = Vec::with_capacity(pairs.len());
    let mut emitted = alloc::vec![false; pairs.len()];
    while let Some(i) = queue.pop_front() {
        order.push(i);
        emitted[i] = true;
        for &c in &children[i] {
            // Each child has exactly one parent (its unique `blocked_by`
            // predecessor), so this can only run once per child and never
            // underflows below 0.
            in_degree[c] = in_degree[c].saturating_sub(1);
            if in_degree[c] == 0 {
                queue.push_back(c);
            }
        }
    }
    order.extend((0..pairs.len()).filter(|&i| !emitted[i]));
    let ordered_pairs = order.into_iter().map(|i| pairs[i]).collect();
    pairs = ordered_pairs;

    for (rp, tp) in pairs {
        // Event-time state: authorize against the state as of this
        // redaction's own `prev_events`, not a shared/final snapshot. A
        // missing lookup result is treated as unauthorized rather than
        // guessed at.
        let authorized = match state_at(&events[rp].event_id) {
            Some(state_at_redaction) => redaction_is_authorized(
                &events[rp],
                &events[tp],
                state_at_redaction,
                version,
                room_version,
            ),
            None => false,
        };
        if !authorized {
            report
                .skipped_unauthorized
                .push((events[rp].event_id.clone(), events[tp].event_id.clone()));
            continue;
        }
        let (target, redaction) = if tp < rp {
            let (left, right) = events.split_at_mut(rp);
            (&mut left[tp], &right[0])
        } else {
            let (left, right) = events.split_at_mut(tp);
            (&mut right[0], &left[rp])
        };
        let redaction_id = redaction.event_id.clone();
        let target_id = target.event_id.clone();
        if let Some(redacted) = apply_redaction(target, redaction, room_version) {
            *target = redacted;
            report.applied.push((redaction_id, target_id));
        } else {
            // An authorized redaction whose target WAS present in this batch
            // but still failed to apply (e.g., its `redacts` field was
            // already stripped by a prior redaction in the chain). Distinct
            // from `target_not_in_batch`, which means "not present yet, try
            // again later" -- this target is present and won't change.
            report.failed_to_apply.push((redaction_id, target_id));
        }
    }

    // Redactions whose target is absent from this batch are deferred, not
    // applied; surface them so the caller can re-drive them once the target
    // arrives (or reject them) rather than silently dropping the redaction.
    for (rp, target_id) in deferred {
        report
            .target_not_in_batch
            .push((events[rp].event_id.clone(), target_id));
    }

    report
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
        return pl_threshold_for_event(pl_event, event_type, state_key);
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

/// Required power level for `event_type` under a specific `m.room.power_levels`
/// event. Shared by auth checks and the CDO demotion filter so the spec rule
/// (events.{type} -> `state_default` -> `events_default`) stays in one place.
pub(crate) fn pl_threshold_for_event<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    E: EventLike<Id = Id, Content = C>,
>(
    pl_event: &E,
    event_type: &str,
    state_key: Option<&str>,
) -> i64 {
    // Spec Rule 7: m.room.third_party_invite events require the invite level
    if event_type == crate::basespec::event_types::M_ROOM_THIRD_PARTY_INVITE {
        return pl_event.get_invite().unwrap_or(0);
    }
    // Check specific event type overrides
    if let Some(pl) = pl_event.get_event_power_level(event_type) {
        return pl;
    }
    // Fall back to state_default for state events, events_default for others
    if state_key.is_some() {
        return pl_event.get_state_default().unwrap_or(50);
    }
    pl_event.get_events_default().unwrap_or(0)
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
    let (required, label) = if current_membership == MEM_BAN {
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
    if target_user != event.sender() && (new_membership == MEM_LEAVE || new_membership == MEM_BAN) {
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
        MEM_JOIN => check_join_rules(event, state, target_user, version, verifier)?,
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
    verifier: Option<&dyn crate::basespec::rezzy_types::EventVerifier<Id>>,
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

    let supports_restricted = room_version_at_least(state, 8)?;
    let supports_knock_restricted = room_version_at_least(state, 10)?;

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
    } else if (join_rule == RULE_RESTRICTED && supports_restricted)
        || (join_rule == RULE_KNOCK_RESTRICTED && supports_knock_restricted)
    {
        // Restricted/knock_restricted (room version 8+/10+):
        // Allow if user is already invited/joined. Otherwise, require a valid
        // join_authorised_via_users_server field whose referenced user is:
        //   1. Joined to the room, AND
        //   2. Has sufficient power level to invite.
        if current_membership == MEM_INVITE || current_membership == MEM_JOIN {
            // Already invited or joined — allowed without further checks.
        } else if let Some(authorising_user) = event.get_join_authorised_via_users_server() {
            check_authorising_user(event, state, authorising_user, version, verifier)?;
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
    verifier: Option<&dyn crate::basespec::rezzy_types::EventVerifier<Id>>,
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

    // The normal verification pipeline checks the joining event's origin
    // signature. A restricted join additionally needs a signature from the
    // authorising user's homeserver. State-resolution callers deliberately
    // pass no verifier; PDU-receipt callers that do supply one get this
    // additional check.
    if let Some(verifier) = verifier {
        verifier
            .verify_join_authorised_via_users_server(event.event_id(), authorising_user)
            .map_err(AuthError::InvalidSyntax)?;
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

    let supports_knock_restricted = room_version_at_least(state, 10)?;
    if join_rule != RULE_KNOCK && !(join_rule == RULE_KNOCK_RESTRICTED && supports_knock_restricted)
    {
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

    let mut event_map: crate::HashMap<Id, LeanEvent<Id, C>> = sorted_events
        .iter()
        .map(|ev| (ev.event_id.clone(), ev.clone()))
        .collect();
    // Include initial-state events so Rule 2.5 foreign-room checks cannot be
    // bypassed by citing an auth event that lives only in initial_state.
    for ev in initial_state.values() {
        event_map
            .entry(ev.event_id.clone())
            .or_insert_with(|| ev.clone());
    }

    let mut rejected_ids = crate::HashSet::new();

    // V12+: room_id is no longer server-assigned/domain-based -- it's
    // derived from the create event, "!" followed by the same content hash
    // used for that event's own "$"-prefixed event ID (version_props.rs's
    // "Room ID format" note). Computed once; used only by the create-event
    // check below.
    let is_v12_plus = matches!(
        version,
        StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2
    );

    for event in sorted_events {
        // Rule 1.2 (V12+): if an m.room.create event declares a room_id, it
        // must be the hash-derived value anchored to this event's own event
        // ID, not merely internally consistent across the auth chain (that
        // weaker check is Rule 2.5, below, and applies to every event type).
        // A `None` here is not rejected -- `room_id` is opt-in on this crate's
        // `LeanEvent` (see its doc comment), and a caller that never
        // populates it must see identical behavior to before this check
        // existed.
        // Rule 1.2 (V12+): room_id is on the wire for ordinary events (it's
        // "!" + the create event's own hash-derived event ID, checked
        // against cited auth events by Rule 2.5 below), but *not* for the
        // create event itself: the room doesn't exist, and room_id isn't
        // knowable, until this event's own ID has been computed -- a create
        // event cannot self-referentially declare it. Any declared room_id
        // on a create event is invalid regardless of its value; this is not
        // a hash-match check.
        if is_v12_plus && event.event_type == "m.room.create" && event.room_id.is_some() {
            let err = AuthError::InvalidSyntax(
                "m.room.create must not declare room_id -- the room's ID is derived from this \
                 event's own hash and isn't knowable until this event exists"
                    .into(),
            );
            rejected.push((event.event_id.clone(), err));
            rejected_ids.insert(event.event_id.clone());
            continue;
        }

        // Rule 2.3 / MSC4242 Rule 4.3: an event citing an auth event that
        // was itself rejected during PDU receipt is rejected in turn (see
        // `AuthError::RejectedAuthEvent`'s docs).
        if let Some(auth_event_id) = event
            .auth_events
            .iter()
            .find(|auth_id| rejected_ids.contains(*auth_id))
            .cloned()
        {
            let err = AuthError::RejectedAuthEvent {
                event_id: event.event_id.clone(),
                auth_event_id,
            };
            rejected.push((event.event_id.clone(), err));
            rejected_ids.insert(event.event_id.clone());
            continue;
        }

        // Rule 2.5: reject if any cited auth event carries a room_id that
        // disagrees with this event's own, OR carries no room_id at all --
        // opt-in only on this (citing) event's side (see ForeignRoomEvent's
        // docs for why a `None` here never triggers the check, but a `None`
        // on the auth event's side, once triggered, is not a free pass).
        if let Some(expected) = &event.room_id {
            let foreign = event.auth_events.iter().find_map(|auth_id| {
                let auth_event = event_map.get(auth_id)?;
                match &auth_event.room_id {
                    Some(actual) if actual == expected => None,
                    Some(actual) => Some((auth_id.clone(), Some(actual.clone()))),
                    None => Some((auth_id.clone(), None)),
                }
            });
            if let Some((auth_event_id, actual)) = foreign {
                let err = AuthError::ForeignRoomEvent {
                    event_id: event.event_id.clone(),
                    auth_event_id,
                    expected: expected.to_string(),
                    actual: actual.map(|a| a.to_string()),
                };
                rejected.push((event.event_id.clone(), err));
                rejected_ids.insert(event.event_id.clone());
                continue;
            }
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
/// Trait-generic counterpart to [`auth_types_for_event`], used by rule 2.2's
/// completeness check in `check_auth_with_context`. Operates on
/// [`EventLike`]/[`crate::basespec::rezzy_types::EventContent`] accessors
/// rather than raw `serde_json::Value`, so it works for any event
/// representation (not just JSON-backed ones).
///
/// Delegates to the shared selection core [`auth_types_for_event_core`], so it
/// cannot drift from [`auth_types_for_event`].
fn required_auth_types_for<
    'a,
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent + 'a,
    E: EventLike<Id = Id, Content = C>,
>(
    event: &'a E,
    event_type: &'a str,
    version: StateResVersion,
    room_version: &'a str,
) -> Vec<(&'a str, &'a str)> {
    auth_types_for_event_core(
        event_type,
        event.sender(),
        event.state_key(),
        event.get_membership(),
        event.content().get_third_party_invite_token(),
        event.get_join_authorised_via_users_server(),
        version,
        room_version,
    )
}

/// The single auth-event selection algorithm shared by both the JSON-facing
/// [`auth_types_for_event`] and the trait-generic [`required_auth_types_for`].
///
/// Returns the `(type, state_key)` pairs an event requires in its
/// `auth_events`, given the event's already-extracted fields. Version checks
/// route through [`StateResVersion::is_v2_1_plus`] so there is one place the
/// V2.1 create-omission rule is expressed.
#[allow(clippy::too_many_arguments)]
fn auth_types_for_event_core<'a>(
    event_type: &str,
    sender: &'a str,
    state_key: Option<&'a str>,
    membership: Option<&str>,
    third_party_invite_token: Option<&'a str>,
    join_authorised_via_users_server: Option<&'a str>,
    version: StateResVersion,
    room_version: &str,
) -> Vec<(&'static str, &'a str)> {
    let mut auth_types = Vec::new();

    if event_type == M_ROOM_CREATE {
        return auth_types;
    }

    // V2.1+ omits m.room.create from auth events (spec change)
    if !version.is_v2_1_plus() {
        auth_types.push((M_ROOM_CREATE, ""));
    }
    auth_types.push((M_ROOM_MEMBER, sender));
    auth_types.push((M_ROOM_POWER_LEVELS, ""));

    if event_type == M_ROOM_MEMBER {
        if let Some(sk) = state_key.filter(|sk| *sk != sender) {
            auth_types.push((M_ROOM_MEMBER, sk));
        }

        if matches!(membership, Some(MEM_JOIN | MEM_INVITE | MEM_KNOCK)) {
            auth_types.push((M_ROOM_JOIN_RULES, ""));
        }

        // The `m.room.third_party_invite` auth event only applies to invite
        // memberships carrying a token (mirrors the accept-side gating in the
        // flagged-auth-state check); a token on any other membership is ignored.
        if membership == Some(MEM_INVITE) {
            if let Some(token) = third_party_invite_token {
                auth_types.push((M_ROOM_THIRD_PARTY_INVITE, token));
            }
        }

        // The authorising member is only a required auth event for
        // restricted-join memberships, which is a room-version-8+ (MSC3089)
        // feature. Gated on the ACTUAL room version string — the collapsed
        // `StateResVersion::V2` covers v2–11 and cannot express "v8+", so a
        // pre-v8 join that (maliciously or erroneously) carries the field must
        // not be made to require an authorising member the v2–7 rules don't.
        if membership == Some(MEM_JOIN)
            && (room_version
                .split('.')
                .next()
                .and_then(|m| m.parse::<u32>().ok())
                .is_some_and(|major| major >= 8)
                || StateResVersion::from_room_version(room_version)
                    .is_some_and(|v| v.is_v2_1_plus()))
        {
            if let Some(authorising_user) = join_authorised_via_users_server {
                auth_types.push((M_ROOM_MEMBER, authorising_user));
            }
        }
    }

    auth_types
}

#[must_use]
pub fn auth_types_for_event(
    event_type: &str,
    sender: &str,
    state_key: Option<&str>,
    content: &serde_json::Value,
    version: StateResVersion,
    room_version: &str,
) -> Vec<(String, String)> {
    let membership = content.get(FIELD_MEMBERSHIP).and_then(|v| v.as_str());

    let third_party_invite_token = content
        .get(FIELD_THIRD_PARTY_INVITE)
        .and_then(|t| t.as_object())
        .and_then(|tpi| tpi.get(FIELD_SIGNED).and_then(|s| s.as_object()))
        .and_then(|s| s.get(FIELD_TOKEN).and_then(|t| t.as_str()));

    let join_authorised_via_users_server = content
        .get(crate::basespec::event_types::FIELD_JOIN_AUTHORISED_VIA_USERS_SERVER)
        .and_then(|v| v.as_str());

    auth_types_for_event_core(
        event_type,
        sender,
        state_key,
        membership,
        third_party_invite_token,
        join_authorised_via_users_server,
        version,
        room_version,
    )
    .into_iter()
    .map(|(event_type, state_key)| (event_type.to_string(), state_key.to_string()))
    .collect()
}

/// Computes the required `(event_type, state_key)` authorization tuples for any [`EventLike`].
#[must_use]
pub fn auth_types_for_event_like<'a, E: EventLike + ?Sized>(
    event: &'a E,
    version: StateResVersion,
    room_version: &str,
) -> Vec<(&'static str, &'a str)> {
    auth_types_for_event_core(
        event.event_type().as_ref(),
        event.sender(),
        event.state_key(),
        event.get_membership(),
        event.get_third_party_invite_token(),
        event.get_join_authorised_via_users_server(),
        version,
        room_version,
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::basespec::event_types::M_ROOM_ALIASES;
    use alloc::vec;
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

        let result = check_join_rules(&join_event, &state, "@evil:x", StateResVersion::V2, None);
        assert!(
            matches!(result, Err(AuthError::BannedUser { .. })),
            "Must reject join from banned user: {result:?}"
        );
    }

    /// Coverage: `reject_flagged_auth_state` - invite must reject REJECTED
    /// `m.room.join_rules` auth state.
    #[test]
    fn test_invite_rejects_rejected_join_rules() {
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
                rejected: true,
                soft_fail: false,
                ..Default::default()
            },
        );

        let result = reject_flagged_auth_state(&invite_event, &state);
        assert!(
            matches!(result, Err(AuthError::InvalidSyntax(_))),
            "Invite must reject rejected join_rules auth state: {result:?}"
        );
    }

    /// Coverage: `reject_flagged_auth_state` must NOT reject SOFT-FAILED
    /// auth state. Per the server-server spec's "Soft failure" section:
    /// "Soft failed events participate in state resolution as normal if
    /// further events are received which reference it" and "it is possible
    /// for such events to appear in the current state of the room" -- once
    /// legitimately resolved into state, a soft-failed event is meant to be
    /// usable by later events like any other state, not blanket-rejected.
    #[test]
    fn test_invite_allows_soft_failed_join_rules() {
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
            result.is_ok(),
            "Soft-failed join_rules auth state must be usable, per spec \"Soft failure\": {result:?}"
        );
    }

    /// Coverage: `required_auth_types_for`'s `m.room.create` early return.
    /// Unreachable through the public API -- `check_auth_with_context`
    /// authorizes `m.room.create` and returns `Ok(())` before ever reaching
    /// rule 2.2's loop (creates are "always authorized if they're first"),
    /// so this function is never actually called with `event_type ==
    /// M_ROOM_CREATE` in practice. Exercised directly since it's still real,
    /// intentional behavior (an `m.room.create` has no required auth types
    /// of its own to check) -- called out explicitly rather than left
    /// permanently uncovered.
    #[test]
    fn test_coverage_required_auth_types_for_create_returns_empty() {
        let create_ev = make_test_event(
            "$create",
            M_ROOM_CREATE,
            "@creator:x",
            json!({"room_version": "11"}),
        );
        let required =
            required_auth_types_for(&create_ev, M_ROOM_CREATE, StateResVersion::V2, "11");
        assert!(
            required.is_empty(),
            "m.room.create has no required auth types of its own: {required:?}"
        );
    }

    /// Coverage: `required_auth_types_for`'s `m.room.third_party_invite`
    /// push. Reachable through the public API in principle (unlike the
    /// create early return above -- `m.room.member` events go through rule
    /// 2.2's loop normally), just never exercised by an existing scenario:
    /// no test built a member event with a `third_party_invite.signed.token`
    /// present in `content`.
    #[test]
    fn test_coverage_required_auth_types_for_third_party_invite_token() {
        let invite_ev = make_test_event(
            "$invite",
            M_ROOM_MEMBER,
            "@alice:x",
            json!({
                "membership": "invite",
                "third_party_invite": { "signed": { "token": "abc123" } }
            }),
        );
        let required =
            required_auth_types_for(&invite_ev, M_ROOM_MEMBER, StateResVersion::V2_1, "11");
        assert!(
            required.contains(&(M_ROOM_THIRD_PARTY_INVITE, "abc123")),
            "expected an (m.room.third_party_invite, \"abc123\") entry: {required:?}"
        );
    }

    /// Coverage: `required_auth_types_for`'s `join_authorised_via_users_server`
    /// push (the restricted-join authorising-member requirement). Same
    /// reachability note as the `third_party_invite` test above -- never
    /// exercised by an existing scenario.
    #[test]
    fn test_coverage_required_auth_types_for_join_authorised_via_users_server() {
        let join_ev = make_test_event(
            "$join",
            M_ROOM_MEMBER,
            "@alice:x",
            json!({
                "membership": "join",
                "join_authorised_via_users_server": "@authoriser:x"
            }),
        );
        let required =
            required_auth_types_for(&join_ev, M_ROOM_MEMBER, StateResVersion::V2_1, "11");
        assert!(
            required.contains(&(M_ROOM_MEMBER, "@authoriser:x")),
            "expected an (m.room.member, \"@authoriser:x\") entry: {required:?}"
        );
    }

    /// Regression: a pre-v8 (V1) join carrying `join_authorised_via_users_server`
    /// must NOT add the authorising member to its required auth events -- the
    /// field is a room-version-8+ (MSC3089) feature and pre-v8 rooms never
    /// honor it, even if a malformed event forges the field.
    #[test]
    fn test_pre_v8_join_authorised_via_users_server_omitted() {
        let join_ev = make_test_event(
            "$join",
            M_ROOM_MEMBER,
            "@alice:x",
            json!({
                "membership": "join",
                "join_authorised_via_users_server": "@authoriser:x"
            }),
        );
        let required = required_auth_types_for(&join_ev, M_ROOM_MEMBER, StateResVersion::V1, "1");
        assert!(
            !required.contains(&(M_ROOM_MEMBER, "@authoriser:x")),
            "a pre-v8 join must not require the authorising member as an auth event: {required:?}"
        );
    }

    /// Regression: the `join_authorised_via_users_server` auth tuple is gated
    /// on the ACTUAL room version (v8+), not the collapsed `StateResVersion`
    /// enum. `StateResVersion::V2` covers v2–11, so a pre-v8 (e.g. v6) join
    /// carrying the field must not be made to require an authorising member the
    /// v2–7 rules don't have, while a v8+ join must.
    #[test]
    fn test_join_authorised_gated_on_actual_room_version() {
        let join_ev = make_test_event(
            "$join",
            M_ROOM_MEMBER,
            "@alice:x",
            json!({
                "membership": "join",
                "join_authorised_via_users_server": "@authoriser:x"
            }),
        );

        let pre_v8 = required_auth_types_for(&join_ev, M_ROOM_MEMBER, StateResVersion::V2, "6");
        assert!(
            !pre_v8.contains(&(M_ROOM_MEMBER, "@authoriser:x")),
            "a v6 join must not require the authorising member: {pre_v8:?}"
        );

        let v8 = required_auth_types_for(&join_ev, M_ROOM_MEMBER, StateResVersion::V2, "8");
        assert!(
            v8.contains(&(M_ROOM_MEMBER, "@authoriser:x")),
            "a v8+ join with the field must require the authorising member: {v8:?}"
        );
    }

    /// Regression: a non-invite membership carrying a `third_party_invite`
    /// token must NOT add the third-party invite auth event -- that auth type
    /// applies only to `membership: invite` events.
    #[test]
    fn test_non_invite_membership_third_party_token_omitted() {
        let join_ev = make_test_event(
            "$join",
            M_ROOM_MEMBER,
            "@alice:x",
            json!({
                "membership": "join",
                "third_party_invite": { "signed": { "token": "abc123" } }
            }),
        );
        let required =
            required_auth_types_for(&join_ev, M_ROOM_MEMBER, StateResVersion::V2_1, "11");
        assert!(
            !required.contains(&(M_ROOM_THIRD_PARTY_INVITE, "abc123")),
            "a non-invite membership's token must not require the third-party invite auth event: {required:?}"
        );
    }

    /// Partial-state resolution keeps the historical v1 fallback when no
    /// `m.room.create` is available.
    #[test]
    fn test_room_version_warn_no_create_in_state() {
        let mut state: RoomState = RoomState::new();
        // Need a member event so Rule 2 (sender must be joined) passes.
        state.insert(
            (M_ROOM_MEMBER.into(), "@alice:example.com".into()),
            make_test_event(
                "$member",
                M_ROOM_MEMBER,
                "@alice:example.com",
                json!({ "membership": "join" }),
            ),
        );
        // Need a power_levels event so Rule 7 (sender PL check) passes.
        state.insert(
            (M_ROOM_POWER_LEVELS.into(), String::new()),
            make_test_event(
                "$pl",
                M_ROOM_POWER_LEVELS,
                "@alice:example.com",
                json!({ "users": { "@alice:example.com": 100 } }),
            ),
        );

        // An m.room.aliases event triggers Rule 4. With no create state the
        // room-version helper uses the spec-defined v1 default.
        let aliases_ev = LeanEvent {
            event_id: "$aliases".into(),
            event_type: M_ROOM_ALIASES.into(),
            state_key: Some("#test:example.com".into()),
            sender: "@alice:example.com".into(),
            content: json!({}),
            ..Default::default()
        };
        let result = check_auth_with_context(&aliases_ev, &state, StateResVersion::V1, None, None);
        // Rule 4 fires for v1-v5 and the default passes the aliases domain
        // check; missing create state is not itself an authorization error.
        assert!(
            result.is_ok(),
            "aliases event should still auth OK with default room version: {result:?}"
        );
    }

    #[test]
    fn test_auth_rejects_unsupported_create_room_version() {
        let create = make_test_event(
            "$create",
            M_ROOM_CREATE,
            "@creator:example.com",
            json!({ "room_version": "0" }),
        );
        let result = check_auth(&create, &RoomState::new(), StateResVersion::V1, None);
        assert!(
            matches!(result, Err(AuthError::InvalidSyntax(ref message)) if message.contains("room_version")),
            "unsupported create room version must fail auth: {result:?}"
        );
    }

    #[test]
    fn test_auth_chain_rejects_state_with_unsupported_room_version() {
        let mut initial_state = RoomState::new();
        initial_state.insert(
            (M_ROOM_CREATE.into(), String::new()),
            make_test_event(
                "$create",
                M_ROOM_CREATE,
                "@creator:example.com",
                json!({ "room_version": "0" }),
            ),
        );
        let event = make_test_event("$event", "m.room.name", "@creator:example.com", json!({}));
        let (accepted, rejected) = check_auth_chain(&[event], &initial_state, StateResVersion::V1);
        assert_eq!(accepted, [] as [std::string::String; 0]);
        assert!(matches!(
            rejected.as_slice(),
            [(id, AuthError::InvalidSyntax(message))]
                if id == "$event" && message.contains("room_version")
        ));
    }

    #[test]
    fn test_auth_chain_rejects_non_string_room_version() {
        // A `room_version` present but not a string (e.g. a JSON number) must
        // not be silently treated as "absent" and fall back to v1 — that
        // would let a malformed label sneak past `validated_room_version_or_v1`
        // into legacy literal-version rules instead of being rejected.
        let mut initial_state = RoomState::new();
        initial_state.insert(
            (M_ROOM_CREATE.into(), String::new()),
            make_test_event(
                "$create",
                M_ROOM_CREATE,
                "@creator:example.com",
                json!({ "room_version": 12 }),
            ),
        );
        let event = make_test_event("$event", "m.room.name", "@creator:example.com", json!({}));
        let (accepted, rejected) = check_auth_chain(&[event], &initial_state, StateResVersion::V1);
        assert_eq!(accepted, [] as [std::string::String; 0]);
        assert!(matches!(
            rejected.as_slice(),
            [(id, AuthError::InvalidSyntax(message))]
                if id == "$event" && message.contains("room_version")
        ));
    }

    /// Coverage: `apply_authorized_redactions` — self-redaction no-op (line 1279).
    /// A redaction whose `redacts` field points to its own `event_id` is a
    /// no-op: the pair is skipped (`Some(_) => {}`), not deferred.
    #[test]
    fn test_self_redaction_is_no_op() {
        use crate::auth::{apply_authorized_redactions, RoomState};

        let pl: LeanEvent = LeanEvent {
            event_id: "$pl:example.com".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@admin:example.com".into(),
            content: serde_json::json!({
                "users": { "@admin:example.com": 100 },
                "redact": 0
            }),
            ..Default::default()
        };
        let mut state = RoomState::new();
        state.insert(("m.room.power_levels".to_string(), String::new()), pl);

        // A redaction that targets itself.
        let self_redact: LeanEvent = LeanEvent {
            event_id: "$self_redact:example.com".into(),
            event_type: "m.room.redaction".into(),
            sender: "@alice:example.com".into(),
            origin_server_ts: 10,
            content: serde_json::json!({ "redacts": "$self_redact:example.com" }),
            ..Default::default()
        };

        let mut events = vec![self_redact.clone()];
        let report = apply_authorized_redactions(&mut events, &state, StateResVersion::V2, "11");

        assert!(
            report.applied.is_empty(),
            "self-redaction must not be applied: {report:?}"
        );
        assert!(
            report.target_not_in_batch.is_empty(),
            "self-redaction must not be deferred either: {report:?}"
        );
        assert!(
            report.skipped_unauthorized.is_empty(),
            "self-redaction must not be reported unauthorized: {report:?}"
        );
        // The event content must be unchanged.
        assert_eq!(events[0].content, self_redact.content);
    }

    /// Coverage: `apply_authorized_redactions` — authorized redaction that
    /// failed to apply because its `redacts` field was already stripped by
    /// a prior redaction in the chain (lines 1363-1369).
    ///
    /// Scenario: a cycle — R1 redacts R2 and R2 redacts R1, using a pre-v11
    /// room version where `m.room.redaction` has no preserved keys (so
    /// redacting an `m.room.redaction` strips its `redacts` field). The topo
    /// sort can't break the cycle, so pairs are emitted in original order. R1
    /// runs first, stripping R2 (including its `redacts` field). R2 then
    /// tries to redact R1 but `get_redacts()` returns None, so
    /// `apply_redaction` returns None.
    #[test]
    fn test_authorized_redaction_failed_to_apply_surfaces_in_report() {
        use crate::auth::{apply_authorized_redactions, RoomState};

        let pl: LeanEvent = LeanEvent {
            event_id: "$pl:example.com".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@admin:example.com".into(),
            content: serde_json::json!({
                "users": { "@alice:example.com": 50 },
                "redact": 0
            }),
            ..Default::default()
        };
        let mut state = RoomState::new();
        state.insert(("m.room.power_levels".to_string(), String::new()), pl);

        // R1 redacts R2.
        let r1: LeanEvent = LeanEvent {
            event_id: "$r1:example.com".into(),
            event_type: "m.room.redaction".into(),
            sender: "@alice:example.com".into(),
            origin_server_ts: 10,
            content: serde_json::json!({ "redacts": "$r2:example.com" }),
            ..Default::default()
        };
        // R2 redacts R1 — a cycle.
        let r2: LeanEvent = LeanEvent {
            event_id: "$r2:example.com".into(),
            event_type: "m.room.redaction".into(),
            sender: "@alice:example.com".into(),
            origin_server_ts: 11,
            content: serde_json::json!({ "redacts": "$r1:example.com" }),
            ..Default::default()
        };

        // Use room version "1" where m.room.redaction preserves no keys —
        // so redacting R2 strips its `redacts` field.
        let mut events = vec![r1.clone(), r2.clone()];
        let report = apply_authorized_redactions(&mut events, &state, StateResVersion::V1, "1");

        // R1 applied (redacted R2).
        assert!(
            report
                .applied
                .contains(&("$r1:example.com".into(), "$r2:example.com".into())),
            "R1's redaction of R2 must be applied: {report:?}"
        );
        // R2's redaction of R1 failed because R2 was stripped by R1. R1 (the
        // target) IS present in the batch, so this is `failed_to_apply`, not
        // `target_not_in_batch` (which means "target not present yet").
        assert!(
            report
                .failed_to_apply
                .contains(&("$r2:example.com".into(), "$r1:example.com".into())),
            "R2's failed redaction of R1 must surface in failed_to_apply: {report:?}"
        );
    }

    /// Coverage: `check_auth_chain` — `initial_state` events included in
    /// Rule 2.5 foreign-room check (lines 1959-1961).
    ///
    /// An auth event present only in `initial_state` (not in `sorted_events`)
    /// with a foreign `room_id` must be caught by Rule 2.5.
    #[test]
    fn test_check_auth_chain_foreign_room_in_initial_state() {
        // A create event from a different room, living only in initial_state.
        let foreign_create = make_test_event(
            "$foreign_create:other.org",
            M_ROOM_CREATE,
            "@admin:other.org",
            json!({ "room_version": "11", "room_id": "!other:other.org" }),
        );
        let mut initial_state: RoomState = RoomState::new();
        initial_state.insert(
            (M_ROOM_CREATE.into(), String::new()),
            foreign_create.clone(),
        );

        // An event that cites the foreign create in its auth_events.
        let mut citing_event = make_test_event(
            "$citing:example.com",
            M_ROOM_POWER_LEVELS,
            "@alice:example.com",
            json!({ "users": { "@alice:example.com": 100 } }),
        );
        citing_event.auth_events = vec!["$foreign_create:other.org".into()];
        citing_event.room_id = Some("!myroom:example.com".into());

        let sorted_events = vec![citing_event];
        let (_accepted, rejected) =
            check_auth_chain(&sorted_events, &initial_state, StateResVersion::V2);

        assert!(
            rejected.iter().any(|(_, err)| matches!(
                err,
                AuthError::ForeignRoomEvent { .. }
            )),
            "event citing a foreign-room auth event from initial_state must be rejected: {rejected:?}"
        );
    }

    /// Coverage: `check_auth_chain` Rule 1.2 (V12+) -- an `m.room.create`
    /// event must not declare a `room_id` at all. This is not a hash-match
    /// check: the room doesn't exist, and its ID isn't knowable, until the
    /// create event's own hash has been computed, so a create event can
    /// never legitimately declare *any* `room_id`, correct-looking or not.
    #[test]
    fn test_check_auth_chain_rejects_any_v12_create_room_id() {
        let mut create = make_test_event(
            "$QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE",
            M_ROOM_CREATE,
            "@alice:example.com",
            json!({ "room_version": "12", "creator": "@alice:example.com" }),
        );
        // Even a room_id that happens to equal this event's own
        // hash-derived form is still rejected -- Rule 1.2 has no "correct
        // value" exception, unlike Rule 2.5's hash-match style check.
        create.room_id = Some("!QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE".into());

        let sorted_events = vec![create];
        let (accepted, rejected) =
            check_auth_chain(&sorted_events, &RoomState::new(), StateResVersion::V2_1);

        assert!(
            accepted.is_empty(),
            "a create event declaring any room_id must not be accepted: {accepted:?}"
        );
        assert!(
            rejected
                .iter()
                .any(|(_, err)| matches!(err, AuthError::InvalidSyntax(_))),
            "V12+ create event with a declared room_id must be rejected: {rejected:?}"
        );
    }

    /// Coverage: `check_auth_chain` Rule 1.2 -- a `None` `room_id` (the
    /// field is opt-in on `LeanEvent`, and a create event legitimately
    /// never has one under V12+) does not trigger this rule.
    #[test]
    fn test_check_auth_chain_v12_create_without_room_id_is_accepted() {
        let event_id = "$abcHASHpart";
        let create = make_test_event(
            event_id,
            M_ROOM_CREATE,
            "@alice:example.com",
            json!({ "room_version": "12", "creator": "@alice:example.com" }),
        );
        assert_eq!(create.room_id, None);

        let sorted_events = vec![create];
        let (accepted, rejected) =
            check_auth_chain(&sorted_events, &RoomState::new(), StateResVersion::V2_1);

        assert!(
            rejected.is_empty(),
            "a create event with no room_id at all must not be affected by Rule 1.2: {rejected:?}"
        );
        assert_eq!(accepted, vec![event_id.to_string()]);
    }

    /// Coverage: `check_auth_chain` Rule 1.2 is gated to V12+ -- a
    /// pre-V12 room version's create event may declare a `room_id` (the
    /// legacy, server-assigned/domain-based form) without being affected
    /// by a rule that only exists for the hash-derived room-ID scheme.
    #[test]
    fn test_check_auth_chain_pre_v12_create_room_id_is_unaffected_by_rule_1_2() {
        let event_id = "$create:example.com";
        let mut create = make_test_event(
            event_id,
            M_ROOM_CREATE,
            "@alice:example.com",
            json!({ "room_version": "9", "creator": "@alice:example.com" }),
        );
        create.room_id = Some("!legacy:example.com".into());

        let sorted_events = vec![create];
        let (accepted, rejected) =
            check_auth_chain(&sorted_events, &RoomState::new(), StateResVersion::V2);

        assert!(
            rejected.is_empty(),
            "pre-V12 create room_id must not trigger the V12+-only Rule 1.2: {rejected:?}"
        );
        assert_eq!(accepted, vec![event_id.to_string()]);
    }
}
