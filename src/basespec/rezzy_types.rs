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

//! Core data types for Matrix state resolution.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use serde::Deserialize;
use serde_json::Value;

use crate::basespec::event_types::MAX_POWER_LEVEL_JSON;

/// Trait alias for types that can serve as event identifiers.
///
/// Any type that is `Clone + Eq + Hash + Ord + Debug` automatically implements
/// this trait via a blanket impl. In practice, this is either `String` (for
/// human-readable event IDs like `$abc123:example.com`) or `u32`/`u64` (for
/// integer-interned short IDs used by homeservers).
pub trait EventId: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug {}
impl<T: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug> EventId for T {}

/// Selects which state resolution algorithm to use.
///
/// Each variant corresponds to a set of Matrix room versions and spec behaviors:
///
/// | Variant | Room Versions | Key Change |
/// |---------|:---:|---|
/// | [`V1`](Self::V1) | 1 | Depth-based topological sort, all `m.room.member` events are power events. |
/// | [`V2`](Self::V2) | 2–11 | Reverse topological power ordering via Kahn's algorithm, mainline sort. |
/// | [`V2_1`](Self::V2_1) | 12+ ([MSC4297]) | Empty initial state, conflicted subgraph extraction, CDO filtering. |
/// | [`V2_1_1`](Self::V2_1_1) | — | Ban evasion fix: restricts power-phase state supplementation. |
/// | [`V2_2`](Self::V2_2) | — | Reserved for State DAGs ([MSC4242]). |
///
/// [MSC4297]: https://github.com/matrix-org/matrix-spec-proposals/pull/4297
/// [MSC4242]: https://github.com/matrix-org/matrix-spec-proposals/pull/4242
///
/// ## TODO: Redaction preserved keys
///
/// Rezzy does not implement redaction stripping. The spec defines which content
/// keys survive redaction per event type, evolving across room versions:
///
/// | Fragment | Room Versions | Delta from previous |
/// |----------|:---:|---|
/// | `v1-redactions.txt` | 1–5 | Baseline. PL: `ban`, `events`, `events_default`, `kick`, `redact`, `state_default`, `users`, `users_default`. Member: `membership`. |
/// | `v6-redactions.txt` | 6–8 | Removes `m.room.aliases`. |
/// | `v9-redactions.txt` | 9–10 | Member: adds `join_authorised_via_users_server`. Join rules: adds `allow`. |
/// | `v11-redactions.txt` | 11+ | PL: adds `invite`. Create: allows ALL keys. Member: adds `third_party_invite.signed`. Drops top-level `prev_state`, `origin`, `membership`. Adds `m.room.redaction` preserving `redacts`. |
///
/// **Key invariant:** `users` in `m.room.power_levels` is preserved on redaction
/// in ALL versions. Redaction alone cannot cause the PL wipeout vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[allow(non_camel_case_types)]
pub enum StateResVersion {
    /// State Resolution V1 (room version 1).
    V1,
    /// State Resolution V2 (room versions 2–11).
    V2,
    /// State Resolution V2.1 — [MSC4297](https://github.com/matrix-org/matrix-spec-proposals/pull/4297) (room version 12+).
    V2_1,
    /// State Resolution V2.1.1 — experimental algo (restricts power-phase supplementation).
    V2_1_1,
    /// State Resolution V2.2 — reserved for State DAGs ([MSC4242](https://github.com/matrix-org/matrix-spec-proposals/pull/4242)).
    V2_2,
}

impl StateResVersion {
    /// Map a Matrix room version string (e.g. `"10"`, `"12"`) to the corresponding
    /// state resolution algorithm version.
    ///
    /// Returns `None` for unrecognized room versions.
    #[must_use]
    pub fn from_room_version(ver: &str) -> Option<Self> {
        match ver {
            "1" => Some(Self::V1),
            "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10" | "11" => Some(Self::V2),
            "12" => Some(Self::V2_1),
            "12.1" => Some(Self::V2_1_1),
            _ => None,
        }
    }
}

impl serde::Serialize for StateResVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            StateResVersion::V1 => "V1",
            StateResVersion::V2 => "V2",
            StateResVersion::V2_1 => "V2_1",
            StateResVersion::V2_1_1 => "V2_1_1",
            StateResVersion::V2_2 => "V2_2",
        };
        serializer.serialize_str(s)
    }
}

impl<'de> serde::Deserialize<'de> for StateResVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StateResVersionVisitor;

        impl serde::de::Visitor<'_> for StateResVersionVisitor {
            type Value = StateResVersion;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a StateResVersion string")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value {
                    "V1" => Ok(StateResVersion::V1),
                    "V2" => Ok(StateResVersion::V2),
                    "V2_1" => Ok(StateResVersion::V2_1),
                    "V2_1_1" => Ok(StateResVersion::V2_1_1),
                    "V2_2" => Ok(StateResVersion::V2_2),
                    _ => Err(E::custom(alloc::format!("unknown variant `{value}`"))),
                }
            }
        }

        deserializer.deserialize_str(StateResVersionVisitor)
    }
}

/// Result of Kahn's topological sort with diagnostic information.
#[derive(Debug, Clone)]
pub enum KahnSortResult<Id = String> {
    /// All events were successfully sorted.
    Ok(Vec<Id>),
    /// A cycle was detected. `sorted` contains the partial ordering of events
    /// that could be processed, `stuck` contains events that could not reach
    /// in-degree 0 (involved in cycles).
    CycleDetected { sorted: Vec<Id>, stuck: Vec<Id> },
}

impl<Id> KahnSortResult<Id> {
    /// Returns the sorted event IDs, or an empty vec if a cycle was detected.
    /// This preserves backward compatibility with the old API.
    #[must_use]
    pub fn into_sorted(self) -> Vec<Id> {
        match self {
            KahnSortResult::Ok(v) => v,
            KahnSortResult::CycleDetected { .. } => Vec::new(),
        }
    }

    /// Returns true if sorting completed without cycles.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, KahnSortResult::Ok(_))
    }
}

/// A generic interface for graph nodes required by topological algorithms
/// (e.g., `compute_merge_base`). This allows consumers like `conduwuit` to
/// pass their own lightweight `EventMeta` tuples without allocating dummy JSON structs.
///
/// # Relationship to [`EventLike`]
///
/// `DagNode` is a supertrait of [`EventLike`]. Implementors who only need
/// topological traversal (e.g. LCA / merge-base computation) can implement
/// `DagNode` alone without the full suite of auth-related accessors.
pub trait DagNode {
    /// The event identifier type (e.g. `String`, `u32`).
    type Id: EventId;

    /// Returns a reference to this event's unique identifier.
    fn event_id(&self) -> &Self::Id;

    /// DAG depth (distance from the root `m.room.create` event).
    fn depth(&self) -> u64;

    /// Event IDs of this event's parents in the timeline DAG.
    fn prev_events(&self) -> &[Self::Id];

    /// Event IDs of the authorization events for this event.
    fn auth_events(&self) -> &[Self::Id];
}

impl<Id: EventId, C> DagNode for LeanEvent<Id, C> {
    type Id = Id;

    fn event_id(&self) -> &Id {
        &self.event_id
    }
    fn depth(&self) -> u64 {
        self.depth
    }
    fn prev_events(&self) -> &[Id] {
        &self.prev_events
    }
    fn auth_events(&self) -> &[Id] {
        &self.auth_events
    }
}

/// Unified trait for Matrix events used by the auth and resolution engines.
///
/// `EventLike` extends [`DagNode`] with the full set of envelope fields
/// (sender, event type, state key, etc.) and content accessors (membership,
/// power levels, join rules, etc.) needed for authorization checks.
///
/// # For downstream homeservers
///
/// Implement this trait on your native event type (e.g. `PduEvent`) to call
/// `check_auth` and `resolve_iterative_sort` without converting to `LeanEvent`.
/// This eliminates all string cloning, content serialization, and `Vec`
/// allocation at the rezzy boundary.
///
/// # Example
///
/// ```rust,ignore
/// impl EventLike for PduEvent {
///     fn event_type(&self) -> Cow<'_, str> { self.kind.to_cow_str() }
///     fn sender(&self) -> &str { self.sender.as_str() }
///     fn get_membership(&self) -> Option<&str> { /* read from typed content */ }
///     // ...
/// }
/// ```
pub trait EventLike: DagNode {
    /// The content type (e.g. `serde_json::Value` or a typed struct).
    type Content: EventContent;

    /// Matrix event type (e.g. `m.room.member`, `m.room.power_levels`).
    ///
    /// Returns `Cow::Borrowed` when the type string is stored inline (e.g. `LeanEvent`),
    /// or `Cow::Owned`/`Cow::Borrowed` from a typed enum (e.g. ruma `TimelineEventType`).
    fn event_type(&self) -> alloc::borrow::Cow<'_, str>;

    /// The MXID of the user who sent the event.
    fn sender(&self) -> &str;

    /// State key for state events; `None` for timeline (non-state) events.
    fn state_key(&self) -> Option<&str>;

    /// Sender's cached power level at the time of the event.
    fn power_level(&self) -> i64;

    /// Origin server timestamp in milliseconds since Unix epoch.
    fn origin_server_ts(&self) -> u64;

    /// Access the event content (parsed or stored).
    fn content(&self) -> &Self::Content;

    // === Content accessors — default impls delegate to self.content() ===

    /// Returns the `membership` field from event content.
    fn get_membership(&self) -> Option<&str> {
        self.content().get_membership()
    }

    /// Returns the `join_rule` field from event content.
    fn get_join_rule(&self) -> Option<&str> {
        self.content().get_join_rule()
    }

    /// Returns the power level for a specific user from `content.users`.
    fn get_user_power_level(&self, user: &str) -> Option<i64> {
        self.content().get_user_power_level(user)
    }

    /// Returns the required power level for a specific event type from `content.events`.
    fn get_event_power_level(&self, event_type: &str) -> Option<i64> {
        self.content().get_event_power_level(event_type)
    }

    /// Returns the `users_default` power level.
    fn get_users_default(&self) -> Option<i64> {
        self.content().get_users_default()
    }

    /// Returns the `events_default` power level.
    fn get_events_default(&self) -> Option<i64> {
        self.content().get_events_default()
    }

    /// Returns the `state_default` power level.
    fn get_state_default(&self) -> Option<i64> {
        self.content().get_state_default()
    }

    /// Returns the `ban` power level threshold.
    fn get_ban(&self) -> Option<i64> {
        self.content().get_ban()
    }

    /// Returns the `kick` power level threshold.
    fn get_kick(&self) -> Option<i64> {
        self.content().get_kick()
    }

    /// Returns the `invite` power level threshold.
    fn get_invite(&self) -> Option<i64> {
        self.content().get_invite()
    }

    /// Returns the `redact` power level threshold.
    fn get_redact(&self) -> Option<i64> {
        self.content().get_redact()
    }

    /// Returns the `creator` field from `m.room.create` content.
    fn get_creator(&self) -> Option<&str> {
        self.content().get_creator()
    }

    /// Returns the `room_version` field from `m.room.create` content.
    fn get_room_version(&self) -> Option<&str> {
        self.content().get_room_version()
    }

    /// Returns true if `sender` is listed in the V12+ `additional_creators` array.
    fn has_additional_creator(&self, sender: &str) -> bool {
        self.content().has_additional_creator(sender)
    }

    /// Returns the `join_authorised_via_users_server` field, if present.
    fn get_join_authorised_via_users_server(&self) -> Option<&str> {
        self.content().get_join_authorised_via_users_server()
    }

    /// Returns whether a `third_party_invite` field is present.
    fn has_third_party_invite(&self) -> bool {
        self.content().has_third_party_invite()
    }

    /// Returns the signed token from `third_party_invite.signed.token`.
    fn get_third_party_invite_token(&self) -> Option<&str> {
        self.content().get_third_party_invite_token()
    }

    /// Returns the mxid from `third_party_invite.signed.mxid`.
    fn get_third_party_invite_mxid(&self) -> Option<&str> {
        self.content().get_third_party_invite_mxid()
    }

    /// Returns whether `third_party_invite.signed.signatures` is present and non-empty.
    fn has_third_party_invite_signatures(&self) -> bool {
        self.content().has_third_party_invite_signatures()
    }
}

impl<Id: EventId, C: EventContent> EventLike for LeanEvent<Id, C> {
    type Content = C;

    fn event_type(&self) -> alloc::borrow::Cow<'_, str> {
        alloc::borrow::Cow::Borrowed(&self.event_type)
    }
    fn sender(&self) -> &str {
        &self.sender
    }
    fn state_key(&self) -> Option<&str> {
        self.state_key.as_deref()
    }
    fn power_level(&self) -> i64 {
        self.power_level
    }
    fn origin_server_ts(&self) -> u64 {
        self.origin_server_ts
    }
    fn content(&self) -> &C {
        &self.content
    }
}

// ── RawEvent + ParsedEvent: zero-boilerplate adapter ────────────────

/// Trait for external event types that store content as raw JSON.
///
/// Implement this on your native PDU type (~9 one-liner field accessors),
/// then wrap with [`ParsedEvent`] to get [`DagNode`] + [`EventLike`] for free.
///
/// # Example
///
/// ```rust,ignore
/// impl RawEvent for MyPdu {
///     type Id = OwnedEventId;
///     fn raw_event_id(&self) -> &OwnedEventId { &self.event_id }
///     fn raw_event_type(&self) -> Cow<'_, str> { self.kind.to_cow_str() }
///     fn raw_sender(&self) -> &str { self.sender.as_str() }
///     fn raw_state_key(&self) -> Option<&str> { self.state_key.as_deref() }
///     fn raw_content_json(&self) -> &str { self.content.get() }
///     fn raw_prev_events(&self) -> &[OwnedEventId] { &self.prev_events }
///     fn raw_auth_events(&self) -> &[OwnedEventId] { &self.auth_events }
///     fn raw_depth(&self) -> u64 { self.depth.into() }
///     fn raw_origin_server_ts(&self) -> u64 { self.origin_server_ts.into() }
/// }
///
/// // Then:
/// let event = ParsedEvent::new(&my_pdu);
/// rezzy::auth::check_auth(&event, &state, version, None)?;
/// ```
pub trait RawEvent {
    /// The event ID type (e.g. `OwnedEventId`, `String`).
    type Id: EventId;

    /// The event's unique identifier.
    fn raw_event_id(&self) -> &Self::Id;

    /// The Matrix event type as a string (e.g. `"m.room.member"`).
    fn raw_event_type(&self) -> alloc::borrow::Cow<'_, str>;

    /// The sender's MXID as a string slice.
    fn raw_sender(&self) -> &str;

    /// The state key, if this is a state event.
    fn raw_state_key(&self) -> Option<&str>;

    /// The raw JSON content of the event.
    fn raw_content_json(&self) -> &str;

    /// References to parent event IDs in the DAG.
    fn raw_prev_events(&self) -> &[Self::Id];

    /// References to auth event IDs.
    fn raw_auth_events(&self) -> &[Self::Id];

    /// DAG depth.
    fn raw_depth(&self) -> u64;

    /// Origin server timestamp in milliseconds since Unix epoch.
    fn raw_origin_server_ts(&self) -> u64;

    /// Cached power level (used for state resolution sort priority).
    /// Defaults to `0` — override if your type caches this.
    fn raw_power_level(&self) -> i64 {
        0
    }
}

/// Wraps a `&T` (where `T: RawEvent`) with a cached parsed
/// `serde_json::Value` content, providing [`DagNode`] + [`EventLike`]
/// for free.
///
/// Content is parsed once at construction from [`RawEvent::raw_content_json`].
pub struct ParsedEvent<'a, T: RawEvent> {
    raw: &'a T,
    content: serde_json::Value,
}

impl<'a, T: RawEvent> ParsedEvent<'a, T> {
    /// Create a new `ParsedEvent`, parsing the raw JSON content once.
    #[must_use]
    pub fn new(event: &'a T) -> Self {
        let content = serde_json::from_str(event.raw_content_json()).unwrap_or_default();
        Self {
            raw: event,
            content,
        }
    }
}

impl<T: RawEvent> DagNode for ParsedEvent<'_, T> {
    type Id = T::Id;

    fn event_id(&self) -> &T::Id {
        self.raw.raw_event_id()
    }

    fn depth(&self) -> u64 {
        self.raw.raw_depth()
    }

    fn prev_events(&self) -> &[T::Id] {
        self.raw.raw_prev_events()
    }

    fn auth_events(&self) -> &[T::Id] {
        self.raw.raw_auth_events()
    }
}

impl<T: RawEvent> EventLike for ParsedEvent<'_, T> {
    type Content = serde_json::Value;

    fn event_type(&self) -> alloc::borrow::Cow<'_, str> {
        self.raw.raw_event_type()
    }

    fn sender(&self) -> &str {
        self.raw.raw_sender()
    }

    fn state_key(&self) -> Option<&str> {
        self.raw.raw_state_key()
    }

    fn power_level(&self) -> i64 {
        self.raw.raw_power_level()
    }

    fn origin_server_ts(&self) -> u64 {
        self.raw.raw_origin_server_ts()
    }

    fn content(&self) -> &serde_json::Value {
        &self.content
    }
}

/// A lightweight Matrix event representation optimized for state resolution.
///
/// `LeanEvent` strips away fields irrelevant to state resolution (e.g. `unsigned`,
/// `signatures`, `hashes`) and retains only the fields needed for topological
/// sorting, power-level lookups, and auth checks.
///
/// The generic `Id` parameter defaults to `String` but can be substituted with
/// `u32` or `u64` for integer-interned resolution (see [`EventId`]).
///
/// # Deserialization
///
/// `LeanEvent<String>` implements `Deserialize` with the following behaviors:
/// - `event_id`: If absent and the `hashing` feature is enabled, a SHA-256
///   content hash is computed and used as the ID.
/// - `power_level`: Accepts integers, unsigned integers, or string-encoded
///   integers, clamped to [`MAX_POWER_LEVEL_JSON`].
/// - `typed_content`: Populated from `content` for auth-relevant events.
/// - All other fields default to empty/zero if absent.
///
/// # Note on Room ID
///
/// `LeanEvent` omits `room_id`. `rezzy` is a specialized algorithmic engine
/// that expects the host homeserver (e.g., Synapse, Conduit) to perform initial
/// database-level filtering. The host is responsible for verifying cryptographic
/// signatures and filtering events by `room_id` *before* passing them to `resolve_iterative_sort`.
///
/// TODO: Consider adding optional `room_id` validation or a dedicated `ForeignEvent`
/// error check, in case rogue "foreign room" events leak into the `auth_context`.
#[derive(Debug, Clone, Default)]
pub struct LeanEvent<Id = String, C = Value> {
    /// Unique event identifier (e.g. `$abc123:example.com`).
    pub event_id: Id,
    /// Matrix event type (e.g. `m.room.member`, `m.room.power_levels`).
    pub event_type: String,
    /// State key for state events; `None` for timeline (non-state) events.
    /// For `m.room.member` events this is the target user's MXID.
    pub state_key: Option<String>,
    /// Sender's power level at the time of the event, used for sort priority.
    /// This is a pre-computed cache — the authoritative PL is derived from the
    /// auth chain during resolution.
    pub power_level: i64,
    /// Origin server timestamp in milliseconds since Unix epoch.
    /// Used as a tie-breaker in V2+ topological sort ordering.
    pub origin_server_ts: u64,
    /// The MXID of the user who sent the event.
    pub sender: String,
    /// The event's content field (membership, power levels, join rules, etc.).
    pub content: C,
    /// Event IDs of this event's parents in the DAG (timeline graph).
    pub prev_events: Vec<Id>,
    /// Event IDs of the authorization events for this event (auth DAG).
    pub auth_events: Vec<Id>,
    /// DAG depth (distance from the root). Required for V1 sort ordering.
    pub depth: u64,
}

impl<Id: serde::Serialize, C: serde::Serialize> serde::Serialize for LeanEvent<Id, C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use crate::basespec::event_types::{
            FIELD_AUTH_EVENTS, FIELD_CONTENT, FIELD_DEPTH, FIELD_EVENT_ID, FIELD_ORIGIN_SERVER_TS,
            FIELD_POWER_LEVEL, FIELD_PREV_EVENTS, FIELD_SENDER, FIELD_STATE_KEY, FIELD_TYPE,
        };
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("LeanEvent", 10)?;
        state.serialize_field(FIELD_EVENT_ID, &self.event_id)?;
        state.serialize_field(FIELD_TYPE, &self.event_type)?;
        if let Some(ref sk) = self.state_key {
            state.serialize_field(FIELD_STATE_KEY, sk)?;
        }
        state.serialize_field(FIELD_POWER_LEVEL, &self.power_level)?;
        state.serialize_field(FIELD_ORIGIN_SERVER_TS, &self.origin_server_ts)?;
        state.serialize_field(FIELD_SENDER, &self.sender)?;
        state.serialize_field(FIELD_CONTENT, &self.content)?;
        state.serialize_field(FIELD_PREV_EVENTS, &self.prev_events)?;
        state.serialize_field(FIELD_AUTH_EVENTS, &self.auth_events)?;
        state.serialize_field(FIELD_DEPTH, &self.depth)?;
        state.end()
    }
}

/// Trait abstracting event content access for state resolution.
///
/// Implement this for custom content types to avoid `serde_json::Value` overhead.
/// The default `Value` implementation preserves full backwards compatibility.
pub trait EventContent: Clone + core::fmt::Debug + Default {
    fn get_membership(&self) -> Option<&str>;
    fn get_join_rule(&self) -> Option<&str>;
    fn get_user_power_level(&self, user: &str) -> Option<i64>;
    fn get_event_power_level(&self, event_type: &str) -> Option<i64>;
    fn get_users_default(&self) -> Option<i64>;
    fn get_events_default(&self) -> Option<i64>;
    fn get_state_default(&self) -> Option<i64>;
    fn get_ban(&self) -> Option<i64>;
    fn get_kick(&self) -> Option<i64>;
    fn get_invite(&self) -> Option<i64>;
    fn get_redact(&self) -> Option<i64>;
    fn get_creator(&self) -> Option<&str>;
    /// Returns the `room_version` field from `m.room.create` content.
    fn get_room_version(&self) -> Option<&str>;
    /// Specific to V12+ rooms.
    fn has_additional_creator(&self, sender: &str) -> bool;
    /// Returns the `join_authorised_via_users_server` field, if present.
    /// Used for `restricted`/`knock_restricted` join rules (room version 8+).
    fn get_join_authorised_via_users_server(&self) -> Option<&str>;

    /// Returns whether a `third_party_invite` field is present.
    fn has_third_party_invite(&self) -> bool {
        false
    }

    /// Returns the signed token from the `third_party_invite` field, if present.
    fn get_third_party_invite_token(&self) -> Option<&str> {
        None
    }

    /// Returns the mxid from the `third_party_invite` field, if present.
    fn get_third_party_invite_mxid(&self) -> Option<&str> {
        None
    }

    /// Check if signatures block exists in `third_party_invite.signed`.
    fn has_third_party_invite_signatures(&self) -> bool {
        false
    }
}

/// Caller-provided event verification pipeline.
///
/// Rezzy invokes these methods at the right points during auth checking.
/// The caller holds raw JSON, server keys, and crypto — rezzy holds none.
///
/// **Default impls return `Ok(())`** (skip verification). Override individual
/// methods to enable specific verification steps. Pass `None` instead of a
/// verifier to skip all verification entirely (e.g. during state resolution).
///
/// # Verification Steps
///
/// | Step | Method | What it verifies |
/// |------|--------|-----------------|
/// | 1 | [`verify_event_id_hash`](Self::verify_event_id_hash) | Event ID = SHA256(canonical JSON) (room v4+) |
/// | 2 | [`verify_signatures`](Self::verify_signatures) | Server ed25519 signatures on the PDU |
/// | 3 | [`verify_content_hash`](Self::verify_content_hash) | `hashes.sha256` matches canonical JSON hash |
/// | 4 | [`verify_third_party_invite`](Self::verify_third_party_invite) | 3PI `signed.signatures` against TPI public keys |
pub trait EventVerifier<Id> {
    /// Step 1: Verify event ID matches the SHA256 hash of the canonical JSON
    /// (with `signatures` and `unsigned` stripped). For room versions 4+.
    ///
    /// # Errors
    /// Return `Err(reason)` to reject the event.
    fn verify_event_id_hash(&self, _event_id: &Id) -> Result<(), alloc::string::String> {
        Ok(())
    }

    /// Step 2: Verify the event's server signatures against the origin server's
    /// ed25519 public keys.
    ///
    /// # Errors
    /// Return `Err(reason)` to reject the event.
    fn verify_signatures(&self, _event_id: &Id) -> Result<(), alloc::string::String> {
        Ok(())
    }

    /// Step 3: Verify the content hash (`hashes.sha256`) matches the computed
    /// hash of the canonical JSON.
    ///
    /// # Errors
    /// Return `Err(reason)` to reject the event.
    fn verify_content_hash(&self, _event_id: &Id) -> Result<(), alloc::string::String> {
        Ok(())
    }

    /// Step 4: Verify third-party invite signatures against the public keys
    /// from the referenced `m.room.third_party_invite` event.
    ///
    /// # Errors
    /// Return `Err(reason)` to reject the event.
    fn verify_third_party_invite(
        &self,
        _event_id: &Id,
        _tpi_token: &str,
    ) -> Result<(), alloc::string::String> {
        Ok(())
    }
}

impl EventContent for Value {
    fn get_membership(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_MEMBERSHIP)?
            .as_str()
    }

    fn get_join_rule(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_JOIN_RULE)?
            .as_str()
    }

    fn get_user_power_level(&self, user: &str) -> Option<i64> {
        let users = self
            .get(crate::basespec::event_types::FIELD_USERS)?
            .as_object()?;
        coerce_json_to_i64(users.get(user)?).map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_event_power_level(&self, event_type: &str) -> Option<i64> {
        let events = self
            .get(crate::basespec::event_types::FIELD_EVENTS)?
            .as_object()?;
        coerce_json_to_i64(events.get(event_type)?).map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_users_default(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_USERS_DEFAULT)?)
            .map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_events_default(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_EVENTS_DEFAULT)?)
            .map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_state_default(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_STATE_DEFAULT)?)
            .map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_ban(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_BAN)?)
            .map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_kick(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_KICK)?)
            .map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_invite(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_INVITE)?)
            .map(|i| i.min(MAX_POWER_LEVEL_JSON))
    }

    fn get_redact(&self) -> Option<i64> {
        coerce_json_to_i64(self.get(crate::basespec::event_types::FIELD_REDACT)?)
    }

    fn get_creator(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_CREATOR)?
            .as_str()
    }

    fn get_room_version(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_ROOM_VERSION)?
            .as_str()
    }

    fn has_additional_creator(&self, sender: &str) -> bool {
        self.get(crate::basespec::event_types::FIELD_ADDITIONAL_CREATORS)
            .and_then(|v| v.as_array())
            .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some(sender)))
    }

    fn get_join_authorised_via_users_server(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_JOIN_AUTHORISED_VIA_USERS_SERVER)?
            .as_str()
    }

    fn has_third_party_invite(&self) -> bool {
        self.get(crate::basespec::event_types::FIELD_THIRD_PARTY_INVITE)
            .is_some()
    }

    fn get_third_party_invite_token(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_THIRD_PARTY_INVITE)?
            .get(crate::basespec::event_types::FIELD_SIGNED)?
            .get(crate::basespec::event_types::FIELD_TOKEN)?
            .as_str()
    }

    fn get_third_party_invite_mxid(&self) -> Option<&str> {
        self.get(crate::basespec::event_types::FIELD_THIRD_PARTY_INVITE)?
            .get(crate::basespec::event_types::FIELD_SIGNED)?
            .get(crate::basespec::event_types::FIELD_MXID)?
            .as_str()
    }

    fn has_third_party_invite_signatures(&self) -> bool {
        self.get(crate::basespec::event_types::FIELD_THIRD_PARTY_INVITE)
            .and_then(|tpi| tpi.get(crate::basespec::event_types::FIELD_SIGNED))
            .and_then(|signed| signed.get(crate::basespec::event_types::FIELD_SIGNATURES))
            .and_then(|s| s.as_object())
            .is_some_and(|m| !m.is_empty())
    }
}

impl<Id, C> LeanEvent<Id, C> {
    /// Validates basic syntactic limits (`prev_events`, `auth_events` array sizes).
    ///
    /// NOTE: Event types are NOT whitelisted — the spec does not restrict types at the auth level.
    /// Any event type is valid as long as the sender has sufficient PL.
    ///
    /// # Errors
    ///
    /// Returns static string error if structural limits are exceeded.
    ///
    /// # TODO(compliance): PDU structural invariants not yet enforced
    ///
    /// - `content` is required (must be present, even if `{}`)
    /// - `hashes` is required (sha256 content hash)
    /// - `signatures` is required
    /// - `room_id` is version-dependent (present in v1-v11, omitted from create in v12+)
    /// - `sender` must be a valid MXID
    /// - `depth` must be < 2^53 - 1
    ///
    /// These should be validated and tested per room version.
    ///
    /// # Errors
    /// Returns an error if the event violates spec invariants (e.g. >20 `prev_events`).
    pub fn validate_syntactic(&self) -> Result<(), &'static str> {
        // TODO: Are there any other invariants?
        if self.prev_events.len() > 20 {
            return Err("prev_events exceeds maximum allowed length of 20");
        }
        if self.auth_events.len() > 10 {
            return Err("auth_events exceeds maximum allowed length of 10");
        }
        if self.event_type.is_empty() {
            return Err("event_type cannot be empty");
        }

        Ok(())
    }

    // --- Typed Content Accessors (delegate to EventContent) ---

    pub fn get_membership(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_membership()
    }

    pub fn get_join_rule(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_join_rule()
    }

    pub fn get_join_authorised_via_users_server(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_join_authorised_via_users_server()
    }

    pub fn get_user_power_level(&self, user: &str) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_user_power_level(user)
    }

    pub fn get_event_power_level(&self, event_type: &str) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_event_power_level(event_type)
    }

    pub fn get_users_default(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_users_default()
    }

    pub fn get_events_default(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_events_default()
    }

    pub fn get_state_default(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_state_default()
    }

    pub fn get_ban(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_ban()
    }

    pub fn get_kick(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_kick()
    }

    pub fn get_invite(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_invite()
    }

    pub fn get_redact(&self) -> Option<i64>
    where
        C: EventContent,
    {
        self.content.get_redact()
    }

    pub fn get_creator(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_creator()
    }

    pub fn get_room_version(&self) -> Option<&str>
    where
        C: EventContent,
    {
        self.content.get_room_version()
    }

    pub fn has_additional_creator(&self, sender: &str) -> bool
    where
        C: EventContent,
    {
        self.content.has_additional_creator(sender)
    }
}

#[cfg(feature = "hashing")]
fn sort_json_value_keys(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let mut sorted = alloc::collections::BTreeMap::new();
            let taken = core::mem::take(map);
            for (k, mut v) in taken {
                sort_json_value_keys(&mut v);
                sorted.insert(k, v);
            }
            for (k, v) in sorted {
                map.insert(k, v);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                sort_json_value_keys(v);
            }
        }
        _ => {}
    }
}

impl<'de> Deserialize<'de> for LeanEvent<String, Value> {
    #[allow(clippy::too_many_lines)]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use crate::basespec::event_types::{
            FIELD_AUTH_EVENTS, FIELD_CONTENT, FIELD_DEPTH, FIELD_EVENT_ID, FIELD_ORIGIN_SERVER_TS,
            FIELD_POWER_LEVEL, FIELD_PREV_EVENTS, FIELD_SENDER, FIELD_STATE_KEY, FIELD_TYPE,
        };

        let value = Value::deserialize(deserializer)?;

        let event_id = if let Some(id) = value.get(FIELD_EVENT_ID).and_then(|v| v.as_str()) {
            String::from(id)
        } else {
            #[cfg(feature = "hashing")]
            {
                use crate::basespec::event_types::{FIELD_SIGNATURES, FIELD_UNSIGNED};
                use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
                use sha2::{Digest, Sha256};

                let mut hash_value = value.clone();
                if let Some(obj) = hash_value.as_object_mut() {
                    obj.remove(FIELD_UNSIGNED);
                    obj.remove(FIELD_SIGNATURES);
                }
                sort_json_value_keys(&mut hash_value);

                let canonical_json =
                    serde_json::to_string(&hash_value).map_err(serde::de::Error::custom)?;
                let mut hasher = Sha256::new();
                hasher.update(canonical_json.as_bytes());
                let hash = hasher.finalize();

                alloc::format!("${}", URL_SAFE_NO_PAD.encode(hash))
            }
            #[cfg(not(feature = "hashing"))]
            {
                return Err(serde::de::Error::custom(
                    "event_id is missing and 'hashing' feature is disabled",
                ));
            }
        };

        let event_type: String = value
            .get(FIELD_TYPE)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into();

        if event_type.is_empty() {
            return Err(serde::de::Error::custom(
                "event_type cannot be missing or empty",
            ));
        }
        let state_key = value
            .get(FIELD_STATE_KEY)
            .and_then(|v| v.as_str())
            .map(String::from);

        let power_level = match value.get(FIELD_POWER_LEVEL) {
            Some(pl) => {
                if let Some(i) = pl.as_i64() {
                    i.min(MAX_POWER_LEVEL_JSON)
                } else if let Some(u) = pl.as_u64() {
                    let i = i64::try_from(u).unwrap_or(MAX_POWER_LEVEL_JSON);
                    i.min(MAX_POWER_LEVEL_JSON)
                } else if let Some(s) = pl.as_str() {
                    if let Ok(i) = s.parse::<i64>() {
                        i.min(MAX_POWER_LEVEL_JSON)
                    } else {
                        0
                    }
                } else {
                    return Err(serde::de::Error::custom("invalid power_level type"));
                }
            }
            None => 0,
        };

        let origin_server_ts = match value.get(FIELD_ORIGIN_SERVER_TS) {
            Some(ts) => ts.as_u64().unwrap_or(0),
            None => 0,
        };

        let sender = value
            .get(FIELD_SENDER)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into();
        let content = value.get(FIELD_CONTENT).cloned().unwrap_or(Value::Null);

        let parse_string_array = |key: &str| -> Vec<String> {
            value
                .get(key)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };

        let prev_events = parse_string_array(FIELD_PREV_EVENTS);
        let auth_events = parse_string_array(FIELD_AUTH_EVENTS);
        let depth = value
            .get(FIELD_DEPTH)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);

        Ok(LeanEvent {
            event_id,
            event_type,
            state_key,
            power_level,
            origin_server_ts,
            sender,
            content,
            prev_events,
            auth_events,
            depth,
        })
    }
}

impl<Id: PartialEq, C> PartialEq for LeanEvent<Id, C> {
    fn eq(&self, other: &Self) -> bool {
        self.event_id == other.event_id
    }
}

impl<Id: Eq, C> Eq for LeanEvent<Id, C> {}

impl<Id: Ord, C> Ord for LeanEvent<Id, C> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.event_id.cmp(&other.event_id)
    }
}

impl<Id: Ord, C> PartialOrd for LeanEvent<Id, C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<Id, C: EventContent> LeanEvent<Id, C> {
    /// Returns `true` if this event is a ban (`membership: "ban"`) or a kick
    /// (`membership: "leave"` where `state_key ≠ sender`).
    ///
    /// Self-leaves (where the user removes themselves) return `false`.
    #[must_use]
    pub fn is_ban_or_kick(&self) -> bool {
        if self.event_type == crate::basespec::event_types::M_ROOM_MEMBER {
            if let Some(membership) = self.get_membership() {
                if membership == crate::basespec::event_types::MEM_BAN
                    || membership == crate::basespec::event_types::MEM_LEAVE
                {
                    if let Some(ref state_key) = self.state_key {
                        return state_key != &self.sender;
                    }
                }
            }
        }
        false
    }

    /// Returns `true` if this is a `m.room.power_levels` event (a potential demotion).
    #[must_use]
    pub fn is_demotion(&self) -> bool {
        self.event_type == crate::basespec::event_types::M_ROOM_POWER_LEVELS
    }

    /// Returns `true` if this is a `m.room.join_rules` event setting the room to invite-only.
    #[must_use]
    pub fn is_lockdown(&self) -> bool {
        self.event_type == crate::basespec::event_types::M_ROOM_JOIN_RULES
            && self
                .get_join_rule()
                .is_some_and(|rule| rule == crate::basespec::event_types::RULE_INVITE)
    }

    /// Returns `true` if this event restricts the given `sender` — either by
    /// banning/kicking them or by demoting their power level to zero.
    #[must_use]
    pub fn restricts_sender(&self, sender: &str) -> bool {
        if self.is_ban_or_kick() {
            return self.state_key.as_deref() == Some(sender);
        }
        if self.is_demotion() {
            return self.get_user_power_level(sender) == Some(0);
        }
        false
    }

    /// Returns `true` if this administrative event causally restricts `other`.
    ///
    /// Checks whether `self` is a ban/kick/demotion targeting `other`'s sender,
    /// or a join-rules lockdown that blocks `other`'s join attempt.
    #[must_use]
    pub fn restricts_event(&self, other: &LeanEvent<Id, C>) -> bool {
        if self.is_ban_or_kick() || self.is_demotion() {
            return self.restricts_sender(&other.sender);
        }
        self.is_lockdown()
            && other.event_type == crate::basespec::event_types::M_ROOM_MEMBER
            && other
                .get_membership()
                .is_some_and(|m| m == crate::basespec::event_types::MEM_JOIN)
    }
}

impl<Id: Ord, C> LeanEvent<Id, C> {
    /// Deterministic ordering: depth ascending, then `event_id` ascending.
    /// Use this instead of `sort_by_key(|ev| ev.depth)` to avoid
    /// non-determinism from `HashMap` iteration order on equal depths.
    #[must_use]
    pub fn cmp_by_depth(&self, other: &Self) -> Ordering {
        self.depth
            .cmp(&other.depth)
            .then(self.event_id.cmp(&other.event_id))
    }
}

/// A priority wrapper for [`BinaryHeap`](alloc::collections::BinaryHeap)-based
/// topological sorting of events.
///
/// Rust's `BinaryHeap` is a **max-heap** — the element with the greatest `Ord`
/// value is popped first. In state resolution, the *worst* (lowest-priority)
/// event must be applied first so that better events overwrite it via
/// last-write-wins. Therefore:
///
/// - **V1**: Greater = deeper depth (applied first -> loses).
/// - **V2+**: Greater = higher PL (applied first -> sets auth context, then
///   lower-PL events overwrite for same-key conflicts).
///
/// See the [`Ord`] implementation for the full tie-breaking cascade.
#[derive(Debug)]
pub struct SortPriority<'a, Id = String, C = Value> {
    /// Reference to the event being sorted.
    pub event: &'a LeanEvent<Id, C>,
    /// The sender's power level, derived from the auth chain (not `event.power_level`).
    pub power_level: i64,
    /// Shortest auth-chain distance to the `m.room.create` event (V2.2 only).
    pub auth_chain_distance: u64,
    /// The resolution version, which selects the comparison strategy.
    pub version: StateResVersion,
}

impl<Id, C> Clone for SortPriority<'_, Id, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Id, C> Copy for SortPriority<'_, Id, C> {}

impl<Id: Eq, C> PartialEq for SortPriority<'_, Id, C> {
    fn eq(&self, other: &Self) -> bool {
        self.power_level == other.power_level
            && self.event.origin_server_ts == other.event.origin_server_ts
            && self.event.event_id == other.event.event_id
    }
}

impl<Id: Eq, C> Eq for SortPriority<'_, Id, C> {}

impl<Id: Ord, C> Ord for SortPriority<'_, Id, C> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.version {
            StateResVersion::V1 => {
                // Matrix Spec - State Resolution v1:
                // "First we resolve conflicts between m.room.power_levels events...
                //  If there is a tie, we resolve it by comparing the events' depths
                //  and then their event IDs."
                //
                // In Rust's Max-Heap BinaryHeap, "greater" elements are popped first.
                // We want deeper events to pop FIRST, so they must be "greater".
                // NOTE: This is a defense-in-depth vulnerability, which V2 fixes.
                match self.event.depth.cmp(&other.event.depth) {
                    Ordering::Equal => self.event.event_id.cmp(&other.event.event_id),
                    ord => ord,
                }
            }
            StateResVersion::V2
            | StateResVersion::V2_1
            | StateResVersion::V2_1_1
            | StateResVersion::V2_2 => {
                // V2 reverse topological power ordering: worst events pop FIRST.
                //
                // Ruma uses Reverse(TieBreaker) on a BinaryHeap where TieBreaker.cmp is:
                //   other.pl.cmp(&self.pl)  -> higher PL = smaller TieBreaker -> larger Reverse -> pops first
                //   self.ts.cmp(&other.ts)  -> earlier ts = smaller TieBreaker -> larger Reverse -> pops first
                //   self.id.cmp(&other.id)  -> smaller id = smaller TieBreaker -> larger Reverse -> pops first
                //
                // In our direct max-heap (no Reverse) we invert each: Greater = pops first.
                //   higher PL -> Greater  -> use self.pl.cmp(&other.pl)
                //   earlier ts -> Greater -> use other.ts.cmp(&self.ts)
                //   smaller id -> Greater -> use other.id.cmp(&self.id)
                //
                // Net result: high-PL events pop first (losing for same-key conflicts but
                // setting auth context before lower-PL events are checked — this is what
                // makes Alice's ban appear before Bob's concurrent PL change).
                match self.power_level.cmp(&other.power_level) {
                    Ordering::Equal => {
                        // V2.1.1: prioritize topological depth over `origin_server_ts`.
                        // Smaller Depth -> Greater TieBreaker -> Pops First -> Loses.
                        // Larger Depth -> Smaller TieBreaker -> Pops Last -> Wins.
                        if self.version == StateResVersion::V2_1_1
                            || self.version == StateResVersion::V2_2
                        {
                            match other.auth_chain_distance.cmp(&self.auth_chain_distance) {
                                Ordering::Equal => {}
                                ord => return ord,
                            }
                        }

                        match other
                            .event
                            .origin_server_ts
                            .cmp(&self.event.origin_server_ts)
                        {
                            Ordering::Equal => other.event.event_id.cmp(&self.event.event_id),
                            ord => ord,
                        }
                    }
                    ord => ord,
                }
            }
        }
    }
}

impl<Id: Ord, C> PartialOrd for SortPriority<'_, Id, C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Coerces JSON values to `i64` (accepts `ints`, `uints`, or string-encoded ints).
///
/// Returns `None` if the value cannot be interpreted as an integer.
/// This three-way coercion handles the real-world inconsistency where some
/// homeservers encode power levels as strings in their JSON.
///
/// FUN FACT: Room versions 1-9 actually allowed power levels to be floats
/// and strings in the JSON, which is why `rezzy` has this `coerce_json_to_i64`
/// function in the first place!
#[must_use]
pub fn coerce_json_to_i64(pl: &Value) -> Option<i64> {
    let val = pl
        .as_i64()
        .or_else(|| pl.as_u64().map(|u| i64::try_from(u).unwrap_or(i64::MAX)))
        // Legacy float power levels (e.g. 50.0) — truncate toward zero
        .or_else(|| {
            pl.as_f64()
                .and_then(|f| serde_json::Number::from_f64(f.trunc()))
                .and_then(|n| n.as_i64())
        })
        .or_else(|| pl.as_str().and_then(|s| s.parse::<i64>().ok()));
    // Matrix Spec (Client-Server API) — m.room.power_levels:
    // "The power level ... must be an integer between -2^53 + 1 and 2^53 - 1."
    val.map(|v| v.clamp(-MAX_POWER_LEVEL_JSON, MAX_POWER_LEVEL_JSON))
}

/// Lookup trait for retrieving events by ID during sorting and auth checks.
pub trait EventProvider<Id, C> {
    fn get_event(&self, id: &Id) -> Option<&LeanEvent<Id, C>>;
}

impl<Id: core::hash::Hash + Eq, C, S: core::hash::BuildHasher> EventProvider<Id, C>
    for crate::HashMap<Id, LeanEvent<Id, C>, S>
{
    fn get_event(&self, id: &Id) -> Option<&LeanEvent<Id, C>> {
        self.get(id)
    }
}

impl<Id: core::hash::Hash + Eq + Ord, C> EventProvider<Id, C>
    for alloc::collections::BTreeMap<Id, LeanEvent<Id, C>>
{
    fn get_event(&self, id: &Id) -> Option<&LeanEvent<Id, C>> {
        self.get(id)
    }
}

/// Merged event lookup across the conflicted set and auth context.
pub struct SortContext<'a, Id, C, S1, S2> {
    pub primary: &'a crate::HashMap<Id, LeanEvent<Id, C>, S1>,
    pub secondary: &'a crate::HashMap<Id, LeanEvent<Id, C>, S2>,
}

impl<Id: core::hash::Hash + Eq, C, S1: core::hash::BuildHasher, S2: core::hash::BuildHasher>
    EventProvider<Id, C> for SortContext<'_, Id, C, S1, S2>
{
    fn get_event(&self, id: &Id) -> Option<&LeanEvent<Id, C>> {
        self.primary.get(id).or_else(|| self.secondary.get(id))
    }
}
