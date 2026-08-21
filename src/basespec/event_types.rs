//! Matrix Event Type Constants

use alloc::boxed::Box;
use alloc::string::String;
use core::fmt;

pub const M_ROOM_MEMBER: &str = "m.room.member";
pub const M_ROOM_POWER_LEVELS: &str = "m.room.power_levels";
pub const M_ROOM_JOIN_RULES: &str = "m.room.join_rules";
pub const M_ROOM_CREATE: &str = "m.room.create";
pub const M_ROOM_THIRD_PARTY_INVITE: &str = "m.room.third_party_invite";
pub const M_ROOM_NAME: &str = "m.room.name";
pub const M_ROOM_TOPIC: &str = "m.room.topic";
pub const M_ROOM_AVATAR: &str = "m.room.avatar";
pub const M_ROOM_CANONICAL_ALIAS: &str = "m.room.canonical_alias";
pub const M_ROOM_HISTORY_VISIBILITY: &str = "m.room.history_visibility";
pub const M_ROOM_GUEST_ACCESS: &str = "m.room.guest_access";
pub const M_ROOM_SERVER_ACL: &str = "m.room.server_acl";
pub const M_ROOM_TOMBSTONE: &str = "m.room.tombstone";
pub const M_ROOM_ENCRYPTION: &str = "m.room.encryption";
pub const M_ROOM_PINNED_EVENTS: &str = "m.room.pinned_events";
pub const M_ROOM_MESSAGE: &str = "m.room.message";
pub const M_ROOM_REDACTION: &str = "m.room.redaction";
pub const M_SPACE_CHILD: &str = "m.space.child";
pub const M_SPACE_PARENT: &str = "m.space.parent";
pub const M_ROOM_ALIASES: &str = "m.room.aliases";

pub const M_EMPTY_STATE_KEY: &str = "";

/// An interned representation of a Matrix event `type`.
///
/// The well-known types above (and below) are collapsed into `Copy`-free,
/// integer-tag enum variants, so equality and ordering on them are plain
/// discriminant comparisons instead of byte-by-byte string comparisons. This
/// is the dominant type held in [`crate::state::at::SharedState`] keys, so
/// avoiding a `String` allocation + hash/compare per well-known entry matters
/// on the state-resolution hot path.
///
/// Matrix event types are open-ended (custom/vendor types like
/// `org.matrix.msc...` are valid and appear in real rooms), so this is not a
/// closed enum: anything outside the known set falls back to `Custom`, which
/// still round-trips exactly via [`Display`](fmt::Display)/[`EventType::as_str`].
///
/// `Custom` stores a `Box<str>` rather than `String` — event types are
/// immutable once interned, so the extra `capacity` field a `String` carries
/// is dead weight here.
///
/// `Eq`/`Ord`/`Hash` are hand-written against [`Self::as_str`] rather than
/// derived. A derived `Ord` would order by variant declaration position, not
/// string content — that would silently break the `Borrow<dyn StateKeyDyn>`
/// bridge in [`crate::auth`], which compares keys lexicographically as
/// strings to support zero-copy `&str` lookups into `SharedState`. Matching
/// `Ord` to `Display`/`as_str` also keeps `SharedState` iteration order
/// identical to the old plain-`String` key, so nothing downstream that
/// depends on sorted-by-type-string order shifts.
#[derive(Clone, Debug)]
pub enum EventType {
    RoomCreate,
    RoomMember,
    RoomPowerLevels,
    RoomJoinRules,
    RoomThirdPartyInvite,
    RoomName,
    RoomTopic,
    RoomAvatar,
    RoomCanonicalAlias,
    RoomHistoryVisibility,
    RoomGuestAccess,
    RoomServerAcl,
    RoomTombstone,
    RoomEncryption,
    RoomPinnedEvents,
    RoomMessage,
    RoomRedaction,
    RoomAliases,
    SpaceChild,
    SpaceParent,
    /// Any event type outside the well-known set above, preserved verbatim.
    Custom(Box<str>),
}

impl EventType {
    /// Returns the canonical wire-format string for this event type.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::RoomCreate => M_ROOM_CREATE,
            Self::RoomMember => M_ROOM_MEMBER,
            Self::RoomPowerLevels => M_ROOM_POWER_LEVELS,
            Self::RoomJoinRules => M_ROOM_JOIN_RULES,
            Self::RoomThirdPartyInvite => M_ROOM_THIRD_PARTY_INVITE,
            Self::RoomName => M_ROOM_NAME,
            Self::RoomTopic => M_ROOM_TOPIC,
            Self::RoomAvatar => M_ROOM_AVATAR,
            Self::RoomCanonicalAlias => M_ROOM_CANONICAL_ALIAS,
            Self::RoomHistoryVisibility => M_ROOM_HISTORY_VISIBILITY,
            Self::RoomGuestAccess => M_ROOM_GUEST_ACCESS,
            Self::RoomServerAcl => M_ROOM_SERVER_ACL,
            Self::RoomTombstone => M_ROOM_TOMBSTONE,
            Self::RoomEncryption => M_ROOM_ENCRYPTION,
            Self::RoomPinnedEvents => M_ROOM_PINNED_EVENTS,
            Self::RoomMessage => M_ROOM_MESSAGE,
            Self::RoomRedaction => M_ROOM_REDACTION,
            Self::RoomAliases => M_ROOM_ALIASES,
            Self::SpaceChild => M_SPACE_CHILD,
            Self::SpaceParent => M_SPACE_PARENT,
            Self::Custom(s) => s,
        }
    }
}

impl From<&str> for EventType {
    fn from(s: &str) -> Self {
        match s {
            M_ROOM_CREATE => Self::RoomCreate,
            M_ROOM_MEMBER => Self::RoomMember,
            M_ROOM_POWER_LEVELS => Self::RoomPowerLevels,
            M_ROOM_JOIN_RULES => Self::RoomJoinRules,
            M_ROOM_THIRD_PARTY_INVITE => Self::RoomThirdPartyInvite,
            M_ROOM_NAME => Self::RoomName,
            M_ROOM_TOPIC => Self::RoomTopic,
            M_ROOM_AVATAR => Self::RoomAvatar,
            M_ROOM_CANONICAL_ALIAS => Self::RoomCanonicalAlias,
            M_ROOM_HISTORY_VISIBILITY => Self::RoomHistoryVisibility,
            M_ROOM_GUEST_ACCESS => Self::RoomGuestAccess,
            M_ROOM_SERVER_ACL => Self::RoomServerAcl,
            M_ROOM_TOMBSTONE => Self::RoomTombstone,
            M_ROOM_ENCRYPTION => Self::RoomEncryption,
            M_ROOM_PINNED_EVENTS => Self::RoomPinnedEvents,
            M_ROOM_MESSAGE => Self::RoomMessage,
            M_ROOM_REDACTION => Self::RoomRedaction,
            M_ROOM_ALIASES => Self::RoomAliases,
            M_SPACE_CHILD => Self::SpaceChild,
            M_SPACE_PARENT => Self::SpaceParent,
            other => Self::Custom(Box::from(other)),
        }
    }
}

impl From<String> for EventType {
    fn from(s: String) -> Self {
        match s.as_str() {
            M_ROOM_CREATE => Self::RoomCreate,
            M_ROOM_MEMBER => Self::RoomMember,
            M_ROOM_POWER_LEVELS => Self::RoomPowerLevels,
            M_ROOM_JOIN_RULES => Self::RoomJoinRules,
            M_ROOM_THIRD_PARTY_INVITE => Self::RoomThirdPartyInvite,
            M_ROOM_NAME => Self::RoomName,
            M_ROOM_TOPIC => Self::RoomTopic,
            M_ROOM_AVATAR => Self::RoomAvatar,
            M_ROOM_CANONICAL_ALIAS => Self::RoomCanonicalAlias,
            M_ROOM_HISTORY_VISIBILITY => Self::RoomHistoryVisibility,
            M_ROOM_GUEST_ACCESS => Self::RoomGuestAccess,
            M_ROOM_SERVER_ACL => Self::RoomServerAcl,
            M_ROOM_TOMBSTONE => Self::RoomTombstone,
            M_ROOM_ENCRYPTION => Self::RoomEncryption,
            M_ROOM_PINNED_EVENTS => Self::RoomPinnedEvents,
            M_ROOM_MESSAGE => Self::RoomMessage,
            M_ROOM_REDACTION => Self::RoomRedaction,
            M_ROOM_ALIASES => Self::RoomAliases,
            M_SPACE_CHILD => Self::SpaceChild,
            M_SPACE_PARENT => Self::SpaceParent,
            _ => Self::Custom(s.into_boxed_str()),
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for EventType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for EventType {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for EventType {}

impl PartialOrd for EventType {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EventType {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl core::hash::Hash for EventType {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl serde::Serialize for EventType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for EventType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

// JSON field keys
pub const FIELD_MEMBERSHIP: &str = "membership";
pub const FIELD_USERS: &str = "users";
pub const FIELD_USERS_DEFAULT: &str = "users_default";
pub const FIELD_EVENTS: &str = "events";
pub const FIELD_EVENTS_DEFAULT: &str = "events_default";
pub const FIELD_STATE_DEFAULT: &str = "state_default";
pub const FIELD_BAN: &str = "ban";
pub const FIELD_KICK: &str = "kick";
pub const FIELD_INVITE: &str = "invite";
pub const FIELD_REDACT: &str = "redact";
pub const FIELD_JOIN_RULE: &str = "join_rule";
pub const FIELD_CREATOR: &str = "creator";
pub const FIELD_ROOM_VERSION: &str = "room_version";
pub const FIELD_REDACTS: &str = "redacts";
pub const FIELD_ADDITIONAL_CREATORS: &str = "additional_creators";
pub const FIELD_THIRD_PARTY_INVITE: &str = "third_party_invite";
pub const FIELD_SIGNED: &str = "signed";
pub const FIELD_TOKEN: &str = "token";
pub const FIELD_DISPLAY_NAME: &str = "display_name";
pub const FIELD_JOIN_AUTHORISED_VIA_USERS_SERVER: &str = "join_authorised_via_users_server";
pub const FIELD_MXID: &str = "mxid";
pub const FIELD_SIGNATURES: &str = "signatures";
pub const FIELD_NOTIFICATIONS: &str = "notifications";
// Note: Part of canonical JSON in pre-v3 rooms
pub const FIELD_EVENT_ID: &str = "event_id";
// LeanEvent PDU fields
pub const FIELD_TYPE: &str = "type";
pub const FIELD_STATE_KEY: &str = "state_key";
pub const FIELD_POWER_LEVEL: &str = "power_level";
pub const FIELD_ORIGIN_SERVER_TS: &str = "origin_server_ts";
pub const FIELD_SENDER: &str = "sender";
pub const FIELD_CONTENT: &str = "content";
pub const FIELD_PREV_EVENTS: &str = "prev_events";
pub const FIELD_AUTH_EVENTS: &str = "auth_events";
pub const FIELD_DEPTH: &str = "depth";
pub const FIELD_REJECTED: &str = "__rejected";
pub const FIELD_SOFT_FAIL: &str = "__soft_fail";
pub const FIELD_UNSIGNED: &str = "unsigned";

// Membership and Join Rule string values
pub const MEM_JOIN: &str = "join";
pub const MEM_LEAVE: &str = "leave";
pub const MEM_INVITE: &str = "invite";
pub const MEM_BAN: &str = "ban";
pub const MEM_KNOCK: &str = "knock";
pub const RULE_PUBLIC: &str = "public";
pub const RULE_INVITE: &str = "invite";
pub const RULE_KNOCK: &str = "knock";
pub const RULE_RESTRICTED: &str = "restricted";
pub const RULE_KNOCK_RESTRICTED: &str = "knock_restricted";

// Spec-defined default power levels (server-server-api §Definitions)
// "The invite level defaults to 0 if unspecified."
pub const DEFAULT_PL_INVITE: i64 = 0;
// "The kick level, ban level and redact level each default to 50 if unspecified."
pub const DEFAULT_PL_KICK: i64 = 50;
pub const DEFAULT_PL_BAN: i64 = 50;
pub const DEFAULT_PL_REDACT: i64 = 50;
// Implicit default when no power_levels event exists
pub const DEFAULT_PL_USER: i64 = 0;
// Creator implicit PL in rooms v11 & earlier (state res v2 & earlier)
pub const DEFAULT_PL_CREATOR_V11: i64 = 100;

/// Maximum safe power level value: 2^53 − 1 (the JavaScript `Number.MAX_SAFE_INTEGER`).
///
/// The Matrix spec constrains power levels to this bound because clients and
/// servers in the ecosystem use JSON numbers, which are IEEE 754 doubles.
/// Values above this lose integer precision.
pub const MAX_POWER_LEVEL_JSON: i64 = 9_007_199_254_740_991; // 2^53 - 1

/// Maximum safe JSON integer, as a `u64`. Same bound as [`MAX_POWER_LEVEL_JSON`],
/// just typed for unsigned fields (e.g. `depth`) instead of power levels.
pub const MAX_SAFE_JSON_INTEGER: u64 = MAX_POWER_LEVEL_JSON as u64;

/// Maximum safe INTERNAL power level value (`i64::MAX`).
///
/// Used for creator implicit PL in v12+ rooms, where the creator must always
/// win PL comparisons. Incoming wire values are clamped to [`MAX_POWER_LEVEL_JSON`]
/// on deserialization, so this is strictly unreachable by any wire value.
pub const MAX_POWER_LEVEL_RUST: i64 = i64::MAX;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod event_type_tests {
    use super::*;
    use alloc::format;
    use alloc::vec::Vec;

    /// Every well-known constant paired with the `EventType` variant it maps to.
    fn known_pairs() -> Vec<(&'static str, EventType)> {
        alloc::vec![
            (M_ROOM_CREATE, EventType::RoomCreate),
            (M_ROOM_MEMBER, EventType::RoomMember),
            (M_ROOM_POWER_LEVELS, EventType::RoomPowerLevels),
            (M_ROOM_JOIN_RULES, EventType::RoomJoinRules),
            (M_ROOM_THIRD_PARTY_INVITE, EventType::RoomThirdPartyInvite),
            (M_ROOM_NAME, EventType::RoomName),
            (M_ROOM_TOPIC, EventType::RoomTopic),
            (M_ROOM_AVATAR, EventType::RoomAvatar),
            (M_ROOM_CANONICAL_ALIAS, EventType::RoomCanonicalAlias),
            (M_ROOM_HISTORY_VISIBILITY, EventType::RoomHistoryVisibility),
            (M_ROOM_GUEST_ACCESS, EventType::RoomGuestAccess),
            (M_ROOM_SERVER_ACL, EventType::RoomServerAcl),
            (M_ROOM_TOMBSTONE, EventType::RoomTombstone),
            (M_ROOM_ENCRYPTION, EventType::RoomEncryption),
            (M_ROOM_PINNED_EVENTS, EventType::RoomPinnedEvents),
            (M_ROOM_MESSAGE, EventType::RoomMessage),
            (M_ROOM_REDACTION, EventType::RoomRedaction),
            (M_ROOM_ALIASES, EventType::RoomAliases),
            (M_SPACE_CHILD, EventType::SpaceChild),
            (M_SPACE_PARENT, EventType::SpaceParent),
        ]
    }

    #[test]
    fn as_str_round_trips_every_known_variant() {
        for (s, variant) in known_pairs() {
            assert_eq!(variant.as_str(), s);
            assert_eq!(EventType::from(s).as_str(), s);
            assert_eq!(EventType::from(s), variant);
        }
    }

    #[test]
    fn from_string_round_trips_every_known_variant() {
        for (s, variant) in known_pairs() {
            assert_eq!(EventType::from(String::from(s)), variant);
        }
    }

    #[test]
    fn custom_from_str_falls_back_and_round_trips() {
        let custom = EventType::from("org.matrix.msc9999.custom");
        assert_eq!(custom.as_str(), "org.matrix.msc9999.custom");
        assert!(matches!(custom, EventType::Custom(_)));
    }

    #[test]
    fn custom_from_owned_string_avoids_reparsing_mismatch() {
        let owned = String::from("org.matrix.msc9999.custom");
        let custom = EventType::from(owned.clone());
        assert_eq!(custom.as_str(), owned.as_str());
        assert!(matches!(custom, EventType::Custom(_)));
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(format!("{}", EventType::RoomMember), M_ROOM_MEMBER);
        let custom = EventType::from("org.example.foo");
        assert_eq!(format!("{custom}"), "org.example.foo");
    }

    #[test]
    fn as_ref_matches_as_str() {
        let ev = EventType::RoomTopic;
        let r: &str = ev.as_ref();
        assert_eq!(r, ev.as_str());
    }

    #[test]
    fn equality_is_content_based_not_variant_based() {
        assert_eq!(EventType::RoomMember, EventType::from(M_ROOM_MEMBER));
        assert_eq!(
            EventType::from("org.example.foo"),
            EventType::from(String::from("org.example.foo"))
        );
        assert_ne!(EventType::RoomMember, EventType::RoomCreate);
    }

    #[test]
    fn ord_matches_lexicographic_string_order() {
        // `m.room.create` < `m.room.member` lexicographically, and Custom
        // types sort by their literal string too — this must agree with
        // `dyn StateKeyDyn`'s string-based ordering (see the type's doc
        // comment) or `SharedState`'s OrdMap lookups become unsound.
        assert!(EventType::RoomCreate < EventType::RoomMember);
        assert_eq!(
            EventType::RoomCreate.partial_cmp(&EventType::RoomMember),
            Some(core::cmp::Ordering::Less)
        );

        let mut values = alloc::vec![
            EventType::RoomMessage,
            EventType::from("a.custom.type"),
            EventType::RoomCreate,
            EventType::from("z.custom.type"),
        ];
        values.sort();
        let strs: Vec<&str> = values.iter().map(EventType::as_str).collect();
        let mut expected = strs.clone();
        expected.sort_unstable();
        assert_eq!(strs, expected);
    }

    #[test]
    fn hash_matches_between_equal_values_built_different_ways() {
        use core::hash::BuildHasher;
        use hashbrown::DefaultHashBuilder;

        // Use a single builder so both hashes are computed with the same
        // seed — `DefaultHashBuilder::default()` is randomized per
        // instance, so two separate builders would legitimately disagree
        // even for equal inputs.
        fn hash_of(builder: DefaultHashBuilder, ev: &EventType) -> u64 {
            builder.hash_one(ev)
        }

        let builder = DefaultHashBuilder::default();

        let a = EventType::from(M_ROOM_MEMBER);
        let b = EventType::RoomMember;
        assert_eq!(hash_of(builder, &a), hash_of(builder, &b));

        let c = EventType::from("org.example.foo");
        let d = EventType::from(String::from("org.example.foo"));
        assert_eq!(hash_of(builder, &c), hash_of(builder, &d));
    }

    #[test]
    fn serde_round_trips_known_and_custom_variants() {
        let known = EventType::RoomPowerLevels;
        let json = serde_json::to_string(&known).unwrap();
        assert_eq!(json, "\"m.room.power_levels\"");
        let back: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, known);

        let custom = EventType::from("org.example.custom");
        let json = serde_json::to_string(&custom).unwrap();
        assert_eq!(json, "\"org.example.custom\"");
        let back: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, custom);
    }

    #[test]
    fn clone_preserves_value() {
        let a = EventType::from("org.example.foo");
        let b = a.clone();
        assert_eq!(a, b);

        let known = EventType::RoomTombstone;
        assert_eq!(known.clone(), known);
    }

    #[test]
    fn debug_does_not_panic() {
        // Just exercises the derived `Debug` impl for coverage; no format
        // assertion since it's not part of the type's public contract.
        let _ = format!("{:?}", EventType::RoomCreate);
        let _ = format!("{:?}", EventType::from("org.example.foo"));
    }
}
