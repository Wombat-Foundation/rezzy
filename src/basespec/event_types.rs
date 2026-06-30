//! Matrix Event Type Constants

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

pub const M_EMPTY_STATE_KEY: &str = "";

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
pub const FIELD_ADDITIONAL_CREATORS: &str = "additional_creators";
pub const FIELD_THIRD_PARTY_INVITE: &str = "third_party_invite";
pub const FIELD_SIGNED: &str = "signed";
pub const FIELD_TOKEN: &str = "token";
pub const FIELD_DISPLAY_NAME: &str = "display_name";
pub const FIELD_JOIN_AUTHORISED_VIA_USERS_SERVER: &str = "join_authorised_via_users_server";
pub const FIELD_MXID: &str = "mxid";
pub const FIELD_SIGNATURES: &str = "signatures";
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

/// Maximum safe INTERNAL power level value (`i64::MAX`).
///
/// Used for creator implicit PL in v12+ rooms, where the creator must always
/// win PL comparisons. Incoming wire values are clamped to [`MAX_POWER_LEVEL_JSON`]
/// on deserialization, so this is strictly unreachable by any wire value.
pub const MAX_POWER_LEVEL_RUST: i64 = i64::MAX;
