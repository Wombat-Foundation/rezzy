//! Power-level threshold queries — "does this user meet the PL requirement?"
//!
//! These are **threshold-only** sub-queries that check `sender_pl >= action_pl`.
//! They do NOT perform full authorization — use [`check_auth`](super::check_auth)
//! for complete Matrix auth rule evaluation.
//!
//! Full authorization for these actions depends on additional context not
//! available here (target user, membership state, 3PI tokens, etc.):
//!
//! - **Invite**: also requires sender≠target, target not banned, 3PI checks.
//! - **Ban/Kick**: also requires `sender_pl > target_pl`.
//! - **Redact**: rules vary by room version, event sender, and creator status.

use super::StateProvider;
use crate::basespec::event_types::{
    DEFAULT_PL_USER, MAX_POWER_LEVEL_RUST, M_ROOM_CREATE, M_ROOM_POWER_LEVELS,
};
use crate::basespec::rezzy_types::{EventContent, StateResVersion};

/// Get the effective power level of a user from the current room state.
///
/// Handles V12+ implicit creator PL (`i64::MAX`) and falls back through
/// the `users` map → `users_default` → `0`.
pub fn get_sender_power_level<Id, C: EventContent>(
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
    DEFAULT_PL_USER // Default power level if no power_levels event exists
}

/// Whether a user's power level meets the invite threshold.
///
/// **Threshold-only** — does not check target membership, sender≠target, or
/// 3PI rules. Use [`check_auth`](super::check_auth) for full authorization.
#[must_use]
pub fn user_can_invite<Id, C: EventContent>(
    user: &str,
    state: &impl StateProvider<Id, C>,
    version: StateResVersion,
) -> bool {
    get_sender_power_level(user, state, version) >= super::get_invite_power_level(state)
}

/// Whether a user's power level meets the ban threshold.
///
/// **Threshold-only** — does not check `sender_pl > target_pl`.
/// Use [`check_auth`](super::check_auth) for full authorization.
#[must_use]
pub fn user_can_ban<Id, C: EventContent>(
    user: &str,
    state: &impl StateProvider<Id, C>,
    version: StateResVersion,
) -> bool {
    get_sender_power_level(user, state, version) >= super::get_ban_power_level(state)
}

/// Whether a user's power level meets the kick threshold.
///
/// **Threshold-only** — does not check `sender_pl > target_pl`.
/// Use [`check_auth`](super::check_auth) for full authorization.
#[must_use]
pub fn user_can_kick<Id, C: EventContent>(
    user: &str,
    state: &impl StateProvider<Id, C>,
    version: StateResVersion,
) -> bool {
    get_sender_power_level(user, state, version) >= super::get_kick_power_level(state)
}

/// Whether a user's power level meets the redact threshold.
///
/// **Threshold-only** — does not check room version redaction rules or
/// creator status. Use [`check_auth`](super::check_auth) for full authorization.
#[must_use]
pub fn user_can_redact<Id, C: EventContent>(
    user: &str,
    state: &impl StateProvider<Id, C>,
    version: StateResVersion,
) -> bool {
    get_sender_power_level(user, state, version) >= super::get_redact_power_level(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basespec::rezzy_types::LeanEvent;
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use serde_json::json;

    type State = BTreeMap<(String, String), LeanEvent>;

    fn state_with_pl(pl: serde_json::Value) -> State {
        let mut s = State::new();
        s.insert(
            ("m.room.power_levels".into(), String::new()),
            LeanEvent {
                event_id: "$pl".into(),
                event_type: "m.room.power_levels".into(),
                state_key: Some(String::new()),
                content: pl,
                ..Default::default()
            },
        );
        s
    }

    #[test]
    fn test_all_thresholds() {
        let state = state_with_pl(json!({
            "invite": 10, "ban": 50, "kick": 50, "redact": 50,
            "users": { "@admin:x": 100, "@pleb:x": 5 }
        }));
        let v = StateResVersion::V2;

        assert_eq!(get_sender_power_level("@admin:x", &state, v), 100);
        assert_eq!(get_sender_power_level("@pleb:x", &state, v), 5);
        assert_eq!(get_sender_power_level("@nobody:x", &state, v), 0);

        assert!(user_can_invite("@admin:x", &state, v));
        assert!(!user_can_invite("@pleb:x", &state, v));

        assert!(user_can_ban("@admin:x", &state, v));
        assert!(!user_can_ban("@pleb:x", &state, v));

        assert!(user_can_kick("@admin:x", &state, v));
        assert!(!user_can_kick("@pleb:x", &state, v));

        assert!(user_can_redact("@admin:x", &state, v));
        assert!(!user_can_redact("@pleb:x", &state, v));
    }

    #[test]
    fn test_no_pl_event_defaults() {
        let state = State::new();
        let v = StateResVersion::V2;
        // All defaults are 0 except ban/kick/redact (50)
        assert_eq!(get_sender_power_level("@x:x", &state, v), 0);
        assert!(user_can_invite("@x:x", &state, v)); // 0 >= 0
        assert!(!user_can_ban("@x:x", &state, v)); // 0 < 50
        assert!(!user_can_kick("@x:x", &state, v)); // 0 < 50
        assert!(!user_can_redact("@x:x", &state, v)); // 0 < 50
    }
}
