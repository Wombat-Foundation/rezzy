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
use crate::basespec::rezzy_types::{EventContent, StateResVersion};

/// Get the effective power level of a user from the current room state.
///
/// Handles V12+ implicit creator PL (`i64::MAX`) and falls back through
/// the `users` map → `users_default` → `0`.
pub fn user_power_level<Id, C: EventContent>(
    user: &str,
    state: &impl StateProvider<Id, C>,
    version: StateResVersion,
) -> i64 {
    super::get_sender_power_level(user, state, version)
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
    super::get_sender_power_level(user, state, version) >= super::get_invite_power_level(state)
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
    super::get_sender_power_level(user, state, version) >= super::get_ban_power_level(state)
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
    super::get_sender_power_level(user, state, version) >= super::get_kick_power_level(state)
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
    super::get_sender_power_level(user, state, version) >= super::get_redact_power_level(state)
}
