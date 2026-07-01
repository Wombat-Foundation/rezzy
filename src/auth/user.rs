//! Public query API — "can this user do X?"
//!
//! These decompose the monolithic [`check_auth`](super::check_auth) into
//! reusable sub-queries for power-level threshold checks. They work with
//! [`StateProvider`](super::StateProvider) (raw JSON) so callers don't need
//! ruma content types.

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

/// Whether a user has sufficient power to invite other users.
#[must_use]
pub fn user_can_invite<Id, C: EventContent>(
    user: &str,
    state: &impl StateProvider<Id, C>,
    version: StateResVersion,
) -> bool {
    super::get_sender_power_level(user, state, version) >= super::get_invite_power_level(state)
}

/// Whether a user has sufficient power to ban other users.
#[must_use]
pub fn user_can_ban<Id, C: EventContent>(
    user: &str,
    state: &impl StateProvider<Id, C>,
    version: StateResVersion,
) -> bool {
    super::get_sender_power_level(user, state, version) >= super::get_ban_power_level(state)
}

/// Whether a user has sufficient power to kick other users.
#[must_use]
pub fn user_can_kick<Id, C: EventContent>(
    user: &str,
    state: &impl StateProvider<Id, C>,
    version: StateResVersion,
) -> bool {
    super::get_sender_power_level(user, state, version) >= super::get_kick_power_level(state)
}

/// Whether a user has sufficient power to redact other users' events.
#[must_use]
pub fn user_can_redact<Id, C: EventContent>(
    user: &str,
    state: &impl StateProvider<Id, C>,
    version: StateResVersion,
) -> bool {
    super::get_sender_power_level(user, state, version) >= super::get_redact_power_level(state)
}
