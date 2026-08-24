//! A structured, stably-coded channel for conditions the Matrix spec leaves
//! undefined or homeserver-specific -- rezzy detects them but deliberately
//! does not pick a policy (reject vs continue) on the caller's behalf.
//!
//! Contrast with [`crate::auth::AuthError`]: an `AuthError` means the spec
//! is definite and the event MUST be rejected. A [`Warning`] means the spec
//! is silent or explicitly defers to implementations, so rezzy surfaces the
//! condition structurally instead of hard-coding an opinion. Two examples
//! already wired through this channel:
//!
//! - An event whose `prev_events` reference an ID missing from the local
//!   DAG. The spec has no rule for this (it's a backfill/sync concern, not
//!   an auth concern) -- some homeservers may want to reject until backfill
//!   completes, others may want to process what they have and backfill
//!   asynchronously.
//! - A pre-v11 event exceeding the 255-byte field limit that v11+ hard-
//!   enforces. Synapse itself only warns pre-v11 (`strict_event_byte_limits_room_versions`)
//!   to avoid splitting the DAG against legacy rooms with oversized fields
//!   already baked into their history; a from-scratch deployment might
//!   reasonably choose to reject instead.
//!
//! Every variant has a [`Warning::code`] -- a short, stable string safe to
//! match on or log across rezzy versions even as a variant's fields grow.

use alloc::vec::Vec;

/// A non-fatal condition rezzy detected but left to the caller's own policy.
///
/// See the module docs for the distinction from [`crate::auth::AuthError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning<Id> {
    /// W001: an event's `prev_events` cite one or more IDs not found in the
    /// local DAG. Convertible from [`crate::state::at::BackwardExtremity`],
    /// which groups the same information as a caller-facing backfill-gap
    /// report; this variant exists so that information can also flow
    /// through the general warnings channel.
    UnknownPrevEvent {
        /// The event whose `prev_events` reference missing parents.
        event_id: Id,
        /// The specific parent IDs that are unknown locally.
        missing_ids: Vec<Id>,
    },
    /// W002: a pre-v11 event exceeds the 255-byte field limit that v11+
    /// hard-enforces (`strict_event_byte_limits_room_versions`). Emitted by
    /// [`crate::basespec::rezzy_types::LeanEvent::validate_syntactic`]
    /// instead of the `eprintln!` it previously used.
    OversizedFieldPreV11 {
        /// The event with the oversized field.
        event_id: Id,
        /// Which field exceeded the limit (`"event_id"`, `"sender"`,
        /// `"event_type"`, or `"state_key"`).
        field: &'static str,
        /// The field's actual byte length.
        len: usize,
        /// The limit it exceeded (255, per spec).
        limit: usize,
    },
}

impl<Id> Warning<Id> {
    /// A short, stable code for this warning, safe to match on or log
    /// across rezzy versions independent of the variant's exact fields.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownPrevEvent { .. } => "W001_UNKNOWN_PREV_EVENT",
            Self::OversizedFieldPreV11 { .. } => "W002_OVERSIZED_FIELD_PRE_V11",
        }
    }
}

impl<Id> From<crate::state::at::BackwardExtremity<Id>> for Warning<Id> {
    fn from(gap: crate::state::at::BackwardExtremity<Id>) -> Self {
        Self::UnknownPrevEvent {
            event_id: gap.event_id,
            missing_ids: gap.missing_prev_events,
        }
    }
}

/// A successful result bundled with any non-fatal [`Warning`]s collected
/// along the way.
///
/// Hard failures stay in the `Err` side of whatever `Result` a function
/// returns; `Outcome` only ever wraps the `Ok` payload, so a caller that
/// doesn't care about warnings can ignore `.warnings` entirely and still
/// get correct pass/fail behavior from the `Result`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome<T, Id> {
    /// The successful result.
    pub value: T,
    /// Non-fatal conditions collected while producing `value`. Empty in the
    /// common case; never affects whether `value` itself is trustworthy --
    /// only whether the caller wants to act on what's in here (log it,
    /// apply local policy, surface it to an operator, ...).
    pub warnings: Vec<Warning<Id>>,
}

impl<T, Id> Outcome<T, Id> {
    /// Wraps `value` with no warnings.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self {
            value,
            warnings: Vec::new(),
        }
    }

    /// Wraps `value` with an already-collected list of warnings.
    #[must_use]
    pub const fn with_warnings(value: T, warnings: Vec<Warning<Id>>) -> Self {
        Self { value, warnings }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{Outcome, Warning};
    use alloc::{
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    #[test]
    fn test_warning_codes_are_stable() {
        let unknown_prev: Warning<String> = Warning::UnknownPrevEvent {
            event_id: "$a".into(),
            missing_ids: vec!["$missing".into()],
        };
        assert_eq!(unknown_prev.code(), "W001_UNKNOWN_PREV_EVENT");

        let oversized: Warning<String> = Warning::OversizedFieldPreV11 {
            event_id: "$a".into(),
            field: "sender",
            len: 300,
            limit: 255,
        };
        assert_eq!(oversized.code(), "W002_OVERSIZED_FIELD_PRE_V11");
    }

    #[test]
    fn test_backward_extremity_converts_to_unknown_prev_event_warning() {
        let gap = crate::state::at::BackwardExtremity {
            event_id: "$a".to_string(),
            missing_prev_events: vec!["$b".to_string(), "$c".to_string()],
        };
        let warning: Warning<String> = gap.into();
        assert_eq!(
            warning,
            Warning::UnknownPrevEvent {
                event_id: "$a".into(),
                missing_ids: vec!["$b".into(), "$c".into()],
            }
        );
        assert_eq!(warning.code(), "W001_UNKNOWN_PREV_EVENT");
    }

    #[test]
    fn test_outcome_new_has_no_warnings() {
        let outcome: Outcome<i32, String> = Outcome::new(42);
        assert_eq!(outcome.value, 42);
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn test_outcome_with_warnings() {
        let warnings: Vec<Warning<String>> = vec![Warning::OversizedFieldPreV11 {
            event_id: "$a".into(),
            field: "event_id",
            len: 300,
            limit: 255,
        }];
        let outcome = Outcome::with_warnings(42, warnings.clone());
        assert_eq!(outcome.value, 42);
        assert_eq!(outcome.warnings, warnings);
    }
}
