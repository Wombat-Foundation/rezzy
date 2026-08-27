//! Diagnostic warnings for spec-undefined or implementation-deferred conditions.
//!
//! Unlike [`crate::auth::AuthError`] (which strictly invalidates events per the
//! spec), a [`Warning`] reports non-fatal anomalies — such as missing DAG
//! references or legacy oversized fields — without enforcing a rejection policy.
//!
//! Every variant provides a stable [`Warning::code`] for programmatic matching and logging.

use alloc::string::String;
use alloc::vec::Vec;

/// A non-fatal condition rezzy detected but left to the caller's own policy.
///
/// See the module docs for the distinction from [`crate::auth::AuthError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning<Id = String> {
    /// An event's `prev_events` cite one or more IDs not found in the local DAG.
    UnknownPrevEvent {
        /// The event whose `prev_events` reference missing parents.
        event_id: Id,
        /// The specific parent IDs that are unknown locally.
        missing_ids: Vec<Id>,
    },
    /// A pre-v11 event exceeds the 255-byte field length limit.
    OversizedFieldPreV11 {
        /// The event with the oversized field.
        event_id: Id,
        /// Which field exceeded the limit (`"event_id"`, `"sender"`, `"event_type"`, or `"state_key"`).
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

impl<Id: core::fmt::Display> core::fmt::Display for Warning<Id> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownPrevEvent {
                event_id,
                missing_ids,
            } => {
                write!(
                    f,
                    "[{}] event {} references {} missing prev_events",
                    self.code(),
                    event_id,
                    missing_ids.len()
                )
            }
            Self::OversizedFieldPreV11 {
                event_id,
                field,
                len,
                limit,
            } => {
                write!(
                    f,
                    "[{}] event {} field '{}' length {} exceeds limit {}",
                    self.code(),
                    event_id,
                    field,
                    len,
                    limit
                )
            }
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
        assert_eq!(
            unknown_prev.to_string(),
            "[W001_UNKNOWN_PREV_EVENT] event $a references 1 missing prev_events"
        );

        let oversized: Warning<String> = Warning::OversizedFieldPreV11 {
            event_id: "$a".into(),
            field: "sender",
            len: 300,
            limit: 255,
        };
        assert_eq!(oversized.code(), "W002_OVERSIZED_FIELD_PRE_V11");
        assert_eq!(
            oversized.to_string(),
            "[W002_OVERSIZED_FIELD_PRE_V11] event $a field 'sender' length 300 exceeds limit 255"
        );
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
