//! Certified Causal Governance (V3) resolution primitives.
//!
//! This module is deliberately separate from the legacy iterative resolver.
//! It owns V3's admission certificates, per-key candidate indexes, and the
//! synchronous repair schedule specified by MSC00C2.

use crate::basespec::event_types::EventType;
use crate::basespec::rezzy_types::{EventId, StateKey};
use crate::{HashMap, LeanEvent, SharedState};

/// V3 cannot safely resolve until the caller supplies verified admission and
/// branch-auth material. This separate error contract prevents legacy V2
/// callers from silently opting into partially implemented semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V3ResolveError<Id> {
    /// A candidate's branch-auth context is unavailable and must be fetched.
    IncompleteAuthContext {
        missing_event_ids: alloc::vec::Vec<Id>,
    },
    /// V3 requires verified-admission metadata, which this entry point has not
    /// yet been given.
    MissingVerifiedAdmission,
}

/// Resolve a `tk.nutra.cdo.12` conflict set.
///
/// This is intentionally a separate API from `resolve_iterative_sort`: V3
/// requires verified admission and branch-auth snapshots before it may perform
/// candidate selection. The metadata-bearing input type is introduced next.
pub fn resolve_v3<Id, C, S1, S2, K>(
    _unconflicted_state: &SharedState<Id, K>,
    _conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S1>,
    _auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
) -> Result<SharedState<Id, K>, V3ResolveError<Id>>
where
    Id: EventId,
    C: crate::basespec::rezzy_types::EventContent,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    K: StateKey,
{
    Err(V3ResolveError::MissingVerifiedAdmission)
}

/// Immutable evidence that a creator authority grant passed V3 certification.
///
/// Construction is intentionally private to the future branch-auth
/// certification pass; callers cannot manufacture a certificate from a raw
/// event shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertifiedCreatorGrant<Id, K> {
    pub(crate) grant_id: Id,
    pub(crate) target: K,
    pub(crate) target_pl: i64,
    pub(crate) prior_pl_id: Id,
    pub(crate) active_witness: Id,
}

/// A candidate selected for one state key in an immutable V3 repair round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoundSelection<Id, K> {
    pub(crate) key: (EventType, K),
    pub(crate) event_id: Id,
}

/// Result of one synchronous repair round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepairRound<Id, K> {
    pub(crate) selections: alloc::vec::Vec<RoundSelection<Id, K>>,
    /// All failures are collected before any removal, making removal
    /// simultaneous and independent of map iteration order.
    pub(crate) rejected: alloc::vec::Vec<Id>,
}

/// V3 certification and repair require stable, canonical identifiers.
pub(crate) trait V3Event: EventId {}
impl<T: EventId> V3Event for T {}

/// Marker bound for state-key types accepted by the V3 evaluator.
pub(crate) trait V3StateKey: StateKey {}
impl<T: StateKey> V3StateKey for T {}
