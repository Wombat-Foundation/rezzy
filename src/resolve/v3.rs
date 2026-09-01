//! Certified Causal Governance (V3) resolution.
//!
//! V3 deliberately does not reuse the V2 iterative resolver. Its caller must
//! first verify PDU admission and construct branch-auth snapshots. This module
//! consumes those certified facts, selects causally-maximal per-key candidates
//! with a total semantic rank, then runs the MSC00C2 synchronous repair loop.
//! It never treats `LeanEvent::rejected == false` as signature verification.
//!
//! # Formal model
//!
//! For verified events <math><mi>E</mi></math>, write
//! <math><mi>x</mi><mo>≺</mo><mi>y</mi></math> when <math><mi>x</mi></math>
//! is a causal ancestor of <math><mi>y</mi></math>. The candidate writers for
//! a state key <math><mi>k</mi></math> are its causal maxima:
//!
//! <math display="block"><semantics><mrow><mi>Candidate</mi><mo>(</mo><mi>k</mi><mo>)</mo><mo>=</mo><mo>{</mo><mi>e</mi><mo>∈</mo><msub><mi>A</mi><mrow><mi>G</mi></mrow></msub><mo>∣</mo><mo>¬</mo><mo>∃</mo><mi>f</mi><mo>∈</mo><msub><mi>A</mi><mi>G</mi></msub><mo>:</mo><mi>e</mi><mo>≺</mo><mi>f</mi><mo>}</mo></mrow><annotation encoding="application/x-tex">\operatorname{Cand}(k) = \{e \in A(G)_k \mid \nexists f \in A(G)_k : e \prec f\}</annotation></semantics></math>
//!
//! Concurrent candidates are ordered lexicographically by their semantic rank
//! and, only as irreducible deterministic residue, by canonical event ID:
//!
//! <math display="block"><semantics><mrow><mi>r</mi><mo>(</mo><mi>e</mi><mo>)</mo><mo>=</mo><mo>(</mo><msub><mi>authority</mi><mrow><mi>θ</mi><mo>(</mo><mi>e</mi><mo>)</mo></mrow></msub><mo>(</mo><mi>e</mi><mo>)</mo><mo>,</mo><mi>polarity</mi><mo>(</mo><mi>e</mi><mo>)</mo><mo>,</mo><mi>specificity</mi><mo>(</mo><mi>e</mi><mo>)</mo><mo>,</mo><mi>id</mi><mo>(</mo><mi>e</mi><mo>)</mo><mo>)</mo></mrow><annotation encoding="application/x-tex">r(e) = (\operatorname{authority}_{\theta(e)}(e), \operatorname{polarity}(e), \operatorname{specificity}(e), \operatorname{id}(e))</annotation></semantics></math>
//!
//! Each repair round selects one maximum-ranked candidate per key against an
//! immutable <math><msub><mi>σ</mi><mi>i</mi></msub></math>, evaluates all selected events jointly, and removes
//! all failures simultaneously:
//!
//! <math display="block"><semantics><mrow><msub><mi>D</mi><mrow><mi>i</mi><mo>+</mo><mn>1</mn></mrow></msub><mo>=</mo><msub><mi>D</mi><mi>i</mi></msub><mo>∖</mo><msub><mi>F</mi><mi>i</mi></msub><mo>,</mo><mspace width="1em"/><msub><mi>F</mi><mi>i</mi></msub><mo>=</mo><mo>{</mo><mi>e</mi><mo>∈</mo><mi>Sel</mi><mo>(</mo><msub><mi>D</mi><mi>i</mi></msub><mo>)</mo><mo>∣</mo><mo>¬</mo><mi>JointAuth</mi><mo>(</mo><mi>e</mi><mo>,</mo><msub><mi>σ</mi><mi>i</mi></msub><mo>)</mo><mo>}</mo></mrow><annotation encoding="application/x-tex">D_{i+1} = D_i \setminus F_i, \qquad F_i = \{e \in \operatorname{Sel}(D_i) \mid \neg\operatorname{JointAuth}(e, \sigma_i)\}</annotation></semantics></math>

//! ## Notation
//!
//! - <math><mi>θ</mi><mo>(</mo><mi>e</mi><mo>)</mo></math>: `e`'s verified, canonical causal-past snapshot.
//! - `authority`: the sender's power level in <math><mi>θ</mi><mo>(</mo><mi>e</mi><mo>)</mo></math>; `polarity`: grant versus restrictive transition; `specificity`: governance, membership, access-policy, or generic-state class.
//! - <math><mi>Sel</mi><mo>(</mo><msub><mi>D</mi><mi>i</mi></msub><mo>)</mo></math>: the causal-maximal, highest-ranked writer selected for each state key.
//! - <math><msub><mi>σ</mi><mi>i</mi></msub></math>: the frozen provisional state made from those selections.
//! - <math><mi>JointAuth</mi><mo>(</mo><mi>e</mi><mo>,</mo><msub><mi>σ</mi><mi>i</mi></msub><mo>)</mo></math>: whether `e` remains authorized against that whole frozen state, including V3 cross-key policy.
//! - <math><msub><mi>F</mi><mi>i</mi></msub></math>: selected events that fail `JointAuth`; all are removed together before the next round.

#![allow(clippy::doc_lazy_continuation, clippy::doc_markdown)]

//! # Normative conflict stances
//!
//! | Situation | `tk.nutra.cdo.12` stance |
//! |---|---|
//! | Kick is causally after B's join or promotion | The kick wins normally. B's earlier valid actions remain valid. |
//! | Creator-certified `grant_admin(B)` concurrent with a lower-authority kick | The compound creator grant wins B's membership/governance conflict; the kick is rejected for that conflict. |
//! | Equal admins concurrently kick or ban each other | Neither has strict cross-branch domination. Their unrelated actions survive; the membership slot uses the declared deterministic residue. |
//! | Ban concurrent with join for the same target | Ban wins: a safety restriction outranks permissive admission at equal authority. |
//! | Lockdown concurrent with joins | Lockdown controls future admission but does not itself evict an established member. A concurrent join can fail admission without becoming a retroactive kick. |
//! | Kick or ban versus the target's unrelated concurrent actions | Those actions survive unless the revoker strictly dominates the target in both <math><mi>θ</mi><mo>(</mo><mi>ρ</mi><mo>)</mo></math> and the selected <math><msub><mi>σ</mi><mi>i</mi></msub></math>. |

use crate::auth::StateProvider;
use crate::basespec::event_types::{
    EventType, MEM_BAN, MEM_INVITE, MEM_JOIN, MEM_KNOCK, MEM_LEAVE, M_ROOM_CREATE,
    M_ROOM_JOIN_RULES, M_ROOM_MEMBER, M_ROOM_POWER_LEVELS, RULE_PUBLIC,
};
use crate::basespec::rezzy_types::{EventId, EventVerifier, StateKey};
use crate::{HashMap, LeanEvent, SharedState};
use alloc::{string::ToString, vec::Vec};

/// The non-grindable portion of the V3 concurrent-writer ordering.
///
/// The components are supplied by the certified-admission layer. They must be
/// derived from the event's branch-auth snapshot, never from cached power
/// level, depth, timestamp, or arrival order. `event_id` is used only as the
/// final deterministic residue when two ranks are equal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct V3Rank {
    /// Authority established by the event's certified branch-auth snapshot.
    pub authority: i64,
    /// Restrictive/safety policy class defined by the V3 room-version spec.
    pub safety: i8,
    /// Event-class-specific policy precision.
    pub specificity: u8,
}

/// The typed safety direction of a state transition.
///
/// Higher values win only after authority ties. This intentionally is not an
/// add-wins rule: a concurrent ban is more restrictive than a join, while a
/// higher-authority creator grant still outranks a lower-authority kick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i8)]
pub enum V3Polarity {
    Grant = 0,
    Neutral = 1,
    Revoke = 2,
    Ban = 3,
}

/// The event-family component of the V3 semantic rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum V3Specificity {
    GenericState = 0,
    AccessPolicy = 1,
    Membership = 2,
    Governance = 3,
}

/// Closed classification table for the currently-defined V3 state families.
/// Unknown/custom state is deliberately neutral until the room-version spec
/// assigns it a policy; it does not inherit a surprising grant or revoke bias.
#[must_use]
pub fn classify_v3_event<C, K>(event: &LeanEvent<impl EventId, C, K>) -> (V3Polarity, V3Specificity)
where
    C: crate::basespec::rezzy_types::EventContent,
    K: StateKey,
{
    match event.event_type.as_str() {
        M_ROOM_MEMBER => match event.get_membership() {
            Some(MEM_BAN) => (V3Polarity::Ban, V3Specificity::Membership),
            Some(MEM_LEAVE) => (V3Polarity::Revoke, V3Specificity::Membership),
            Some(MEM_JOIN | MEM_INVITE | MEM_KNOCK) => {
                (V3Polarity::Grant, V3Specificity::Membership)
            }
            _ => (V3Polarity::Neutral, V3Specificity::Membership),
        },
        M_ROOM_JOIN_RULES => match event.get_join_rule() {
            Some(RULE_PUBLIC) => (V3Polarity::Grant, V3Specificity::AccessPolicy),
            Some(_) => (V3Polarity::Revoke, V3Specificity::AccessPolicy),
            None => (V3Polarity::Neutral, V3Specificity::AccessPolicy),
        },
        M_ROOM_POWER_LEVELS => (V3Polarity::Neutral, V3Specificity::Governance),
        _ => (V3Polarity::Neutral, V3Specificity::GenericState),
    }
}

/// Evidence supplied by the admission pipeline for one event.
///
/// This is metadata, not a claim inferred from raw event fields. Implementors
/// of [`V3AdmissionProvider`] only return it after signature/hash verification
/// and branch-local authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchAuthSnapshot<Id, K: Ord> {
    /// Canonical state selected from this event's verified causal history.
    /// `imbl::OrdMap` makes snapshot clones structural, so certificates may
    /// share most of their branch state without copying a whole room map.
    state: SharedState<Id, K>,
}

/// Verified metadata and its immutable branch-auth snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3Admission<Id, K: Ord> {
    rank: V3Rank,
    branch_auth: BranchAuthSnapshot<Id, K>,
    creator_grant: Option<CertifiedCreatorGrant<Id, K>>,
}

/// A creator promotion paired with the signed, canonical active-member
/// witness required by `tk.nutra.cdo.12`.
///
/// Its fields are private: only V3 admission can establish that the witness
/// was the target's maximal member state in the grant's branch snapshot.
/// Formally, for creator <math><mi>c</mi></math>, target <math><mi>b</mi></math>,
/// grant <math><mi>g</mi></math>, and witness <math><mi>w</mi></math>:
///
/// <math display="block"><semantics><mtext>GrantAdmin(g,b,w) ⇔ sender(g)=c ∧ member_θ(g)(b)=w=join(b) ∧ PL_g(b)&gt;PL_θ(g)(b)</mtext><annotation encoding="application/x-tex">\operatorname{GrantAdmin}(g,b,w) \iff \operatorname{sender}(g)=c \land \operatorname{member}_{\theta(g)}(b)=w=\operatorname{join}(b) \land \operatorname{PL}_g(b)&gt;\operatorname{PL}_{\theta(g)}(b)</annotation></semantics></math>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedCreatorGrant<Id, K: Ord> {
    grant_id: Id,
    target: K,
    target_power_level: i64,
    active_member: Id,
}

impl<Id, K: Ord> V3Admission<Id, K> {
    /// The certified event's V3 semantic rank.
    #[must_use]
    pub const fn rank(&self) -> V3Rank {
        self.rank
    }

    /// Immutable canonical state for the event's causal authorization point.
    #[must_use]
    pub const fn branch_auth(&self) -> &BranchAuthSnapshot<Id, K> {
        &self.branch_auth
    }

    /// The certified compound creator grant, when this event is one.
    #[must_use]
    pub const fn creator_grant(&self) -> Option<&CertifiedCreatorGrant<Id, K>> {
        self.creator_grant.as_ref()
    }
}

impl<Id, K: Ord> CertifiedCreatorGrant<Id, K> {
    #[must_use]
    pub const fn grant_id(&self) -> &Id {
        &self.grant_id
    }

    #[must_use]
    pub const fn target(&self) -> &K {
        &self.target
    }

    #[must_use]
    pub const fn target_power_level(&self) -> i64 {
        self.target_power_level
    }

    #[must_use]
    pub const fn active_member(&self) -> &Id {
        &self.active_member
    }
}

impl<Id, K: Ord> BranchAuthSnapshot<Id, K> {
    /// Read the verified causal state IDs cached for this certificate.
    #[must_use]
    pub const fn state(&self) -> &SharedState<Id, K> {
        &self.state
    }
}

/// The room-version-defined semantic ordering for concurrent V3 writers.
///
/// A production `tk.nutra.cdo.12` implementation supplies one normative
/// policy. Keeping it explicit here prevents a caller from passing a raw rank
/// into certification after inspecting the conflict set.
///
/// The policy supplies the first three components of <math><mi>r</mi><mo>(</mo><mi>e</mi><mo>)</mo></math>;
/// selection appends <math><mi>id</mi><mo>(</mo><mi>e</mi><mo>)</mo></math> only after those semantic components tie.
pub trait V3RankPolicy<Id, C, K: Ord> {
    /// Derive the event's semantic rank from its already-canonical branch
    /// authorization state.
    fn rank(
        &self,
        event: &LeanEvent<Id, C, K>,
        branch_auth: &crate::auth::RoomState<Id, C, K>,
    ) -> V3Rank;
}

/// Normative rank policy for the `tk.nutra.cdo.12` experimental room version.
///
/// The semantic tuple is `(authority, polarity, specificity, event_id)`. The
/// resolver supplies `event_id` only as the final tie-break; this policy reads
/// neither timestamp, depth, nor arrival order.
///
/// <math display="block"><semantics><mtext>r_tk.nutra.cdo.12(e) = (PL_θ(e)(sender(e)), polarity(e), specificity(e), id(e))</mtext><annotation encoding="application/x-tex">r_{\texttt{tk.nutra.cdo.12}}(e) = (\operatorname{PL}_{\theta(e)}(\operatorname{sender}(e)), \operatorname{polarity}(e), \operatorname{specificity}(e), \operatorname{id}(e))</annotation></semantics></math>
#[derive(Debug, Default, Clone, Copy)]
pub struct TkNutraCdo12RankPolicy;

impl<Id, C, K> V3RankPolicy<Id, C, K> for TkNutraCdo12RankPolicy
where
    Id: EventId,
    C: crate::basespec::rezzy_types::EventContent,
    K: StateKey,
    for<'a> (alloc::string::String, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'a>,
{
    fn rank(
        &self,
        event: &LeanEvent<Id, C, K>,
        branch_auth: &crate::auth::RoomState<Id, C, K>,
    ) -> V3Rank {
        let (polarity, specificity) = classify_v3_event(event);
        V3Rank {
            authority: crate::auth::user::get_sender_power_level(
                &event.sender,
                branch_auth,
                crate::StateResVersion::V3,
            ),
            safety: polarity as i8,
            specificity: specificity as u8,
        }
    }
}

/// Certify an event using the normative `tk.nutra.cdo.12` rank policy.
///
/// # Errors
///
/// Returns the authorization or verification failure reported by
/// [`crate::auth::check_auth`].
pub fn certify_tk_nutra_cdo12_admission<Id, C, K>(
    event: &LeanEvent<Id, C, K>,
    branch_auth: &crate::auth::RoomState<Id, C, K>,
    verifier: &dyn EventVerifier<Id>,
) -> Result<V3Admission<Id, K>, crate::auth::AuthError<Id>>
where
    Id: EventId,
    C: crate::basespec::rezzy_types::EventContent,
    K: StateKey,
    for<'a> (alloc::string::String, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'a>,
{
    certify_v3_admission(event, branch_auth, &TkNutraCdo12RankPolicy, verifier)
}

/// Certify an event for V3 selection against its canonical branch-auth state.
///
/// The caller supplies a canonical `(type, state_key) -> event` snapshot for
/// the event's causal past and a mandatory PDU verifier.  No certificate is
/// returned unless ordinary Matrix authorization succeeds in that snapshot and
/// the verifier accepts the PDU. The opaque result is the only public way to
/// obtain [`V3Admission`] outside this module's tests.
///
/// # Errors
///
/// Returns the authorization or verification failure reported by
/// [`crate::auth::check_auth`].
pub fn certify_v3_admission<Id, C, K>(
    event: &LeanEvent<Id, C, K>,
    branch_auth: &crate::auth::RoomState<Id, C, K>,
    rank_policy: &impl V3RankPolicy<Id, C, K>,
    verifier: &dyn EventVerifier<Id>,
) -> Result<V3Admission<Id, K>, crate::auth::AuthError<Id>>
where
    Id: EventId,
    C: crate::basespec::rezzy_types::EventContent,
    K: StateKey,
    for<'a> (alloc::string::String, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'a>,
{
    crate::auth::check_auth(
        event,
        branch_auth,
        crate::StateResVersion::V3,
        Some(verifier),
    )?;
    let mut state = SharedState::new();
    for ((event_type, state_key), auth_event) in branch_auth {
        state.insert(
            (EventType::from(event_type.as_str()), state_key.clone()),
            auth_event.event_id.clone(),
        );
    }
    Ok(V3Admission {
        rank: rank_policy.rank(event, branch_auth),
        branch_auth: BranchAuthSnapshot { state },
        creator_grant: certify_creator_grant(event, branch_auth),
    })
}

/// Validate the signed compound form of `grant_admin(target)`.
///
/// A successful result proves all of the following in the grant's canonical
/// branch snapshot: the sender is a room creator; the signed witness names a
/// joined target; that witness is the snapshot's maximal membership writer for
/// that target; and the power-level event raises the target above the prior
/// branch value. No DAG walk occurs during selection.
fn certify_creator_grant<Id, C, K>(
    grant: &LeanEvent<Id, C, K>,
    branch_auth: &crate::auth::RoomState<Id, C, K>,
) -> Option<CertifiedCreatorGrant<Id, K>>
where
    Id: EventId,
    C: crate::basespec::rezzy_types::EventContent,
    K: StateKey,
    for<'a> (alloc::string::String, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'a>,
{
    if grant.event_type != M_ROOM_POWER_LEVELS {
        return None;
    }
    let create = branch_auth.get_event(M_ROOM_CREATE, "")?;
    if create.sender != grant.sender && !create.has_additional_creator(&grant.sender) {
        return None;
    }
    let signed_witness = grant.content.get_cdo_active_member()?;
    let witness = branch_auth
        .values()
        .find(|event| event.event_id.to_string() == signed_witness)?;
    if witness.event_type != M_ROOM_MEMBER || witness.get_membership() != Some(MEM_JOIN) {
        return None;
    }
    let target = witness.state_key.clone()?;
    let canonical_member = branch_auth.get_event(M_ROOM_MEMBER, target.as_ref())?;
    if canonical_member.event_id != witness.event_id {
        return None;
    }
    let target_power_level = grant.get_user_power_level(target.as_ref())?;
    let prior_power_level = branch_auth
        .get_event(M_ROOM_POWER_LEVELS, "")
        .and_then(|event| event.get_user_power_level(target.as_ref()))
        .unwrap_or(0);
    (target_power_level > prior_power_level).then(|| CertifiedCreatorGrant {
        grant_id: grant.event_id.clone(),
        target,
        target_power_level,
        active_member: witness.event_id.clone(),
    })
}

/// V3 cannot resolve when a required certified fact is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V3ResolveError<Id> {
    /// A conflicted state event did not have verified-admission evidence.
    MissingVerifiedAdmission { event_id: Id },
    /// A causal relation or branch-auth dependency is unavailable locally.
    IncompleteAuthContext { missing_event_ids: Vec<Id> },
}

/// Certified facts consumed by [`resolve_v3`].
///
/// This is the boundary between ingestion/branch authentication and V3 state
/// selection. In particular, implementations must not answer `admission` for
/// merely non-rejected events: it means the event passed PDU verification and
/// authorization against its canonical causal snapshot.
pub trait V3AdmissionProvider<Id, C, K: Ord> {
    /// Return certified admission metadata for `event_id`, if available.
    fn admission(&self, event_id: &Id) -> Option<&V3Admission<Id, K>>;

    /// Whether `ancestor` is causally before `descendant` in verified DAG
    /// edges. Missing dependencies must be reported, not guessed as
    /// concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`V3ResolveError::IncompleteAuthContext`] when the relation
    /// cannot be decided from verified local DAG material.
    fn causally_precedes(&self, ancestor: &Id, descendant: &Id)
        -> Result<bool, V3ResolveError<Id>>;

    /// Evaluate the selected writer against the immutable state assembled for
    /// this repair round. The implementation supplies the event's certified
    /// branch-auth snapshot as required by the V3 admission rules.
    ///
    /// For a revocation <math><mi>ρ</mi></math> targeting user <math><mi>u</mi></math>, a provider that gives the
    /// revocation cross-branch reach must require strict domination in both
    /// views; it must not infer wall-clock order:
    ///
    /// <math display="block"><semantics><mtext>Reach(ρ,u) ⇔ PL_θ(ρ)(sender(ρ)) &gt; PL_θ(ρ)(u) ∧ PL_σᵢ(sender(ρ)) &gt; PL_σᵢ(u)</mtext><annotation encoding="application/x-tex">\operatorname{Reach}(\rho,u) \iff \operatorname{PL}_{\theta(\rho)}(\operatorname{sender}(\rho)) &gt; \operatorname{PL}_{\theta(\rho)}(u) \land \operatorname{PL}_{\sigma_i}(\operatorname{sender}(\rho)) &gt; \operatorname{PL}_{\sigma_i}(u)</annotation></semantics></math>
    ///
    /// This trait is the enforcement boundary for that room-version policy;
    /// `resolve_v3` itself does not invent an answer when the provider lacks
    /// the certified facts.
    ///
    /// # Errors
    ///
    /// Returns [`V3ResolveError::IncompleteAuthContext`] if required
    /// branch-auth material is unavailable.
    fn jointly_authorized(
        &self,
        event: &LeanEvent<Id, C, K>,
        selected_state: &SharedState<Id, K>,
    ) -> Result<bool, V3ResolveError<Id>>;
}

/// A selected candidate for one state key in an immutable V3 repair round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundSelection<Id, K> {
    pub key: (EventType, K),
    pub event_id: Id,
}

/// Auditable result of one synchronous repair round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairRound<Id, K> {
    pub selections: Vec<RoundSelection<Id, K>>,
    /// Every entry was evaluated against the same immutable state. Callers
    /// remove these entries simultaneously before beginning the next round.
    pub rejected: Vec<Id>,
}

/// Resolve a `tk.nutra.cdo.12` conflict set with the V3 repair schedule.
///
/// `conflicted_events` must contain every writer being resolved. The provider
/// supplies verified-admission certificates and canonical causal facts;
/// missing evidence is a fail-closed error. Ordinary, unconflicted state is
/// retained unchanged.
///
/// The loop is deterministic: candidates are causal-maximal per state key,
/// ranked by [`V3Rank`], then by canonical event ID. Each round evaluates all
/// winners against one immutable snapshot and removes all failures together.
/// It therefore executes at most one removing round per admitted event.
/// In particular, no mutation in round <math><mi>i</mi></math> can affect another event's
/// authorization until construction of <math><msub><mi>σ</mi><mrow><mi>i</mi><mo>+</mo><mn>1</mn></mrow></msub></math>.
///
/// # Errors
///
/// Returns an error instead of resolving when a state writer lacks a verified
/// admission certificate or the provider cannot establish a required causal or
/// branch-auth fact.
#[allow(clippy::implicit_hasher)]
pub fn resolve_v3<Id, C, S, K>(
    unconflicted_state: &SharedState<Id, K>,
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    admission: &impl V3AdmissionProvider<Id, C, K>,
) -> Result<SharedState<Id, K>, V3ResolveError<Id>>
where
    Id: EventId,
    C: crate::basespec::rezzy_types::EventContent,
    S: core::hash::BuildHasher,
    K: StateKey,
{
    let mut admitted = Vec::new();
    for event in conflicted_events.values() {
        if event.state_key.is_none() {
            continue;
        }
        if admission.admission(&event.event_id).is_none() {
            return Err(V3ResolveError::MissingVerifiedAdmission {
                event_id: event.event_id.clone(),
            });
        }
        admitted.push(event.event_id.clone());
    }
    admitted.sort_unstable();
    let mut index = AdmittedWriterIndex::build(&admitted, conflicted_events)?;
    let mut causal_cache = CausalRelationCache::default();

    loop {
        let selections = select_round(&index, admission, &mut causal_cache)?;
        let selected_state = state_for_round(unconflicted_state, &selections);
        let round = evaluate_round(selections, &selected_state, conflicted_events, admission)?;

        if round.rejected.is_empty() {
            return Ok(state_for_round(unconflicted_state, &round.selections));
        }

        index.remove_all(&round.rejected);
    }
}

fn evaluate_round<Id, C, S, K>(
    selections: Vec<RoundSelection<Id, K>>,
    selected_state: &SharedState<Id, K>,
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    admission: &impl V3AdmissionProvider<Id, C, K>,
) -> Result<RepairRound<Id, K>, V3ResolveError<Id>>
where
    Id: EventId,
    C: crate::basespec::rezzy_types::EventContent,
    S: core::hash::BuildHasher,
    K: StateKey,
{
    let mut rejected = Vec::new();
    for selection in &selections {
        let event = conflicted_events
            .get(&selection.event_id)
            // `select_round` only selects IDs from this map.
            .expect("V3 selected event missing from conflict set");
        if !admission.jointly_authorized(event, selected_state)? {
            rejected.push(selection.event_id.clone());
        }
    }
    rejected.sort_unstable();
    rejected.dedup();
    Ok(RepairRound {
        selections,
        rejected,
    })
}

/// Cached writers by state key. It is built once from the admitted set and
/// updated only for synchronous round failures, avoiding a full conflict-map
/// scan on every repair round.
#[derive(Debug, Clone)]
struct AdmittedWriterIndex<Id, K> {
    writers: alloc::collections::BTreeMap<(EventType, K), Vec<Id>>,
}

impl<Id: EventId, K: StateKey> AdmittedWriterIndex<Id, K> {
    fn build<C, S>(
        admitted: &[Id],
        conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    ) -> Result<Self, V3ResolveError<Id>>
    where
        C: crate::basespec::rezzy_types::EventContent,
        S: core::hash::BuildHasher,
    {
        let mut writers = alloc::collections::BTreeMap::<(EventType, K), Vec<Id>>::new();
        for event_id in admitted {
            let event = conflicted_events.get(event_id).ok_or_else(|| {
                V3ResolveError::IncompleteAuthContext {
                    missing_event_ids: alloc::vec![event_id.clone()],
                }
            })?;
            let Some(state_key) = event.state_key.as_ref() else {
                continue;
            };
            writers
                .entry((
                    EventType::from(event.event_type.as_str()),
                    state_key.clone(),
                ))
                .or_default()
                .push(event_id.clone());
        }
        Ok(Self { writers })
    }

    fn remove_all(&mut self, rejected: &[Id]) {
        for writers in self.writers.values_mut() {
            writers.retain(|event_id| rejected.binary_search(event_id).is_err());
        }
        self.writers.retain(|_, writers| !writers.is_empty());
    }
}

/// Memoized causal relation queries for one V3 resolution invocation.
///
/// Reachability can be expensive even when the branch-auth provider has an
/// efficient graph index. Each ordered pair is therefore queried at most once
/// across all repair rounds.
#[derive(Debug, Clone)]
struct CausalRelationCache<Id> {
    precedes: alloc::collections::BTreeMap<(Id, Id), bool>,
}

impl<Id> Default for CausalRelationCache<Id> {
    fn default() -> Self {
        Self {
            precedes: alloc::collections::BTreeMap::new(),
        }
    }
}

impl<Id: Clone + Ord> CausalRelationCache<Id> {
    fn precedes<C, K: Ord>(
        &mut self,
        admission: &impl V3AdmissionProvider<Id, C, K>,
        ancestor: &Id,
        descendant: &Id,
    ) -> Result<bool, V3ResolveError<Id>> {
        let key = (ancestor.clone(), descendant.clone());
        if let Some(result) = self.precedes.get(&key) {
            return Ok(*result);
        }
        let result = admission.causally_precedes(ancestor, descendant)?;
        self.precedes.insert(key, result);
        Ok(result)
    }
}

/// Select the maximum-ranked causal candidate independently for every state
/// key <math><mi>k</mi></math> in the current admitted-writer index:
/// <math display="block"><semantics><mrow><msub><mi>max</mi><mrow><mi>r</mi><mo>(</mo><mi>e</mi><mo>)</mo></mrow></msub><mi>Candidate</mi><mo>(</mo><mi>k</mi><mo>)</mo></mrow><annotation encoding="application/x-tex">\max_{r(e)}\operatorname{Cand}(k)</annotation></semantics></math>
fn select_round<Id, C, K>(
    index: &AdmittedWriterIndex<Id, K>,
    admission: &impl V3AdmissionProvider<Id, C, K>,
    causal_cache: &mut CausalRelationCache<Id>,
) -> Result<Vec<RoundSelection<Id, K>>, V3ResolveError<Id>>
where
    Id: EventId,
    C: crate::basespec::rezzy_types::EventContent,
    K: StateKey,
{
    let mut selections = Vec::with_capacity(index.writers.len());
    for (key, writers) in &index.writers {
        let mut maximal = Vec::new();
        for candidate in writers {
            let mut is_maximal = true;
            for other in writers {
                if candidate != other && causal_cache.precedes(admission, candidate, other)? {
                    is_maximal = false;
                    break;
                }
            }
            if is_maximal {
                maximal.push(candidate);
            }
        }
        let winner = maximal
            .into_iter()
            .max_by(|left, right| {
                let left_rank = &admission
                    .admission(left)
                    .expect("V3 admitted event lost its certificate")
                    .rank();
                let right_rank = &admission
                    .admission(right)
                    .expect("V3 admitted event lost its certificate")
                    .rank();
                left_rank.cmp(right_rank).then_with(|| left.cmp(right))
            })
            .expect("each V3 state-key writer list is non-empty");
        selections.push(RoundSelection {
            key: key.clone(),
            event_id: winner.clone(),
        });
    }
    Ok(selections)
}

fn state_for_round<Id: Clone + Ord, K: Clone + Ord>(
    unconflicted_state: &SharedState<Id, K>,
    selections: &[RoundSelection<Id, K>],
) -> SharedState<Id, K> {
    let mut state = unconflicted_state.clone();
    for selection in selections {
        state.insert(selection.key.clone(), selection.event_id.clone());
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basespec::event_types::{
        M_EMPTY_STATE_KEY, M_ROOM_CREATE, M_ROOM_MEMBER, M_ROOM_NAME, M_ROOM_POWER_LEVELS,
        M_ROOM_TOPIC,
    };
    use alloc::string::String;
    use serde_json::Value;

    #[derive(Default)]
    struct TestAdmission {
        admissions: alloc::collections::BTreeMap<String, V3Admission<String, String>>,
        reject: alloc::collections::BTreeSet<String>,
        causal: alloc::collections::BTreeSet<(String, String)>,
        reject_when_selected: Option<(String, (EventType, String), String)>,
    }

    struct AllowVerifier;
    impl EventVerifier<String> for AllowVerifier {}

    struct FixedRank(V3Rank);
    impl V3RankPolicy<String, Value, String> for FixedRank {
        fn rank(
            &self,
            _event: &LeanEvent<String, Value, String>,
            _branch_auth: &crate::auth::RoomState<String, Value, String>,
        ) -> V3Rank {
            self.0
        }
    }

    impl V3AdmissionProvider<String, Value, String> for TestAdmission {
        fn admission(&self, event_id: &String) -> Option<&V3Admission<String, String>> {
            self.admissions.get(event_id)
        }

        fn causally_precedes(
            &self,
            ancestor: &String,
            descendant: &String,
        ) -> Result<bool, V3ResolveError<String>> {
            Ok(self
                .causal
                .contains(&(ancestor.clone(), descendant.clone())))
        }

        fn jointly_authorized(
            &self,
            event: &LeanEvent<String, Value, String>,
            selected_state: &SharedState<String, String>,
        ) -> Result<bool, V3ResolveError<String>> {
            let conditional_rejection = self.reject_when_selected.as_ref().is_some_and(
                |(event_id, key, required_selection)| {
                    &event.event_id == event_id
                        && selected_state.get(key) == Some(required_selection)
                },
            );
            Ok(!self.reject.contains(&event.event_id) && !conditional_rejection)
        }
    }

    fn topic(event_id: &str) -> LeanEvent<String, Value, String> {
        LeanEvent {
            event_id: event_id.into(),
            event_type: M_ROOM_TOPIC.into(),
            state_key: Some(String::new()),
            ..Default::default()
        }
    }

    fn state_event(
        event_id: &str,
        event_type: &str,
        state_key: &str,
    ) -> LeanEvent<String, Value, String> {
        LeanEvent {
            event_id: event_id.into(),
            event_type: event_type.into(),
            state_key: Some(state_key.into()),
            ..Default::default()
        }
    }

    fn membership(event_id: &str, membership: &str) -> LeanEvent<String, Value, String> {
        LeanEvent {
            event_id: event_id.into(),
            event_type: M_ROOM_MEMBER.into(),
            state_key: Some("@target:example.com".into()),
            content: serde_json::json!({ "membership": membership }),
            ..Default::default()
        }
    }

    fn certificate(rank: V3Rank) -> V3Admission<String, String> {
        V3Admission {
            rank,
            branch_auth: BranchAuthSnapshot {
                state: SharedState::new(),
            },
            creator_grant: None,
        }
    }

    #[test]
    fn repair_round_removes_a_failed_winner_simultaneously() {
        let a = topic("$a");
        let b = topic("$b");
        let mut events: HashMap<String, LeanEvent<String, Value, String>> = HashMap::default();
        events.insert(a.event_id.clone(), a);
        events.insert(b.event_id.clone(), b);
        let mut admission = TestAdmission::default();
        admission
            .admissions
            .insert("$a".into(), certificate(V3Rank::default()));
        admission.admissions.insert(
            "$b".into(),
            certificate(V3Rank {
                authority: 1,
                ..V3Rank::default()
            }),
        );
        admission.reject.insert("$b".into());

        let state = resolve_v3(&SharedState::new(), &events, &admission).unwrap();
        assert_eq!(
            state.get(&(EventType::from(M_ROOM_TOPIC), String::new())),
            Some(&String::from("$a"))
        );
    }

    #[test]
    fn missing_certificate_fails_closed() {
        let event = topic("$unverified");
        let mut events: HashMap<String, LeanEvent<String, Value, String>> = HashMap::default();
        events.insert(event.event_id.clone(), event);

        assert_eq!(
            resolve_v3(&SharedState::new(), &events, &TestAdmission::default()),
            Err(V3ResolveError::MissingVerifiedAdmission {
                event_id: "$unverified".into(),
            })
        );
    }

    #[test]
    fn certification_requires_branch_auth_and_a_verifier() {
        let create: LeanEvent<String, Value, String> = LeanEvent {
            event_id: "$create".into(),
            event_type: M_ROOM_CREATE.into(),
            state_key: Some(M_EMPTY_STATE_KEY.into()),
            sender: "@creator:example.com".into(),
            content: serde_json::json!({
                "creator": "@creator:example.com",
                "room_version": "tk.nutra.cdo.12",
            }),
            ..Default::default()
        };
        let branch_auth = crate::auth::RoomState::new();

        let certificate = certify_v3_admission(
            &create,
            &branch_auth,
            &FixedRank(V3Rank {
                authority: 100,
                ..V3Rank::default()
            }),
            &AllowVerifier,
        )
        .unwrap();

        assert_eq!(certificate.rank().authority, 100);
        assert!(certificate.branch_auth().state().is_empty());
    }

    #[test]
    fn creator_grant_requires_a_maximal_join_witness_and_a_power_increase() {
        let create: LeanEvent<String, Value, String> = LeanEvent {
            event_id: "$create".into(),
            event_type: M_ROOM_CREATE.into(),
            state_key: Some(String::new()),
            sender: "@creator:example.com".into(),
            content: serde_json::json!({ "creator": "@creator:example.com" }),
            ..Default::default()
        };
        let b_join = LeanEvent {
            event_id: "$b_join".into(),
            event_type: M_ROOM_MEMBER.into(),
            state_key: Some("@b:example.com".into()),
            sender: "@b:example.com".into(),
            content: serde_json::json!({ "membership": MEM_JOIN }),
            ..Default::default()
        };
        let prior_power = LeanEvent {
            event_id: "$prior_power".into(),
            event_type: M_ROOM_POWER_LEVELS.into(),
            state_key: Some(String::new()),
            sender: "@creator:example.com".into(),
            content: serde_json::json!({ "users": { "@b:example.com": 0 } }),
            ..Default::default()
        };
        let grant = LeanEvent {
            event_id: "$grant".into(),
            event_type: M_ROOM_POWER_LEVELS.into(),
            state_key: Some(String::new()),
            sender: "@creator:example.com".into(),
            content: serde_json::json!({
                "users": { "@b:example.com": 100 },
                "tk.nutra.cdo": { "active_member": "$b_join" },
            }),
            ..Default::default()
        };
        let mut branch_auth = crate::auth::RoomState::new();
        branch_auth.insert((M_ROOM_CREATE.into(), String::new()), create);
        branch_auth.insert((M_ROOM_MEMBER.into(), "@b:example.com".into()), b_join);
        branch_auth.insert((M_ROOM_POWER_LEVELS.into(), String::new()), prior_power);

        let certified = certify_creator_grant(&grant, &branch_auth).unwrap();
        assert_eq!(certified.target(), &String::from("@b:example.com"));
        assert_eq!(certified.active_member(), &String::from("$b_join"));
        assert_eq!(certified.target_power_level(), 100);
    }

    #[test]
    fn typed_rank_table_is_restrictive_only_after_authority_ties() {
        let join = membership("$join", MEM_JOIN);
        let ban = membership("$ban", MEM_BAN);
        let join_class = classify_v3_event(&join);
        let ban_class = classify_v3_event(&ban);
        assert_eq!(join_class, (V3Polarity::Grant, V3Specificity::Membership));
        assert_eq!(ban_class, (V3Polarity::Ban, V3Specificity::Membership));
        assert!((ban_class.0 as i8) > (join_class.0 as i8));

        let public = LeanEvent {
            content: serde_json::json!({ "join_rule": RULE_PUBLIC }),
            ..state_event("$public", M_ROOM_JOIN_RULES, "")
        };
        let restrictive = LeanEvent {
            content: serde_json::json!({ "join_rule": "invite" }),
            ..public.clone()
        };
        assert_eq!(
            classify_v3_event(&public),
            (V3Polarity::Grant, V3Specificity::AccessPolicy),
        );
        assert_eq!(
            classify_v3_event(&restrictive),
            (V3Polarity::Revoke, V3Specificity::AccessPolicy),
        );
    }

    #[test]
    fn causal_descendant_excludes_a_higher_ranked_ancestor() {
        let ancestor = topic("$ancestor");
        let descendant = topic("$descendant");
        let mut events: HashMap<String, LeanEvent<String, Value, String>> = HashMap::default();
        events.insert(ancestor.event_id.clone(), ancestor);
        events.insert(descendant.event_id.clone(), descendant);
        let mut admission = TestAdmission::default();
        admission.admissions.insert(
            "$ancestor".into(),
            certificate(V3Rank {
                authority: 100,
                ..V3Rank::default()
            }),
        );
        admission
            .admissions
            .insert("$descendant".into(), certificate(V3Rank::default()));
        admission
            .causal
            .insert(("$ancestor".into(), "$descendant".into()));

        let state = resolve_v3(&SharedState::new(), &events, &admission).unwrap();
        assert_eq!(
            state.get(&(EventType::from(M_ROOM_TOPIC), String::new())),
            Some(&String::from("$descendant"))
        );
    }

    #[test]
    fn synchronous_cross_key_repair_prevents_the_dueling_admins_massacre() {
        let b_join = state_event("$b_join", M_ROOM_MEMBER, "@b:example.com");
        let kick_b = state_event("$kick_b", M_ROOM_MEMBER, "@b:example.com");
        let creator_grant = state_event("$creator_grant", M_ROOM_POWER_LEVELS, "");
        let b_action = state_event("$b_action", M_ROOM_NAME, "");
        let mut events: HashMap<String, LeanEvent<String, Value, String>> = HashMap::default();
        for event in [b_join, kick_b, creator_grant, b_action] {
            events.insert(event.event_id.clone(), event);
        }

        let mut admission = TestAdmission::default();
        admission
            .admissions
            .insert("$b_join".into(), certificate(V3Rank::default()));
        admission.admissions.insert(
            "$kick_b".into(),
            certificate(V3Rank {
                authority: 100,
                ..V3Rank::default()
            }),
        );
        admission.admissions.insert(
            "$creator_grant".into(),
            certificate(V3Rank {
                authority: 101,
                ..V3Rank::default()
            }),
        );
        admission
            .admissions
            .insert("$b_action".into(), certificate(V3Rank::default()));
        admission.reject_when_selected = Some((
            "$kick_b".into(),
            (EventType::from(M_ROOM_POWER_LEVELS), String::new()),
            "$creator_grant".into(),
        ));

        let state = resolve_v3(&SharedState::new(), &events, &admission).unwrap();
        assert_eq!(
            state.get(&(EventType::from(M_ROOM_MEMBER), "@b:example.com".into())),
            Some(&String::from("$b_join")),
        );
        assert_eq!(
            state.get(&(EventType::from(M_ROOM_NAME), String::new())),
            Some(&String::from("$b_action")),
        );
    }
}
